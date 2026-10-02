import io
import os
import tempfile
import time
import zipfile

from ..authz import Identity, policy, statement
from ..result import CallOutcome

FUNCTION = "cloudsec-probe-fn"
RUNTIME = "python3.13"
HANDLER = "handler.main"
INVOKE_TIMEOUT = 90
CODE = (
    "import json\n"
    "def main(event, context):\n"
    "    return {'statusCode': 200, 'body': json.dumps({'synthetic': True})}\n"
)


def _package():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("handler.py", CODE)
    return buffer.getvalue()


def probe(floci, matrix, suffix):
    gaps = []
    operations = {}
    authz = {}
    signals = {}
    lambda_client = floci.client("lambda", read_timeout=INVOKE_TIMEOUT)
    name = f"{FUNCTION}-{suffix}"
    role = _role(floci, name)

    archive = _package()
    created = CallOutcome.capture("lambda", "CreateFunction", lambda c: c.create_function(
        FunctionName=name,
        Runtime=RUNTIME,
        Role=role or f"arn:aws:iam::{floci.account}:role/cloudsec-probe-role",
        Handler=HANDLER,
        Code={"ZipFile": archive},
        Environment={"Variables": {"CLOUDSEC_PROBE": "synthetic-value"}},
        Timeout=10), lambda_client)
    operations["CreateFunction"] = created.to_dict()
    operations["CreateFunctionRuntime"] = RUNTIME
    operations["CreateFunctionCodeBytes"] = len(archive)
    if not created.ok:
        gaps.append(
            f"Lambda CreateFunction failed: {created.error_code} / "
            f"{created.exception}; invocation is therefore unproven")
        signals["lambda"] = {"lambda_deny_observed": None}
        return {"available": False, "operations": operations, "authorization": authz,
                "gaps": gaps, "enforcement_signals": signals}

    if created.raw.get("State"):
        operations["CreateFunctionState"] = created.raw["State"]

    configuration = CallOutcome.capture("lambda", "GetFunctionConfiguration",
                                        lambda c: c.get_function_configuration(
                                            FunctionName=name), lambda_client)
    operations["GetFunctionConfiguration"] = configuration.to_dict()
    env_read = None
    if configuration.ok:
        env_read = configuration.raw.get("Environment", {}).get("Variables", {})
        env_read = {k: v for k, v in env_read.items() if k.startswith("CLOUDSEC_")}
    operations["EnvironmentVariablesReadBack"] = {
        "operation": "GetFunctionConfiguration", "ok": env_read is not None,
        "variables": env_read}
    operations["EnvironmentSyntheticOnly"] = {
        "operation": "GetFunctionConfiguration",
        "ok": bool(env_read) and all(
            value == "synthetic-value" for value in env_read.values())}
    if not operations["EnvironmentSyntheticOnly"]["ok"]:
        gaps.append("Lambda environment variables did not read back as the synthetic value")

    updated = CallOutcome.capture("lambda", "UpdateFunctionConfiguration",
                                  lambda c: c.update_function_configuration(
                                      FunctionName=name,
                                      Environment={"Variables": {
                                          "CLOUDSEC_PROBE": "synthetic-value-2",
                                          "CLOUDSEC_STAGE": "probe"}}),
                                  lambda_client)
    operations["UpdateFunctionConfiguration"] = updated.to_dict()
    after_update = CallOutcome.capture("lambda", "GetFunctionConfiguration",
                                       lambda c: c.get_function_configuration(
                                           FunctionName=name), lambda_client)
    operations["UpdateEnvironmentReadBack"] = (
        after_update.raw.get("Environment", {}).get("Variables")
        if after_update.ok else None)

    if updated.raw and updated.raw.get("State") in ("Pending", "InProgress"):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            waiter = CallOutcome.capture("lambda", "GetFunctionConfiguration",
                                         lambda c: c.get_function_configuration(
                                             FunctionName=name), lambda_client)
            if waiter.ok and waiter.raw.get("State") == "Active":
                operations["UpdateStateSettled"] = "Active"
                break
            time.sleep(2)
        else:
            operations["UpdateStateSettled"] = (
                waiter.raw.get("State") if waiter.ok else None)
            if operations["UpdateStateSettled"] != "Active":
                gaps.append(
                    f"Lambda function never reached Active after update "
                    f"(observed {operations['UpdateStateSettled']!r}); invoke may not run")

    started = time.monotonic()
    invoked = CallOutcome.capture("lambda", "Invoke", lambda c: c.invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=b'{"synthetic":true}', LogType="None"), lambda_client)
    operations["Invoke"] = invoked.to_dict()
    operations["InvokeElapsedSeconds"] = round(time.monotonic() - started, 2)
    operations["InvokeErrorDetails"] = (
        invoked.raw.get("FunctionError") if invoked.ok else invoked.detail)
    if not invoked.ok:
        gaps.append(
            f"Lambda Invoke failed: {invoked.error_code or invoked.exception}; "
            f"Floci Lambda execution is unproven on this host")
    elif invoked.raw.get("FunctionError"):
        gaps.append(f"Lambda returned a function error: {invoked.raw.get('FunctionError')}")

    operations["ListFunctions"] = _capture(lambda_client, "ListFunctions",
                                           lambda c: c.list_functions())

    availability = {"lambda_deny_observed": True}
    function_arn = created.raw.get("FunctionArn") or (
        f"arn:aws:lambda:{floci.region()}:{floci.account}:function:{name}")
    deny_identity = Identity(floci, f"lambdadeny{suffix}")
    if not deny_identity.create():
        availability["lambda_deny_observed"] = None
        authz["explicit_deny"] = {"error": "identity creation failed"}
    else:
        confirmed = deny_identity.put_inline_policy("lambda-deny", policy([
            statement("Allow", "lambda:GetFunctionConfiguration", function_arn),
            statement("Deny", "lambda:GetFunctionConfiguration", function_arn),
        ]))
        outcome = CallOutcome.capture("lambda", "GetFunctionConfiguration",
                                      lambda c: c.get_function_configuration(
                                          FunctionName=name),
                                      deny_identity.client("lambda"))
        authz["explicit_deny"] = matrix.record(
            "LM-C", "lambda:GetFunctionConfiguration", "lambda", "iam-user-deny",
            deny_identity.arn, function_arn, "deny", outcome, state_changed=False,
            policy_confirmed=confirmed, signals=["lambda_deny"])
        availability["lambda_deny_observed"] = authz["explicit_deny"]["classification"]
        deny_identity.delete()

    deleted = CallOutcome.capture("lambda", "DeleteFunction", lambda c: c.delete_function(
        FunctionName=name), lambda_client)
    operations["DeleteFunction"] = deleted.to_dict()
    gone = CallOutcome.capture("lambda", "GetFunctionConfiguration",
                               lambda c: c.get_function_configuration(FunctionName=name),
                               lambda_client)
    operations["FunctionGoneAfterDelete"] = {
        "operation": "GetFunctionConfiguration", "ok": not gone.ok,
        "observed_error_code": gone.error_code}
    CallOutcome.capture("iam", "DeleteRole", lambda c: c.delete_role(RoleName=name))

    signals["lambda"] = availability
    return {"available": True, "operations": operations, "authorization": authz,
            "gaps": gaps, "enforcement_signals": signals}


def _role(floci, name):
    from ..authz import policy as _policy
    from ..authz import statement as _statement

    iam = floci.client("iam")
    trust = _policy([_statement("Allow", "sts:AssumeRole", "*")])
    CallOutcome.capture("iam", "DeleteRole", lambda c: c.delete_role(RoleName=name))
    created = CallOutcome.capture("iam", "CreateRole", lambda c: c.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust))
    if not created.ok:
        return None
    return f"arn:aws:iam::{floci.account}:role/{name}"


def _capture(client, operation, func):
    service = client.meta.service_model.service_name
    return CallOutcome.capture(service, operation, func, client).to_dict()