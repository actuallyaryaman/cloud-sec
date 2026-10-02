__all__ = [
    "SeedExecution",
    "SeedResult",
    "SeedOutcome",
    "MutationClass",
    "MutationRecord",
    "observe",
    "LambdaStatus",
    "SetupStateError",
    "ResourceRecord",
    "SCENARIO_FILENAME",
    "SECRET_PLAINTEXT",
    "LAMBDA_RUNTIME",
    "LAMBDA_HANDLER",
    "INCIDENT_POLICY_NAME",
    "INVESTIGATOR_POLICY_NAME",
    "incident_policy_document",
    "investigator_policy_document",
    "lambda_configuration",
    "object_bodies",
    "evidence_control_document",
    "lambda_package",
    "evidence_object_name",
    "evidence_object_body",
    "seed_scenario",
    "seed_scenario_with_runtime",
    "seed_canonical_scenario",
    "incident_bucket_arn",
    "evidence_bucket_arn",
    "trail_bucket_arn",
    "secret_logical_arn",
    "incident_user_arn",
    "investigator_user_arn",
]

import io
import json
import zipfile
from dataclasses import asdict, dataclass, field

from .credentials import IncidentRuntimeCredential
from .determinism import RESOURCES
from .manifest import register_manifest_secret

SCENARIO_FILENAME = "csi-incident-v1"
INCIDENT_POLICY_NAME = RESOURCES.incident_policy
INVESTIGATOR_POLICY_NAME = "csi-investigator-readonly"
INCIDENT_POLICY_DOCUMENT = "csi-incident-scout.json"
LAMBDA_RUNTIME = "python3.13"
LAMBDA_HANDLER = "handler.main"
LAMBDA_CODE = "def main(event, context):\n    return {'statusCode': 200}\n"
LAMBDA_TIMEOUT = 10
SECRET_PLAINTEXT = "synthetic-production-credential-do-not-use"

CLASSIFICATION_INTERNAL = "internal"


class SeedOutcome:
    CREATED = "created"
    PRE_EXISTING = "pre_existing"
    FAILED = "failed"
    SKIPPED = "skipped"


class LambdaStatus:
    NOT_ATTEMPTED = "not_attempted"
    CREATED = "created"
    PRE_EXISTING = "pre_existing"
    FAILED = "failed"


class SetupStateError(RuntimeError):
    pass


def _access_key_payload(call):
    payload = (call.raw or {}).get("AccessKey") or {}
    access_key_id = payload.get("AccessKeyId")
    secret_access_key = payload.get("SecretAccessKey")
    if not access_key_id or not secret_access_key:
        raise SetupStateError(
            "CreateAccessKey returned success without an access key payload; "
            "refusing to record an unverifiable credential")
    return access_key_id, secret_access_key


@dataclass
class ResourceRecord:
    kind: str
    name: str
    identifier: str | None = None
    outcome: str = SeedOutcome.CREATED
    detail: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


class MutationClass:
    CONFIRMED = "CONFIRMED"
    API_ERROR = "API_ERROR"
    EMPTY_SUCCESS = "EMPTY_SUCCESS"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class MutationRecord:
    operation: str
    resource_type: str
    resource_id: str
    http_status: int | None = None
    request_id: str | None = None
    response_keys: tuple = ()
    expected_payload_present: bool | None = None
    readback_performed: bool = False
    readback_ok: bool | None = None
    readback_detail: str | None = None
    classification: str = MutationClass.INCONCLUSIVE
    error_code: str | None = None
    required: bool = True
    access_key_id: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        return (f"{self.classification:<14} {self.operation:<18} "
                f"{self.resource_id:<46} status={self.http_status} "
                f"payload={self.expected_payload_present} "
                f"readback={self.readback_ok} err={self.error_code}")


def _keys(call) -> tuple:
    return tuple(sorted(k for k in (call.raw or {}) if k != "ResponseMetadata"))


def observe(result, call, resource_type, resource_id, readback,
            expected_payload=None, required=True, access_key_id=None):
    ok = bool(call.ok)
    raw = call.raw or {}
    payload_present = (expected_payload in raw) if expected_payload else None
    if not ok:
        classification = MutationClass.API_ERROR
        readback_ok = None
        readback_detail = None
    else:
        readback_ok, readback_detail = readback()
        if expected_payload and payload_present is not True:
            classification = MutationClass.EMPTY_SUCCESS
        elif readback_ok:
            classification = MutationClass.CONFIRMED
        else:
            classification = MutationClass.EMPTY_SUCCESS
    record = MutationRecord(
        operation=call.operation,
        resource_type=resource_type,
        resource_id=resource_id,
        http_status=raw.get("ResponseMetadata", {}).get("HTTPStatusCode") or call.status,
        request_id=raw.get("ResponseMetadata", {}).get("RequestId") or call.request_id,
        response_keys=_keys(call),
        expected_payload_present=payload_present,
        readback_performed=ok,
        readback_ok=readback_ok,
        readback_detail=readback_detail,
        classification=classification,
        error_code=call.error_code,
        required=required,
        access_key_id=access_key_id,
    )
    result.mutations.append(record)
    if record.classification in (MutationClass.EMPTY_SUCCESS,
                                 MutationClass.API_ERROR) and required:
        result.fatal_errors.append(
            f"{record.classification} at {record.operation} on {resource_id}: "
            f"error={record.error_code} readback={record.readback_detail}")
        result.divergence = record
    return record


@dataclass
class SeedExecution:
    result: object
    incident_credential: object = field(repr=False, default=None)

    def __repr__(self) -> str:
        credential = self.incident_credential
        access_key_id = credential.access_key_id if credential else None
        return (f"SeedExecution(result={type(self.result).__name__}, "
                f"incident_credential={access_key_id!r})")

    __str__ = __repr__


@dataclass
class SeedResult:
    scenario_id: str
    endpoint: str
    flavour_contract: str = "endpoint-identity:4567"
    account: str | None = None
    incident_access_key_id: str | None = None
    investigator_access_key_id: str | None = None
    secret_id: str | None = None
    secret_logical_name: str = RESOURCES.secret_name
    resources: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    fatal_errors: list = field(default_factory=list)
    lambda_status: str = LambdaStatus.NOT_ATTEMPTED
    mutations: list = field(default_factory=list)
    divergence: object = None

    def record(self, kind: str, name: str, identifier=None, outcome=None, detail=None):
        entry = ResourceRecord(kind=kind, name=name, identifier=identifier,
                               outcome=outcome or SeedOutcome.CREATED, detail=detail)
        self.resources.append(entry)
        return entry

    def created(self) -> list:
        return [item.name for item in self.resources
                if item.outcome == SeedOutcome.CREATED]

    def pre_existing(self) -> list:
        return [item.name for item in self.resources
                if item.outcome == SeedOutcome.PRE_EXISTING]

    def as_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "endpoint": self.endpoint,
            "flavour_contract": self.flavour_contract,
            "account": self.account,
            "principal": {
                "incident_user": RESOURCES.incident_user,
                "incident_access_key_id": self.incident_access_key_id,
                "investigator_user": RESOURCES.investigator_user,
                "investigator_access_key_id": self.investigator_access_key_id,
            },
            "secret": {
                "logical_name": self.secret_logical_name,
                "secret_id": self.secret_id,
            },
            "resources": [item.as_dict() for item in self.resources],
            "created": self.created(),
            "pre_existing": self.pre_existing(),
            "lambda_status": self.lambda_status,
            "mutations": [item.as_dict() for item in self.mutations],
            "first_divergence": (self.divergence.as_dict()
                                 if self.divergence is not None else None),
            "gaps": list(self.gaps),
            "fatal_errors": list(self.fatal_errors),
        }


def incident_bucket_arn() -> str:
    return f"arn:aws:s3:::{RESOURCES.incident_bucket}"


def evidence_bucket_arn() -> str:
    return f"arn:aws:s3:::{RESOURCES.evidence_bucket}"


def trail_bucket_arn() -> str:
    return f"arn:aws:s3:::{RESOURCES.trail_bucket}"


def secret_logical_arn() -> str:
    return (f"arn:aws:secretsmanager:us-east-1:000000000000:secret:"
            f"{RESOURCES.secret_name}")


def incident_user_arn() -> str:
    return f"arn:aws:iam::000000000000:user/{RESOURCES.incident_user}"


def investigator_user_arn() -> str:
    return f"arn:aws:iam::000000000000:user/{RESOURCES.investigator_user}"


def _statement(effect, actions, resources):
    return {
        "Effect": effect,
        "Action": actions if isinstance(actions, list) else [actions],
        "Resource": resources if isinstance(resources, list) else [resources],
    }


def incident_policy_document() -> str:
    bucket = incident_bucket_arn()
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            _statement("Allow", "s3:GetObject", f"{bucket}/reports/*"),
            _statement("Allow", "s3:GetObject", f"{bucket}/notes/*"),
            _statement("Allow", ["s3:ListBucket", "s3:GetBucketLocation"], bucket),
            _statement("Deny", "s3:GetObject", f"{bucket}/restricted/*"),
        ],
    }, sort_keys=True)


def investigator_policy_document() -> str:
    incident = incident_bucket_arn()
    evidence = evidence_bucket_arn()
    trail = trail_bucket_arn()
    log_arn = (f"arn:aws:logs:us-east-1:000000000000:log-group:{RESOURCES.log_group}:*")
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            _statement("Allow", "s3:GetObject",
                       [f"{evidence}/*", f"{trail}/*", f"{incident}/reports/*",
                        f"{incident}/notes/*", f"{incident}/restricted/*"]),
            _statement("Allow", ["s3:ListBucket", "s3:GetBucketTagging"],
                       [evidence, trail, incident]),
            _statement("Allow", ["logs:FilterLogEvents", "logs:GetLogEvents"], log_arn),
            _statement("Allow", "lambda:GetFunctionConfiguration",
                       f"arn:aws:lambda:us-east-1:000000000000:function:"
                       f"{RESOURCES.function_name}"),
            _statement("Allow", "secretsmanager:DescribeSecret", secret_logical_arn()),
            _statement("Allow", ["iam:GetUser", "iam:ListAccessKeys",
                                 "iam:GetUserPolicy", "iam:ListUserPolicies"],
                       incident_user_arn()),
        ],
    }, sort_keys=True)


def object_bodies() -> dict:
    return {
        RESOURCES.baseline_object: (
            "Quarterly reporting summary.\n"
            "Owner: finance-analytics.\n"
            f"Classification: {CLASSIFICATION_INTERNAL}.\n"
            "Status: reviewed.\n"
        ),
        RESOURCES.notes_object: (
            "Reporting handoff notes.\n"
            "Check the quarterly summary before the next reporting cycle.\n"
            "No containment action is required from this file.\n"
        ),
        RESOURCES.restricted_object: (
            "account_id,status\n"
            "synthetic-001,restricted\n"
            "synthetic-002,restricted\n"
        ),
    }


def evidence_control_document() -> str:
    return json.dumps({
        "scenario": "csi-incident-v1",
        "purpose": "synthetic evidence control object",
    }, indent=2, sort_keys=True) + "\n"


def lambda_configuration() -> dict:
    return {
        "function_name": RESOURCES.function_name,
        "description": f"Synthetic reporting scheduler for {SCENARIO_FILENAME}",
        "runtime": LAMBDA_RUNTIME,
        "handler": LAMBDA_HANDLER,
        "timeout": LAMBDA_TIMEOUT,
        "environment": {
            "CSI_OWNER": "finance-analytics",
            "CSI_ENV": "synthetic",
            "CSI_SCENARIO": SCENARIO_FILENAME,
        },
    }


def lambda_package() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("handler.py", LAMBDA_CODE)
    return buffer.getvalue()


def evidence_object_name() -> str:
    return RESOURCES.evidence_index_object


def evidence_object_body(bucket: str) -> str:
    return json.dumps({
        "scenario": SCENARIO_FILENAME,
        "evidence_bucket": bucket,
        "generated_by": "cloudsec_agent.scenario.seed",
    }, indent=2, sort_keys=True) + "\n"



def _outcome(call, name: str, kind: str) -> object:
    if call.ok:
        return SeedOutcome.CREATED
    if call.error_code in {"NoSuchEntity", "NoSuchEntityException", "404"}:
        return None
    return call


def seed_scenario(floci, scenario_id: str) -> SeedResult:
    return _seed_scenario_impl(floci, scenario_id, capture_runtime=False)


def seed_scenario_with_runtime(floci, scenario_id: str) -> SeedExecution:
    return _seed_scenario_impl(floci, scenario_id, capture_runtime=True)


def _finish(result, incident_credential, capture_runtime):
    if capture_runtime and incident_credential is not None:
        return SeedExecution(result=result, incident_credential=incident_credential)
    return result


def _seed_scenario_impl(floci, scenario_id: str, capture_runtime: bool):
    from ..result import CallOutcome

    result = SeedResult(scenario_id=scenario_id, endpoint=floci.endpoint,
                        account=floci.account)
    register_manifest_secret(SECRET_PLAINTEXT)

    s3 = floci.client("s3")
    iam = floci.client("iam")
    logs = floci.client("logs")
    sm = floci.client("secretsmanager")
    lambda_client = floci.client("lambda")
    cloudtrail = floci.client("cloudtrail")

    def halted() -> bool:
        return result.divergence is not None

    def bucket_readback(bucket):
        def run():
            listed = CallOutcome.capture("s3", "ListBuckets",
                                         lambda c: c.list_buckets(), s3)
            visible = any(item["Name"] == bucket
                          for item in (listed.raw or {}).get("Buckets", []))
            head = CallOutcome.capture("s3", "HeadBucket",
                                       lambda c: c.head_bucket(Bucket=bucket), s3)
            return bool(visible and head.ok), (
                f"list_buckets_visible={visible} head_bucket={head.ok}")
        return run

    def object_readback(bucket, key):
        def run():
            head = CallOutcome.capture("s3", "HeadObject",
                                       lambda c: c.head_object(Bucket=bucket, Key=key),
                                       s3)
            return bool(head.ok), f"head_object={head.ok} err={head.error_code}"
        return run

    for bucket in (RESOURCES.incident_bucket, RESOURCES.evidence_bucket,
                   RESOURCES.trail_bucket):
        head = CallOutcome.capture("s3", "HeadBucket",
                                   lambda c, b=bucket: c.head_bucket(Bucket=b), s3)
        if head.ok:
            result.record("s3-bucket", bucket, bucket, SeedOutcome.PRE_EXISTING,
                          "head_bucket succeeded before seeding")
            continue
        made = CallOutcome.capture("s3", "CreateBucket",
                                   lambda c, b=bucket: c.create_bucket(Bucket=b), s3)
        observe(result, made, "s3-bucket", bucket, bucket_readback(bucket),
                expected_payload="Location")
        if halted():
            return _finish(result, incident_credential, capture_runtime)
        result.record("s3-bucket", bucket, bucket, SeedOutcome.CREATED)

    incident_bucket_exists = any(
        item.kind == "s3-bucket" and item.name == RESOURCES.incident_bucket
        for item in result.resources)

    bodies = dict(object_bodies())
    for key, body in bodies.items():
        if not incident_bucket_exists and key in (
                RESOURCES.baseline_object, RESOURCES.notes_object,
                RESOURCES.restricted_object):
            continue
        put = CallOutcome.capture("s3", "PutObject", lambda c, k=key, v=body: c.put_object(
            Bucket=RESOURCES.incident_bucket, Key=k, Body=v.encode("utf-8")), s3)
        observe(result, put, "s3-object", f"{RESOURCES.incident_bucket}/{key}",
                object_readback(RESOURCES.incident_bucket, key), expected_payload="ETag")
        if halted():
            return _finish(result, incident_credential, capture_runtime)
        result.record("s3-object", key, f"{RESOURCES.incident_bucket}/{key}",
                      SeedOutcome.CREATED)

    control_key = evidence_object_name()
    put_control = CallOutcome.capture("s3", "PutObject", lambda c: c.put_object(
        Bucket=RESOURCES.evidence_bucket, Key=control_key,
        Body=evidence_control_document().encode("utf-8")), s3)
    observe(result, put_control, "s3-object",
            f"{RESOURCES.evidence_bucket}/{control_key}",
            object_readback(RESOURCES.evidence_bucket, control_key),
            expected_payload="ETag")
    if halted():
        return _finish(result, incident_credential, capture_runtime)
    result.record("s3-object", control_key,
                  f"{RESOURCES.evidence_bucket}/{control_key}",
                  SeedOutcome.CREATED)

    if incident_bucket_exists:
        tagged = CallOutcome.capture("s3", "PutBucketTagging",
                                     lambda c: c.put_bucket_tagging(
                                         Bucket=RESOURCES.incident_bucket,
                                         Tagging={"TagSet": [{
                                             "Key": "REPORT_TAG",
                                             "Value": "csi-owned"}]}), s3)

        def tag_readback():
            got = CallOutcome.capture("s3", "GetBucketTagging",
                                      lambda c: c.get_bucket_tagging(
                                          Bucket=RESOURCES.incident_bucket), s3)
            pairs = {item["Key"]: item["Value"]
                     for item in (got.raw or {}).get("TagSet", [])}
            return pairs.get("REPORT_TAG") == "csi-owned", f"tags={pairs}"
        observe(result, tagged, "s3-bucket-tag", RESOURCES.incident_bucket,
                tag_readback)
        if halted():
            return _finish(result, incident_credential, capture_runtime)
        result.record("s3-bucket-tag", RESOURCES.incident_bucket,
                      "REPORT_TAG=csi-owned", SeedOutcome.CREATED)

    incident_credential = _seed_user(
        result, iam, RESOURCES.incident_user, INCIDENT_POLICY_NAME,
        incident_policy_document(), incident_user_arn(),
        "incident_access_key_id", halted, capture_runtime)
    if halted():
        return _finish(result, incident_credential, capture_runtime)

    _seed_user(result, iam, RESOURCES.investigator_user, INVESTIGATOR_POLICY_NAME,
               investigator_policy_document(), investigator_user_arn(),
               "investigator_access_key_id", halted, capture_runtime)
    if halted():
        return _finish(result, incident_credential, capture_runtime)

    described = CallOutcome.capture("secretsmanager", "DescribeSecret",
                                    lambda c: c.describe_secret(
                                        SecretId=RESOURCES.secret_name), sm)
    if described.ok:
        result.record("secret", RESOURCES.secret_name, described.raw.get("ARN"),
                      SeedOutcome.PRE_EXISTING,
                      "deterministic secret name already present; "
                      "recovery-window handling is M1D work")
        result.secret_id = described.raw.get("ARN")
        result.fatal_errors.append(
            f"secret {RESOURCES.secret_name} already exists; M1D reset work required "
            f"before a clean canonical seed is possible")
        result.divergence = MutationRecord(
            operation="DescribeSecret", resource_type="secret",
            resource_id=RESOURCES.secret_name,
            readback_performed=True, readback_ok=True,
            classification=MutationClass.API_ERROR,
            error_code="ResourceAlreadyExists")
        return _finish(result, incident_credential, capture_runtime)

    created = CallOutcome.capture("secretsmanager", "CreateSecret",
                                  lambda c: c.create_secret(
                                      Name=RESOURCES.secret_name,
                                      SecretString=SECRET_PLAINTEXT,
                                      Description="Synthetic production-like "
                                                  "credential for csi-incident-v1"), sm)

    def secret_readback():
        got = CallOutcome.capture("secretsmanager", "DescribeSecret",
                                  lambda c: c.describe_secret(
                                      SecretId=RESOURCES.secret_name), sm)
        return bool(got.ok), f"describe={got.ok} err={got.error_code}"
    observe(result, created, "secret", RESOURCES.secret_name, secret_readback,
            expected_payload="ARN")
    if halted():
        return _finish(result, incident_credential, capture_runtime)
    result.secret_id = (created.raw or {}).get("ARN")
    result.record("secret", RESOURCES.secret_name, result.secret_id,
                  SeedOutcome.CREATED)

    group = CallOutcome.capture("logs", "CreateLogGroup",
                                lambda c: c.create_log_group(
                                    logGroupName=RESOURCES.log_group), logs)

    def group_readback():
        got = CallOutcome.capture("logs", "DescribeLogGroups",
                                  lambda c: c.describe_log_groups(), logs)
        names = [item["logGroupName"]
                 for item in (got.raw or {}).get("logGroups", [])]
        return RESOURCES.log_group in names, f"groups={names}"
    observe(result, group, "log-group", RESOURCES.log_group, group_readback,
            expected_payload=None)
    if halted():
        return _finish(result, incident_credential, capture_runtime)
    result.record("log-group", RESOURCES.log_group, RESOURCES.log_group,
                  SeedOutcome.CREATED)

    stream = CallOutcome.capture("logs", "CreateLogStream",
                                 lambda c: c.create_log_stream(
                                     logGroupName=RESOURCES.log_group,
                                     logStreamName=RESOURCES.log_stream), logs)

    def stream_readback():
        got = CallOutcome.capture("logs", "DescribeLogStreams",
                                  lambda c: c.describe_log_streams(
                                      logGroupName=RESOURCES.log_group), logs)
        names = [item["logStreamName"]
                 for item in (got.raw or {}).get("logStreams", [])]
        return RESOURCES.log_stream in names, f"streams={names}"
    observe(result, stream, "log-stream", RESOURCES.log_stream, stream_readback,
            expected_payload=None)
    if halted():
        return _finish(result, incident_credential, capture_runtime)
    result.record("log-stream", RESOURCES.log_stream,
                  f"{RESOURCES.log_group}/{RESOURCES.log_stream}",
                  SeedOutcome.CREATED)

    configuration = lambda_configuration()
    existing = CallOutcome.capture("lambda", "GetFunctionConfiguration",
                                   lambda c: c.get_function_configuration(
                                       FunctionName=configuration["function_name"]),
                                   lambda_client)
    if existing.ok:
        result.lambda_status = LambdaStatus.PRE_EXISTING
        result.record("lambda", configuration["function_name"], None,
                      SeedOutcome.PRE_EXISTING, "function already exists")
    else:
        role = f"arn:aws:iam::{floci.account}:role/{RESOURCES.function_name}-role"
        CallOutcome.capture("iam", "CreateRole", lambda c: c.create_role(
            RoleName=f"{RESOURCES.function_name}-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                               "Resource": "*"}]})), iam)
        made = CallOutcome.capture("lambda", "CreateFunction", lambda c: c.create_function(
            FunctionName=configuration["function_name"],
            Runtime=configuration["runtime"], Role=role,
            Handler=configuration["handler"],
            Code={"ZipFile": lambda_package()},
            Description=configuration["description"],
            Environment={"Variables": configuration["environment"]},
            Timeout=configuration["timeout"]), lambda_client)

        def function_readback():
            got = CallOutcome.capture("lambda", "GetFunctionConfiguration",
                                      lambda c: c.get_function_configuration(
                                          FunctionName=configuration["function_name"]),
                                      lambda_client)
            variables = (got.raw or {}).get("Environment", {}).get("Variables", {})
            return (bool(got.ok) and variables == configuration["environment"],
                    f"get_function_configuration={got.ok} env={variables}")
        record = observe(result, made, "lambda", configuration["function_name"],
                         function_readback, expected_payload="FunctionArn",
                         required=False)
        if record.classification == MutationClass.CONFIRMED:
            result.lambda_status = LambdaStatus.CREATED
            result.record("lambda", configuration["function_name"],
                          (made.raw or {}).get("FunctionArn"), SeedOutcome.CREATED)
        else:
            result.lambda_status = LambdaStatus.FAILED
            result.gaps.append(
                f"Lambda CreateFunction not confirmed "
                f"({record.classification}); treated as an M1C gap")

    trail = CallOutcome.capture("cloudtrail", "CreateTrail", lambda c: c.create_trail(
        Name=RESOURCES.trail_name, S3BucketName=RESOURCES.trail_bucket,
        IsMultiRegionTrail=False, IncludeGlobalServiceEvents=False), cloudtrail)

    def trail_readback():
        got = CallOutcome.capture("cloudtrail", "DescribeTrails",
                                  lambda c: c.describe_trails(
                                      trailNameList=[RESOURCES.trail_name]),
                                  cloudtrail)
        names = [item.get("Name")
                 for item in (got.raw or {}).get("trailList", [])]
        return RESOURCES.trail_name in names, f"trails={names}"
    record = observe(result, trail, "cloudtrail", RESOURCES.trail_name,
                     trail_readback, expected_payload="TrailARN", required=False)
    if record.classification == MutationClass.CONFIRMED:
        CallOutcome.capture("cloudtrail", "PutEventSelectors", lambda c: (
            c.put_event_selectors(
                TrailName=RESOURCES.trail_name,
                EventSelectors=[{"ReadWriteType": "All",
                                 "IncludeManagementEvents": True,
                                 "DataResources": [{
                                     "Type": "AWS::S3::Object",
                                     "Values": [f"{incident_bucket_arn()}/",
                                                f"{evidence_bucket_arn()}/"]}]}])),
            cloudtrail)
        started = CallOutcome.capture("cloudtrail", "StartLogging",
                                      lambda c: c.start_logging(
                                          Name=RESOURCES.trail_name), cloudtrail)
        result.record("cloudtrail", RESOURCES.trail_name,
                      (trail.raw or {}).get("TrailARN"),
                      SeedOutcome.CREATED if started.ok else SeedOutcome.PRE_EXISTING,
                      "optional corroboration" if started.ok else
                      f"StartLogging unconfirmed: {started.error_code}")
        if not started.ok:
            result.gaps.append(
                "CloudTrail StartLogging was not confirmed; native corroboration "
                "is optional and was not awaited")
    else:
        result.gaps.append(
            f"CloudTrail CreateTrail not confirmed ({record.classification}); "
            f"corroboration is optional")

    return _finish(result, incident_credential, capture_runtime)


def _seed_user(result, iam, user_name, policy_name, document, arn, key_field,
               halted, capture_runtime: bool = False):
    from ..result import CallOutcome

    created = CallOutcome.capture("iam", "CreateUser",
                                  lambda c: c.create_user(UserName=user_name), iam)

    def user_readback():
        got = CallOutcome.capture("iam", "GetUser",
                                  lambda c: c.get_user(UserName=user_name), iam)
        return bool(got.ok), f"get_user={got.ok} err={got.error_code}"
    user_record = observe(result, created, "iam-user", user_name, user_readback,
                          expected_payload="User")
    if user_record.classification in (MutationClass.EMPTY_SUCCESS,
                                      MutationClass.API_ERROR):
        return
    result.record("iam-user", user_name, arn, SeedOutcome.CREATED)

    put_policy = CallOutcome.capture("iam", "PutUserPolicy", lambda c: c.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=document), iam)

    def policy_readback():
        got = CallOutcome.capture("iam", "GetUserPolicy",
                                  lambda c: c.get_user_policy(
                                      UserName=user_name, PolicyName=policy_name), iam)
        if not got.ok:
            return False, f"get_user_policy={got.ok} err={got.error_code}"
        stored = (got.raw or {}).get("PolicyDocument")
        matches = (isinstance(stored, dict)
                   and stored.get("Statement") == json.loads(document)["Statement"])
        return bool(matches), f"statement_match={matches}"
    observe(result, put_policy, "iam-inline-policy", policy_name, policy_readback,
            expected_payload=None)
    if halted():
        return
    result.record("iam-inline-policy", policy_name, arn, SeedOutcome.CREATED)

    made_key = CallOutcome.capture("iam", "CreateAccessKey", lambda c: c.create_access_key(
        UserName=user_name), iam)
    payload = (made_key.raw or {}).get("AccessKey") or {}
    key_id = payload.get("AccessKeyId")
    secret_value = payload.get("SecretAccessKey")
    if secret_value:
        register_manifest_secret(secret_value)

    def key_readback():
        got = CallOutcome.capture("iam", "ListAccessKeys",
                                  lambda c: c.list_access_keys(UserName=user_name), iam)
        ids = [item["AccessKeyId"]
               for item in (got.raw or {}).get("AccessKeyMetadata", [])]
        return (bool(key_id) and key_id in ids), f"listed={ids}"
    key_record = observe(result, made_key, "iam-access-key", user_name, key_readback,
                         expected_payload="AccessKey", access_key_id=key_id)
    if halted():
        return None
    setattr(result, key_field, key_id)
    if not capture_runtime or key_field != "incident_access_key_id":
        return None
    if key_record.classification != MutationClass.CONFIRMED:
        return None
    if not key_id or not secret_value:
        return None
    return IncidentRuntimeCredential(access_key_id=key_id,
                                    secret_access_key=secret_value)
    result.record("iam-access-key", user_name, key_id, SeedOutcome.CREATED,
                  "secret retained in process memory only")


def seed_canonical_scenario(floci, scenario_id: str) -> SeedResult:
    from ..floci_client import EndpointUnavailable
    from .determinism import (assert_canonical_endpoint, CANONICAL_ENDPOINT,
                              SCENARIO_FLAVOUR)

    assert_canonical_endpoint(floci.endpoint)
    if floci.endpoint.rstrip("/") != CANONICAL_ENDPOINT:
        raise SetupStateError(
            f"refusing to seed {floci.endpoint}; canonical is {CANONICAL_ENDPOINT}")
    floci.health()
    floci.describe_identity()
    result = seed_scenario(floci, scenario_id)
    result.flavour_contract = (f"endpoint-identity:{CANONICAL_ENDPOINT}; "
                               f"declared={SCENARIO_FLAVOUR}; "
                               f"iam_enforcement_flag_introspected=false")
    if result.fatal_errors:
        raise SetupStateError(
            "canonical scenario seed failed: " + "; ".join(result.fatal_errors))
    return result
