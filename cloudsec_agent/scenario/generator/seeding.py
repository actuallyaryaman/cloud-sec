__all__ = [
    "GeneratedSeedResult",
    "seed_generated",
]

from dataclasses import dataclass, field

from ..seed import (LAMBDA_CODE, LAMBDA_HANDLER, LAMBDA_RUNTIME,
                    SECRET_PLAINTEXT, investigator_policy_document,
                    lambda_package)
from .families import incident_policy_for


@dataclass
class GeneratedSeedResult:
    scenario_id: str
    created_key_ids: object = None
    outcomes: object = ()
    fatal_errors: object = ()

    def __post_init__(self):
        object.__setattr__(self, "created_key_ids",
                            dict(self.created_key_ids or {}))
        object.__setattr__(self, "outcomes", tuple(self.outcomes or ()))
        object.__setattr__(self, "fatal_errors",
                            tuple(self.fatal_errors or ()))

    @property
    def ok(self) -> bool:
        return not self.fatal_errors


def _fail(errors, message):
    errors.append(message)
    return None


def seed_generated(floci, spec):
    from ...result import CallOutcome
    errors = []
    outcomes = []
    keys = {}

    def run(service, operation, func):
        outcome = CallOutcome.capture(service, operation, func,
                                      floci.client(service))
        outcomes.append((service, operation, outcome.ok))
        if not outcome.ok:
            _fail(errors,
                  f"{service}.{operation}: {outcome.error_code}")
            return None
        return outcome.raw or {}

    iam = floci.client("iam")
    for user in (spec.incident_user, spec.investigator_user):
        created = CallOutcome.capture(
            "iam", "CreateUser", lambda c, u=user: c.create_user(
                UserName=u), iam)
        outcomes.append(("iam", "CreateUser", created.ok))
        if not created.ok:
            _fail(errors, f"iam.CreateUser {user}: {created.error_code}")
            return GeneratedSeedResult(spec.scenario_id, keys, outcomes,
                                       errors)
        made = CallOutcome.capture(
            "iam", "CreateAccessKey", lambda c, u=user: c.create_access_key(
                UserName=u), iam)
        outcomes.append(("iam", "CreateAccessKey", made.ok))
        payload = (made.raw or {}).get("AccessKey") or {}
        if not made.ok or not payload.get("AccessKeyId"):
            _fail(errors, f"iam.CreateAccessKey {user}")
            return GeneratedSeedResult(spec.scenario_id, keys, outcomes,
                                       errors)
        keys[user] = payload["AccessKeyId"]
    document = incident_policy_for(spec.bucket, spec.log_group)
    policy = CallOutcome.capture(
        "iam", "PutUserPolicy", lambda c: c.put_user_policy(
            UserName=spec.incident_user, PolicyName=spec.incident_policy,
            PolicyDocument=document), iam)
    outcomes.append(("iam", "PutUserPolicy", policy.ok))
    if not policy.ok:
        _fail(errors, f"iam.PutUserPolicy: {policy.error_code}")
    investigator = CallOutcome.capture(
        "iam", "PutUserPolicy", lambda c: c.put_user_policy(
            UserName=spec.investigator_user,
            PolicyName="m7a-investigator-readonly",
            PolicyDocument=investigator_policy_document()), iam)
    outcomes.append(("iam", "PutUserPolicy-investigator", investigator.ok))
    if not investigator.ok:
        _fail(errors, f"investigator policy: {investigator.error_code}")
    s3 = floci.client("s3")
    made_bucket = CallOutcome.capture(
        "s3", "CreateBucket",
        lambda c: c.create_bucket(Bucket=spec.bucket), s3)
    outcomes.append(("s3", "CreateBucket", made_bucket.ok))
    if not made_bucket.ok:
        _fail(errors, f"s3.CreateBucket: {made_bucket.error_code}")
        return GeneratedSeedResult(spec.scenario_id, keys, outcomes,
                                   errors)
    for item in spec.objects:
        put = CallOutcome.capture(
            "s3", "PutObject", lambda c, k=item.key, v=item.body: (
                c.put_object(Bucket=spec.bucket, Key=k,
                             Body=v.encode("utf-8"))), s3)
        outcomes.append(("s3", "PutObject", put.ok))
        if not put.ok:
            _fail(errors, f"s3.PutObject {item.key}: {put.error_code}")
    sm = floci.client("secretsmanager")
    secret = CallOutcome.capture(
        "secretsmanager", "CreateSecret", lambda c: c.create_secret(
            Name=spec.secret_name, SecretString=SECRET_PLAINTEXT), sm)
    outcomes.append(("secretsmanager", "CreateSecret", secret.ok))
    if not secret.ok:
        _fail(errors, f"secretsmanager.CreateSecret: {secret.error_code}")
    logs = floci.client("logs")
    group = CallOutcome.capture(
        "logs", "CreateLogGroup",
        lambda c: c.create_log_group(logGroupName=spec.log_group), logs)
    outcomes.append(("logs", "CreateLogGroup", group.ok))
    stream = CallOutcome.capture(
        "logs", "CreateLogStream",
        lambda c: c.create_log_stream(logGroupName=spec.log_group,
                                      logStreamName=spec.log_stream), logs)
    outcomes.append(("logs", "CreateLogStream", stream.ok))
    if group.ok and stream.ok:
        import json
        messages = []
        for event in spec.log_events:
            payload = dict(event.message())
            if event.key_ref == "incident":
                payload["actor_access_key_id"] = keys.get(
                    spec.incident_user)
            messages.append({"message": json.dumps(payload,
                                                   sort_keys=True)})
        put = CallOutcome.capture(
            "logs", "PutLogEvents", lambda c: c.put_log_events(
                logGroupName=spec.log_group,
                logStreamName=spec.log_stream,
                logEvents=[{"timestamp": 0, "message": item["message"]}
                           for item in messages]), logs)
        outcomes.append(("logs", "PutLogEvents", put.ok))
        if not put.ok:
            _fail(errors, f"logs.PutLogEvents: {put.error_code}")
    lambda_client = floci.client("lambda")
    role = f"arn:aws:iam::000000000000:role/{spec.function_name}-role"
    made_role = CallOutcome.capture(
        "iam", "CreateRole", lambda c: c.create_role(
            RoleName=f"{spec.function_name}-role",
            AssumeRolePolicyDocument="{}"), iam)
    outcomes.append(("iam", "CreateRole", made_role.ok))
    made_function = CallOutcome.capture(
        "lambda", "CreateFunction", lambda c: c.create_function(
            FunctionName=spec.function_name, Runtime=LAMBDA_RUNTIME,
            Role=role, Handler=LAMBDA_HANDLER,
            Code={"ZipFile": lambda_package()},
            Description="m7a generated function",
            Environment={"Variables": {}}, Timeout=10), lambda_client)
    outcomes.append(("lambda", "CreateFunction", made_function.ok))
    if not made_function.ok:
        _fail(errors,
              f"lambda.CreateFunction: {made_function.error_code}")
    return GeneratedSeedResult(spec.scenario_id, keys, outcomes, errors)
