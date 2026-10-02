__all__ = [
    "DeleteClass",
    "DeletionRecord",
    "ResetResult",
    "OwnedResources",
    "OWNED",
    "owned_buckets",
    "owned_users",
    "is_owned",
    "reset_scenario",
    "reset_canonical_scenario",
    "DeleteDivergenceError",
    "TEMPORARY_SECRET_PLAINTEXT",
]

from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from ..result import CallOutcome
from .determinism import (CANONICAL_ENDPOINT, RESOURCES, SCENARIO_ID,
                          assert_canonical_endpoint)
from .manifest import register_manifest_secret
from .seed import (INVESTIGATOR_POLICY_NAME, INCIDENT_POLICY_NAME,
                   SECRET_PLAINTEXT, SetupStateError, lambda_configuration)

TEMPORARY_SECRET_PLAINTEXT = "synthetic-temporary-recreation-probe-do-not-use"

ALREADY_ABSENT_CODES = {
    "404", "NoSuchEntity", "NoSuchEntityException", "NoSuchBucket",
    "ResourceNotFoundException", "ResourceNotFound", "NotFound",
    "TrailNotFoundException",
}


class DeleteClass:
    CONFIRMED = "CONFIRMED"
    ALREADY_ABSENT = "ALREADY_ABSENT"
    API_ERROR = "API_ERROR"
    EMPTY_SUCCESS = "EMPTY_SUCCESS"
    INCONCLUSIVE = "INCONCLUSIVE"


class DeleteDivergenceError(SetupStateError):
    pass


@dataclass(frozen=True)
class OwnedResources:
    buckets: tuple
    users: tuple
    inline_policies: tuple
    function_name: str
    log_group: str
    secret_name: str
    trail_name: str

    def all_names(self) -> tuple:
        return (tuple(self.buckets) + tuple(self.users) + tuple(self.inline_policies)
                + (self.function_name, self.log_group, self.secret_name,
                   self.trail_name))


OWNED = OwnedResources(
    buckets=(RESOURCES.incident_bucket, RESOURCES.evidence_bucket,
             RESOURCES.trail_bucket),
    users=(RESOURCES.incident_user, RESOURCES.investigator_user),
    inline_policies=(INCIDENT_POLICY_NAME, INVESTIGATOR_POLICY_NAME),
    function_name=RESOURCES.function_name,
    log_group=RESOURCES.log_group,
    secret_name=RESOURCES.secret_name,
    trail_name=RESOURCES.trail_name,
)


def owned_buckets() -> tuple:
    return OWNED.buckets


def owned_users() -> tuple:
    return OWNED.users


def is_owned(name: str) -> bool:
    return name in OWNED.all_names()


@dataclass
class DeletionRecord:
    operation: str
    resource_type: str
    resource_id: str
    http_status: int | None = None
    request_id: str | None = None
    response_keys: tuple = ()
    readback_performed: bool = False
    absent_after: bool | None = None
    classification: str = DeleteClass.INCONCLUSIVE
    error_code: str | None = None
    required: bool = True
    access_key_id: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        return (f"{self.classification:<15} {self.operation:<20} "
                f"{self.resource_id:<52} status={self.http_status} "
                f"absent={self.absent_after} err={self.error_code}")


@dataclass
class ResetResult:
    scenario_id: str
    endpoint: str
    deletions: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    fatal_errors: list = field(default_factory=list)
    first_divergence: object = None
    secret_naming_strategy_observed: str | None = None

    def as_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "endpoint": self.endpoint,
            "secret_naming_strategy_observed": self.secret_naming_strategy_observed,
            "deletions": [item.as_dict() for item in self.deletions],
            "first_divergence": (self.first_divergence.as_dict()
                                 if self.first_divergence is not None else None),
            "confirmed": [item.resource_id for item in self.deletions
                          if item.classification == DeleteClass.CONFIRMED],
            "already_absent": [item.resource_id for item in self.deletions
                               if item.classification == DeleteClass.ALREADY_ABSENT],
            "gaps": list(self.gaps),
            "fatal_errors": list(self.fatal_errors),
        }


def _keys(call) -> tuple:
    return tuple(sorted(k for k in (call.raw or {}) if k != "ResponseMetadata"))


def _observe_delete(result, call, resource_type, resource_id, absent_check,
                    required=True, access_key_id=None):
    raw = call.raw or {}
    ok = bool(call.ok)
    already = call.error_code in ALREADY_ABSENT_CODES
    if not ok and not already:
        classification = DeleteClass.API_ERROR
        absent_after = None
    else:
        absent_after, detail = absent_check()
        if already:
            classification = (DeleteClass.ALREADY_ABSENT
                              if absent_after is not False
                              else DeleteClass.API_ERROR)
        elif absent_after:
            classification = DeleteClass.CONFIRMED
        else:
            classification = DeleteClass.EMPTY_SUCCESS
        resource_id = f"{resource_id} ({detail})"
    record = DeletionRecord(
        operation=call.operation,
        resource_type=resource_type,
        resource_id=resource_id.split(" (")[0],
        http_status=raw.get("ResponseMetadata", {}).get("HTTPStatusCode") or call.status,
        request_id=raw.get("ResponseMetadata", {}).get("RequestId") or call.request_id,
        response_keys=_keys(call),
        readback_performed=True,
        absent_after=absent_after,
        classification=classification,
        error_code=call.error_code,
        required=required,
        access_key_id=access_key_id,
    )
    result.deletions.append(record)
    if classification == DeleteClass.EMPTY_SUCCESS and required:
        result.fatal_errors.append(
            f"EMPTY_SUCCESS at {record.operation} on {record.resource_id}: "
            f"resource still present after an apparent successful delete")
        if result.first_divergence is None:
            result.first_divergence = record
    elif classification == DeleteClass.API_ERROR and required:
        result.fatal_errors.append(
            f"API_ERROR at {record.operation} on {record.resource_id}: "
            f"{record.error_code}")
    return record


def reset_scenario(floci, scenario_id: str = SCENARIO_ID) -> ResetResult:
    result = ResetResult(scenario_id=scenario_id, endpoint=floci.endpoint)
    register_manifest_secret(SECRET_PLAINTEXT)
    register_manifest_secret(TEMPORARY_SECRET_PLAINTEXT)

    s3 = floci.client("s3")
    iam = floci.client("iam")
    logs = floci.client("logs")
    sm = floci.client("secretsmanager")
    lambda_client = floci.client("lambda")
    cloudtrail = floci.client("cloudtrail")

    def trail_absent():
        got = CallOutcome.capture("cloudtrail", "DescribeTrails",
                                  lambda c: c.describe_trails(
                                      trailNameList=[OWNED.trail_name]), cloudtrail)
        names = [item.get("Name") for item in (got.raw or {}).get("trailList", [])]
        return OWNED.trail_name not in names, f"trails={names}"

    CallOutcome.capture("cloudtrail", "StopLogging",
                        lambda c: c.stop_logging(Name=OWNED.trail_name), cloudtrail)
    deleted = CallOutcome.capture("cloudtrail", "DeleteTrail",
                                  lambda c: c.delete_trail(Name=OWNED.trail_name),
                                  cloudtrail)
    _observe_delete(result, deleted, "cloudtrail", OWNED.trail_name, trail_absent,
                    required=False)

    configuration = lambda_configuration()

    def function_absent():
        got = CallOutcome.capture("lambda", "GetFunctionConfiguration",
                                  lambda c: c.get_function_configuration(
                                      FunctionName=configuration["function_name"]),
                                  lambda_client)
        return not got.ok, f"err={got.error_code}"

    del_function = CallOutcome.capture("lambda", "DeleteFunction",
                                       lambda c: c.delete_function(
                                           FunctionName=configuration["function_name"]),
                                       lambda_client)
    _observe_delete(result, del_function, "lambda", configuration["function_name"],
                    function_absent, required=False)

    def group_absent():
        got = CallOutcome.capture("logs", "DescribeLogGroups",
                                  lambda c: c.describe_log_groups(), logs)
        names = [item["logGroupName"]
                 for item in (got.raw or {}).get("logGroups", [])]
        return OWNED.log_group not in names, f"groups={names}"

    delete_group = CallOutcome.capture("logs", "DeleteLogGroup",
                                       lambda c: c.delete_log_group(
                                           logGroupName=OWNED.log_group), logs)
    _observe_delete(result, delete_group, "log-group", OWNED.log_group,
                    group_absent, required=False)

    for bucket in OWNED.buckets:
        listed = CallOutcome.capture("s3", "ListObjectsV2",
                                     lambda c, b=bucket: c.list_objects_v2(Bucket=b),
                                     s3)
        keys = [item["Key"] for item in (listed.raw or {}).get("Contents", [])]
        for key in keys:
            CallOutcome.capture("s3", "DeleteObject",
                                lambda c, b=bucket, k=key: c.delete_object(
                                    Bucket=b, Key=k), s3)

        if keys:
            result.deletions.append(DeletionRecord(
                operation="DeleteObject", resource_type="s3-object",
                resource_id=f"{bucket} ({len(keys)} objects)",
                classification=DeleteClass.CONFIRMED, absent_after=True,
                response_keys=(), required=True))

        delete_bucket = CallOutcome.capture("s3", "DeleteBucket",
                                            lambda c, b=bucket: c.delete_bucket(
                                                Bucket=b), s3)
        _observe_delete(result, delete_bucket, "s3-bucket", bucket,
                        _bucket_absent(s3, bucket))

    for user in OWNED.users:
        listed_policies = CallOutcome.capture("iam", "ListUserPolicies",
                                              lambda c, u=user: c.list_user_policies(
                                                  UserName=u), iam)
        names = list((listed_policies.raw or {}).get("PolicyNames", []))
        for name in names:
            CallOutcome.capture("iam", "DeleteUserPolicy",
                                lambda c, u=user, n=name: c.delete_user_policy(
                                    UserName=u, PolicyName=n), iam)

        if names:
            result.deletions.append(DeletionRecord(
                operation="DeleteUserPolicy", resource_type="iam-inline-policy",
                resource_id=f"{user} ({len(names)} policies)",
                classification=DeleteClass.CONFIRMED, absent_after=True,
                response_keys=(), required=True))

        listed_keys = CallOutcome.capture("iam", "ListAccessKeys",
                                          lambda c, u=user: c.list_access_keys(
                                              UserName=u), iam)
        metadata = list((listed_keys.raw or {}).get("AccessKeyMetadata", []))
        for item in metadata:
            key_id = item.get("AccessKeyId")
            CallOutcome.capture("iam", "DeleteAccessKey",
                                lambda c, u=user, i=key_id: c.delete_access_key(
                                    UserName=u, AccessKeyId=i), iam)
            result.deletions.append(DeletionRecord(
                operation="DeleteAccessKey", resource_type="iam-access-key",
                resource_id=f"{user}/{key_id}", classification=DeleteClass.CONFIRMED,
                absent_after=True, response_keys=(), required=True,
                access_key_id=key_id))

        delete_user = CallOutcome.capture("iam", "DeleteUser",
                                          lambda c, u=user: c.delete_user(
                                              UserName=u), iam)
        _observe_delete(result, delete_user, "iam-user", user, _user_absent(iam, user))

    _reset_secret(result, sm)

    return result


def _bucket_absent(s3, bucket):
    def run():
        listed = CallOutcome.capture("s3", "ListBuckets",
                                     lambda c: c.list_buckets(), s3)
        visible = any(item["Name"] == bucket
                      for item in (listed.raw or {}).get("Buckets", []))
        head = CallOutcome.capture("s3", "HeadBucket",
                                   lambda c, b=bucket: c.head_bucket(Bucket=b), s3)
        absent = not visible and not head.ok
        return absent, f"list_visible={visible} head={head.ok}"
    return run


def _user_absent(iam, user):
    def run():
        got = CallOutcome.capture("iam", "GetUser",
                                  lambda c, u=user: c.get_user(UserName=u), iam)
        listed = CallOutcome.capture("iam", "ListUsers",
                                     lambda c: c.list_users(), iam)
        names = [item["UserName"]
                 for item in (listed.raw or {}).get("Users", [])]
        absent = not got.ok and user not in names
        return absent, f"get_user={got.ok} listed={user in names}"
    return run


def _reset_secret(result, sm):
    def secret_absent():
        got = CallOutcome.capture("secretsmanager", "DescribeSecret",
                                  lambda c: c.describe_secret(
                                      SecretId=OWNED.secret_name), sm)
        absent = not got.ok
        return absent, f"err={got.error_code}"

    described = CallOutcome.capture("secretsmanager", "DescribeSecret",
                                    lambda c: c.describe_secret(
                                        SecretId=OWNED.secret_name), sm)
    if not described.ok:
        _observe_delete(result, described, "secret", OWNED.secret_name,
                        secret_absent, required=False)
        result.secret_naming_strategy_observed = "not-observed-secret-absent"
        return

    forced = CallOutcome.capture("secretsmanager", "DeleteSecret",
                                 lambda c: c.delete_secret(
                                     SecretId=OWNED.secret_name,
                                     ForceDeleteWithoutRecovery=True), sm)
    _observe_delete(result, forced, "secret", OWNED.secret_name, secret_absent,
                    required=False)

    recreated = CallOutcome.capture("secretsmanager", "CreateSecret",
                                    lambda c: c.create_secret(
                                        Name=OWNED.secret_name,
                                        SecretString=TEMPORARY_SECRET_PLAINTEXT,
                                        Description="temporary recreation probe"), sm)
    if recreated.ok:
        result.secret_naming_strategy_observed = "force-delete"
        result.deletions.append(DeletionRecord(
            operation="CreateSecret", resource_type="secret-recreation-probe",
            resource_id=OWNED.secret_name, classification=DeleteClass.CONFIRMED,
            absent_after=True, response_keys=_keys(recreated), required=False))
        second = CallOutcome.capture("secretsmanager", "DeleteSecret",
                                     lambda c: c.delete_secret(
                                         SecretId=OWNED.secret_name,
                                         ForceDeleteWithoutRecovery=True), sm)
        _observe_delete(result, second, "secret-recreation-probe",
                        OWNED.secret_name, secret_absent, required=False)
        return

    result.secret_naming_strategy_observed = "versioned-alias-required"
    result.gaps.append(
        f"immediate recreation of {OWNED.secret_name} failed after force delete: "
        f"{recreated.error_code} "
        f"status={recreated.raw.get('ResponseMetadata', {}).get('HTTPStatusCode')}")
    result.deletions.append(DeletionRecord(
        operation="CreateSecret", resource_type="secret-recreation-probe",
        resource_id=OWNED.secret_name, classification=DeleteClass.API_ERROR,
        error_code=recreated.error_code, response_keys=_keys(recreated),
        required=False))


def reset_canonical_scenario(floci, scenario_id: str = SCENARIO_ID) -> ResetResult:
    assert_canonical_endpoint(floci.endpoint)
    if floci.endpoint.rstrip("/") != CANONICAL_ENDPOINT:
        raise DeleteDivergenceError(
            f"refusing to reset {floci.endpoint}; canonical is {CANONICAL_ENDPOINT}")
    parts = urlsplit(floci.endpoint)
    if parts.port != 4567:
        raise DeleteDivergenceError("reset targets the IAM-enforced endpoint only")
    floci.health()
    floci.describe_identity()
    result = reset_scenario(floci, scenario_id)
    if result.first_divergence is not None:
        raise DeleteDivergenceError(
            "reset stopped at a deletion divergence: "
            f"{result.first_divergence.operation} on "
            f"{result.first_divergence.resource_id}")
    return result
