__all__ = [
    "M2OwnedResources",
    "M2Owned",
    "CONTAINMENT_POLICY_NAME",
    "FLOCI_IAM_RESOURCE",
    "CONTAINMENT_ALLOWED_ACTIONS",
    "containment_policy_document",
    "M2ExecutionCredential",
    "M2SetupClass",
    "M2CleanupClass",
    "M2SetupRecord",
    "M2CleanupRecord",
    "M2IdentitySetupResult",
    "M2IdentityCleanupResult",
    "M2SetupDivergence",
    "setup_executor_identity",
    "cleanup_executor_identity",
    "executor_identity_absent",
]

import json
from dataclasses import dataclass, field
from enum import Enum

from .registry import EXECUTION_IDENTITY_USER

CONTAINMENT_POLICY_NAME = "csi-containment-executor"


class M2OwnedResources:
    users = (EXECUTION_IDENTITY_USER,)
    inline_policies = (CONTAINMENT_POLICY_NAME,)

    @classmethod
    def all_names(cls) -> tuple:
        return tuple(cls.users) + tuple(cls.inline_policies)

    @classmethod
    def is_owned(cls, name: str) -> bool:
        return name in cls.all_names()


M2Owned = M2OwnedResources


FLOCI_IAM_RESOURCE = "*"

CONTAINMENT_ALLOWED_ACTIONS = ("iam:UpdateAccessKey", "iam:ListAccessKeys",
                               "iam:GetUser")


def containment_policy_document() -> str:
    document = {"Version": "2012-10-17", "Statement": [
        {"Sid": "ContainCompromisedIncidentKey", "Effect": "Allow",
         "Action": ["iam:UpdateAccessKey"],
         "Resource": [FLOCI_IAM_RESOURCE]},
        {"Sid": "VerifyContainmentOutcome", "Effect": "Allow",
         "Action": ["iam:ListAccessKeys", "iam:GetUser"],
         "Resource": [FLOCI_IAM_RESOURCE]},
    ]}
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


class M2SetupClass(str, Enum):
    CONFIRMED = "confirmed"
    ALREADY_ABSENT = "already_absent"
    API_ERROR = "api_error"
    EMPTY_SUCCESS = "empty_success"
    INCONCLUSIVE = "inconclusive"
    NOT_ATTEMPTED = "not_attempted"


M2CleanupClass = M2SetupClass


@dataclass(frozen=True)
class M2SetupRecord:
    step: str
    classification: M2SetupClass
    resource_id: str = ""
    error_code: str = ""


@dataclass(frozen=True)
class M2CleanupRecord:
    step: str
    classification: M2CleanupClass
    resource_id: str = ""
    error_code: str = ""


class M2SetupDivergence(RuntimeError):
    def __init__(self, record, result):
        self.record = record
        self.result = result
        super().__init__(f"setup diverged at {record.step}")


@dataclass(frozen=True)
class M2IdentitySetupResult:
    user_created: bool
    policy_confirmed: bool
    access_key_confirmed: bool
    access_key_id: str = ""
    fatal_errors: tuple = ()
    first_divergence: object = None
    records: tuple = ()

    @property
    def ok(self) -> bool:
        return (self.user_created and self.policy_confirmed
                and self.access_key_confirmed and not self.fatal_errors
                and self.first_divergence is None)

    def as_dict(self) -> dict:
        return {"user_created": self.user_created,
                "policy_confirmed": self.policy_confirmed,
                "access_key_confirmed": self.access_key_confirmed,
                "access_key_id": self.access_key_id,
                "fatal_errors": list(self.fatal_errors),
                "first_divergence": (self.first_divergence.step
                                     if self.first_divergence else None),
                "records": [{"step": item.step,
                             "classification": item.classification.value,
                             "resource_id": item.resource_id,
                             "error_code": item.error_code}
                            for item in self.records]}


@dataclass(frozen=True)
class M2IdentityCleanupResult:
    policy_removed: bool
    keys_removed: int
    user_removed: bool
    fatal_errors: tuple = ()
    first_divergence: object = None
    records: tuple = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return not self.fatal_errors and self.first_divergence is None

    def as_dict(self) -> dict:
        return {"policy_removed": self.policy_removed,
                "keys_removed": self.keys_removed,
                "user_removed": self.user_removed,
                "fatal_errors": list(self.fatal_errors),
                "first_divergence": (self.first_divergence.step
                                     if self.first_divergence else None),
                "records": [{"step": item.step,
                             "classification": item.classification.value,
                             "resource_id": item.resource_id,
                             "error_code": item.error_code}
                            for item in self.records]}


@dataclass(frozen=True)
class M2ExecutionCredential:
    access_key_id: str
    secret_access_key: str = field(repr=False)
    user_name: str = EXECUTION_IDENTITY_USER

    def safe_summary(self) -> dict:
        return {"user_name": self.user_name, "access_key_id": self.access_key_id,
                "secret_access_key": "[not-exposed]"}

    def as_dict(self) -> dict:
        return self.safe_summary()

    def __repr__(self) -> str:
        return (f"M2ExecutionCredential(user_name={self.user_name!r}, "
                f"access_key_id={self.access_key_id!r}, "
                f"secret_access_key=[redacted])")

    __str__ = __repr__


def _error_code(exc):
    from .live_executor import _error_fields
    _, code, _ = _error_fields(exc)
    return code


def _call(fn):
    try:
        return True, fn(), None
    except Exception as exc:  # noqa: BLE001
        return False, None, _error_code(exc)


def _user_exists(iam, user_name) -> bool:
    ok, _, _ = _call(lambda: iam.get_user(UserName=user_name))
    return ok


def executor_identity_absent(iam) -> bool:
    return not _user_exists(iam, EXECUTION_IDENTITY_USER)


def _policy_matches(document) -> bool:
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return False
    if not isinstance(document, dict):
        return False
    return document == json.loads(containment_policy_document())


def setup_executor_identity(iam):
    records = []
    errors = []

    def fail(step, classification, resource_id="", error_code=""):
        record = M2SetupRecord(step=step, classification=classification,
                               resource_id=resource_id, error_code=error_code)
        records.append(record)
        errors.append(f"{classification.value} at {step}"
                      + (f" ({error_code})" if error_code else ""))
        result = M2IdentitySetupResult(
            user_created=any(item.step == "create_user" for item in records),
            policy_confirmed=any(item.step == "policy_readback"
                                 for item in records),
            access_key_confirmed=False, access_key_id="",
            fatal_errors=tuple(errors), first_divergence=record,
            records=tuple(records))
        raise M2SetupDivergence(record, result)

    if not executor_identity_absent(iam):
        fail("preflight_identity_absent", M2SetupClass.ALREADY_ABSENT,
             EXECUTION_IDENTITY_USER)

    ok, raw, code = _call(lambda: iam.create_user(
        UserName=EXECUTION_IDENTITY_USER))
    if not ok:
        fail("create_user", M2SetupClass.API_ERROR, EXECUTION_IDENTITY_USER,
             code)
    if ((raw or {}).get("User") or {}).get("UserName") != \
            EXECUTION_IDENTITY_USER:
        fail("create_user", M2SetupClass.EMPTY_SUCCESS, EXECUTION_IDENTITY_USER)
    if not _user_exists(iam, EXECUTION_IDENTITY_USER):
        fail("user_readback", M2SetupClass.EMPTY_SUCCESS,
             EXECUTION_IDENTITY_USER)
    records.append(M2SetupRecord("create_user", M2SetupClass.CONFIRMED,
                                 EXECUTION_IDENTITY_USER))

    ok, _, code = _call(lambda: iam.put_user_policy(
        UserName=EXECUTION_IDENTITY_USER, PolicyName=CONTAINMENT_POLICY_NAME,
        PolicyDocument=containment_policy_document()))
    if not ok:
        fail("put_user_policy", M2SetupClass.API_ERROR,
             CONTAINMENT_POLICY_NAME, code)
    ok, raw, code = _call(lambda: iam.get_user_policy(
        UserName=EXECUTION_IDENTITY_USER, PolicyName=CONTAINMENT_POLICY_NAME))
    if not ok:
        fail("policy_readback", M2SetupClass.API_ERROR, CONTAINMENT_POLICY_NAME,
             code)
    if not _policy_matches((raw or {}).get("PolicyDocument")):
        fail("policy_readback", M2SetupClass.EMPTY_SUCCESS,
             CONTAINMENT_POLICY_NAME)
    records.append(M2SetupRecord("policy_readback", M2SetupClass.CONFIRMED,
                                 CONTAINMENT_POLICY_NAME))

    ok, raw, code = _call(lambda: iam.create_access_key(
        UserName=EXECUTION_IDENTITY_USER))
    if not ok:
        fail("create_access_key", M2SetupClass.API_ERROR,
             EXECUTION_IDENTITY_USER, code)
    key = (raw or {}).get("AccessKey") or {}
    key_id = key.get("AccessKeyId") or ""
    secret = key.get("SecretAccessKey") or ""
    if not key_id or not secret:
        fail("create_access_key", M2SetupClass.EMPTY_SUCCESS,
             EXECUTION_IDENTITY_USER)
    ok, raw, code = _call(lambda: iam.list_access_keys(
        UserName=EXECUTION_IDENTITY_USER))
    if not ok:
        fail("key_readback", M2SetupClass.API_ERROR, EXECUTION_IDENTITY_USER,
             code)
    listed = (raw or {}).get("AccessKeyMetadata") or ()
    if not [item for item in listed if item.get("AccessKeyId") == key_id]:
        fail("key_readback", M2SetupClass.EMPTY_SUCCESS,
             EXECUTION_IDENTITY_USER)
    records.append(M2SetupRecord("key_readback", M2SetupClass.CONFIRMED,
                                 EXECUTION_IDENTITY_USER))
    credential = M2ExecutionCredential(access_key_id=key_id,
                                       secret_access_key=secret)
    return (M2IdentitySetupResult(user_created=True, policy_confirmed=True,
                                  access_key_confirmed=True,
                                  access_key_id=key_id,
                                  records=tuple(records)), credential)


def cleanup_executor_identity(iam) -> M2IdentityCleanupResult:
    records = []
    errors = []

    def diverge(step, classification, resource_id="", error_code=""):
        record = M2CleanupRecord(step=step, classification=classification,
                                 resource_id=resource_id, error_code=error_code)
        records.append(record)
        errors.append(f"{classification.value} at {step}"
                      + (f" ({error_code})" if error_code else ""))
        return M2IdentityCleanupResult(
            policy_removed=any(item.step == "delete_user_policy"
                               for item in records),
            keys_removed=sum(1 for item in records
                             if item.step == "delete_access_key"),
            user_removed=any(item.step == "delete_user" for item in records),
            fatal_errors=tuple(errors), first_divergence=record,
            records=tuple(records))

    if not _user_exists(iam, EXECUTION_IDENTITY_USER):
        records.append(M2CleanupRecord("preflight_absence",
                                       M2CleanupClass.ALREADY_ABSENT,
                                       EXECUTION_IDENTITY_USER))
        return M2IdentityCleanupResult(policy_removed=True, keys_removed=0,
                                       user_removed=True,
                                       records=tuple(records))

    ok, _, code = _call(lambda: iam.delete_user_policy(
        UserName=EXECUTION_IDENTITY_USER, PolicyName=CONTAINMENT_POLICY_NAME))
    records.append(M2CleanupRecord(
        "delete_user_policy",
        M2CleanupClass.CONFIRMED if ok else M2CleanupClass.ALREADY_ABSENT,
        CONTAINMENT_POLICY_NAME, code if not ok else ""))

    ok, raw, code = _call(lambda: iam.list_access_keys(
        UserName=EXECUTION_IDENTITY_USER))
    if not ok:
        return diverge("list_access_keys", M2CleanupClass.API_ERROR,
                       EXECUTION_IDENTITY_USER, code)
    removed = 0
    for entry in (raw or {}).get("AccessKeyMetadata") or ():
        key_id = entry.get("AccessKeyId")
        ok, _, code = _call(lambda i=key_id: iam.delete_access_key(
            UserName=EXECUTION_IDENTITY_USER, AccessKeyId=i))
        if not ok:
            return diverge("delete_access_key", M2CleanupClass.API_ERROR,
                           EXECUTION_IDENTITY_USER, code)
        records.append(M2CleanupRecord("delete_access_key",
                                       M2CleanupClass.CONFIRMED, key_id))
        removed += 1

    ok, _, code = _call(lambda: iam.delete_user(
        UserName=EXECUTION_IDENTITY_USER))
    if not ok:
        return diverge("delete_user", M2CleanupClass.API_ERROR,
                       EXECUTION_IDENTITY_USER, code)
    if _user_exists(iam, EXECUTION_IDENTITY_USER):
        return diverge("absence_readback", M2CleanupClass.EMPTY_SUCCESS,
                       EXECUTION_IDENTITY_USER)
    records.append(M2CleanupRecord("delete_user", M2CleanupClass.CONFIRMED,
                                   EXECUTION_IDENTITY_USER))
    return M2IdentityCleanupResult(policy_removed=True, keys_removed=removed,
                                   user_removed=True, records=tuple(records))
