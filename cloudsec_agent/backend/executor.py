__all__ = [
    "ContainmentClassification",
    "ExecutionPrerequisiteError",
    "AccessKeyState",
    "ExecutionPort",
    "ExecutionResult",
    "ContainmentExecutor",
    "EXECUTION_IDENTITY",
]

from dataclasses import dataclass
from enum import Enum

from .approval import ApprovalDecision
from .broker import BrokerDecision
from .policy import PolicyDecision
from .registry import EXECUTION_IDENTITY_USER, UPDATE_ACCESS_KEY
from .request import CANONICAL_STATUS_INACTIVE, CanonicalAction
from ..scenario import determinism as _d

EXECUTION_IDENTITY = EXECUTION_IDENTITY_USER

_CONTAINMENT_SERVICE_ACTION = "iam:UpdateAccessKey"
_INCONCLUSIVE_ERROR_CODE = "InconclusiveReadback"


class ContainmentClassification(str, Enum):
    CONFIRMED = "confirmed"
    ALREADY_EFFECTIVE = "already_effective"
    BROKER_DENIED = "broker_denied"
    POLICY_DENIED = "policy_denied"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_DENIED = "approval_denied"
    INVALID_REQUEST = "invalid_request"
    API_ERROR = "api_error"
    EMPTY_SUCCESS = "empty_success"
    INCONCLUSIVE = "inconclusive"


class ExecutionPrerequisiteError(RuntimeError):
    def __init__(self, classification, problem):
        self.classification = classification
        self.problem = problem
        super().__init__(f"{classification.value}: {problem}")


class AccessKeyState(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    MISSING = "missing"
    DUPLICATE = "duplicate"
    MALFORMED = "malformed"
    UNREADABLE = "unreadable"


class ExecutionPort:
    def list_access_keys(self, user_name):
        raise NotImplementedError

    def update_access_key_status(self, user_name, access_key_id, status):
        raise NotImplementedError


@dataclass(frozen=True)
class ExecutionResult:
    execution_attempted: bool
    execution_succeeded: bool
    verified_effective: bool
    classification: ContainmentClassification
    reason_code: str = ""
    http_status: object = None
    error_code: str = ""
    detail: str = ""
    execution_identity: str = EXECUTION_IDENTITY

    def __post_init__(self):
        if not isinstance(self.classification, ContainmentClassification):
            raise TypeError("classification must be a ContainmentClassification")
        for name in ("execution_attempted", "execution_succeeded",
                     "verified_effective"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a bool")
        if self.execution_identity != EXECUTION_IDENTITY:
            raise ExecutionPrerequisiteError(
                ContainmentClassification.INVALID_REQUEST,
                "execution identity is fixed by backend configuration")
        if self.verified_effective and not self.execution_attempted and \
                self.classification is not \
                ContainmentClassification.ALREADY_EFFECTIVE:
            raise ExecutionPrerequisiteError(
                ContainmentClassification.INCONCLUSIVE,
                "verified_effective requires an attempted or already-effective "
                "classification")

    def as_dict(self) -> dict:
        return {"execution_attempted": self.execution_attempted,
                "execution_succeeded": self.execution_succeeded,
                "verified_effective": self.verified_effective,
                "classification": self.classification.value,
                "reason_code": self.reason_code,
                "http_status": self.http_status,
                "error_code": self.error_code,
                "detail": self.detail,
                "execution_identity": self.execution_identity}


def _require_prerequisites(action, action_digest, broker_decision,
                           policy_decision, approval_decision,
                           protected_user) -> None:
    if not isinstance(action, CanonicalAction):
        raise ExecutionPrerequisiteError(
            ContainmentClassification.INVALID_REQUEST,
            "executor requires a CanonicalAction")
    if action.tool_id != UPDATE_ACCESS_KEY:
        raise ExecutionPrerequisiteError(
            ContainmentClassification.INVALID_REQUEST,
            "executor only performs access key status containment")
    if action.service_action != _CONTAINMENT_SERVICE_ACTION:
        raise ExecutionPrerequisiteError(
            ContainmentClassification.INVALID_REQUEST,
            "service action is not an access key status update")
    arguments = action.normalized_arguments
    if arguments.get("Status") != CANONICAL_STATUS_INACTIVE:
        raise ExecutionPrerequisiteError(
            ContainmentClassification.INVALID_REQUEST,
            "status must be the canonical inactive value")
    if not isinstance(broker_decision, BrokerDecision) or \
            not broker_decision.granted:
        raise ExecutionPrerequisiteError(
            ContainmentClassification.BROKER_DENIED,
            "broker did not grant this action")
    if not isinstance(policy_decision, PolicyDecision) or \
            not policy_decision.allowed:
        raise ExecutionPrerequisiteError(
            ContainmentClassification.POLICY_DENIED,
            "policy did not allow this action")
    if policy_decision.evaluated_action_digest != action_digest:
        raise ExecutionPrerequisiteError(
            ContainmentClassification.POLICY_DENIED,
            "policy evaluated a different action digest")
    if not isinstance(approval_decision, ApprovalDecision) or \
            not approval_decision.approved:
        classification = (ContainmentClassification.APPROVAL_REQUIRED
                         if approval_decision is None
                         else ContainmentClassification.APPROVAL_DENIED)
        raise ExecutionPrerequisiteError(
            classification, "human approval did not authorize this action")
    if approval_decision.action_digest != action_digest:
        raise ExecutionPrerequisiteError(
            ContainmentClassification.APPROVAL_DENIED,
            "approval is bound to a different action digest")
    if protected_user == action.normalized_arguments.get("UserName"):
        raise ExecutionPrerequisiteError(
            ContainmentClassification.INVALID_REQUEST,
            "containment must never target the protected identity")


_TYPED_FIELDS = ("access_key_id", "status")
_MAPPING_FIELDS = ("AccessKeyId", "Status")


def _text_field(value):
    return value if isinstance(value, str) and value.strip() else None


def _state_fields(entry):
    if isinstance(entry, dict):
        key, status = entry.get(_MAPPING_FIELDS[0]), entry.get(_MAPPING_FIELDS[1])
    else:
        key = getattr(entry, _TYPED_FIELDS[0], None)
        status = getattr(entry, _TYPED_FIELDS[1], None)
    key_text = _text_field(key)
    status_text = _text_field(status)
    if key_text is None or status_text is None:
        return None
    return key_text, status_text


class ContainmentExecutor:
    def __init__(self, port, execution_identity=EXECUTION_IDENTITY):
        if not isinstance(port, ExecutionPort):
            raise TypeError("port must implement ExecutionPort")
        if execution_identity != EXECUTION_IDENTITY:
            raise ExecutionPrerequisiteError(
                ContainmentClassification.INVALID_REQUEST,
                "execution identity is fixed by backend configuration")
        self._port = port
        self._identity = execution_identity

    @property
    def execution_identity(self) -> str:
        return self._identity

    def _read_state(self, user_name, access_key_id) -> tuple:
        try:
            raw = self._port.list_access_keys(user_name)
        except Exception:  # noqa: BLE001
            return AccessKeyState.UNREADABLE, None
        if not isinstance(raw, (list, tuple)):
            return AccessKeyState.UNREADABLE, None
        matches = []
        malformed = False
        for entry in raw:
            fields = _state_fields(entry)
            if fields is None:
                malformed = True
                continue
            if fields[0] == access_key_id:
                matches.append(fields)
        if len(matches) > 1:
            return AccessKeyState.DUPLICATE, None
        if not matches:
            return (AccessKeyState.MALFORMED if malformed
                    else AccessKeyState.MISSING), None
        status = matches[0][1]
        if status == CANONICAL_STATUS_INACTIVE:
            return AccessKeyState.INACTIVE, matches[0]
        if status == "Active":
            return AccessKeyState.ACTIVE, matches[0]
        return AccessKeyState.MALFORMED, matches[0]

    def _protected_intact(self, protected_user, protected_key_id) -> bool:
        try:
            raw = self._port.list_access_keys(protected_user)
        except Exception:  # noqa: BLE001
            return False
        if not isinstance(raw, (list, tuple)):
            return False
        for entry in raw:
            fields = _state_fields(entry)
            if fields is not None and fields[0] == protected_key_id:
                return fields[1] == "Active"
        return False

    def execute(self, action, action_digest, broker_decision, policy_decision,
                approval_decision, protected_user,
                protected_key_id) -> ExecutionResult:
        _require_prerequisites(action, action_digest, broker_decision,
                               policy_decision, approval_decision,
                               protected_user)
        arguments = action.normalized_arguments
        user_name = arguments["UserName"]
        access_key_id = arguments["AccessKeyId"]

        state, _ = self._read_state(user_name, access_key_id)
        if state is AccessKeyState.UNREADABLE:
            return ExecutionResult(False, False, False,
                                   ContainmentClassification.INCONCLUSIVE,
                                   reason_code="read_failed",
                                   error_code="ReadFailure",
                                   detail="access key pre-read unreadable")
        if state is AccessKeyState.DUPLICATE:
            return ExecutionResult(False, False, False,
                                   ContainmentClassification.INCONCLUSIVE,
                                   reason_code="duplicate_exact_key",
                                   error_code=_INCONCLUSIVE_ERROR_CODE,
                                   detail="multiple exact key entries")
        if state is AccessKeyState.MALFORMED:
            return ExecutionResult(False, False, False,
                                   ContainmentClassification.INCONCLUSIVE,
                                   reason_code="malformed_readback",
                                   error_code=_INCONCLUSIVE_ERROR_CODE,
                                   detail="access key pre-read malformed")
        if state is AccessKeyState.MISSING:
            return ExecutionResult(False, False, False,
                                   ContainmentClassification.INCONCLUSIVE,
                                   reason_code="key_not_found",
                                   error_code=_INCONCLUSIVE_ERROR_CODE,
                                   detail="exact access key absent")
        if state is AccessKeyState.INACTIVE:
            if not self._protected_intact(protected_user, protected_key_id):
                return ExecutionResult(False, False, False,
                                       ContainmentClassification.INCONCLUSIVE,
                                       reason_code="protected_state_changed",
                                       error_code=_INCONCLUSIVE_ERROR_CODE,
                                       detail="protected identity not intact")
            return ExecutionResult(False, False, True,
                                   ContainmentClassification.ALREADY_EFFECTIVE,
                                   reason_code="already_inactive")

        outcome = self._port.update_access_key_status(
            user_name, access_key_id, CANONICAL_STATUS_INACTIVE)
        status_code, error_code, detail = _port_outcome(outcome)
        if error_code:
            return ExecutionResult(True, False, False,
                                   ContainmentClassification.API_ERROR,
                                   reason_code="update_failed",
                                   http_status=status_code,
                                   error_code=error_code, detail=detail)

        after, _ = self._read_state(user_name, access_key_id)
        if after is AccessKeyState.INACTIVE:
            if not self._protected_intact(protected_user, protected_key_id):
                return ExecutionResult(True, True, False,
                                       ContainmentClassification.INCONCLUSIVE,
                                       reason_code="protected_state_changed",
                                       http_status=status_code,
                                       error_code=_INCONCLUSIVE_ERROR_CODE,
                                       detail="protected identity not intact")
            return ExecutionResult(True, True, True,
                                   ContainmentClassification.CONFIRMED,
                                   reason_code="verified_inactive",
                                   http_status=status_code)
        if after is AccessKeyState.ACTIVE:
            return ExecutionResult(True, True, False,
                                   ContainmentClassification.EMPTY_SUCCESS,
                                   reason_code="status_unchanged",
                                   http_status=status_code,
                                   detail="mutation reported success but the "
                                          "exact key is still active")
        return ExecutionResult(True, False, False,
                               ContainmentClassification.INCONCLUSIVE,
                               reason_code="post_mutation_read_unreliable",
                               http_status=status_code,
                               error_code=_INCONCLUSIVE_ERROR_CODE,
                               detail="post-mutation state could not be "
                                      "established")


def _port_outcome(outcome) -> tuple:
    if outcome is None:
        return None, "PortNoOutcome", "execution port returned no outcome"
    succeeded = getattr(outcome, "succeeded", None)
    if isinstance(succeeded, bool):
        return (getattr(outcome, "http_status", None),
                getattr(outcome, "error_code", None) or None,
                getattr(outcome, "detail", "") or "")
    if isinstance(outcome, tuple):
        status_code = outcome[0] if len(outcome) > 0 else None
        error_code = outcome[1] if len(outcome) > 1 else None
        detail = outcome[2] if len(outcome) > 2 else ""
        return status_code, error_code, detail
    if isinstance(outcome, dict):
        return (outcome.get("http_status"), outcome.get("error_code"),
                outcome.get("detail", ""))
    if isinstance(outcome, BaseException):
        return None, type(outcome).__name__, "port raised"
    return None, None, ""