__all__ = [
    "AuditStage",
    "StageState",
    "AuditSafetyError",
    "AuditTransitionError",
    "AuditRecord",
    "AuditLog",
    "FORBIDDEN_FIELD_NAMES",
    "require_safe_field_names",
    "safe_field_names",
]

from dataclasses import dataclass
from enum import Enum
import hashlib

from .registry import Category, get_tool

_SENSITIVE_READ_TAG = "sensitive:sha256:"

FORBIDDEN_FIELD_NAMES = frozenset({
    "secretaccesskey", "sessiontoken", "secretstring", "secretbinary",
    "secret_access_key", "aws_secret_access_key", "session_token",
    "secret_string", "secret_binary", "credential", "credentials",
    "password", "justification", "prompt", "chain_of_thought", "reasoning",
    "normalized_arguments", "arguments", "access_key_id", "accesskeyid",
    "secretid", "secret_id", "raw", "response", "payload", "body",
    "execution_principal", "actor", "model_output", "thoughts",
})

_SUBSTRING_FORBIDDEN = ("secret", "credential", "password", "justification",
                        "prompt", "chain_of_thought", "reasoning")


class AuditSafetyError(ValueError):
    def __init__(self, field_names):
        self.field_names = tuple(sorted(field_names))
        super().__init__(f"unsafe field names: {list(self.field_names)}")


class AuditTransitionError(ValueError):
    def __init__(self, stage, problem):
        self.stage = stage
        self.problem = problem
        super().__init__(f"{stage.value}: {problem}")


def require_safe_field_names(names) -> None:
    offending = set()
    for name in names:
        if not isinstance(name, str):
            continue
        lowered = name.strip().lower()
        if lowered in FORBIDDEN_FIELD_NAMES or \
                any(part in lowered for part in _SUBSTRING_FORBIDDEN):
            offending.add(name)
    if offending:
        raise AuditSafetyError(offending)


def safe_field_names(names) -> tuple:
    require_safe_field_names(names)
    return tuple(sorted(names))


def _fingerprint_sensitive_resource(tool_id: str,
                                    canonical_resource: str) -> str:
    payload = b"cloudsec-audit-resource-v1\0"
    payload += tool_id.encode("utf-8")
    payload += b"\0"
    payload += canonical_resource.encode("utf-8")
    return _SENSITIVE_READ_TAG + hashlib.sha256(payload).hexdigest()


def audit_resource_ref(tool_id: str, category: Category,
                       canonical_resource: str) -> str:
    if category is Category.SENSITIVE_READ:
        return _fingerprint_sensitive_resource(tool_id, canonical_resource)
    return canonical_resource


class AuditStage(str, Enum):
    REQUEST_VALIDATED = "request_validated"
    CANONICALIZED = "canonicalized"
    BROKER_DECIDED = "broker_decided"
    POLICY_DECIDED = "policy_decided"
    APPROVAL_DECIDED = "approval_decided"
    EXECUTION_DECIDED = "execution_decided"
    VERIFICATION_DECIDED = "verification_decided"


@dataclass(frozen=True)
class StageState:
    attempted: bool = False
    broker_granted: bool = False
    policy_allowed: bool = False
    approved: bool = False
    executed: bool = False
    effective: bool = False

    def as_dict(self) -> dict:
        return {"attempted": self.attempted,
                "broker_granted": self.broker_granted,
                "policy_allowed": self.policy_allowed,
                "approved": self.approved,
                "executed": self.executed,
                "effective": self.effective}


_NOT_REACHED = "not_reached"


def _check_transitions(stage, attempted, broker_granted, policy_allowed,
                       approved, executed, effective,
                       requires_approval) -> None:
    def fail(message):
        raise AuditTransitionError(stage, message)

    if executed and not attempted:
        fail("executed requires attempted")
    if executed and not policy_allowed:
        fail("executed requires policy_allowed")
    if requires_approval and executed and not approved:
        fail("executed requires approved when approval is required")
    if approved and not policy_allowed:
        fail("approved requires policy_allowed")
    if policy_allowed and not broker_granted:
        fail("policy_allowed requires broker_granted")
    if broker_granted and not attempted:
        fail("broker_granted requires attempted")


@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    request_id: str
    run_id: str
    scenario_id: str
    tool_id: str
    resource_ref: str
    action_digest: str
    requires_approval: bool
    stage: AuditStage
    state: StageState
    broker_reason_code: str = _NOT_REACHED
    policy_reason_code: str = _NOT_REACHED
    approval_reason_code: str = _NOT_REACHED
    execution_status: str = _NOT_REACHED
    verification_status: str = _NOT_REACHED
    rule_id: str = ""
    timestamp: object = None

    def __post_init__(self):
        require_safe_field_names(self.__dataclass_fields__)
        if not isinstance(self.stage, AuditStage):
            raise TypeError("stage must be an AuditStage")
        if not isinstance(self.state, StageState):
            raise TypeError("state must be a StageState")
        for name in ("audit_id", "request_id", "run_id", "scenario_id",
                     "tool_id", "action_digest", "resource_ref"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise TypeError(f"{name} must be a non-empty string")
        spec = get_tool(self.tool_id)
        if spec.category is Category.SENSITIVE_READ and not self.resource_ref.startswith(_SENSITIVE_READ_TAG):
            raise ValueError("sensitive resource_ref must use fingerprint form")
        if not isinstance(self.requires_approval, bool):
            raise TypeError("requires_approval must be a bool")
        _check_transitions(self.stage, self.state.attempted,
                           self.state.broker_granted, self.state.policy_allowed,
                           self.state.approved, self.state.executed,
                           self.state.effective, self.requires_approval)

    def as_dict(self) -> dict:
        payload = {"audit_id": self.audit_id, "request_id": self.request_id,
                   "run_id": self.run_id, "scenario_id": self.scenario_id,
                   "tool_id": self.tool_id,
                   "resource_ref": self.resource_ref,
                   "action_digest": self.action_digest,
                   "requires_approval": self.requires_approval,
                   "stage": self.stage.value,
                   "broker_reason_code": self.broker_reason_code,
                   "policy_reason_code": self.policy_reason_code,
                   "approval_reason_code": self.approval_reason_code,
                   "execution_status": self.execution_status,
                   "verification_status": self.verification_status,
                   "rule_id": self.rule_id, "timestamp": self.timestamp}
        payload.update(self.state.as_dict())
        return payload


class AuditLog:
    def __init__(self):
        self._records = []

    def append(self, record) -> None:
        if not isinstance(record, AuditRecord):
            raise TypeError("append requires an AuditRecord")
        self._records.append(record)

    def records(self) -> tuple:
        return tuple(self._records)

    def by_request(self, request_id) -> tuple:
        return tuple(item for item in self._records
                     if item.request_id == request_id)

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(tuple(self._records))

    def __repr__(self) -> str:
        return f"AuditLog(records={len(self._records)})"