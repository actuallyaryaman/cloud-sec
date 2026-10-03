__all__ = [
    "ApprovalReasonCode",
    "ApprovalRecord",
    "ApprovalDecision",
    "ApprovalProvider",
    "FakeApprovalProvider",
    "CliApprovalProvider",
    "AuditSafetyError",
    "StageNotReached",
    "CONFIRMATION_PREFIX",
    "evaluate_approval_stage",
]

from dataclasses import dataclass
from enum import Enum

from .audit import AuditSafetyError, require_safe_field_names
from .policy import PolicyDecision
from .request import CanonicalAction

CONFIRMATION_PREFIX = "APPROVE "

class ApprovalReasonCode(str, Enum):
    APPROVED = "approved"
    MISSING_APPROVAL = "missing_approval"
    DIGEST_MISMATCH = "digest_mismatch"
    EXPIRED = "expired"
    REPLAYED = "replayed"
    DENIED = "denied"


class StageNotReached(RuntimeError):
    def __init__(self, stage, reason_code):
        self.stage = stage
        self.reason_code = reason_code
        super().__init__(f"{stage} stage not reached: {reason_code}")


@dataclass(frozen=True)
class ApprovalRecord:
    action_digest: str
    approved_by: str
    approved_at: object
    expires_at: object
    single_use: bool = True
    approval_id: str = ""

    def __post_init__(self):
        require_safe_field_names(self.__dataclass_fields__)
        if not isinstance(self.action_digest, str) or not self.action_digest:
            raise TypeError("action_digest must be a non-empty string")
        if not isinstance(self.approved_by, str) or not self.approved_by:
            raise TypeError("approved_by must be a non-empty string")
        if not isinstance(self.single_use, bool):
            raise TypeError("single_use must be a bool")

    def is_expired(self, current_time) -> bool:
        return current_time >= self.expires_at

    def as_dict(self) -> dict:
        return {"approval_id": self.approval_id,
                "action_digest": self.action_digest,
                "approved_by": self.approved_by,
                "approved_at": self.approved_at,
                "expires_at": self.expires_at,
                "single_use": self.single_use}


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    reason_code: ApprovalReasonCode
    action_digest: str
    approval_id: str = ""

    def __post_init__(self):
        if not isinstance(self.reason_code, ApprovalReasonCode):
            raise TypeError("reason_code must be an ApprovalReasonCode")
        if not isinstance(self.approved, bool):
            raise TypeError("approved must be a bool")
        if not isinstance(self.action_digest, str) or not self.action_digest:
            raise TypeError("action_digest must be a non-empty string")


class ApprovalProvider:
    def decide(self, action, action_digest, current_time) -> ApprovalDecision:
        raise NotImplementedError


def _decision(approved, reason_code, digest, approval_id="") -> ApprovalDecision:
    return ApprovalDecision(approved=approved, reason_code=reason_code,
                            action_digest=digest, approval_id=approval_id)


class FakeApprovalProvider(ApprovalProvider):
    def __init__(self, records=()):
        self._records = {}
        for record in records:
            self.provision(record)
        self._consumed = set()
        self.calls = 0

    def provision(self, record) -> None:
        if not isinstance(record, ApprovalRecord):
            raise TypeError("provision requires an ApprovalRecord")
        self._records[record.approval_id] = record

    @property
    def consumed_approval_ids(self) -> frozenset:
        return frozenset(self._consumed)

    @property
    def provisioned_approval_ids(self) -> tuple:
        return tuple(sorted(self._records))

    def decide(self, action, action_digest, current_time) -> ApprovalDecision:
        self.calls += 1
        consumed_only = False
        for approval_id in sorted(self._records):
            record = self._records[approval_id]
            if record.action_digest != action_digest:
                continue
            if record.is_expired(current_time):
                return _decision(False, ApprovalReasonCode.EXPIRED,
                                 action_digest, approval_id)
            if record.single_use and record.approval_id in self._consumed:
                consumed_only = True
                continue
            if record.single_use:
                self._consumed.add(record.approval_id)
            return _decision(True, ApprovalReasonCode.APPROVED, action_digest,
                             approval_id)
        if consumed_only:
            return _decision(False, ApprovalReasonCode.REPLAYED, action_digest)
        return _decision(False, ApprovalReasonCode.MISSING_APPROVAL,
                         action_digest)


class CliApprovalProvider(ApprovalProvider):
    def __init__(self, input_fn, output_fn, approved_by, approval_id,
                 expires_at, single_use=True):
        if not callable(input_fn) or not callable(output_fn):
            raise TypeError("input_fn and output_fn must be callables")
        self._input_fn = input_fn
        self._output_fn = output_fn
        self._approved_by = approved_by
        self._approval_id = approval_id
        self._expires_at = expires_at
        self._single_use = single_use
        self._consumed = set()
        self.calls = 0

    def _prompt(self, action, action_digest) -> None:
        if not isinstance(action, CanonicalAction):
            raise TypeError(
                "approval requires a CanonicalAction; model prose and request "
                "types must never reach the approval stage")
        self._output_fn(f"tool            : {action.tool_id}")
        self._output_fn(f"service_action  : {action.service_action}")
        self._output_fn(f"resource        : {action.resource}")
        self._output_fn(f"digest          : {action_digest}")
        self._output_fn(
            f"type the exact confirmation '{CONFIRMATION_PREFIX}"
            f"{action_digest}' to approve, anything else denies")

    def decide(self, action, action_digest, current_time) -> ApprovalDecision:
        self.calls += 1
        self._prompt(action, action_digest)
        if not isinstance(action, CanonicalAction):
            raise TypeError("approval requires a CanonicalAction")
        response = self._input_fn()
        expected = f"{CONFIRMATION_PREFIX}{action_digest}"
        if not isinstance(response, str) or response != expected:
            return _decision(False, ApprovalReasonCode.DENIED, action_digest)
        record = ApprovalRecord(action_digest=action_digest,
                                approved_by=self._approved_by,
                                approved_at=current_time,
                                expires_at=self._expires_at,
                                single_use=self._single_use,
                                approval_id=self._approval_id)
        if record.is_expired(current_time):
            return _decision(False, ApprovalReasonCode.EXPIRED, action_digest,
                             self._approval_id)
        if self._single_use:
            if self._approval_id in self._consumed:
                return _decision(False, ApprovalReasonCode.REPLAYED,
                                 action_digest, self._approval_id)
            self._consumed.add(self._approval_id)
        return _decision(True, ApprovalReasonCode.APPROVED, action_digest,
                         self._approval_id)


def evaluate_approval_stage(action, action_digest, policy_decision,
                            provider, current_time) -> ApprovalDecision:
    if not isinstance(policy_decision, PolicyDecision):
        raise TypeError("policy_decision must be a PolicyDecision")
    if not policy_decision.allowed:
        raise StageNotReached("approval", policy_decision.reason_code)
    if policy_decision.evaluated_action_digest != action_digest:
        raise StageNotReached("approval", ApprovalReasonCode.DIGEST_MISMATCH)
    return provider.decide(action, action_digest, current_time)