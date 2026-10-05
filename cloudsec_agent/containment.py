__all__ = [
    "ContainmentResult",
    "contain_containment",
]

from dataclasses import dataclass, field

from .backend.approval import (ApprovalReasonCode, StageNotReached,
                       evaluate_approval_stage)
from .backend.audit import (AuditLog, AuditRecord, AuditStage, StageState,
                            audit_resource_ref)
from .backend.broker import evaluate as evaluate_broker
from .backend.executor import (ContainmentClassification, ContainmentExecutor,
                               ExecutionPrerequisiteError, ExecutionResult)
from .backend.policy import evaluate_containment_policy
from .backend.registry import (CONTAINMENT_CANONICALIZER, SECRET_READ_CANONICALIZER,
                       get_tool)
from .backend.request import (ToolRequest, ToolValidationError, action_digest,
                      canonicalize_containment_update_access_key,
                      canonicalize_secret_read, validate_arguments)

_APPROVAL_CLASSIFICATION = {
    ApprovalReasonCode.MISSING_APPROVAL: ContainmentClassification.APPROVAL_REQUIRED,
    ApprovalReasonCode.DENIED: ContainmentClassification.APPROVAL_DENIED,
    ApprovalReasonCode.EXPIRED: ContainmentClassification.APPROVAL_DENIED,
    ApprovalReasonCode.REPLAYED: ContainmentClassification.APPROVAL_DENIED,
    ApprovalReasonCode.DIGEST_MISMATCH: ContainmentClassification.APPROVAL_DENIED,
}


@dataclass(frozen=True)
class ContainmentResult:
    requested: bool
    broker_authorized: bool
    policy_authorized: bool
    approval_authorized: bool
    execution_attempted: bool
    execution_succeeded: bool
    verified_effective: bool
    classification: ContainmentClassification
    reason_code: str
    action_digest: str
    audit_records: tuple = field(default_factory=tuple)

    def __post_init__(self):
        if not isinstance(self.classification, ContainmentClassification):
            raise TypeError("classification must be a ContainmentClassification")
        if self.verified_effective and not (
                self.execution_succeeded
                or self.classification
                is ContainmentClassification.ALREADY_EFFECTIVE):
            raise ValueError("verified_effective requires a successful or "
                             "already-effective outcome")
        if self.approval_authorized and not self.policy_authorized:
            raise ValueError("approval_authorized requires policy_authorized")
        if self.policy_authorized and not self.broker_authorized:
            raise ValueError("policy_authorized requires broker_authorized")
        if not self.requested and (
                self.broker_authorized or self.policy_authorized
                or self.approval_authorized or self.execution_attempted):
            raise ValueError("an invalid request cannot be authorized")

    def as_dict(self) -> dict:
        return {"requested": self.requested,
                "broker_authorized": self.broker_authorized,
                "policy_authorized": self.policy_authorized,
                "approval_authorized": self.approval_authorized,
                "execution_attempted": self.execution_attempted,
                "execution_succeeded": self.execution_succeeded,
                "verified_effective": self.verified_effective,
                "classification": self.classification.value,
                "reason_code": self.reason_code,
                "action_digest": self.action_digest,
                "audit_record_count": len(self.audit_records)}


def _state(attempted=False, broker=False, policy=False, approved=False,
           executed=False, effective=False) -> StageState:
    return StageState(attempted=attempted, broker_granted=broker,
                      policy_allowed=policy, approved=approved,
                      executed=executed, effective=effective)


class _Recorder:
    def __init__(self, log, context):
        self._log = log
        self._context = context
        self._count = 0

    def emit(self, stage, state, **overrides):
        self._count += 1
        fields = {"audit_id": f"audit-{self._count}",
                  "request_id": self._context["request_id"],
                  "run_id": self._context["run_id"],
                  "scenario_id": self._context["scenario_id"],
                  "tool_id": self._context["tool_id"],
                  "resource_ref": self._context["resource_ref"],
                  "action_digest": self._context["digest"],
                  "requires_approval": self._context["requires_approval"],
                  "stage": stage, "state": state}
        fields.update(overrides)
        self._log.append(AuditRecord(**fields))


def _canonicalize(request, context):
    try:
        spec = get_tool(request.tool_id)
        validate_arguments(spec, request.arguments)
        if spec.canonicalizer_id == CONTAINMENT_CANONICALIZER:
            return spec, canonicalize_containment_update_access_key(
                request.arguments)
        if spec.canonicalizer_id == SECRET_READ_CANONICALIZER:
            return spec, canonicalize_secret_read(request.arguments)
    except (KeyError, ToolValidationError, ValueError):
        return None, None
    return spec, None


def contain_containment(request, grant, context, executor=None,
                        approval_provider=None, current_time=None,
                        protected_user=None, protected_key_id=None,
                        audit_log=None) -> ContainmentResult:
    log = audit_log if audit_log is not None else AuditLog()
    tool_id = request.tool_id if isinstance(request, ToolRequest) else ""
    recorder = _Recorder(log, {"request_id": getattr(request, "request_id", ""),
                               "run_id": grant.run_scope,
                               "scenario_id": context.scenario_id,
                               "tool_id": tool_id, "resource_ref": "",
                               "digest": "",
                               "requires_approval": True})

    def finish(classification, reason_code, digest="", broker=False,
               policy=False, approved=False, result=None):
        return ContainmentResult(
            requested=True, broker_authorized=broker, policy_authorized=policy,
            approval_authorized=approved,
            execution_attempted=bool(result and result.execution_attempted),
            execution_succeeded=bool(result and result.execution_succeeded),
            verified_effective=bool(result and result.verified_effective),
            classification=classification, reason_code=reason_code,
            action_digest=digest, audit_records=log.records())

    spec, action = _canonicalize(request, context) \
        if isinstance(request, ToolRequest) else (None, None)
    if spec is None or action is None:
        return ContainmentResult(
            requested=False, broker_authorized=False, policy_authorized=False,
            approval_authorized=False, execution_attempted=False,
            execution_succeeded=False, verified_effective=False,
            classification=ContainmentClassification.INVALID_REQUEST,
            reason_code="canonicalization_failed", action_digest="",
            audit_records=log.records())

    digest = action_digest(action)
    recorder._context.update({
        "resource_ref": audit_resource_ref(spec.tool_id, spec.category,
                                           action.resource),
        "digest": digest,
        "requires_approval": spec.requires_approval})
    recorder.emit(AuditStage.CANONICALIZED, _state(attempted=True))

    broker = evaluate_broker(grant, action, grant.run_scope)
    recorder.emit(AuditStage.BROKER_DECIDED,
                  _state(attempted=True, broker=broker.granted),
                  broker_reason_code=broker.reason_code.value)
    if not broker.granted:
        return finish(ContainmentClassification.BROKER_DENIED,
                      broker.reason_code.value, digest)

    policy = evaluate_containment_policy(action, digest, broker, context)
    recorder.emit(AuditStage.POLICY_DECIDED,
                  _state(attempted=True, broker=True,
                         policy=policy.allowed),
                  policy_reason_code=policy.reason_code.value,
                  rule_id=policy.rule_id)
    if not policy.allowed:
        return finish(ContainmentClassification.POLICY_DENIED,
                      policy.reason_code.value, digest, broker=True)

    try:
        approval = evaluate_approval_stage(action, digest, policy,
                                            approval_provider, current_time)
    except StageNotReached as stopped:
        return finish(ContainmentClassification.POLICY_DENIED,
                      stopped.reason_code.value, digest, broker=True,
                      policy=True)
    recorder.emit(AuditStage.APPROVAL_DECIDED,
                  _state(attempted=True, broker=True, policy=True,
                         approved=approval.approved),
                  approval_reason_code=approval.reason_code.value)
    if not approval.approved:
        classification = _APPROVAL_CLASSIFICATION.get(approval.reason_code,
                                                     ContainmentClassification.APPROVAL_DENIED)
        return finish(classification, approval.reason_code.value, digest,
                      broker=True, policy=True)

    if executor is None:
        return finish(ContainmentClassification.INCONCLUSIVE,
                      "no_executor_configured", digest, broker=True,
                      policy=True, approved=True)

    try:
        outcome: ExecutionResult = executor.execute(
            action, digest, broker, policy, approval, protected_user,
            protected_key_id)
    except ExecutionPrerequisiteError as refused:
        return finish(refused.classification, refused.problem, digest,
                      broker=True, policy=True, approved=True)
    mutation_executed = outcome.execution_attempted
    final_state = _state(attempted=True, broker=True, policy=True,
                         approved=True, executed=mutation_executed,
                         effective=outcome.verified_effective)
    recorder.emit(AuditStage.EXECUTION_DECIDED, final_state,
                  execution_status=outcome.classification.value)
    recorder.emit(AuditStage.VERIFICATION_DECIDED,
                  _state(attempted=True, broker=True, policy=True,
                         approved=True,
                         executed=mutation_executed,
                         effective=outcome.verified_effective),
                  execution_status=outcome.classification.value,
                  verification_status="effective" if outcome.verified_effective
                  else "not_effective")
    return finish(outcome.classification, outcome.reason_code, digest,
                  broker=True, policy=True, approved=True, result=outcome)