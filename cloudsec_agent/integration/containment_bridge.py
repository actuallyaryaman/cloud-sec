__all__ = [
    "ContainmentBridgeError",
    "PreparedContainment",
    "AgentContainmentOutcome",
    "ContainmentBridge",
]

import time
from dataclasses import dataclass

from ..agent.events import AgentEvent, AgentEventKind
from ..agent.models import RecommendedAction
from ..backend.audit import AuditLog
from ..backend.broker import BrokerGrant
from ..containment import contain_containment
from ..backend.executor import ContainmentClassification, ContainmentExecutor
from ..backend.policy import ScenarioPolicyContext
from ..backend.registry import UPDATE_ACCESS_KEY
from ..backend.request import (ToolRequest, action_digest,
                               canonicalize_containment_update_access_key)


class ContainmentBridgeError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


_POST_APPROVAL = frozenset({
    ContainmentClassification.CONFIRMED,
    ContainmentClassification.ALREADY_EFFECTIVE,
    ContainmentClassification.API_ERROR,
    ContainmentClassification.EMPTY_SUCCESS,
    ContainmentClassification.INCONCLUSIVE,
})

_APPROVAL_GATE = frozenset({
    ContainmentClassification.APPROVAL_DENIED,
    ContainmentClassification.APPROVAL_REQUIRED,
})


@dataclass(frozen=True)
class PreparedContainment:
    action_call_id: str
    request: ToolRequest
    digest: str

    def __post_init__(self):
        if not isinstance(self.action_call_id, str) or \
                not self.action_call_id:
            raise ValueError("action_call_id must be a non-empty string")
        if not isinstance(self.request, ToolRequest):
            raise TypeError("request must be a ToolRequest")
        if not isinstance(self.digest, str) or not self.digest:
            raise ValueError("digest must be a non-empty string")


@dataclass(frozen=True)
class AgentContainmentOutcome:
    run_id: str
    action_call_id: str
    backend_request_id: str
    classification: str
    executed: bool
    effective: bool
    approval_ref: str = ""
    reason_code: str = ""

    def __post_init__(self):
        for name in ("run_id", "action_call_id", "backend_request_id",
                     "classification"):
            if not isinstance(getattr(self, name), str) or \
                    not getattr(self, name):
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("executed", "effective"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a bool")
        if not isinstance(self.approval_ref, str):
            raise TypeError("approval_ref must be a string")
        if not isinstance(self.reason_code, str):
            raise TypeError("reason_code must be a string")


class ContainmentBridge:
    def __init__(self, *, run_id, actor, scenario_id, run_scope,
                 audit_log=None, clock=None, event_id_factory=None):
        for name, value in (("run_id", run_id), ("actor", actor),
                            ("scenario_id", scenario_id),
                            ("run_scope", run_scope)):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        self._run_id = run_id
        self._actor = actor
        self._scenario_id = scenario_id
        self._run_scope = run_scope
        self._log = audit_log if audit_log is not None else AuditLog()
        self._clock = clock or time.time
        self._event_id_factory = event_id_factory or (
            lambda rid, sequence: f"{rid}:c{sequence:04d}")
        self._events = []
        self._used_call_ids = set()

    @property
    def audits(self):
        return self._log.records()

    @property
    def events(self):
        return tuple(self._events)

    def _emit(self, kind, payload):
        sequence = len(self._events)
        event = AgentEvent(
            event_id=self._event_id_factory(self._run_id, sequence),
            run_id=self._run_id, sequence=sequence, kind=kind,
            timestamp=self._clock(), payload=dict(payload))
        self._events.append(event)
        return event

    def prepare(self, action_call_id, proposal, discovered_principal,
                discovered_key):
        if not isinstance(action_call_id, str) or not action_call_id:
            raise ContainmentBridgeError("invalid_call_id")
        if action_call_id in self._used_call_ids:
            raise ContainmentBridgeError("duplicate_call_id")
        if not isinstance(proposal, RecommendedAction):
            raise ContainmentBridgeError("not_a_recommendation")
        if proposal.tool_id != UPDATE_ACCESS_KEY:
            raise ContainmentBridgeError("unsupported_action")
        arguments = dict(proposal.arguments)
        if arguments.get("UserName") != discovered_principal or \
                arguments.get("AccessKeyId") != discovered_key:
            raise ContainmentBridgeError("discovery_mismatch")
        try:
            action = canonicalize_containment_update_access_key(arguments)
        except (ValueError, TypeError):
            raise ContainmentBridgeError("invalid_arguments")
        self._used_call_ids.add(action_call_id)
        request = ToolRequest(
            request_id=f"{self._run_id}:contain:{action_call_id}",
            tool_id=UPDATE_ACCESS_KEY, arguments=dict(arguments),
            actor=self._actor, scenario_id=self._scenario_id,
            justification=proposal.reason[:200])
        return PreparedContainment(action_call_id=action_call_id,
                                   request=request,
                                   digest=action_digest(action))

    def submit(self, prepared, *, grant, policy_context,
               approval_provider, executor, protected_user,
               protected_key_id, approval_ref="", current_time=None):
        if not isinstance(prepared, PreparedContainment):
            raise ContainmentBridgeError("not_prepared")
        if not isinstance(grant, BrokerGrant):
            raise ContainmentBridgeError("invalid_grant")
        if not isinstance(policy_context, ScenarioPolicyContext):
            raise ContainmentBridgeError("invalid_policy_context")
        if policy_context.scenario_id != self._scenario_id:
            raise ContainmentBridgeError("invalid_policy_context")
        if not isinstance(executor, ContainmentExecutor):
            raise TypeError("executor must be a ContainmentExecutor")
        request = prepared.request
        context = policy_context
        self._emit(AgentEventKind.CONTAINMENT_SUBMITTED,
                   {"action_call_id": prepared.action_call_id,
                    "backend_request_id": request.request_id,
                    "tool_id": request.tool_id})
        try:
            result = contain_containment(
                request, grant, context, executor, approval_provider,
                current_time if current_time is not None else self._clock(),
                protected_user, protected_key_id, self._log)
        except Exception:
            return self._failed(prepared, request, approval_ref)
        if result.classification in _POST_APPROVAL:
            self._emit(AgentEventKind.CONTAINMENT_APPROVED,
                       {"action_call_id": prepared.action_call_id,
                        "backend_request_id": request.request_id,
                        "approval_ref": approval_ref})
        elif result.classification in _APPROVAL_GATE:
            self._emit(AgentEventKind.CONTAINMENT_APPROVAL_REQUIRED,
                       {"action_call_id": prepared.action_call_id,
                        "backend_request_id": request.request_id})
        self._emit(AgentEventKind.CONTAINMENT_RESULT,
                   {"action_call_id": prepared.action_call_id,
                    "backend_request_id": request.request_id,
                    "classification": result.classification.value,
                    "executed": result.execution_attempted,
                    "effective": result.verified_effective,
                    "reason_code": result.reason_code})
        return AgentContainmentOutcome(
            run_id=self._run_id, action_call_id=prepared.action_call_id,
            backend_request_id=request.request_id,
            classification=result.classification.value,
            executed=result.execution_attempted,
            effective=result.verified_effective, approval_ref=approval_ref,
            reason_code=result.reason_code)

    def _failed(self, prepared, request, approval_ref):
        self._emit(AgentEventKind.CONTAINMENT_RESULT,
                   {"action_call_id": prepared.action_call_id,
                    "backend_request_id": request.request_id,
                    "classification": "bridge_error",
                    "executed": False, "effective": False,
                    "reason_code": "unexpected_failure"})
        return AgentContainmentOutcome(
            run_id=self._run_id, action_call_id=prepared.action_call_id,
            backend_request_id=request.request_id,
            classification="bridge_error", executed=False, effective=False,
            approval_ref=approval_ref, reason_code="unexpected_failure")
