__all__ = [
    "AgentOrchestrator",
    "REPEAT_WARNING",
    "LOW_BUDGET_WARNING",
    "CONVERGENCE_CHECKPOINT",
    "CONVERGENCE_TOOL_CALLS",
]

import json
import time
from collections.abc import Mapping

from .events import AgentEvent, AgentEventKind
from .model_port import ModelContext, ModelPort, ModelPortError, ModelTurn
from .models import (AgentFinalAnswer, AgentLimits, InvestigationResult,
                     InvestigationStatus, RecommendedAction, ToolObservation)
from .tool_port import (KNOWN_TOOL_IDS, BackendToolRequest, ToolPort,
                        ToolPortError, ToolResult)

_STRIPPED_KEY_PARTS = ("secretstring", "secretbinary", "secretaccesskey",
                       "secretvalue", "sessiontoken", "credential",
                       "password", "privatekey")

REPEAT_WARNING = (
    "Warning: this exact tool request has already been repeated. "
    "Repeating the identical request again will terminate the "
    "investigation. Choose a different evidence-gathering action or "
    "provide your final answer.")

LOW_BUDGET_WARNING = (
    "Budget warning: the investigation budget is nearly exhausted. If "
    "the available evidence supports a grounded conclusion, produce the "
    "final answer now. Use another tool only if it is necessary to "
    "resolve a fact that could materially change the conclusion.")

CONVERGENCE_TOOL_CALLS = 8

CONVERGENCE_CHECKPOINT = (
    "Convergence checkpoint: substantial investigation has already been "
    "performed. Before requesting another tool, decide whether the "
    "current grounded evidence is sufficient for the best supported "
    "final answer. If it is sufficient, finalize now. Request another "
    "tool only if a specific unresolved fact could materially change "
    "the finding, confidence, or recommended action.")


def _summarize_request(tool_id, arguments) -> str:
    try:
        items = sorted(dict(arguments or {}).items())
    except (TypeError, ValueError, AttributeError):
        items = []
    parts = []
    for name, value in items:
        text = value if isinstance(value, str) else str(value)
        if len(text) > 120:
            text = text[:120] + "<truncated>"
        parts.append(f"{name}={text}")
    return f"{tool_id}({', '.join(parts)})"


def _normalize_key(name) -> str:
    return "".join(ch for ch in str(name).lower() if ch.isalnum())


def _sanitize_value(value, max_string_chars: int, depth: int):
    if isinstance(value, str):
        return value[:max_string_chars]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if depth <= 0:
        return None
    if isinstance(value, (list, tuple)):
        kept = []
        for item in list(value)[:50]:
            bound = _sanitize_value(item, max_string_chars, depth - 1)
            if bound is not None:
                kept.append(bound)
        return kept
    if isinstance(value, Mapping):
        kept = {}
        for key, item in list(dict(value).items())[:50]:
            if not isinstance(key, str):
                continue
            if any(part in _normalize_key(key)
                   for part in _STRIPPED_KEY_PARTS):
                continue
            bound = _sanitize_value(item, max_string_chars, depth - 1)
            if bound is not None:
                kept[key] = bound
        return kept
    return None


def sanitize_data(data, max_string_chars: int) -> dict:
    if data is None:
        return {}
    if isinstance(data, Mapping):
        data = dict(data)
    if not isinstance(data, dict):
        return {}
    clean = {}
    for key, value in data.items():
        if not isinstance(key, str):
            continue
        if any(part in _normalize_key(key) for part in _STRIPPED_KEY_PARTS):
            continue
        bound = _sanitize_value(value, max_string_chars, 2)
        if bound is not None:
            clean[key] = bound
    return clean


def repeat_key(tool_id: str, arguments) -> str:
    try:
        payload = json.dumps(arguments if isinstance(arguments, dict)
                             else dict(arguments),
                             sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False,
                             default=str)
    except (TypeError, ValueError):
        payload = "<unserializable>"
    return f"{tool_id}\0{payload}"


class AgentOrchestrator:
    def __init__(self, model: ModelPort, tools: ToolPort, *,
                 limits: AgentLimits = None,
                 actor: str = "agent",
                 scenario_id: str = "local",
                 clock=None,
                 event_id_factory=None):
        if not isinstance(model, ModelPort):
            raise TypeError("model must be a ModelPort")
        if not isinstance(tools, ToolPort):
            raise TypeError("tools must be a ToolPort")
        self._model = model
        self._tools = tools
        self._limits = limits or AgentLimits()
        if not isinstance(self._limits, AgentLimits):
            raise TypeError("limits must be an AgentLimits")
        if not isinstance(actor, str) or not actor:
            raise ValueError("actor must be a non-empty string")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("scenario_id must be a non-empty string")
        self._actor = actor
        self._scenario_id = scenario_id
        self._clock = clock or time.time
        self._event_id_factory = event_id_factory or (
            lambda run_id, sequence: f"{run_id}:e{sequence:04d}")

    def run(self, run_id: str):
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        limits = self._limits
        events = []
        observations = []
        repeat_counts = {}
        warned_requests = []
        tool_call_count = 0
        model_turn_count = 0

        def emit(kind, payload):
            sequence = len(events)
            event = AgentEvent(
                event_id=self._event_id_factory(run_id, sequence),
                run_id=run_id, sequence=sequence, kind=kind,
                timestamp=self._clock(), payload=dict(payload))
            events.append(event)
            return event

        def stop(status, stop_reason, findings=(), principal="",
                 key_id="", confidence=0.0, action=None, evidence=()):
            terminal = (AgentEventKind.RUN_COMPLETED
                        if status is InvestigationStatus.COMPLETE
                        else AgentEventKind.RUN_STOPPED)
            emit(terminal, {"status": status.value,
                            "stop_reason": stop_reason,
                            "tool_call_count": tool_call_count,
                            "model_turn_count": model_turn_count})
            result = InvestigationResult(
                run_id=run_id, status=status,
                findings=tuple(findings or ()),
                compromised_principal=principal,
                compromised_access_key_id=key_id,
                confidence=confidence, recommended_action=action,
                evidence_refs=tuple(evidence or ()),
                tool_call_count=tool_call_count,
                model_turn_count=model_turn_count,
                stop_reason=stop_reason)
            return result, tuple(events)

        emit(AgentEventKind.RUN_STARTED,
             {"actor": self._actor, "scenario_id": self._scenario_id,
              "max_turns": limits.max_turns,
              "max_tool_calls": limits.max_tool_calls})

        for turn_number in range(1, limits.max_turns + 1):
            model_turn_count += 1
            emit(AgentEventKind.MODEL_TURN_STARTED,
                 {"turn_number": turn_number})
            turns_remaining = limits.max_turns - model_turn_count
            calls_remaining = limits.max_tool_calls - tool_call_count
            budget_warning = ""
            if turns_remaining <= 3 or calls_remaining <= 5:
                budget_warning = LOW_BUDGET_WARNING
            convergence_checkpoint = ""
            if tool_call_count >= CONVERGENCE_TOOL_CALLS:
                convergence_checkpoint = CONVERGENCE_CHECKPOINT
            try:
                turn = self._model.complete(
                    ModelContext(run_id=run_id, turn_number=turn_number,
                                 observations=tuple(observations),
                                 turns_used=model_turn_count - 1,
                                 turns_remaining=turns_remaining,
                                 tool_calls_used=tool_call_count,
                                 tool_calls_remaining=calls_remaining,
                                 budget_warning=budget_warning,
                                 warned_requests=tuple(warned_requests),
                                 convergence_checkpoint=
                                 convergence_checkpoint))
            except ModelPortError as exc:
                return stop(InvestigationStatus.INCOMPLETE,
                            f"model_stopped:{self._safe_code(exc)}")
            except Exception:
                return stop(InvestigationStatus.FAILED, "model_error")
            if not isinstance(turn, ModelTurn):
                return stop(InvestigationStatus.FAILED,
                            "malformed_model_turn")
            if turn.is_final:
                code = self._check_final(turn.final_answer, limits)
                if code is not None:
                    return stop(InvestigationStatus.FAILED,
                                f"invalid_final_answer:{code}")
                answer = turn.final_answer
                emit(AgentEventKind.FINDING_UPDATED,
                     {"finding_count": len(answer.findings),
                      "evidence_count": len(answer.evidence_refs)})
                emit(AgentEventKind.ACTION_PROPOSED,
                     {"tool_id": answer.recommended_action.tool_id}
                     if answer.recommended_action is not None else {})
                return stop(
                    InvestigationStatus.COMPLETE, "final_answer_accepted",
                    findings=answer.findings,
                    principal=answer.compromised_principal,
                    key_id=answer.compromised_access_key_id,
                    confidence=float(answer.confidence),
                    action=answer.recommended_action,
                    evidence=answer.evidence_refs)
            for call in turn.tool_calls:
                shape_error = self._check_call_shape(call)
                if shape_error is not None:
                    observations.append(ToolObservation(
                        call_id=self._call_id(call),
                        request_id=f"{run_id}:req:invalid",
                        tool_id=self._tool_id(call), ok=False,
                        classification="validation_error",
                        data={}, safe_error=shape_error))
                    emit(AgentEventKind.TOOL_RESULT,
                         {"call_id": self._call_id(call),
                          "request_id": f"{run_id}:req:invalid",
                          "tool_id": self._tool_id(call), "ok": False,
                          "classification": "validation_error"})
                    continue
                if tool_call_count >= limits.max_tool_calls:
                    return stop(InvestigationStatus.LIMIT_REACHED,
                                "max_tool_calls_exceeded")
                key = repeat_key(call.tool_id, dict(call.arguments))
                seen = repeat_counts.get(key, 0)
                if seen >= limits.max_identical_request_repeats:
                    return stop(InvestigationStatus.LIMIT_REACHED,
                                "identical_request_repeat_limit")
                repeat_counts[key] = seen + 1
                repeat_count = seen + 1
                repeat_will_stop = repeat_count >= \
                    limits.max_identical_request_repeats
                repeat_warning = ""
                if repeat_will_stop:
                    repeat_warning = REPEAT_WARNING
                    summary = _summarize_request(call.tool_id,
                                                 dict(call.arguments))
                    if summary not in warned_requests:
                        warned_requests.append(summary)
                request_id = f"{run_id}:req:{tool_call_count:04d}"
                justification = (call.justification or "")[
                    :limits.max_justification_chars]
                emit(AgentEventKind.TOOL_REQUESTED,
                     {"call_id": call.call_id, "request_id": request_id,
                      "tool_id": call.tool_id})
                invocation = BackendToolRequest(
                    request_id=request_id, tool_id=call.tool_id,
                    arguments=dict(call.arguments), actor=self._actor,
                    scenario_id=self._scenario_id,
                    justification=justification)
                try:
                    outcome = self._tools.execute(invocation)
                except ToolPortError:
                    outcome = ToolResult(ok=False,
                                        classification="backend_error",
                                        safe_error="tool port failure")
                except Exception:
                    outcome = ToolResult(ok=False,
                                        classification="backend_error",
                                        safe_error="tool port failure")
                if not isinstance(outcome, ToolResult):
                    outcome = ToolResult(ok=False,
                                        classification="backend_error",
                                        safe_error="tool port failure")
                tool_call_count += 1
                safe_data = sanitize_data(
                    outcome.data, limits.max_observation_string_chars)
                safe_error = outcome.safe_error if outcome.ok else \
                    (outcome.safe_error[:limits.max_justification_chars]
                     if isinstance(outcome.safe_error, str)
                     else "tool request failed")
                observations.append(ToolObservation(
                    call_id=call.call_id, request_id=request_id,
                    tool_id=call.tool_id, ok=outcome.ok,
                    classification=outcome.classification,
                    data=safe_data, safe_error="" if outcome.ok
                    else safe_error, repeat_count=repeat_count,
                    next_identical_request_will_stop=repeat_will_stop,
                    repeat_warning=repeat_warning))
                emit(AgentEventKind.TOOL_RESULT,
                     {"call_id": call.call_id, "request_id": request_id,
                      "tool_id": call.tool_id, "ok": outcome.ok,
                      "classification": outcome.classification})
        return stop(InvestigationStatus.LIMIT_REACHED, "max_turns_exceeded")

    @staticmethod
    def _safe_code(exc) -> str:
        text = str(exc) if isinstance(exc, ModelPortError) else ""
        code = "".join(ch for ch in text.lower()
                       if ch.isalnum() or ch in ("-", "_", " "))[:60]
        return code.strip().replace(" ", "_") or "stopped"

    @staticmethod
    def _call_id(call) -> str:
        value = getattr(call, "call_id", "")
        return value if isinstance(value, str) and value else "<unknown>"

    @staticmethod
    def _tool_id(call) -> str:
        value = getattr(call, "tool_id", "")
        return value if isinstance(value, str) and value else "<unknown>"

    @staticmethod
    def _check_call_shape(call) -> str:
        if not hasattr(call, "tool_id") or \
                not isinstance(call.tool_id, str) or not call.tool_id:
            return "tool_id must be a non-empty string"
        if call.tool_id not in KNOWN_TOOL_IDS:
            return "unknown tool_id"
        arguments = getattr(call, "arguments", None)
        if not isinstance(arguments, Mapping):
            return "arguments must be a mapping"
        return None

    @staticmethod
    def _check_final(answer, limits: AgentLimits):
        if not isinstance(answer, AgentFinalAnswer):
            return "not_a_final_answer"
        if len(answer.findings) > limits.max_findings:
            return "too_many_findings"
        if len(answer.evidence_refs) > limits.max_evidence_refs:
            return "too_many_evidence_refs"
        if len(answer.rationale_summary) > limits.max_rationale_chars:
            return "oversized_rationale"
        for item in answer.findings:
            if len(item) > limits.max_rationale_chars:
                return "oversized_finding"
        for item in answer.evidence_refs:
            if len(item) > limits.max_rationale_chars:
                return "oversized_evidence_ref"
        action = answer.recommended_action
        if action is None:
            return "missing_recommended_action"
        if not isinstance(action, RecommendedAction):
            return "malformed_recommended_action"
        if action.tool_id not in KNOWN_TOOL_IDS:
            return "unknown_action_tool"
        if len(action.reason) > limits.max_rationale_chars:
            return "oversized_action_reason"
        return None
