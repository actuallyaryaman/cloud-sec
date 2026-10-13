__all__ = [
    "AgentLimits",
    "AgentToolCall",
    "RecommendedAction",
    "AgentFinalAnswer",
    "ToolObservation",
    "InvestigationStatus",
    "InvestigationResult",
]

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType


def _freeze_arguments(arguments):
    if arguments is None:
        return MappingProxyType({})
    if isinstance(arguments, MappingProxyType):
        return arguments
    if isinstance(arguments, dict):
        return MappingProxyType(dict(arguments))
    raise TypeError("arguments must be a mapping")


def _thaw(arguments):
    if isinstance(arguments, MappingProxyType):
        return dict(arguments)
    return dict(arguments)


def _require_text(name, value, max_chars=None):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if max_chars is not None and len(value) > max_chars:
        raise ValueError(f"{name} exceeds {max_chars} characters")
    return value


@dataclass(frozen=True)
class AgentLimits:
    max_turns: int = 20
    max_tool_calls: int = 30
    max_identical_request_repeats: int = 2
    max_rationale_chars: int = 500
    max_justification_chars: int = 200
    max_findings: int = 20
    max_evidence_refs: int = 20
    max_observation_string_chars: int = 2000

    def __post_init__(self):
        for name in ("max_turns", "max_tool_calls",
                     "max_identical_request_repeats",
                     "max_rationale_chars", "max_justification_chars",
                     "max_findings", "max_evidence_refs",
                     "max_observation_string_chars"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive int")


@dataclass(frozen=True)
class AgentToolCall:
    call_id: str
    tool_id: str
    arguments: object = field(default_factory=dict)
    justification: str = ""

    def __post_init__(self):
        _require_text("call_id", self.call_id)
        _require_text("tool_id", self.tool_id)
        object.__setattr__(self, "arguments",
                            _freeze_arguments(self.arguments))
        if not isinstance(self.justification, str):
            raise TypeError("justification must be a string")


@dataclass(frozen=True)
class RecommendedAction:
    tool_id: str
    arguments: object = field(default_factory=dict)
    reason: str = ""

    def __post_init__(self):
        _require_text("tool_id", self.tool_id)
        object.__setattr__(self, "arguments",
                            _freeze_arguments(self.arguments))
        if not isinstance(self.reason, str):
            raise TypeError("reason must be a string")


@dataclass(frozen=True)
class AgentFinalAnswer:
    compromised_principal: str
    compromised_access_key_id: str
    confidence: float
    findings: tuple = ()
    evidence_refs: tuple = ()
    recommended_action: RecommendedAction = None
    rationale_summary: str = ""

    def __post_init__(self):
        _require_text("compromised_principal", self.compromised_principal)
        _require_text("compromised_access_key_id",
                      self.compromised_access_key_id)
        if isinstance(self.confidence, bool) or \
                not isinstance(self.confidence, (int, float)):
            raise TypeError("confidence must be a number")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be within [0, 1]")
        object.__setattr__(self, "findings", tuple(self.findings or ()))
        object.__setattr__(self, "evidence_refs",
                            tuple(self.evidence_refs or ()))
        for item in self.findings:
            if not isinstance(item, str):
                raise TypeError("findings must be strings")
        for item in self.evidence_refs:
            if not isinstance(item, str):
                raise TypeError("evidence_refs must be strings")
        if self.recommended_action is not None and \
                not isinstance(self.recommended_action, RecommendedAction):
            raise TypeError(
                "recommended_action must be a RecommendedAction")
        if not isinstance(self.rationale_summary, str):
            raise TypeError("rationale_summary must be a string")


@dataclass(frozen=True)
class ToolObservation:
    call_id: str
    request_id: str
    tool_id: str
    ok: bool
    classification: str
    data: object = field(default_factory=dict)
    safe_error: str = ""
    repeat_count: int = 1
    next_identical_request_will_stop: bool = False
    repeat_warning: str = ""

    def __post_init__(self):
        _require_text("call_id", self.call_id)
        _require_text("request_id", self.request_id)
        _require_text("tool_id", self.tool_id)
        if not isinstance(self.ok, bool):
            raise TypeError("ok must be a bool")
        _require_text("classification", self.classification)
        object.__setattr__(self, "data", _freeze_arguments(self.data))
        if not isinstance(self.safe_error, str):
            raise TypeError("safe_error must be a string")
        if isinstance(self.repeat_count, bool) or \
                not isinstance(self.repeat_count, int) or \
                self.repeat_count < 1:
            raise ValueError("repeat_count must be a positive int")
        if not isinstance(self.next_identical_request_will_stop, bool):
            raise TypeError("next_identical_request_will_stop must be a bool")
        if not isinstance(self.repeat_warning, str):
            raise TypeError("repeat_warning must be a string")


class InvestigationStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"
    LIMIT_REACHED = "LIMIT_REACHED"


@dataclass(frozen=True)
class InvestigationResult:
    run_id: str
    status: InvestigationStatus
    findings: tuple = ()
    compromised_principal: str = ""
    compromised_access_key_id: str = ""
    confidence: float = 0.0
    recommended_action: RecommendedAction = None
    evidence_refs: tuple = ()
    tool_call_count: int = 0
    model_turn_count: int = 0
    stop_reason: str = ""

    def __post_init__(self):
        _require_text("run_id", self.run_id)
        if not isinstance(self.status, InvestigationStatus):
            raise TypeError("status must be an InvestigationStatus")
        object.__setattr__(self, "findings", tuple(self.findings or ()))
        object.__setattr__(self, "evidence_refs",
                            tuple(self.evidence_refs or ()))
        if self.recommended_action is not None and \
                not isinstance(self.recommended_action, RecommendedAction):
            raise TypeError(
                "recommended_action must be a RecommendedAction")
        for name in ("tool_call_count", "model_turn_count"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative int")
        if not isinstance(self.stop_reason, str) or not self.stop_reason:
            raise ValueError("stop_reason must be a non-empty string")
