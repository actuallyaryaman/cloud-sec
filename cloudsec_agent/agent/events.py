__all__ = [
    "AgentEventKind",
    "AgentEvent",
]

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType


class AgentEventKind(str, Enum):
    RUN_STARTED = "RUN_STARTED"
    MODEL_TURN_STARTED = "MODEL_TURN_STARTED"
    TOOL_REQUESTED = "TOOL_REQUESTED"
    TOOL_RESULT = "TOOL_RESULT"
    FINDING_UPDATED = "FINDING_UPDATED"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    RUN_COMPLETED = "RUN_COMPLETED"
    RUN_STOPPED = "RUN_STOPPED"


@dataclass(frozen=True)
class AgentEvent:
    event_id: str
    run_id: str
    sequence: int
    kind: AgentEventKind
    timestamp: object
    payload: object = None

    def __post_init__(self):
        for name in ("event_id", "run_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.sequence, int) or self.sequence < 0:
            raise ValueError("sequence must be a non-negative int")
        if not isinstance(self.kind, AgentEventKind):
            raise TypeError("kind must be an AgentEventKind")
        payload = self.payload
        if payload is None:
            payload = {}
        if isinstance(payload, MappingProxyType):
            pass
        elif isinstance(payload, dict):
            payload = MappingProxyType(dict(payload))
        else:
            raise TypeError("payload must be a mapping")
        object.__setattr__(self, "payload", payload)

    def as_dict(self) -> dict:
        return {"event_id": self.event_id, "run_id": self.run_id,
                "sequence": self.sequence, "kind": self.kind.value,
                "timestamp": self.timestamp, "payload": dict(self.payload)}
