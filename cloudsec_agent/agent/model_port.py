__all__ = [
    "ModelPortError",
    "ModelContext",
    "ModelTurn",
    "ModelPort",
]

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .models import AgentFinalAnswer, AgentToolCall


class ModelPortError(Exception):
    pass


@dataclass(frozen=True)
class ModelContext:
    run_id: str
    turn_number: int
    observations: tuple = ()
    turns_used: int = 0
    turns_remaining: int = 0
    tool_calls_used: int = 0
    tool_calls_remaining: int = 0
    budget_warning: str = ""

    def __post_init__(self):
        if not isinstance(self.run_id, str) or not self.run_id:
            raise ValueError("run_id must be a non-empty string")
        if not isinstance(self.turn_number, int) or self.turn_number < 1:
            raise ValueError("turn_number must be a positive int")
        object.__setattr__(self, "observations",
                            tuple(self.observations or ()))
        for name in ("turns_used", "turns_remaining", "tool_calls_used",
                     "tool_calls_remaining"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or \
                    value < 0:
                raise ValueError(f"{name} must be a non-negative int")
        if not isinstance(self.budget_warning, str):
            raise TypeError("budget_warning must be a string")


@dataclass(frozen=True)
class ModelTurn:
    tool_calls: tuple = ()
    final_answer: AgentFinalAnswer = None

    def __post_init__(self):
        calls = tuple(self.tool_calls or ())
        object.__setattr__(self, "tool_calls", calls)
        for item in calls:
            if not isinstance(item, AgentToolCall):
                raise TypeError("tool_calls must be AgentToolCall items")
        if self.final_answer is not None and \
                not isinstance(self.final_answer, AgentFinalAnswer):
            raise TypeError("final_answer must be an AgentFinalAnswer")
        if bool(calls) == (self.final_answer is not None):
            raise ValueError(
                "a turn must carry either tool_calls or a final_answer, "
                "never both or neither")

    @property
    def is_final(self) -> bool:
        return self.final_answer is not None


class ModelPort(ABC):
    @abstractmethod
    def complete(self, context: ModelContext) -> ModelTurn:
        raise NotImplementedError
