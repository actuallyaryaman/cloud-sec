__all__ = [
    "KNOWN_TOOL_IDS",
    "ToolPortError",
    "BackendToolRequest",
    "ToolResult",
    "ToolPort",
]

from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import MappingProxyType


KNOWN_TOOL_IDS = frozenset({
    "s3_get_object",
    "s3_list_objects",
    "iam_get_user",
    "iam_list_access_keys",
    "iam_get_user_policy",
    "iam_list_user_policies",
    "iam_list_users",
    "secrets_describe_secret",
    "logs_get_log_events",
    "lambda_get_function_configuration",
    "get_secret_value",
    "update_access_key",
})


class ToolPortError(Exception):
    pass


def _freeze(arguments):
    if arguments is None:
        return MappingProxyType({})
    if isinstance(arguments, MappingProxyType):
        return arguments
    if isinstance(arguments, dict):
        return MappingProxyType(dict(arguments))
    raise TypeError("arguments must be a mapping")


@dataclass(frozen=True)
class BackendToolRequest:
    request_id: str
    tool_id: str
    arguments: object
    actor: str
    scenario_id: str
    justification: str = ""

    def __post_init__(self):
        for name in ("request_id", "tool_id", "actor", "scenario_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        object.__setattr__(self, "arguments", _freeze(self.arguments))
        if not isinstance(self.justification, str):
            raise TypeError("justification must be a string")


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    classification: str
    data: object = None
    safe_error: str = ""

    def __post_init__(self):
        if not isinstance(self.ok, bool):
            raise TypeError("ok must be a bool")
        if not isinstance(self.classification, str) or \
                not self.classification:
            raise ValueError("classification must be a non-empty string")
        object.__setattr__(self, "data", _freeze(self.data))
        if not isinstance(self.safe_error, str):
            raise TypeError("safe_error must be a string")


class ToolPort(ABC):
    @abstractmethod
    def execute(self, invocation: BackendToolRequest) -> ToolResult:
        raise NotImplementedError
