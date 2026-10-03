__all__ = [
    "ToolRequest",
    "CanonicalAction",
    "ToolValidationError",
    "ToolCanonicalizationError",
    "CANONICAL_STATUS_INACTIVE",
    "SECRET_READ_OUTCOMES",
    "canonicalize",
    "validate_arguments",
    "canonical_json",
    "action_digest",
    "canonicalize_containment_update_access_key",
    "canonicalize_secret_read",
]

import hashlib
import json
from dataclasses import dataclass, field
from types import MappingProxyType

from .registry import (CONTAINMENT_CANONICALIZER, GET_SECRET_VALUE,
                       SECRET_READ_CANONICALIZER, UPDATE_ACCESS_KEY,
                       get_tool)

CANONICAL_STATUS_INACTIVE = "Inactive"

CONTAINMENT_USER = "incident-user"

SECRET_READ_OUTCOMES = ("requested", "authorized", "executed",
                         "value_returned")

_SECRET_ACTIONS = ("GetSecretValue", "CreateSecret", "PutSecretValue",
                   "UpdateSecret", "DeleteSecret", "RestoreSecret",
                   "ReplicateSecret", "RotateSecret", "CancelRotateSecret",
                   "TagResource", "UntagResource")


class ToolValidationError(ValueError):
    def __init__(self, tool_id, problem, argument_names=()):
        self.tool_id = tool_id
        self.problem = problem
        self.argument_names = tuple(argument_names)
        super().__init__(f"{tool_id}: {problem}"
                         + (f" {list(self.argument_names)}" if self.argument_names
                            else ""))


class ToolCanonicalizationError(ValueError):
    def __init__(self, tool_id, problem):
        self.tool_id = tool_id
        self.problem = problem
        super().__init__(f"{tool_id}: {problem}")


def _freeze(arguments):
    if arguments is None:
        return MappingProxyType({})
    if not isinstance(arguments, dict):
        raise TypeError("arguments must be a dict")
    return MappingProxyType(dict(arguments))


def _thaw(arguments):
    if isinstance(arguments, MappingProxyType):
        return dict(arguments)
    if isinstance(arguments, dict):
        return dict(arguments)
    raise TypeError("arguments must be a mapping")


@dataclass(frozen=True)
class ToolRequest:
    request_id: str
    tool_id: str
    arguments: object
    actor: str
    scenario_id: str
    justification: str = ""

    def __post_init__(self):
        object.__setattr__(self, "arguments", _freeze(self.arguments))

    def as_dict(self) -> dict:
        return {"request_id": self.request_id, "tool_id": self.tool_id,
                "arguments": _thaw(self.arguments), "actor": self.actor,
                "scenario_id": self.scenario_id,
                "justification": self.justification}


@dataclass(frozen=True)
class CanonicalAction:
    tool_id: str
    service_action: str
    resource: str
    normalized_arguments: object = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "normalized_arguments",
                           _freeze(self.normalized_arguments))

    def as_dict(self) -> dict:
        return {"tool_id": self.tool_id,
                "service_action": self.service_action,
                "resource": self.resource,
                "normalized_arguments": _thaw(self.normalized_arguments)}


def validate_arguments(spec, arguments) -> dict:
    supplied = _thaw(arguments)
    allowed = set(spec.required_arguments) | set(spec.optional_arguments)
    unknown = sorted(set(supplied) - allowed)
    if unknown:
        raise ToolValidationError(spec.tool_id, "unknown argument names",
                                  unknown)
    missing = sorted(name for name in spec.required_arguments
                     if name not in supplied)
    if missing:
        raise ToolValidationError(spec.tool_id, "missing required arguments",
                                  missing)
    return supplied


def _require_text(spec, arguments, name) -> str:
    value = arguments[name]
    if not isinstance(value, str) or not value.strip():
        raise ToolValidationError(spec.tool_id,
                                  "argument must be a non-empty string",
                                  (name,))
    return value


def canonicalize_containment_update_access_key(arguments) -> CanonicalAction:
    from ..scenario.seed import incident_user_arn

    spec = get_tool(UPDATE_ACCESS_KEY)
    supplied = validate_arguments(spec, arguments)
    user_name = _require_text(spec, supplied, "UserName")
    access_key_id = _require_text(spec, supplied, "AccessKeyId")
    status = supplied["Status"]
    if not isinstance(status, str):
        raise ToolValidationError(spec.tool_id,
                                  "argument must be a non-empty string",
                                  ("Status",))
    if status != CANONICAL_STATUS_INACTIVE:
        raise ToolValidationError(
            spec.tool_id,
            f"status must be {CANONICAL_STATUS_INACTIVE}", ("Status",))
    if user_name != CONTAINMENT_USER:
        raise ToolValidationError(
            spec.tool_id, f"user must be {CONTAINMENT_USER}", ("UserName",))
    return CanonicalAction(
        tool_id=spec.tool_id, service_action=spec.service_action,
        resource=incident_user_arn(),
        normalized_arguments={"AccessKeyId": access_key_id,
                              "Status": CANONICAL_STATUS_INACTIVE,
                              "UserName": user_name})


def canonicalize_secret_read(arguments) -> CanonicalAction:
    spec = get_tool(GET_SECRET_VALUE)
    supplied = validate_arguments(spec, arguments)
    secret_id = _require_text(spec, supplied, "SecretId")
    if any(action in secret_id for action in _SECRET_ACTIONS):
        raise ToolCanonicalizationError(spec.tool_id,
                                        "SecretId must be a read-only "
                                        "logical identifier")
    return CanonicalAction(tool_id=spec.tool_id,
                           service_action=spec.service_action,
                           resource=secret_id,
                           normalized_arguments={"SecretId": secret_id})


_CANONICALIZERS = {
    CONTAINMENT_CANONICALIZER: canonicalize_containment_update_access_key,
    SECRET_READ_CANONICALIZER: canonicalize_secret_read,
}

def canonicalize(spec, arguments) -> CanonicalAction:
    canonicalizer = _CANONICALIZERS.get(spec.canonicalizer_id)
    if canonicalizer is None:
        raise ToolCanonicalizationError(spec.tool_id,
                                        "no canonicalizer is implemented yet")
    return canonicalizer(arguments)


def canonical_json(action) -> str:
    payload = action.as_dict() if hasattr(action, "as_dict") else action
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False, default=_reject)


def _reject(value):
    raise TypeError(f"non-canonical value in action: {type(value).__name__}")


def action_digest(action) -> str:
    return hashlib.sha256(canonical_json(action).encode("utf-8")).hexdigest()