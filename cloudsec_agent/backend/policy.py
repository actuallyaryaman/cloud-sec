__all__ = [
    "PolicyReasonCode",
    "ScenarioPolicyContext",
    "PolicyDecision",
    "CONTAINMENT_RULE_ID",
    "evaluate_containment_policy",
]

from dataclasses import dataclass
from enum import Enum

from .registry import UPDATE_ACCESS_KEY
from ..scenario.seed import incident_user_arn, secret_logical_arn

CONTAINMENT_RULE_ID = "CONTAIN-001"

_CONTAINMENT_USER = "incident-user"
_CONTAINMENT_STATUS = "Inactive"
_CONTAINMENT_SERVICE_ACTION = "iam:UpdateAccessKey"
_CONTAINMENT_ARGUMENTS = frozenset({"UserName", "AccessKeyId", "Status"})
_NO_RULE = ""


class PolicyReasonCode(str, Enum):
    ALLOW_CONTAINMENT = "allow_containment"
    BROKER_NOT_GRANTED = "broker_not_granted"
    WRONG_TOOL = "wrong_tool"
    WRONG_SERVICE_ACTION = "wrong_service_action"
    WRONG_RESOURCE = "wrong_resource"
    WRONG_USER = "wrong_user"
    WRONG_ACCESS_KEY = "wrong_access_key"
    WRONG_STATUS = "wrong_status"
    ARGUMENT_SHAPE_INVALID = "argument_shape_invalid"
    NO_MATCHING_RULE = "no_matching_rule"


@dataclass(frozen=True)
class ScenarioPolicyContext:
    scenario_id: str
    incident_user: str
    compromised_access_key_id: str

    def __post_init__(self):
        for name in ("scenario_id", "incident_user",
                     "compromised_access_key_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise TypeError(f"{name} must be a non-empty string")


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: PolicyReasonCode
    rule_id: str
    evaluated_action_digest: str

    def __post_init__(self):
        if not isinstance(self.reason_code, PolicyReasonCode):
            raise TypeError("reason_code must be a PolicyReasonCode")
        if not isinstance(self.allowed, bool):
            raise TypeError("allowed must be a bool")
        if not isinstance(self.evaluated_action_digest, str) or \
                not self.evaluated_action_digest:
            raise TypeError("evaluated_action_digest must be a non-empty string")


def _deny(reason_code, digest, rule_id=_NO_RULE) -> PolicyDecision:
    return PolicyDecision(allowed=False, reason_code=reason_code,
                          rule_id=rule_id, evaluated_action_digest=digest)


def evaluate_containment_policy(action, digest, broker_decision,
                                context) -> PolicyDecision:
    if not broker_decision.granted:
        return _deny(PolicyReasonCode.BROKER_NOT_GRANTED, digest)
    if action.tool_id != UPDATE_ACCESS_KEY:
        return _deny(PolicyReasonCode.WRONG_TOOL, digest)
    if action.service_action != _CONTAINMENT_SERVICE_ACTION:
        return _deny(PolicyReasonCode.WRONG_SERVICE_ACTION, digest)
    expected_resource = incident_user_arn().rsplit("/", 1)[0] + \
        f"/{context.incident_user}"
    if action.resource != expected_resource:
        return _deny(PolicyReasonCode.WRONG_RESOURCE, digest)
    arguments = action.normalized_arguments
    if not isinstance(arguments, dict) and \
            not hasattr(arguments, "keys"):
        return _deny(PolicyReasonCode.ARGUMENT_SHAPE_INVALID, digest)
    if set(arguments.keys()) != _CONTAINMENT_ARGUMENTS:
        return _deny(PolicyReasonCode.ARGUMENT_SHAPE_INVALID, digest)
    if arguments["UserName"] != context.incident_user:
        return _deny(PolicyReasonCode.WRONG_USER, digest)
    if arguments["Status"] != _CONTAINMENT_STATUS:
        return _deny(PolicyReasonCode.WRONG_STATUS, digest)
    if arguments["AccessKeyId"] != context.compromised_access_key_id:
        return _deny(PolicyReasonCode.WRONG_ACCESS_KEY, digest)
    return PolicyDecision(allowed=True,
                          reason_code=PolicyReasonCode.ALLOW_CONTAINMENT,
                          rule_id=CONTAINMENT_RULE_ID,
                          evaluated_action_digest=digest)