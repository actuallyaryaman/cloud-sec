__all__ = [
    "SufficiencyStatus",
    "ACTION_IDENTIFIER_KINDS",
    "classify_final",
]

from collections.abc import Mapping

from .grounding import GroundingStatus, classify_use


class SufficiencyStatus:
    ACTIONABLE_SUFFICIENT = "ACTIONABLE_SUFFICIENT"
    PREMATURE_ACTIONABLE = "PREMATURE_ACTIONABLE"
    NONACTIONABLE_SAFE = "NONACTIONABLE_SAFE"
    INSUFFICIENT_UNKNOWN = "INSUFFICIENT_UNKNOWN"


ACTION_IDENTIFIER_KINDS = {
    "update_access_key": {
        "UserName": "username",
        "AccessKeyId": "access_key_id",
    },
}


def classify_final(action, observations) -> str:
    if action is None:
        return SufficiencyStatus.NONACTIONABLE_SAFE
    kinds = ACTION_IDENTIFIER_KINDS.get(getattr(action, "tool_id", None))
    if kinds is None:
        return SufficiencyStatus.INSUFFICIENT_UNKNOWN
    raw = getattr(action, "arguments", None)
    arguments = dict(raw) if isinstance(raw, Mapping) else {}
    for name, kind in kinds.items():
        if classify_use(arguments.get(name), observations or (),
                         kind) != GroundingStatus.OBSERVED_TYPED:
            return SufficiencyStatus.PREMATURE_ACTIONABLE
    return SufficiencyStatus.ACTIONABLE_SUFFICIENT
