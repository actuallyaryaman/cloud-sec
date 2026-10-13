__all__ = [
    "GroundingStatus",
    "TYPED_FIELDS",
    "classify_use",
]

import json
from collections.abc import Mapping


class GroundingStatus:
    OBSERVED_TYPED = "OBSERVED_TYPED"
    LITERAL_ONLY = "LITERAL_ONLY"
    UNGROUNDED = "UNGROUNDED"


TYPED_FIELDS = {
    "username": frozenset({"user_name"}),
    "access_key_id": frozenset({"access_key_id", "actor_access_key_id"}),
    "actor": frozenset({"actor"}),
    "bucket": frozenset({"bucket"}),
    "object_key": frozenset({"key"}),
    "log_group": frozenset({"logGroupName"}),
    "log_stream": frozenset({"logStreamName"}),
    "secret": frozenset({"name", "secret_id"}),
    "function": frozenset({"function_name"}),
    "policy": frozenset({"policy_name"}),
    "arn": frozenset({"arn"}),
}


def _as_data(observation):
    if isinstance(observation, Mapping):
        return dict(observation)
    data = getattr(observation, "data", None)
    if isinstance(data, Mapping):
        return dict(data)
    return {}


def _pairs(blob, depth=0):
    found = []
    if isinstance(blob, str) and depth < 2:
        try:
            parsed = json.loads(blob)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            found.extend(_pairs(parsed, depth + 1))
            return found
        found.append((None, blob))
        return found
    if isinstance(blob, str):
        found.append((None, blob))
        return found
    if isinstance(blob, list):
        for item in blob:
            found.extend(_pairs(item, depth))
        return found
    if isinstance(blob, Mapping):
        for field, item in blob.items():
            if isinstance(item, str):
                found.append((field, item))
            found.extend(_pairs(item, depth))
        return found
    return found


def classify_use(value, observations, expected_kind) -> str:
    typed = TYPED_FIELDS.get(expected_kind, frozenset())
    pairs = []
    for observation in observations or ():
        pairs.extend(_pairs(_as_data(observation)))
    for field, item in pairs:
        if isinstance(value, str) and value and item == value and \
                field in typed:
            return GroundingStatus.OBSERVED_TYPED
    if isinstance(value, str) and value and \
            any(item == value for _, item in pairs):
        return GroundingStatus.LITERAL_ONLY
    return GroundingStatus.UNGROUNDED
