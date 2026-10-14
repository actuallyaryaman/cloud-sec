__all__ = [
    "ContainmentScope",
    "derive_containment_scope",
]

import hashlib
import json

from ..backend.broker import CapabilitySet
from ..scenario.seed import incident_user_arn


def _users_root() -> str:
    return incident_user_arn().rsplit("/", 1)[0]


class ContainmentScope:
    def __init__(self, scenario_id, allowed_user_name=None,
                 allowed_user_arn=None):
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("scenario_id must be a non-empty string")
        if allowed_user_name is None and allowed_user_arn is None:
            self._user_name = None
            self._user_arn = None
        else:
            if not isinstance(allowed_user_name, str) or \
                    not allowed_user_name:
                raise ValueError(
                    "allowed_user_name must be a non-empty string")
            if not isinstance(allowed_user_arn, str) or \
                    not allowed_user_arn:
                raise ValueError("allowed_user_arn must be a non-empty string")
            self._user_name = allowed_user_name
            self._user_arn = allowed_user_arn
        self._scenario_id = scenario_id

    @property
    def scenario_id(self) -> str:
        return self._scenario_id

    @property
    def allowed_user_name(self):
        return self._user_name

    @property
    def allowed_user_arn(self):
        return self._user_arn

    @property
    def has_target(self) -> bool:
        return self._user_name is not None

    def to_capability(self) -> CapabilitySet:
        if not self.has_target:
            return CapabilitySet(tool_resources={})
        return CapabilitySet(tool_resources={
            "update_access_key": {self._user_arn}})

    def digest(self) -> str:
        canonical = json.dumps(
            {"scenario_id": self._scenario_id,
             "allowed_user_name": self._user_name,
             "allowed_user_arn": self._user_arn},
            sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict:
        return {"scenario_id": self._scenario_id,
                "allowed_user_name": self._user_name,
                "allowed_user_arn": self._user_arn}


def derive_containment_scope(spec) -> ContainmentScope:
    truth = getattr(spec, "ground_truth", None)
    malicious = bool(getattr(truth, "malicious", False)) \
        if truth is not None else False
    if not malicious:
        return ContainmentScope(spec.scenario_id)
    user_name = spec.incident_user
    return ContainmentScope(
        spec.scenario_id, user_name,
        _users_root() + f"/{user_name}")
