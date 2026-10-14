__all__ = [
    "InvestigationScope",
    "derive_investigation_scope",
]

import hashlib
import json

from ..backend.broker import CapabilitySet
from ..backend.registry import READ_ONLY_SPECS
from .agent_backend import canonical_read_resource

_USERS_ROOT_SUFFIX = "/user"


def _users_root() -> str:
    return canonical_read_resource("iam_list_users", {})


def _user_arn(user_name) -> str:
    return _users_root() + f"/{user_name}"


def _collect(spec) -> dict:
    grants = {}
    grants["s3_list_objects"] = {
        canonical_read_resource("s3_list_objects",
                                {"Bucket": spec.bucket})}
    grants["s3_get_object"] = {
        canonical_read_resource("s3_get_object",
                                {"Bucket": spec.bucket, "Key": item.key})
        for item in spec.objects}
    grants["iam_list_users"] = {_users_root()}
    grants["iam_get_user"] = {_user_arn(spec.incident_user)}
    grants["iam_list_access_keys"] = {_user_arn(spec.incident_user)}
    grants["iam_list_user_policies"] = {_user_arn(spec.incident_user)}
    grants["iam_get_user_policy"] = {_user_arn(spec.incident_user)}
    grants["secrets_describe_secret"] = {
        canonical_read_resource("secrets_describe_secret",
                                {"SecretId": spec.secret_name})}
    grants["logs_get_log_events"] = {
        canonical_read_resource("logs_get_log_events",
                                {"logGroupName": spec.log_group,
                                 "logStreamName": spec.log_stream})}
    grants["lambda_get_function_configuration"] = {
        canonical_read_resource("lambda_get_function_configuration",
                                {"FunctionName": spec.function_name})}
    return {tool_id: frozenset(resources)
            for tool_id, resources in grants.items()}


class InvestigationScope:
    def __init__(self, scenario_id, tool_resources):
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("scenario_id must be a non-empty string")
        if not isinstance(tool_resources, dict) or not tool_resources:
            raise ValueError("tool_resources must be a non-empty dict")
        cleaned = {}
        for tool_id, resources in tool_resources.items():
            if not isinstance(tool_id, str) or not tool_id:
                raise ValueError("tool ids must be non-empty strings")
            cleaned[tool_id] = frozenset(resources)
        self._scenario_id = scenario_id
        self._grants = dict(cleaned)

    @property
    def scenario_id(self) -> str:
        return self._scenario_id

    @property
    def tool_ids(self) -> frozenset:
        return frozenset(self._grants)

    def resources_for(self, tool_id) -> frozenset:
        return self._grants.get(tool_id, frozenset())

    def to_capability(self) -> CapabilitySet:
        return CapabilitySet(tool_resources=dict(self._grants))

    def digest(self) -> str:
        canonical = json.dumps(
            {"scenario_id": self._scenario_id,
             "grants": {tool_id: sorted(resources)
                        for tool_id, resources in sorted(
                            self._grants.items())}},
            sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def derive_investigation_scope(spec) -> InvestigationScope:
    known = {item.tool_id for item in READ_ONLY_SPECS}
    collected = _collect(spec)
    unknown = set(collected) - known
    if unknown:
        raise ValueError(f"scope covers unknown tools: {sorted(unknown)}")
    return InvestigationScope(spec.scenario_id, collected)
