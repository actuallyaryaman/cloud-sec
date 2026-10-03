__all__ = [
    "BrokerReasonCode",
    "CapabilitySet",
    "BrokerGrant",
    "BrokerDecision",
    "CONTAINMENT_EXECUTION_PRINCIPAL",
    "BROAD_CAPABILITY",
    "TASK_SCOPED_CAPABILITY",
    "evaluate",
    "grant_for",
]

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from ..scenario import determinism as _d
from ..scenario.seed import (evidence_bucket_arn, incident_bucket_arn,
                             incident_user_arn, trail_bucket_arn)
from .registry import EXECUTION_IDENTITY_USER, GET_SECRET_VALUE, UPDATE_ACCESS_KEY

CONTAINMENT_EXECUTION_PRINCIPAL = EXECUTION_IDENTITY_USER

_FORBIDDEN_RESOURCE_CHARS = ("*", "?", "$")


class BrokerReasonCode(str, Enum):
    GRANTED = "granted"
    TOOL_NOT_GRANTED = "tool_not_granted"
    RESOURCE_NOT_GRANTED = "resource_not_granted"
    RUN_SCOPE_MISMATCH = "run_scope_mismatch"


def _freeze_resources(mapping):
    if mapping is None:
        return MappingProxyType({})
    if not isinstance(mapping, dict):
        raise TypeError("tool_resources must be a dict")
    frozen = {}
    for tool_id, resources in mapping.items():
        if not isinstance(tool_id, str) or not tool_id:
            raise TypeError("tool_id keys must be non-empty strings")
        if isinstance(resources, str) or not isinstance(resources, (set,
                                                                   frozenset,
                                                                   tuple,
                                                                   list)):
            raise TypeError("resources must be a collection of strings")
        for resource in resources:
            if not isinstance(resource, str) or not resource:
                raise TypeError("resources must be non-empty strings")
            for forbidden in _FORBIDDEN_RESOURCE_CHARS:
                if forbidden in resource:
                    raise ValueError(
                        "wildcard and pattern characters are not permitted "
                        "in a capability resource")
        frozen[tool_id] = frozenset(resources)
    return MappingProxyType(frozen)


@dataclass(frozen=True)
class CapabilitySet:
    tool_resources: object = field(default_factory=dict)
    run_scope: str = ""
    expires_at: object = None

    def __post_init__(self):
        object.__setattr__(self, "tool_resources",
                           _freeze_resources(self.tool_resources))

    @property
    def tool_ids(self) -> frozenset:
        return frozenset(self.tool_resources)

    def resources_for(self, tool_id) -> frozenset:
        return self.tool_resources.get(tool_id, frozenset())

    def permits(self, tool_id, resource) -> bool:
        return tool_id in self.tool_resources and \
            resource in self.tool_resources[tool_id]


@dataclass(frozen=True)
class BrokerGrant:
    capability: CapabilitySet
    execution_principal_ref: str
    run_scope: str = ""

    def __post_init__(self):
        if not isinstance(self.capability, CapabilitySet):
            raise TypeError("capability must be a CapabilitySet")
        if not isinstance(self.execution_principal_ref, str) or \
                not self.execution_principal_ref:
            raise TypeError("execution_principal_ref must be a non-empty string")


@dataclass(frozen=True)
class BrokerDecision:
    granted: bool
    reason_code: BrokerReasonCode
    tool_id: str
    resource: str
    run_scope: str

    def __post_init__(self):
        if not isinstance(self.reason_code, BrokerReasonCode):
            raise TypeError("reason_code must be a BrokerReasonCode")
        if not isinstance(self.granted, bool):
            raise TypeError("granted must be a bool")


def evaluate(grant, action, current_run_scope) -> BrokerDecision:
    tool_id = action.tool_id
    resource = action.resource
    if not isinstance(current_run_scope, str) or \
            current_run_scope != grant.run_scope:
        return BrokerDecision(False, BrokerReasonCode.RUN_SCOPE_MISMATCH,
                              tool_id, resource, current_run_scope)
    if tool_id not in grant.capability.tool_resources:
        return BrokerDecision(False, BrokerReasonCode.TOOL_NOT_GRANTED,
                              tool_id, resource, current_run_scope)
    if not grant.capability.permits(tool_id, resource):
        return BrokerDecision(False, BrokerReasonCode.RESOURCE_NOT_GRANTED,
                              tool_id, resource, current_run_scope)
    return BrokerDecision(True, BrokerReasonCode.GRANTED, tool_id, resource,
                          current_run_scope)


def _investigation_resources() -> dict:
    return {
        "s3_get_object": frozenset({
            f"{incident_bucket_arn()}/reports/q1-summary.txt",
            f"{incident_bucket_arn()}/notes/handoff.md",
            f"{incident_bucket_arn()}/{_d.RESOURCES.restricted_object}",
            f"{evidence_bucket_arn()}/control/evidence-index.json",
            f"{trail_bucket_arn()}/csi-trail",
        }),
        "s3_list_objects": frozenset({incident_bucket_arn(),
                                      evidence_bucket_arn(),
                                      trail_bucket_arn()}),
        "iam_get_user": frozenset({incident_user_arn()}),
        "iam_list_access_keys": frozenset({incident_user_arn()}),
        "iam_get_user_policy": frozenset({incident_user_arn()}),
        "iam_list_user_policies": frozenset({incident_user_arn()}),
        "secrets_describe_secret": frozenset({_d.RESOURCES.secret_name}),
        "logs_get_log_events": frozenset({
            f"arn:aws:logs:us-east-1:000000000000:log-group:"
            f"{_d.RESOURCES.log_group}:log-stream:{_d.RESOURCES.log_stream}"}),
        "lambda_get_function_configuration": frozenset({
            f"arn:aws:lambda:us-east-1:000000000000:function:"
            f"{_d.RESOURCES.function_name}"}),
    }


BROAD_CAPABILITY = CapabilitySet(
    tool_resources={
        **_investigation_resources(),
        GET_SECRET_VALUE: frozenset({_d.RESOURCES.secret_name}),
        UPDATE_ACCESS_KEY: frozenset({incident_user_arn()}),
    },
    run_scope="",
    expires_at=None)

TASK_SCOPED_CAPABILITY = CapabilitySet(
    tool_resources=dict(_investigation_resources()),
    run_scope="",
    expires_at=None)

def grant_for(capability, run_scope, expires_at=None) -> BrokerGrant:
    return BrokerGrant(capability=capability,
                       execution_principal_ref=CONTAINMENT_EXECUTION_PRINCIPAL,
                       run_scope=run_scope)