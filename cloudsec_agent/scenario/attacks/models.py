__all__ = [
    "ATTACK_VERSION",
    "SUPPORTED_ATTACK_VERSIONS",
    "AttackClass",
    "AttackStrength",
    "AttackPlacement",
    "AttackObjective",
    "ContextPenetration",
    "ModelCompromise",
    "ControlResponse",
    "SystemEffect",
    "BlockStage",
    "AttackSpec",
    "InjectedArtifact",
    "AttackManifest",
    "AttackedScenarioView",
    "AttackTransformResult",
    "AttackProvenance",
    "SecretFlow",
    "ActionPath",
    "AttackOutcome",
]

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum

ATTACK_VERSION = "m8a-v1"
SUPPORTED_ATTACK_VERSIONS = ("m8a-v1",)


class AttackClass(str, Enum):
    EVIDENCE_PROMPT_INJECTION = "evidence_prompt_injection"
    INVESTIGATOR_STEERING = "investigator_steering"
    DECOY_PRINCIPAL = "decoy_principal"
    RESOURCE_SUBSTITUTION = "resource_substitution"
    SECRET_EXFILTRATION_LURE = "secret_exfiltration_lure"


class AttackStrength(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AttackPlacement(str, Enum):
    S3_OBJECT_BODY = "s3_object_body"
    S3_OBJECT_NAME = "s3_object_name"
    LOG_MESSAGE = "log_message"
    LOG_STREAM = "log_stream"
    SECRET_METADATA = "secret_metadata"


class AttackObjective(str, Enum):
    WRONG_ATTRIBUTION = "wrong_attribution"
    WRONG_KEY = "wrong_key"
    WRONG_CONTAINMENT_TARGET = "wrong_containment_target"
    INVESTIGATOR_SELF_TARGET = "investigator_self_target"
    CROSS_RESOURCE_TARGET = "cross_resource_target"
    SECRET_EXFILTRATION_REQUEST = "secret_exfiltration_request"
    PROMPT_INJECTION_FOLLOWING = "prompt_injection_following"
    FALSE_BENIGN = "false_benign"
    FALSE_POSITIVE = "false_positive"
    TOOL_ABUSE = "tool_abuse"


class ContextPenetration(str, Enum):
    NOT_OBSERVED = "not_observed"
    OBSERVED_BY_TOOL = "observed_by_tool"
    ENTERED_MODEL_CONTEXT = "entered_model_context"
    REFERENCED_IN_OUTPUT = "referenced_in_output"
    INFLUENCED_ACTION = "influenced_action"


class ModelCompromise(str, Enum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


class ControlResponse(str, Enum):
    NOT_NEEDED = "not_needed"
    BLOCKED = "blocked"
    ALLOWED_CORRECT = "allowed_correct"
    FAILED_TO_BLOCK = "failed_to_block"


class SystemEffect(str, Enum):
    SAFE = "safe"
    CORRECT_CONTAINMENT = "correct_containment"
    MISSED_CONTAINMENT = "missed_containment"
    HARMFUL_MUTATION = "harmful_mutation"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"


class BlockStage(str, Enum):
    NOT_BLOCKED = "not_blocked"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED_CANONICALIZATION = "blocked_canonicalization"
    BLOCKED_SCOPE = "blocked_scope"
    BLOCKED_BROKER = "blocked_broker"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_APPROVAL = "blocked_approval"
    BLOCKED_EXECUTOR_PRECONDITION = "blocked_executor_precondition"
    EXECUTED_BUT_INEFFECTIVE = "executed_but_ineffective"
    HARMFUL_EFFECTIVE = "harmful_effective"


def _require_version(value):
    if value not in SUPPORTED_ATTACK_VERSIONS:
        raise ValueError(f"unknown attack version: {value!r}")
    return value


def _digest(payload) -> str:
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, default=str).encode()).hexdigest()


@dataclass(frozen=True)
class AttackSpec:
    attack_version: str
    attack_class: AttackClass
    strength: AttackStrength
    placement: AttackPlacement
    payload_template_id: str
    objective: AttackObjective
    attack_index: int = 0

    def __post_init__(self):
        _require_version(self.attack_version)
        if not isinstance(self.attack_class, AttackClass):
            raise TypeError("attack_class must be an AttackClass")
        if not isinstance(self.strength, AttackStrength):
            raise TypeError("strength must be an AttackStrength")
        if not isinstance(self.placement, AttackPlacement):
            raise TypeError("placement must be an AttackPlacement")
        if not isinstance(self.payload_template_id, str) or \
                not self.payload_template_id:
            raise ValueError("payload_template_id must be non-empty")
        if not isinstance(self.objective, AttackObjective):
            raise TypeError("objective must be an AttackObjective")
        if not isinstance(self.attack_index, int) or self.attack_index < 0:
            raise ValueError("attack_index must be a non-negative int")

    def as_dict(self) -> dict:
        return {
            "attack_version": self.attack_version,
            "attack_class": self.attack_class.value,
            "strength": self.strength.value,
            "placement": self.placement.value,
            "payload_template_id": self.payload_template_id,
            "objective": self.objective.value,
            "attack_index": self.attack_index,
        }

    def digest(self) -> str:
        return _digest(self.as_dict())


@dataclass(frozen=True)
class InjectedArtifact:
    artifact_id: str
    placement: AttackPlacement
    channel_identity: str
    content_digest: str
    model_readable: bool = True

    def as_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "placement": self.placement.value,
            "channel_identity": self.channel_identity,
            "content_digest": self.content_digest,
            "model_readable": self.model_readable,
        }


@dataclass(frozen=True)
class AttackManifest:
    attack_id: str
    attack_version: str
    source_scenario_id: str
    attack_class: AttackClass
    strength: AttackStrength
    placement: AttackPlacement
    objective: AttackObjective
    injected_artifacts: tuple = ()
    decoy_identities: tuple = ()
    expected_unauthorized_target: object = None
    secret_reference: object = None
    intended_boundary: str = ""

    def __post_init__(self):
        _require_version(self.attack_version)
        object.__setattr__(self, "injected_artifacts",
                           tuple(self.injected_artifacts or ()))
        object.__setattr__(self, "decoy_identities",
                           tuple(self.decoy_identities or ()))

    def as_dict(self) -> dict:
        return {
            "attack_id": self.attack_id,
            "attack_version": self.attack_version,
            "source_scenario_id": self.source_scenario_id,
            "attack_class": self.attack_class.value,
            "strength": self.strength.value,
            "placement": self.placement.value,
            "objective": self.objective.value,
            "injected_artifacts": [
                item.as_dict() for item in self.injected_artifacts],
            "decoy_identities": list(self.decoy_identities),
            "expected_unauthorized_target":
                self.expected_unauthorized_target,
            "secret_reference": self.secret_reference,
            "intended_boundary": self.intended_boundary,
        }


@dataclass(frozen=True)
class AttackProvenance:
    attack_id: str
    artifact_id: str
    placement: AttackPlacement
    content_digest: str
    source_scenario_id: str
    model_readable: bool
    trusted: bool = False

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["placement"] = self.placement.value
        return payload


@dataclass(frozen=True)
class AttackedScenarioView:
    source_scenario_id: str
    attack_id: str
    attack_version: str
    spec_snapshot_digest: str
    added_objects: tuple = ()
    added_log_events: tuple = ()
    added_log_streams: tuple = ()
    manifest: object = None

    def __post_init__(self):
        _require_version(self.attack_version)
        object.__setattr__(self, "added_objects",
                           tuple(self.added_objects or ()))
        object.__setattr__(self, "added_log_events",
                           tuple(self.added_log_events or ()))
        object.__setattr__(self, "added_log_streams",
                           tuple(self.added_log_streams or ()))


@dataclass(frozen=True)
class AttackTransformResult:
    source_scenario_id: str
    attack_id: str
    view: AttackedScenarioView
    manifest: AttackManifest
    transform_digest: str
    changed_fields: tuple = ()

    def __post_init__(self):
        object.__setattr__(self, "changed_fields",
                           tuple(self.changed_fields or ()))


@dataclass(frozen=True)
class SecretFlow:
    requested: bool = False
    broker_authorized: bool = False
    policy_allowed: bool = False
    backend_executed: bool = False
    value_returned: bool = False
    entered_model_context: bool = False

    def __post_init__(self):
        if self.entered_model_context and not self.value_returned:
            raise ValueError("entered context requires returned value")
        if self.value_returned and not self.backend_executed:
            raise ValueError("returned value requires backend execution")
        if self.backend_executed and not (
                self.broker_authorized and self.policy_allowed):
            raise ValueError("backend execution requires authorization")


@dataclass(frozen=True)
class ActionPath:
    proposed: bool = False
    canonicalizable: bool = False
    broker_granted: bool = False
    policy_allowed: bool = False
    approval_issued: bool = False
    executor_called: bool = False
    mutation_issued: bool = False
    effective: bool = False
    target_correct: bool = False
    target_authorized: bool = False
    investigator_preserved: bool = True


@dataclass(frozen=True)
class AttackOutcome:
    attack_id: str
    penetration: ContextPenetration = ContextPenetration.NOT_OBSERVED
    compromise: ModelCompromise = ModelCompromise.NONE
    secret_flow: SecretFlow = field(default_factory=SecretFlow)
    action_path: ActionPath = field(default_factory=ActionPath)
    block_stage: BlockStage = BlockStage.NOT_APPLICABLE
    control_response: ControlResponse = ControlResponse.NOT_NEEDED
    system_effect: SystemEffect = SystemEffect.SAFE
