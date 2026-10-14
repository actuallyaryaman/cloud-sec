__all__ = [
    "InfraStatus",
    "ProviderStatus",
    "ContractStatus",
    "ModelDecision",
    "ControlStatus",
    "EffectiveState",
    "TopLevel",
    "Stability",
    "Truth",
    "ExperimentConfig",
    "ScenarioCase",
    "RunKey",
    "RunOutcome",
    "TokenUsage",
    "GroundingCounts",
    "Prematurity",
    "ScenarioAggregate",
    "BenchmarkSpec",
    "BenchmarkAggregate",
]

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum


class InfraStatus(str, Enum):
    VALID = "valid"
    GENERATION_FAILURE = "generation_failure"
    SEED_FAILURE = "seed_failure"
    VERIFY_FAILURE = "verify_failure"
    SCOPE_FAILURE = "scope_failure"
    BROKER_FAILURE = "broker_failure"
    CONTROL_FAILURE = "control_failure"
    CLEANUP_FAILURE = "cleanup_failure"


class ProviderStatus(str, Enum):
    NOT_CALLED = "not_called"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    SERVICE_UNAVAILABLE = "service_unavailable"
    TRANSPORT_ERROR = "transport_error"
    OTHER_PROVIDER_ERROR = "other_provider_error"


class ContractStatus(str, Enum):
    VALID = "valid"
    NO_FINAL = "no_final"
    FINAL_NOT_JSON = "final_not_json"
    INVALID_FINAL_SCHEMA = "invalid_final_schema"
    INVALID_TOOL_ARGS = "invalid_tool_args"
    OTHER_CONTRACT_FAILURE = "other_contract_failure"
    NOT_EVALUABLE = "not_evaluable"


class ModelDecision(str, Enum):
    SUCCESS = "success"
    WRONG_PRINCIPAL = "wrong_principal"
    WRONG_KEY = "wrong_key"
    PREMATURE_BENIGN = "premature_benign"
    INSUFFICIENT_INVESTIGATION = "insufficient_investigation"
    WRONG_ACTION = "wrong_action"
    TYPE_CONFUSION = "type_confusion"
    NO_VALID_FINAL = "no_valid_final"
    OTHER_MODEL_FAILURE = "other_model_failure"
    NOT_EVALUABLE = "not_evaluable"


class ControlStatus(str, Enum):
    NOT_PROPOSED = "not_proposed"
    PREPARE_ACCEPTED = "prepare_accepted"
    PREPARE_REJECTED = "prepare_rejected"
    APPROVED = "approved"
    EXECUTION_CONFIRMED = "execution_confirmed"
    ALREADY_EFFECTIVE = "already_effective"
    EXECUTION_FAILED = "execution_failed"
    NOT_APPLICABLE = "not_applicable"


class EffectiveState(str, Enum):
    TARGET_INACTIVE = "target_inactive"
    TARGET_ACTIVE = "target_active"
    BENIGN_UNCHANGED = "benign_unchanged"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class TopLevel(str, Enum):
    VALID_MODEL_SUCCESS = "valid_model_success"
    VALID_MODEL_FAILURE = "valid_model_failure"
    PROVIDER_INTERRUPTED = "provider_interrupted"
    RESPONSE_CONTRACT_FAILURE = "response_contract_failure"
    INFRASTRUCTURE_INVALID = "infrastructure_invalid"


class Stability(str, Enum):
    CONSISTENT_SUCCESS = "consistent_success"
    CONSISTENT_FAILURE = "consistent_failure"
    MIXED = "mixed"
    INSUFFICIENT_EVALUABLE_RUNS = "insufficient_evaluable_runs"


class Truth(str, Enum):
    MALICIOUS = "malicious"
    BENIGN = "benign"


def _digest(payload) -> str:
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, default=str).encode()).hexdigest()


@dataclass(frozen=True)
class ExperimentConfig:
    provider: str
    model: str
    adapter_version: str
    prompt_version: str
    temperature: float
    max_output_tokens: int
    retries: int
    generator_version: str

    def identity(self) -> str:
        return _digest({
            "provider": self.provider, "model": self.model,
            "adapter_version": self.adapter_version,
            "prompt_version": self.prompt_version,
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
            "retries": self.retries,
            "generator_version": self.generator_version})


@dataclass(frozen=True)
class ScenarioCase:
    family: str
    difficulty: str
    seed: int
    scenario_id: str
    malicious: bool
    calibration: bool = False


@dataclass(frozen=True)
class RunKey:
    benchmark_version: str
    scenario_id: str
    repetition_index: int
    config_digest: str

    def key(self) -> str:
        return (f"{self.benchmark_version}:{self.scenario_id}:"
                f"rep{self.repetition_index}:{self.config_digest[:12]}")


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True)
class GroundingCounts:
    observed_typed: int = 0
    literal_only: int = 0
    ungrounded: int = 0
    actor_reused_as_username: bool = False
    recovered_after_confusion: bool = False
    correct_username_observed: bool = False
    correct_key_observed: bool = False


@dataclass(frozen=True)
class Prematurity:
    material_path_remaining: bool = False
    iam_discovery_attempted: bool = False
    key_discovery_attempted: bool = False
    logs_path_attempted: bool = False
    final_turn: int = 0


@dataclass(frozen=True)
class RunOutcome:
    key: RunKey
    truth: Truth
    infra: InfraStatus
    provider: ProviderStatus
    contract: ContractStatus
    decision: ModelDecision
    control: ControlStatus
    effective: EffectiveState
    top_level: TopLevel
    turns: int = 0
    tool_calls: int = 0
    ordered_tools: tuple = ()
    broker_denials: int = 0
    unexpected_denials: int = 0
    grounding: GroundingCounts = field(default_factory=GroundingCounts)
    prematurity: Prematurity = field(default_factory=Prematurity)
    sufficiency: str = ""
    confidence: float = 0.0
    tokens: TokenUsage = field(default_factory=TokenUsage)
    latency_s: float = 0.0
    input_digest: str = ""
    unexpected_rejection: bool = False
    investigator_failed: bool = False
    provenance: tuple = ()


@dataclass(frozen=True)
class ScenarioAggregate:
    scenario_id: str
    family: str
    difficulty: str
    attempted_runs: int = 0
    evaluable_runs: int = 0
    provider_interrupted: int = 0
    infrastructure_invalid: int = 0
    successes: int = 0
    model_failures: int = 0
    contract_failures: int = 0
    actor_confusion_count: int = 0
    premature_final_count: int = 0
    no_final_count: int = 0
    turns: tuple = ()
    tool_calls: tuple = ()
    tokens: tuple = ()
    stability: Stability = Stability.INSUFFICIENT_EVALUABLE_RUNS

    def success_fraction_evaluable(self):
        if not self.evaluable_runs:
            return None
        return self.successes / self.evaluable_runs

    def success_fraction_attempted(self):
        if not self.attempted_runs:
            return None
        return self.successes / self.attempted_runs


@dataclass(frozen=True)
class BenchmarkSpec:
    version: str
    generator_version: str
    scoring_version: str
    repetitions: int
    min_evaluable: int
    cases: tuple = ()
    config: ExperimentConfig = None
    max_consecutive_interruptions: int = 3
    min_attempts_for_rate: int = 10
    max_interruption_rate: float = 0.20
    scheduler: dict = field(default_factory=dict)


@dataclass(frozen=True)
class BenchmarkAggregate:
    version: str
    scenarios: int = 0
    attempted_runs: int = 0
    evaluable_runs: int = 0
    successful_runs: int = 0
    model_failure_runs: int = 0
    provider_interrupted_runs: int = 0
    infrastructure_invalid_runs: int = 0
    benign_attempted: int = 0
    benign_evaluable: int = 0
    benign_correct: int = 0
    benign_false_positives: int = 0
    benign_interruptions: int = 0
    proposals: int = 0
    prepare_accepted: int = 0
    prepare_rejected: int = 0
    approvals: int = 0
    confirmed_mutations: int = 0
    already_effective: int = 0
    unexpected_valid_rejections: int = 0
    investigator_failures: int = 0
    actor_confusion_total: int = 0
    literal_only_total: int = 0
    ungrounded_total: int = 0
    scenario_stabilities: tuple = ()
