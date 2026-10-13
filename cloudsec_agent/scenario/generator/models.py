__all__ = [
    "GENERATOR_VERSION",
    "SUPPORTED_VERSIONS",
    "FAMILY_CREDENTIAL_COMPROMISE",
    "FAMILY_RECON_HEAVY",
    "FAMILY_DATA_ACCESS_ANOMALY",
    "FAMILY_BENIGN",
    "FAMILIES",
    "DIFFICULTY_EASY",
    "DIFFICULTY_MEDIUM",
    "DIFFICULTIES",
    "Difficulty",
    "Provenance",
    "EvidenceObject",
    "LogEventSpec",
    "GroundTruth",
    "ExpectedState",
    "SeedManifest",
    "PublicBriefing",
    "ExperimentRecord",
    "GeneratedScenario",
]

from dataclasses import asdict, dataclass, field

GENERATOR_VERSION = "m7a-v1"
SUPPORTED_VERSIONS = ("m7a-v1",)

FAMILY_CREDENTIAL_COMPROMISE = "credential_compromise"
FAMILY_RECON_HEAVY = "recon_heavy"
FAMILY_DATA_ACCESS_ANOMALY = "data_access_anomaly"
FAMILY_BENIGN = "benign"
FAMILIES = (FAMILY_CREDENTIAL_COMPROMISE, FAMILY_RECON_HEAVY,
            FAMILY_DATA_ACCESS_ANOMALY, FAMILY_BENIGN)

DIFFICULTY_EASY = "easy"
DIFFICULTY_MEDIUM = "medium"
DIFFICULTIES = (DIFFICULTY_EASY, DIFFICULTY_MEDIUM)


class Difficulty:
    EASY = DIFFICULTY_EASY
    MEDIUM = DIFFICULTY_MEDIUM


class Provenance:
    LIVE_OBSERVED = "live_observed"
    RECORDED_RUNTIME = "recorded_runtime"
    INDEPENDENTLY_RECOMPUTED = "independently_recomputed"
    UNAVAILABLE_AFTER_TEARDOWN = "unavailable_after_teardown"


def _require_text(name, value):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class EvidenceObject:
    key: str
    body: str
    evidence_ref: str

    def __post_init__(self):
        _require_text("key", self.key)
        if not isinstance(self.body, str):
            raise TypeError("body must be a string")
        _require_text("evidence_ref", self.evidence_ref)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class LogEventSpec:
    ref: str
    actor: str
    actor_access_key_id: object = None
    operation: str = ""
    target: str = ""
    result: str = "success"
    key_ref: object = None

    def __post_init__(self):
        _require_text("ref", self.ref)
        _require_text("actor", self.actor)
        if self.actor_access_key_id is not None and \
                not isinstance(self.actor_access_key_id, str):
            raise TypeError("actor_access_key_id must be a string or None")
        if not isinstance(self.operation, str):
            raise TypeError("operation must be a string")
        if self.result not in ("success", "denied"):
            raise ValueError("result must be success or denied")

    def message(self) -> dict:
        payload = {"id": self.ref, "actor": self.actor,
                   "operation": self.operation, "target": self.target,
                   "result": self.result}
        if self.actor_access_key_id is not None:
            payload["actor_access_key_id"] = self.actor_access_key_id
        return payload

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class GroundTruth:
    malicious: bool
    principal: object = None
    key_owner: object = None
    action_tool_id: object = None
    action_arguments: object = None
    actor_to_principal: object = None
    label: str = ""

    def __post_init__(self):
        if not isinstance(self.malicious, bool):
            raise TypeError("malicious must be a bool")
        if self.malicious:
            _require_text("principal", self.principal)
            _require_text("key_owner", self.key_owner)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ExpectedState:
    users: tuple = ()
    incident_key_active_count: int = 1
    investigator_key_active_count: int = 1
    object_keys: tuple = ()
    log_event_count: int = 0
    secret_name: str = ""
    function_name: str = ""
    policy_name: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class SeedManifest:
    generator_version: str
    seed: object
    family: str
    difficulty: str
    scenario_id: str
    variation: object = None

    def __post_init__(self):
        _require_text("generator_version", self.generator_version)
        _require_text("family", self.family)
        _require_text("scenario_id", self.scenario_id)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class PublicBriefing:
    scenario_id: str
    family: str
    difficulty: str
    text: str
    bucket: str
    log_group: str
    log_stream: str

    def __post_init__(self):
        _require_text("scenario_id", self.scenario_id)
        _require_text("text", self.text)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ExperimentRecord:
    generator_version: str
    seed: object
    family: str
    difficulty: str
    scenario_id: str
    model: str = ""
    provider: str = ""
    prompt_version: str = ""
    run_id: str = ""
    classification: str = ""
    provenance: str = Provenance.RECORDED_RUNTIME

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class GeneratedScenario:
    generator_version: str
    seed: object
    family: str
    difficulty: str
    scenario_id: str
    bucket: str
    incident_user: str
    investigator_user: str
    incident_policy: str
    secret_name: str
    function_name: str
    log_group: str
    log_stream: str
    objects: tuple = ()
    log_events: tuple = ()
    ground_truth: object = None
    expected: object = None
    manifest: object = None
    briefing_text: str = ""

    def __post_init__(self):
        _require_text("generator_version", self.generator_version)
        if self.family not in FAMILIES:
            raise ValueError("unknown family")
        if self.difficulty not in DIFFICULTIES:
            raise ValueError("unknown difficulty")
        _require_text("scenario_id", self.scenario_id)
        object.__setattr__(self, "objects", tuple(self.objects or ()))
        object.__setattr__(self, "log_events", tuple(self.log_events or ()))

    def public_briefing(self) -> PublicBriefing:
        return PublicBriefing(
            scenario_id=self.scenario_id, family=self.family,
            difficulty=self.difficulty, text=self.briefing_text,
            bucket=self.bucket, log_group=self.log_group,
            log_stream=self.log_stream)

    def as_dict(self, include_truth=False) -> dict:
        payload = {
            "generator_version": self.generator_version,
            "seed": self.seed, "family": self.family,
            "difficulty": self.difficulty,
            "scenario_id": self.scenario_id, "bucket": self.bucket,
            "incident_user": self.incident_user,
            "investigator_user": self.investigator_user,
            "incident_policy": self.incident_policy,
            "secret_name": self.secret_name,
            "function_name": self.function_name,
            "log_group": self.log_group, "log_stream": self.log_stream,
            "objects": [item.as_dict() for item in self.objects],
            "log_events": [item.as_dict() for item in self.log_events],
            "expected": self.expected.as_dict(),
            "manifest": self.manifest.as_dict(),
            "briefing_text": self.briefing_text,
        }
        if include_truth:
            payload["ground_truth"] = self.ground_truth.as_dict()
        return payload
