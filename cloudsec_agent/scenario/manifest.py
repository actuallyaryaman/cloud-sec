__all__ = [
    "ManifestSafetyError",
    "FlociInfo",
    "Identity",
    "Identities",
    "Principal",
    "Resources",
    "ObjectKeys",
    "ContainmentAction",
    "ExpectedContainment",
    "SecretAttemptExpectation",
    "EvidenceRecord",
    "NativeCorroboration",
    "VerificationAssertion",
    "ScenarioManifest",
    "ALLOWED_IDENTIFIER_PATHS",
    "FORBIDDEN_FIELD_NAMES",
    "register_manifest_secret",
    "clear_manifest_secrets",
    "registered_manifest_secrets",
    "manifest_payload",
    "validate_manifest_payload",
    "serialize_manifest",
    "write_manifest",
]

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any

from .determinism import (CANONICAL_ENDPOINT, MANIFEST_IS_EVIDENCE,
                          MANIFEST_RELATIVE_PATH, MANIFEST_ROLE, REFERENCE_TIME_ISO,
                          SCENARIO_FLAVOUR, SCENARIO_ID, SCHEMA_VERSION, SEED)

ACCESS_KEY_ID_PATTERN = re.compile(r"^(?:AKIA|ASIA)[0-9A-Z]{8,}$")

ALLOWED_IDENTIFIER_PATHS = frozenset({
    "principal.access_key_id",
    "evidence[].access_key_id",
    "identities.incident.arn",
    "identities.investigator.arn",
    "resources.secret_arn",
    "resources.trail_arn",
    "expected_findings.compromised_access_key_id",
    "expected_containment.primary.target",
})

FORBIDDEN_FIELD_NAMES = frozenset({
    "secretaccesskey",
    "awssecretaccesskey",
    "sessiontoken",
    "awssessiontoken",
    "secretstring",
    "secretbinary",
    "credentials",
    "password",
    "plaintext",
    "token",
    "apikey",
    "privatekey",
})

_MANIFEST_SECRETS: dict[str, str] = {}


class ManifestSafetyError(ValueError):
    pass


def register_manifest_secret(value: str) -> None:
    if value and len(value) >= 6:
        _MANIFEST_SECRETS[value] = "[REDACTED]"


def clear_manifest_secrets() -> None:
    _MANIFEST_SECRETS.clear()


def registered_manifest_secrets() -> dict:
    return dict(_MANIFEST_SECRETS)


def _normalise(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _is_secret_value(value: Any, secrets: dict) -> bool:
    if not isinstance(value, str):
        return False
    return any(value == secret or secret in value for secret in secrets)


def validate_manifest_payload(payload: Any, path: str = "") -> None:
    secrets = registered_manifest_secrets()
    if isinstance(payload, dict):
        for key, value in payload.items():
            if _normalise(key) in FORBIDDEN_FIELD_NAMES:
                raise ManifestSafetyError(
                    f"forbidden credential field at {path or '<root>'}.{key}")
            validate_manifest_payload(value, f"{path}.{key}" if path else str(key))
        return
    if isinstance(payload, (list, tuple)):
        for item in payload:
            validate_manifest_payload(item, f"{path}[]")
        return
    if isinstance(payload, str):
        if _is_secret_value(payload, secrets):
            raise ManifestSafetyError(f"registered secret material present at {path}")
        if ACCESS_KEY_ID_PATTERN.match(payload) and path not in ALLOWED_IDENTIFIER_PATHS:
            raise ManifestSafetyError(
                f"access key identifier at unapproved path {path}")


@dataclass
class FlociInfo:
    version: str | None = None
    edition: str | None = None


@dataclass
class Identity:
    user_name: str
    arn: str | None = None
    policy_name: str | None = None


@dataclass
class Identities:
    incident: Identity
    investigator: Identity
    seeding_credential_shape: str | None = None


@dataclass
class Principal:
    access_key_id: str | None = None
    access_key_count: int | None = None
    access_key_status: str | None = None


@dataclass
class Resources:
    incident_bucket: str
    evidence_bucket: str
    trail_bucket: str
    secret_logical_name: str
    log_group: str
    log_stream: str
    function_name: str
    trail_name: str
    secret_id: str | None = None
    secret_arn: str | None = None
    trail_arn: str | None = None


@dataclass
class ObjectKeys:
    baseline: str
    notes: str
    restricted: str
    evidence_index: str


@dataclass
class ContainmentAction:
    action: str
    target: str
    status: str | None = None
    destructive: bool = False


@dataclass
class ExpectedContainment:
    primary: ContainmentAction | None = None
    secondary: dict | None = None


@dataclass
class SecretAttemptExpectation:
    secret_read_requested: bool = False
    secret_read_authorized: bool = False
    secret_read_executed: bool = False
    secret_value_returned: bool = False

    def as_dict(self) -> dict:
        return {
            "secret_read_requested": self.secret_read_requested,
            "secret_read_authorized": self.secret_read_authorized,
            "secret_read_executed": self.secret_read_executed,
            "secret_value_returned": self.secret_value_returned,
        }


@dataclass
class EvidenceRecord:
    id: str
    event_time: str
    time_basis: str
    authoritative: bool
    required: bool
    service: str
    operation: str
    target: str
    tool: str | None = None
    access_key_id: str | None = None
    offset_seconds: int | None = None
    observed_result: str | None = None
    observed_http_status: int | None = None
    observed_error_code: str | None = None
    native_corroborated: bool | None = None
    attacker_controllable: bool = False


@dataclass
class NativeCorroboration:
    trail_name: str
    required: bool = False
    events_observed: list = field(default_factory=list)
    events_absent: list = field(default_factory=list)
    note: str | None = None


@dataclass
class VerificationAssertion:
    id: str
    description: str
    expected: Any = True
    fatal: bool = True


@dataclass
class ScenarioManifest:
    generated_at: str
    identities: Identities
    principal: Principal
    resources: Resources
    object_keys: ObjectKeys
    evidence: list = field(default_factory=list)
    floci: FlociInfo = field(default_factory=FlociInfo)
    expected_findings: dict = field(default_factory=dict)
    expected_containment: ExpectedContainment = field(
        default_factory=ExpectedContainment)
    secret_attempt_expectation: SecretAttemptExpectation = field(
        default_factory=SecretAttemptExpectation)
    native_corroboration: NativeCorroboration | None = None
    verification_assertions: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION
    scenario_id: str = SCENARIO_ID
    seed: int = SEED
    reference_time: str = REFERENCE_TIME_ISO
    endpoint: str = CANONICAL_ENDPOINT
    scenario_flavour: str = SCENARIO_FLAVOUR
    activity_seeded: bool = False

    def ground_truth_metadata(self) -> dict:
        return {
            "manifest_path": MANIFEST_RELATIVE_PATH,
            "manifest_role": MANIFEST_ROLE,
            "is_incident_evidence": MANIFEST_IS_EVIDENCE,
            "exposed_to_model": False,
            "activity_seeded": self.activity_seeded,
        }


def manifest_payload(manifest: ScenarioManifest) -> dict:
    if not is_dataclass(manifest):
        raise ManifestSafetyError("manifest must be a ScenarioManifest")
    if manifest.endpoint.rstrip("/") != CANONICAL_ENDPOINT:
        raise ManifestSafetyError(
            f"manifest endpoint {manifest.endpoint!r} is not the canonical scenario "
            f"endpoint {CANONICAL_ENDPOINT}")
    payload = asdict(manifest)
    payload["manifest_metadata"] = manifest.ground_truth_metadata()
    return payload


def serialize_manifest(manifest: ScenarioManifest) -> str:
    payload = manifest_payload(manifest)
    validate_manifest_payload(payload)
    return json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n"


def write_manifest(path: str, manifest: ScenarioManifest) -> str:
    text = serialize_manifest(manifest)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".manifest-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return os.path.abspath(path)