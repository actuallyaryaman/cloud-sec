__all__ = [
    "SCENARIO_ID",
    "SCHEMA_VERSION",
    "SEED",
    "REFERENCE_TIME",
    "REFERENCE_TIME_ISO",
    "CANONICAL_ENDPOINT",
    "CANONICAL_ENDPOINT_PORT",
    "SCENARIO_FLAVOUR",
    "REJECTED_SCENARIO_ENDPOINTS",
    "MANIFEST_RELATIVE_PATH",
    "MANIFEST_ROLE",
    "MANIFEST_IS_EVIDENCE",
    "SCENARIO_RESOURCE_PREFIX",
    "M0_RESOURCE_PREFIX",
    "EVENT_OFFSETS_SECONDS",
    "ScenarioResources",
    "RESOURCES",
    "ScenarioConfigurationError",
    "event_time",
    "event_time_iso",
    "ordered_event_ids",
    "is_canonical_endpoint",
    "assert_canonical_endpoint",
    "assert_scenario_namespace",
]

from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

SCENARIO_ID = "csi-incident-v1"
SCHEMA_VERSION = 2
SEED = 20260115
REFERENCE_TIME = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
REFERENCE_TIME_ISO = "2026-01-15T09:00:00Z"
CANONICAL_ENDPOINT = "http://localhost:4567"
CANONICAL_ENDPOINT_PORT = 4567
SCENARIO_FLAVOUR = "iam-enforced"
REJECTED_SCENARIO_ENDPOINTS = ("http://localhost:4566",)
MANIFEST_RELATIVE_PATH = "artifacts/scenario/manifest.json"
MANIFEST_ROLE = "evaluation-ground-truth"
MANIFEST_IS_EVIDENCE = False
SCENARIO_RESOURCE_PREFIX = "csi-"
M0_RESOURCE_PREFIX = "cloudsec-"

EVENT_OFFSETS_SECONDS = {
    "EV-001": -3600,
    "EV-002": -400,
    "EV-003": -350,
    "EV-004": -300,
    "EV-005": -250,
    "EV-006": -200,
    "EV-007": -150,
    "EV-008": -100,
}


class ScenarioConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class ScenarioResources:
    incident_user: str = "incident-user"
    investigator_user: str = "security-agent-backend"
    incident_policy: str = "csi-incident-scout"
    incident_bucket: str = "csi-incident-bucket"
    evidence_bucket: str = "csi-evidence-bucket"
    trail_bucket: str = "csi-trail-sink"
    baseline_object: str = "reports/q1-summary.txt"
    notes_object: str = "notes/handoff.md"
    restricted_object: str = "restricted/merger-acquisition-accounts.csv"
    evidence_index_object: str = "control/evidence-index.json"
    function_name: str = "csi-report-sched"
    log_group: str = "csi-audit-log"
    log_stream: str = "synth-v1"
    secret_name: str = "csi-db-production-credential"
    trail_name: str = "csi-trail"

    def all_names(self) -> dict:
        return {item.name: getattr(self, item.name) for item in fields(self)}


RESOURCES = ScenarioResources()


def event_time(evidence_id: str) -> datetime:
    if evidence_id not in EVENT_OFFSETS_SECONDS:
        raise ScenarioConfigurationError(f"unknown evidence id: {evidence_id!r}")
    return REFERENCE_TIME + timedelta(seconds=EVENT_OFFSETS_SECONDS[evidence_id])


def event_time_iso(evidence_id: str) -> str:
    return event_time(evidence_id).strftime("%Y-%m-%dT%H:%M:%SZ")


def ordered_event_ids() -> list:
    return sorted(EVENT_OFFSETS_SECONDS, key=lambda item: EVENT_OFFSETS_SECONDS[item])


def is_canonical_endpoint(endpoint: str) -> bool:
    parts = urlsplit(str(endpoint).rstrip("/"))
    return (
        parts.scheme == "http"
        and (parts.hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}
        and parts.port == CANONICAL_ENDPOINT_PORT
    )


def assert_canonical_endpoint(endpoint: str) -> str:
    normalised = str(endpoint).rstrip("/")
    if normalised in REJECTED_SCENARIO_ENDPOINTS:
        raise ScenarioConfigurationError(
            f"{normalised} is stock Floci; the canonical M1 scenario targets "
            f"{CANONICAL_ENDPOINT}")
    if not is_canonical_endpoint(normalised):
        raise ScenarioConfigurationError(
            f"{normalised} is not the canonical scenario endpoint {CANONICAL_ENDPOINT}")
    return normalised


def assert_scenario_namespace() -> dict:
    names = RESOURCES.all_names()
    for name, value in names.items():
        if value.startswith(M0_RESOURCE_PREFIX):
            raise ScenarioConfigurationError(
                f"{name}={value!r} collides with the M0 {M0_RESOURCE_PREFIX!r} namespace")
    return names