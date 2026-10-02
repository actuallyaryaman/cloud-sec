__all__ = [
    "CheckStatus",
    "VerificationCheck",
    "VerificationReport",
    "PreflightBlocked",
    "EXIT_SUCCESS",
    "EXIT_FAILURE",
    "EXIT_ENDPOINT",
    "EXIT_MANIFEST",
    "canonical_endpoint",
    "preflight",
    "verify_live_state",
    "build_manifest",
    "seed_and_write_manifest",
    "run_lifecycle",
    "restricted_verification_read",
    "summarise",
    "main",
]

import argparse
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .floci_client import Floci, UnsafeEndpointError
from .result import CallOutcome
from .scenario import evidence as ev
from .scenario import reset as rs
from .scenario.determinism import (CANONICAL_ENDPOINT, MANIFEST_RELATIVE_PATH,
                                   RESOURCES, SCENARIO_FLAVOUR, SCENARIO_ID,
                                   ScenarioConfigurationError,
                                   assert_canonical_endpoint)
from .scenario.manifest import (ManifestSafetyError, ScenarioManifest,
                                write_manifest)
from .scenario.manifest import (EvidenceRecord, FlociInfo, Identities, Identity,
                                NativeCorroboration, ObjectKeys, Principal,
                                Resources, SecretAttemptExpectation,
                                VerificationAssertion)
from .scenario.seed import (INVESTIGATOR_POLICY_NAME, INCIDENT_POLICY_NAME,
                            SetupStateError, evidence_bucket_arn,
                            incident_bucket_arn, incident_user_arn,
                            investigator_policy_document, investigator_user_arn,
                            lambda_configuration, secret_logical_arn,
                            seed_scenario, seed_scenario_with_runtime)

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_ENDPOINT = 2
EXIT_MANIFEST = 3

CANONICAL_PORT = 4567
STOCK_ENDPOINT = "http://localhost:4566"


class PreflightBlocked(RuntimeError):
    def __init__(self, present):
        super().__init__("canonical scenario resources already exist")
        self.present = list(present)


class CheckStatus:
    PASS = "pass"
    FAIL = "fail"
    GAP = "gap"


@dataclass
class VerificationCheck:
    id: str
    description: str
    status: str
    detail: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class VerificationReport:
    checks: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    failures: list = field(default_factory=list)

    def add(self, identifier, description, status, detail=None):
        self.checks.append(VerificationCheck(id=identifier,
                                             description=description,
                                             status=status, detail=detail))
        if status == CheckStatus.GAP:
            self.gaps.append(f"{identifier}: {detail}")
        elif status == CheckStatus.FAIL:
            self.failures.append(f"{identifier}: {detail}")

    @property
    def ok(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict:
        return {
            "checks": [item.as_dict() for item in self.checks],
            "gaps": list(self.gaps),
            "failures": list(self.failures),
            "ok": self.ok,
        }


def canonical_endpoint(endpoint: str) -> str:
    normalised = assert_canonical_endpoint(endpoint)
    if normalised == STOCK_ENDPOINT:
        raise ScenarioConfigurationError(
            f"{STOCK_ENDPOINT} is stock Floci; the canonical scenario targets "
            f"{CANONICAL_ENDPOINT}")
    if urlsplit(normalised).port != CANONICAL_PORT:
        raise ScenarioConfigurationError(
            f"{normalised} is not the IAM-enforced canonical endpoint "
            f"{CANONICAL_ENDPOINT}")
    return normalised


def _connect(endpoint: str) -> Floci:
    floci = Floci(canonical_endpoint(endpoint))
    floci.health()
    floci.describe_identity()
    return floci


def _precheck(floci) -> list:
    present = []
    s3 = floci.client("s3")
    iam = floci.client("iam")
    buckets = {item["Name"]
               for item in CallOutcome.capture("s3", "ListBuckets",
                                               lambda c: c.list_buckets(),
                                               s3).raw.get("Buckets", [])}
    users = {item["UserName"] for item in CallOutcome.capture(
        "iam", "ListUsers", lambda c: c.list_users(), iam).raw.get("Users", [])}
    for bucket in rs.owned_buckets():
        if bucket in buckets:
            present.append(bucket)
    for user in rs.owned_users():
        if user in users:
            present.append(user)
    return present


def preflight(floci) -> list:
    present = _precheck(floci)
    if present:
        raise PreflightBlocked(present)
    return present


def _check_user_and_key(floci, report, user, policy_name, expected_key_id, prefix):
    iam = floci.client("iam")
    got_user = CallOutcome.capture("iam", "GetUser",
                                   lambda c: c.get_user(UserName=user), iam)
    report.add(f"VA-{prefix}-user", f"{user} exists",
               CheckStatus.PASS if got_user.ok else CheckStatus.FAIL,
               None if got_user.ok else f"err={got_user.error_code}")
    keys = CallOutcome.capture("iam", "ListAccessKeys",
                               lambda c: c.list_access_keys(UserName=user), iam)
    active = [item["AccessKeyId"] for item in keys.raw.get("AccessKeyMetadata", [])
              if item.get("Status") == "Active"]
    if user == RESOURCES.incident_user:
        report.add(f"VA-{prefix}-keys", f"{user} has exactly one active key",
                   CheckStatus.PASS if len(active) == 1 else CheckStatus.FAIL,
                   f"active={active}")
        report.add(f"VA-{prefix}-key-id",
                   "active key matches the seeded AccessKeyId",
                   CheckStatus.PASS if expected_key_id in active else CheckStatus.FAIL,
                   f"expected={expected_key_id} active={active}")
    else:
        report.add(f"VA-{prefix}-keys", f"{user} has exactly one active key",
                   CheckStatus.PASS if len(active) == 1 else CheckStatus.FAIL,
                   f"active={active}")
    policy = CallOutcome.capture("iam", "GetUserPolicy",
                                 lambda c: c.get_user_policy(
                                     UserName=user, PolicyName=policy_name), iam)
    report.add(f"VA-{prefix}-policy", f"{policy_name} is retrievable",
               CheckStatus.PASS if policy.ok else CheckStatus.FAIL,
               None if policy.ok else f"err={policy.error_code}")


def verify_live_state(floci, seed_result) -> VerificationReport:
    report = VerificationReport()
    s3 = floci.client("s3")
    _check_user_and_key(floci, report, RESOURCES.incident_user,
                        INCIDENT_POLICY_NAME, seed_result.incident_access_key_id,
                        "02")
    _check_user_and_key(floci, report, RESOURCES.investigator_user,
                        INVESTIGATOR_POLICY_NAME,
                        seed_result.investigator_access_key_id, "11")

    buckets = {item["Name"]
               for item in CallOutcome.capture("s3", "ListBuckets",
                                               lambda c: c.list_buckets(),
                                               s3).raw.get("Buckets", [])}
    for index, bucket in enumerate(rs.owned_buckets(), start=1):
        head = CallOutcome.capture("s3", "HeadBucket",
                                   lambda c, b=bucket: c.head_bucket(Bucket=b), s3)
        report.add(f"VA-04-{index}", f"{bucket} exists",
                   CheckStatus.PASS if head.ok and bucket in buckets
                   else CheckStatus.FAIL,
                   f"visible={bucket in buckets} head={head.ok}")

    objects = [(RESOURCES.incident_bucket, RESOURCES.baseline_object),
               (RESOURCES.incident_bucket, RESOURCES.notes_object),
               (RESOURCES.incident_bucket, RESOURCES.restricted_object),
               (RESOURCES.evidence_bucket, RESOURCES.evidence_index_object)]
    for index, (bucket, key) in enumerate(objects, start=1):
        head = CallOutcome.capture("s3", "HeadObject",
                                   lambda c, b=bucket, k=key: c.head_object(
                                       Bucket=b, Key=k), s3)
        report.add(f"VA-05-{index}", f"{bucket}/{key} exists",
                   CheckStatus.PASS if head.ok else CheckStatus.FAIL,
                   None if head.ok else f"err={head.error_code}")

    tags = CallOutcome.capture("s3", "GetBucketTagging",
                               lambda c: c.get_bucket_tagging(
                                   Bucket=RESOURCES.incident_bucket), s3)
    pairs = {item["Key"]: item["Value"] for item in tags.raw.get("TagSet", [])}
    report.add("VA-06", "incident bucket REPORT_TAG=csi-owned",
               CheckStatus.PASS if pairs.get("REPORT_TAG") == "csi-owned"
               else CheckStatus.FAIL, f"tags={pairs}")

    secret = CallOutcome.capture("secretsmanager", "DescribeSecret",
                                 lambda c: c.describe_secret(
                                     SecretId=RESOURCES.secret_name),
                                 floci.client("secretsmanager"))
    report.add("VA-07", "scenario secret is describable",
               CheckStatus.PASS if secret.ok else CheckStatus.FAIL,
               None if secret.ok else f"err={secret.error_code}")

    groups = CallOutcome.capture("logs", "DescribeLogGroups",
                                 lambda c: c.describe_log_groups(),
                                 floci.client("logs"))
    names = [item["logGroupName"] for item in groups.raw.get("logGroups", [])]
    report.add("VA-08", "log group exists",
               CheckStatus.PASS if RESOURCES.log_group in names else CheckStatus.FAIL,
               f"groups={names}")
    streams = CallOutcome.capture("logs", "DescribeLogStreams",
                                  lambda c: c.describe_log_streams(
                                      logGroupName=RESOURCES.log_group),
                                  floci.client("logs"))
    stream_names = [item["logStreamName"]
                    for item in streams.raw.get("logStreams", [])]
    report.add("VA-09", "log stream exists",
               CheckStatus.PASS if RESOURCES.log_stream in stream_names
               else CheckStatus.FAIL, f"streams={stream_names}")

    configuration = CallOutcome.capture(
        "lambda", "GetFunctionConfiguration",
        lambda c: c.get_function_configuration(
            FunctionName=RESOURCES.function_name), floci.client("lambda"))
    variables = configuration.raw.get("Environment", {}).get("Variables", {})
    from .scenario.seed import lambda_configuration as expected_configuration
    matches = (variables == expected_configuration()["environment"])
    report.add("VA-10", "function exists with expected environment",
               CheckStatus.PASS if configuration.ok and matches else CheckStatus.FAIL,
               f"env={variables}")

    trails = CallOutcome.capture(
        "cloudtrail", "DescribeTrails",
        lambda c: c.describe_trails(trailNameList=[RESOURCES.trail_name]),
        floci.client("cloudtrail"))
    trail_names = [item.get("Name") for item in trails.raw.get("trailList", [])]
    if RESOURCES.trail_name in trail_names:
        report.add("VA-12", "optional trail exists", CheckStatus.PASS,
                   f"trails={trail_names}")
    else:
        report.add("VA-12", "optional trail exists", CheckStatus.GAP,
                   "trail absent; native corroboration is optional")
    return report


def _evidence_records(compromised_key_id, activity=None):
    observations = _activity_observations(activity)
    records = []
    for item in ev.EVIDENCE_CATALOGUE:
        observed = observations.get(item.id)
        records.append(dict(
            id=item.id, event_time=item.event_time, time_basis=item.time_basis,
            authoritative=item.authoritative, required=item.required,
            service=item.service, operation=item.operation, target=item.target,
            tool=item.future_tool,
            access_key_id=(compromised_key_id
                           if item.actor == ev.Actor.COMPROMISED_KEY else None),
            offset_seconds=item.offset_seconds,
            observed_result=observed.observed_result if observed else None,
            observed_http_status=observed.http_status if observed else None,
            observed_error_code=observed.error_code if observed else None,
            native_corroborated=(observed.native_corroborated
                                 if observed else None),
            attacker_controllable=item.attacker_controllable))
    return records


def _activity_observations(activity):
    if activity is None:
        return {}
    from .scenario.verify import VerificationInputError, result_by_event_id

    try:
        results = result_by_event_id(activity)
    except VerificationInputError as exc:
        raise VerificationInputError(str(exc)) from exc
    if getattr(activity, "stopped_early", False):
        raise VerificationInputError(
            "a stopped-early activity cannot produce a final activity manifest")
    catalogue = {item.id: item for item in ev.EVIDENCE_CATALOGUE}
    for event_id, result in results.items():
        entry = catalogue[event_id]
        if (result.service != entry.service or result.operation != entry.operation
                or result.target != entry.target):
            raise VerificationInputError(
                f"{event_id} activity contradicts the catalogue service, operation "
                f"or target")
    return results


def build_manifest(floci, seed_result, activity=None) -> ScenarioManifest:
    compromised = seed_result.incident_access_key_id
    investigator = seed_result.investigator_access_key_id
    expected = lambda_configuration()
    return ScenarioManifest(
        generated_at=datetime.now(timezone.utc).isoformat(),
        identities=Identities(
            incident=Identity(user_name=RESOURCES.incident_user,
                              arn=incident_user_arn(),
                              policy_name=INCIDENT_POLICY_NAME),
            investigator=Identity(user_name=RESOURCES.investigator_user,
                                  arn=investigator_user_arn(),
                                  policy_name=INVESTIGATOR_POLICY_NAME),
            seeding_credential_shape=floci.admin_credential),
        principal=Principal(access_key_id=compromised, access_key_count=1,
                            access_key_status="Active"),
        resources=Resources(
            incident_bucket=RESOURCES.incident_bucket,
            evidence_bucket=RESOURCES.evidence_bucket,
            trail_bucket=RESOURCES.trail_bucket,
            secret_logical_name=RESOURCES.secret_name,
            secret_id=seed_result.secret_id,
            log_group=RESOURCES.log_group, log_stream=RESOURCES.log_stream,
            function_name=RESOURCES.function_name, trail_name=RESOURCES.trail_name,
            trail_arn=_trail_arn(floci)),
        object_keys=ObjectKeys(baseline=RESOURCES.baseline_object,
                               notes=RESOURCES.notes_object,
                               restricted=RESOURCES.restricted_object,
                               evidence_index=RESOURCES.evidence_index_object),
        floci=FlociInfo(version=floci.floci_version,
                        edition=floci.floci_edition),
        expected_findings={
            "compromised_principal": incident_user_arn(),
            "compromised_access_key_id": compromised,
            "affected_bucket": RESOURCES.incident_bucket,
            "baseline_prefixes": ["reports/*"],
            "anomalous_prefixes": ["notes/*"],
            "first_deviation_event_id": ev.FIRST_DEVIATION_EVENT_ID,
            "cross_scope_event_id": ev.CROSS_SCOPE_EVENT_ID,
            "secret_attempt_event_id": ev.SECRET_ATTEMPT_EVENT_ID,
            "denied_targets": [RESOURCES.evidence_bucket,
                               RESOURCES.secret_name],
            "status": ("activity executed; see evidence observations"
                       if activity is not None else
                       "declared-for-future-investigation; "
                       "incident activity has not been executed"),
        },
        expected_containment={
            "primary": {"action": "iam:UpdateAccessKey", "status": "Inactive",
                        "target": compromised, "destructive": False},
            "secondary": {"action": "investigate",
                          "target": "object_user_metadata"},
        },
        secret_attempt_expectation=SecretAttemptExpectation(),
        evidence=[EvidenceRecord(**record) for record in
                  _evidence_records(compromised, activity)],
        activity_seeded=activity is not None,
        native_corroboration=NativeCorroboration(
            trail_name=RESOURCES.trail_name, required=False, events_observed=[],
            events_absent=["ListObjectsV2", "GetSecretValue", "GetUser",
                           "GetCallerIdentity"],
            note="Floci CloudTrail emits S3 data events only; IAM, STS and "
                 "Secrets events are not emitted."),
        verification_assertions=list(_VERIFICATION_ITEMS),
        notes=[
            "Synthetic records are authoritative and use reference time.",
            "Native Floci records are corroborating only and use emulator "
            "wall-clock time.",
            "Manifest is evaluation ground truth and is never exposed to the model.",
            ("Incident activity EV-001..EV-008 was executed in this process; "
             "evidence observation fields are populated." if activity is not None
             else "Incident activity EV-001..EV-008 has not been executed; all "
             "evidence observation fields are null."),
        ],
    )


_VERIFICATION_ITEMS = [
    VerificationAssertion(id="VA-02", description="incident-user has exactly one "
                           "active access key matching the manifest",
                          expected=True, fatal=True),
    VerificationAssertion(id="VA-03", description="csi-incident-scout is retrievable",
                          expected=True, fatal=True),
    VerificationAssertion(id="VA-04", description="three canonical buckets exist",
                          expected=True, fatal=True),
    VerificationAssertion(id="VA-05", description="four canonical objects exist",
                          expected=True, fatal=True),
    VerificationAssertion(id="VA-06", description="incident bucket REPORT_TAG is set",
                          expected=True, fatal=True),
    VerificationAssertion(id="VA-07", description="scenario secret is describable",
                          expected=True, fatal=True),
    VerificationAssertion(id="VA-08", description="log group and stream exist",
                          expected=True, fatal=True),
    VerificationAssertion(id="VA-10", description="function exists with expected "
                           "environment", expected=True, fatal=False),
    VerificationAssertion(id="VA-12", description="optional native trail exists",
                          expected=True, fatal=False),
]


def _trail_arn(floci):
    trails = CallOutcome.capture(
        "cloudtrail", "DescribeTrails",
        lambda c: c.describe_trails(trailNameList=[RESOURCES.trail_name]),
        floci.client("cloudtrail"))
    for item in trails.raw.get("trailList", []):
        if item.get("Name") == RESOURCES.trail_name:
            return item.get("TrailARN")
    return None


def summarise(manifest, seed_result, verification, path) -> list:
    resources = manifest.resources
    return [
        f"scenario_id          : {manifest.scenario_id}",
        f"endpoint             : {manifest.endpoint}",
        f"scenario_flavour     : {manifest.scenario_flavour}",
        f"floci                : version={manifest.floci.version} "
        f"edition={manifest.floci.edition}",
        f"account              : {seed_result.account}",
        f"incident user        : {manifest.identities.incident.user_name}",
        f"investigator user    : {manifest.identities.investigator.user_name}",
        f"compromised AccessKeyId: {manifest.principal.access_key_id}",
        f"seeded resources     : {len(seed_result.resources)} "
        f"(created {len(seed_result.created())}, "
        f"pre-existing {len(seed_result.pre_existing())})",
        f"verified mutations   : "
        f"{sum(1 for r in seed_result.mutations if r.classification == 'CONFIRMED')}"
        f"/{len(seed_result.mutations)} confirmed",
        f"live verification    : "
        f"{sum(1 for c in verification.checks if c.status == CheckStatus.PASS)}"
        f"/{len(verification.checks)} pass, {len(verification.gaps)} gap, "
        f"{len(verification.failures)} fail",
        f"activity_seeded      : {manifest.activity_seeded}",
        f"optional gaps        : {verification.gaps or 'none'}",
        f"seed gaps            : {seed_result.gaps or 'none'}",
        f"manifest path        : {path}",
    ]


def seed_and_write_manifest(endpoint=CANONICAL_ENDPOINT, artifacts_dir=None):
    floci = _connect(endpoint)
    preflight(floci)
    seed_result = seed_scenario(floci, SCENARIO_ID)
    if seed_result.divergence is not None:
        raise SeedDivergence(seed_result)
    if seed_result.fatal_errors:
        raise SetupStateError("; ".join(seed_result.fatal_errors))
    verification = verify_live_state(floci, seed_result)
    if not verification.ok:
        raise VerificationFailure(verification)
    manifest = build_manifest(floci, seed_result)
    directory = artifacts_dir or os.path.dirname(MANIFEST_RELATIVE_PATH)
    path = os.path.join(directory, "manifest.json")
    write_manifest(path, manifest)
    return {"manifest": manifest, "seed_result": seed_result,
            "verification": verification, "path": os.path.abspath(path),
            "floci": floci}


def summarise_lifecycle(outcome) -> list:
    manifest = outcome["manifest"]
    seed_result = outcome["seed_result"]
    seed_verification = outcome["seed_verification"]
    activity = outcome["activity"]
    evidence = outcome["evidence_write"]
    restricted = outcome["restricted_read"]
    verification = outcome["verification"]
    confirmed = sum(1 for record in seed_result.mutations
                    if record.classification == "CONFIRMED")
    return [
        f"scenario_id          : {manifest.scenario_id}",
        f"endpoint             : {manifest.endpoint}",
        f"scenario_flavour     : {manifest.scenario_flavour}",
        f"seeded resources     : {len(seed_result.resources)} "
        f"(created {len(seed_result.created())}, "
        f"pre-existing {len(seed_result.pre_existing())})",
        f"verified mutations   : {confirmed}/{len(seed_result.mutations)} confirmed",
        f"seed verification    : "
        f"{sum(1 for c in seed_verification.checks if c.status == CheckStatus.PASS)}"
        f"/{len(seed_verification.checks)} pass, "
        f"{len(seed_verification.failures)} fail",
        f"activity events      : {len(activity.results)} "
        f"(stopped_early={activity.stopped_early})",
        f"activity outcomes    : "
        + ", ".join(f"{r.event_id}={r.observed_result}" for r in activity.results),
        f"evidence s3          : {len(evidence.confirmed_s3())}"
        f"/{len(evidence.s3_records)} confirmed",
        f"evidence cloudwatch  : {len(evidence.confirmed_cloudwatch())}"
        f"/{len(evidence.cloudwatch_records)} confirmed",
        f"restricted read      : {restricted.observed_result} "
        f"(status={restricted.http_status}, error={restricted.error_code})",
        f"verification         : "
        f"{sum(1 for c in verification.checks if c.status == CheckStatus.PASS)}"
        f"/{len(verification.checks)} pass, {len(verification.gaps)} gap, "
        f"{len(verification.failures)} fail",
        f"verification gaps    : {verification.gaps or 'none'}",
        f"activity_seeded      : {manifest.activity_seeded}",
        f"manifest path        : {outcome['path']}",
    ]


class SeedDivergence(RuntimeError):
    def __init__(self, seed_result):
        super().__init__("seed stopped at a mutation divergence")
        self.seed_result = seed_result


class VerificationFailure(RuntimeError):
    def __init__(self, verification):
        super().__init__("live verification failed")
        self.verification = verification


class LifecycleBlocked(RuntimeError):
    def __init__(self, stage, detail=None):
        super().__init__(f"lifecycle stopped at {stage}")
        self.stage = stage
        self.detail = detail


STALE_MANIFEST_WARNING = (
    "STALE MANIFEST NOT REPLACED: artifacts/scenario/manifest.json still "
    "describes the pre-restart emulator state and must not be treated as "
    "current. It was left untouched deliberately and must be replaced by a "
    "successful lifecycle run.")


def restricted_verification_read(floci, credential):
    from .scenario.activity import Observed, classify_outcome
    from .scenario.verify import RestrictedReadResult

    client = credential.client(floci, "s3")
    observed = Observed.INCONCLUSIVE
    status = None
    error_code = None
    try:
        response = client.get_object(Bucket=RESOURCES.incident_bucket,
                                    Key=RESOURCES.restricted_object)
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        try:
            response["Body"].close()
        except Exception:
            pass
        observed = Observed.UNEXPECTED_SUCCESS
    except Exception as exc:
        error_code, status = _exception_codes(exc)
        observed, status, error_code, _ = classify_outcome(
            ok=False, error_code=error_code, http_status=status)
    return RestrictedReadResult(observed_result=observed, http_status=status,
                                error_code=error_code)


def _exception_codes(exc):
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return (response.get("Error", {}).get("Code"),
                response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
    return (getattr(exc, "response", None) and None, None)


def _require(condition, stage, detail=None):
    if not condition:
        raise LifecycleBlocked(stage, detail)


RUN_SUMMARY_NAME = "last-run-summary.json"


def _safe_activity_rows(activity) -> list:
    if activity is None:
        return []
    return [{"event_id": item.event_id,
             "observed_result": item.observed_result,
             "http_status": item.http_status,
             "error_code": item.error_code,
             "detail": item.detail}
            for item in activity.results]


def _write_run_summary(directory, trace) -> None:
    payload = {"status": trace.get("status", "unknown"),
               "phase_reached": trace.get("phase"),
               "seed_mutation_counts": trace.get("seed_mutation_counts", {}),
               "activity_results": trace.get("activity_results", []),
               "evidence": trace.get("evidence", {}),
               "verification": trace.get("verification", {}),
               "manifest_written": bool(trace.get("manifest_written", False))}
    target = os.path.join(directory, RUN_SUMMARY_NAME)
    try:
        os.makedirs(directory, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=directory,
                                             prefix=".run-summary-",
                                             suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except OSError:
        pass


def _verification_counts(report) -> dict:
    if report is None:
        return {}
    return {"pass_count": sum(1 for item in report.checks
                              if item.status == CheckStatus.PASS),
            "gap_count": len(report.gaps),
            "fail_count": len(report.failures),
            "failed_check_ids": [item.split(":", 1)[0]
                                 for item in report.failures]}


def run_lifecycle(endpoint=CANONICAL_ENDPOINT, artifacts_dir=None):
    from .scenario.activity import execute_incident_activity, ordered_events
    from .scenario.evidence_store import write_evidence
    from .scenario.verify import verify_scenario

    directory = artifacts_dir or os.path.dirname(MANIFEST_RELATIVE_PATH)
    trace = {"status": "failed", "phase": "connect"}
    try:
        return _lifecycle_body(endpoint, directory, trace)
    finally:
        _write_run_summary(directory, trace)


def _lifecycle_body(endpoint, directory, trace):
    from .scenario.activity import execute_incident_activity, ordered_events
    from .scenario.evidence_store import write_evidence
    from .scenario.verify import verify_scenario

    floci = _connect(endpoint)
    trace["phase"] = "preflight"
    preflight(floci)

    trace["phase"] = "seed"
    execution = seed_scenario_with_runtime(floci, SCENARIO_ID)
    seed_result = execution.result
    _require(seed_result.divergence is None, "seed",
             "seed stopped at a mutation divergence")
    _require(not seed_result.fatal_errors, "seed",
             "; ".join(seed_result.fatal_errors))

    credential = execution.incident_credential
    _require(credential is not None, "credential-capture",
             "seed returned no runtime incident credential")
    _require(credential.access_key_id == seed_result.incident_access_key_id,
             "credential-consistency",
             "runtime credential does not match the seeded incident key")

    counts = {}
    for record in seed_result.mutations:
        counts[record.classification] = counts.get(record.classification, 0) + 1
    trace["seed_mutation_counts"] = counts

    trace["phase"] = "seed-verification"
    verification = verify_live_state(floci, seed_result)
    _require(verification.ok, "seed-verification",
             "; ".join(verification.failures))

    trace["phase"] = "activity"
    activity = execute_incident_activity(
        floci, credential, secret_arn=secret_logical_arn(),
        evidence_bucket_arn=evidence_bucket_arn())
    trace["activity_results"] = _safe_activity_rows(activity)
    catalogue_ids = [item.id for item in ordered_events()]
    observed_ids = [item.event_id for item in activity.results]
    _require(not activity.stopped_early, "activity",
             activity.stop_reason or "activity stopped early")
    _require(observed_ids == catalogue_ids, "activity-order",
             f"expected {catalogue_ids}, observed {observed_ids}")
    _require(len(set(observed_ids)) == len(observed_ids), "activity-order",
             "duplicate event ids observed")

    trace["phase"] = "evidence"
    evidence_write = write_evidence(floci, activity)
    trace["evidence"] = {
        "s3_confirmed_count": len(evidence_write.confirmed_s3()),
        "cloudwatch_confirmed_count": len(evidence_write.confirmed_cloudwatch())}
    _require(evidence_write.first_divergence is None, "evidence",
             "; ".join(evidence_write.fatal_errors))
    _require(not evidence_write.fatal_errors, "evidence",
             "; ".join(evidence_write.fatal_errors))

    trace["phase"] = "restricted-read"
    restricted = restricted_verification_read(floci, credential)

    trace["phase"] = "candidate-manifest"
    candidate = build_manifest(floci, seed_result, activity=activity)
    _require(candidate.activity_seeded is True, "candidate-manifest",
             "candidate manifest is not an activity manifest")

    trace["phase"] = "verification"
    report = verify_scenario(floci, candidate, activity=activity,
                             evidence_write=evidence_write,
                             restricted_read=restricted)
    trace["verification"] = _verification_counts(report)

    path = os.path.join(directory, "manifest.json")
    absolute = os.path.abspath(path)

    result = {"manifest": candidate, "seed_result": seed_result,
              "seed_verification": verification, "activity": activity,
              "evidence_write": evidence_write, "restricted_read": restricted,
              "verification": report, "path": absolute, "floci": floci,
              "written": False, "stale_warning": None}

    if not report.ok:
        trace["phase"] = "verification-failed"
        result["stale_warning"] = STALE_MANIFEST_WARNING
        credential = None
        execution = None
        return result

    trace["phase"] = "manifest-write"
    write_manifest(path, candidate)
    result["written"] = True
    trace["status"] = "ok"
    trace["manifest_written"] = True
    credential = None
    execution = None
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cloudsec_agent.seed_scenario",
        description="Seed the canonical csi-incident-v1 scenario and emit its "
                    "evaluation manifest")
    parser.add_argument("--endpoint", default=CANONICAL_ENDPOINT)
    parser.add_argument("--artifacts-dir", default=None)
    parser.add_argument("--with-activity", action="store_true",
                        help="seed, then execute EV-001..EV-008, persist "
                             "evidence and verify in this single process")
    args = parser.parse_args(argv)

    if args.with_activity:
        return _main_lifecycle(args)
    return _main_seed_only(args)


def _main_lifecycle(args) -> int:
    try:
        outcome = run_lifecycle(args.endpoint, args.artifacts_dir)
    except (ScenarioConfigurationError, UnsafeEndpointError) as exc:
        print(f"endpoint rejected: {exc}", file=sys.stderr)
        return EXIT_ENDPOINT
    except PreflightBlocked as exc:
        print("canonical scenario resources already exist: "
              + ", ".join(exc.present), file=sys.stderr)
        print("run M1E-B reset orchestration; M1E-A never deletes", file=sys.stderr)
        return EXIT_FAILURE
    except SetupStateError as exc:
        print(f"seed failed: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except LifecycleBlocked as exc:
        print(f"lifecycle stopped at {exc.stage}; "
              f"final manifest not written", file=sys.stderr)
        if exc.detail:
            print(f"  {exc.detail}", file=sys.stderr)
        print(STALE_MANIFEST_WARNING, file=sys.stderr)
        return EXIT_FAILURE
    except ManifestSafetyError as exc:
        print(f"manifest safety rejection: {exc}", file=sys.stderr)
        return EXIT_MANIFEST
    except OSError as exc:
        print(f"manifest could not be written: {exc}", file=sys.stderr)
        return EXIT_MANIFEST

    if outcome["stale_warning"]:
        for item in outcome["verification"].failures:
            print(f"  {item}", file=sys.stderr)
        print(outcome["stale_warning"], file=sys.stderr)
        return EXIT_FAILURE

    for line in summarise_lifecycle(outcome):
        print(line)
    return EXIT_SUCCESS


def _main_seed_only(args) -> int:
    try:
        outcome = seed_and_write_manifest(args.endpoint, args.artifacts_dir)
    except (ScenarioConfigurationError, UnsafeEndpointError) as exc:
        print(f"endpoint rejected: {exc}", file=sys.stderr)
        return EXIT_ENDPOINT
    except PreflightBlocked as exc:
        print("canonical scenario resources already exist: "
              + ", ".join(exc.present), file=sys.stderr)
        print("run M1E-B reset orchestration; M1E-A never deletes", file=sys.stderr)
        return EXIT_FAILURE
    except SeedDivergence as exc:
        print("seed stopped at a mutation divergence; manifest not written",
              file=sys.stderr)
        for record in exc.seed_result.mutations:
            print("  " + record.summary(), file=sys.stderr)
        return EXIT_FAILURE
    except SetupStateError as exc:
        print(f"seed failed: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except VerificationFailure as exc:
        print("live verification failed; manifest not written", file=sys.stderr)
        for item in exc.verification.failures:
            print(f"  {item}", file=sys.stderr)
        return EXIT_FAILURE
    except ManifestSafetyError as exc:
        print(f"manifest safety rejection: {exc}", file=sys.stderr)
        return EXIT_MANIFEST
    except OSError as exc:
        print(f"manifest could not be written: {exc}", file=sys.stderr)
        return EXIT_MANIFEST

    for line in summarise(outcome["manifest"], outcome["seed_result"],
                          outcome["verification"], outcome["path"]):
        print(line)
    return EXIT_SUCCESS


__all__.extend(["SeedDivergence", "VerificationFailure",
                 "LifecycleBlocked", "STALE_MANIFEST_WARNING"])

if __name__ == "__main__":
    sys.exit(main())
