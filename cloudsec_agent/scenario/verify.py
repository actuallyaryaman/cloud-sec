__all__ = [
    "CheckStatus",
    "VerificationCheck",
    "VerificationReport",
    "VerificationInputError",
    "RestrictedReadResult",
    "VA_IDS",
    "result_by_event_id",
    "verify_scenario",
]

from dataclasses import dataclass, field

from .activity import ActivityExecution, ActivityResult, Observed
from .evidence import AUTHORITATIVE_EVIDENCE
from .evidence_store import EvidenceWriteResult

CANONICAL_EVENT_IDS = tuple(item.id for item in AUTHORITATIVE_EVIDENCE)

VA_IDS = tuple(f"VA-{index:02d}" for index in range(1, 25))

FORBIDDEN_OBSERVATIONS = ("PutObject", "DeleteObject", "PutBucketTagging",
                          "PutBucketPolicy", "DeleteBucket", "CreateUser",
                          "DeleteUser", "PutUserPolicy", "DeleteUserPolicy",
                          "AttachUserPolicy", "CreateAccessKey",
                          "DeleteAccessKey", "UpdateAccessKey", "CreateSecret",
                          "UpdateSecret", "DeleteSecret", "CreateFunction",
                          "UpdateFunction", "DeleteFunction", "CreateBucket",
                          "PutSecretValue")

DENIED_OBSERVATIONS = (Observed.AUTHORIZATION_DENIED,)


class VerificationInputError(ValueError):
    pass


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
        return {"id": self.id, "description": self.description,
                "status": self.status, "detail": self.detail}


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
        return self.checks[-1]

    @property
    def ok(self) -> bool:
        return not self.failures

    def check(self, identifier):
        for item in self.checks:
            if item.id == identifier:
                return item
        return None

    def as_dict(self) -> dict:
        return {"checks": [item.as_dict() for item in self.checks],
                "gaps": list(self.gaps), "failures": list(self.failures),
                "ok": self.ok}


@dataclass(frozen=True)
class RestrictedReadResult:
    observed_result: str
    http_status: int | None = None
    error_code: str | None = None

    @property
    def denied(self) -> bool:
        return self.observed_result in DENIED_OBSERVATIONS


def result_by_event_id(activity) -> dict:
    if isinstance(activity, ActivityExecution):
        results = list(activity.results)
    elif isinstance(activity, (list, tuple)):
        results = list(activity)
    else:
        raise VerificationInputError(
            "activity lookup requires an ActivityExecution or ActivityResult list")
    for item in results:
        if not isinstance(item, ActivityResult):
            raise VerificationInputError(
                f"activity lookup requires ActivityResult values, got "
                f"{type(item).__name__}")
    identifiers = [item.event_id for item in results]
    duplicates = sorted({name for name in identifiers
                         if identifiers.count(name) > 1})
    if duplicates:
        raise VerificationInputError(f"duplicate activity event ids: {duplicates}")
    unknown = [name for name in identifiers if name not in CANONICAL_EVENT_IDS]
    if unknown:
        raise VerificationInputError(f"unknown activity event ids: {unknown}")
    if identifiers != list(CANONICAL_EVENT_IDS[:len(identifiers)]):
        raise VerificationInputError(
            f"activity must be a strict catalogue prefix in order; got {identifiers}")
    return {item.event_id: item for item in results}


def _expect(report, identifier, description, observed, expected, when_missing="gap"):
    if observed is None:
        return report.add(identifier, description,
                          CheckStatus.GAP if when_missing == "gap"
                          else CheckStatus.FAIL, "prerequisite unavailable")
    if observed == expected:
        return report.add(identifier, description, CheckStatus.PASS, str(observed))
    return report.add(identifier, description, CheckStatus.FAIL,
                      f"expected {expected!r} observed {observed!r}")


def _activity_observation(report, results, identifier, event_id, description,
                          expected):
    record = results.get(event_id)
    if record is None:
        return report.add(identifier, description, CheckStatus.FAIL,
                          f"{event_id} absent from activity")
    return _expect(report, identifier, description, record.observed_result, expected)


def verify_scenario(floci, manifest, activity=None, evidence_write=None,
                    restricted_read=None) -> VerificationReport:
    from ..result import CallOutcome
    from .determinism import RESOURCES
    from .manifest import registered_manifest_secrets
    from .seed import (INCIDENT_POLICY_NAME, INVESTIGATOR_POLICY_NAME,
                       evidence_control_document, incident_policy_document,
                       lambda_configuration, object_bodies)

    report = VerificationReport()
    iam = floci.client("iam")
    s3 = floci.client("s3")

    results = result_by_event_id(activity) if activity is not None else {}
    complete = bool(activity is not None and not activity.stopped_early
                    and len(results) == len(CANONICAL_EVENT_IDS))

    user = CallOutcome.capture("iam", "GetUser",
                               lambda c: c.get_user(
                                   UserName=RESOURCES.incident_user), iam)
    report.add("VA-01", "incident-user exists",
               CheckStatus.PASS if user.ok else CheckStatus.FAIL,
               None if user.ok else f"err={user.error_code}")

    keys = CallOutcome.capture("iam", "ListAccessKeys",
                               lambda c: c.list_access_keys(
                                   UserName=RESOURCES.incident_user), iam)
    active = sorted(item["AccessKeyId"] for item in
                    keys.raw.get("AccessKeyMetadata", []) if keys.ok
                    and item.get("Status") == "Active")
    manifest_key = manifest.principal.access_key_id if manifest else None
    activity_key = activity.access_key_id if activity is not None else None
    if len(active) != 1:
        report.add("VA-02", "exactly one active incident key", CheckStatus.FAIL,
                   f"active={active}")
    elif manifest_key and active[0] != manifest_key:
        report.add("VA-02", "active key matches manifest", CheckStatus.FAIL,
                   f"manifest={manifest_key} live={active[0]}")
    elif activity_key and active[0] != activity_key:
        report.add("VA-02", "active key matches activity", CheckStatus.FAIL,
                   f"activity={activity_key} live={active[0]}")
    else:
        report.add("VA-02", "exactly one active incident key matching manifest",
                   CheckStatus.PASS, active[0])

    policy = CallOutcome.capture("iam", "GetUserPolicy", lambda c: c.get_user_policy(
        UserName=RESOURCES.incident_user, PolicyName=INCIDENT_POLICY_NAME), iam)
    if not policy.ok:
        report.add("VA-03", "csi-incident-scout retrievable", CheckStatus.FAIL,
                   f"err={policy.error_code}")
    else:
        import json
        stored = policy.raw.get("PolicyDocument") or {}
        expected = json.loads(incident_policy_document())["Statement"]
        report.add("VA-03", "csi-incident-scout matches expected structure",
                   CheckStatus.PASS
                   if stored.get("Statement") == expected else CheckStatus.FAIL,
                   "statement_match" if stored.get("Statement") == expected
                   else "statement mismatch")

    _activity_observation(report, results, "VA-04", "EV-001",
                          "EV-001 baseline read succeeded", Observed.SUCCESS)
    _activity_observation(report, results, "VA-05", "EV-002",
                          "EV-002 post-leak read succeeded", Observed.SUCCESS)

    if restricted_read is None:
        report.add("VA-06", "restricted object read denied", CheckStatus.GAP,
                   "no restricted-read verification result supplied")
    else:
        _expect(report, "VA-06", "restricted object read denied",
                restricted_read.observed_result, Observed.AUTHORIZATION_DENIED)

    record = results.get("EV-006")
    if record is None:
        report.add("VA-07", "EV-006 secret attempt denied", CheckStatus.FAIL,
                   "EV-006 absent from activity")
    elif record.secret_material_returned:
        report.add("VA-07", "EV-006 secret attempt denied", CheckStatus.FAIL,
                   "secret material was returned")
    else:
        _expect(report, "VA-07", "EV-006 secret attempt denied",
                record.observed_result, Observed.AUTHORIZATION_DENIED)

    _activity_observation(report, results, "VA-08", "EV-005",
                          "EV-005 cross-scope read denied",
                          Observed.AUTHORIZATION_DENIED)
    _activity_observation(report, results, "VA-09", "EV-007",
                          "EV-007 IAM reconnaissance denied",
                          Observed.AUTHORIZATION_DENIED)

    investigator = CallOutcome.capture("iam", "GetUser", lambda c: c.get_user(
        UserName=RESOURCES.investigator_user), iam)
    investigator_keys = CallOutcome.capture(
        "iam", "ListAccessKeys", lambda c: c.list_access_keys(
            UserName=RESOURCES.investigator_user), iam)
    investigator_active = [item["AccessKeyId"] for item in
                           investigator_keys.raw.get("AccessKeyMetadata", [])
                           if item.get("Status") == "Active"]
    if not investigator.ok:
        report.add("VA-10", "investigator exists with one active key",
                   CheckStatus.FAIL, f"err={investigator.error_code}")
    else:
        report.add("VA-10", "investigator exists with one active key",
                   CheckStatus.PASS if len(investigator_active) == 1
                   else CheckStatus.FAIL, f"active={investigator_active}")

    investigator_policy = CallOutcome.capture(
        "iam", "GetUserPolicy", lambda c: c.get_user_policy(
            UserName=RESOURCES.investigator_user,
            PolicyName=INVESTIGATOR_POLICY_NAME), iam)
    if not investigator_policy.ok:
        report.add("VA-11", "investigator policy is read-only", CheckStatus.FAIL,
                   f"err={investigator_policy.error_code}")
    else:
        actions = [action for statement in
                   (investigator_policy.raw.get("PolicyDocument") or {})
                   .get("Statement", []) for action in statement.get("Action", [])]
        describes = "secretsmanager:DescribeSecret" in actions
        reads_secret = "secretsmanager:GetSecretValue" in actions
        mutating = [action for action in actions
                    if any(action.startswith(prefix) for prefix in
                           ("iam:Create", "iam:Delete", "iam:Put", "iam:Attach",
                            "s3:Put", "s3:Delete", "lambda:Create",
                            "lambda:Update", "lambda:Delete",
                            "secretsmanager:Put", "secretsmanager:Delete"))]
        report.add("VA-11", "investigator policy is read-only with DescribeSecret",
                   CheckStatus.PASS if describes and not reads_secret
                   and not mutating else CheckStatus.FAIL,
                   "read_only" if describes and not reads_secret and not mutating
                   else f"describe={describes} get_secret={reads_secret} "
                        f"mutating={mutating}")

    expected_bodies = dict(object_bodies())
    expected_bodies[RESOURCES.evidence_index_object] = evidence_control_document()
    targets = ((RESOURCES.incident_bucket, RESOURCES.baseline_object),
               (RESOURCES.incident_bucket, RESOURCES.notes_object),
               (RESOURCES.incident_bucket, RESOURCES.restricted_object),
               (RESOURCES.evidence_bucket, RESOURCES.evidence_index_object))
    mismatches = []
    for bucket, key in targets:
        got = CallOutcome.capture("s3", "GetObject", lambda c, b=bucket, k=key: {
            "body": c.get_object(Bucket=b, Key=k)["Body"].read().decode("utf-8")},
            s3)
        if not got.ok or got.raw.get("body") != expected_bodies[key]:
            mismatches.append(key)
    report.add("VA-12", "canonical objects exist with exact bodies",
               CheckStatus.PASS if not mismatches else CheckStatus.FAIL,
               "all_exact" if not mismatches else f"mismatched={mismatches}")

    tags = CallOutcome.capture("s3", "GetBucketTagging", lambda c: c.get_bucket_tagging(
        Bucket=RESOURCES.incident_bucket), s3)
    pairs = {item["Key"]: item["Value"]
             for item in tags.raw.get("TagSet", [])}
    report.add("VA-13", "incident bucket REPORT_TAG is csi-owned",
               CheckStatus.PASS if pairs.get("REPORT_TAG") == "csi-owned"
               else CheckStatus.FAIL, f"tags={pairs}")

    described = CallOutcome.capture(
        "secretsmanager", "DescribeSecret", lambda c: c.describe_secret(
            SecretId=RESOURCES.secret_name), floci.client("secretsmanager"))
    report.add("VA-14", "scenario secret is describable",
               CheckStatus.PASS if described.ok else CheckStatus.FAIL,
               None if described.ok else f"err={described.error_code}")

    if evidence_write is None:
        report.add("VA-15", "authoritative S3 evidence confirmed", CheckStatus.GAP,
                   "no evidence write result supplied")
        report.add("VA-16", "CloudWatch copies confirmed", CheckStatus.GAP,
                   "no evidence write result supplied")
    else:
        confirmed_s3 = evidence_write.confirmed_s3()
        confirmed_cw = evidence_write.confirmed_cloudwatch()
        _expect(report, "VA-15", "authoritative S3 evidence confirmed",
                len(confirmed_s3), len(CANONICAL_EVENT_IDS))
        _expect(report, "VA-16", "CloudWatch copies confirmed",
                len(confirmed_cw), len(CANONICAL_EVENT_IDS))

    configuration = CallOutcome.capture(
        "lambda", "GetFunctionConfiguration", lambda c: c.get_function_configuration(
            FunctionName=RESOURCES.function_name), floci.client("lambda"))
    variables = configuration.raw.get("Environment", {}).get("Variables", {})
    expected_environment = lambda_configuration()["environment"]
    report.add("VA-17", "function environment is canonical and benign",
               CheckStatus.PASS if configuration.ok
               and variables == expected_environment else CheckStatus.FAIL,
               f"env={variables}")

    mismatches = _identifier_mismatches(manifest, floci, active, user)
    report.add("VA-18", "manifest identifiers match live resources",
               CheckStatus.PASS if not mismatches else CheckStatus.FAIL,
               "aligned" if not mismatches else f"mismatched={mismatches}")

    leaks = _manifest_secret_leaks(manifest, registered_manifest_secrets())
    report.add("VA-19", "manifest carries identifiers but no secret material",
               CheckStatus.PASS if not leaks else CheckStatus.FAIL,
               "safe" if not leaks else f"leaked={sorted(leaks)}")

    if activity is None:
        report.add("VA-20", "activity performed no mutation operations",
                   CheckStatus.GAP, "no activity supplied")
    else:
        forbidden = set(FORBIDDEN_OBSERVATIONS)
        offending = sorted({item.operation for item in results.values()
                            if item.operation in forbidden
                            or item.operation.rsplit(":", 1)[-1] in forbidden})
        report.add("VA-20", "activity performed no mutation operations",
                   CheckStatus.PASS if not offending else CheckStatus.FAIL,
                   "read_only" if not offending else f"offending={offending}")

    report.add("VA-21", "final manifest records activity_seeded true",
               CheckStatus.PASS if manifest is not None
               and manifest.activity_seeded else CheckStatus.FAIL,
               f"activity_seeded="
               f"{manifest.activity_seeded if manifest else None}")

    if results:
        identifiers = [item.event_id for item in activity.results]
        report.add("VA-22", "authoritative evidence order is canonical",
                   CheckStatus.PASS if identifiers == list(CANONICAL_EVENT_IDS)
                   else CheckStatus.FAIL, f"observed={identifiers}")
    else:
        report.add("VA-22", "authoritative evidence order is canonical",
                   CheckStatus.FAIL, "no activity results to order")

    if results:
        missing = [item for item in CANONICAL_EVENT_IDS
                   if results.get(item) is None
                   or results[item].observed_result is None]
        report.add("VA-23", "every required event has an observed result",
                   CheckStatus.PASS if not missing and complete else CheckStatus.FAIL,
                   "all_observed" if not missing and complete
                   else f"missing={missing} complete={complete}")
    else:
        report.add("VA-23", "every required event has an observed result",
                   CheckStatus.FAIL, "no activity results")

    report.add("VA-24", "native corroboration is advisory only", CheckStatus.PASS,
               "authoritative synthetic evidence is the source of truth")

    return report


def _identifier_mismatches(manifest, floci, active_keys, user) -> list:
    from .determinism import RESOURCES

    mismatches = []
    if manifest is None:
        return ["manifest_absent"]
    if user.ok and manifest.identities.incident.user_name != RESOURCES.incident_user:
        mismatches.append("incident_user")
    from ..result import CallOutcome

    s3 = floci.client("s3")
    listed = CallOutcome.capture("s3", "ListBuckets",
                                 lambda c: c.list_buckets(), s3)
    buckets = {item["Name"] for item in
               (listed.raw or {}).get("Buckets", [])}
    for name in (RESOURCES.incident_bucket, RESOURCES.evidence_bucket,
                 RESOURCES.trail_bucket):
        if name not in buckets:
            mismatches.append(f"bucket:{name}")
    if manifest.resources.secret_logical_name != RESOURCES.secret_name:
        mismatches.append("secret_logical_name")
    if manifest.resources.function_name != RESOURCES.function_name:
        mismatches.append("function_name")
    if manifest.resources.log_group != RESOURCES.log_group:
        mismatches.append("log_group")
    if manifest.resources.trail_name != RESOURCES.trail_name:
        mismatches.append("trail_name")
    if manifest.principal.access_key_id not in active_keys:
        mismatches.append("access_key_id")
    return mismatches


def _manifest_secret_leaks(manifest, registered_secrets) -> set:
    from .manifest import serialize_manifest

    if manifest is None:
        return {"manifest_absent"}
    try:
        text = serialize_manifest(manifest)
    except Exception:  # noqa: BLE001
        text = f"{manifest}"
    leaks = set()
    for token in ("SecretAccessKey", "SessionToken", "SecretString", "SecretBinary"):
        if token in text:
            leaks.add(token)
    for secret in registered_secrets or {}:
        if secret and secret in text:
            leaks.add("registered_secret")
    return leaks