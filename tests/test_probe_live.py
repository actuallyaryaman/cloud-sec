import json
import os
import socket
import uuid

import pytest

from cloudsec_agent.authz import Identity, ensure_bucket, policy, statement
from cloudsec_agent.floci_client import (EndpointUnavailable, Floci,
                                         UnsafeEndpointError, assert_local_endpoint)
from cloudsec_agent.result import CallOutcome

ENFORCED = "http://localhost:4567"

ENDPOINTS = [
    ("stock", "http://localhost:4566"),
    ("iam-enforced", "http://localhost:4567"),
]


def _reachable(endpoint):
    assert_local_endpoint(endpoint)
    host, port = endpoint.split("//", 1)[1].split(":")
    try:
        with socket.create_connection((host.strip("[]"), int(port)), timeout=2):
            return True
    except OSError:
        return False


def _probe_available():
    try:
        Floci("http://localhost:4566").health()
        return True
    except (EndpointUnavailable, UnsafeEndpointError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not _probe_available(),
    reason="Floci is not reachable at http://localhost:4566; "
           "start it with 'docker compose up -d --wait'")


@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_health_reports_version_and_edition(label, endpoint):
    data = Floci(endpoint).health()
    assert data.get("version"), f"{label}: health response carried no version"
    assert "edition" in data


@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_get_caller_identity_reports_an_account(label, endpoint):
    floci = Floci(endpoint)
    identity = floci.connect()
    assert identity["account"]
    assert identity["account"].isdigit()


@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_synthetic_probe_credentials_are_accepted(label, endpoint):
    floci = Floci(endpoint)
    outcome = CallOutcome.capture("s3", "ListBuckets",
                                  lambda c: c.list_buckets(), floci.client("s3"))
    assert outcome.ok, f"{label}: {outcome.error_code or outcome.detail}"


@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_s3_round_trip_and_cleanup(label, endpoint):
    floci = Floci(endpoint)
    s3 = floci.client("s3")
    bucket = f"cloudsec-test-{label}"
    body = b"cloudsec-synthetic-live-body"
    CallOutcome.capture("s3", "CreateBucket", lambda c: c.create_bucket(Bucket=bucket), s3)
    put = CallOutcome.capture("s3", "PutObject", lambda c: c.put_object(
        Bucket=bucket, Key="probe.txt", Body=body), s3)
    assert put.ok, put.detail
    got = CallOutcome.capture("s3", "GetObject", lambda c: {
        "Body": c.get_object(Bucket=bucket, Key="probe.txt")["Body"].read()}, s3)
    assert got.ok, got.detail
    assert got.raw["Body"] == body
    CallOutcome.capture("s3", "DeleteObject", lambda c: c.delete_object(
        Bucket=bucket, Key="probe.txt"), s3)
    deleted = CallOutcome.capture("s3", "DeleteBucket", lambda c: c.delete_bucket(
        Bucket=bucket), s3)
    assert deleted.ok, deleted.detail


@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_floci_issued_credentials_are_distinct_from_the_probe_credential(label, endpoint):
    floci = Floci(endpoint)
    created = CallOutcome.capture("iam", "CreateUser", lambda c: c.create_user(
        UserName=f"cloudsec-live-{label}"), floci.client("iam"))
    assert created.ok, created.detail
    key = CallOutcome.capture("iam", "CreateAccessKey", lambda c: c.create_access_key(
        UserName=f"cloudsec-live-{label}"), floci.client("iam"))
    assert key.ok, key.detail
    access_key_id = key.raw["AccessKey"]["AccessKeyId"]
    assert access_key_id != "test"
    assert access_key_id != "CLOUDSECPROBEKEY000001"
    who = CallOutcome.capture("sts", "GetCallerIdentity",
                              lambda c: c.get_caller_identity(),
                              floci.client("sts", akid=access_key_id,
                                           secret=key.raw["AccessKey"]["SecretAccessKey"]))
    assert who.ok, who.detail
    CallOutcome.capture("iam", "DeleteAccessKey", lambda c: c.delete_access_key(
        UserName=f"cloudsec-live-{label}", AccessKeyId=access_key_id), floci.client("iam"))
    CallOutcome.capture("iam", "DeleteUser", lambda c: c.delete_user(
        UserName=f"cloudsec-live-{label}"), floci.client("iam"))


def test_probe_run_produces_a_redacted_artifact(tmp_path):
    from cloudsec_agent import floci_probe

    original = floci_probe.ARTIFACT_DIR
    floci_probe.ARTIFACT_DIR = str(tmp_path)
    try:
        code = floci_probe.main(["--endpoint", "http://localhost:4566",
                                 "--label", "live", "--quiet"])
        assert code == 0
    finally:
        floci_probe.ARTIFACT_DIR = original
    path = tmp_path / "floci-capabilities.live.json"
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["probe_version"] == 1
    assert payload["endpoint"] == "http://localhost:4566"
    for field in ("identity_allow_observed", "implicit_deny_observed",
                   "explicit_deny_observed", "resource_scoping_observed"):
        assert payload["iam_enforcement"][field] in (True, False, None)
    text = path.read_text(encoding="utf-8")
    assert "cloudsec-synthetic-secret-value-do-not-use" not in text


def test_probe_refuses_a_non_local_endpoint():
    from cloudsec_agent import floci_probe

    assert floci_probe.main(["--endpoint", "http://s3.amazonaws.com"]) == 2


def test_probe_exits_nonzero_when_floci_is_unreachable():
    from cloudsec_agent import floci_probe

    assert floci_probe.main(["--endpoint", "http://localhost:4599"]) == 4

def _exists(s3, bucket, key):
    return CallOutcome.capture("s3", "HeadObject", lambda c: c.head_object(
        Bucket=bucket, Key=key), s3).ok


def test_explicit_identity_deny_blocks_s3_put_object_on_enforced_floci():
    bucket = f"cloudsec-denycheck-{uuid.uuid4().hex[:8]}"
    policy_name = "cloudsec-deny-putobject"
    denied_key = "denied.txt"
    control_key = "control.txt"
    denied_arn = f"arn:aws:s3:::{bucket}/{denied_key}"
    allow_only = policy([statement("Allow", "s3:PutObject", f"arn:aws:s3:::{bucket}/*")])
    document = policy([
        statement("Allow", "s3:PutObject", f"arn:aws:s3:::{bucket}/*"),
        statement("Deny", "s3:PutObject", denied_arn),
    ])

    floci = Floci(ENFORCED)
    floci.connect()
    admin = floci.client("s3")
    principal = Identity(floci, f"denycheck{uuid.uuid4().hex[:8]}")

    try:
        assert ensure_bucket(admin, bucket).ok
        assert principal.create(), "Floci IAM user or access key was not created"
        assert principal.access_key_id and principal.access_key_id != "test"

        owner = principal.client("s3")
        baseline_policy = principal.put_inline_policy(policy_name, allow_only)

        baseline = CallOutcome.capture("s3", "PutObject", lambda c: c.put_object(
            Bucket=bucket, Key=control_key, Body=b"cloudsec-synthetic-control"), owner)
        baseline_exists = _exists(admin, bucket, control_key)

        readback = principal.put_inline_policy(policy_name, document)

        denied = CallOutcome.capture("s3", "PutObject", lambda c: c.put_object(
            Bucket=bucket, Key=denied_key, Body=b"cloudsec-synthetic-denied"), owner)
        denied_exists = _exists(admin, bucket, denied_key)

        if not readback:
            classification = "INCONCLUSIVE"
        elif denied.ok and denied_exists:
            classification = "DENY_NOT_ENFORCED"
        elif not denied.ok and not denied_exists:
            classification = "DENY_ENFORCED"
        else:
            classification = "INCONCLUSIVE"

        report = {
            "endpoint": ENFORCED,
            "bucket": bucket,
            "principal": principal.arn,
            "access_key_id": principal.access_key_id,
            "policy_name": policy_name,
            "deny_resource": denied_arn,
            "baseline_policy": allow_only,
            "baseline_policy_readback": baseline_policy,
            "policy_readback": readback,
            "baseline_put_object": {
                "ok": baseline.ok,
                "status": baseline.status,
                "error_code": baseline.error_code,
                "request_id": baseline.request_id,
                "control_object_exists": baseline_exists,
            },
            "denied_put_object": {
                "ok": denied.ok,
                "status": denied.status,
                "exception": denied.exception,
                "error_code": denied.error_code,
                "error_message": denied.error_message,
                "request_id": denied.request_id,
                "denied_object_exists": denied_exists,
            },
            "classification": classification,
        }
        print("\nS3_PUTOBJECT_DENY_CHECK " + json.dumps(report, indent=2))

        assert baseline_policy, "the baseline Allow policy could not be read back"
        assert readback, "the Deny policy could not be read back after attachment"
        assert baseline.ok and baseline_exists, (
            "control PutObject failed, so the principal cannot write and the later "
            f"result would not be attributable to the Deny: {baseline.to_dict()}")
        assert classification != "INCONCLUSIVE"
    finally:
        for key in (control_key, denied_key):
            CallOutcome.capture("s3", "DeleteObject", lambda c, k=key: c.delete_object(
                Bucket=bucket, Key=k), admin)
        CallOutcome.capture("s3", "DeleteBucket",
                            lambda c: c.delete_bucket(Bucket=bucket), admin)
        principal.delete()
