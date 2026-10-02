import json
import os
import pathlib

import pytest

from cloudsec_agent import seed_scenario as cli
from cloudsec_agent.floci_client import (EndpointUnavailable, Floci,
                                         UnsafeEndpointError, assert_local_endpoint)
from cloudsec_agent.result import CallOutcome
from cloudsec_agent.scenario import determinism as d
from cloudsec_agent.scenario import reset as rs
from cloudsec_agent.scenario import seed as s
from cloudsec_agent.scenario.manifest import registered_manifest_secrets

CANONICAL = "http://localhost:4567"
ARTIFACTS_DIR = "artifacts/scenario"
MANIFEST_NAME = "manifest.json"
REPO = pathlib.Path(__file__).resolve().parents[1]
DIAGNOSTIC_FILES = ("scripts/diagnose_floci_client_lifecycle.py",
                    "tests/test_floci_client_lifecycle_live.py")
RESIDUE_USER = "csi-probe-timing"
UNRELATED_USERS = ("cloudsec-trail-4567",)
INTERNAL_BUCKET = "awslambda-us-east-1-tasks"


def _reachable():
    assert_local_endpoint(CANONICAL)
    try:
        Floci(CANONICAL).health()
        return True
    except (EndpointUnavailable, UnsafeEndpointError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not _reachable(),
    reason="Floci IAM-enforced is not reachable at http://localhost:4567")


def _capture(service, operation, func, client):
    return CallOutcome.capture(service, operation, func, client)


def _active_keys(iam, user):
    listed = _capture("iam", "ListAccessKeys",
                      lambda c: c.list_access_keys(UserName=user), iam)
    if not listed.ok:
        return []
    return [item["AccessKeyId"] for item in listed.raw["AccessKeyMetadata"]
            if item["Status"] == "Active"]


def snapshot(floci):
    iam = floci.client("iam")
    s3 = floci.client("s3")
    described = _capture("secretsmanager", "DescribeSecret",
                         lambda c: c.describe_secret(SecretId=d.RESOURCES.secret_name),
                         floci.client("secretsmanager"))
    user = _capture("iam", "GetUser",
                    lambda c: c.get_user(UserName=d.RESOURCES.incident_user), iam)
    objects = {}
    for bucket, key in ((d.RESOURCES.incident_bucket, d.RESOURCES.baseline_object),
                        (d.RESOURCES.incident_bucket, d.RESOURCES.notes_object),
                        (d.RESOURCES.incident_bucket, d.RESOURCES.restricted_object),
                        (d.RESOURCES.evidence_bucket,
                         d.RESOURCES.evidence_index_object)):
        got = _capture("s3", "GetObject", lambda c, b=bucket, k=key: {
            "body": c.get_object(Bucket=b, Key=k)["Body"].read().decode("utf-8")}, s3)
        objects[f"{bucket}/{key}"] = got.raw.get("body") if got.ok else None
    tags = _capture("s3", "GetBucketTagging", lambda c: c.get_bucket_tagging(
        Bucket=d.RESOURCES.incident_bucket), s3)
    function = _capture("lambda", "GetFunctionConfiguration",
                        lambda c: c.get_function_configuration(
                            FunctionName=d.RESOURCES.function_name),
                        floci.client("lambda"))
    groups = _capture("logs", "DescribeLogGroups",
                      lambda c: c.describe_log_groups(), floci.client("logs"))
    trails = _capture("cloudtrail", "DescribeTrails", lambda c: c.describe_trails(
        trailNameList=[d.RESOURCES.trail_name]), floci.client("cloudtrail"))
    return {
        "incident_access_key_id": (_active_keys(iam, d.RESOURCES.incident_user)
                                   or [None])[0],
        "investigator_access_key_id": (_active_keys(iam, d.RESOURCES.investigator_user)
                                       or [None])[0],
        "incident_arn": user.raw.get("User", {}).get("Arn") if user.ok else None,
        "investigator_arn": (f"arn:aws:iam::{floci.account}:user/"
                             f"{d.RESOURCES.investigator_user}"),
        "buckets": [item["Name"] for item in s3.list_buckets()["Buckets"]],
        "secret_logical_name": d.RESOURCES.secret_name,
        "secret_id": described.raw.get("ARN") if described.ok else None,
        "function_name": d.RESOURCES.function_name,
        "log_group": d.RESOURCES.log_group,
        "trail_name": d.RESOURCES.trail_name,
        "object_bodies": objects,
        "bucket_tags": {item["Key"]: item["Value"]
                        for item in tags.raw.get("TagSet", [])},
        "function_env": (function.raw.get("Environment", {}).get("Variables", {})
                         if function.ok else None),
        "log_groups": [item["logGroupName"]
                       for item in groups.raw.get("logGroups", [])],
        "trails": [item.get("Name") for item in trails.raw.get("trailList", [])],
    }


def verify_absent(floci):
    s3 = floci.client("s3")
    iam = floci.client("iam")
    buckets = {item["Name"]
               for item in s3.list_buckets()["Buckets"]}
    users = {item["UserName"] for item in iam.list_users()["Users"]}
    survivors = []
    for bucket in rs.owned_buckets():
        if bucket in buckets:
            survivors.append(bucket)
        head = _capture("s3", "HeadBucket", lambda c, b=bucket: c.head_bucket(
            Bucket=b), s3)
        if head.ok:
            survivors.append(f"{bucket}:head")
    for user in rs.owned_users():
        if user in users:
            survivors.append(user)
        got = _capture("iam", "GetUser", lambda c, u=user: c.get_user(UserName=u), iam)
        if got.ok:
            survivors.append(f"{user}:get")
    secret = _capture("secretsmanager", "DescribeSecret",
                      lambda c: c.describe_secret(SecretId=d.RESOURCES.secret_name),
                      floci.client("secretsmanager"))
    if secret.ok:
        survivors.append(d.RESOURCES.secret_name)
    function = _capture("lambda", "GetFunctionConfiguration",
                        lambda c: c.get_function_configuration(
                            FunctionName=d.RESOURCES.function_name),
                        floci.client("lambda"))
    if function.ok:
        survivors.append(d.RESOURCES.function_name)
    groups = _capture("logs", "DescribeLogGroups",
                      lambda c: c.describe_log_groups(), floci.client("logs"))
    if d.RESOURCES.log_group in [item["logGroupName"]
                                 for item in groups.raw.get("logGroups", [])]:
        survivors.append(d.RESOURCES.log_group)
    trails = _capture("cloudtrail", "DescribeTrails", lambda c: c.describe_trails(
        trailNameList=[d.RESOURCES.trail_name]), floci.client("cloudtrail"))
    if d.RESOURCES.trail_name in [item.get("Name")
                                 for item in trails.raw.get("trailList", [])]:
        survivors.append(d.RESOURCES.trail_name)
    unrelated_users = [name for name in UNRELATED_USERS if name in users]
    return {"survivors": survivors, "users": sorted(users),
            "buckets": sorted(buckets),
            "internal_bucket_present": INTERNAL_BUCKET in buckets,
            "residue_present": RESIDUE_USER in users,
            "unrelated_users_present": unrelated_users}


@pytest.fixture(scope="module")
def cycle():
    floci = Floci(CANONICAL)
    floci.health()
    floci.describe_identity()
    state = {}
    state["pre"] = snapshot(floci)

    reset_result = rs.reset_canonical_scenario(floci, d.SCENARIO_ID)
    state["reset"] = {
        "fatal_errors": reset_result.fatal_errors,
        "divergence": reset_result.first_divergence,
        "classifications": [item.classification for item in reset_result.deletions],
        "secret_strategy": reset_result.secret_naming_strategy_observed,
        "gaps": reset_result.gaps,
    }
    state["empty"] = verify_absent(floci)

    if state["empty"]["survivors"]:
        print("\nCYCLE ABORTED AT PHASE 2")
        print(json.dumps(state, indent=2, default=str))
        return state

    outcome = cli.seed_and_write_manifest(CANONICAL, ARTIFACTS_DIR)
    state["seed"] = {
        "mutations": [item.classification for item in outcome["seed_result"].mutations],
        "fatal_errors": outcome["seed_result"].fatal_errors,
        "divergence": outcome["seed_result"].divergence,
        "gaps": outcome["seed_result"].gaps,
        "verification_failures": outcome["verification"].failures,
        "verification_gaps": outcome["verification"].gaps,
    }
    state["post"] = snapshot(outcome["floci"])
    manifest_path = outcome["path"]
    state["manifest_path"] = manifest_path
    state["manifest_raw"] = pathlib.Path(manifest_path).read_text(
        encoding="utf-8")
    state["manifest"] = json.loads(state["manifest_raw"])
    state["final"] = verify_absent(outcome["floci"])
    state["registered_secrets"] = dict(registered_manifest_secrets())
    state["artifact_leftovers"] = sorted(
        name for name in os.listdir(ARTIFACTS_DIR) if name.startswith(".manifest-"))

    if (state["seed"]["fatal_errors"] or state["seed"]["divergence"]
            or state["seed"]["verification_failures"]):
        print("\nCYCLE ABORTED AT PHASE 3")
        print(json.dumps({k: v for k, v in state.items()
                          if k not in ("manifest_raw", "manifest")},
                         indent=2, default=str))
        return state

    state["residue_cleanup"] = _remove_residue(outcome["floci"])
    for relative in DIAGNOSTIC_FILES:
        target = REPO / relative
        if target.exists():
            target.unlink()
    state["diagnostic_files_removed"] = [
        relative for relative in DIAGNOSTIC_FILES
        if not (REPO / relative).exists()]
    return state


def _remove_residue(floci):
    iam = floci.client("iam")
    if RESIDUE_USER not in {item["UserName"]
                            for item in iam.list_users()["Users"]}:
        return {"present_before": False, "deleted": None,
                "absent_after": True}
    listed = _capture("iam", "ListAccessKeys",
                      lambda c: c.list_access_keys(UserName=RESIDUE_USER), iam)
    deleted_keys = []
    if listed.ok:
        for item in listed.raw.get("AccessKeyMetadata", []):
            outcome = _capture("iam", "DeleteAccessKey",
                               lambda c, i=item["AccessKeyId"]: c.delete_access_key(
                                   UserName=RESIDUE_USER, AccessKeyId=i), iam)
            deleted_keys.append(outcome.ok)
    delete = _capture("iam", "DeleteUser",
                      lambda c: c.delete_user(UserName=RESIDUE_USER), iam)
    got = _capture("iam", "GetUser",
                   lambda c: c.get_user(UserName=RESIDUE_USER), iam)
    return {"present_before": True, "keys_deleted": deleted_keys,
            "deleted": delete.ok, "delete_error": delete.error_code,
            "absent_after": (not got.ok) and RESIDUE_USER not in
            {item["UserName"] for item in iam.list_users()["Users"]}}


class TestPreState:
    def test_pre_state_was_populated(self, cycle):
        pre = cycle["pre"]
        assert pre["incident_access_key_id"]
        assert pre["investigator_access_key_id"]
        assert pre["secret_id"]
        for bucket in rs.owned_buckets():
            assert bucket in pre["buckets"]
        assert len(pre["object_bodies"]) == 4

    def test_pre_state_holds_no_secret_material(self, cycle):
        blob = json.dumps(cycle["pre"])
        assert "SecretAccessKey" not in blob
        assert "SessionToken" not in blob
        assert s.SECRET_PLAINTEXT not in blob


class TestPhaseOneReset:
    def test_reset_had_no_fatal_errors_or_divergence(self, cycle):
        assert cycle["reset"]["fatal_errors"] == []
        assert cycle["reset"]["divergence"] is None

    def test_reset_produced_no_empty_success_or_api_error(self, cycle):
        for classification in cycle["reset"]["classifications"]:
            assert classification not in ("EMPTY_SUCCESS", "API_ERROR")

    def test_reset_recorded_classifications(self, cycle):
        counts = {}
        for item in cycle["reset"]["classifications"]:
            counts[item] = counts.get(item, 0) + 1
        print("\nRESET CLASSIFICATIONS: " + json.dumps(counts))
        assert counts


class TestPhaseTwoEmpty:
    def test_no_canonical_resource_survived(self, cycle):
        assert cycle["empty"]["survivors"] == []

    def test_unrelated_resources_survived_reset(self, cycle):
        assert cycle["empty"]["internal_bucket_present"] is True
        for name in UNRELATED_USERS:
            assert name in cycle["empty"]["users"], name

    def test_residue_was_present_and_untouched_by_reset(self, cycle):
        assert cycle["empty"]["residue_present"] is True


class TestPhaseThreeReseed:
    def test_all_required_mutations_confirmed(self, cycle):
        assert cycle["seed"]["fatal_errors"] == []
        assert cycle["seed"]["divergence"] is None
        assert cycle["seed"]["verification_failures"] == []
        for classification in cycle["seed"]["mutations"]:
            assert classification == "CONFIRMED", classification

    def test_no_empty_success_reproduced(self, cycle):
        assert "EMPTY_SUCCESS" not in cycle["seed"]["mutations"]
        assert "API_ERROR" not in cycle["seed"]["mutations"]


class TestPhaseFourFinalState:
    def test_final_state_is_populated(self, cycle):
        survivors = set(cycle["final"]["survivors"])
        canonical = {item for item in rs.OWNED.all_names()
                     if item in (*rs.owned_buckets(), *rs.owned_users(),
                                 d.RESOURCES.function_name, d.RESOURCES.log_group,
                                 d.RESOURCES.secret_name, d.RESOURCES.trail_name)}
        assert canonical <= survivors, canonical - survivors
        for bucket in rs.owned_buckets():
            assert bucket in cycle["final"]["buckets"]
        for user in rs.owned_users():
            assert user in cycle["final"]["users"]

    def test_unrelated_resources_survived_the_cycle(self, cycle):
        assert cycle["final"]["internal_bucket_present"] is True
        for name in UNRELATED_USERS:
            assert name in cycle["final"]["users"], name


class TestRepeatabilityComparison:
    def test_stable_identity_fields(self, cycle):
        pre, post = cycle["pre"], cycle["post"]
        assert pre["incident_arn"] == post["incident_arn"]
        assert pre["investigator_arn"] == post["investigator_arn"]
        assert pre["secret_logical_name"] == post["secret_logical_name"]
        assert pre["function_name"] == post["function_name"]
        assert pre["log_group"] == post["log_group"]
        assert pre["trail_name"] == post["trail_name"]

    def test_stable_object_bodies_and_tags(self, cycle):
        pre, post = cycle["pre"], cycle["post"]
        assert pre["object_bodies"] == post["object_bodies"]
        assert pre["bucket_tags"] == post["bucket_tags"]
        assert pre["bucket_tags"].get("REPORT_TAG") == "csi-owned"

    def test_stable_lambda_environment(self, cycle):
        pre, post = cycle["pre"], cycle["post"]
        assert pre["function_env"] == post["function_env"]
        assert post["function_env"] == {"CSI_OWNER": "finance-analytics",
                                         "CSI_ENV": "synthetic",
                                         "CSI_SCENARIO": "csi-incident-v1"}

    def test_stable_log_groups_and_trails(self, cycle):
        pre, post = cycle["pre"], cycle["post"]
        assert d.RESOURCES.log_group in pre["log_groups"]
        assert d.RESOURCES.log_group in post["log_groups"]
        assert pre["trails"] == post["trails"] == [d.RESOURCES.trail_name]

    def test_variable_fields_are_allowed_to_differ(self, cycle):
        pre, post = cycle["pre"], cycle["post"]
        assert pre["incident_access_key_id"] != post["incident_access_key_id"]
        assert pre["investigator_access_key_id"] != post["investigator_access_key_id"]

    def test_secret_physical_arn_may_vary_but_logical_name_must_not(self, cycle):
        pre, post = cycle["pre"], cycle["post"]
        assert pre["secret_logical_name"] == post["secret_logical_name"] == (
            "csi-db-production-credential")


class TestAccessKeyReplacement:
    def test_new_incident_key_differs_from_old(self, cycle):
        assert cycle["pre"]["incident_access_key_id"] != cycle["post"][
            "incident_access_key_id"]

    def test_old_incident_key_is_not_listed_after_reseed(self, cycle):
        iam = cycle["post"].get("_iam_all_keys")
        if iam is None:
            floci = Floci(CANONICAL)
            floci.health()
            floci.describe_identity()
            iam_client = floci.client("iam")
            listed = _capture("iam", "ListAccessKeys",
                              lambda c: c.list_access_keys(
                                  UserName=d.RESOURCES.incident_user), iam_client)
            ids = [item["AccessKeyId"]
                   for item in listed.raw.get("AccessKeyMetadata", [])]
        else:
            ids = iam
        assert cycle["pre"]["incident_access_key_id"] not in ids
        assert cycle["post"]["incident_access_key_id"] in ids

    def test_manifest_principal_matches_the_new_key(self, cycle):
        assert cycle["manifest"]["principal"]["access_key_id"] == cycle["post"][
            "incident_access_key_id"]

    def test_manifest_principal_reports_one_active_key(self, cycle):
        assert cycle["manifest"]["principal"]["access_key_count"] == 1
        assert cycle["manifest"]["principal"]["access_key_status"] == "Active"


class TestManifestAssertions:
    def test_canonical_manifest_exists_and_parses(self, cycle):
        assert os.path.exists(cycle["manifest_path"])
        assert cycle["manifest"]["scenario_id"] == "csi-incident-v1"

    def test_manifest_activity_is_not_seeded(self, cycle):
        assert cycle["manifest"]["activity_seeded"] is False
        assert cycle["manifest"]["manifest_metadata"]["is_incident_evidence"] is False

    def test_manifest_has_eight_authoritative_and_two_corroborating(self, cycle):
        records = cycle["manifest"]["evidence"]
        assert len(records) == 10
        assert sum(1 for item in records if item["authoritative"]) == 8

    def test_every_evidence_observation_field_is_null(self, cycle):
        for record in cycle["manifest"]["evidence"]:
            assert record["observed_result"] is None
            assert record["observed_http_status"] is None
            assert record["observed_error_code"] is None
            assert record["native_corroborated"] is None

    def test_manifest_contains_no_secret_material(self, cycle):
        raw = cycle["manifest_raw"]
        assert "SecretAccessKey" not in raw
        assert "SessionToken" not in raw
        assert "SecretString" not in raw
        assert s.SECRET_PLAINTEXT not in raw
        for secret in cycle["registered_secrets"]:
            assert secret not in raw

    def test_manifest_was_written_atomically(self, cycle):
        assert cycle["artifact_leftovers"] == []

    def test_manifest_identifiers_match_live_state(self, cycle):
        resources = cycle["manifest"]["resources"]
        assert resources["incident_bucket"] == d.RESOURCES.incident_bucket
        assert resources["evidence_bucket"] == d.RESOURCES.evidence_bucket
        assert resources["trail_bucket"] == d.RESOURCES.trail_bucket
        assert resources["secret_id"] == cycle["post"]["secret_id"]
        assert resources["secret_logical_name"] == d.RESOURCES.secret_name

    def test_manifest_holds_stable_scenario_constants(self, cycle):
        assert cycle["manifest"]["seed"] == d.SEED
        assert cycle["manifest"]["reference_time"] == d.REFERENCE_TIME_ISO
        assert cycle["manifest"]["scenario_flavour"] == d.SCENARIO_FLAVOUR
        assert cycle["manifest"]["endpoint"] == CANONICAL


class TestDiagnosticResidueRemoved:
    def test_diagnostic_files_are_gone_from_the_working_tree(self, cycle):
        assert cycle["diagnostic_files_removed"] == list(DIAGNOSTIC_FILES)
        for relative in DIAGNOSTIC_FILES:
            assert not (REPO / relative).exists()

    def test_residue_user_was_removed_and_confirmed_absent(self, cycle):
        cleanup = cycle["residue_cleanup"]
        assert cleanup["present_before"] is True
        assert cleanup["deleted"] is True
        assert cleanup["absent_after"] is True

    def test_residue_user_is_absent_from_live_iam(self, cycle):
        assert RESIDUE_USER not in cycle["final"]["users"]

    def test_m0_user_still_present(self, cycle):
        for name in UNRELATED_USERS:
            assert name in cycle["final"]["users"]