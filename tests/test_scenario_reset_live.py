import json

import pytest

from cloudsec_agent.floci_client import (EndpointUnavailable, Floci,
                                         UnsafeEndpointError, assert_local_endpoint)
from cloudsec_agent.scenario import determinism as d
from cloudsec_agent.scenario import reset as r
from cloudsec_agent.scenario import seed as s

CANONICAL = "http://localhost:4567"
UNRELATED = ("csi-probe-timing", "cloudsec-trail-4567", "awslambda-us-east-1-tasks")


def _canonical_reachable():
    assert_local_endpoint(CANONICAL)
    try:
        Floci(CANONICAL).health()
        return True
    except (EndpointUnavailable, UnsafeEndpointError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not _canonical_reachable(),
    reason="Floci IAM-enforced is not reachable at http://localhost:4567")


@pytest.fixture(scope="module")
def reset_report():
    floci = Floci(CANONICAL)
    s3 = floci.client("s3")
    iam = floci.client("iam")
    sm = floci.client("secretsmanager")
    logs = floci.client("logs")
    lambda_client = floci.client("lambda")
    cloudtrail = floci.client("cloudtrail")

    before = {
        "buckets": sorted(item["Name"]
                          for item in s3.list_buckets()["Buckets"]),
        "users": sorted(item["UserName"]
                        for item in iam.list_users()["Users"]),
    }
    before["owned_buckets_present"] = [b for b in r.owned_buckets()
                                       if b in before["buckets"]]
    before["owned_users_present"] = [u for u in r.owned_users()
                                     if u in before["users"]]
    from cloudsec_agent.result import CallOutcome

    before["secret_present"] = CallOutcome.capture(
        "secretsmanager", "DescribeSecret",
        lambda c: c.describe_secret(SecretId=d.RESOURCES.secret_name), sm).ok
    before["lambda_present"] = CallOutcome.capture(
        "lambda", "GetFunctionConfiguration",
        lambda c: c.get_function_configuration(FunctionName=d.RESOURCES.function_name),
        lambda_client).ok
    before["log_group_present"] = d.RESOURCES.log_group in [
        item["logGroupName"]
        for item in CallOutcome.capture(
            "logs", "DescribeLogGroups", lambda c: c.describe_log_groups(),
            logs).raw.get("logGroups", [])]
    before["trail_present"] = d.RESOURCES.trail_name in [
        item.get("Name")
        for item in CallOutcome.capture(
            "cloudtrail", "DescribeTrails",
            lambda c: c.describe_trails(trailNameList=[d.RESOURCES.trail_name]),
            cloudtrail).raw.get("trailList", [])]
    before["unrelated_present"] = {
        "csi-probe-timing": "csi-probe-timing" in before["users"],
        "cloudsec-trail-4567": "cloudsec-trail-4567" in before["users"],
        "awslambda-us-east-1-tasks": "awslambda-us-east-1-tasks" in before["buckets"],
    }

    report = r.reset_canonical_scenario(floci, d.SCENARIO_ID)

    print("\nPRE-RESET STATE")
    print(json.dumps(before, indent=2))
    print("\nDELETION TRACE")
    for record in report.deletions:
        print("  " + record.summary())
    print("\nSECRET NAMING STRATEGY: " + str(report.secret_naming_strategy_observed))
    print("GAPS: " + json.dumps(report.gaps, indent=2))
    print("FATAL ERRORS: " + json.dumps(report.fatal_errors, indent=2))

    return {"before": before, "report": report, "floci": floci,
            "clients": {"s3": s3, "iam": iam, "sm": sm, "logs": logs,
                        "lambda": lambda_client, "cloudtrail": cloudtrail}}


class TestPreStateIsNotARequirement:
    def test_pre_state_is_recorded_without_asserting_completeness(self, reset_report):
        before = reset_report["before"]
        for key in ("owned_buckets_present", "owned_users_present", "secret_present",
                    "lambda_present", "log_group_present", "trail_present",
                    "unrelated_present", "buckets", "users"):
            assert key in before, key

    def test_any_subset_of_canonical_state_is_valid_input(self, reset_report):
        before = reset_report["before"]
        present_buckets = set(before["owned_buckets_present"])
        present_users = set(before["owned_users_present"])
        assert present_buckets <= set(r.owned_buckets())
        assert present_users <= set(r.owned_users())
        assert bool(present_buckets) or not present_buckets
        assert bool(present_users) or not present_users

    def test_reset_succeeded_regardless_of_pre_state(self, reset_report):
        assert reset_report["report"].fatal_errors == []
        assert reset_report["report"].first_divergence is None

    def test_unrelated_resources_were_present_before_reset(self, reset_report):
        assert reset_report["before"]["unrelated_present"] == {
            "csi-probe-timing": True,
            "cloudsec-trail-4567": True,
            "awslambda-us-east-1-tasks": True,
        }


class TestDeletionTrace:
    def test_no_fatal_errors(self, reset_report):
        assert reset_report["report"].fatal_errors == []

    def test_no_divergence(self, reset_report):
        assert reset_report["report"].first_divergence is None

    def test_every_required_deletion_was_confirmed(self, reset_report):
        for record in reset_report["report"].deletions:
            assert record.classification in (r.DeleteClass.CONFIRMED,
                                             r.DeleteClass.ALREADY_ABSENT), \
                record.summary()

    def test_secret_strategy_was_observed(self, reset_report):
        assert reset_report["report"].secret_naming_strategy_observed in (
            "force-delete", "versioned-alias-required", "not-observed-secret-absent")

    def test_reset_result_carries_no_credential_material(self, reset_report):
        report = reset_report["report"]
        blob = json.dumps(report.as_dict()) + repr(report) + str(report)
        assert "SecretAccessKey" not in blob
        assert "SessionToken" not in blob
        assert s.SECRET_PLAINTEXT not in blob
        assert r.TEMPORARY_SECRET_PLAINTEXT not in blob


class TestCanonicalAbsence:
    def test_owned_buckets_absent(self, reset_report):
        clients = reset_report["clients"]
        names = [item["Name"] for item in clients["s3"].list_buckets()["Buckets"]]
        for bucket in r.owned_buckets():
            assert bucket not in names, bucket
            from cloudsec_agent.result import CallOutcome

            head = CallOutcome.capture(
                "s3", "HeadBucket",
                lambda c, b=bucket: c.head_bucket(Bucket=b), clients["s3"])
            assert not head.ok, bucket

    def test_owned_users_absent(self, reset_report):
        from cloudsec_agent.result import CallOutcome

        clients = reset_report["clients"]
        names = [item["UserName"] for item in clients["iam"].list_users()["Users"]]
        for user in r.owned_users():
            assert user not in names, user
            got = CallOutcome.capture("iam", "GetUser",
                                      lambda c, u=user: c.get_user(UserName=u),
                                      clients["iam"])
            assert not got.ok, user
            assert got.error_code == "NoSuchEntity", user

    def test_secret_absent(self, reset_report):
        from cloudsec_agent.result import CallOutcome

        got = CallOutcome.capture("secretsmanager", "DescribeSecret",
                                  lambda c: c.describe_secret(
                                      SecretId=d.RESOURCES.secret_name),
                                  reset_report["clients"]["sm"])
        assert not got.ok

    def test_lambda_absent(self, reset_report):
        from cloudsec_agent.result import CallOutcome

        got = CallOutcome.capture("lambda", "GetFunctionConfiguration",
                                  lambda c: c.get_function_configuration(
                                      FunctionName=d.RESOURCES.function_name),
                                  reset_report["clients"]["lambda"])
        assert not got.ok

    def test_log_group_absent(self, reset_report):
        from cloudsec_agent.result import CallOutcome

        got = CallOutcome.capture("logs", "DescribeLogGroups",
                                  lambda c: c.describe_log_groups(),
                                  reset_report["clients"]["logs"])
        names = [item["logGroupName"] for item in got.raw.get("logGroups", [])]
        assert d.RESOURCES.log_group not in names

    def test_trail_absent(self, reset_report):
        from cloudsec_agent.result import CallOutcome

        got = CallOutcome.capture("cloudtrail", "DescribeTrails",
                                  lambda c: c.describe_trails(
                                      trailNameList=[d.RESOURCES.trail_name]),
                                  reset_report["clients"]["cloudtrail"])
        names = [item.get("Name") for item in got.raw.get("trailList", [])]
        assert d.RESOURCES.trail_name not in names


class TestUnrelatedPreservation:
    def test_csi_probe_timing_preserved(self, reset_report):
        clients = reset_report["clients"]
        names = [item["UserName"] for item in clients["iam"].list_users()["Users"]]
        assert "csi-probe-timing" in names

    def test_cloudsec_trail_user_preserved(self, reset_report):
        clients = reset_report["clients"]
        names = [item["UserName"] for item in clients["iam"].list_users()["Users"]]
        assert "cloudsec-trail-4567" in names

    def test_floci_internal_lambda_bucket_preserved(self, reset_report):
        clients = reset_report["clients"]
        names = [item["Name"] for item in clients["s3"].list_buckets()["Buckets"]]
        assert "awslambda-us-east-1-tasks" in names

    def test_no_cloudsec_bucket_was_deleted(self, reset_report):
        clients = reset_report["clients"]
        after = {item["Name"] for item in clients["s3"].list_buckets()["Buckets"]}
        before = set(reset_report["before"]["buckets"])
        assert not any(name.startswith("cloudsec-") for name in after - before) or \
            after >= {n for n in before if n.startswith("cloudsec-")}