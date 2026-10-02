import json

import pytest

from cloudsec_agent.floci_client import (EndpointUnavailable, Floci,
                                         UnsafeEndpointError, assert_local_endpoint)
from cloudsec_agent.scenario import determinism as d
from cloudsec_agent.scenario import seed as s

CANONICAL = "http://localhost:4567"


def _canonical_reachable():
    assert_local_endpoint(CANONICAL)
    try:
        Floci(CANONICAL).health()
        return True
    except (EndpointUnavailable, UnsafeEndpointError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not _canonical_reachable(),
    reason="Floci IAM-enforced is not reachable at http://localhost:4567; "
           "start it with 'docker compose up -d --wait'")


@pytest.fixture(scope="module")
def seeded():
    floci = Floci(CANONICAL)
    try:
        result = s.seed_canonical_scenario(floci, d.SCENARIO_ID)
    except s.SetupStateError as exc:
        result = s.seed_scenario(floci, d.SCENARIO_ID)
        print("\nSEED STOPPED: " + str(exc))
        print("\nMUTATION TRACE")
        for record in result.mutations:
            print("  " + record.summary())
        divergence = result.divergence
        print("FIRST DIVERGENCE: " + json.dumps(divergence.as_dict()
                                                if divergence else None, indent=2))
        print("PARTIAL STATE: " + json.dumps({
            "created": result.created(),
            "pre_existing": result.pre_existing(),
            "fatal_errors": result.fatal_errors,
        }, indent=2))
        raise
    print("\nMUTATION TRACE")
    for record in result.mutations:
        print("  " + record.summary())
    return floci, result


class TestSeedCompleted:
    def test_no_fatal_errors(self, seeded):
        _, result = seeded
        assert result.fatal_errors == []
        assert result.flavour_contract.startswith("endpoint-identity:")
        assert "iam_enforcement_flag_introspected=false" in result.flavour_contract

    def test_endpoint_and_account(self, seeded):
        _, result = seeded
        assert result.endpoint == CANONICAL
        assert result.account and result.account.isdigit()

    def test_three_buckets_created(self, seeded):
        _, result = seeded
        created = [item.name for item in result.resources
                   if item.kind == "s3-bucket" and item.outcome == s.SeedOutcome.CREATED]
        assert set(created) == {d.RESOURCES.incident_bucket,
                                d.RESOURCES.evidence_bucket,
                                d.RESOURCES.trail_bucket}

    def test_incident_and_investigator_users_exist(self, seeded):
        floci, _ = seeded
        iam = floci.client("iam")
        for user in (d.RESOURCES.incident_user, d.RESOURCES.investigator_user):
            from cloudsec_agent.result import CallOutcome

            got = CallOutcome.capture("iam", "GetUser",
                                      lambda c: c.get_user(UserName=user), iam)
            assert got.ok, f"{user} missing: {got.error_code}"

    def test_both_inline_policies_read_back(self, seeded):
        floci, _ = seeded
        iam = floci.client("iam")
        from cloudsec_agent.result import CallOutcome

        incident = CallOutcome.capture("iam", "GetUserPolicy",
                                       lambda c: c.get_user_policy(
                                           UserName=d.RESOURCES.incident_user,
                                           PolicyName=s.INCIDENT_POLICY_NAME), iam)
        assert incident.ok, incident.error_code
        stored = incident.raw["PolicyDocument"]
        submitted = json.loads(s.incident_policy_document())
        assert stored.get("Statement") == submitted["Statement"]

        investigator = CallOutcome.capture("iam", "GetUserPolicy",
                                           lambda c: c.get_user_policy(
                                               UserName=d.RESOURCES.investigator_user,
                                               PolicyName=s.INVESTIGATOR_POLICY_NAME),
                                           iam)
        assert investigator.ok, investigator.error_code
        stored_investigator = investigator.raw["PolicyDocument"]
        assert stored_investigator.get("Statement") == json.loads(
            s.investigator_policy_document())["Statement"]

    def test_incident_user_has_exactly_one_active_access_key(self, seeded):
        floci, _ = seeded
        from cloudsec_agent.result import CallOutcome

        iam = floci.client("iam")
        listed = CallOutcome.capture("iam", "ListAccessKeys",
                                     lambda c: c.list_access_keys(
                                         UserName=d.RESOURCES.incident_user), iam)
        assert listed.ok
        active = [item for item in listed.raw["AccessKeyMetadata"]
                  if item["Status"] == "Active"]
        assert len(active) == 1

    def test_investigator_has_exactly_one_active_access_key(self, seeded):
        floci, _ = seeded
        from cloudsec_agent.result import CallOutcome

        iam = floci.client("iam")
        listed = CallOutcome.capture("iam", "ListAccessKeys",
                                     lambda c: c.list_access_keys(
                                         UserName=d.RESOURCES.investigator_user), iam)
        assert listed.ok
        active = [item for item in listed.raw["AccessKeyMetadata"]
                  if item["Status"] == "Active"]
        assert len(active) == 1

    def test_four_s3_objects_exist_with_deterministic_bodies(self, seeded):
        floci, _ = seeded
        from cloudsec_agent.result import CallOutcome

        s3 = floci.client("s3")
        expected = dict(s.object_bodies())
        expected[d.RESOURCES.evidence_index_object] = s.evidence_control_document()
        for bucket, key in ((d.RESOURCES.incident_bucket, d.RESOURCES.baseline_object),
                            (d.RESOURCES.incident_bucket, d.RESOURCES.notes_object),
                            (d.RESOURCES.incident_bucket,
                             d.RESOURCES.restricted_object),
                            (d.RESOURCES.evidence_bucket,
                             d.RESOURCES.evidence_index_object)):
            got = CallOutcome.capture("s3", "GetObject", lambda c, b=bucket, k=key: {
                "body": c.get_object(Bucket=b, Key=k)["Body"].read().decode("utf-8")},
                s3)
            assert got.ok, f"{bucket}/{key}: {got.error_code}"
            assert got.raw["body"] == expected[key], key

    def test_report_tag_present_on_incident_bucket(self, seeded):
        floci, _ = seeded
        from cloudsec_agent.result import CallOutcome

        s3 = floci.client("s3")
        tags = CallOutcome.capture("s3", "GetBucketTagging",
                                   lambda c: c.get_bucket_tagging(
                                       Bucket=d.RESOURCES.incident_bucket), s3)
        assert tags.ok, tags.error_code
        pairs = {item["Key"]: item["Value"] for item in tags.raw["TagSet"]}
        assert pairs.get("REPORT_TAG") == "csi-owned"

    def test_describe_secret_works_with_the_seed_identity(self, seeded):
        floci, result = seeded
        from cloudsec_agent.result import CallOutcome

        described = CallOutcome.capture("secretsmanager", "DescribeSecret",
                                        lambda c: c.describe_secret(
                                            SecretId=d.RESOURCES.secret_name),
                                        floci.client("secretsmanager"))
        assert described.ok, described.error_code
        assert result.secret_id
        assert described.raw.get("Name") == d.RESOURCES.secret_name

    def test_log_group_and_stream_exist(self, seeded):
        floci, _ = seeded
        from cloudsec_agent.result import CallOutcome

        logs = floci.client("logs")
        groups = CallOutcome.capture("logs", "DescribeLogGroups",
                                     lambda c: c.describe_log_groups(), logs)
        assert groups.ok
        assert any(item["logGroupName"] == d.RESOURCES.log_group
                   for item in groups.raw["logGroups"])
        streams = CallOutcome.capture("logs", "DescribeLogStreams",
                                      lambda c: c.describe_log_streams(
                                          logGroupName=d.RESOURCES.log_group), logs)
        assert streams.ok, streams.error_code
        assert any(item["logStreamName"] == d.RESOURCES.log_stream
                   for item in streams.raw["logStreams"])

    def test_lambda_configuration_is_readable(self, seeded):
        floci, result = seeded
        from cloudsec_agent.result import CallOutcome

        assert result.lambda_status in (s.LambdaStatus.CREATED,
                                        s.LambdaStatus.PRE_EXISTING)
        configuration = CallOutcome.capture(
            "lambda", "GetFunctionConfiguration",
            lambda c: c.get_function_configuration(
                FunctionName=d.RESOURCES.function_name),
            floci.client("lambda"))
        assert configuration.ok, configuration.error_code
        assert configuration.raw["Description"] == s.lambda_configuration()["description"]
        assert configuration.raw["Environment"]["Variables"] == \
            s.lambda_configuration()["environment"]

    def test_cloudtrail_setup_is_recorded_as_optional(self, seeded):
        _, result = seeded
        entries = [item for item in result.resources if item.kind == "cloudtrail"]
        assert entries, "no CloudTrail record produced"
        assert all("optional" in (item.detail or "") for item in entries)

    def test_seed_result_carries_no_credential_material(self, seeded):
        _, result = seeded
        blob = json.dumps(result.as_dict()) + repr(result)
        assert "SecretAccessKey" not in blob
        assert "SessionToken" not in blob
        assert s.SECRET_PLAINTEXT not in blob

    def test_secret_plaintext_is_registered_for_manifest_safety(self, seeded):
        from cloudsec_agent.scenario.manifest import registered_manifest_secrets

        registered = registered_manifest_secrets()
        assert s.SECRET_PLAINTEXT in registered
        for key_id in (seeded[1].incident_access_key_id,
                       seeded[1].investigator_access_key_id):
            assert key_id not in registered