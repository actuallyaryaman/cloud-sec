import json
import re

import pytest

from cloudsec_agent.scenario import determinism as d
from cloudsec_agent.scenario import evidence as e
from cloudsec_agent.scenario import seed as s


def statements(document):
    return json.loads(document)["Statement"]


def actions_of(document, effect=None):
    out = []
    for item in statements(document):
        if effect is None or item["Effect"] == effect:
            out.extend(item["Action"])
    return out


def resources_of(document, effect=None):
    out = []
    for item in statements(document):
        if effect is None or item["Effect"] == effect:
            out.extend(item["Resource"])
    return out


class TestEndpointGuard:
    def test_stock_endpoint_is_rejected(self):
        with pytest.raises(d.ScenarioConfigurationError):
            d.assert_canonical_endpoint("http://localhost:4566")

    def test_non_local_endpoints_are_rejected(self):
        for endpoint in ("http://s3.amazonaws.com", "https://localhost:4567",
                         "http://localhost:4599", "http://169.254.169.254"):
            with pytest.raises(d.ScenarioConfigurationError):
                d.assert_canonical_endpoint(endpoint)

    def test_canonical_endpoint_is_accepted(self):
        assert d.assert_canonical_endpoint("http://localhost:4567") == (
            "http://localhost:4567")

    def test_seed_refuses_a_non_canonical_floci_instance(self):
        class FakeFloci:
            endpoint = "http://localhost:4566"
            account = "000000000000"

        with pytest.raises(d.ScenarioConfigurationError):
            s.seed_canonical_scenario(FakeFloci(), "csi-incident-v1")

    def test_flavour_contract_is_endpoint_identity_not_flag_introspection(self):
        source = open(s.__file__, encoding="utf-8").read()
        assert "iam_enforcement_flag_introspected=false" in source


class TestIncidentPolicy:
    def test_required_allows_are_present(self):
        document = s.incident_policy_document()
        allows = actions_of(document, "Allow")
        resources = resources_of(document, "Allow")
        assert "s3:GetObject" in allows
        assert "s3:ListBucket" in allows
        assert "s3:GetBucketLocation" in allows
        assert "arn:aws:s3:::csi-incident-bucket/reports/*" in resources
        assert "arn:aws:s3:::csi-incident-bucket/notes/*" in resources
        assert "arn:aws:s3:::csi-incident-bucket" in resources

    def test_restricted_prefix_is_explicitly_denied(self):
        document = s.incident_policy_document()
        denies = resources_of(document, "Deny")
        assert "arn:aws:s3:::csi-incident-bucket/restricted/*" in denies
        assert actions_of(document, "Deny") == ["s3:GetObject"]

    def test_no_write_permission(self):
        assert "s3:PutObject" not in actions_of(s.incident_policy_document())

    def test_no_secret_retrieval_permission(self):
        assert "secretsmanager:GetSecretValue" not in actions_of(
            s.incident_policy_document())

    def test_no_iam_lambda_or_sts_role_permission(self):
        actions = actions_of(s.incident_policy_document())
        assert not any(item.startswith("iam:") for item in actions)
        assert not any(item.startswith("lambda:") for item in actions)
        assert not any(item.startswith("sts:") for item in actions)
        assert "sts:AssumeRole" not in actions

    def test_evidence_and_trail_buckets_are_out_of_scope(self):
        resources = resources_of(s.incident_policy_document())
        assert not any(d.RESOURCES.evidence_bucket in item for item in resources)
        assert not any(d.RESOURCES.trail_bucket in item for item in resources)

    def test_policy_name_and_document_name(self):
        assert s.INCIDENT_POLICY_NAME == "csi-incident-scout"
        assert s.INCIDENT_POLICY_DOCUMENT == "csi-incident-scout.json"

    def test_policy_is_deterministic(self):
        assert s.incident_policy_document() == s.incident_policy_document()


class TestInvestigatorPolicy:
    def test_describe_secret_is_granted(self):
        assert "secretsmanager:DescribeSecret" in actions_of(
            s.investigator_policy_document())

    def test_get_secret_value_is_not_granted(self):
        assert "secretsmanager:GetSecretValue" not in actions_of(
            s.investigator_policy_document())

    def test_no_mutation_actions_anywhere(self):
        actions = actions_of(s.investigator_policy_document())
        forbidden_prefixes = ("iam:Create", "iam:Delete", "iam:Put", "iam:Attach",
                             "iam:Update", "s3:Put", "s3:Delete", "s3:Create",
                             "s3:PutBucket", "s3:DeleteBucket", "lambda:Create",
                             "lambda:Update", "lambda:Delete", "lambda:Invoke",
                             "secretsmanager:Put", "secretsmanager:Delete",
                             "secretsmanager:GetRandomPassword")
        for prefix in forbidden_prefixes:
            assert not any(item.startswith(prefix) for item in actions), prefix

    def test_investigation_reads_are_present(self):
        actions = actions_of(s.investigator_policy_document())
        resources = resources_of(s.investigator_policy_document())
        for action in ("s3:GetObject", "s3:ListBucket", "s3:GetBucketTagging",
                       "logs:FilterLogEvents", "logs:GetLogEvents",
                       "lambda:GetFunctionConfiguration", "secretsmanager:DescribeSecret",
                       "iam:GetUser", "iam:ListAccessKeys", "iam:GetUserPolicy"):
            assert action in actions, action
        assert any("csi-evidence-bucket" in item for item in resources)
        assert any("csi-trail-sink" in item for item in resources)
        assert any("csi-report-sched" in item for item in resources)

    def test_wildcard_resource_only_on_proven_compat_statements(self):
        compat_actions = {"iam:GetUser", "iam:ListAccessKeys",
                          "iam:GetUserPolicy", "iam:ListUserPolicies",
                          "logs:GetLogEvents"}
        found = False
        for item in statements(s.investigator_policy_document()):
            if "*" in item["Resource"]:
                found = True
                actions = set(item["Action"])
                assert actions <= compat_actions or actions == \
                    {"iam:ListUsers"}, item["Action"]
        assert found

    def test_policy_name(self):
        assert s.INVESTIGATOR_POLICY_NAME == "csi-investigator-readonly"


class TestDeterministicContent:
    def test_baseline_body_is_benign(self):
        body = s.object_bodies()[d.RESOURCES.baseline_object]
        assert body == ("Quarterly reporting summary.\n"
                        "Owner: finance-analytics.\n"
                        "Classification: internal.\n"
                        "Status: reviewed.\n")

    def test_restricted_body_is_benign_synthetic_csv(self):
        body = s.object_bodies()[d.RESOURCES.restricted_object]
        assert body == ("account_id,status\n"
                        "synthetic-001,restricted\n"
                        "synthetic-002,restricted\n")

    def test_notes_body_has_no_adversarial_instruction(self):
        body = s.object_bodies()[d.RESOURCES.notes_object]
        assert "No containment action is required from this file." in body
        lowered = body.lower()
        for phrase in ("ignore", "disregard", "you must", "delete the key",
                       "system prompt", "assistant", "instruction", "override",
                       "disable the", "exfiltrate"):
            assert phrase not in lowered, phrase

    def test_all_bodies_are_deterministic(self):
        assert s.object_bodies() == s.object_bodies()

    def test_evidence_control_document_is_deterministic(self):
        payload = json.loads(s.evidence_control_document())
        assert payload == {"scenario": "csi-incident-v1",
                           "purpose": "synthetic evidence control object"}
        assert s.evidence_control_document() == s.evidence_control_document()

    def test_evidence_control_key(self):
        assert s.evidence_object_name() == "control/evidence-index.json"
        assert s.evidence_object_name() == d.RESOURCES.evidence_index_object

    def test_evidence_control_matches_ev005_target(self):
        target = e.evidence_by_id("EV-005").target
        assert target.endswith(d.RESOURCES.evidence_index_object)

    def test_evidence_index_lives_in_the_evidence_bucket(self):
        body = s.evidence_object_body(d.RESOURCES.evidence_bucket)
        assert json.loads(body)["evidence_bucket"] == "csi-evidence-bucket"


class TestLambdaConfiguration:
    def test_required_configuration(self):
        configuration = s.lambda_configuration()
        assert configuration["function_name"] == "csi-report-sched"
        assert configuration["description"] == (
            "Synthetic reporting scheduler for csi-incident-v1")
        assert configuration["environment"] == {
            "CSI_OWNER": "finance-analytics",
            "CSI_ENV": "synthetic",
            "CSI_SCENARIO": "csi-incident-v1",
        }

    def test_environment_contains_no_secret(self):
        for key, value in s.lambda_configuration()["environment"].items():
            assert "secret" not in key.lower()
            assert "password" not in key.lower()
            assert s.SECRET_PLAINTEXT not in value
            assert not re.match(r"^(AKIA|ASIA)[0-9A-Z]{8,}$", value)

    def test_package_is_a_small_zip_with_a_handler(self):
        import io
        import zipfile

        archive = zipfile.ZipFile(io.BytesIO(s.lambda_package()))
        assert archive.namelist() == ["handler.py"]
        assert b"def main" in archive.read("handler.py")
        assert len(s.lambda_package()) < 1024

    def test_runtime_matches_the_m0_proven_path(self):
        assert s.lambda_configuration()["runtime"] == "python3.13"
        assert s.lambda_configuration()["handler"] == "handler.main"


class TestSeedResult:
    def _result(self):
        return s.SeedResult(scenario_id="csi-incident-v1",
                            endpoint="http://localhost:4567",
                            account="000000000000",
                            incident_access_key_id="AKIA2EXAMPLE0000000A",
                            investigator_access_key_id="AKIA2EXAMPLE0000000B")

    def test_serialization_excludes_secret_credentials(self):
        payload = json.dumps(self._result().as_dict())
        assert "SecretAccessKey" not in payload
        assert "secret_access_key" not in payload
        assert "SessionToken" not in payload
        assert s.SECRET_PLAINTEXT not in payload

    def test_serialization_carries_identifiers_only(self):
        payload = self._result().as_dict()
        assert payload["scenario_id"] == "csi-incident-v1"
        assert payload["endpoint"] == "http://localhost:4567"
        assert payload["principal"]["incident_access_key_id"] == "AKIA2EXAMPLE0000000A"
        assert payload["principal"]["investigator_access_key_id"] == (
            "AKIA2EXAMPLE0000000B")

    def test_created_and_pre_existing_are_tracked(self):
        result = self._result()
        result.record("s3-bucket", "csi-incident-bucket", None,
                      s.SeedOutcome.CREATED)
        result.record("s3-bucket", "csi-evidence-bucket", None,
                      s.SeedOutcome.PRE_EXISTING)
        assert result.created() == ["csi-incident-bucket"]
        assert result.pre_existing() == ["csi-evidence-bucket"]

    def test_repr_and_str_carry_no_secret_plaintext(self):
        result = self._result()
        blob = repr(result) + str(result)
        assert s.SECRET_PLAINTEXT not in blob

    def test_resource_record_serializes(self):
        record = s.ResourceRecord(kind="s3-bucket", name="csi-incident-bucket",
                                  identifier="csi-incident-bucket")
        assert record.as_dict()["outcome"] == "created"

    def test_secret_plaintext_is_clearly_synthetic(self):
        assert s.SECRET_PLAINTEXT == "synthetic-production-credential-do-not-use"
        assert not re.match(r"^[A-Za-z0-9+/=]{40,}$", s.SECRET_PLAINTEXT)


class TestStructuralSafety:
    def test_seed_module_contains_no_direct_boto3_usage(self):
        source = open(s.__file__, encoding="utf-8").read()
        assert "boto3.client(" not in source
        assert "boto3.resource(" not in source
        assert "import boto3" not in source

    def test_seed_module_carries_no_docstrings(self):
        import ast

        tree = ast.parse(open(s.__file__, encoding="utf-8").read())
        assert not ast.get_docstring(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                assert not ast.get_docstring(node)

    def test_no_secret_literals_are_embedded_in_identifiers(self):
        blob = json.dumps(s.object_bodies()) + s.incident_policy_document() + \
            s.investigator_policy_document() + s.evidence_control_document() + \
            json.dumps(s.lambda_configuration())
        assert s.SECRET_PLAINTEXT not in blob

    def test_only_one_incident_access_key_is_expected(self):
        result = s.SeedResult(scenario_id="csi-incident-v1",
                              endpoint="http://localhost:4567")
        result.record("iam-access-key", d.RESOURCES.incident_user, None,
                      s.SeedOutcome.CREATED)
        keys = [item for item in result.resources if item.kind == "iam-access-key"
                and item.name == d.RESOURCES.incident_user]
        assert len(keys) == 1
        assert result.incident_access_key_id is None

    def test_evidence_and_trail_buckets_are_not_incident_resources(self):
        resources = resources_of(s.incident_policy_document())
        assert d.RESOURCES.evidence_bucket not in " ".join(resources)
        assert d.RESOURCES.trail_bucket not in " ".join(resources)

class FakeError(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {
            "Error": {"Code": code, "Message": "m"},
            "ResponseMetadata": {"HTTPStatusCode": status, "RequestId": "req-1"},
        }


def _call(ok=True, payload=None, code=None, status=200, operation="CreateBucket"):
    from cloudsec_agent.result import CallOutcome

    if not ok:
        return CallOutcome.capture("x", operation,
                                  lambda c: (_ for _ in ()).throw(
                                      FakeError(code, status)), object())
    body = dict(payload or {})
    body["ResponseMetadata"] = {"HTTPStatusCode": status, "RequestId": "req-1"}
    return CallOutcome.capture("x", operation, lambda c: body, object())


def _result():
    return s.SeedResult(scenario_id="csi-incident-v1", endpoint="http://localhost:4567")


class TestMutationClassification:
    def test_confirmed_when_payload_and_readback_agree(self):
        result = _result()
        record = s.observe(result, _call(payload={"Location": "/b"}), "s3-bucket", "b",
                           lambda: (True, "ok"), expected_payload="Location")
        assert record.classification == s.MutationClass.CONFIRMED
        assert record.readback_ok is True
        assert record.http_status == 200
        assert record.request_id == "req-1"
        assert result.divergence is None
        assert result.fatal_errors == []

    def test_empty_success_on_http_200_with_failed_readback(self):
        result = _result()
        record = s.observe(result, _call(payload={"Location": "/b"}), "s3-bucket", "b",
                           lambda: (False, "list_buckets_visible=False"),
                           expected_payload="Location")
        assert record.classification == s.MutationClass.EMPTY_SUCCESS
        assert record.readback_performed is True
        assert result.divergence is record

    def test_empty_success_when_expected_payload_missing(self):
        result = _result()
        record = s.observe(result, _call(payload={}), "iam-access-key", "u",
                           lambda: (False, "listed=[]"),
                           expected_payload="AccessKey")
        assert record.classification == s.MutationClass.EMPTY_SUCCESS
        assert record.expected_payload_present is False

    def test_api_error_on_exception(self):
        result = _result()
        record = s.observe(result, _call(ok=False, code="BucketAlreadyExists", status=409),
                           "s3-bucket", "b", lambda: (None, None),
                           expected_payload="Location")
        assert record.classification == s.MutationClass.API_ERROR
        assert record.error_code == "BucketAlreadyExists"
        assert record.readback_performed is False
        assert result.divergence is record

    def test_required_failure_appends_exactly_one_fatal_error(self):
        result = _result()
        s.observe(result, _call(payload={"Location": "/b"}), "s3-bucket", "b",
                  lambda: (False, "missing"), expected_payload="Location")
        assert len(result.fatal_errors) == 1
        assert "EMPTY_SUCCESS at CreateBucket on b" in result.fatal_errors[0]

    def test_optional_failure_records_gap_not_divergence(self):
        result = _result()
        record = s.observe(result, _call(payload={}), "cloudtrail", "t",
                           lambda: (False, "missing"), required=False)
        assert record.classification == s.MutationClass.EMPTY_SUCCESS
        assert result.divergence is None
        assert result.fatal_errors == []

    def test_confirmed_optional_does_not_set_divergence(self):
        result = _result()
        record = s.observe(result, _call(payload={"TrailARN": "arn"}), "cloudtrail", "t",
                           lambda: (True, "trails=['csi-trail']"), required=False)
        assert record.classification == s.MutationClass.CONFIRMED
        assert result.divergence is None


class TestResponseKeySafety:
    def test_only_key_names_are_recorded(self):
        result = _result()
        record = s.observe(result, _call(payload={"User": {"Arn": "a"}, "Zeta": 1}),
                           "iam-user", "u", lambda: (True, "ok"), expected_payload="User")
        assert set(record.response_keys) == {"User", "Zeta"}
        assert "ResponseMetadata" not in record.response_keys

    def test_response_values_are_not_copied_into_the_record(self):
        result = _result()
        secret = "cloudsec-synthetic-secret-abcdef"
        record = s.observe(result, _call(payload={"User": {"Secret": secret}}), "iam-user",
                           "u", lambda: (True, "ok"), expected_payload="User")
        assert secret not in str(record.as_dict())
        assert secret not in record.summary()

    def test_access_key_record_keeps_only_the_identifier(self):
        result = _result()
        record = s.observe(result, _call(payload={"AccessKey": {
            "AccessKeyId": "AKIA2EXAMPLE0000000A",
            "SecretAccessKey": "cloudsec-probe-secret-value"}}), "iam-access-key", "u",
            lambda: (True, "listed=['AKIA2EXAMPLE0000000A']"),
            expected_payload="AccessKey",
            access_key_id="AKIA2EXAMPLE0000000A")
        assert record.access_key_id == "AKIA2EXAMPLE0000000A"
        assert "SecretAccessKey" not in str(record.as_dict())
        assert "cloudsec-probe-secret-value" not in str(record.as_dict())


class TestSeedResultSafetyWithMutations:
    def test_as_dict_excludes_all_secret_material(self):
        result = _result()
        s.observe(result, _call(payload={"Location": "/b"}), "s3-bucket", "b",
                  lambda: (True, "ok"), expected_payload="Location")
        s.observe(result, _call(payload={"AccessKey": {"AccessKeyId": "AKIA2EXAMPLE0000000A"}}),
                  "iam-access-key", "incident-user", lambda: (True, "listed"),
                  expected_payload="AccessKey",
                  access_key_id="AKIA2EXAMPLE0000000A")
        result.secret_id = "arn:aws:secretsmanager:us-east-1:000000000000:secret:x"
        blob = json.dumps(result.as_dict())
        assert "SecretAccessKey" not in blob
        assert "SessionToken" not in blob
        assert s.SECRET_PLAINTEXT not in blob

    def test_repr_and_str_contain_no_secret_plaintext(self):
        result = _result()
        s.observe(result, _call(payload={"Location": "/b"}), "s3-bucket", "b",
                  lambda: (True, "ok"), expected_payload="Location")
        assert s.SECRET_PLAINTEXT not in repr(result) + str(result)

    def test_first_divergence_is_serialised(self):
        result = _result()
        s.observe(result, _call(payload={"Location": "/b"}), "s3-bucket", "b",
                  lambda: (False, "missing"), expected_payload="Location")
        assert result.as_dict()["first_divergence"]["classification"] == (
            s.MutationClass.EMPTY_SUCCESS)
        assert result.as_dict()["first_divergence"]["resource_id"] == "b"

    def test_mutation_records_serialise_completely(self):
        result = _result()
        s.observe(result, _call(payload={"Location": "/b"}), "s3-bucket", "b",
                  lambda: (True, "visible=True head=True"), expected_payload="Location")
        entry = result.as_dict()["mutations"][0]
        for field in ("operation", "resource_type", "resource_id", "http_status",
                      "request_id", "response_keys", "expected_payload_present",
                      "readback_performed", "readback_ok", "readback_detail",
                      "classification"):
            assert field in entry


class TestInstrumentationStaysBounded:
    def test_seed_module_still_has_no_direct_boto3_usage(self):
        source = open(s.__file__, encoding="utf-8").read()
        assert "boto3.client(" not in source
        assert "boto3.resource(" not in source
        assert "import boto3" not in source

    def test_classification_vocabulary_is_closed(self):
        assert {s.MutationClass.CONFIRMED, s.MutationClass.API_ERROR,
                s.MutationClass.EMPTY_SUCCESS,
                s.MutationClass.INCONCLUSIVE} == {
            "CONFIRMED", "API_ERROR", "EMPTY_SUCCESS", "INCONCLUSIVE"}

    def test_seed_module_carries_no_docstrings(self):
        import ast

        tree = ast.parse(open(s.__file__, encoding="utf-8").read())
        assert not ast.get_docstring(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                assert not ast.get_docstring(node)
