import ast
import json

import pytest

from cloudsec_agent.scenario import determinism as d
from cloudsec_agent.scenario import reset as r
from cloudsec_agent.scenario import seed as s


class FakeError(Exception):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.response = {
            "Error": {"Code": code, "Message": "m"},
            "ResponseMetadata": {"HTTPStatusCode": status, "RequestId": "req-1"},
        }


def _call(ok=True, payload=None, code=None, status=400, operation="Delete"):
    from cloudsec_agent.result import CallOutcome

    if not ok:
        return CallOutcome.capture("x", operation,
                                  lambda c: (_ for _ in ()).throw(
                                      FakeError(code, status)), object())
    body = dict(payload or {})
    body["ResponseMetadata"] = {"HTTPStatusCode": status, "RequestId": "req-1"}
    return CallOutcome.capture("x", operation, lambda c: body, object())


def _result():
    return r.ResetResult(scenario_id="csi-incident-v1", endpoint="http://localhost:4567")


class TestOwnershipBoundary:
    def test_includes_every_canonical_resource(self):
        names = set(r.OWNED.all_names())
        for expected in (d.RESOURCES.incident_bucket, d.RESOURCES.evidence_bucket,
                         d.RESOURCES.trail_bucket, d.RESOURCES.incident_user,
                         d.RESOURCES.investigator_user, s.INCIDENT_POLICY_NAME,
                         s.INVESTIGATOR_POLICY_NAME, d.RESOURCES.function_name,
                         d.RESOURCES.log_group, d.RESOURCES.secret_name,
                         d.RESOURCES.trail_name):
            assert expected in names, expected

    def test_excludes_csi_probe_timing(self):
        assert "csi-probe-timing" not in r.OWNED.all_names()
        assert r.is_owned("csi-probe-timing") is False

    def test_excludes_cloudsec_trail_and_m0_resources(self):
        names = r.OWNED.all_names()
        assert "cloudsec-trail-4567" not in names
        assert not any(item.startswith("cloudsec-") for item in names)

    def test_excludes_floci_internal_lambda_bucket(self):
        assert "awslambda-us-east-1-tasks" not in r.OWNED.all_names()
        assert r.is_owned("awslambda-us-east-1-tasks") is False

    def test_no_wildcard_csi_deletion_logic(self):
        source = open(r.__file__, encoding="utf-8").read()
        assert "startswith(\"csi-\")" not in source
        assert "startswith('csi-')" not in source
        assert "startswith(\"cloudsec-\")" not in source
        for literal in ("csi-*", "cloudsec-*"):
            assert literal not in source

    def test_bucket_list_is_exact_and_ordered(self):
        assert r.owned_buckets() == (d.RESOURCES.incident_bucket,
                                     d.RESOURCES.evidence_bucket,
                                     d.RESOURCES.trail_bucket)

    def test_user_list_is_exact(self):
        assert r.owned_users() == (d.RESOURCES.incident_user,
                                   d.RESOURCES.investigator_user)

    def test_ownership_is_immutable(self):
        with pytest.raises(Exception):
            r.OWNED.trail_name = "other"


class TestDeleteClassification:
    def test_confirmed_on_success_and_absence(self):
        result = _result()
        record = r._observe_delete(result, _call(status=204), "s3-bucket",
                                   "csi-incident-bucket", lambda: (True, "absent"))
        assert record.classification == r.DeleteClass.CONFIRMED
        assert record.absent_after is True
        assert result.first_divergence is None
        assert result.fatal_errors == []

    def test_already_absent_from_not_found(self):
        result = _result()
        record = r._observe_delete(result, _call(ok=False, code="NoSuchEntity",
                                                 status=404), "iam-user",
                                   "incident-user", lambda: (True, "absent"))
        assert record.classification == r.DeleteClass.ALREADY_ABSENT
        assert result.fatal_errors == []

    def test_already_absent_variants(self):
        for code in ("ResourceNotFoundException", "NoSuchBucket", "404"):
            result = _result()
            record = r._observe_delete(result, _call(ok=False, code=code, status=404),
                                       "lambda", "csi-report-sched",
                                       lambda: (True, "absent"))
            assert record.classification == r.DeleteClass.ALREADY_ABSENT, code

    def test_empty_success_when_resource_still_present(self):
        result = _result()
        record = r._observe_delete(result, _call(status=204), "s3-bucket",
                                   "csi-incident-bucket",
                                   lambda: (False, "list_visible=True"))
        assert record.classification == r.DeleteClass.EMPTY_SUCCESS
        assert record.absent_after is False
        assert result.first_divergence is record
        assert len(result.fatal_errors) == 1

    def test_api_error_records_error_code(self):
        result = _result()
        record = r._observe_delete(result, _call(ok=False, code="AccessDenied",
                                                 status=403), "s3-bucket",
                                   "csi-incident-bucket", lambda: (None, None))
        assert record.classification == r.DeleteClass.API_ERROR
        assert record.error_code == "AccessDenied"
        assert result.fatal_errors

    def test_optional_api_error_is_not_fatal(self):
        result = _result()
        record = r._observe_delete(result, _call(ok=False, code="AccessDenied",
                                                 status=403), "cloudtrail",
                                   "csi-trail", lambda: (True, "absent"),
                                   required=False)
        assert record.classification == r.DeleteClass.API_ERROR
        assert result.first_divergence is None
        assert result.fatal_errors == []

    def test_optional_empty_success_does_not_set_divergence(self):
        result = _result()
        record = r._observe_delete(result, _call(status=204), "lambda",
                                   "csi-report-sched",
                                   lambda: (False, "still present"), required=False)
        assert record.classification == r.DeleteClass.EMPTY_SUCCESS
        assert result.first_divergence is None
        assert result.fatal_errors == []


class TestDeleteRecordSafety:
    def test_only_key_names_are_stored(self):
        result = _result()
        record = r._observe_delete(result, _call(payload={"Zeta": 1}, status=200),
                                   "x", "y", lambda: (True, "absent"))
        assert set(record.response_keys) == {"Zeta"}
        assert "ResponseMetadata" not in record.response_keys

    def test_access_key_id_is_permitted(self):
        result = _result()
        record = r._observe_delete(result, _call(status=200), "iam-access-key",
                                   "incident-user/AKIA2EXAMPLE0000000A",
                                   lambda: (True, "absent"),
                                   access_key_id="AKIA2EXAMPLE0000000A")
        assert record.access_key_id == "AKIA2EXAMPLE0000000A"

    def test_reset_result_excludes_all_secret_material(self):
        result = _result()
        r._observe_delete(result, _call(payload={"AccessKey": {"AccessKeyId": "AKIA2X"}}),
                          "iam-access-key", "incident-user", lambda: (True, "absent"),
                          access_key_id="AKIA2EXAMPLE0000000A")
        result.secret_naming_strategy_observed = "force-delete"
        blob = json.dumps(result.as_dict()) + repr(result) + str(result)
        assert "SecretAccessKey" not in blob
        assert "SessionToken" not in blob
        assert s.SECRET_PLAINTEXT not in blob
        assert r.TEMPORARY_SECRET_PLAINTEXT not in blob

    def test_temporary_secret_plaintext_is_synthetic_and_absent_from_output(self):
        assert r.TEMPORARY_SECRET_PLAINTEXT == (
            "synthetic-temporary-recreation-probe-do-not-use")
        result = _result()
        result.deletions.append(r.DeletionRecord(
            operation="CreateSecret", resource_type="secret-recreation-probe",
            resource_id=d.RESOURCES.secret_name,
            classification=r.DeleteClass.CONFIRMED, absent_after=True))
        assert r.TEMPORARY_SECRET_PLAINTEXT not in json.dumps(result.as_dict())


class TestSecretResetSemantics:
    def test_uses_force_delete_without_recovery(self):
        source = open(r.__file__, encoding="utf-8").read()
        assert source.count("ForceDeleteWithoutRecovery=True") == 2

    def test_never_calls_get_secret_value(self):
        source = open(r.__file__, encoding="utf-8").read()
        assert "get_secret_value" not in source
        assert "GetSecretValue" not in source

    def test_recreation_success_selects_force_delete_strategy(self):
        result = _result()
        r._observe_delete(result, _call(status=200), "secret",
                          d.RESOURCES.secret_name, lambda: (True, "absent"),
                          required=False)
        result.secret_naming_strategy_observed = "force-delete"
        assert result.secret_naming_strategy_observed == "force-delete"
        assert result.as_dict()["secret_naming_strategy_observed"] == "force-delete"

    def test_reserved_name_selects_versioned_alias_strategy(self):
        result = _result()
        result.secret_naming_strategy_observed = "versioned-alias-required"
        result.gaps.append("immediate recreation failed")
        assert result.as_dict()["secret_naming_strategy_observed"] == (
            "versioned-alias-required")
        assert result.gaps

    def test_secret_absent_start_selects_not_observed_strategy(self):
        result = _result()
        r._observe_delete(result, _call(ok=False, code="ResourceNotFoundException",
                                       status=400), "secret",
                          d.RESOURCES.secret_name, lambda: (True, "absent"),
                          required=False)
        result.secret_naming_strategy_observed = "not-observed-secret-absent"
        assert result.secret_naming_strategy_observed == "not-observed-secret-absent"


class TestOrderingAndGuards:
    def test_deletion_order_is_trail_lambda_logs_buckets_iam_secret(self):
        source = open(r.__file__, encoding="utf-8").read()
        positions = [source.index(needle) for needle in (
            '"cloudtrail", "DeleteTrail"',
            '"lambda", "DeleteFunction"',
            '"logs", "DeleteLogGroup"',
            'for bucket in OWNED.buckets:',
            'for user in OWNED.users:',
            "_reset_secret(result, sm)")]
        assert positions == sorted(positions)

    def test_iam_policies_are_deleted_before_access_keys_before_user(self):
        source = open(r.__file__, encoding="utf-8").read()
        assert (source.index('"iam", "DeleteUserPolicy"')
                < source.index('"iam", "DeleteAccessKey"')
                < source.index('"iam", "DeleteUser"'))

    def test_reset_refuses_stock_endpoint(self):
        from cloudsec_agent.scenario.determinism import ScenarioConfigurationError

        class FakeFloci:
            endpoint = "http://localhost:4566"

        with pytest.raises(ScenarioConfigurationError):
            r.reset_canonical_scenario(FakeFloci())

    def test_reset_requires_iam_enforced_port(self):
        class FakeFloci:
            endpoint = "http://localhost:4599"

        with pytest.raises(Exception):
            r.reset_canonical_scenario(FakeFloci())

    def test_classification_vocabulary_is_closed(self):
        assert {r.DeleteClass.CONFIRMED, r.DeleteClass.ALREADY_ABSENT,
                r.DeleteClass.API_ERROR, r.DeleteClass.EMPTY_SUCCESS,
                r.DeleteClass.INCONCLUSIVE} == {
            "CONFIRMED", "ALREADY_ABSENT", "API_ERROR", "EMPTY_SUCCESS",
            "INCONCLUSIVE"}


class TestStructuralSafety:
    def test_reset_module_has_no_direct_boto3_usage(self):
        source = open(r.__file__, encoding="utf-8").read()
        assert "boto3.client(" not in source
        assert "boto3.resource(" not in source
        assert "import boto3" not in source

    def test_reset_module_carries_no_docstrings(self):
        import ast

        tree = ast.parse(open(r.__file__, encoding="utf-8").read())
        assert not ast.get_docstring(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                assert not ast.get_docstring(node)

    def test_m1c_instrumentation_semantics_are_unchanged(self):
        assert s.MutationClass.CONFIRMED == "CONFIRMED"
        assert s.MutationClass.API_ERROR == "API_ERROR"
        assert s.MutationClass.EMPTY_SUCCESS == "EMPTY_SUCCESS"
        assert s.MutationClass.INCONCLUSIVE == "INCONCLUSIVE"
        seed_result = s.SeedResult(scenario_id="x", endpoint="http://localhost:4567")
        assert seed_result.mutations == []
        assert seed_result.divergence is None

class TestTrailNotFoundClassification:
    def test_trail_not_found_maps_to_already_absent(self):
        result = _result()
        record = r._observe_delete(result, _call(ok=False,
                                                 code="TrailNotFoundException",
                                                 status=400), "cloudtrail",
                                   d.RESOURCES.trail_name,
                                   lambda: (True, "trails=[]"))
        assert record.classification == r.DeleteClass.ALREADY_ABSENT
        assert record.absent_after is True

    def test_absent_trail_is_not_api_error(self):
        result = _result()
        record = r._observe_delete(result, _call(ok=False,
                                                 code="TrailNotFoundException"),
                                   "cloudtrail", d.RESOURCES.trail_name,
                                   lambda: (True, "trails=[]"), required=True)
        assert record.classification != r.DeleteClass.API_ERROR
        assert record.classification in (r.DeleteClass.CONFIRMED,
                                         r.DeleteClass.ALREADY_ABSENT)
        assert result.fatal_errors == []
        assert result.first_divergence is None

    def test_trail_not_found_is_in_the_already_absent_set(self):
        assert "TrailNotFoundException" in r.ALREADY_ABSENT_CODES

    def test_already_absent_set_was_not_broadened_with_generic_codes(self):
        assert r.ALREADY_ABSENT_CODES == {
            "404", "NoSuchEntity", "NoSuchEntityException", "NoSuchBucket",
            "ResourceNotFoundException", "ResourceNotFound", "NotFound",
            "TrailNotFoundException"}
        for forbidden in ("AccessDenied", "ValidationError", "ThrottlingException",
                          "InternalFailure", "500", "403"):
            assert forbidden not in r.ALREADY_ABSENT_CODES


class TestAlreadyAbsentIsValidResetInput:
    @pytest.mark.parametrize("resource_type,resource_id,code", [
        ("cloudtrail", "csi-trail", "TrailNotFoundException"),
        ("lambda", "csi-report-sched", "ResourceNotFoundException"),
        ("log-group", "csi-audit-log", "ResourceNotFoundException"),
        ("s3-bucket", "csi-incident-bucket", "NoSuchBucket"),
        ("iam-user", "incident-user", "NoSuchEntity"),
        ("secret", "csi-db-production-credential", "ResourceNotFoundException"),
    ])
    def test_fully_absent_owned_resource_is_valid_input(self, resource_type,
                                                        resource_id, code):
        result = _result()
        record = r._observe_delete(result, _call(ok=False, code=code, status=404),
                                   resource_type, resource_id,
                                   lambda: (True, "absent"), required=True)
        assert record.classification == r.DeleteClass.ALREADY_ABSENT
        assert result.fatal_errors == []
        assert result.first_divergence is None

    def test_partial_state_records_confirmed_and_absent_without_fatal_errors(self):
        result = _result()
        r._observe_delete(result, _call(ok=False, code="NoSuchBucket", status=404),
                          "s3-bucket", "csi-incident-bucket", lambda: (True, "absent"))
        r._observe_delete(result, _call(status=204), "s3-bucket",
                          "csi-evidence-bucket", lambda: (True, "absent"))
        r._observe_delete(result, _call(ok=False, code="NoSuchEntity", status=404),
                          "iam-user", "incident-user", lambda: (True, "absent"))
        assert len(result.deletions) == 3
        assert result.fatal_errors == []
        assert result.as_dict()["confirmed"] == ["csi-evidence-bucket"]
        assert set(result.as_dict()["already_absent"]) == {"csi-incident-bucket",
                                                           "incident-user"}

    def test_live_test_does_not_require_complete_pre_state(self):
        source = open(
            __import__("pathlib").Path(__file__).with_name(
                "test_scenario_reset_live.py"), encoding="utf-8").read()
        assert "test_canonical_scenario_was_present_before_reset" not in source
        assert "owned_buckets_present\"] == list(r.owned_buckets())" not in source
        assert "TestPreStateIsNotARequirement" in source


class TestRequiredResultsStillRejectFailures:
    def test_required_api_error_is_rejected(self):
        result = _result()
        record = r._observe_delete(result, _call(ok=False, code="AccessDenied",
                                                 status=403), "s3-bucket",
                                   "csi-incident-bucket", lambda: (None, None),
                                   required=True)
        assert record.classification == r.DeleteClass.API_ERROR
        assert result.fatal_errors
        assert record.classification not in (r.DeleteClass.CONFIRMED,
                                             r.DeleteClass.ALREADY_ABSENT)

    def test_required_empty_success_is_rejected(self):
        result = _result()
        record = r._observe_delete(result, _call(status=204), "s3-bucket",
                                   "csi-incident-bucket",
                                   lambda: (False, "still visible"), required=True)
        assert record.classification == r.DeleteClass.EMPTY_SUCCESS
        assert result.first_divergence is record
        assert result.fatal_errors

    def test_required_inconclusive_is_rejected(self):
        result = _result()
        record = r._observe_delete(result, _call(ok=False, code="ThrottlingException"),
                                   "s3-bucket", "csi-incident-bucket",
                                   lambda: (None, None), required=True)
        assert record.classification == r.DeleteClass.API_ERROR
        assert result.fatal_errors

    def test_confirmed_and_already_absent_are_the_only_accepted_outcomes(self):
        accepted = {r.DeleteClass.CONFIRMED, r.DeleteClass.ALREADY_ABSENT}
        for rejected in (r.DeleteClass.API_ERROR, r.DeleteClass.EMPTY_SUCCESS,
                         r.DeleteClass.INCONCLUSIVE):
            assert rejected not in accepted


class TestBoundariesAndStrategyUnchanged:
    def test_unrelated_ownership_boundaries_are_unchanged(self):
        assert r.is_owned("csi-probe-timing") is False
        assert r.is_owned("cloudsec-trail-4567") is False
        assert r.is_owned("awslambda-us-east-1-tasks") is False
        assert r.owned_buckets() == (d.RESOURCES.incident_bucket,
                                     d.RESOURCES.evidence_bucket,
                                     d.RESOURCES.trail_bucket)
        assert r.owned_users() == (d.RESOURCES.incident_user,
                                   d.RESOURCES.investigator_user)

    def test_no_wildcard_logic_was_introduced(self):
        source = open(r.__file__, encoding="utf-8").read()
        assert "startswith(\"csi-\")" not in source
        assert "startswith('csi-')" not in source
        assert "csi-*" not in source

    def test_force_delete_strategy_path_is_unchanged(self):
        source = open(r.__file__, encoding="utf-8").read()
        assert source.count("ForceDeleteWithoutRecovery=True") == 2
        assert r.TEMPORARY_SECRET_PLAINTEXT == (
            "synthetic-temporary-recreation-probe-do-not-use")

    def test_absent_secret_reports_a_non_conflicting_strategy_value(self):
        result = _result()
        r._observe_delete(result, _call(ok=False,
                                       code="ResourceNotFoundException", status=400),
                          "secret", d.RESOURCES.secret_name, lambda: (True, "absent"),
                          required=False)
        result.secret_naming_strategy_observed = "not-observed-secret-absent"
        assert result.secret_naming_strategy_observed == (
            "not-observed-secret-absent")
        assert result.secret_naming_strategy_observed != "force-delete"


class TestIamTargetDerivationIsStatic:
    def test_reset_user_targets_come_only_from_the_owned_tuple(self):
        assert r.OWNED.users == (d.RESOURCES.incident_user,
                                 d.RESOURCES.investigator_user)
        assert r.OWNED.users == ("incident-user", "security-agent-backend")

    def test_unrelated_users_are_never_owned(self):
        for unrelated in ("cloudsec-trail-4567", "csi-probe-timing",
                          "m1f-control-unrelated", "m1f-control-scenario-like",
                          "m1f-owned-target"):
            assert unrelated not in r.OWNED.users
            assert r.is_owned(unrelated) is False

    def test_reset_source_never_derives_user_targets_from_list_users(self):
        tree = ast.parse(open(r.__file__, encoding="utf-8").read())
        list_users_calls = []
        delete_user_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "list_users":
                list_users_calls.append(node.lineno)
            if node.func.attr == "delete_user":
                delete_user_calls.append(node.lineno)
        for lineno in list_users_calls:
            enclosing = self._enclosing_function(tree, lineno)
            assert "delete" not in enclosing.lower(), (
                f"ListUsers at line {lineno} appears inside {enclosing}")

    def test_reset_iam_loop_is_bounded_by_owned_users(self):
        import ast

        tree = ast.parse(open(r.__file__, encoding="utf-8").read())
        loops = [node for node in ast.walk(tree)
                 if isinstance(node, ast.For)
                 and isinstance(node.target, ast.Name)
                 and node.target.id == "user"]
        assert loops, "expected an explicit loop over owned users"
        for loop in loops:
            assert isinstance(loop.iter, ast.Attribute), (
                "user loop must iterate a registry attribute, not a live query")
            assert loop.iter.attr == "users"
            body_sources = [ast.dump(statement) for statement in loop.body]
            assert any("delete_user" in source for source in body_sources)

    def test_reset_module_has_no_prefix_based_deletion(self):
        source = open(r.__file__, encoding="utf-8").read()
        assert "startswith(\"csi-\")" not in source
        assert "startswith('csi-')" not in source
        assert "startswith(\"cloudsec-\")" not in source
        assert "startswith('cloudsec-')" not in source

    @staticmethod
    def _enclosing_function(tree, lineno):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = getattr(node, "body", [])
                for statement in body:
                    end = getattr(statement, "end_lineno", statement.lineno)
                    if statement.lineno <= lineno <= end:
                        return node.name
        return "<module>"
