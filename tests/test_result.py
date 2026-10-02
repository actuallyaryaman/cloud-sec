import json

import pytest

from cloudsec_agent.redaction import clear_secrets, redact, register_secret
from cloudsec_agent.result import (AuthorizationMatrix, CallOutcome,
                                  aggregate_values, classify_enforcement,
                                  normalize_enforcement)

FIELDS = ["identity_allow_observed", "implicit_deny_observed",
          "explicit_deny_observed", "resource_scoping_observed",
          "sts_trust_enforcement_observed", "sts_role_restrictions_observed",
          "unresolved_action_behavior"]


class FakeClientError(Exception):
    def __init__(self, code, status):
        super().__init__(f"{code} ({status})")
        self.response = {
            "Error": {"Code": code, "Message": "denied"},
            "ResponseMetadata": {"HTTPStatusCode": status, "RequestId": "req-123"},
        }


def _outcome(ok=True, code=None, status=None):
    def call(client):
        if not ok:
            raise FakeClientError(code, status)
        return {"Arn": "arn:aws:s3:::bucket"}
    return CallOutcome.capture("s3", "GetObject", call, object())


class TestClassifyEnforcement:
    def test_allow_expected_and_observed_is_true(self):
        assert classify_enforcement("allow", True, True) is True

    def test_deny_expected_and_blocked_is_true(self):
        assert classify_enforcement("deny", False, True) is True

    def test_deny_expected_but_call_succeeded_is_false(self):
        assert classify_enforcement("deny", True, True) is False

    def test_allow_expected_but_call_was_denied_is_false(self):
        assert classify_enforcement("allow", False, True) is False

    def test_inconclusive_call_is_null(self):
        assert classify_enforcement("deny", None, True) is None

    def test_unconfirmed_policy_is_never_false(self):
        assert classify_enforcement("deny", True, False) is None
        assert classify_enforcement("deny", True, None) is None

    def test_unsupported_operation_yields_null(self):
        assert classify_enforcement("allow", None, None) is None


class TestAggregate:
    def test_all_true_is_true(self):
        assert aggregate_values([True, True]) is True

    def test_any_false_is_false(self):
        assert aggregate_values([True, False]) is False

    def test_mixed_true_and_null_is_null(self):
        assert aggregate_values([True, None]) is None

    def test_all_null_is_null(self):
        assert aggregate_values([None, None]) is None

    def test_empty_is_null(self):
        assert aggregate_values([]) is None


class TestNormalizeEnforcement:
    def test_every_field_present_and_tri_state(self):
        out = normalize_enforcement({"identity_allow_observed": True})
        assert sorted(out) == sorted(FIELDS)
        for value in out.values():
            assert value is None or isinstance(value, bool)

    def test_missing_fields_become_null(self):
        assert normalize_enforcement({})["explicit_deny_observed"] is None


class TestCallOutcome:
    def test_success_records_request_id(self):
        outcome = _outcome(ok=True)
        assert outcome.ok is True
        assert outcome.result_summary["Arn"] == "arn:aws:s3:::bucket"

    def test_failure_records_status_code_and_request_id(self):
        outcome = _outcome(ok=False, code="AccessDenied", status=403)
        assert outcome.ok is False
        assert outcome.error_code == "AccessDenied"
        assert outcome.status == 403
        assert outcome.request_id == "req-123"
        assert outcome.denied is True

    def test_connection_failure_has_no_error_code_and_is_not_a_denial(self):
        outcome = CallOutcome.capture("s3", "GetObject",
                                      lambda c: (_ for _ in ()).throw(
                                          ConnectionError("down")), object())
        assert outcome.ok is False
        assert outcome.error_code is None
        assert outcome.denied is False

    def test_raw_payload_available_for_policy_verification(self):
        def call(client):
            return {"PolicyDocument": {"Statement": []}}
        outcome = CallOutcome.capture("iam", "GetUserPolicy", call, object())
        assert outcome.raw["PolicyDocument"] == {"Statement": []}


class TestAuthorizationMatrix:
    def test_record_captures_every_required_field(self):
        matrix = AuthorizationMatrix()
        case = matrix.record("A", "s3:GetObject", "s3", "iam-user", "arn:user/x",
                             "arn:aws:s3:::b/*", "allow",
                             _outcome(ok=False, code="AccessDenied", status=403),
                             state_changed=False, policy_confirmed=True,
                             signals=["identity_allow"])
        for field in ("label", "operation", "principal_type", "principal",
                      "target_resource", "expected_aws_outcome", "actual_allowed",
                      "http_status", "exception", "error_code", "request_id",
                      "state_changed", "policy_confirmed", "classification"):
            assert field in case
        assert case["classification"] is False
        assert case["actual_allowed"] is False

    def test_aggregate_uses_signal_names(self):
        matrix = AuthorizationMatrix()
        matrix.record("A", "op", "s3", "p", "a", "r", "allow", _outcome(True),
                      policy_confirmed=True, signals=["identity_allow"])
        assert matrix.aggregate()["identity_allow"] is True

    def test_serialization_round_trips_through_json(self):
        matrix = AuthorizationMatrix()
        matrix.record("C", "s3:GetObject", "s3", "iam-user", "arn:user/x",
                      "arn:aws:s3:::b/*", "deny",
                      _outcome(ok=False, code="AccessDenied", status=403),
                      state_changed=True, policy_confirmed=True,
                      signals=["explicit_deny"])
        payload = json.loads(json.dumps(matrix.to_dict()))
        assert payload["cases"][0]["classification"] is True
        assert payload["cases"][0]["error_code"] == "AccessDenied"


class TestRedaction:
    def setup_method(self):
        clear_secrets()

    def teardown_method(self):
        clear_secrets()

    @pytest.mark.parametrize("key", [
        "AKIAIOSFODNN7EXAMPLE",
        "ASIAIOSFODNN7EXAMPLE",
        "AKIA1234567890ABCDEF",
    ])
    def test_access_keys_are_redacted(self, key):
        assert key not in redact(f"credential={key} rest")
        assert "[REDACTED-AKID]" in redact(key)

    def test_session_tokens_are_redacted(self):
        token = "FQoGZXIvYXdzEXAMPLESESSIONTOKENVALUE"
        out = redact(json.dumps({"SessionToken": token}))
        assert token not in out
        assert "[REDACTED]" in out

    def test_registered_secret_values_are_redacted_anywhere(self):
        register_secret("cloudsec-synthetic-secret-value-abc123")
        payload = {
            "body": "cloudsec-synthetic-secret-value-abc123",
            "nested": ["cloudsec-synthetic-secret-value-abc123"],
        }
        out = redact(payload)
        assert "cloudsec-synthetic-secret-value-abc123" not in json.dumps(out)
        assert out["nested"] == ["[REDACTED]"]

    def test_registered_keys_redacted_in_dict_keys(self):
        register_secret("cloudsec-synthetic-secret-value-abc123")
        out = redact({"cloudsec-synthetic-secret-value-abc123": "v"})
        assert "cloudsec-synthetic-secret-value-abc123" not in json.dumps(out)

    def test_short_values_are_not_registered(self):
        register_secret("abc")
        assert redact("abc") == "abc"

    def test_report_shape_serialises_to_tri_state_nulls(self):
        report = {
            "probe_version": 1,
            "endpoint": "http://localhost:4566",
            "floci": {"version": "2.1.0", "edition": "community"},
            "services": {"s3": {"available": True, "operations": {},
                                "authorization": {}, "gaps": []}},
            "iam_enforcement": normalize_enforcement({}),
            "important_gaps": [],
        }
        payload = json.loads(json.dumps(redact(report)))
        assert payload["iam_enforcement"] == {field: None for field in FIELDS}
        assert payload["services"]["s3"]["gaps"] == []