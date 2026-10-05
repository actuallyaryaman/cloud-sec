import ast
import json
import pathlib

import pytest

from cloudsec_agent.backend import approval as ap
from cloudsec_agent.backend import audit as au
from cloudsec_agent.backend import policy as pl
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.backend import request as rq
from cloudsec_agent.backend.audit import audit_resource_ref

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKEND = REPO / "cloudsec_agent/backend"

KEY_A = "AKIAEXAMPLE0000000A"
INCIDENT_ARN = "arn:aws:iam::000000000000:user/incident-user"
SECRET_NAME = "csi-db-production-credential"


def _state(**overrides):
    values = {"attempted": True, "broker_granted": False,
              "policy_allowed": False, "approved": False, "executed": False,
              "effective": False}
    values.update(overrides)
    return au.StageState(**values)


def _record(stage=au.AuditStage.POLICY_DECIDED, state=None,
            requires_approval=True, tool_id=rg.UPDATE_ACCESS_KEY,
            action_digest="d" * 64, canonical_resource=INCIDENT_ARN,
            **overrides):
    try:
        category = rg.get_tool(tool_id).category
    except Exception:
        category = rg.Category.READ_ONLY
    fields = {"audit_id": "audit-1", "request_id": "req-1", "run_id": "run-A",
              "scenario_id": "csi-incident-v1", "tool_id": tool_id,
              "resource_ref": audit_resource_ref(
                  tool_id, category, canonical_resource),
              "action_digest": action_digest,
              "requires_approval": requires_approval, "stage": stage,
              "state": state or _state()}
    fields.update(overrides)
    return au.AuditRecord(**fields)


class TestAuditStageEnum:
    def test_seven_stages_declared(self):
        assert [member.name for member in au.AuditStage] == [
            "REQUEST_VALIDATED", "CANONICALIZED", "BROKER_DECIDED",
            "POLICY_DECIDED", "APPROVAL_DECIDED", "EXECUTION_DECIDED",
            "VERIFICATION_DECIDED"]

    def test_stage_values_are_stable_strings(self):
        assert au.AuditStage.POLICY_DECIDED.value == "policy_decided"


class TestStageStateSixBooleans:
    def test_six_experimental_booleans_are_exact(self):
        assert set(au.StageState.__dataclass_fields__) == {
            "attempted", "broker_granted", "policy_allowed", "approved",
            "executed", "effective"}

    def test_all_defaults_false(self):
        state = au.StageState()
        assert all(value is False for value in state.as_dict().values())

    def test_stage_state_is_immutable(self):
        with pytest.raises(Exception):
            _state().attempted = True


class TestAuditRecordModel:
    def test_audit_record_is_immutable(self):
        with pytest.raises(Exception):
            _record().tool_id = "other"

    def test_audit_record_is_frozen(self):
        assert au.AuditRecord.__dataclass_params__.frozen is True

    def test_audit_record_contains_action_digest(self):
        assert _record(action_digest="a" * 64).as_dict()["action_digest"] == \
            "a" * 64

    def test_audit_record_contains_resource_ref(self):
        assert _record().as_dict()["resource_ref"] == INCIDENT_ARN

    def test_audit_record_does_not_contain_access_key_argument(self):
        blob = json.dumps(_record().as_dict())
        assert KEY_A not in blob

    def test_audit_record_does_not_contain_normalized_arguments(self):
        payload = _record().as_dict()
        assert "normalized_arguments" not in payload
        assert "arguments" not in payload

    def test_audit_record_has_no_credential_or_prose_fields(self):
        names = set(au.AuditRecord.__dataclass_fields__)
        for forbidden in ("SecretAccessKey", "SessionToken", "SecretString",
                          "secret_access_key", "justification", "actor",
                          "prompt", "chain_of_thought", "raw", "response",
                          "normalized_arguments", "arguments"):
            assert forbidden not in names

    def test_audit_record_declares_reason_codes_and_statuses(self):
        payload = _record().as_dict()
        for key in ("broker_reason_code", "policy_reason_code",
                    "approval_reason_code", "execution_status",
                    "verification_status", "rule_id", "timestamp",
                    "requires_approval"):
            assert key in payload

    def test_audit_record_rejects_non_audit_stage(self):
        with pytest.raises(TypeError):
            _record(stage="policy_decided")

    def test_audit_record_rejects_non_stage_state(self):
        with pytest.raises(TypeError):
            _record(state={"attempted": True})

    def test_audit_record_rejects_empty_required_strings(self):
        for name in ("audit_id", "request_id", "run_id", "scenario_id",
                     "tool_id", "action_digest"):
            with pytest.raises(TypeError):
                _record(**{name: ""})
        with pytest.raises(TypeError):
            _record(resource_ref="")


class TestAuditSafetyDenylist:
    @pytest.mark.parametrize("name", [
        "SecretAccessKey", "SessionToken", "SecretString", "SecretBinary",
        "secret_access_key", "aws_secret_access_key", "credential",
        "credentials", "password", "justification", "prompt",
        "chain_of_thought", "reasoning", "normalized_arguments", "arguments",
        "AccessKeyId", "SecretId", "raw", "response", "payload", "body",
        "actor"])
    def test_dangerous_name_rejected(self, name):
        with pytest.raises(au.AuditSafetyError):
            au.require_safe_field_names({name})

    @pytest.mark.parametrize("name", [
        "session_token", "secret_string", "user_secret_id",
        "model_justification", "agent_prompt", "db_password",
        "aws_credentials_blob", "chain_of_thought_notes"])
    def test_dangerous_substring_rejected(self, name):
        with pytest.raises(au.AuditSafetyError):
            au.require_safe_field_names({name})

    @pytest.mark.parametrize("name", [
        "audit_id", "request_id", "run_id", "scenario_id", "tool_id",
        "resource_ref", "action_digest", "broker_reason_code",
        "policy_reason_code", "approval_reason_code", "execution_status",
        "verification_status", "rule_id", "timestamp", "requires_approval",
        "stage"])
    def test_safe_name_accepted(self, name):
        assert au.safe_field_names({name}) == (name,)

    def test_safe_field_names_returns_sorted_tuple(self):
        assert au.safe_field_names({"b", "a"}) == ("a", "b")

    def test_safety_error_names_only_offending_fields(self):
        with pytest.raises(au.AuditSafetyError) as exc:
            au.require_safe_field_names({"audit_id", "SecretAccessKey"})
        assert exc.value.field_names == ("SecretAccessKey",)

    def test_forbidden_names_ignore_non_strings(self):
        au.require_safe_field_names({1, None})

    def test_audit_record_construction_is_safety_checked(self):
        assert au.safe_field_names(
            au.AuditRecord.__dataclass_fields__) == tuple(
            sorted(au.AuditRecord.__dataclass_fields__))

    def test_caller_cannot_smuggle_secret_through_serialized_output(self):
        record = _record()
        blob = json.dumps(record.as_dict())
        for forbidden in ("SecretAccessKey", "SessionToken", "SecretString",
                          "justification", "AKIA", "synthetic-production"):
            assert forbidden not in blob

    def test_serialized_output_has_no_key_id_pattern(self):
        blob = json.dumps(_record().as_dict())
        assert "AKIA" not in blob


class TestAuditTransitionInvariants:
    def test_effective_no_longer_requires_executed(self):
        record = _record(stage=au.AuditStage.VERIFICATION_DECIDED,
                         state=_state(broker_granted=True, policy_allowed=True,
                                      approved=True, executed=False,
                                      effective=True))
        assert record.state.effective is True
        assert record.state.executed is False

    def test_executed_requires_attempted(self):
        with pytest.raises(au.AuditTransitionError):
            _record(state=_state(attempted=False, executed=True))

    def test_executed_requires_policy_allowed(self):
        with pytest.raises(au.AuditTransitionError):
            _record(state=_state(attempted=True, broker_granted=True,
                                 policy_allowed=False, approved=True,
                                 executed=True))

    def test_approval_required_execution_requires_approved(self):
        with pytest.raises(au.AuditTransitionError):
            _record(state=_state(broker_granted=True, policy_allowed=True,
                                 approved=False, executed=True))

    def test_non_approval_tool_may_execute_without_approval(self):
        record = _record(requires_approval=False, tool_id=rg.GET_SECRET_VALUE,
                         state=_state(broker_granted=True, policy_allowed=True,
                                      approved=False, executed=True))
        assert record.state.executed is True
        assert record.state.approved is False

    def test_approved_requires_policy_allowed(self):
        with pytest.raises(au.AuditTransitionError):
            _record(state=_state(broker_granted=True, policy_allowed=False,
                                 approved=True))

    def test_policy_allowed_requires_broker_granted(self):
        with pytest.raises(au.AuditTransitionError):
            _record(state=_state(broker_granted=False, policy_allowed=True))

    def test_broker_granted_requires_attempted(self):
        with pytest.raises(au.AuditTransitionError):
            _record(state=_state(attempted=False, broker_granted=True))

    def test_transition_error_names_stage_and_problem(self):
        with pytest.raises(au.AuditTransitionError) as exc:
            _record(state=_state(broker_granted=True, policy_allowed=True,
                                 approved=False, executed=True))
        assert exc.value.stage is au.AuditStage.POLICY_DECIDED
        assert "executed" in exc.value.problem

    def test_transition_error_is_distinct_from_safety_error(self):
        assert au.AuditTransitionError is not au.AuditSafetyError
        assert issubclass(au.AuditTransitionError, ValueError)
        assert issubclass(au.AuditSafetyError, ValueError)


class TestSixStageIndependence:
    def test_attempted_independent_from_broker_granted(self):
        record = _record(state=_state(attempted=True, broker_granted=False))
        assert record.state.attempted and not record.state.broker_granted

    def test_broker_granted_independent_from_policy_allowed(self):
        record = _record(state=_state(broker_granted=True,
                                      policy_allowed=False))
        assert record.state.broker_granted and not record.state.policy_allowed

    def test_policy_allowed_independent_from_approved(self):
        record = _record(state=_state(broker_granted=True, policy_allowed=True,
                                      approved=False))
        assert record.state.policy_allowed and not record.state.approved

    def test_approved_independent_from_executed(self):
        record = _record(state=_state(broker_granted=True, policy_allowed=True,
                                      approved=True, executed=False))
        assert record.state.approved and not record.state.executed

    def test_executed_independent_from_effective(self):
        record = _record(stage=au.AuditStage.EXECUTION_DECIDED,
                         state=_state(broker_granted=True, policy_allowed=True,
                                      approved=True, executed=True,
                                      effective=False))
        assert record.state.executed and not record.state.effective

    def test_six_booleans_serialise_independently(self):
        payload = _record(state=_state(broker_granted=True,
                                        policy_allowed=True)).as_dict()
        assert payload["attempted"] is True
        assert payload["broker_granted"] is True
        assert payload["policy_allowed"] is True
        assert payload["approved"] is False
        assert payload["executed"] is False
        assert payload["effective"] is False


class TestContainmentStageScenarios:
    def test_broker_denied_containment_audit_valid(self):
        record = _record(stage=au.AuditStage.BROKER_DECIDED,
                         state=_state(attempted=True, broker_granted=False),
                         broker_reason_code="tool_not_granted")
        assert record.state.attempted is True
        assert record.state.broker_granted is False
        assert record.state.policy_allowed is False

    def test_policy_denied_containment_audit_valid(self):
        record = _record(state=_state(attempted=True, broker_granted=True,
                                       policy_allowed=False),
                         broker_reason_code="granted",
                         policy_reason_code="wrong_access_key")
        assert record.state.broker_granted is True
        assert record.state.policy_allowed is False

    def test_approved_not_executed_containment_audit_valid(self):
        record = _record(stage=au.AuditStage.APPROVAL_DECIDED,
                         state=_state(attempted=True, broker_granted=True,
                                      policy_allowed=True, approved=True),
                         approval_reason_code="approved", rule_id="CONTAIN-001")
        assert record.state.approved is True
        assert record.state.executed is False
        assert record.state.effective is False

    def test_executed_not_effective_containment_audit_valid(self):
        record = _record(stage=au.AuditStage.EXECUTION_DECIDED,
                         state=_state(attempted=True, broker_granted=True,
                                      policy_allowed=True, approved=True,
                                      executed=True),
                         execution_status="api_error")
        assert record.state.executed is True
        assert record.state.effective is False

    def test_effective_containment_audit_valid(self):
        record = _record(stage=au.AuditStage.VERIFICATION_DECIDED,
                         state=_state(attempted=True, broker_granted=True,
                                      policy_allowed=True, approved=True,
                                      executed=True, effective=True),
                         execution_status="ok",
                         verification_status="confirmed")
        assert record.state.effective is True

    def test_effective_without_executed_is_valid(self):
        record = _record(stage=au.AuditStage.VERIFICATION_DECIDED,
                         state=_state(attempted=True, broker_granted=True,
                                      policy_allowed=True, approved=True,
                                      executed=False, effective=True))
        assert record.state.effective is True
        assert record.state.executed is False


class TestSecretReadAuditSemantics:
    def test_broad_secret_read_broker_granted_policy_denied(self):
        record = _record(stage=au.AuditStage.POLICY_DECIDED,
                         tool_id=rg.GET_SECRET_VALUE, requires_approval=False,
                         canonical_resource=SECRET_NAME,
                         state=_state(attempted=True, broker_granted=True,
                                      policy_allowed=False),
                         broker_reason_code="granted",
                         policy_reason_code="wrong_tool")
        assert record.state.attempted is True
        assert record.state.broker_granted is True
        assert record.state.policy_allowed is False
        assert record.state.executed is False
        assert record.state.effective is False

    def test_task_scoped_secret_read_broker_denied(self):
        record = _record(stage=au.AuditStage.BROKER_DECIDED,
                         tool_id=rg.GET_SECRET_VALUE, requires_approval=False,
                         canonical_resource=SECRET_NAME,
                         state=_state(attempted=True, broker_granted=False),
                         broker_reason_code="tool_not_granted")
        assert record.state.attempted is True
        assert record.state.broker_granted is False
        assert record.state.policy_allowed is False
        assert record.state.executed is False

    def test_sensitive_read_never_records_a_value(self):
        record = _record(tool_id=rg.GET_SECRET_VALUE,
                         requires_approval=False)
        blob = json.dumps(record.as_dict())
        for forbidden in ("SecretString", "SecretBinary", "SecretAccessKey",
                          "value_returned", "synthetic-production"):
            assert forbidden not in blob

    def test_sensitive_read_record_carries_no_secret_id(self):
        blob = json.dumps(_record(tool_id=rg.GET_SECRET_VALUE,
                                  requires_approval=False).as_dict())
        assert "csi-db-production-credential" not in blob


class TestAuditLogAppendOnly:
    def test_append_preserves_order(self):
        log = au.AuditLog()
        for index in range(5):
            log.append(_record(audit_id=f"audit-{index}",
                               action_digest=f"{index}" * 64))
        assert [item.audit_id for item in log.records()] == [
            f"audit-{index}" for index in range(5)]

    def test_records_returns_immutable_tuple(self):
        log = au.AuditLog()
        log.append(_record())
        assert isinstance(log.records(), tuple)

    def test_records_snapshot_is_not_live(self):
        log = au.AuditLog()
        log.append(_record(audit_id="first"))
        snapshot = log.records()
        log.append(_record(audit_id="second"))
        assert len(snapshot) == 1
        assert len(log.records()) == 2

    def test_records_tuple_cannot_be_mutated(self):
        log = au.AuditLog()
        log.append(_record())
        with pytest.raises(TypeError):
            log.records()[0] = _record(audit_id="other")

    def test_prior_records_cannot_be_mutated(self):
        log = au.AuditLog()
        log.append(_record())
        with pytest.raises(Exception):
            log.records()[0].tool_id = "tampered"

    def test_log_rejects_non_audit_record(self):
        with pytest.raises(TypeError):
            au.AuditLog().append({"tool_id": "t"})

    def test_log_has_no_delete_replace_update_or_clear(self):
        log = au.AuditLog()
        for absent in ("delete", "replace", "update", "clear", "pop",
                       "remove", "extend", "insert"):
            assert not hasattr(log, absent), absent

    def test_log_exposes_only_append_and_reads(self):
        public = {name for name in dir(au.AuditLog)
                  if not name.startswith("_")}
        assert public == {"append", "records", "by_request"}

    def test_by_request_filters_correctly(self):
        log = au.AuditLog()
        log.append(_record(request_id="r1", audit_id="a"))
        log.append(_record(request_id="r2", audit_id="b"))
        log.append(_record(request_id="r1", audit_id="c"))
        assert [item.audit_id for item in log.by_request("r1")] == ["a", "c"]
        assert log.by_request("r-missing") == ()

    def test_log_length_and_iteration(self):
        log = au.AuditLog()
        assert len(log) == 0
        log.append(_record())
        assert len(log) == 1
        assert [item.audit_id for item in log] == ["audit-1"]

    def test_log_repr_does_not_leak_fields(self):
        log = au.AuditLog()
        log.append(_record())
        assert repr(log) == "AuditLog(records=1)"

    def test_log_persists_nothing_to_disk(self):
        source = (BACKEND / "audit.py").read_text()
        for forbidden in ("open(", "jsonl", "write", "dump", "tempfile"):
            assert forbidden not in source, forbidden


class TestAuditIsObservationalOnly:
    def test_audit_record_cannot_be_used_as_policy_decision(self):
        with pytest.raises(TypeError):
            ap.evaluate_approval_stage(
                rq.CanonicalAction(rg.UPDATE_ACCESS_KEY, "iam:UpdateAccessKey",
                                   INCIDENT_ARN, {"UserName": "incident-user",
                                                  "AccessKeyId": KEY_A,
                                                  "Status": "Inactive"}),
                "d" * 64, _record(), _provider_stub(), 1)

    def test_policy_decision_cannot_be_built_from_audit_record(self):
        with pytest.raises(TypeError):
            pl.PolicyDecision(allowed=True, evaluated_action_digest="d",
                              rule_id="CONTAIN-001",
                              reason_code=au.AuditStage.POLICY_DECIDED)

    def test_audit_module_defines_no_authorization_entrypoint(self):
        source = (BACKEND / "audit.py").read_text()
        for absent in ("def allow", "def authorize", "def decide", "def permit",
                       "def approve", "def execute", "def evaluate"):
            assert absent not in source

    def test_constructing_an_all_true_audit_record_grants_nothing(self):
        record = _record(stage=au.AuditStage.VERIFICATION_DECIDED,
                         state=_state(attempted=True, broker_granted=True,
                                      policy_allowed=True, approved=True,
                                      executed=True, effective=True))
        assert record.state.effective is True
        assert not isinstance(record, pl.PolicyDecision)
        assert not isinstance(record, ap.ApprovalDecision)

    def test_audit_record_exposes_no_decision_consuming_method(self):
        tree = ast.parse((BACKEND / "audit.py").read_text())
        target = next(node for node in tree.body
                      if isinstance(node, ast.ClassDef)
                      and node.name == "AuditRecord")
        methods = {node.name for node in target.body
                   if isinstance(node, ast.FunctionDef)}
        assert methods == {"__post_init__", "as_dict"}


def _provider_stub():
    return ap.FakeApprovalProvider()


class TestSecretReadMetricNamesRemainAvailable:
    def test_request_module_still_declares_four_outcomes(self):
        assert rq.SECRET_READ_OUTCOMES == (
            "requested", "authorized", "executed", "value_returned")

    def test_audit_stage_state_covers_executed_and_effective(self):
        payload = au.StageState(executed=True, effective=True).as_dict()
        assert payload["executed"] is True
        assert payload["effective"] is True

    def test_audit_does_not_implement_secret_counters(self):
        source = (BACKEND / "audit.py").read_text()
        assert "secret_read_requested" not in source
        assert "secret_value_returned" not in source
class TestResourceRefFingerprint:
    RAW_SECRET = "csi-db-production-credential"

    def test_same_tool_resource_deterministic(self):
        a = au.audit_resource_ref(rg.GET_SECRET_VALUE,
                                  rg.Category.SENSITIVE_READ, self.RAW_SECRET)
        b = au.audit_resource_ref(rg.GET_SECRET_VALUE,
                                  rg.Category.SENSITIVE_READ, self.RAW_SECRET)
        assert a == b

    def test_different_resource_different_ref(self):
        a = au.audit_resource_ref(rg.GET_SECRET_VALUE,
                                  rg.Category.SENSITIVE_READ, self.RAW_SECRET)
        b = au.audit_resource_ref(rg.GET_SECRET_VALUE,
                                  rg.Category.SENSITIVE_READ,
                                  "other-production-credential")
        assert a != b

    def test_same_resource_different_tool_different_ref(self):
        a = au.audit_resource_ref("get_secret_value",
                                  rg.Category.SENSITIVE_READ, self.RAW_SECRET)
        b = au.audit_resource_ref("another_secret_tool",
                                  rg.Category.SENSITIVE_READ, self.RAW_SECRET)
        assert a != b

    def test_fingerprint_has_expected_shape(self):
        ref = au.audit_resource_ref(rg.GET_SECRET_VALUE,
                                    rg.Category.SENSITIVE_READ, self.RAW_SECRET)
        assert ref.startswith("sensitive:sha256:")
        digest = ref.split(":", 2)[2]
        assert len(digest) == 64
        assert digest == digest.lower()
        assert all(ch in "0123456789abcdef" for ch in digest)

    def test_fingerprint_uses_declared_domain_prefix(self):
        source = (BACKEND / "audit.py").read_text()
        assert "cloudsec-audit-resource-v1" in source

    def test_no_raw_resource_in_fingerprint(self):
        ref = au.audit_resource_ref(rg.GET_SECRET_VALUE,
                                    rg.Category.SENSITIVE_READ, self.RAW_SECRET)
        assert self.RAW_SECRET not in ref

    def test_non_sensitive_resource_remains_canonical(self):
        ref = au.audit_resource_ref(rg.UPDATE_ACCESS_KEY,
                                    rg.Category.STATE_CHANGING, INCIDENT_ARN)
        assert ref == INCIDENT_ARN

    def test_audit_record_for_sensitive_tool_stores_fingerprint(self):
        record = _record(tool_id=rg.GET_SECRET_VALUE, requires_approval=False,
                         canonical_resource=self.RAW_SECRET,
                         state=_state(attempted=True, broker_granted=True,
                                      policy_allowed=False))
        assert record.resource_ref.startswith("sensitive:sha256:")
        assert self.RAW_SECRET not in json.dumps(record.as_dict())

    def test_audit_record_for_state_changing_keeps_canonical_resource(self):
        record = _record()
        assert record.resource_ref == INCIDENT_ARN

    def test_serialized_audit_contains_tool_id_and_digest(self):
        record = _record()
        blob = json.dumps(record.as_dict())
        assert rg.UPDATE_ACCESS_KEY in blob
        assert '"action_digest"' in blob

    def test_audit_record_field_is_resource_ref_not_canonical_resource(self):
        assert "resource_ref" in au.AuditRecord.__dataclass_fields__
        assert "canonical_resource" not in au.AuditRecord.__dataclass_fields__
