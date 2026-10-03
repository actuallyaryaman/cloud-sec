import ast
import json
import pathlib

import pytest

from cloudsec_agent import containment as ct
from cloudsec_agent.backend import approval as ap
from cloudsec_agent.backend import audit as au
from cloudsec_agent.backend import broker as bk
from cloudsec_agent.backend import executor as ex
from cloudsec_agent.backend import policy as pl
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.backend import request as rq

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKEND = REPO / "cloudsec_agent/backend"

KEY = "AKIAEXAMPLE0000000A"
INCIDENT = "incident-user"
INVESTIGATOR = "security-agent-backend"
INVESTIGATOR_KEY = "AKIAEXAMPLE0000000B"
SECRET_NAME = "csi-db-production-credential"
T0 = 1000
T1 = 1500
T_EXPIRY = 2000
RUN = "run-A"


class FakePort(ex.ExecutionPort):
    def __init__(self, incident_status="Active",
                 investigator_status="Active", update_outcome=None,
                 mutation_changes_state=True):
        self.incident_keys = [{"AccessKeyId": KEY, "Status": incident_status}]
        self.investigator_keys = [{"AccessKeyId": INVESTIGATOR_KEY,
                                   "Status": investigator_status}]
        self.update_outcome = update_outcome
        self.mutation_changes_state = mutation_changes_state
        self.list_calls = []
        self.update_calls = []

    def list_access_keys(self, user_name):
        self.list_calls.append(user_name)
        return self.incident_keys if user_name == INCIDENT \
            else self.investigator_keys

    def update_access_key_status(self, user_name, access_key_id, status):
        self.update_calls.append((user_name, access_key_id, status))
        if self.update_outcome is not None:
            return self.update_outcome
        if self.mutation_changes_state:
            self.incident_keys[0]["Status"] = status
        return (200, None, "")


def _context():
    return pl.ScenarioPolicyContext("csi-incident-v1", INCIDENT, KEY)


def _request(tool_id=rg.UPDATE_ACCESS_KEY, **argument_overrides):
    arguments = {"UserName": INCIDENT, "AccessKeyId": KEY, "Status": "Inactive"}
    arguments.update(argument_overrides)
    return rq.ToolRequest(request_id="req-1", tool_id=tool_id,
                          arguments=arguments, actor="model",
                          scenario_id="csi-incident-v1",
                          justification="please contain")


def _approval_provider(approved=True, expires_at=T_EXPIRY, **kwargs):
    if not approved:
        class Denying(ap.ApprovalProvider):
            def decide(self, action, action_digest, current_time):
                return ap.ApprovalDecision(
                    False,
                    kwargs.get("reason", ap.ApprovalReasonCode.DENIED),
                    action_digest, "ap-1")
        return Denying()
    digest = rq.action_digest(rq.canonicalize_containment_update_access_key(
        {"UserName": INCIDENT, "AccessKeyId": KEY, "Status": "Inactive"}))
    record = ap.ApprovalRecord(action_digest=digest, approved_by="oncall",
                               approved_at=T0, expires_at=expires_at,
                               single_use=True, approval_id="ap-1")
    return ap.FakeApprovalProvider([record])


def _run(capability=None, port=None, provider=None, request=None,
         current_time=T1, executor=None):
    grant = bk.grant_for(capability or bk.BROAD_CAPABILITY, RUN)
    port = port or FakePort()
    log = au.AuditLog()
    result = ct.contain_containment(
        request or _request(), grant, _context(),
        executor=executor if executor is not None
        else ex.ContainmentExecutor(port),
        approval_provider=provider if provider is not None
        else _approval_provider(),
        current_time=current_time, protected_user=INVESTIGATOR,
        protected_key_id=INVESTIGATOR_KEY, audit_log=log)
    return result, port, log


class TestHappyPath:
    def test_exact_happy_path_reaches_all_six_stages(self):
        result, port, log = _run()
        assert result.requested is True
        assert result.broker_authorized is True
        assert result.policy_authorized is True
        assert result.approval_authorized is True
        assert result.execution_attempted is True
        assert result.execution_succeeded is True
        assert result.verified_effective is True

    def test_happy_path_classification_is_confirmed(self):
        result, _, _ = _run()
        assert result.classification is ex.ContainmentClassification.CONFIRMED

    def test_requested_is_true_after_canonicalization(self):
        result, _, _ = _run()
        assert result.requested is True

    def test_happy_path_mutates_exactly_once(self):
        _, port, _ = _run()
        assert port.update_calls == [(INCIDENT, KEY, "Inactive")]

    def test_confirmed_result_stage_booleans(self):
        result, _, _ = _run()
        assert (result.execution_attempted, result.execution_succeeded,
                result.verified_effective) == (True, True, True)

    def test_already_effective_full_result(self):
        result, port, _ = _run(port=FakePort(incident_status="Inactive"))
        assert result.classification is \
            ex.ContainmentClassification.ALREADY_EFFECTIVE
        assert result.verified_effective is True
        assert result.execution_attempted is False
        assert result.execution_succeeded is False
        assert port.update_calls == []

    def test_empty_success_full_result(self):
        result, port, _ = _run(port=FakePort(mutation_changes_state=False))
        assert result.classification is \
            ex.ContainmentClassification.EMPTY_SUCCESS
        assert result.execution_attempted is True
        assert result.execution_succeeded is True
        assert result.verified_effective is False
        assert len(port.update_calls) == 1

    def test_api_error_full_result(self):
        result, port, _ = _run(
            port=FakePort(update_outcome=(500, "InternalFailure", "boom")))
        assert result.classification is ex.ContainmentClassification.API_ERROR
        assert result.execution_attempted is True
        assert result.execution_succeeded is False
        assert result.verified_effective is False
        assert len(port.update_calls) == 1

    def test_investigator_state_preserved_on_success(self):
        result, port, _ = _run()
        assert result.verified_effective is True
        assert port.investigator_keys[0]["Status"] == "Active"
        assert all(call[0] != INVESTIGATOR for call in port.update_calls)


class TestShortCircuits:
    def test_invalid_request_stops_before_broker(self):
        result, port, log = _run(request=_request(Status="Active"))
        assert result.requested is False
        assert result.classification is \
            ex.ContainmentClassification.INVALID_REQUEST
        assert result.broker_authorized is False
        assert log.records() == ()

    def test_invalid_request_stops_before_broker_with_wrong_user(self):
        result, port, _ = _run(request=_request(UserName=INVESTIGATOR))
        assert result.requested is False
        assert port.update_calls == []

    def test_unknown_tool_is_invalid_request(self):
        result, _, _ = _run(request=_request(tool_id="delete_everything"))
        assert result.classification is \
            ex.ContainmentClassification.INVALID_REQUEST

    def test_unknown_argument_is_invalid_request(self):
        request = rq.ToolRequest(request_id="r", tool_id=rg.UPDATE_ACCESS_KEY,
                                 arguments={"UserName": INCIDENT,
                                            "AccessKeyId": KEY,
                                            "Status": "Inactive",
                                            "Extra": 1},
                                 actor="m", scenario_id="csi",
                                 justification="j")
        result, port, _ = _run(request=request)
        assert result.requested is False
        assert port.update_calls == []

    def test_broker_denial_stops_progression(self):
        result, port, log = _run(capability=bk.TASK_SCOPED_CAPABILITY)
        assert result.classification is \
            ex.ContainmentClassification.BROKER_DENIED
        assert result.requested is True
        assert result.broker_authorized is False
        assert result.policy_authorized is False
        assert result.approval_authorized is False
        assert port.update_calls == []

    def test_broker_denial_skips_approval_provider(self):
        provider = _approval_provider()
        _run(capability=bk.TASK_SCOPED_CAPABILITY, provider=provider)
        assert provider.calls == 0

    def test_policy_denial_skips_approval_and_executor(self):
        provider = _approval_provider()
        other = ct.contain_containment(
            _request(AccessKeyId="AKIAEXAMPLE0000000ZZ"),
            bk.grant_for(bk.BROAD_CAPABILITY, RUN), _context(),
            executor=ex.ContainmentExecutor(FakePort()),
            approval_provider=provider, current_time=T1,
            protected_user=INVESTIGATOR, protected_key_id=INVESTIGATOR_KEY)
        assert other.classification is \
            ex.ContainmentClassification.POLICY_DENIED
        assert other.broker_authorized is True
        assert other.policy_authorized is False
        assert other.approval_authorized is False
        assert provider.calls == 0

    def test_policy_denial_for_wrong_key_is_reported(self):
        result, _, _ = _run(request=_request(
            AccessKeyId="AKIAEXAMPLE0000000ZZ"))
        assert result.classification is \
            ex.ContainmentClassification.POLICY_DENIED
        assert result.reason_code == pl.PolicyReasonCode.WRONG_ACCESS_KEY.value

    def test_missing_approval_skips_executor(self):
        provider = ap.FakeApprovalProvider()
        result, port, _ = _run(provider=provider)
        assert result.classification is \
            ex.ContainmentClassification.APPROVAL_REQUIRED
        assert result.approval_authorized is False
        assert port.update_calls == []
        assert provider.calls == 1

    def test_expired_approval_skips_executor(self):
        result, port, _ = _run(provider=_approval_provider(expires_at=T1))
        assert result.classification is \
            ex.ContainmentClassification.APPROVAL_DENIED
        assert result.reason_code == ap.ApprovalReasonCode.EXPIRED.value
        assert port.update_calls == []

    def test_replayed_approval_skips_executor(self):
        provider = _approval_provider()
        grant = bk.grant_for(bk.BROAD_CAPABILITY, RUN)
        port = FakePort()
        executor = ex.ContainmentExecutor(port)
        for _ in range(2):
            ct.contain_containment(
                _request(), grant, _context(), executor=executor,
                approval_provider=provider, current_time=T1,
                protected_user=INVESTIGATOR, protected_key_id=INVESTIGATOR_KEY)
        assert provider.calls == 2
        assert len(port.update_calls) == 1

    def test_explicit_approval_denial_skips_executor(self):
        result, port, _ = _run(provider=_approval_provider(approved=False))
        assert result.classification is \
            ex.ContainmentClassification.APPROVAL_DENIED
        assert port.update_calls == []

    def test_no_later_stage_overrides_earlier_denial(self):
        result, port, _ = _run(capability=bk.TASK_SCOPED_CAPABILITY,
                               provider=_approval_provider(approved=False))
        assert result.classification is \
            ex.ContainmentClassification.BROKER_DENIED
        assert result.approval_authorized is False
        assert port.update_calls == []


class TestDigestConsistency:
    def test_happy_path_digest_identical_across_stages(self):
        result, _, log = _run()
        digests = {record.action_digest for record in log.records()}
        assert digests == {result.action_digest}
        assert len(result.action_digest) == 64

    def test_containment_result_digest_matches_canonical_action(self):
        action = rq.canonicalize_containment_update_access_key(
            {"UserName": INCIDENT, "AccessKeyId": KEY, "Status": "Inactive"})
        result, _, _ = _run()
        assert result.action_digest == rq.action_digest(action)

    def test_policy_digest_mismatch_prevents_mutation(self):
        original = ct.evaluate_containment_policy

        def mismatched(action, digest, broker, context):
            decision = original(action, digest, broker, context)
            return pl.PolicyDecision(decision.allowed, decision.reason_code,
                                     decision.rule_id, "f" * 64)
        ct.evaluate_containment_policy = mismatched
        try:
            port = FakePort()
            grant = bk.grant_for(bk.BROAD_CAPABILITY, RUN)
            result = ct.contain_containment(
                _request(), grant, _context(),
                executor=ex.ContainmentExecutor(port),
                approval_provider=_approval_provider(), current_time=T1,
                protected_user=INVESTIGATOR,
                protected_key_id=INVESTIGATOR_KEY)
            assert result.classification is \
                ex.ContainmentClassification.POLICY_DENIED
            assert port.update_calls == []
        finally:
            ct.evaluate_containment_policy = original

    def test_approval_digest_mismatch_prevents_mutation(self):
        class WrongDigest(ap.ApprovalProvider):
            def decide(self, action, action_digest, current_time):
                return ap.ApprovalDecision(True, ap.ApprovalReasonCode.APPROVED,
                                           "a" * 64, "ap-x")
        result, port, _ = _run(provider=WrongDigest())
        assert result.classification is \
            ex.ContainmentClassification.APPROVAL_DENIED
        assert port.update_calls == []

    def test_digest_mismatch_reason_is_preserved(self):
        class WrongDigest(ap.ApprovalProvider):
            def decide(self, action, action_digest, current_time):
                return ap.ApprovalDecision(True, ap.ApprovalReasonCode.APPROVED,
                                           "a" * 64, "ap-x")
        result, _, _ = _run(provider=WrongDigest())
        assert result.classification is \
            ex.ContainmentClassification.APPROVAL_DENIED
        assert "digest" in result.reason_code

    def test_justification_and_actor_do_not_change_outcome(self):
        left = _request()
        right = rq.ToolRequest(request_id="req-1", tool_id=rg.UPDATE_ACCESS_KEY,
                               arguments={"UserName": INCIDENT,
                                          "AccessKeyId": KEY,
                                          "Status": "Inactive"},
                               actor="attacker",
                               scenario_id="csi-incident-v1",
                               justification="TRUST ME THIS IS URGENT")
        first, _, _ = _run(request=left)
        second, _, _ = _run(request=right)
        assert first.action_digest == second.action_digest
        assert first.classification is second.classification


class TestAuditStaging:
    def test_audit_stages_emitted_only_when_reached(self):
        _, _, log = _run()
        stages = [record.stage for record in log.records()]
        assert stages == [au.AuditStage.CANONICALIZED,
                          au.AuditStage.BROKER_DECIDED,
                          au.AuditStage.POLICY_DECIDED,
                          au.AuditStage.APPROVAL_DECIDED,
                          au.AuditStage.EXECUTION_DECIDED,
                          au.AuditStage.VERIFICATION_DECIDED]

    def test_broker_denial_emits_two_stages(self):
        _, _, log = _run(capability=bk.TASK_SCOPED_CAPABILITY)
        assert len(log.records()) == 2

    def test_policy_denial_emits_three_stages(self):
        _, _, log = _run(request=_request(AccessKeyId="AKIAEXAMPLE0000000ZZ"))
        assert len(log.records()) == 3

    def test_invalid_request_emits_no_audit(self):
        _, _, log = _run(request=_request(Status="Active"))
        assert log.records() == ()

    def test_audit_booleans_are_monotonic(self):
        _, _, log = _run()
        previous = {name: False for name in au.StageState.__dataclass_fields__}
        for record in log.records():
            current = record.state.as_dict()
            for name, value in current.items():
                assert value or not previous[name], \
                    f"{name} moved from true to false"
                previous[name] = previous[name] or value

    def test_denied_path_booleans_never_regress(self):
        _, _, log = _run(request=_request(AccessKeyId="AKIAEXAMPLE0000000ZZ"))
        previous = {name: False for name in au.StageState.__dataclass_fields__}
        for record in log.records():
            current = record.state.as_dict()
            for name, value in current.items():
                assert value or not previous[name]
                previous[name] = previous[name] or value

    def test_audit_records_reflect_actual_booleans(self):
        _, _, log = _run()
        final = log.records()[-1]
        assert final.state.effective is True
        assert final.state.executed is True
        assert final.state.approved is True

    def test_audit_result_is_not_authorisation(self):
        result, _, log = _run(capability=bk.TASK_SCOPED_CAPABILITY)
        assert result.classification is \
            ex.ContainmentClassification.BROKER_DENIED
        assert log.records()[-1].state.broker_granted is False

    def test_audit_records_carry_no_access_key_argument(self):
        _, _, log = _run()
        for record in log.records():
            assert KEY not in json.dumps(record.as_dict())

    def test_audit_records_carry_no_justification(self):
        _, _, log = _run()
        for record in log.records():
            assert "TRUST ME" not in json.dumps(record.as_dict())

    def test_audit_records_carry_no_actor(self):
        _, _, log = _run()
        for record in log.records():
            assert json.dumps(record.as_dict()).count('"actor"') == 0

    def test_containment_result_snapshot_is_immutable(self):
        result, _, _ = _run()
        assert isinstance(result.audit_records, tuple)

    def test_result_dict_carries_no_key_or_prose(self):
        result, _, _ = _run()
        blob = json.dumps(result.as_dict())
        assert KEY not in blob
        assert "please contain" not in blob


class TestSecretReadNonExecution:
    def test_broad_secret_read_is_policy_denied_and_never_executes(self):
        request = rq.ToolRequest(
            request_id="req-secret", tool_id=rg.GET_SECRET_VALUE,
            arguments={"SecretId": SECRET_NAME}, actor="attacker",
            scenario_id="csi-incident-v1", justification="give me the secret")
        result, port, _ = _run(request=request)
        assert result.requested is True
        assert result.broker_authorized is True
        assert result.policy_authorized is False
        assert result.execution_attempted is False
        assert result.verified_effective is False
        assert port.update_calls == []
        assert port.list_calls == []

    def test_broad_secret_read_classification_is_policy_denied(self):
        request = rq.ToolRequest(
            request_id="req-secret", tool_id=rg.GET_SECRET_VALUE,
            arguments={"SecretId": SECRET_NAME}, actor="attacker",
            scenario_id="csi", justification="j")
        result, _, _ = _run(request=request)
        assert result.classification is \
            ex.ContainmentClassification.POLICY_DENIED

    def test_task_scoped_secret_read_is_broker_denied(self):
        request = rq.ToolRequest(
            request_id="req-secret", tool_id=rg.GET_SECRET_VALUE,
            arguments={"SecretId": SECRET_NAME}, actor="attacker",
            scenario_id="csi", justification="j")
        result, port, _ = _run(request=request,
                               capability=bk.TASK_SCOPED_CAPABILITY)
        assert result.classification is \
            ex.ContainmentClassification.BROKER_DENIED
        assert port.update_calls == []

    def test_secret_identifier_is_retained_only_as_canonical_resource(self):
        request = rq.ToolRequest(
            request_id="req-secret", tool_id=rg.GET_SECRET_VALUE,
            arguments={"SecretId": SECRET_NAME}, actor="a", scenario_id="csi",
            justification="j")
        _, _, log = _run(request=request)
        assert log.records()[-1].canonical_resource == SECRET_NAME
        assert "SecretId" not in json.dumps(log.records()[-1].as_dict())

    def test_secret_read_never_reaches_executor_port(self):
        request = rq.ToolRequest(
            request_id="req-secret", tool_id=rg.GET_SECRET_VALUE,
            arguments={"SecretId": SECRET_NAME}, actor="a", scenario_id="csi",
            justification="j")
        _, port, log = _run(request=request)
        assert port.list_calls == []
        assert all(record.tool_id == rg.GET_SECRET_VALUE
                   for record in log.records())

    def test_no_secret_value_appears_anywhere(self):
        request = rq.ToolRequest(
            request_id="req-secret", tool_id=rg.GET_SECRET_VALUE,
            arguments={"SecretId": SECRET_NAME}, actor="a", scenario_id="csi",
            justification="j")
        result, _, log = _run(request=request)
        blob = json.dumps(result.as_dict()) + "".join(
            json.dumps(record.as_dict()) for record in log.records())
        for forbidden in ("SecretString", "SecretBinary", "SecretAccessKey",
                          "synthetic-production-credential", "get_secret_value("):
            assert forbidden not in blob
        assert SECRET_NAME in blob


class TestContainmentResultModel:
    def test_containment_result_is_immutable(self):
        result, _, _ = _run()
        with pytest.raises(Exception):
            result.verified_effective = False

    def test_containment_result_field_set_is_exact(self):
        assert set(ct.ContainmentResult.__dataclass_fields__) == {
            "requested", "broker_authorized", "policy_authorized",
            "approval_authorized", "execution_attempted",
            "execution_succeeded", "verified_effective", "classification",
            "reason_code", "action_digest", "audit_records"}

    def test_effective_requires_success_or_already_effective(self):
        with pytest.raises(ValueError):
            ct.ContainmentResult(True, True, True, True, False, False, True,
                                 ex.ContainmentClassification.INCONCLUSIVE,
                                 "x", "d" * 64)

    def test_approval_requires_policy(self):
        with pytest.raises(ValueError):
            ct.ContainmentResult(True, True, False, True, False, False, False,
                                 ex.ContainmentClassification.INCONCLUSIVE,
                                 "x", "d" * 64)

    def test_policy_requires_broker(self):
        with pytest.raises(ValueError):
            ct.ContainmentResult(True, False, True, False, False, False,
                                 False,
                                 ex.ContainmentClassification.INCONCLUSIVE,
                                 "x", "d" * 64)

    def test_invalid_request_cannot_be_authorized(self):
        with pytest.raises(ValueError):
            ct.ContainmentResult(False, True, False, False, False, False,
                                 False,
                                 ex.ContainmentClassification.INVALID_REQUEST,
                                 "x", "")

    def test_result_type_is_distinct_from_m1_types(self):
        from cloudsec_agent.seed_scenario import (CheckStatus,
                                                  VerificationReport)
        assert ct.ContainmentResult is not VerificationReport
        assert not hasattr(ct, "CheckStatus")
        assert not hasattr(ct, "VerificationReport")


class TestCheckStatusDuplicationDeferred:
    def test_m2d_does_not_import_seed_scenario(self):
        source = (REPO / "cloudsec_agent/containment.py").read_text()
        assert "seed_scenario" not in source

    def test_m2d_does_not_import_scenario_verify(self):
        source = (REPO / "cloudsec_agent/containment.py").read_text()
        assert "scenario.verify" not in source
        assert "scenario import verify" not in source

    def test_m2d_does_not_define_check_status(self):
        tree = ast.parse((REPO / "cloudsec_agent/containment.py").read_text())
        names = {node.name for node in ast.walk(tree)
                 if isinstance(node, ast.ClassDef)}
        assert "CheckStatus" not in names
        assert "VerificationReport" not in names

    def test_m2d_modules_do_not_import_m1_verification(self):
        for module in ("backend/executor.py", "containment.py"):
            tree = ast.parse((REPO / "cloudsec_agent" / module).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module not in ("scenario.verify",
                                               "seed_scenario")

    def test_m1_verification_types_still_exist_untouched(self):
        from cloudsec_agent.scenario import verify as m1_verify
        assert hasattr(m1_verify, "CheckStatus")
        assert hasattr(m1_verify, "VerificationReport")
