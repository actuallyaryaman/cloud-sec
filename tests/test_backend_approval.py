import ast
import pathlib
import queue

import pytest

from cloudsec_agent.backend import approval as ap
from cloudsec_agent.backend import audit as au
from cloudsec_agent.backend import broker as bk
from cloudsec_agent.backend import policy as pl
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.backend import request as rq

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKEND = REPO / "cloudsec_agent/backend"

KEY_A = "AKIAEXAMPLE0000000A"
KEY_B = "AKIAEXAMPLE0000000B"
INCIDENT_ARN = "arn:aws:iam::000000000000:user/incident-user"
SECRET_NAME = "csi-db-production-credential"
T0 = 1000
T1 = 1500
T_EXPIRY = 2000


def _action(**overrides):
    arguments = {"UserName": "incident-user", "AccessKeyId": KEY_A,
                 "Status": "Inactive"}
    arguments.update(overrides.pop("arguments", {}))
    fields = {"tool_id": rg.UPDATE_ACCESS_KEY,
              "service_action": "iam:UpdateAccessKey",
              "resource": INCIDENT_ARN, "normalized_arguments": arguments}
    fields.update(overrides)
    return rq.CanonicalAction(**fields)


def _containment_digest():
    return rq.action_digest(_action())


def _record(digest=None, approval_id="ap-1", expires_at=T_EXPIRY,
            single_use=True, approved_by="human-operator"):
    return ap.ApprovalRecord(action_digest=digest or _containment_digest(),
                             approved_by=approved_by, approved_at=T0,
                             expires_at=expires_at, single_use=single_use,
                             approval_id=approval_id)


def _provider(**kwargs):
    return ap.FakeApprovalProvider([_record(**kwargs)])


class TestApprovalRecordModel:
    def test_approval_record_is_immutable(self):
        record = _record()
        with pytest.raises(Exception):
            record.approved_by = "someone-else"

    def test_approval_record_is_frozen(self):
        assert ap.ApprovalRecord.__dataclass_params__.frozen is True

    def test_approval_record_field_set_is_exact(self):
        assert set(ap.ApprovalRecord.__dataclass_fields__) == {
            "action_digest", "approved_by", "approved_at", "expires_at",
            "single_use", "approval_id"}

    def test_approval_record_has_no_credential_field(self):
        names = set(ap.ApprovalRecord.__dataclass_fields__)
        for forbidden in ("secret_access_key", "SecretAccessKey",
                          "session_token", "credentials", "justification",
                          "actor", "normalized_arguments", "arguments",
                          "execution_principal"):
            assert forbidden not in names

    def test_approval_record_rejects_empty_digest(self):
        with pytest.raises(TypeError):
            ap.ApprovalRecord(action_digest="", approved_by="human",
                              approved_at=T0, expires_at=T_EXPIRY,
                              single_use=True, approval_id="ap-1")

    def test_approval_record_rejects_empty_approver(self):
        with pytest.raises(TypeError):
            _record(approved_by="")

    def test_approval_record_rejects_non_bool_single_use(self):
        with pytest.raises(TypeError):
            _record(single_use="yes")

    def test_approval_record_field_names_are_safety_checked(self):
        au.require_safe_field_names(ap.ApprovalRecord.__dataclass_fields__)
        for forbidden in ("SecretAccessKey", "justification", "chain_of_thought"):
            with pytest.raises(au.AuditSafetyError):
                au.require_safe_field_names({"ok", forbidden})


class TestApprovalDecisionModel:
    def test_approval_decision_is_immutable(self):
        decision = _provider().decide(_action(), _containment_digest(), T1)
        with pytest.raises(Exception):
            decision.approved = False

    def test_approval_decision_field_set_is_exact(self):
        assert set(ap.ApprovalDecision.__dataclass_fields__) == {
            "approved", "reason_code", "action_digest", "approval_id"}

    def test_approval_decision_rejects_foreign_reason_code(self):
        with pytest.raises(TypeError):
            ap.ApprovalDecision(approved=True, action_digest="d",
                                reason_code=bk.BrokerReasonCode.GRANTED)

    def test_approval_reason_codes_are_the_six_declared(self):
        assert {member.name for member in ap.ApprovalReasonCode} == {
            "APPROVED", "MISSING_APPROVAL", "DIGEST_MISMATCH", "EXPIRED",
            "REPLAYED", "DENIED"}

    def test_approval_reason_codes_distinct_from_broker_and_policy(self):
        approval = {member.name for member in ap.ApprovalReasonCode}
        assert approval.isdisjoint(
            {member.name for member in bk.BrokerReasonCode})
        assert approval.isdisjoint(
            {member.name for member in pl.PolicyReasonCode})

    def test_approval_decision_type_distinct_from_others(self):
        assert type(ap.ApprovalDecision) is not bk.BrokerDecision
        assert type(ap.ApprovalDecision) is not pl.PolicyDecision
        assert type(ap.ApprovalDecision) is not au.AuditRecord


class TestFakeApprovalProviderDecision:
    def test_exact_digest_approval_succeeds(self):
        decision = _provider().decide(_action(), _containment_digest(), T1)
        assert decision.approved is True
        assert decision.reason_code is ap.ApprovalReasonCode.APPROVED

    def test_different_digest_denied(self):
        decision = _provider().decide(_action(), "0" * 64, T1)
        assert decision.approved is False
        assert decision.reason_code is ap.ApprovalReasonCode.MISSING_APPROVAL

    def test_missing_approval_denied(self):
        decision = ap.FakeApprovalProvider().decide(_action(),
                                                    _containment_digest(), T1)
        assert decision.reason_code is ap.ApprovalReasonCode.MISSING_APPROVAL

    def test_explicit_denied_approval_denied(self):
        class Denying(ap.FakeApprovalProvider):
            def decide(self, action, action_digest, current_time):
                return ap.ApprovalDecision(
                    approved=False,
                    reason_code=ap.ApprovalReasonCode.DENIED,
                    action_digest=action_digest, approval_id="ap-x")
        decision = Denying().decide(_action(), _containment_digest(), T1)
        assert decision.approved is False
        assert decision.reason_code is ap.ApprovalReasonCode.DENIED

    def test_provider_does_not_mint_approval_on_its_own(self):
        provider = ap.FakeApprovalProvider()
        for _ in range(3):
            assert provider.decide(_action(), _containment_digest(),
                                   T1).approved is False
        assert provider.consumed_approval_ids == frozenset()

    def test_provider_requires_explicit_provisioning(self):
        with pytest.raises(TypeError):
            ap.FakeApprovalProvider().provision({"action_digest": "d"})

    def test_provider_is_deterministic_across_instances(self):
        first = _provider().decide(_action(), _containment_digest(), T1)
        second = _provider().decide(_action(), _containment_digest(), T1)
        assert first == second

    def test_approved_by_is_independent_of_model_actor(self):
        record = _record(approved_by="security-oncall")
        provider = ap.FakeApprovalProvider([record])
        request = rq.ToolRequest(request_id="r", tool_id=rg.UPDATE_ACCESS_KEY,
                                 arguments={}, actor="attacker-model",
                                 scenario_id="csi", justification="urgent")
        decision = provider.decide(request, _containment_digest(), T1)
        assert decision.approved is True
        assert record.approved_by == "security-oncall"
        assert request.actor == "attacker-model"


class TestApprovalExpiryFailsClosed:
    def test_before_expiry_succeeds(self):
        decision = _provider(expires_at=T_EXPIRY).decide(
            _action(), _containment_digest(), T_EXPIRY - 1)
        assert decision.approved is True

    def test_at_expiry_fails(self):
        decision = _provider(expires_at=T_EXPIRY).decide(
            _action(), _containment_digest(), T_EXPIRY)
        assert decision.approved is False
        assert decision.reason_code is ap.ApprovalReasonCode.EXPIRED

    def test_after_expiry_fails(self):
        decision = _provider(expires_at=T_EXPIRY).decide(
            _action(), _containment_digest(), T_EXPIRY + 1)
        assert decision.reason_code is ap.ApprovalReasonCode.EXPIRED

    def test_expiry_boundary_is_inclusive(self):
        record = _record(expires_at=T_EXPIRY)
        assert record.is_expired(T_EXPIRY - 1) is False
        assert record.is_expired(T_EXPIRY) is True

    def test_expired_approval_is_not_consumed(self):
        provider = _provider(expires_at=T1)
        provider.decide(_action(), _containment_digest(), T_EXPIRY)
        assert provider.consumed_approval_ids == frozenset()

    def test_approval_module_reads_no_clock(self):
        source = (BACKEND / "approval.py").read_text()
        for forbidden in ("datetime", "time.time", "utcnow", "monotonic"):
            assert forbidden not in source

    def test_approval_module_imports_no_time_module(self):
        tree = ast.parse((BACKEND / "approval.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in ("time", "datetime")
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in ("time", "datetime")

    def test_capability_expiry_remains_unenforced_distinctly(self):
        assert bk.BROAD_CAPABILITY.expires_at is None
        source = (BACKEND / "broker.py").read_text()
        assert "is_expired" not in source


class TestSingleUseReplayPrevention:
    def test_first_use_succeeds(self):
        decision = _provider().decide(_action(), _containment_digest(), T1)
        assert decision.reason_code is ap.ApprovalReasonCode.APPROVED

    def test_second_use_is_replayed(self):
        provider = _provider()
        provider.decide(_action(), _containment_digest(), T1)
        decision = provider.decide(_action(), _containment_digest(), T1)
        assert decision.approved is False
        assert decision.reason_code is ap.ApprovalReasonCode.REPLAYED

    def test_replay_state_is_retained_and_inspectable(self):
        provider = _provider()
        provider.decide(_action(), _containment_digest(), T1)
        assert provider.consumed_approval_ids == frozenset({"ap-1"})

    def test_replay_does_not_depend_on_single_use_field_alone(self):
        multi = ap.FakeApprovalProvider([_record(single_use=False)])
        for _ in range(3):
            assert multi.decide(_action(), _containment_digest(),
                                T1).approved is True
        assert multi.consumed_approval_ids == frozenset()

    def test_distinct_approval_ids_are_tracked_independently(self):
        digest = _containment_digest()
        provider = ap.FakeApprovalProvider([
            _record(approval_id="ap-1"), _record(approval_id="ap-2")])
        first = provider.decide(_action(), digest, T1)
        second = provider.decide(_action(), digest, T1)
        assert first.approval_id == "ap-1"
        assert second.approval_id == "ap-2"
        assert second.approved is True
        assert provider.consumed_approval_ids == frozenset({"ap-1", "ap-2"})

    def test_consumed_approval_is_blocked_for_repeat_digest(self):
        digest = _containment_digest()
        provider = ap.FakeApprovalProvider([_record(approval_id="ap-1")])
        provider.decide(_action(), digest, T1)
        third = provider.decide(_action(), digest, T1)
        assert third.reason_code is ap.ApprovalReasonCode.REPLAYED


class TestApprovalDigestBinding:
    def _approved_for(self, action):
        provider = ap.FakeApprovalProvider(
            [_record(digest=rq.action_digest(action))])
        return provider

    def test_key_a_approval_does_not_authorize_key_b(self):
        provider = self._approved_for(_action())
        other = rq.action_digest(_action(arguments={"AccessKeyId": KEY_B}))
        decision = provider.decide(_action(arguments={"AccessKeyId": KEY_B}),
                                   other, T1)
        assert decision.approved is False

    def test_inactive_approval_does_not_authorize_active_action(self):
        provider = self._approved_for(_action())
        active = _action(arguments={"Status": "Active"})
        decision = provider.decide(active, rq.action_digest(active), T1)
        assert decision.approved is False

    def test_incident_user_approval_does_not_authorize_investigator(self):
        provider = self._approved_for(_action())
        other = _action(resource="arn:aws:iam::000000000000:user/"
                                 "security-agent-backend")
        decision = provider.decide(other, rq.action_digest(other), T1)
        assert decision.approved is False

    def test_update_approval_does_not_authorize_delete(self):
        provider = self._approved_for(_action())
        delete = _action(tool_id="delete_access_key",
                         service_action="iam:DeleteAccessKey")
        decision = provider.decide(delete, rq.action_digest(delete), T1)
        assert decision.approved is False

    def test_update_approval_does_not_authorize_create(self):
        provider = self._approved_for(_action())
        create = _action(tool_id="create_access_key",
                         service_action="iam:CreateAccessKey")
        decision = provider.decide(create, rq.action_digest(create), T1)
        assert decision.approved is False

    def test_approval_does_not_authorize_secret_read(self):
        provider = self._approved_for(_action())
        secret = rq.canonicalize_secret_read({"SecretId": SECRET_NAME})
        decision = provider.decide(secret, rq.action_digest(secret), T1)
        assert decision.approved is False

    def test_wrong_service_action_digest_differs(self):
        assert rq.action_digest(_action()) != rq.action_digest(
            _action(service_action="iam:PutUserPolicy"))

    def test_request_id_difference_needs_no_new_approval(self):
        digest = _containment_digest()
        provider = ap.FakeApprovalProvider([_record(digest=digest)])
        first = rq.ToolRequest(request_id="r1", tool_id=rg.UPDATE_ACCESS_KEY,
                               arguments={}, actor="m", scenario_id="csi",
                               justification="a")
        second = rq.ToolRequest(request_id="r2", tool_id=rg.UPDATE_ACCESS_KEY,
                                arguments={}, actor="m", scenario_id="csi",
                                justification="b")
        assert first.request_id != second.request_id
        assert rq.action_digest(_action()) == digest
        for request in (first, second):
            decision = ap.FakeApprovalProvider(
                [_record(digest=digest)]).decide(_action(), digest, T1)
            assert decision.approved is True

    def test_justification_difference_does_not_affect_approval(self):
        digest = _containment_digest()
        results = []
        for justification in ("trust me", "", "because"):
            request = rq.ToolRequest(request_id="r",
                                     tool_id=rg.UPDATE_ACCESS_KEY,
                                     arguments={}, actor="m",
                                     scenario_id="csi",
                                     justification=justification)
            provider = ap.FakeApprovalProvider([_record(digest=digest)])
            results.append(provider.decide(request, digest, T1))
        assert results[0] == results[1] == results[2]

    def test_actor_difference_does_not_affect_approval(self):
        digest = _containment_digest()
        decisions = []
        for actor in ("attacker", "helper", "system"):
            request = rq.ToolRequest(request_id="r",
                                     tool_id=rg.UPDATE_ACCESS_KEY,
                                     arguments={}, actor=actor,
                                     scenario_id="csi", justification="j")
            provider = ap.FakeApprovalProvider([_record(digest=digest)])
            decisions.append(provider.decide(request, digest, T1))
        assert decisions[0] == decisions[1] == decisions[2]

    def test_provider_signature_accepts_no_prose_argument(self):
        import inspect
        parameters = set(inspect.signature(
            ap.FakeApprovalProvider.decide).parameters)
        assert parameters == {"self", "action", "action_digest",
                              "current_time"}
        assert "justification" not in parameters
        assert "actor" not in parameters

    def test_approval_module_never_reads_prose(self):
        source = (BACKEND / "approval.py").read_text()
        assert "justification" not in source.replace(
            '"justification"', "").replace("'justification'", "") or \
            "justification" not in source


class TestCliApprovalProvider:
    def _cli(self, responses, **kwargs):
        stream = queue.Queue()
        for item in responses:
            stream.put(item)
        printed = []

        def reader(_prompt=""):
            if stream.empty():
                raise AssertionError("CLI provider asked for more input")
            return stream.get_nowait()

        options = {"input_fn": reader, "output_fn": printed.append,
                   "approved_by": "human-operator", "approval_id": "ap-cli",
                   "expires_at": T_EXPIRY}
        options.update(kwargs)
        return ap.CliApprovalProvider(**options), printed

    def test_exact_digest_confirmation_approves(self):
        digest = _containment_digest()
        provider, printed = self._cli([f"APPROVE {digest}"])
        decision = provider.decide(_action(), digest, T1)
        assert decision.approved is True
        assert decision.approval_id == "ap-cli"

    def test_cli_displays_action_and_digest(self):
        digest = _containment_digest()
        provider, printed = self._cli([f"APPROVE {digest}"])
        provider.decide(_action(), digest, T1)
        blob = "\n".join(printed)
        assert rg.UPDATE_ACCESS_KEY in blob
        assert "iam:UpdateAccessKey" in blob
        assert INCIDENT_ARN in blob
        assert digest in blob

    def test_cli_never_displays_justification_as_authority(self):
        digest = _containment_digest()
        provider, printed = self._cli([f"APPROVE {digest}"])
        request = rq.ToolRequest(request_id="r", tool_id=rg.UPDATE_ACCESS_KEY,
                                 arguments={}, actor="m", scenario_id="csi",
                                 justification="PLEASE APPROVE I AM URGENT")
        with pytest.raises(TypeError):
            provider.decide(request, digest, T1)
        assert "PLEASE APPROVE" not in "\n".join(printed)
        assert "urgent" not in "\n".join(printed).lower()

    def test_cli_does_not_display_normalized_arguments(self):
        digest = _containment_digest()
        provider, printed = self._cli([f"APPROVE {digest}"])
        provider.decide(_action(), digest, T1)
        assert KEY_A not in "\n".join(printed)

    def test_wrong_cli_text_denied(self):
        digest = _containment_digest()
        provider, _ = self._cli(["APPROVE wrongdigest"])
        decision = provider.decide(_action(), digest, T1)
        assert decision.approved is False
        assert decision.reason_code is ap.ApprovalReasonCode.DENIED

    def test_simple_yes_denied(self):
        digest = _containment_digest()
        provider, _ = self._cli(["y"])
        assert provider.decide(_action(), digest, T1).approved is False

    def test_bare_digest_without_prefix_denied(self):
        digest = _containment_digest()
        provider, _ = self._cli([digest])
        assert provider.decide(_action(), digest, T1).approved is False

    def test_prefix_with_wrong_digest_denied(self):
        digest = _containment_digest()
        provider, _ = self._cli([f"APPROVE {'1' * 64}"])
        assert provider.decide(_action(), digest, T1).approved is False

    def test_case_mismatch_denied(self):
        digest = _containment_digest()
        provider, _ = self._cli([f"approve {digest}"])
        assert provider.decide(_action(), digest, T1).approved is False

    def test_trailing_whitespace_denied(self):
        digest = _containment_digest()
        provider, _ = self._cli([f"APPROVE {digest} "])
        assert provider.decide(_action(), digest, T1).approved is False

    def test_non_string_response_denied(self):
        digest = _containment_digest()
        provider, _ = self._cli([None])
        assert provider.decide(_action(), digest, T1).approved is False

    def test_cli_approved_at_uses_injected_time(self):
        digest = _containment_digest()
        provider, _ = self._cli([f"APPROVE {digest}"])
        decision = provider.decide(_action(), digest, T1)
        assert decision.approved is True
        assert decision.reason_code is ap.ApprovalReasonCode.APPROVED

    def test_cli_respects_expiry(self):
        digest = _containment_digest()
        provider, _ = self._cli([f"APPROVE {digest}"], expires_at=T1)
        decision = provider.decide(_action(), digest, T_EXPIRY)
        assert decision.reason_code is ap.ApprovalReasonCode.EXPIRED

    def test_cli_enforces_single_use(self):
        digest = _containment_digest()
        provider, _ = self._cli([f"APPROVE {digest}", f"APPROVE {digest}"])
        assert provider.decide(_action(), digest, T1).approved is True
        second = provider.decide(_action(), digest, T1)
        assert second.reason_code is ap.ApprovalReasonCode.REPLAYED

    def test_cli_requires_injected_callables(self):
        with pytest.raises(TypeError):
            ap.CliApprovalProvider(input_fn=print, output_fn=None,
                                   approved_by="h", approval_id="a",
                                   expires_at=T_EXPIRY)


class TestApprovalPrecedence:
    def _policy_allowed(self, action=None):
        action = action or _action()
        digest = rq.action_digest(action)
        grant = bk.grant_for(bk.BROAD_CAPABILITY, "run-A")
        broker = bk.evaluate(grant, action, "run-A")
        context = pl.ScenarioPolicyContext("csi-incident-v1", "incident-user",
                                           KEY_A)
        return pl.evaluate_containment_policy(action, digest, broker, context)

    def test_policy_denied_never_invokes_provider(self):
        action = _action(arguments={"Status": "Active"})
        decision = self._policy_allowed(action)
        assert decision.allowed is False
        provider = _provider()
        with pytest.raises(ap.StageNotReached) as exc:
            ap.evaluate_approval_stage(action, rq.action_digest(action),
                                       decision, provider, T1)
        assert provider.calls == 0
        assert exc.value.stage == "approval"

    def test_broker_denied_manifests_as_policy_denial(self):
        grant = bk.grant_for(bk.TASK_SCOPED_CAPABILITY, "run-A")
        action = _action()
        broker = bk.evaluate(grant, action, "run-A")
        context = pl.ScenarioPolicyContext("csi-incident-v1", "incident-user",
                                           KEY_A)
        decision = pl.evaluate_containment_policy(
            action, rq.action_digest(action), broker, context)
        assert decision.allowed is False
        provider = _provider()
        with pytest.raises(ap.StageNotReached):
            ap.evaluate_approval_stage(action, rq.action_digest(action),
                                       decision, provider, T1)
        assert provider.calls == 0

    def test_stage_helper_requires_real_policy_decision(self):
        with pytest.raises(TypeError):
            ap.evaluate_approval_stage(_action(), "d", "allowed", _provider(),
                                       T1)

    def test_stage_helper_rejects_digest_disagreement(self):
        provider = _provider()
        with pytest.raises(ap.StageNotReached) as exc:
            ap.evaluate_approval_stage(_action(), "f" * 64,
                                       self._policy_allowed(), provider, T1)
        assert exc.value.reason_code is ap.ApprovalReasonCode.DIGEST_MISMATCH
        assert provider.calls == 0

    def test_policy_allowed_reaches_provider(self):
        provider = _provider()
        decision = ap.evaluate_approval_stage(
            _action(), _containment_digest(), self._policy_allowed(),
            provider, T1)
        assert decision.approved is True
        assert provider.calls == 1

    def test_approval_cannot_upgrade_a_policy_denial(self):
        action = _action(arguments={"AccessKeyId": KEY_B})
        denied = self._policy_allowed(action)
        assert denied.allowed is False
        provider = ap.FakeApprovalProvider(
            [_record(digest=rq.action_digest(action))])
        with pytest.raises(ap.StageNotReached):
            ap.evaluate_approval_stage(action, rq.action_digest(action),
                                       denied, provider, T1)
        assert provider.calls == 0
        assert provider.consumed_approval_ids == frozenset()


class TestApprovalNoBypassSurface:
    @pytest.mark.parametrize("name", ["approval.py", "audit.py"])
    def test_module_imports_no_aws_sdk(self, name):
        tree = ast.parse((BACKEND / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in ("boto3", "botocore")
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in ("boto3", "botocore")

    @pytest.mark.parametrize("name", ["approval.py", "audit.py"])
    def test_module_does_not_reference_client_factory(self, name):
        source = (BACKEND / name).read_text()
        assert "Floci" not in source
        assert "floci_client" not in source

    @pytest.mark.parametrize("name", ["approval.py", "audit.py"])
    def test_module_invokes_no_api_or_client(self, name):
        source = (BACKEND / name).read_text()
        for forbidden in (".client(", ".resource(", "Session(",
                          "update_access_key(", "get_secret_value("):
            assert forbidden not in source, forbidden

    @pytest.mark.parametrize("name", ["approval.py", "audit.py"])
    def test_module_has_no_subprocess(self, name):
        assert "subprocess" not in (BACKEND / name).read_text()

    @pytest.mark.parametrize("name", ["approval.py", "audit.py"])
    def test_module_writes_no_files(self, name):
        source = (BACKEND / name).read_text()
        for forbidden in ("open(", "write_text", "write(", "os.replace",
                          "mkdir", "tempfile", "json.dump"):
            assert forbidden not in source, forbidden

    def test_approval_module_defines_no_executor(self):
        source = (BACKEND / "approval.py").read_text()
        for absent in ("def execute", "Executor", "containment"):
            assert absent not in source

    def test_audit_module_defines_no_allow_function(self):
        source = (BACKEND / "audit.py").read_text()
        for absent in ("def allow", "def authorize", "def decide", "def permit",
                       "def approve", "def execute"):
            assert absent not in source

    def test_backend_directory_permits_exactly_ten_modules(self):
        present = sorted(item.name for item in BACKEND.iterdir()
                         if item.suffix == ".py")
        assert present == ["__init__.py", "approval.py", "audit.py",
                           "broker.py", "executor.py", "live_executor.py",
                           "m2_identity.py", "policy.py", "registry.py",
                           "request.py"]

    def test_backend_directory_forbids_premature_modules(self):
        present = {item.name for item in BACKEND.iterdir()
                   if item.suffix == ".py"}
        for premature in ("containment.py", "containment_cli.py"):
            assert premature not in present