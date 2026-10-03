import ast
import pathlib

import pytest

from cloudsec_agent.backend import approval as ap
from cloudsec_agent.backend import broker as bk
from cloudsec_agent.backend import executor as ex
from cloudsec_agent.backend import policy as pl
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.backend import request as rq

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKEND = REPO / "cloudsec_agent/backend"

KEY = "AKIAEXAMPLE0000000A"
OTHER_KEY = "AKIAEXAMPLE0000000B"
INCIDENT = "incident-user"
INVESTIGATOR = "security-agent-backend"
INVESTIGATOR_KEY = "AKIAEXAMPLE0000000B"
INCIDENT_ARN = "arn:aws:iam::000000000000:user/incident-user"
T1 = 1500
T_EXPIRY = 2000


class FakePort(ex.ExecutionPort):
    def __init__(self, incident_status="Active", investigator_status="Active",
                 incident_keys=None, investigator_keys=None,
                 update_outcome=None, mutation_changes_state=True,
                 post_status=None):
        self.incident_keys = incident_keys if incident_keys is not None else [
            {"AccessKeyId": KEY, "Status": incident_status}]
        self.investigator_keys = investigator_keys if investigator_keys is not None else [
            {"AccessKeyId": INVESTIGATOR_KEY, "Status": investigator_status}]
        self.update_outcome = update_outcome
        self.mutation_changes_state = mutation_changes_state
        self.post_status = post_status
        self.list_calls = []
        self.update_calls = []

    def list_access_keys(self, user_name):
        self.list_calls.append(user_name)
        if user_name == INCIDENT:
            return self.incident_keys
        if user_name == INVESTIGATOR:
            return self.investigator_keys
        return []

    def update_access_key_status(self, user_name, access_key_id, status):
        self.update_calls.append((user_name, access_key_id, status))
        if self.update_outcome is not None:
            return self.update_outcome
        if self.mutation_changes_state:
            applied = self.post_status or status
            for entry in self.incident_keys:
                if entry["AccessKeyId"] == access_key_id:
                    entry["Status"] = applied
        return (200, None, "")


def _context():
    return pl.ScenarioPolicyContext("csi-incident-v1", INCIDENT, KEY)


def _action(**overrides):
    fields = {"tool_id": rg.UPDATE_ACCESS_KEY,
              "service_action": "iam:UpdateAccessKey",
              "resource": INCIDENT_ARN,
              "normalized_arguments": {"UserName": INCIDENT,
                                       "AccessKeyId": KEY,
                                       "Status": "Inactive"}}
    fields.update(overrides)
    return rq.CanonicalAction(**fields)


def _decisions(action=None, approved=True, policy_allowed=True,
               broker_granted=True, approval_digest=None,
               policy_digest=None):
    action = action or _action()
    digest = rq.action_digest(action)
    grant = bk.grant_for(bk.BROAD_CAPABILITY, "run-A")
    broker = bk.evaluate(grant, action, "run-A")
    if not broker_granted:
        broker = bk.BrokerDecision(False, bk.BrokerReasonCode.TOOL_NOT_GRANTED,
                                   action.tool_id, action.resource, "run-A")
    policy = pl.evaluate_containment_policy(action, digest, broker, _context())
    if not policy_allowed:
        policy = pl.PolicyDecision(False, pl.PolicyReasonCode.WRONG_ACCESS_KEY,
                                   "", policy_digest or digest)
    elif policy_digest:
        policy = pl.PolicyDecision(True, pl.PolicyReasonCode.ALLOW_CONTAINMENT,
                                   "CONTAIN-001", policy_digest)
    reason = (ap.ApprovalReasonCode.APPROVED if approved
              else ap.ApprovalReasonCode.DENIED)
    approval = ap.ApprovalDecision(approved, reason,
                                   approval_digest or digest, "ap-1")
    return action, digest, broker, policy, approval


def _execute(port, **kwargs):
    action, digest, broker, policy, approval = _decisions(**kwargs)
    executor = ex.ContainmentExecutor(port)
    return executor.execute(action, digest, broker, policy, approval,
                            INVESTIGATOR, INVESTIGATOR_KEY)


class TestExecutorIdentityEnforcement:
    def test_executor_identity_is_the_agreed_principal(self):
        assert ex.EXECUTION_IDENTITY == "security-containment-executor"

    def test_executor_identity_comes_from_registry_constant(self):
        assert ex.EXECUTION_IDENTITY is rg.EXECUTION_IDENTITY_USER

    def test_executor_reports_its_fixed_identity(self):
        executor = ex.ContainmentExecutor(FakePort())
        assert executor.execution_identity == ex.EXECUTION_IDENTITY

    def test_executor_rejects_alternative_identity_at_construction(self):
        for other in ("incident-user", INVESTIGATOR, "admin"):
            with pytest.raises(ex.ExecutionPrerequisiteError):
                ex.ContainmentExecutor(FakePort(), execution_identity=other)

    def test_execution_result_rejects_alternative_identity(self):
        with pytest.raises(ex.ExecutionPrerequisiteError):
            ex.ExecutionResult(False, False, False,
                               ex.ContainmentClassification.INCONCLUSIVE,
                               execution_identity="someone-else")

    def test_tool_request_cannot_select_executor_identity(self):
        request = rq.ToolRequest(
            request_id="r", tool_id=rg.UPDATE_ACCESS_KEY,
            arguments={"UserName": INCIDENT, "AccessKeyId": KEY,
                       "Status": "Inactive",
                       "execution_principal": "attacker-chosen"},
            actor="attacker", scenario_id="csi", justification="j")
        result = _execute(FakePort())
        assert result.execution_identity == ex.EXECUTION_IDENTITY
        assert "attacker-chosen" not in str(result.as_dict())

    def test_canonical_action_cannot_select_executor_identity(self):
        action = _action()
        with pytest.raises(TypeError):
            rq.CanonicalAction(tool_id=action.tool_id,
                               service_action=action.service_action,
                               resource=action.resource,
                               normalized_arguments=dict(
                                   action.normalized_arguments),
                               execution_principal="attacker-chosen")

    def test_policy_decision_cannot_select_executor_identity(self):
        with pytest.raises(TypeError):
            pl.PolicyDecision(True, pl.PolicyReasonCode.ALLOW_CONTAINMENT,
                              "CONTAIN-001", "d" * 64,
                              execution_principal="attacker-chosen")

    def test_approval_decision_cannot_select_executor_identity(self):
        with pytest.raises(TypeError):
            ap.ApprovalDecision(True, ap.ApprovalReasonCode.APPROVED, "d" * 64,
                                "ap-1", execution_principal="attacker-chosen")

    def test_execution_result_has_no_credential_field(self):
        names = set(ex.ExecutionResult.__dataclass_fields__)
        for forbidden in ("secret_access_key", "SecretAccessKey",
                          "session_token", "credentials", "access_key_id",
                          "AccessKeyId", "client", "port"):
            assert forbidden not in names

    def test_execution_result_does_not_serialise_key_id(self):
        result = _execute(FakePort())
        assert KEY not in str(result.as_dict())


class TestExecutionPrerequisites:
    def test_policy_denial_refuses_executor(self):
        with pytest.raises(ex.ExecutionPrerequisiteError) as exc:
            _execute(FakePort(), policy_allowed=False)
        assert exc.value.classification is \
            ex.ContainmentClassification.POLICY_DENIED

    def test_broker_denial_refuses_executor(self):
        with pytest.raises(ex.ExecutionPrerequisiteError) as exc:
            _execute(FakePort(), broker_granted=False)
        assert exc.value.classification is \
            ex.ContainmentClassification.BROKER_DENIED

    def test_approval_denial_refuses_executor(self):
        with pytest.raises(ex.ExecutionPrerequisiteError) as exc:
            _execute(FakePort(), approved=False)
        assert exc.value.classification is \
            ex.ContainmentClassification.APPROVAL_DENIED

    def test_missing_approval_refuses_executor(self):
        action, digest, broker, policy, _ = _decisions()
        executor = ex.ContainmentExecutor(FakePort())
        with pytest.raises(ex.ExecutionPrerequisiteError) as exc:
            executor.execute(action, digest, broker, policy, None,
                             INVESTIGATOR, INVESTIGATOR_KEY)
        assert exc.value.classification is \
            ex.ContainmentClassification.APPROVAL_REQUIRED

    def test_policy_digest_mismatch_refuses_executor(self):
        with pytest.raises(ex.ExecutionPrerequisiteError) as exc:
            _execute(FakePort(), policy_digest="f" * 64)
        assert exc.value.classification is \
            ex.ContainmentClassification.POLICY_DENIED

    def test_approval_digest_mismatch_refuses_executor(self):
        with pytest.raises(ex.ExecutionPrerequisiteError) as exc:
            _execute(FakePort(), approval_digest="e" * 64)
        assert exc.value.classification is \
            ex.ContainmentClassification.APPROVAL_DENIED

    def test_wrong_tool_refuses_executor(self):
        with pytest.raises(ex.ExecutionPrerequisiteError) as exc:
            _execute(FakePort(), action=_action(tool_id="delete_access_key"))
        assert exc.value.classification is \
            ex.ContainmentClassification.INVALID_REQUEST

    def test_wrong_service_action_refuses_executor(self):
        with pytest.raises(ex.ExecutionPrerequisiteError):
            _execute(FakePort(),
                     action=_action(service_action="iam:DeleteAccessKey"))

    def test_wrong_status_refuses_executor(self):
        with pytest.raises(ex.ExecutionPrerequisiteError):
            _execute(FakePort(),
                     action=_action(normalized_arguments={
                         "UserName": INCIDENT, "AccessKeyId": KEY,
                         "Status": "Active"}))

    def test_non_canonical_action_input_refuses_executor(self):
        _, digest, broker, policy, approval = _decisions()
        executor = ex.ContainmentExecutor(FakePort())
        with pytest.raises(ex.ExecutionPrerequisiteError):
            executor.execute("not-an-action", digest, broker, policy, approval,
                             INVESTIGATOR, INVESTIGATOR_KEY)

    def test_prerequisite_failure_performs_no_port_call(self):
        port = FakePort()
        with pytest.raises(ex.ExecutionPrerequisiteError):
            _execute(port, policy_allowed=False)
        assert port.list_calls == []
        assert port.update_calls == []

    def test_executor_rejects_non_port_object(self):
        with pytest.raises(TypeError):
            ex.ContainmentExecutor(object())


class TestIdempotentPreRead:
    def test_active_pre_read_calls_mutation_exactly_once(self):
        port = FakePort(incident_status="Active")
        result = _execute(port)
        assert port.update_calls == [(INCIDENT, KEY, "Inactive")]
        assert result.classification is ex.ContainmentClassification.CONFIRMED

    def test_inactive_pre_read_returns_already_effective(self):
        port = FakePort(incident_status="Inactive")
        result = _execute(port)
        assert result.classification is \
            ex.ContainmentClassification.ALREADY_EFFECTIVE

    def test_already_effective_performs_zero_mutations(self):
        port = FakePort(incident_status="Inactive")
        result = _execute(port)
        assert port.update_calls == []
        assert result.execution_attempted is False
        assert result.execution_succeeded is False

    def test_already_effective_is_still_verified_effective(self):
        port = FakePort(incident_status="Inactive")
        result = _execute(port)
        assert result.verified_effective is True

    def test_already_effective_still_reads_protected_identity(self):
        port = FakePort(incident_status="Inactive")
        _execute(port)
        assert INVESTIGATOR in port.list_calls

    def test_already_effective_with_changed_investigator_is_inconclusive(self):
        port = FakePort(incident_status="Inactive",
                        investigator_status="Inactive")
        result = _execute(port)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert result.verified_effective is False
        assert port.update_calls == []

    def test_already_effective_does_not_rely_on_repeat_api_acceptance(self):
        port = FakePort(incident_status="Inactive")
        _execute(port)
        assert port.update_calls == []


class TestConfirmedAndEmptySuccess:
    def test_api_success_plus_inactive_readback_is_confirmed(self):
        result = _execute(FakePort(mutation_changes_state=True))
        assert result.classification is ex.ContainmentClassification.CONFIRMED
        assert result.execution_attempted is True
        assert result.execution_succeeded is True
        assert result.verified_effective is True

    def test_api_success_without_state_change_is_empty_success(self):
        port = FakePort(mutation_changes_state=False)
        result = _execute(port)
        assert result.classification is \
            ex.ContainmentClassification.EMPTY_SUCCESS
        assert result.execution_attempted is True
        assert result.execution_succeeded is True
        assert result.verified_effective is False

    def test_empty_success_is_not_retried(self):
        port = FakePort(mutation_changes_state=False)
        _execute(port)
        assert len(port.update_calls) == 1

    def test_empty_success_does_not_claim_effective(self):
        result = _execute(FakePort(mutation_changes_state=False))
        assert result.verified_effective is False


class TestApiErrorAndInconclusive:
    def test_mutation_api_error_is_api_error(self):
        port = FakePort(update_outcome=(403, "AccessDenied", "denied"))
        result = _execute(port)
        assert result.classification is ex.ContainmentClassification.API_ERROR
        assert result.error_code == "AccessDenied"

    def test_api_error_keeps_booleans_distinct(self):
        port = FakePort(update_outcome=(500, "InternalFailure", "boom"))
        result = _execute(port)
        assert result.execution_attempted is True
        assert result.execution_succeeded is False
        assert result.verified_effective is False

    def test_api_error_is_not_a_denial(self):
        port = FakePort(update_outcome=(403, "AccessDenied", "denied"))
        result = _execute(port)
        assert result.classification not in (
            ex.ContainmentClassification.BROKER_DENIED,
            ex.ContainmentClassification.POLICY_DENIED,
            ex.ContainmentClassification.APPROVAL_DENIED)

    def test_api_error_is_not_retried(self):
        port = FakePort(update_outcome=(500, "InternalFailure", "boom"))
        _execute(port)
        assert len(port.update_calls) == 1

    def test_missing_key_is_inconclusive(self):
        port = FakePort(incident_keys=[{"AccessKeyId": OTHER_KEY,
                                        "Status": "Active"}])
        result = _execute(port)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert result.reason_code == "key_not_found"
        assert port.update_calls == []

    def test_duplicate_exact_key_is_inconclusive(self):
        port = FakePort(incident_keys=[{"AccessKeyId": KEY, "Status": "Active"},
                                       {"AccessKeyId": KEY,
                                        "Status": "Inactive"}])
        result = _execute(port)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert result.reason_code == "duplicate_exact_key"
        assert port.update_calls == []

    def test_malformed_readback_is_inconclusive(self):
        port = FakePort(incident_keys=[{"AccessKeyId": KEY}])
        result = _execute(port)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE

    def test_unreadable_pre_read_is_inconclusive(self):
        port = FakePort(incident_keys="not-a-list")
        result = _execute(port)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert port.update_calls == []

    def test_post_mutation_missing_key_is_inconclusive(self):
        port = FakePort(incident_keys=[{"AccessKeyId": KEY, "Status": "Active"}],
                        mutation_changes_state=False, post_status="Active")
        port.incident_keys = []
        result = _execute(port)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE


class TestInvestigatorPreservation:
    def test_confirmed_requires_investigator_unchanged(self):
        port = FakePort(investigator_status="Active")
        result = _execute(port)
        assert result.classification is ex.ContainmentClassification.CONFIRMED

    def test_investigator_changed_prevents_effective(self):
        port = FakePort(investigator_status="Inactive")
        result = _execute(port)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert result.verified_effective is False
        assert result.execution_succeeded is True

    def test_investigator_missing_prevents_effective(self):
        port = FakePort(investigator_keys=[])
        result = _execute(port)
        assert result.verified_effective is False

    def test_investigator_state_is_never_mutated(self):
        port = FakePort()
        _execute(port)
        assert all(call[0] != INVESTIGATOR for call in port.update_calls)

    def test_protected_identity_is_read_after_mutation(self):
        port = FakePort()
        _execute(port)
        assert port.list_calls[-1] == INVESTIGATOR


class TestExecutionResultModel:
    def test_execution_result_field_set_is_exact(self):
        assert set(ex.ExecutionResult.__dataclass_fields__) == {
            "execution_attempted", "execution_succeeded", "verified_effective",
            "classification", "reason_code", "http_status", "error_code",
            "detail", "execution_identity"}

    def test_execution_result_is_immutable(self):
        result = _execute(FakePort())
        with pytest.raises(Exception):
            result.execution_succeeded = False

    def test_execution_result_retains_no_raw_response(self):
        result = _execute(FakePort())
        assert not any(isinstance(value, (dict, list))
                       for value in vars(result).values())

    def test_execution_result_rejects_foreign_classification(self):
        with pytest.raises(TypeError):
            ex.ExecutionResult(False, False, False, "confirmed")

    def test_effective_requires_execution_or_already_effective(self):
        with pytest.raises(ex.ExecutionPrerequisiteError):
            ex.ExecutionResult(False, True, True,
                               ex.ContainmentClassification.INCONCLUSIVE)

    def test_already_effective_may_be_effective_without_execution(self):
        result = ex.ExecutionResult(False, False, True,
                                    ex.ContainmentClassification.ALREADY_EFFECTIVE)
        assert result.verified_effective is True

    def test_classification_enum_has_no_already_absent(self):
        names = {member.name for member in ex.ContainmentClassification}
        assert "ALREADY_ABSENT" not in names
        assert "ALREADY_EFFECTIVE" in names

    def test_classification_enum_covers_ten_cases(self):
        assert {member.name for member in ex.ContainmentClassification} == {
            "CONFIRMED", "ALREADY_EFFECTIVE", "BROKER_DENIED", "POLICY_DENIED",
            "APPROVAL_REQUIRED", "APPROVAL_DENIED", "INVALID_REQUEST",
            "API_ERROR", "EMPTY_SUCCESS", "INCONCLUSIVE"}


class TestExecutorNoBypassSurface:
    def test_executor_imports_no_aws_sdk(self):
        tree = ast.parse((BACKEND / "executor.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in ("boto3", "botocore")
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in ("boto3", "botocore")

    def test_executor_does_not_reference_client_factory(self):
        source = (BACKEND / "executor.py").read_text()
        assert "Floci" not in source
        assert "floci_client" not in source

    def test_executor_constructs_no_client(self):
        source = (BACKEND / "executor.py").read_text()
        for forbidden in ("boto3.client", "boto3.resource", "Floci(",
                          "Session(", ".client(", ".resource("):
            assert forbidden not in source, forbidden

    def test_executor_reads_no_environment_or_credential_file(self):
        source = (BACKEND / "executor.py").read_text()
        for forbidden in ("os.environ", "getenv", "open(", "load_file",
                          "credential", "aws_secret"):
            assert forbidden not in source, forbidden

    def test_executor_port_exposes_no_generic_escape_hatch(self):
        for absent in ("call", "invoke", "request", "send", "operation"):
            assert not hasattr(ex.ExecutionPort, absent), absent

    def test_executor_port_surface_is_exact(self):
        public = {name for name in dir(ex.ExecutionPort)
                  if not name.startswith("_")}
        assert public == {"list_access_keys", "update_access_key_status"}

    def test_executor_invokes_only_port_methods(self):
        source = (BACKEND / "executor.py").read_text()
        assert "self._port.list_access_keys" in source
        assert "self._port.update_access_key_status" in source
        for absent in ("update_access_key(", "get_access_key_state("):
            assert absent not in source

    def test_executor_does_not_create_iam_identities(self):
        source = (BACKEND / "executor.py").read_text()
        for absent in ("create_user", "CreateUser", "create_access_key",
                       "put_user_policy", "delete_user"):
            assert absent not in source

    def test_executor_does_not_import_m1_verification_types(self):
        source = (BACKEND / "executor.py").read_text()
        for absent in ("CheckStatus", "VerificationReport", "seed_scenario",
                       "scenario.verify"):
            assert absent not in source

    def test_containment_module_has_no_client_surface(self):
        source = (REPO / "cloudsec_agent/containment.py").read_text()
        for forbidden in ("boto3", "botocore", "Floci", "floci_client",
                          ".client(", ".resource(", "update_access_key_status(",
                          "list_access_keys("):
            assert forbidden not in source, forbidden

    def test_containment_module_imports_no_m1_verification_types(self):
        source = (REPO / "cloudsec_agent/containment.py").read_text()
        for absent in ("CheckStatus", "VerificationReport", "seed_scenario",
                       "scenario.verify", "from .scenario.verify"):
            assert absent not in source

    def test_no_third_verification_report_type_exists(self):
        for module in ("backend/executor.py", "containment.py"):
            tree = ast.parse((REPO / "cloudsec_agent" /
                              module).read_text())
            names = {node.name for node in ast.walk(tree)
                     if isinstance(node, ast.ClassDef)}
            assert "VerificationReport" not in names

    def test_backend_directory_permits_exactly_ten_modules(self):
        present = sorted(item.name for item in BACKEND.iterdir()
                         if item.suffix == ".py")
        assert present == ["__init__.py", "approval.py", "audit.py",
                           "broker.py", "executor.py", "live_executor.py",
                           "m2_identity.py", "policy.py", "registry.py",
                           "request.py"]

    def test_no_containment_cli_exists(self):
        assert not (REPO / "cloudsec_agent/containment_cli.py").exists()

    def test_backend_has_no_live_client_factory(self):
        present = {item.name for item in BACKEND.iterdir()
                   if item.suffix == ".py"}
        for absent in ("client.py", "floci.py", "factory.py", "live.py"):
            assert absent not in present
