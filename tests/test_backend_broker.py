import ast
import pathlib

import pytest

from cloudsec_agent.backend import broker as bk
from cloudsec_agent.backend import request as rq
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.scenario import determinism as d
from cloudsec_agent.scenario import reset as rs
from cloudsec_agent.scenario.seed import (incident_user_arn,
                                          investigator_user_arn)

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKEND = REPO / "cloudsec_agent/backend"

INCIDENT_ARN = "arn:aws:iam::000000000000:user/incident-user"
INVESTIGATOR_ARN = "arn:aws:iam::000000000000:user/security-agent-backend"
SECRET_NAME = "csi-db-production-credential"


def _containment_action(**overrides):
    fields = {"tool_id": rg.UPDATE_ACCESS_KEY,
              "service_action": "iam:UpdateAccessKey",
              "resource": INCIDENT_ARN,
              "normalized_arguments": {"AccessKeyId": "AKIAEXAMPLE0000000A",
                                       "Status": "Inactive",
                                       "UserName": "incident-user"}}
    fields.update(overrides)
    return rq.CanonicalAction(**fields)


def _secret_action(secret_id=SECRET_NAME):
    return rq.canonicalize_secret_read({"SecretId": secret_id})


def _grant(capability=None, run_scope="run-A"):
    return bk.grant_for(capability if capability is not None
                        else bk.BROAD_CAPABILITY, run_scope)


class TestCapabilitySetRepresentation:
    def test_capability_set_is_immutable(self):
        capability = bk.CapabilitySet({"iam_get_user": {"r"}})
        with pytest.raises(TypeError):
            capability.tool_resources["iam_get_user"] = {"other"}

    def test_capability_set_rejects_wildcard_resource(self):
        with pytest.raises(ValueError):
            bk.CapabilitySet({"iam_get_user": {"*"}})

    def test_capability_set_rejects_embedded_wildcard(self):
        for bad in ("arn:aws:iam::000000000000:user/*", "prefix?",
                    "arn:aws:iam::*:user/x"):
            with pytest.raises(ValueError):
                bk.CapabilitySet({"iam_get_user": {bad}})

    def test_capability_set_rejects_empty_resource_string(self):
        with pytest.raises(TypeError):
            bk.CapabilitySet({"iam_get_user": {""}})

    def test_capability_set_rejects_non_collection_resources(self):
        with pytest.raises(TypeError):
            bk.CapabilitySet({"iam_get_user": "arn:aws:iam::x"})

    def test_caller_cannot_mutate_source_dict_after_construction(self):
        source = {"iam_get_user": frozenset({"r"})}
        capability = bk.CapabilitySet(source)
        source["iam_get_user"] = frozenset({"other"})
        source["extra"] = frozenset({"z"})
        assert capability.tool_ids == frozenset({"iam_get_user"})
        assert capability.resources_for("iam_get_user") == frozenset({"r"})

    def test_capability_stores_expires_at_as_data(self):
        capability = bk.CapabilitySet({"iam_get_user": {"r"}},
                                       expires_at="2099-01-01T00:00:00Z")
        assert capability.expires_at == "2099-01-01T00:00:00Z"

    def test_capability_exposes_tool_ids_and_lookup(self):
        capability = bk.BROAD_CAPABILITY
        assert capability.tool_ids == frozenset(rg.tool_ids())
        assert capability.resources_for("unknown_tool") == frozenset()


class TestBroadCapability:
    def test_broad_has_all_eleven_registered_tools(self):
        assert bk.BROAD_CAPABILITY.tool_ids == frozenset(rg.tool_ids())
        assert len(rg.tool_ids()) == 11

    def test_broad_includes_sensitive_read(self):
        assert rg.GET_SECRET_VALUE in bk.BROAD_CAPABILITY.tool_ids

    def test_broad_includes_state_changing(self):
        assert rg.UPDATE_ACCESS_KEY in bk.BROAD_CAPABILITY.tool_ids

    def test_broad_grants_containment_on_incident_user_only(self):
        assert bk.BROAD_CAPABILITY.resources_for(
            rg.UPDATE_ACCESS_KEY) == frozenset({INCIDENT_ARN})

    def test_broad_does_not_grant_investigator_for_containment(self):
        assert INVESTIGATOR_ARN not in bk.BROAD_CAPABILITY.resources_for(
            rg.UPDATE_ACCESS_KEY)

    def test_broad_does_not_grant_containment_executor(self):
        assert bk.CONTAINMENT_EXECUTION_PRINCIPAL not in \
            bk.BROAD_CAPABILITY.resources_for(rg.UPDATE_ACCESS_KEY)

    def test_broad_grants_secret_logical_identifier(self):
        assert bk.BROAD_CAPABILITY.resources_for(
            rg.GET_SECRET_VALUE) == frozenset({SECRET_NAME})

    def test_broad_contains_no_wildcard_anywhere(self):
        for tool_id, resources in bk.BROAD_CAPABILITY.tool_resources.items():
            for resource in resources:
                assert not any(ch in resource for ch in "*?$"), tool_id

    def test_broad_resources_are_finite_and_non_empty(self):
        for tool_id, resources in bk.BROAD_CAPABILITY.tool_resources.items():
            assert resources, tool_id
            assert len(resources) < 100, tool_id


class TestTaskScopedCapability:
    def test_task_scoped_has_exactly_nine_tools(self):
        assert len(bk.TASK_SCOPED_CAPABILITY.tool_ids) == 9

    def test_task_scoped_is_exactly_the_read_only_tools(self):
        expected = {spec.tool_id for spec in
                    rg.tools_for_category(rg.Category.READ_ONLY)}
        assert bk.TASK_SCOPED_CAPABILITY.tool_ids == expected

    def test_task_scoped_excludes_sensitive_read(self):
        assert rg.GET_SECRET_VALUE not in bk.TASK_SCOPED_CAPABILITY.tool_ids

    def test_task_scoped_excludes_state_changing(self):
        assert rg.UPDATE_ACCESS_KEY not in bk.TASK_SCOPED_CAPABILITY.tool_ids

    def test_task_scoped_denies_containment_action(self):
        decision = bk.evaluate(_grant(bk.TASK_SCOPED_CAPABILITY),
                              _containment_action(), "run-A")
        assert decision.granted is False
        assert decision.reason_code is bk.BrokerReasonCode.TOOL_NOT_GRANTED

    def test_task_scoped_denies_secret_action(self):
        decision = bk.evaluate(_grant(bk.TASK_SCOPED_CAPABILITY),
                              _secret_action(), "run-A")
        assert decision.granted is False
        assert decision.reason_code is bk.BrokerReasonCode.TOOL_NOT_GRANTED

    def test_task_scoped_still_grants_investigation_reads(self):
        action = rq.CanonicalAction("iam_get_user", "iam:GetUser",
                                    INCIDENT_ARN, {"UserName": "incident-user"})
        decision = bk.evaluate(_grant(bk.TASK_SCOPED_CAPABILITY), action, "run-A")
        assert decision.granted is True


class TestBrokerGrantModel:
    def test_broker_grant_is_immutable(self):
        grant = _grant()
        with pytest.raises(Exception):
            grant.run_scope = "run-Z"

    def test_broker_grant_rejects_non_capability(self):
        with pytest.raises(TypeError):
            bk.BrokerGrant(capability={"iam_get_user": {"r"}},
                           execution_principal_ref="p")

    def test_broker_grant_rejects_empty_principal_ref(self):
        with pytest.raises(TypeError):
            bk.BrokerGrant(capability=bk.BROAD_CAPABILITY,
                           execution_principal_ref="")

    def test_containment_principal_is_the_agreed_identity(self):
        assert bk.CONTAINMENT_EXECUTION_PRINCIPAL == \
            "security-containment-executor"

    def test_containment_principal_reuses_m2a_constant(self):
        assert bk.CONTAINMENT_EXECUTION_PRINCIPAL is rg.EXECUTION_IDENTITY_USER

    def test_containment_principal_is_not_an_m1_identity(self):
        assert bk.CONTAINMENT_EXECUTION_PRINCIPAL != d.RESOURCES.incident_user
        assert bk.CONTAINMENT_EXECUTION_PRINCIPAL != \
            d.RESOURCES.investigator_user

    def test_containment_principal_is_not_in_m1_owned_resources(self):
        assert bk.CONTAINMENT_EXECUTION_PRINCIPAL not in rs.OWNED.all_names()

    def test_broker_grant_has_no_credential_field(self):
        names = set(bk.BrokerGrant.__dataclass_fields__)
        for forbidden in ("secret_access_key", "SecretAccessKey",
                          "session_token", "credentials", "akid", "client"):
            assert forbidden not in names

    def test_broker_grant_field_set_is_exact(self):
        assert set(bk.BrokerGrant.__dataclass_fields__) == {
            "capability", "execution_principal_ref", "run_scope"}


class TestBrokerDecisionModel:
    def test_broker_decision_is_immutable(self):
        decision = bk.evaluate(_grant(), _containment_action(), "run-A")
        with pytest.raises(Exception):
            decision.granted = False

    def test_broker_decision_field_set_is_exact(self):
        assert set(bk.BrokerDecision.__dataclass_fields__) == {
            "granted", "reason_code", "tool_id", "resource", "run_scope"}

    def test_broker_decision_rejects_foreign_reason_code(self):
        with pytest.raises(TypeError):
            bk.BrokerDecision(True, "granted", "t", "r", "run-A")

    def test_broker_reason_codes_are_exactly_the_four(self):
        assert {member.name for member in bk.BrokerReasonCode} == {
            "GRANTED", "TOOL_NOT_GRANTED", "RESOURCE_NOT_GRANTED",
            "RUN_SCOPE_MISMATCH"}

    def test_broker_reason_codes_are_distinct_from_policy(self):
        from cloudsec_agent.backend import policy as pl
        assert bk.BrokerReasonCode is not pl.PolicyReasonCode
        assert {m.name for m in bk.BrokerReasonCode}.isdisjoint(
            {m.name for m in pl.PolicyReasonCode})

    def test_broker_decision_type_differs_from_policy_decision(self):
        from cloudsec_agent.backend import policy as pl
        assert type(bk.BrokerDecision) is not pl.PolicyDecision


class TestBrokerResourceMatching:
    def test_exact_containment_resource_grants(self):
        decision = bk.evaluate(_grant(), _containment_action(), "run-A")
        assert decision.granted is True
        assert decision.reason_code is bk.BrokerReasonCode.GRANTED

    def test_wrong_containment_resource_denied(self):
        action = _containment_action(resource="arn:aws:iam::000000000000:user/x")
        decision = bk.evaluate(_grant(), action, "run-A")
        assert decision.granted is False
        assert decision.reason_code is bk.BrokerReasonCode.RESOURCE_NOT_GRANTED

    def test_investigator_resource_denied(self):
        action = _containment_action(resource=INVESTIGATOR_ARN)
        decision = bk.evaluate(_grant(), action, "run-A")
        assert decision.granted is False
        assert decision.reason_code is bk.BrokerReasonCode.RESOURCE_NOT_GRANTED

    def test_prefix_resource_does_not_grant_exact_action(self):
        action = _containment_action(resource="arn:aws:iam::000000000000:user")
        decision = bk.evaluate(_grant(), action, "run-A")
        assert decision.granted is False

    def test_partial_arn_does_not_grant(self):
        action = _containment_action(resource="arn:aws:iam::000000000000")
        decision = bk.evaluate(_grant(), action, "run-A")
        assert decision.granted is False

    def test_trailing_segment_does_not_grant(self):
        action = _containment_action(resource=INCIDENT_ARN + "/extra")
        decision = bk.evaluate(_grant(), action, "run-A")
        assert decision.granted is False

    def test_wildcard_resource_in_action_never_grants(self):
        action = _containment_action(resource="*")
        decision = bk.evaluate(_grant(), action, "run-A")
        assert decision.granted is False

    def test_unknown_tool_denied(self):
        action = rq.CanonicalAction("delete_everything", "iam:DeleteUser",
                                    INCIDENT_ARN, {})
        decision = bk.evaluate(_grant(), action, "run-A")
        assert decision.granted is False
        assert decision.reason_code is bk.BrokerReasonCode.TOOL_NOT_GRANTED

    def test_per_tool_resource_separation_prevents_cross_tool_confusion(self):
        incident_resource = INCIDENT_ARN
        action = rq.CanonicalAction("iam_get_user", "iam:GetUser",
                                    incident_resource,
                                    {"UserName": "incident-user"})
        decision = bk.evaluate(_grant(), action, "run-A")
        assert decision.granted is True
        same_resource_other_tool = rq.CanonicalAction(
            "iam_delete_user", "iam:DeleteUser", incident_resource, {})
        other = bk.evaluate(_grant(), same_resource_other_tool, "run-A")
        assert other.granted is False
        assert other.reason_code is bk.BrokerReasonCode.TOOL_NOT_GRANTED

    def test_secret_action_grants_under_broad(self):
        decision = bk.evaluate(_grant(), _secret_action(), "run-A")
        assert decision.granted is True

    def test_secret_action_denied_for_other_secret(self):
        decision = bk.evaluate(_grant(), _secret_action("other-secret"), "run-A")
        assert decision.granted is False
        assert decision.reason_code is bk.BrokerReasonCode.RESOURCE_NOT_GRANTED


class TestRunScopeBinding:
    def test_exact_scope_grants(self):
        decision = bk.evaluate(_grant(run_scope="run-A"),
                              _containment_action(), "run-A")
        assert decision.granted is True

    def test_mismatched_scope_denied(self):
        decision = bk.evaluate(_grant(run_scope="run-A"),
                              _containment_action(), "run-B")
        assert decision.granted is False
        assert decision.reason_code is bk.BrokerReasonCode.RUN_SCOPE_MISMATCH

    def test_empty_evaluation_scope_denied(self):
        decision = bk.evaluate(_grant(run_scope="run-A"),
                              _containment_action(), "")
        assert decision.granted is False
        assert decision.reason_code is bk.BrokerReasonCode.RUN_SCOPE_MISMATCH

    def test_scope_prefix_does_not_match(self):
        decision = bk.evaluate(_grant(run_scope="run"),
                              _containment_action(), "run-A")
        assert decision.granted is False

    def test_scope_extension_does_not_match(self):
        decision = bk.evaluate(_grant(run_scope="run-A"),
                              _containment_action(), "run-A-2")
        assert decision.granted is False

    def test_scope_check_precedes_tool_check(self):
        decision = bk.evaluate(_grant(bk.TASK_SCOPED_CAPABILITY, "run-A"),
                              _containment_action(), "run-B")
        assert decision.reason_code is bk.BrokerReasonCode.RUN_SCOPE_MISMATCH

    def test_decision_records_the_evaluation_scope(self):
        decision = bk.evaluate(_grant(run_scope="run-A"),
                              _containment_action(), "run-B")
        assert decision.run_scope == "run-B"


class TestBrokerExpiryIsDataOnly:
    def test_expired_capability_still_grants_in_m2b(self):
        capability = bk.CapabilitySet(
            {rg.UPDATE_ACCESS_KEY: frozenset({INCIDENT_ARN})},
            expires_at="1999-01-01T00:00:00Z")
        decision = bk.evaluate(_grant(capability), _containment_action(),
                               "run-A")
        assert decision.granted is True

    def test_broker_reads_no_clock(self):
        source = (BACKEND / "broker.py").read_text()
        for forbidden in ("datetime", "time.time", "utcnow", "monotonic",
                          "now()"):
            assert forbidden not in source

    def test_broker_imports_no_time_module(self):
        tree = ast.parse((BACKEND / "broker.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in ("time", "datetime")
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in ("time", "datetime")


class TestBrokerIgnoresModelProse:
    def _decisions_for(self, **request_fields):
        action = rq.canonicalize_containment_update_access_key(
            {"UserName": "incident-user",
             "AccessKeyId": "AKIAEXAMPLE0000000A", "Status": "Inactive"})
        request = rq.ToolRequest(arguments={
            "UserName": "incident-user", "AccessKeyId": "AKIAEXAMPLE0000000A",
            "Status": "Inactive"}, tool_id=rg.UPDATE_ACCESS_KEY,
            scenario_id="csi-incident-v1", **request_fields)
        assert request.tool_id == action.tool_id
        decision = bk.evaluate(_grant(), action, "run-A")
        return decision

    def test_broker_decision_independent_of_justification(self):
        left = self._decisions_for(request_id="r1", actor="model-a",
                                   justification="urgent")
        right = self._decisions_for(request_id="r2", actor="model-b",
                                    justification="because")
        assert left == right

    def test_broker_decision_independent_of_actor(self):
        assert self._decisions_for(request_id="r", actor="a",
                                   justification="x") == \
            self._decisions_for(request_id="r", actor="b", justification="y")

    def test_broker_signature_does_not_accept_prose(self):
        import inspect
        parameters = set(inspect.signature(bk.evaluate).parameters)
        assert parameters == {"grant", "action", "current_run_scope"}

    def test_no_model_field_can_select_execution_principal(self):
        grant = _grant()
        assert grant.execution_principal_ref == bk.CONTAINMENT_EXECUTION_PRINCIPAL
        request = rq.ToolRequest(request_id="r", tool_id=rg.UPDATE_ACCESS_KEY,
                                 arguments={}, actor="model",
                                 scenario_id="csi",
                                 justification=bk.CONTAINMENT_EXECUTION_PRINCIPAL)
        assert bk.CONTAINMENT_EXECUTION_PRINCIPAL in request.justification
        assert bk.evaluate(grant, _containment_action(),
                           "run-A").granted is True


class TestBrokerNoBypassSurface:
    @pytest.mark.parametrize("name", ["broker.py", "policy.py"])
    def test_module_imports_no_aws_sdk(self, name):
        tree = ast.parse((BACKEND / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in ("boto3", "botocore")
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in ("boto3", "botocore")

    @pytest.mark.parametrize("name", ["broker.py", "policy.py"])
    def test_module_does_not_reference_client_factory(self, name):
        source = (BACKEND / name).read_text()
        assert "Floci" not in source
        assert "floci_client" not in source

    @pytest.mark.parametrize("name", ["broker.py", "policy.py"])
    def test_module_invokes_no_api(self, name):
        source = (BACKEND / name).read_text()
        for forbidden in (".client(", ".resource(", "Session(",
                          "update_access_key(", "get_secret_value(",
                          "update_access_key", "get_secret_value"):
            assert forbidden not in source, forbidden

    @pytest.mark.parametrize("name", ["broker.py", "policy.py"])
    def test_module_has_no_approval_or_subprocess(self, name):
        source = (BACKEND / name).read_text()
        for forbidden in ("ApprovalProvider", "approval_provider",
                          "subprocess", "os.system", "input("):
            assert forbidden not in source

    @pytest.mark.parametrize("name", ["broker.py", "policy.py"])
    def test_module_exposes_no_audit_record(self, name):
        source = (BACKEND / name).read_text()
        assert "AuditRecord" not in source
        assert "audit" not in source

    def test_backend_has_no_executor_or_containment(self):
        present = sorted(item.name for item in BACKEND.iterdir()
                         if item.suffix == ".py")
        assert present == ["__init__.py", "approval.py", "audit.py",
                           "broker.py", "executor.py", "live_executor.py",
                           "m2_identity.py", "policy.py", "registry.py",
                           "request.py"]
        for premature in ("containment.py", "containment_cli.py",
                          "floci.py"):
            assert premature not in present