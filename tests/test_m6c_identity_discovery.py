"""M6C Track A: generic read-only iam_list_users. Pure tests, no provider."""

import json

import pytest

from cloudsec_agent.agent.models import InvestigationStatus
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.agent.tool_port import BackendToolRequest
from cloudsec_agent.backend import broker as bk
from cloudsec_agent.backend.registry import Category, get_tool
from cloudsec_agent.integration.agent_backend import (
    RealBackendToolPort, canonical_read_resource)
from cloudsec_agent.integration.read_port import (FakeReadPort,
                                                  FlociReadPort, MAX_USERS)
from cloudsec_agent.providers import gemini as adapter
from cloudsec_agent.scenario import determinism as d
from tests.m6c_fakes import (LeadFreeModel, SYNTH_KEY, block_genai_client,
                             neutral_briefing, synthetic_responses)


@pytest.fixture(autouse=True)
def _no_provider_clients(monkeypatch):
    block_genai_client(monkeypatch)


def _port(responses, run_id="run-m6c-a"):
    reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
    port = RealBackendToolPort(reads, run_scope=run_id, actor="m6c-a",
                               scenario_id="test-scenario")
    return reads, port


def _invoke(tool_id, arguments, index=0):
    return BackendToolRequest(
        request_id=f"run-m6c-a:req:{index:04d}", tool_id=tool_id,
        arguments=dict(arguments), actor="m6c-a",
        scenario_id="test-scenario", justification="m6c-a")


class TestListUsersSpec:
    def test_registered_read_only(self):
        spec = get_tool("iam_list_users")
        assert spec.category is Category.READ_ONLY
        assert spec.service_action == "iam:ListUsers"
        assert spec.requires_approval is False
        assert spec.requires_broker is True
        assert spec.requires_policy is True

    def test_empty_arguments_accepted_unknown_rejected(self):
        _, port = _port(synthetic_responses())
        assert port.execute(_invoke("iam_list_users", {})).ok is True
        outcome = port.execute(_invoke(
            "iam_list_users", {"MaxItems": 10}, 1))
        assert outcome.ok is False
        assert outcome.classification == "validation_error"

    def test_canonicalization_stable_and_granted(self):
        first = canonical_read_resource("iam_list_users", {})
        second = canonical_read_resource("iam_list_users", {})
        assert first == second
        assert first in bk.TASK_SCOPED_CAPABILITY.resources_for(
            "iam_list_users")

    def test_task_scoped_grants_without_mutation(self):
        assert "iam_list_users" in bk.TASK_SCOPED_CAPABILITY.tool_ids
        assert "update_access_key" not in bk.TASK_SCOPED_CAPABILITY.tool_ids
        assert "get_secret_value" not in bk.TASK_SCOPED_CAPABILITY.tool_ids


class TestSafeProjection:
    def test_forbidden_fields_stripped(self):
        def handler(method, kwargs):
            assert method == "list_users"
            return {"users": [{"user_name": "analytics-worker",
                               "SecretString": "CANARY",
                               "SessionToken": "CANARY"}],
                    "ResponseMetadata": {"x": 1}, "count": 1,
                    "truncated": False}
        reads = FakeReadPort(handler)
        port = RealBackendToolPort(reads, run_scope="run-m6c-a",
                                   actor="m6c-a",
                                   scenario_id="test-scenario")
        outcome = port.execute(_invoke("iam_list_users", {}))
        assert outcome.ok is True
        blob = repr(outcome) + repr(port.audits)
        assert "CANARY" not in blob
        assert "ResponseMetadata" not in blob
        assert set(outcome.data) <= {"users", "count", "truncated"}
        assert set(outcome.data["users"][0]) <= {
            "user_name", "arn", "create_date"}

    def test_user_list_truncation_bounded(self):
        class StubIam:
            def list_users(self):
                return {"Users": [
                    {"UserName": f"worker-{index:03d}"}
                    for index in range(MAX_USERS + 50)]}

        reads = FlociReadPort(lambda service: StubIam())
        result = reads.list_users()
        assert len(result["users"]) == MAX_USERS
        assert result["truncated"] is True

    def test_no_credentials_exposed(self):
        _, port = _port(synthetic_responses())
        outcome = port.execute(_invoke("iam_list_users", {}))
        blob = json.dumps(dict(outcome.data), default=str)
        for token in ("SecretString", "SecretBinary", "SecretAccessKey",
                      "SessionToken", "AccessKeyId", "PolicyDocument"):
            assert token not in blob


class TestGeminiParity:
    def test_schema_includes_list_users(self):
        decls = {decl["name"]: decl
                 for decl in adapter.build_tool_declarations()}
        assert len(decls) == 10
        assert decls["iam_list_users"]["required"] == []
        assert decls["iam_list_users"]["optional"] == []

    def test_no_state_changing_functions(self):
        names = [decl["name"]
                 for decl in adapter.build_tool_declarations()]
        assert "get_secret_value" not in names
        assert "update_access_key" not in names


class TestNeutralBriefingPath:
    def test_username_reached_without_guessing(self):
        responses = synthetic_responses(user=d.RESOURCES.incident_user)
        briefing = neutral_briefing()
        assert d.RESOURCES.incident_user not in briefing
        reads, port = _port(responses, run_id="run-m6c-lead")
        model = LeadFreeModel(briefing)
        orch = AgentOrchestrator(model, port)
        result, events = orch.run("run-m6c-lead")
        assert result.status is InvestigationStatus.COMPLETE
        assert result.compromised_principal == d.RESOURCES.incident_user
        assert result.compromised_access_key_id == SYNTH_KEY
        called = dict(reads.calls)
        assert "list_users" in called

    def test_key_follows_observed_username(self):
        responses = synthetic_responses(user=d.RESOURCES.incident_user)
        _, port = _port(responses)
        users = port.execute(_invoke("iam_list_users", {}))
        name = users.data["users"][0]["user_name"]
        assert name == d.RESOURCES.incident_user
        keys = port.execute(_invoke(
            "iam_list_access_keys", {"UserName": name}, 1))
        assert keys.ok is True
        assert SYNTH_KEY in json.dumps(dict(keys.data), default=str)

    def test_arbitrary_synthetic_usernames_listed(self):
        responses = synthetic_responses()
        _, port = _port(responses)
        users = port.execute(_invoke("iam_list_users", {}))
        assert users.ok is True
        names = [row["user_name"] for row in users.data["users"]]
        for user in ("analytics-worker", "billing-job", "backup-agent"):
            assert user in names

    def test_broker_mechanism_is_name_agnostic(self):
        from cloudsec_agent.backend.broker import (BrokerGrant,
                                                  CapabilitySet, evaluate)
        from cloudsec_agent.backend.request import CanonicalAction
        resource = ("arn:aws:iam::000000000000:user/"
                    "billing-job")
        capability = CapabilitySet(
            tool_resources={"iam_get_user": {resource}})
        grant = BrokerGrant(capability=capability,
                            execution_principal_ref="m6c-test",
                            run_scope="run-m6c-mech")
        action = CanonicalAction(tool_id="iam_get_user",
                                 service_action="iam:GetUser",
                                 resource=resource,
                                 normalized_arguments={})
        decision = evaluate(grant, action, "run-m6c-mech")
        assert decision.granted is True
