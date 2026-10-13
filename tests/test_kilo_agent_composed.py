"""M6G composed: fake OpenAI client -> KiloModelPort -> AgentOrchestrator."""

import json
import re
from types import SimpleNamespace

import pytest

from cloudsec_agent.agent.events import AgentEventKind
from cloudsec_agent.agent.models import AgentLimits, InvestigationStatus
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.read_port import FakeReadPort
from cloudsec_agent.providers.kilo import KiloModelPort
from cloudsec_agent.scenario import determinism as d


@pytest.fixture(autouse=True)
def _no_live_clients(monkeypatch):
    try:
        import openai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("composed tests must not create clients")

    monkeypatch.setattr(openai, "OpenAI", _blocked)


USER = d.RESOURCES.incident_user
BUCKET = d.RESOURCES.incident_bucket
GROUP = d.RESOURCES.log_group
STREAM = d.RESOURCES.log_stream
KEY = "AKIA-SYNTH-KILO-01"
RUN = "run-kilo-seam-1"

BRIEFING = (f"Review storage bucket {BUCKET} and log location "
            f"{GROUP}/{STREAM} for suspicious activity.")


class FakeMessage:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class FakeResponse:
    def __init__(self, message):
        self.choices = [FakeChoice(message)]
        self.usage = None


class FakeCall:
    def __init__(self, name, arguments, call_id):
        self.id = call_id
        self.function = FakeFunction(name, arguments)


class FakeFunction:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class FakeChoice:
    def __init__(self, message):
        self.message = message


class InvestigatingClient:
    def __init__(self):
        self.chat = SimpleNamespace(completions=self)
        self._steps = 0

    def create(self, **kwargs):
        messages = kwargs["messages"]
        text = messages[-1]["content"]
        self._steps += 1
        step = self._steps
        if step == 1:
            assert "No observations yet" in text
            return self._reply("s3_list_objects", {"Bucket": BUCKET}, "k0")
        if step == 2:
            array = re.search(r"\"keys\": \[(.*?)\]", text)
            names = re.findall(r"\"([A-Za-z0-9_\-\./]+)\"",
                               array.group(1) if array else "")
            assert names
            return self._reply("iam_list_users", {}, "k1")
        if step == 3:
            users = re.findall(r"\"user_name\": \"([\w\-]+)\"",
                               text)
            assert USER in users
            return self._reply("iam_list_access_keys",
                               {"UserName": USER}, "k2")
        keys = re.findall(r"AKIA-[A-Z0-9\-]+", text)
        assert keys
        payload = {
            "compromised_principal": USER,
            "compromised_access_key_id": keys[0],
            "confidence": 0.85,
            "findings": ["identity discovered through listing"],
            "evidence_refs": ["run:req:0"],
            "recommended_action": {
                "tool_id": "update_access_key",
                "arguments": {"UserName": USER, "AccessKeyId": keys[0],
                              "Status": "Inactive"},
                "reason": "disable the observed key"},
            "rationale_summary": "listed then inspected"}
        return FakeResponse(FakeMessage(
            content="```json\n" + json.dumps(payload) + "\n```"))

    def _reply(self, name, arguments, call_id):
        return FakeResponse(FakeMessage(tool_calls=[
            FakeCall(name, json.dumps(arguments), call_id)]))


def _responses():
    return {
        "list_users": {"users": [{"user_name": USER,
                                  "arn": "arn:aws:iam::000000000000:user/x"}],
                       "count": 1, "truncated": False},
        "list_objects": {"bucket": BUCKET,
                         "keys": [d.RESOURCES.baseline_object,
                                  d.RESOURCES.notes_object],
                         "count": 2, "truncated": False},
        "get_object": {"bucket": BUCKET, "key": d.RESOURCES.notes_object,
                       "body": "notes", "size": 5, "truncated": False},
        "get_user": {"user_name": USER, "truncated": False},
        "list_access_keys": {"user_name": USER,
                             "access_keys": [{"access_key_id": KEY,
                                              "status": "Active"}],
                             "count": 1, "truncated": False},
        "list_user_policies": {"user_name": USER, "policy_names": [],
                               "count": 0, "truncated": False},
        "get_user_policy": {"user_name": USER, "policy_name": "p",
                            "policy_document": "{}", "truncated": False},
        "describe_secret": {"name": "s", "truncated": False},
        "get_function_configuration": {"function_name": "f",
                                       "truncated": False},
        "get_log_events": {"events": [], "count": 0, "truncated": False},
    }


def _run(run_id=RUN, limits=None):
    responses = _responses()
    reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
    port = RealBackendToolPort(reads, run_scope=run_id, actor="test-agent",
                               scenario_id="test-scenario")
    client = InvestigatingClient()
    model = KiloModelPort(client=client, case_briefing=BRIEFING)
    orch = AgentOrchestrator(model, port, actor="test-agent",
                             scenario_id="test-scenario",
                             clock=lambda: 1.0,
                             limits=limits or AgentLimits())
    result, events = orch.run(run_id)
    return result, events, reads, port, client


class TestKiloComposedSeam:
    def test_evidence_driven_run_completes(self):
        result, events, reads, port, _ = _run()
        assert result.status is InvestigationStatus.COMPLETE
        assert result.compromised_principal == USER
        assert result.compromised_access_key_id == KEY
        assert dict(result.recommended_action.arguments)["Status"] == \
            "Inactive"
        kinds = [event.kind for event in events]
        assert kinds[0] is AgentEventKind.RUN_STARTED
        assert kinds[-1] is AgentEventKind.RUN_COMPLETED
        assert AgentEventKind.ACTION_PROPOSED in kinds

    def test_no_direct_mutation(self):
        _, _, reads, port, _ = _run()
        assert all(method not in ("update_access_key", "get_secret_value")
                   for method, _ in reads.calls)
        assert all(record.tool_id not in ("update_access_key",
                                          "get_secret_value")
                   for record in port.audits)

    def test_limits_still_apply(self):
        result, _, _, _, _ = _run(
            run_id="run-kilo-limit",
            limits=AgentLimits(max_turns=1, max_tool_calls=30))
        assert result.status is InvestigationStatus.LIMIT_REACHED

    def test_no_secret_material(self):
        result, events, _, port, _ = _run()
        blob = repr(result) + repr([event.as_dict() for event in events])
        blob += repr([record.as_dict() for record in port.audits])
        for token in ("SecretString", "SecretBinary", "SecretAccessKey",
                      "SessionToken", "secret_access_key"):
            assert token not in blob
