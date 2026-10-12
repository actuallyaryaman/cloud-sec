"""M6A composed proof: fake Gemini SDK -> real GeminiModelPort ->
real AgentOrchestrator -> real M5B ToolPort seam (FakeReadPort).

The fake SDK derives each response from the investigation text it is
given, so tool arguments demonstrably depend on prior observations.
A second test drives the M5C bridge to CONFIRMED with a fake executor.
"""

import json
import re
from types import SimpleNamespace

import pytest

from cloudsec_agent.agent.events import AgentEventKind
from cloudsec_agent.agent.models import AgentLimits, InvestigationStatus
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.backend.approval import FakeApprovalProvider
from cloudsec_agent.backend.broker import BROAD_CAPABILITY, grant_for
from cloudsec_agent.backend.executor import ContainmentExecutor
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.containment_bridge import ContainmentBridge
from cloudsec_agent.integration.read_port import FakeReadPort
from cloudsec_agent.providers.gemini import GeminiModelPort
from cloudsec_agent.scenario import determinism as d
from test_agent_containment_integration import (FakeExecutionPort, _approval,
                                               _context)

BUCKET = d.RESOURCES.incident_bucket
GROUP = d.RESOURCES.log_group
STREAM = d.RESOURCES.log_stream
USER = d.RESOURCES.incident_user
KEY = "AKIA-SYNTH-GEMINI-01"
SECRET = d.RESOURCES.secret_name
FUNCTION = d.RESOURCES.function_name
RUN = "run-gemini-seam-1"
SCOPE = "run-gemini-seam-1:contain"
GUARD_USER = "case-guard"
GUARD_KEY = "GUARDKEY01"

BRIEFING = (f"Review storage bucket {BUCKET} and log location "
            f"{GROUP}/{STREAM} for suspicious activity.")

FORBIDDEN = ("SecretString", "SecretBinary", "SecretAccessKey",
             "SessionToken", "secret_access_key", "session_token",
             "password")


class FakeFunctionCall:
    def __init__(self, name, args=None, call_id=""):
        self.name = name
        self.args = args if args is not None else {}
        self.id = call_id


class FakePart:
    def __init__(self, text=None, function_call=None):
        self.text = text
        self.function_call = function_call


class FakeResponse:
    def __init__(self, parts):
        self.candidates = [SimpleNamespace(
            content=SimpleNamespace(parts=list(parts)))]
        self.usage_metadata = None


class InvestigatingSdk:
    """Scripted at the SDK boundary only: each reply is derived from the
    investigation text of the current request, mimicking evidence-driven
    model behavior without touching the adapter or orchestrator."""

    def __init__(self):
        self.models = self
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        text = kwargs["contents"][0].parts[0].text
        step = len(self.calls)
        if step == 1:
            assert "No observations yet" in text
            bucket = re.search(r"storage bucket (\S+)", text)
            assert bucket, "briefing bucket missing"
            return FakeResponse([FakePart(function_call=FakeFunctionCall(
                "s3_list_objects", {"Bucket": bucket.group(1)}, "g0"))])
        if step == 2:
            array = re.search(r"\"keys\": \[(.*?)\]", text)
            names = re.findall(r"\"([A-Za-z0-9_\-\./]+)\"",
                               array.group(1) if array else "")
            picked = next((key for key in names if "notes" in key),
                          next(iter(names), None))
            assert picked is not None, "keys observation missing"
            bucket = re.search(r"\"bucket\": \"(\S+?)\"", text)
            return FakeResponse([FakePart(function_call=FakeFunctionCall(
                "s3_get_object",
                {"Bucket": bucket.group(1) if bucket else BUCKET,
                 "Key": picked}, "g1"))])
        if step == 3:
            assert GROUP in text and STREAM in text
            return FakeResponse([FakePart(function_call=FakeFunctionCall(
                "logs_get_log_events",
                {"logGroupName": GROUP, "logStreamName": STREAM}, "g2"))])
        if step == 4:
            key_match = re.search(r"AKIA-[A-Z0-9\-]+", text)
            actor_match = re.search(r"([\w\-]+)-compromised-access-key", text)
            assert key_match and actor_match, "log evidence missing"
            user = actor_match.group(1)
            return FakeResponse([FakePart(function_call=FakeFunctionCall(
                "iam_get_user", {"UserName": user}, "g3"))])
        if step == 5:
            user_match = re.search(r"\"user_name\":\s*\"([\w\-]+)\"", text)
            assert user_match, "user observation missing"
            return FakeResponse([FakePart(function_call=FakeFunctionCall(
                "iam_list_access_keys",
                {"UserName": user_match.group(1)}, "g4"))])
        user_match = re.search(r"\"user_name\":\s*\"([\w\-]+)\"", text)
        key_match = re.search(r"AKIA-[A-Z0-9\-]+", text)
        assert user_match and key_match
        user, key = user_match.group(1), key_match.group(0)
        refs = ["run:req:0", "run:req:2"]
        payload = {
            "compromised_principal": user,
            "compromised_access_key_id": key,
            "confidence": 0.8,
            "findings": ["bucket enumeration then denied sensitive read",
                         "key state inspected through tools"],
            "evidence_refs": refs,
            "recommended_action": {
                "tool_id": "update_access_key",
                "arguments": {"UserName": user, "AccessKeyId": key,
                              "Status": "Inactive"},
                "reason": "disable the key observed in anomalous access"},
            "rationale_summary": "tool-observed access plus key state"}
        return FakeResponse([FakePart(
            text="```json\n" + json.dumps(payload) + "\n```")])


def _responses():
    log_message = json.dumps({
        "id": "EV-003", "actor": f"{USER}-compromised-access-key",
        "actor_access_key_id": KEY, "operation": "s3:ListObjectsV2"})
    return {
        "list_objects": {"bucket": BUCKET,
                         "keys": [d.RESOURCES.baseline_object,
                                  d.RESOURCES.notes_object,
                                  d.RESOURCES.restricted_object],
                         "count": 3, "truncated": False},
        "get_object": {"bucket": BUCKET, "key": d.RESOURCES.notes_object,
                       "body": "Reporting handoff notes.\n", "size": 24,
                       "truncated": False},
        "get_user": {"user_name": USER, "truncated": False},
        "list_access_keys": {"user_name": USER,
                             "access_keys": [{"access_key_id": KEY,
                                              "status": "Active"}],
                             "count": 1, "truncated": False},
        "list_user_policies": {"user_name": USER,
                               "policy_names": ["case-scout"],
                               "count": 1, "truncated": False},
        "get_user_policy": {"user_name": USER, "policy_name": "case-scout",
                            "policy_document": "{}", "truncated": False},
        "describe_secret": {"name": SECRET, "truncated": False},
        "get_function_configuration": {"function_name": FUNCTION,
                                       "truncated": False},
        "get_log_events": {"events": [{"message": log_message}],
                           "count": 1, "truncated": False},
    }


def _run(run_id=RUN, limits=None):
    responses = _responses()
    reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
    port = RealBackendToolPort(reads, run_scope=run_id, actor="test-agent",
                               scenario_id="test-scenario")
    sdk = InvestigatingSdk()
    model = GeminiModelPort(client=sdk, case_briefing=BRIEFING)
    orch = AgentOrchestrator(model, port, actor="test-agent",
                             scenario_id="test-scenario",
                             clock=lambda: 1.0,
                             limits=limits or AgentLimits())
    result, events = orch.run(run_id)
    return result, events, reads, port, sdk


class TestGeminiComposedSeam:
    def test_evidence_driven_investigation_completes(self):
        result, events, reads, port, sdk = _run()
        assert result.status is InvestigationStatus.COMPLETE
        assert result.compromised_principal == USER
        assert result.compromised_access_key_id == KEY
        assert result.recommended_action.tool_id == "update_access_key"
        assert dict(result.recommended_action.arguments) == {
            "UserName": USER, "AccessKeyId": KEY, "Status": "Inactive"}
        # Request 1 carried no observations; every later request carried
        # the prior tool observations back into the provider.
        assert len(sdk.calls) == 6
        assert "No observations yet" in \
            sdk.calls[0]["contents"][0].parts[0].text
        for call in sdk.calls[1:]:
            assert "Prior tool observations" in \
                call["contents"][0].parts[0].text

    def test_tool_arguments_follow_observations(self):
        _, _, reads, _, _ = _run()
        seen = {method for method, _ in reads.calls}
        assert seen == {"list_objects", "get_object", "get_log_events",
                        "get_user", "list_access_keys"}
        get_object = [kwargs for method, kwargs in reads.calls
                      if method == "get_object"][0]
        assert get_object["key"] == d.RESOURCES.notes_object
        list_keys = [kwargs for method, kwargs in reads.calls
                     if method == "list_access_keys"][0]
        assert list_keys["user_name"] == USER

    def test_action_proposed_without_mutation(self):
        result, events, reads, port, _ = _run()
        kinds = [event.kind for event in events]
        assert kinds[0] is AgentEventKind.RUN_STARTED
        assert kinds[-1] is AgentEventKind.RUN_COMPLETED
        assert AgentEventKind.ACTION_PROPOSED in kinds
        assert AgentEventKind.FINDING_UPDATED in kinds
        assert all(method not in ("update_access_key", "get_secret_value")
                   for method, _ in reads.calls)
        assert len(port.audits) == 5 * 3

    def test_limits_still_apply(self):
        sdk = InvestigatingSdk()
        model = GeminiModelPort(client=sdk, case_briefing=BRIEFING)
        responses = _responses()
        reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
        port = RealBackendToolPort(reads, run_scope="run-limit",
                                   actor="test-agent",
                                   scenario_id="test-scenario")
        orch = AgentOrchestrator(
            model, port, actor="test-agent", scenario_id="test-scenario",
            clock=lambda: 1.0,
            limits=AgentLimits(max_turns=2, max_tool_calls=30))
        result, _ = orch.run("run-limit")
        assert result.status is InvestigationStatus.LIMIT_REACHED

    def test_no_secret_material_crosses_the_seam(self):
        result, events, _, port = _run()[:4]
        blob = repr(result) + repr([event.as_dict() for event in events])
        blob += repr([record.as_dict() for record in port.audits])
        for token in FORBIDDEN:
            assert token not in blob

    def test_provider_adapter_has_no_hardcoded_case(self):
        import pathlib
        source = pathlib.Path(
            "cloudsec_agent/providers/gemini.py").read_text(
                encoding="utf-8").lower()
        for token in ("csi-", "incident-user", "security-agent-backend",
                      "akia", "exactly one compromised",
                      "attempted to read a secret",
                      "disable the access key"):
            assert token not in source, token


class TestGeminiContainmentProof:
    def test_recommended_action_confirms_through_bridge(self):
        result, _, _, _, _ = _run()
        bridge = ContainmentBridge(
            run_id=RUN, actor="test-agent", scenario_id="test-scenario",
            run_scope=SCOPE, clock=lambda: 1.0)
        store = FakeExecutionPort({USER: {KEY: "Active"},
                                   GUARD_USER: {GUARD_KEY: "Active"}})
        prepared = bridge.prepare("a1", result.recommended_action, USER, KEY)
        outcome = bridge.submit(
            prepared, grant=grant_for(BROAD_CAPABILITY, SCOPE),
            policy_context=_context(KEY),
            approval_provider=FakeApprovalProvider(
                [_approval(prepared.digest)]),
            executor=ContainmentExecutor(store), protected_user=GUARD_USER,
            protected_key_id=GUARD_KEY, approval_ref="appr-1",
            current_time=1)
        assert outcome.classification == "confirmed"
        assert outcome.executed is True and outcome.effective is True
        assert store.mutations == [(USER, KEY, "Inactive")]
