"""M6K persistent convergence guidance: pure tests, no network."""

import pytest

from cloudsec_agent.agent.model_port import ModelContext, ModelPort
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentToolCall,
                                         InvestigationStatus,
                                         RecommendedAction)
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.providers import kilo as adapter
from cloudsec_agent.scenario import determinism as d
from tests.agent_fakes import FakeModelPort, FakeToolPort, ok_result
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.read_port import FakeReadPort


@pytest.fixture(autouse=True)
def _no_live_clients(monkeypatch):
    try:
        import openai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("convergence tests must not create clients")

    monkeypatch.setattr(openai, "OpenAI", _blocked)


def _turn(*calls):
    from cloudsec_agent.agent.model_port import ModelTurn
    return ModelTurn(tool_calls=list(calls))


def _call(call_id, tool_id, arguments):
    return AgentToolCall(call_id=call_id, tool_id=tool_id,
                         arguments=arguments)


def _final(principal, key_id, confidence=0.7):
    from cloudsec_agent.agent.model_port import ModelTurn
    return ModelTurn(final_answer=AgentFinalAnswer(
        compromised_principal=principal,
        compromised_access_key_id=key_id, confidence=confidence,
        findings=("guided finding",),
        evidence_refs=("run:req:0",),
        recommended_action=RecommendedAction(
            tool_id="update_access_key",
            arguments={"UserName": principal, "AccessKeyId": key_id,
                       "Status": "Inactive"},
            reason="guided"),
        rationale_summary="guided"))


def _distinct_calls(tool_id, arguments, count):
    return [_turn(_call(f"c{i}", tool_id, dict(arguments, seed=i)))
            for i in range(count)]


class Scripted(ModelPort):
    def __init__(self, script):
        self._script = list(script)
        self.contexts = []

    def complete(self, context):
        self.contexts.append(context)
        return self._script.pop(0)


class TestPersistentWarned:
    def test_k1_no_warned_initially(self):
        model = FakeModelPort([_turn(_call("c0", "s3_list_objects",
                                           {"Bucket": "b"}))])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        orch.run("run-k1")
        assert model.contexts[0].warned_requests == ()
        text = adapter.build_investigation_text(model.contexts[0])
        assert "Do not repeat these exact requests" not in text

    def test_k2_threshold_enters_set(self):
        call = _call("c0", "s3_list_objects", {"Bucket": "b"})
        model = FakeModelPort([_turn(call), _turn(call),
                               _turn(call)])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        orch.run("run-k2")
        warned = model.contexts[2].warned_requests
        assert len(warned) == 1
        assert warned[0].startswith("s3_list_objects(")
        assert "Bucket=b" in warned[0]
        text = adapter.build_investigation_text(model.contexts[2])
        assert "Do not repeat these exact requests" in text
        assert "terminate the run" in text
        assert "after investigating elsewhere" in text
        assert "finalize instead" in text

    def test_k3_intervening_calls_keep_it(self):
        script = [_turn(_call("c0", "s3_list_objects", {"Bucket": "b"})),
                  _turn(_call("c1", "s3_list_objects", {"Bucket": "b"})),
                  _turn(_call("c2", "iam_list_users", {})),
                  _turn(_call("c3", "s3_get_object",
                              {"Bucket": "b", "Key": "k"})),
                  _final("u", "k")]
        model = Scripted(script)
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-k3")
        assert result.status is InvestigationStatus.COMPLETE
        for context in model.contexts[2:]:
            assert len(context.warned_requests) == 1
            text = adapter.build_investigation_text(context)
            assert "Do not repeat these exact requests" in text

    def test_k4_exactness(self):
        from cloudsec_agent.agent.orchestrator import _summarize_request
        first = _summarize_request("iam_get_user", {"UserName": "a"})
        second = _summarize_request("iam_get_user", {"UserName": "b"})
        assert first != second
        assert "UserName=a" in first
        assert "UserName=b" in second

    def test_k5_run_scoped_reset(self):
        call = _call("c0", "s3_list_objects", {"Bucket": "b"})
        for run_id in ("run-k5a", "run-k5b"):
            model = FakeModelPort([_turn(call)])
            orch = AgentOrchestrator(model, FakeToolPort(
                lambda invocation: ok_result({})))
            orch.run(run_id)
            assert model.contexts[0].warned_requests == ()


class TestConvergenceCheckpoint:
    def _run_n(self, count, run_id):
        script = [_turn(_call(f"c{i}", "s3_list_objects",
                              {"Bucket": f"b{i}"})) for i in range(count)]
        model = Scripted(script)
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        orch.run(run_id)
        return model

    def test_k6_before_threshold(self):
        model = self._run_n(7, "run-k6")
        assert model.contexts[6].convergence_checkpoint == ""
        text = adapter.build_investigation_text(model.contexts[6])
        assert "Convergence checkpoint" not in text

    def test_k7_at_threshold(self):
        model = self._run_n(9, "run-k7")
        assert model.contexts[8].convergence_checkpoint != ""
        text = adapter.build_investigation_text(model.contexts[8])
        assert "Convergence checkpoint" in text
        assert "finalize now" in text

    def test_k8_persists(self):
        model = self._run_n(11, "run-k8")
        for context in model.contexts[8:]:
            assert context.convergence_checkpoint != ""

    def test_k9_distinct_read_still_allowed(self):
        script = [_turn(_call(f"c{i}", "s3_list_objects",
                              {"Bucket": f"b{i}"})) for i in range(8)]
        script.append(_turn(_call("c8", "iam_list_users", {})))
        script.append(_final("u", "k"))
        model = Scripted(script)
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-k9")
        assert result.status is InvestigationStatus.COMPLETE
        assert result.tool_call_count == 9

    def test_k10_final_at_checkpoint(self):
        script = [_turn(_call(f"c{i}", "s3_list_objects",
                              {"Bucket": f"b{i}"})) for i in range(8)]
        script.append(_final("u", "k"))
        model = Scripted(script)
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-k10")
        assert result.status is InvestigationStatus.COMPLETE

    def test_k11_benign_final_not_forced(self):
        import json
        from types import SimpleNamespace

        class FakeCompletions:
            def create(self, **kwargs):
                payload = {"compromised_principal": "",
                           "compromised_access_key_id": "",
                           "confidence": 0.2,
                           "findings": ["nothing conclusive"],
                           "evidence_refs": [],
                           "recommended_action": None,
                           "rationale_summary": "insufficient"}
                text = "```json\n" + json.dumps(payload) + "\n```"
                message = SimpleNamespace(content=text, tool_calls=None)
                return SimpleNamespace(
                    choices=[SimpleNamespace(message=message)], usage=None)

        port = adapter.KiloModelPort(client=SimpleNamespace(
            chat=SimpleNamespace(completions=FakeCompletions())))
        orch = AgentOrchestrator(
            port, FakeToolPort(lambda invocation: ok_result({})))
        result, _ = orch.run("run-k11")
        assert result.status is InvestigationStatus.INCOMPLETE
        assert "no_actionable_finding" in result.stop_reason
        assert result.recommended_action is None


USER = d.RESOURCES.incident_user
BUCKET = d.RESOURCES.incident_bucket
GROUP = d.RESOURCES.log_group
STREAM = d.RESOURCES.log_stream
KEY = "AKIA-SYNTH-M6K-01"


def _responses():
    import json
    log_message = json.dumps({
        "id": "EV-003", "actor": f"{USER}-compromised-access-key",
        "actor_access_key_id": KEY, "operation": "s3:ListObjectsV2"})
    return {
        "list_users": {"users": [{"user_name": USER,
                                  "arn": "arn:aws:iam::000000000000:user/x"}],
                       "count": 1, "truncated": False},
        "list_objects": {"bucket": BUCKET,
                         "keys": [d.RESOURCES.notes_object],
                         "count": 1, "truncated": False},
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
        "get_log_events": {"events": [{"message": log_message}],
                           "count": 1, "truncated": False},
    }


class TestCombinedReplay:
    def test_full_path_with_warnings_and_checkpoint(self):
        from cloudsec_agent.agent.events import AgentEventKind
        reads = FakeReadPort(
            lambda method, kwargs: dict(_responses()[method]))
        port = RealBackendToolPort(reads, run_scope="run-m6k",
                                   actor="m6k", scenario_id="test-scenario")
        logs = {"logGroupName": GROUP, "logStreamName": STREAM}
        model = Scripted([
            _turn(_call("h0", "s3_list_objects", {"Bucket": BUCKET})),
            _turn(_call("h1", "logs_get_log_events", dict(logs))),
            _turn(_call("h2", "logs_get_log_events", dict(logs))),
            _turn(_call("h3", "iam_list_users", {})),
            _turn(_call("h4", "iam_list_access_keys",
                       {"UserName": USER})),
            _turn(_call("h5", "s3_get_object",
                       {"Bucket": BUCKET,
                        "Key": d.RESOURCES.notes_object})),
            _turn(_call("h6", "iam_get_user", {"UserName": USER})),
            _turn(_call("h7", "iam_list_user_policies",
                       {"UserName": USER})),
            _final(USER, KEY, confidence=0.8)])
        orch = AgentOrchestrator(model, port)
        result, events = orch.run("run-m6k")
        assert result.status is InvestigationStatus.COMPLETE
        assert result.compromised_principal == USER
        assert result.compromised_access_key_id == KEY
        assert AgentEventKind.ACTION_PROPOSED in [
            event.kind for event in events]
        warned_text = adapter.build_investigation_text(model.contexts[3])
        assert "Do not repeat these exact requests" in warned_text
        assert "logs_get_log_events(logGroupName=" in warned_text
        late = adapter.build_investigation_text(model.contexts[8])
        assert "Convergence checkpoint" in late
        assert "Do not repeat these exact requests" in late
        assert all(method not in ("update_access_key", "get_secret_value")
                   for method, _ in reads.calls)

    def test_drift_back_regression(self):
        logs = {"logGroupName": GROUP, "logStreamName": STREAM}
        model = Scripted([
            _turn(_call("h0", "logs_get_log_events", dict(logs))),
            _turn(_call("h1", "logs_get_log_events", dict(logs))),
            _turn(_call("h2", "iam_list_users", {})),
            _turn(_call("h3", "iam_list_access_keys",
                       {"UserName": USER})),
            _turn(_call("h4", "s3_list_objects", {"Bucket": BUCKET})),
            _final(USER, KEY)])
        orch = AgentOrchestrator(model, FakeToolPort(
            lambda invocation: ok_result({})))
        result, _ = orch.run("run-drift")
        assert result.status is InvestigationStatus.COMPLETE
        text = adapter.build_investigation_text(model.contexts[5])
        assert "Do not repeat these exact requests" in text
        assert "logs_get_log_events(logGroupName=" in text


class TestPromptPreservation:
    def test_all_versions_preserved(self):
        assert "must use them before concluding" in \
            adapter.SYSTEM_INSTRUCTION_M6G_V1
        assert "preserve budget for the final answer" in \
            adapter.SYSTEM_INSTRUCTION_M6I_V1
        assert "Tool calls exist only to gather evidence" in \
            adapter.SYSTEM_INSTRUCTION_M6J_V1
        assert "Requests already flagged as" in \
            adapter.SYSTEM_INSTRUCTION_M6K_V1
        assert "grounded only for the identifier type" in \
            adapter.SYSTEM_INSTRUCTION_M6O_V1
        assert "grounded in enough evidence" in adapter.SYSTEM_INSTRUCTION
        assert adapter.PROMPT_VERSION == "m6p-kilo-sys-v1"

    def test_new_policy_present(self):
        text = adapter.SYSTEM_INSTRUCTION
        assert "Requests already flagged as" in text
        assert "convergence checkpoint" in text.lower()
        assert "unlikely to materially change" in text

    def test_no_m1_hints(self):
        lowered = adapter.SYSTEM_INSTRUCTION.lower()
        for token in ("incident-user", "csi-", "akia",
                      "iam_list_users", "iam_list_access_keys",
                      "s3_list_objects", "logs_get_log_events"):
            assert token not in lowered, token
        assert "→" not in adapter.SYSTEM_INSTRUCTION
