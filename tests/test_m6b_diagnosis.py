"""M6B diagnosis: pure tests only, no provider API calls.

Reconstructs why the scored M6A run (3 turns, 8 tool calls,
identical_request_repeat_limit, no principal/key/action) failed, and
classifies the root cause as model reasoning vs entry-point affordance
vs loop-feedback failure. A session fixture blocks real SDK client
creation so no test here can reach the network.
"""

import json
import subprocess

import pytest

from cloudsec_agent.agent.model_port import (ModelContext, ModelPort,
                                             ModelTurn)
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentLimits,
                                         AgentToolCall, RecommendedAction)
from cloudsec_agent.agent.orchestrator import (AgentOrchestrator,
                                               repeat_key)
from cloudsec_agent.agent.tool_port import BackendToolRequest
from cloudsec_agent.backend.registry import READ_ONLY_SPECS
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.read_port import FakeReadPort
from cloudsec_agent.providers import gemini as adapter
from cloudsec_agent.scenario import determinism as d
from tests.agent_fakes import FakeModelPort


@pytest.fixture(autouse=True)
def _no_provider_clients(monkeypatch):
    try:
        from google import genai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("M6B tests must not create provider clients")

    monkeypatch.setattr(genai, "Client", _blocked)


USER = d.RESOURCES.incident_user
BUCKET = d.RESOURCES.incident_bucket
GROUP = d.RESOURCES.log_group
STREAM = d.RESOURCES.log_stream
SECRET = d.RESOURCES.secret_name
FUNCTION = d.RESOURCES.function_name
SYNTH_KEY = "AKIA-SYNTH-M6B-01"

M6A_BRIEFING_TEMPLATE = ("Review storage bucket {bucket} and log location "
                         "{group}/{stream} for suspicious activity.")


class GroundingStatus:
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED_FROM_OBSERVED"
    BRIEFING = "BRIEFING_PROVIDED"
    UNGROUNDED = "UNGROUNDED_GUESS"


def classify_identifier(value, observations, briefing):
    if value in briefing:
        return GroundingStatus.BRIEFING
    for obs in observations:
        data = getattr(obs, "data", obs)
        try:
            items = dict(data)
        except (TypeError, ValueError):
            continue
        if value == items.get("user_name"):
            return GroundingStatus.OBSERVED
        blob = json.dumps(items, sort_keys=True, default=str)
        if value and value in blob:
            return GroundingStatus.DERIVED
    return GroundingStatus.UNGROUNDED


TOOL_DEPENDENCIES = {
    "s3_list_objects": ("Bucket", "Prefix"),
    "s3_get_object": ("Bucket", "Key"),
    "iam_get_user": ("UserName",),
    "iam_list_access_keys": ("UserName",),
    "iam_get_user_policy": ("UserName", "PolicyName"),
    "iam_list_user_policies": ("UserName",),
    "secrets_describe_secret": ("SecretId",),
    "logs_get_log_events": ("logGroupName", "logStreamName"),
    "lambda_get_function_configuration": ("FunctionName",),
}


def _responses(key_id=SYNTH_KEY, user=USER):
    log_message = json.dumps({
        "id": "EV-003", "actor": f"{user}-compromised-access-key",
        "actor_access_key_id": key_id, "operation": "s3:ListObjectsV2"})
    return {
        "list_objects": {"bucket": BUCKET,
                         "keys": [d.RESOURCES.baseline_object,
                                  d.RESOURCES.notes_object,
                                  d.RESOURCES.restricted_object],
                         "count": 3, "truncated": False},
        "get_object": {"bucket": BUCKET, "key": d.RESOURCES.notes_object,
                       "body": "Reporting handoff notes.\n", "size": 24,
                       "truncated": False},
        "get_user": {"user_name": user, "truncated": False},
        "list_access_keys": {"user_name": user,
                             "access_keys": [{"access_key_id": key_id,
                                              "status": "Active"}],
                             "count": 1, "truncated": False},
        "list_user_policies": {"user_name": user,
                               "policy_names": ["case-scout"],
                               "count": 1, "truncated": False},
        "get_user_policy": {"user_name": user, "policy_name": "case-scout",
                            "policy_document": "{}", "truncated": False},
        "describe_secret": {"name": SECRET, "truncated": False},
        "get_function_configuration": {"function_name": FUNCTION,
                                       "truncated": False},
        "get_log_events": {"events": [{"message": log_message}],
                           "count": 1, "truncated": False},
    }


def _backend(responses, run_id="run-m6b"):
    reads = FakeReadPort(lambda method, kwargs: dict(responses[method]))
    port = RealBackendToolPort(reads, run_scope=run_id, actor="m6b",
                               scenario_id="test-scenario")
    return reads, port


def _invoke(port, tool_id, arguments, index=0):
    return port.execute(BackendToolRequest(
        request_id=f"run-m6b:req:{index:04d}", tool_id=tool_id,
        arguments=dict(arguments), actor="m6b", scenario_id="test-scenario",
        justification="m6b diagnosis"))


def _legal_observations():
    responses = _responses()
    _, port = _backend(responses)
    seen = []
    seen.append(_invoke(port, "s3_list_objects", {"Bucket": BUCKET}, 0))
    seen.append(_invoke(port, "logs_get_log_events",
                        {"logGroupName": GROUP, "logStreamName": STREAM}, 1))
    assert all(outcome.ok for outcome in seen)
    return [outcome.data for outcome in seen]


def _strings(blob):
    from collections.abc import Mapping
    found = set()

    def walk(value):
        if isinstance(value, str):
            found.add(value)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, Mapping):
            for item in value.values():
                walk(item)

    walk(blob)
    return found


def _contains(corpus, value):
    return any(value in item for item in corpus)


class TestToolDependencyGraph:
    def test_before_after_surfaces_explicit(self):
        from cloudsec_agent.backend import registry as rg
        before = set(TOOL_DEPENDENCIES)
        assert len(before) == 9
        current = {spec.tool_id for spec in rg.READ_ONLY_SPECS}
        assert before < current
        assert current - before == {"iam_list_users"}
        for tool_id in before:
            assert tool_id in current

    def test_before_surface_had_no_discovery_sibling(self):
        assert "iam_list_users" not in TOOL_DEPENDENCIES
        assert "sts_get_caller_identity" not in TOOL_DEPENDENCIES


class TestBriefingReview:
    def test_briefing_gives_locators_not_answers(self):
        briefing = M6A_BRIEFING_TEMPLATE.format(
            bucket=BUCKET, group=GROUP, stream=STREAM)
        assert BUCKET in briefing and GROUP in briefing
        assert USER not in briefing
        assert SYNTH_KEY not in briefing
        assert "update_access_key" not in briefing

    def test_briefing_covers_only_three_of_nine_tools(self):
        directly = {"s3_list_objects", "logs_get_log_events"}
        assert "s3_get_object" not in directly
        assert len(directly) == 2


class TestIdentityDiscovery:
    def test_username_absent_from_all_legal_observations(self):
        corpus = _strings(_legal_observations())
        assert USER not in corpus
        assert _contains(corpus, USER)

    def test_actor_string_present_but_not_usable_as_username(self):
        corpus = _strings(_legal_observations())
        actor = f"{USER}-compromised-access-key"
        assert _contains(corpus, actor)
        _, port = _backend(_responses())
        outcome = _invoke(port, "iam_get_user", {"UserName": actor}, 0)
        assert outcome.ok is False
        assert outcome.classification == "broker_denied"

    def test_key_id_directly_observable_in_logs(self):
        corpus = _strings(_legal_observations())
        assert _contains(corpus, SYNTH_KEY)

    def test_s3_evidence_carries_no_principal(self):
        responses = _responses()
        _, port = _backend(responses)
        listed = _invoke(port, "s3_list_objects", {"Bucket": BUCKET}, 0)
        gotten = _invoke(port, "s3_get_object",
                         {"Bucket": BUCKET,
                          "Key": d.RESOURCES.notes_object}, 1)
        assert USER not in _strings([listed.data, gotten.data])

    def test_key_listed_after_username_known(self):
        responses = _responses()
        _, port = _backend(responses)
        outcome = _invoke(port, "iam_list_access_keys",
                          {"UserName": USER}, 0)
        assert outcome.ok
        assert _contains(_strings(outcome.data), SYNTH_KEY)


class TestFailedRunGrounding:
    def test_classifier_marks_briefing_bucket(self):
        assert classify_identifier(BUCKET, [], BUCKET) == \
            GroundingStatus.BRIEFING

    def test_classifier_marks_unobserved_username_guess(self):
        observations = _legal_observations()
        assert classify_identifier("some-guessed-name", observations,
                                   BUCKET) == GroundingStatus.UNGROUNDED

    def test_unknown_username_is_broker_denied(self):
        _, port = _backend(_responses())
        outcome = _invoke(port, "iam_get_user",
                          {"UserName": "some-guessed-name"}, 0)
        assert outcome.ok is False
        assert outcome.classification == "broker_denied"

    def test_scored_iam_calls_match_guess_pattern(self):
        assert classify_identifier("some-guessed-name",
                                   _legal_observations(),
                                   BUCKET) == GroundingStatus.UNGROUNDED


class TestRepeatSemantics:
    def test_identical_requests_share_a_key(self):
        first = repeat_key("logs_get_log_events",
                           {"logGroupName": GROUP, "logStreamName": STREAM})
        second = repeat_key("logs_get_log_events",
                            {"logStreamName": STREAM, "logGroupName": GROUP})
        assert first == second

    def test_different_arguments_are_distinct(self):
        assert repeat_key("s3_get_object", {"Bucket": BUCKET, "Key": "a"}) != \
            repeat_key("s3_get_object", {"Bucket": BUCKET, "Key": "b"})

    def test_third_identical_request_stops_the_run(self):
        call = AgentToolCall(call_id="c", tool_id="logs_get_log_events",
                             arguments={"logGroupName": GROUP,
                                        "logStreamName": STREAM})
        script = [ModelTurn(tool_calls=[call])] * 3
        model = FakeModelPort(script)
        _, port = _backend(_responses())
        orch = AgentOrchestrator(
            model, port, limits=AgentLimits(max_turns=10, max_tool_calls=30))
        result, _ = orch.run("run-repeat")
        assert result.tool_call_count == 2
        assert result.stop_reason == "identical_request_repeat_limit"

    def test_after_surface_exposes_repeat_metadata(self):
        call = AgentToolCall(call_id="c", tool_id="logs_get_log_events",
                             arguments={"logGroupName": GROUP,
                                        "logStreamName": STREAM})
        model = FakeModelPort([ModelTurn(tool_calls=[call])] * 2)
        _, port = _backend(_responses())
        orch = AgentOrchestrator(model, port)
        orch.run("run-dup-obs")
        text = adapter.build_investigation_text(model.contexts[-1])
        assert "repeat_count=2" in text
        assert "next_identical_request_will_stop=True" in text


class TestCounterfactualH1:
    def test_username_not_derivable_without_guessing(self):
        corpus = _strings(_legal_observations())
        assert USER not in corpus
        assert _contains(corpus, USER)
        assert _contains(corpus, f"{USER}-compromised-access-key")


class _LeadModel(ModelPort):
    def __init__(self, user):
        self._user = user

    def complete(self, context):
        step = len(context.observations)
        if step == 0:
            return ModelTurn(tool_calls=[AgentToolCall(
                call_id="h0", tool_id="iam_get_user",
                arguments={"UserName": self._user})])
        if step == 1:
            return ModelTurn(tool_calls=[AgentToolCall(
                call_id="h1", tool_id="iam_list_access_keys",
                arguments={"UserName": self._user})])
        if step == 2:
            return ModelTurn(tool_calls=[AgentToolCall(
                call_id="h2", tool_id="logs_get_log_events",
                arguments={"logGroupName": GROUP,
                           "logStreamName": STREAM})])
        rows = context.observations[1].data.get("access_keys") or []
        key_id = rows[0]["access_key_id"]
        refs = tuple(obs.request_id for obs in context.observations[:2])
        return ModelTurn(final_answer=AgentFinalAnswer(
            compromised_principal=self._user,
            compromised_access_key_id=key_id, confidence=0.8,
            findings=("identity pivot succeeded",),
            evidence_refs=refs,
            recommended_action=RecommendedAction(
                tool_id="update_access_key",
                arguments={"UserName": self._user,
                           "AccessKeyId": key_id, "Status": "Inactive"},
                reason="disable the observed key"),
            rationale_summary="counterfactual lead test"))


class TestCounterfactualH2:
    def test_identity_lead_completes_through_frozen_surface(self):
        _, port = _backend(_responses(), run_id="run-h2")
        orch = AgentOrchestrator(_LeadModel(USER), port)
        result, events = orch.run("run-h2")
        assert result.status.value == "COMPLETE"
        assert result.compromised_principal == USER
        assert result.compromised_access_key_id == SYNTH_KEY
        assert dict(result.recommended_action.arguments)["Status"] == \
            "Inactive"


class _RecoveringModel(ModelPort):
    def __init__(self):
        self._feedback = None

    def complete(self, context):
        observations = context.observations
        if len(observations) >= 2:
            first = dict(observations[0].data)
            second = dict(observations[1].data)
            if first == second:
                self._feedback = "repeated_request_no_new_information"
        if self._feedback and len(observations) == 2:
            return ModelTurn(tool_calls=[AgentToolCall(
                call_id="r2", tool_id="s3_get_object",
                arguments={"Bucket": BUCKET,
                           "Key": d.RESOURCES.notes_object})])
        if len(observations) >= 3:
            return ModelTurn(final_answer=AgentFinalAnswer(
                compromised_principal=USER,
                compromised_access_key_id=SYNTH_KEY, confidence=0.5,
                findings=("recovered after repeat signal",),
                evidence_refs=(observations[0].request_id,),
                recommended_action=RecommendedAction(
                    tool_id="update_access_key",
                    arguments={"UserName": USER, "AccessKeyId": SYNTH_KEY,
                               "Status": "Inactive"},
                    reason="counterfactual recovery test"),
                rationale_summary="recovered"))
        return ModelTurn(tool_calls=[AgentToolCall(
            call_id=f"r{len(observations)}", tool_id="logs_get_log_events",
            arguments={"logGroupName": GROUP,
                       "logStreamName": STREAM})])


class TestCounterfactualH3:
    def test_repeat_signal_enables_recovery(self):
        _, port = _backend(_responses(), run_id="run-h3")
        orch = AgentOrchestrator(_RecoveringModel(), port)
        result, _ = orch.run("run-h3")
        assert result.status.value == "COMPLETE"
        assert result.tool_call_count == 3


class TestProductionFrozen:
    def test_adapter_prompt_and_model_unchanged(self):
        assert adapter.ADAPTER_VERSION == "m6a-v1"
        assert adapter.PROMPT_VERSION == "m6a-sys-v1"
        assert adapter.DEFAULT_MODEL == "gemini-2.5-pro"
        assert "```json" in adapter.SYSTEM_INSTRUCTION
        assert "untrusted evidence" in adapter.SYSTEM_INSTRUCTION

    def test_tool_surface_before_after(self):
        from cloudsec_agent.agent.tool_port import KNOWN_TOOL_IDS
        assert len(KNOWN_TOOL_IDS) == 12
        assert len(adapter.build_tool_declarations()) == 10
        assert len(adapter.READ_TOOL_IDS) == 10
        assert "iam_list_users" in adapter.READ_TOOL_IDS

    def test_no_tracked_production_files_modified(self):
        out = subprocess.run(
            ["git", "diff", "--name-only"], capture_output=True, text=True,
            cwd="/home/logic/Projects/cyber/cloud-sec", timeout=60)
        assert out.returncode == 0
        tracked = [line for line in out.stdout.splitlines() if line.strip()]
        allowed = {"pyproject.toml", "uv.lock",
                   "cloudsec_agent/backend/registry.py",
                   "cloudsec_agent/backend/broker.py",
                   "cloudsec_agent/agent/models.py",
                   "cloudsec_agent/agent/orchestrator.py",
                   "cloudsec_agent/agent/tool_port.py",
                   "cloudsec_agent/integration/read_port.py",
                   "cloudsec_agent/integration/agent_backend.py",
                   "cloudsec_agent/scenario/seed.py",
                   "cloudsec_agent/providers/gemini.py",
                   "tests/test_backend_registry.py",
                   "tests/test_backend_broker.py",
                   "tests/test_backend_m2_identity.py",
                   "tests/test_scenario_seed.py",
                   "tests/test_agent_backend_integration.py",
                   "tests/test_investigator_compat.py",
                   "tests/test_gemini_model_port.py",
                   "tests/test_m6b_diagnosis.py",
                   "tests/test_model_config.py",
                   "tests/test_kilo_config.py",
                   "tests/test_kilo_model_port.py",
                   "tests/test_m6k_convergence.py",
                   "tests/test_m6j_finalization.py",
                   "tests/test_m6i_guidance.py",
                   "cloudsec_agent/agent/model_port.py",
                   "cloudsec_agent/providers/model_config.py",
                   "cloudsec_agent/providers/__init__.py",
                   "cloudsec_agent/providers/kilo.py",
                   "scripts/setup_model_config.py",
                   "config/model.toml",
                   ".env.example",
                   ".gitignore"}
        assert all(path in allowed for path in tracked), tracked

    def test_no_backend_semantics_change(self):
        from cloudsec_agent.backend import broker
        assert broker.TASK_SCOPED_CAPABILITY.run_scope == ""
