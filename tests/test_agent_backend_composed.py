"""Composed Agent<->Backend seam regression: fake reads, real port,
real orchestrator, scripted model. Proves authorization, safety,
correlation, and observation-driven discovery end to end."""

import pytest

from m1_scripted_model import CanonicalScriptedModel
from cloudsec_agent.agent.events import AgentEventKind
from cloudsec_agent.agent.models import InvestigationStatus
from cloudsec_agent.agent.orchestrator import AgentOrchestrator
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.read_port import FakeReadPort
from cloudsec_agent.scenario import determinism as d

USER = d.RESOURCES.incident_user
BUCKET = d.RESOURCES.incident_bucket
SECRET = d.RESOURCES.secret_name
FUNCTION = d.RESOURCES.function_name
GROUP = d.RESOURCES.log_group
STREAM = d.RESOURCES.log_stream

FORBIDDEN = ("SecretString", "SecretBinary", "SecretAccessKey",
             "SessionToken", "secret_access_key", "session_token",
             "password")


def _responses(key_id):
    return {
        "list_objects": {"bucket": BUCKET,
                         "keys": [d.RESOURCES.baseline_object,
                                  d.RESOURCES.notes_object,
                                  d.RESOURCES.restricted_object],
                         "count": 3, "truncated": False},
        "get_object": {"bucket": BUCKET,
                       "key": d.RESOURCES.notes_object,
                       "body": "Reporting handoff notes.\n",
                       "size": 24, "truncated": False},
        "get_user": {"user_name": USER, "user_id": "AIDAEXAMPLE",
                     "arn": "arn:aws:iam::000000000000:user/x",
                     "create_date": "2026-01-15T09:00:00+00:00",
                     "truncated": False},
        "list_access_keys": {"user_name": USER,
                             "access_keys": [{"access_key_id": key_id,
                                              "status": "Active",
                                              "create_date": "2026-01-15"}],
                             "count": 1, "truncated": False},
        "list_user_policies": {"user_name": USER,
                               "policy_names": ["case-scout"],
                               "count": 1, "truncated": False},
        "get_user_policy": {"user_name": USER, "policy_name": "case-scout",
                            "policy_document": "{\"Statement\": []}",
                            "truncated": False},
        "describe_secret": {"name": SECRET, "arn": "arn:aws:sm:x",
                            "description": "synthetic",
                            "created_date": "2026-01-15",
                            "truncated": False},
        "get_function_configuration": {"function_name": FUNCTION,
                                       "runtime": "python3.13",
                                       "handler": "handler.main",
                                       "description": "synthetic",
                                       "timeout": 10, "truncated": False},
        "get_log_events": {"log_group": GROUP, "log_stream": STREAM,
                           "events": [], "count": 0, "truncated": False},
    }


def _run(key_id, run_id):
    responses = _responses(key_id)
    reads = FakeReadPort(
        lambda method, kwargs: dict(responses[method]))
    port = RealBackendToolPort(reads, run_scope=run_id, actor="test-agent",
                               scenario_id="test-scenario")
    model = CanonicalScriptedModel(
        bucket=BUCKET, user=USER, secret=SECRET, function=FUNCTION,
        log_group=GROUP, log_stream=STREAM)
    clock = {"now": 0.0}

    def tick():
        clock["now"] += 1.0
        return clock["now"]

    orch = AgentOrchestrator(model, port, actor="test-agent",
                             scenario_id="test-scenario", clock=tick)
    result, events = orch.run(run_id)
    return result, events, reads, port


@pytest.mark.parametrize("key_id", ["AKIA-SYNTH-COMPOSED-01",
                                    "AKIA-SYNTH-COMPOSED-02"])
def test_composed_investigation_completes(key_id):
    run_id = f"run-seam-{key_id[-2:]}"
    result, events, reads, port = _run(key_id, run_id)
    assert result.status is InvestigationStatus.COMPLETE
    assert result.compromised_principal == USER
    assert result.compromised_access_key_id == key_id
    assert result.recommended_action.tool_id == "update_access_key"
    assert dict(result.recommended_action.arguments) == {
        "UserName": USER, "AccessKeyId": key_id, "Status": "Inactive"}
    kinds = [event.kind for event in events]
    assert kinds[0] is AgentEventKind.RUN_STARTED
    assert kinds[-1] is AgentEventKind.RUN_COMPLETED
    assert AgentEventKind.ACTION_PROPOSED in kinds
    assert AgentEventKind.FINDING_UPDATED in kinds
    assert len(reads.calls) == 9
    assert {method for method, _ in reads.calls} == set(_responses(key_id))
    assert all(method not in ("update_access_key", "get_secret_value")
               for method, _ in reads.calls)


def test_answer_follows_tool_output_not_fixtures():
    first, _, _, _ = _run("AKIA-SYNTH-COMPOSED-01", "run-seam-a")
    second, _, _, _ = _run("AKIA-SYNTH-COMPOSED-02", "run-seam-b")
    assert first.compromised_access_key_id != \
        second.compromised_access_key_id


def test_audit_join_is_exact():
    run_id = "run-seam-join"
    result, events, _, port = _run("AKIA-SYNTH-COMPOSED-01", run_id)
    assert result.status is InvestigationStatus.COMPLETE
    requested = [event for event in events
                 if event.kind is AgentEventKind.TOOL_REQUESTED]
    answered = [event for event in events
                if event.kind is AgentEventKind.TOOL_RESULT]
    assert len(requested) == 9
    assert len(port.audits) == 27
    by_request = {}
    for record in port.audits:
        by_request.setdefault(record.request_id, []).append(record)
    assert set(by_request) == {event.payload["request_id"]
                               for event in requested}
    for request_id, records in by_request.items():
        assert [record.stage.value for record in records] == [
            "canonicalized", "broker_decided", "verification_decided"]
        assert all(record.run_id == run_id for record in records)
    assert [(event.payload["request_id"], event.payload["ok"])
            for event in answered] == [
        (event.payload["request_id"], True) for event in requested]


def test_no_secret_material_crosses_the_seam():
    result, events, _, port = _run("AKIA-SYNTH-COMPOSED-01",
                                   "run-seam-safe")
    blob = repr(result) + repr([event.as_dict() for event in events])
    blob += repr([record.as_dict() for record in port.audits])
    for token in FORBIDDEN:
        assert token not in blob
