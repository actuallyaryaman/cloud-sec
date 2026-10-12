"""Test-only fakes for M6C diagnosis and repair tests. No provider calls."""

import json

import pytest

from cloudsec_agent.agent.model_port import ModelPort, ModelTurn
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentToolCall,
                                         RecommendedAction)

SYNTH_KEY = "AKIA-SYNTH-M6C-01"
SYNTH_BUCKET = "synth-neutral-bucket"
SYNTH_GROUP = "synth-neutral-log-group"
SYNTH_STREAM = "synth-neutral-log-stream"
SYNTH_SECRET = "synth-neutral-secret"
SYNTH_FUNCTION = "synth-neutral-function"
OTHER_USERS = ("billing-job", "backup-agent")


def neutral_briefing():
    return ("Review storage bucket %s and log location %s/%s for "
            "suspicious activity."
            % (SYNTH_BUCKET, SYNTH_GROUP, SYNTH_STREAM))


def block_genai_client(monkeypatch):
    try:
        from google import genai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("M6C tests must not create provider clients")

    monkeypatch.setattr(genai, "Client", _blocked)


def synthetic_responses(user="analytics-worker", key_id=SYNTH_KEY,
                        group=SYNTH_GROUP, stream=SYNTH_STREAM,
                        bucket=SYNTH_BUCKET):
    log_message = json.dumps({
        "id": "EV-003", "actor": f"{user}-observed-access-key",
        "actor_access_key_id": key_id, "operation": "s3:ListObjectsV2"})
    listed = [{"user_name": user,
               "arn": f"arn:aws:iam::000000000000:user/{user}"},
              *[{"user_name": name,
                 "arn": f"arn:aws:iam::000000000000:user/{name}"}
                for name in OTHER_USERS]]
    return {
        "list_users": {"users": listed, "count": len(listed),
                       "truncated": False},
        "list_objects": {"bucket": bucket,
                         "keys": ["reports/q1.txt", "notes/handoff.md"],
                         "count": 2, "truncated": False},
        "get_object": {"bucket": bucket, "key": "notes/handoff.md",
                       "body": "handoff notes", "size": 13,
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
        "describe_secret": {"name": SYNTH_SECRET, "truncated": False},
        "get_function_configuration": {"function_name": SYNTH_FUNCTION,
                                       "truncated": False},
        "get_log_events": {"events": [{"message": log_message}],
                           "count": 1, "truncated": False},
    }


class LeadFreeModel(ModelPort):
    def __init__(self, briefing="", log_group=None, log_stream=None):
        self._briefing = briefing
        self._group = log_group or SYNTH_GROUP
        self._stream = log_stream or SYNTH_STREAM

    def complete(self, context):
        step = len(context.observations)
        if step == 0:
            return self._call("m0", "iam_list_users", {})
        rows = context.observations[0].data.get("users") or []
        if not rows or not isinstance(rows[0], dict):
            from cloudsec_agent.agent.model_port import ModelPortError
            raise ModelPortError("no users observed")
        user = rows[0].get("user_name")
        if step == 1:
            return self._call("m1", "iam_get_user", {"UserName": user})
        if step == 2:
            return self._call("m2", "iam_list_access_keys",
                              {"UserName": user})
        if step == 3:
            return self._call("m3", "logs_get_log_events",
                              {"logGroupName": self._group,
                               "logStreamName": self._stream})
        keys = context.observations[2].data.get("access_keys") or []
        key_id = keys[0]["access_key_id"]
        refs = tuple(obs.request_id for obs in context.observations[:2])
        return ModelTurn(final_answer=AgentFinalAnswer(
            compromised_principal=user,
            compromised_access_key_id=key_id, confidence=0.8,
            findings=("discovered identity through listing",),
            evidence_refs=refs,
            recommended_action=RecommendedAction(
                tool_id="update_access_key",
                arguments={"UserName": user, "AccessKeyId": key_id,
                           "Status": "Inactive"},
                reason="disable the observed key"),
            rationale_summary="m6c track-a test"))

    @staticmethod
    def _call(call_id, tool_id, arguments):
        return ModelTurn(tool_calls=[AgentToolCall(
            call_id=call_id, tool_id=tool_id, arguments=arguments)])
