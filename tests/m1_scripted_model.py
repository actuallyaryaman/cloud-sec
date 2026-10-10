"""Deterministic scripted investigation model for M5B tests.

Test/demo control logic only. Takes bootstrap resource names for the
first calls, then derives every follow-up argument and the final
answer from prior ToolObservations. The final principal and key id
always come from live tool output, never from the bootstrap.
"""

from cloudsec_agent.agent.model_port import (ModelPort, ModelPortError,
                                             ModelTurn)
from cloudsec_agent.agent.models import (AgentFinalAnswer, AgentToolCall,
                                          RecommendedAction)


def _data(observations, index, field):
    try:
        return observations[index].data[field]
    except (IndexError, KeyError, TypeError):
        raise ModelPortError("evidence unavailable")


def _first(rows):
    items = [row for row in (rows or []) if isinstance(row, dict)]
    if not items:
        raise ModelPortError("evidence unavailable")
    return items[0]


class CanonicalScriptedModel(ModelPort):
    def __init__(self, bucket, user, secret, function, log_group,
                 log_stream):
        self._seed = {"bucket": bucket, "user": user, "secret": secret,
                      "function": function, "log_group": log_group,
                      "log_stream": log_stream}

    def complete(self, context):
        observations = context.observations
        step = len(observations)
        get = self._seed.get
        if step == 0:
            return self._turn("s0", "s3_list_objects",
                              {"Bucket": get("bucket")})
        if step == 1:
            keys = _data(observations, 0, "keys") or []
            names = [key for key in keys if isinstance(key, str)]
            picked = next((key for key in names if "notes/" in key),
                          next(iter(names), None))
            if picked is None:
                raise ModelPortError("evidence unavailable")
            return self._turn("s1", "s3_get_object",
                              {"Bucket": get("bucket"), "Key": picked})
        if step == 2:
            return self._turn("s2", "iam_get_user",
                              {"UserName": get("user")})
        if step == 3:
            user_name = _data(observations, 2, "user_name")
            return self._turn("s3", "iam_list_access_keys",
                              {"UserName": user_name})
        if step == 4:
            rows = _data(observations, 3, "access_keys") or []
            active = [row for row in rows
                      if isinstance(row, dict)
                      and row.get("status") == "Active"]
            key_id = (active[0] if active else _first(rows))["access_key_id"]
            user_name = _data(observations, 2, "user_name")
            self._key_id = key_id
            return self._turn("s4", "iam_list_user_policies",
                              {"UserName": user_name})
        if step == 5:
            names = _data(observations, 4, "policy_names") or []
            policy = next((name for name in names
                           if isinstance(name, str)), None)
            if policy is None:
                raise ModelPortError("evidence unavailable")
            user_name = _data(observations, 2, "user_name")
            return self._turn("s5", "iam_get_user_policy",
                              {"UserName": user_name, "PolicyName": policy})
        if step == 6:
            return self._turn("s6", "secrets_describe_secret",
                              {"SecretId": get("secret")})
        if step == 7:
            return self._turn("s7", "lambda_get_function_configuration",
                              {"FunctionName": get("function")})
        if step == 8:
            return self._turn("s8", "logs_get_log_events",
                              {"logGroupName": get("log_group"),
                               "logStreamName": get("log_stream")})
        user_name = _data(observations, 2, "user_name")
        key_id = getattr(self, "_key_id", None) or \
            _first(_data(observations, 3, "access_keys"))["access_key_id"]
        refs = tuple(obs.request_id for obs in observations[:3])
        return ModelTurn(final_answer=AgentFinalAnswer(
            compromised_principal=user_name,
            compromised_access_key_id=key_id,
            confidence=0.8,
            findings=("anomalous object access observed",
                      "key state inspected through tools",
                      "policy and metadata corroborate access"),
            evidence_refs=refs,
            recommended_action=RecommendedAction(
                tool_id="update_access_key",
                arguments={"UserName": user_name,
                           "AccessKeyId": key_id,
                           "Status": "Inactive"},
                reason="disable the key observed in anomalous access"),
            rationale_summary="tool-observed access plus key state"))

    @staticmethod
    def _turn(call_id, tool_id, arguments):
        return ModelTurn(tool_calls=[AgentToolCall(
            call_id=call_id, tool_id=tool_id, arguments=arguments,
            justification="scripted investigation step")])
