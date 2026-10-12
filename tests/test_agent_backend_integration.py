"""Pure tests for RealBackendToolPort against a fake read port."""

import pytest

from cloudsec_agent.agent.tool_port import BackendToolRequest, ToolResult
from cloudsec_agent.backend.audit import AuditStage
from cloudsec_agent.backend.broker import TASK_SCOPED_CAPABILITY
from cloudsec_agent.integration.agent_backend import (
    RealBackendToolPort, canonical_read_resource)
from cloudsec_agent.integration.read_port import (
    BackendReadPort, FakeReadPort, ReadPortError)
from cloudsec_agent.scenario import determinism as d

USER = d.RESOURCES.incident_user
BUCKET = d.RESOURCES.incident_bucket
EVIDENCE_BUCKET = d.RESOURCES.evidence_bucket
SECRET = d.RESOURCES.secret_name


def _port(handler, run_scope="run-pure-1", **kwargs):
    return RealBackendToolPort(FakeReadPort(handler), run_scope=run_scope,
                               actor="test-actor",
                               scenario_id="test-scenario", **kwargs)


def _invoke(tool_id, arguments, request_id="run-pure-1:req:0000"):
    return BackendToolRequest(request_id=request_id, tool_id=tool_id,
                              arguments=arguments, actor="agent",
                              scenario_id="local", justification="triage")


def _ok(handler_data):
    def handler(method, kwargs):
        return dict(handler_data)
    return handler


class TestRequestConversion:
    def test_allowed_read_executes_and_preserves_request_id(self):
        port = _port(_ok({"user_name": USER}))
        request_id = "run-pure-1:req:0007"
        outcome = port.execute(_invoke("iam_get_user", {"UserName": USER},
                                       request_id))
        assert outcome.ok is True
        assert outcome.classification == "success"
        assert outcome.data["user_name"] == USER
        assert [record.request_id for record in port.audits] == \
            [request_id] * 3
        assert {record.run_id for record in port.audits} == {"run-pure-1"}

    def test_read_arguments_reach_read_port(self):
        seen = {}

        def handler(method, kwargs):
            seen.update(kwargs)
            return {"user_name": kwargs["user_name"]}
        port = _port(handler)
        port.execute(_invoke("iam_get_user", {"UserName": USER}))
        assert seen == {"user_name": USER}

    def test_unknown_tool_rejected_without_read_or_audit(self):
        port = _port(_ok({}))
        outcome = port.execute(_invoke("wipe_everything", {}))
        assert outcome.ok is False
        assert outcome.classification == "validation_error"
        assert port.audits == ()

    def test_invalid_arguments_rejected(self):
        port = _port(_ok({}))
        outcome = port.execute(_invoke("iam_get_user", {"Bogus": 1}))
        assert outcome.classification == "validation_error"
        assert port.audits == ()


class TestAuthorizationMapping:
    def test_broker_denial_maps_safely(self):
        port = _port(_ok({}))
        outcome = port.execute(_invoke("iam_get_user",
                                       {"UserName": "unrelated-worker"}))
        assert outcome.ok is False
        assert outcome.classification == "broker_denied"
        assert outcome.safe_error == "broker denied the request"
        assert "unrelated-worker" not in outcome.safe_error
        stages = [record.stage for record in port.audits]
        assert stages == [AuditStage.CANONICALIZED,
                          AuditStage.BROKER_DECIDED]

    def test_state_changing_tool_refused_without_execution(self):
        calls = []

        def handler(method, kwargs):
            calls.append(method)
            return {}
        port = _port(handler)
        outcome = port.execute(_invoke(
            "update_access_key",
            {"UserName": USER, "AccessKeyId": "K", "Status": "Inactive"}))
        assert outcome.classification == "refused_state_changing"
        assert calls == []
        assert port.audits == ()

    def test_sensitive_read_denied_through_backend(self):
        port = _port(_ok({}))
        outcome = port.execute(_invoke("get_secret_value",
                                       {"SecretId": SECRET}))
        assert outcome.ok is False
        assert outcome.classification == "broker_denied"
        stages = [record.stage for record in port.audits]
        assert stages == [AuditStage.CANONICALIZED,
                          AuditStage.BROKER_DECIDED]
        ref = port.audits[0].resource_ref
        assert ref.startswith("sensitive:sha256:")

    def test_no_policy_stage_reached_for_reads(self):
        port = _port(_ok({"user_name": USER}))
        port.execute(_invoke("iam_get_user", {"UserName": USER}))
        assert all(record.stage is not AuditStage.POLICY_DECIDED
                   for record in port.audits)


class TestSafeProjection:
    def test_sdk_like_dict_is_projected(self):
        def handler(method, kwargs):
            return {"user_name": kwargs["user_name"],
                    "SecretAccessKey": "CANARY",
                    "ResponseMetadata": {"RequestId": "x"},
                    "credentials": {"k": "v"},
                    "handle": object()}
        port = _port(handler)
        outcome = port.execute(_invoke("iam_get_user", {"UserName": USER}))
        assert outcome.ok is True
        assert set(outcome.data) <= {"user_name", "truncated"}
        assert "CANARY" not in repr(outcome.data)

    def test_raw_exception_is_sanitized(self):
        def handler(method, kwargs):
            raise RuntimeError("boom SecretAccessKey=CANARY")
        port = _port(handler)
        outcome = port.execute(_invoke("iam_get_user", {"UserName": USER}))
        assert outcome.ok is False
        assert outcome.classification == "backend_error"
        assert outcome.safe_error == "read failed"
        assert "CANARY" not in repr(outcome)

    def test_read_port_denial_mapping(self):
        def handler(method, kwargs):
            raise ReadPortError("access_denied")
        port = _port(handler)
        outcome = port.execute(_invoke("iam_get_user", {"UserName": USER}))
        assert outcome.classification == "access_denied"
        assert outcome.safe_error == "backend denied the read"

    def test_read_port_not_found_mapping(self):
        def handler(method, kwargs):
            raise ReadPortError("not_found")
        port = _port(handler)
        outcome = port.execute(_invoke(
            "s3_get_object",
            {"Bucket": BUCKET, "Key": d.RESOURCES.notes_object}))
        assert outcome.classification == "not_found"

    def test_oversize_body_truncated_and_marked(self):
        port = _port(_ok({"body": "x" * 9000, "truncated": False}))
        outcome = port.execute(_invoke(
            "s3_get_object",
            {"Bucket": BUCKET, "Key": d.RESOURCES.notes_object}))
        assert outcome.ok is True
        assert len(outcome.data["body"]) == 2000
        assert outcome.data["truncated"] is True

    def test_excessive_list_truncated(self):
        port = _port(_ok({"keys": [f"k{i}" for i in range(250)],
                          "truncated": False}))
        outcome = port.execute(_invoke("s3_list_objects",
                                       {"Bucket": EVIDENCE_BUCKET}))
        assert len(outcome.data["keys"]) == 100
        assert outcome.data["truncated"] is True

    def test_no_client_reaches_agent_graph(self):
        def handler(method, kwargs):
            return {"client": object(), "SecretString": "CANARY"}
        port = _port(handler)
        outcome = port.execute(_invoke("secrets_describe_secret",
                                       {"SecretId": SECRET}))
        blob = repr(outcome) + repr(port.audits)
        assert "CANARY" not in blob
        assert "client" not in dict(outcome.data)

    def test_tool_result_contract_preserved(self):
        port = _port(_ok({"user_name": USER}))
        outcome = port.execute(_invoke("iam_get_user", {"UserName": USER}))
        assert isinstance(outcome, ToolResult)
        assert isinstance(port._reads, BackendReadPort)


class TestCanonicalResourcesPinnedToGrant:
    @pytest.mark.parametrize("tool_id,arguments", [
        ("s3_get_object", {"Bucket": d.RESOURCES.incident_bucket,
                           "Key": d.RESOURCES.notes_object}),
        ("s3_list_objects", {"Bucket": d.RESOURCES.evidence_bucket}),
        ("iam_get_user", {"UserName": d.RESOURCES.incident_user}),
        ("iam_list_access_keys", {"UserName": d.RESOURCES.incident_user}),
        ("iam_get_user_policy", {"UserName": d.RESOURCES.incident_user,
                                 "PolicyName": d.RESOURCES.incident_policy}),
        ("iam_list_user_policies",
         {"UserName": d.RESOURCES.incident_user}),
        ("secrets_describe_secret", {"SecretId": d.RESOURCES.secret_name}),
        ("logs_get_log_events", {"logGroupName": d.RESOURCES.log_group,
                                 "logStreamName": d.RESOURCES.log_stream}),
        ("lambda_get_function_configuration",
         {"FunctionName": d.RESOURCES.function_name}),
        ("iam_list_users", {}),
    ])
    def test_canonical_resource_is_granted(self, tool_id, arguments):
        resource = canonical_read_resource(tool_id, arguments)
        assert resource in TASK_SCOPED_CAPABILITY.resources_for(tool_id)

    def test_grant_covers_only_reads(self):
        assert "update_access_key" not in TASK_SCOPED_CAPABILITY.tool_ids
        assert "get_secret_value" not in TASK_SCOPED_CAPABILITY.tool_ids
        assert len(TASK_SCOPED_CAPABILITY.tool_ids) == 10
