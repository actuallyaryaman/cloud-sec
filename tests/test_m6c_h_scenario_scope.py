"""M7C-H scenario-scoped investigation capability. No model calls."""

import pytest

from cloudsec_agent.agent.tool_port import BackendToolRequest
from cloudsec_agent.backend import broker as bk
from cloudsec_agent.backend.registry import READ_ONLY_SPECS
from cloudsec_agent.integration.agent_backend import RealBackendToolPort
from cloudsec_agent.integration.investigation_scope import (
    InvestigationScope, derive_investigation_scope)
from cloudsec_agent.integration.read_port import FakeReadPort
from cloudsec_agent.scenario.generator import generate_scenario


def _spec(family="credential_compromise", seed=1, difficulty="easy"):
    return generate_scenario("m7a-v1", seed, family, difficulty)


def _invoke(port, tool_id, arguments, index=0, run_id="run-h"):
    return port.execute(BackendToolRequest(
        request_id=f"{run_id}:req:{index:04d}", tool_id=tool_id,
        arguments=dict(arguments), actor="harness",
        scenario_id="test-scenario", justification="m7c-h"))


def _port(run_id="run-h", capability=None):
    reads = FakeReadPort(lambda method, kwargs: {"ok": True})
    kwargs = {"run_scope": run_id, "actor": "harness",
              "scenario_id": "test-scenario"}
    if capability is not None:
        kwargs["capability"] = capability
    return reads, RealBackendToolPort(reads, **kwargs)


def _scope(family="credential_compromise", seed=1, difficulty="easy"):
    return derive_investigation_scope(_spec(family, seed, difficulty))


class TestScopeDeterminism:
    def test_h1_identical_grants(self):
        first = _scope()
        second = _scope()
        assert first.digest() == second.digest()
        assert first.tool_ids == second.tool_ids
        for tool_id in first.tool_ids:
            assert first.resources_for(tool_id) == \
                second.resources_for(tool_id)

    def test_h2_different_resources_differ(self):
        first = _scope(seed=1)
        second = _scope(seed=3)
        assert first.digest() != second.digest()
        assert (first.resources_for("s3_list_objects") !=
                second.resources_for("s3_list_objects"))


class TestHiddenTruthIndependence:
    def _retargeted(self, **truth_overrides):
        from cloudsec_agent.scenario.generator import models as gm
        spec = _spec()
        truth = spec.ground_truth
        altered = gm.GroundTruth(
            malicious=truth_overrides.get("malicious", truth.malicious),
            principal=truth_overrides.get("principal", truth.principal),
            key_owner=truth_overrides.get("key_owner", truth.key_owner),
            action_tool_id=truth_overrides.get("action_tool_id",
                                               truth.action_tool_id),
            action_arguments=truth_overrides.get(
                "action_arguments", truth.action_arguments),
            actor_to_principal=truth_overrides.get(
                "actor_to_principal", truth.actor_to_principal),
            label=truth.label)
        return spec, altered

    def test_h3_label_independence(self):
        scope = derive_investigation_scope(_spec())
        spec, _ = self._retargeted(malicious=False)
        assert derive_investigation_scope(spec).digest() == scope.digest()

    def test_h4_principal_independence(self):
        scope = derive_investigation_scope(_spec())
        spec, _ = self._retargeted(principal="someone-else")
        assert derive_investigation_scope(spec).digest() == scope.digest()

    def test_h5_key_independence(self):
        scope = derive_investigation_scope(_spec())
        spec, _ = self._retargeted(key_owner="someone-else")
        assert derive_investigation_scope(spec).digest() == scope.digest()

    def test_h6_action_independence(self):
        scope = derive_investigation_scope(_spec())
        spec, _ = self._retargeted(action_tool_id="other_action")
        assert derive_investigation_scope(spec).digest() == scope.digest()


class TestGrantHygiene:
    def test_h7_exact_resources_only(self):
        scope = _scope()
        capability = scope.to_capability()
        for tool_id in capability.tool_ids:
            for resource in capability.resources_for(tool_id):
                assert "*" not in resource
                assert "?" not in resource
                assert "$" not in resource

    def test_h14_no_mutation_tools(self):
        scope = _scope()
        assert "update_access_key" not in scope.tool_ids
        assert scope.to_capability().tool_ids.isdisjoint(
            {"update_access_key"})

    def test_h15_no_secret_value_tool(self):
        scope = _scope()
        assert "get_secret_value" not in scope.tool_ids


class TestBrokerBehavior:
    def _allowed_port(self, seed=1):
        scope = _scope(seed=seed)
        _, port = _port(run_id=f"run-h-{seed}",
                        capability=scope.to_capability())
        return scope, port

    def test_h8_ten_reads_allowed(self):
        spec = _spec()
        _, port = self._allowed_port()
        calls = [
            ("s3_list_objects", {"Bucket": spec.bucket}),
            ("s3_get_object", {"Bucket": spec.bucket,
                               "Key": spec.objects[0].key}),
            ("iam_list_users", {}),
            ("iam_get_user", {"UserName": spec.incident_user}),
            ("iam_list_access_keys", {"UserName": spec.incident_user}),
            ("iam_list_user_policies", {"UserName": spec.incident_user}),
            ("iam_get_user_policy",
             {"UserName": spec.incident_user,
              "PolicyName": spec.incident_policy}),
            ("secrets_describe_secret", {"SecretId": spec.secret_name}),
            ("logs_get_log_events", {"logGroupName": spec.log_group,
                                     "logStreamName": spec.log_stream}),
            ("lambda_get_function_configuration",
             {"FunctionName": spec.function_name}),
        ]
        for index, (tool_id, arguments) in enumerate(calls):
            outcome = _invoke(port, tool_id, arguments, index)
            assert outcome.ok is True, (tool_id, outcome.classification)

    def test_h9_wrong_seed_resource_denied(self):
        _, port = self._allowed_port(seed=1)
        other = _spec(seed=3)
        outcome = _invoke(port, "s3_list_objects",
                          {"Bucket": other.bucket}, 0)
        assert outcome.ok is False
        assert outcome.classification == "broker_denied"

    def test_h10_cross_seed_isolation(self):
        first = _scope(seed=1)
        second = _scope(seed=3)
        assert first.digest() != second.digest()
        assert first.resources_for("s3_list_objects").isdisjoint(
            second.resources_for("s3_list_objects"))

    def test_h11_unknown_username_denied(self):
        _, port = self._allowed_port()
        outcome = _invoke(port, "iam_get_user",
                          {"UserName": "invented-user"}, 0)
        assert outcome.ok is False
        assert outcome.classification == "broker_denied"

    def test_h12_known_generated_user_allowed(self):
        spec = _spec()
        _, port = self._allowed_port()
        outcome = _invoke(port, "iam_get_user",
                          {"UserName": spec.incident_user}, 0)
        assert outcome.ok is True

    def test_h13_list_users_preserved(self):
        _, port = self._allowed_port()
        outcome = _invoke(port, "iam_list_users", {}, 0)
        assert outcome.ok is True


class TestComposedBrokerRegression:
    def test_generated_path_reaches_backend(self):
        spec = _spec()
        scope = derive_investigation_scope(spec)
        reads, port = _port(run_id="run-composed",
                            capability=scope.to_capability())
        sequence = [
            ("s3_list_objects", {"Bucket": spec.bucket}),
            ("logs_get_log_events", {"logGroupName": spec.log_group,
                                     "logStreamName": spec.log_stream}),
            ("iam_list_users", {}),
            ("iam_list_access_keys", {"UserName": spec.incident_user}),
            ("iam_get_user", {"UserName": spec.incident_user}),
        ]
        for index, (tool_id, arguments) in enumerate(sequence):
            outcome = _invoke(port, tool_id, arguments, index,
                              run_id="run-composed")
            assert outcome.ok is True, (tool_id, outcome.classification)
        methods = [method for method, _ in reads.calls]
        assert methods == ["list_objects", "get_log_events", "list_users",
                           "list_access_keys", "get_user"]
        stranger = _spec(seed=3)
        denied = _invoke(port, "iam_get_user",
                         {"UserName": stranger.incident_user}, 99,
                         run_id="run-composed")
        assert denied.ok is False
        assert denied.classification == "broker_denied"

    def test_m1_default_path_unchanged(self):
        from cloudsec_agent.scenario import determinism as d
        reads, port = _port(run_id="run-m1-check")
        outcome = _invoke(port, "s3_list_objects",
                          {"Bucket": d.RESOURCES.incident_bucket}, 0,
                          run_id="run-m1-check")
        assert outcome.ok is True
