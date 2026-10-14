"""M7C-C scenario-scoped containment target. No model calls."""

import pytest

from cloudsec_agent.agent.models import RecommendedAction
from cloudsec_agent.backend.approval import FakeApprovalProvider
from cloudsec_agent.backend.broker import BROAD_CAPABILITY, grant_for
from cloudsec_agent.backend.executor import ContainmentExecutor
from cloudsec_agent.backend.policy import ScenarioPolicyContext
from cloudsec_agent.integration.containment_bridge import (
    ContainmentBridge, ContainmentBridgeError)
from cloudsec_agent.integration.containment_scope import (
    ContainmentScope, derive_containment_scope)
from cloudsec_agent.scenario.generator import generate_scenario
from test_agent_containment_integration import (
    FakeExecutionPort, _approval)


USER = "synth-target-user"
KEY = "AKIA-SYNTH-M7CC-01"
OTHER_USER = "synth-other-user"
OTHER_KEY = "AKIA-SYNTH-M7CC-02"


def _spec(family="credential_compromise", seed=1, difficulty="easy"):
    return generate_scenario("m7a-v1", seed, family, difficulty)


def _scope(spec=None):
    return derive_containment_scope(spec or _spec())


def _action(user=USER, key=KEY, status="Inactive"):
    return RecommendedAction(
        tool_id="update_access_key",
        arguments={"UserName": user, "AccessKeyId": key, "Status": status},
        reason="test containment")


def _bridge(run_id="run-c"):
    return ContainmentBridge(run_id=run_id, actor="test-agent",
                             scenario_id="test-scenario",
                             run_scope=f"{run_id}:contain")


def _context_for(user, key):
    return ScenarioPolicyContext(scenario_id="test-scenario",
                                 incident_user=user,
                                 compromised_access_key_id=key)


class TestScopeDerivation:
    def test_malicious_scope_targets_incident_identity(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        assert scope.has_target is True
        assert scope.allowed_user_name == spec.incident_user
        assert scope.allowed_user_arn.endswith(f"/{spec.incident_user}")

    def test_benign_scope_has_no_target(self):
        spec = _spec(family="benign", seed=31)
        scope = derive_containment_scope(spec)
        assert scope.has_target is False
        assert scope.allowed_user_name is None

    def test_deterministic_scope(self):
        assert _scope().digest() == _scope().digest()

    def test_truth_changes_do_not_alter_scope(self):
        from cloudsec_agent.scenario.generator import models as gm
        spec = _spec()
        altered_truth = gm.GroundTruth(
            malicious=True, principal="someone-else",
            key_owner="someone-else",
            action_tool_id="other_action",
            action_arguments={"UserName": "someone-else"},
            actor_to_principal={}, label=spec.ground_truth.label)
        altered = gm.GeneratedScenario(
            generator_version=spec.generator_version, seed=spec.seed,
            family=spec.family, difficulty=spec.difficulty,
            scenario_id=spec.scenario_id, bucket=spec.bucket,
            incident_user=spec.incident_user,
            investigator_user=spec.investigator_user,
            incident_policy=spec.incident_policy,
            secret_name=spec.secret_name,
            function_name=spec.function_name,
            log_group=spec.log_group, log_stream=spec.log_stream,
            objects=spec.objects, log_events=spec.log_events,
            ground_truth=altered_truth, expected=spec.expected,
            manifest=spec.manifest, briefing_text=spec.briefing_text)
        assert derive_containment_scope(altered).digest() == \
            _scope().digest()

    def test_no_wildcard_resources(self):
        capability = _scope().to_capability()
        for tool_id in capability.tool_ids:
            for resource in capability.resources_for(tool_id):
                assert "*" not in resource
                assert "?" not in resource


class TestPrepareGate:
    def test_c1_m1_default_unchanged(self):
        bridge = _bridge()
        prepared = bridge.prepare("a1", _action("incident-user",
                                                "AKIA-M1-KEY-01"),
                                  "incident-user", "AKIA-M1-KEY-01")
        assert prepared.request.arguments["Status"] == "Inactive"

    def test_c2_generated_valid_target(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        bridge = _bridge()
        prepared = bridge.prepare("a1", _action(spec.incident_user, KEY),
                                  spec.incident_user, KEY,
                                  containment_scope=scope)
        assert prepared.request.tool_id == "update_access_key"

    def test_c3_wrong_generated_user(self):
        scope = _scope()
        bridge = _bridge()
        with pytest.raises(ContainmentBridgeError) as excinfo:
            bridge.prepare("a1", _action(OTHER_USER, OTHER_KEY),
                           OTHER_USER, OTHER_KEY,
                           containment_scope=scope)
        assert excinfo.value.code in ("discovery_mismatch",
                                      "no_authorized_target")

    def test_c4_investigator_rejected(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        bridge = _bridge()
        with pytest.raises(ContainmentBridgeError):
            bridge.prepare("a1", _action(spec.investigator_user, KEY),
                           spec.investigator_user, KEY,
                           containment_scope=scope)

    def test_c8_benign_scope_rejects(self):
        scope = derive_containment_scope(_spec(family="benign", seed=31))
        bridge = _bridge()
        with pytest.raises(ContainmentBridgeError) as excinfo:
            bridge.prepare("a1", _action(USER, KEY), USER, KEY,
                           containment_scope=scope)
        assert excinfo.value.code == "no_authorized_target"

    def test_c10_cross_seed_isolation(self):
        first = derive_containment_scope(_spec(seed=1))
        second = derive_containment_scope(_spec(seed=3))
        assert first.digest() != second.digest()
        bridge = _bridge()
        with pytest.raises(ContainmentBridgeError):
            bridge.prepare("a1", _action(second.allowed_user_name, KEY),
                           second.allowed_user_name, KEY,
                           containment_scope=first)


class TestSubmitSemantics:
    def _submit(self, user, key, store, scope, approval_digest=None):
        bridge = _bridge(run_id="run-submit")
        action = _action(user, key)
        prepared = bridge.prepare("a1", action, user, key,
                                  containment_scope=scope)
        provider = FakeApprovalProvider(
            [_approval(prepared.digest)])
        fake = FakeExecutionPort(store)
        executor = ContainmentExecutor(fake)
        outcome = bridge.submit(
            prepared,
            grant=grant_for(scope.to_capability(), "run-submit:contain"),
            policy_context=_context_for(user, key),
            approval_provider=provider, executor=executor,
            protected_user="guard-user", protected_key_id="GUARDKEY01",
            approval_ref="appr-1", current_time=1)
        return outcome, fake

    def test_c18_confirmed_path(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        store = {spec.incident_user: {KEY: "Active"},
                 "guard-user": {"GUARDKEY01": "Active"}}
        outcome, _ = self._submit(spec.incident_user, KEY, store, scope)
        assert outcome.classification == "confirmed"
        assert outcome.executed is True and outcome.effective is True

    def test_c5_wrong_key_cannot_execute(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        store = {spec.incident_user: {OTHER_KEY: "Active"},
                 "guard-user": {"GUARDKEY01": "Active"}}
        outcome, fake = self._submit(spec.incident_user, KEY, store, scope)
        assert outcome.classification != "confirmed"
        assert fake.states[spec.incident_user] == {OTHER_KEY: "Active"}
        assert (spec.incident_user, KEY, "Inactive") not in fake.mutations

    def test_c17_already_effective(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        store = {spec.incident_user: {KEY: "Inactive"},
                 "guard-user": {"GUARDKEY01": "Active"}}
        outcome, _ = self._submit(spec.incident_user, KEY, store, scope)
        assert outcome.classification == "already_effective"
        assert outcome.executed is False and outcome.effective is True

    def test_c19_investigator_preserved(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        store = {spec.incident_user: {KEY: "Active"},
                 "guard-user": {"GUARDKEY01": "Active"}}
        outcome, fake = self._submit(spec.incident_user, KEY, store, scope)
        assert outcome.classification == "confirmed"
        assert fake.states["guard-user"] == {"GUARDKEY01": "Active"}
        assert fake.states[spec.incident_user] == {KEY: "Inactive"}

    def test_c6_wrong_status_rejected(self):
        scope = _scope()
        bridge = _bridge()
        with pytest.raises(ContainmentBridgeError):
            bridge.prepare("a1", _action(USER, KEY, status="Active"),
                           USER, KEY, containment_scope=scope)

    def test_c7_wrong_action_rejected(self):
        from cloudsec_agent.agent.models import RecommendedAction as RA
        scope = _scope()
        bridge = _bridge()
        with pytest.raises(ContainmentBridgeError):
            bridge.prepare("a1", RA(tool_id="iam_get_user",
                                    arguments={}, reason="x"),
                           USER, KEY, containment_scope=scope)


class TestApprovalSemantics:
    def test_c14_approval_mandatory(self):
        from cloudsec_agent.backend.approval import FakeApprovalProvider
        spec = _spec()
        scope = derive_containment_scope(spec)
        bridge = _bridge(run_id="run-noappr")
        prepared = bridge.prepare("a1", _action(spec.incident_user, KEY),
                                  spec.incident_user, KEY,
                                  containment_scope=scope)
        store = {spec.incident_user: {KEY: "Active"},
                 "guard-user": {"GUARDKEY01": "Active"}}
        outcome = bridge.submit(
            prepared,
            grant=grant_for(scope.to_capability(), "run-noappr:contain"),
            policy_context=_context_for(spec.incident_user, KEY),
            approval_provider=FakeApprovalProvider([]),
            executor=ContainmentExecutor(FakeExecutionPort(store)),
            protected_user="guard-user", protected_key_id="GUARDKEY01",
            approval_ref="appr-x", current_time=1)
        assert outcome.classification != "confirmed"
        assert store[spec.incident_user] == {KEY: "Active"}

    def test_c15_digest_binding(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        bridge = _bridge(run_id="run-bind")
        prepared = bridge.prepare("a1", _action(spec.incident_user, KEY),
                                  spec.incident_user, KEY,
                                  containment_scope=scope)
        other = bridge.prepare("a2", _action(spec.incident_user,
                                               OTHER_KEY),
                               spec.incident_user, OTHER_KEY,
                               containment_scope=scope)
        assert prepared.digest != other.digest
        provider = FakeApprovalProvider(
            [_approval(other.digest, approval_id="appr-x")])
        store = {spec.incident_user: {KEY: "Active"},
                 "guard-user": {"GUARDKEY01": "Active"}}
        outcome = bridge.submit(
            prepared,
            grant=grant_for(scope.to_capability(), "run-bind:contain"),
            policy_context=_context_for(spec.incident_user, KEY),
            approval_provider=provider,
            executor=ContainmentExecutor(FakeExecutionPort(store)),
            protected_user="guard-user", protected_key_id="GUARDKEY01",
            approval_ref="appr-x", current_time=1)
        assert outcome.classification != "confirmed"

    def test_c16_single_use(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        bridge = _bridge(run_id="run-once")
        prepared = bridge.prepare("a1", _action(spec.incident_user, KEY),
                                  spec.incident_user, KEY,
                                  containment_scope=scope)
        provider = FakeApprovalProvider(
            [_approval(prepared.digest, approval_id="appr-x")])
        store = {spec.incident_user: {KEY: "Active"},
                 "guard-user": {"GUARDKEY01": "Active"}}
        first_kwargs = dict(
            grant=grant_for(scope.to_capability(), "run-once:contain"),
            policy_context=_context_for(spec.incident_user, KEY),
            approval_provider=provider,
            executor=ContainmentExecutor(FakeExecutionPort(store)),
            protected_user="guard-user", protected_key_id="GUARDKEY01",
            approval_ref="appr-x", current_time=1)
        first = bridge.submit(prepared, **first_kwargs)
        assert first.classification == "confirmed"
        second = bridge.submit(prepared, **first_kwargs)
        assert second.classification != "confirmed"


class TestAuditAndVisibility:
    def test_audit_semantics(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        bridge = _bridge(run_id="run-audit")
        prepared = bridge.prepare("a1", _action(spec.incident_user, KEY),
                                  spec.incident_user, KEY,
                                  containment_scope=scope)
        provider = FakeApprovalProvider(
            [_approval(prepared.digest, approval_id="appr-x")])
        store = {spec.incident_user: {KEY: "Active"},
                 "guard-user": {"GUARDKEY01": "Active"}}
        outcome = bridge.submit(
            prepared,
            grant=grant_for(scope.to_capability(), "run-audit:contain"),
            policy_context=_context_for(spec.incident_user, KEY),
            approval_provider=provider,
            executor=ContainmentExecutor(FakeExecutionPort(store)),
            protected_user="guard-user", protected_key_id="GUARDKEY01",
            approval_ref="appr-x", current_time=1)
        assert outcome.classification == "confirmed"
        assert outcome.executed is True and outcome.effective is True
        kinds = [event.kind.value for event in bridge.events]
        assert "CONTAINMENT_SUBMITTED" in kinds
        assert "CONTAINMENT_RESULT" in kinds

    def test_c9_scope_not_model_visible(self):
        scope = _scope()
        blob = repr(scope.as_dict())
        assert "malicious" not in blob
        assert "compromised" not in blob
        assert "update_access_key" not in blob

    def test_resource_ref_deterministic(self):
        from cloudsec_agent.backend.audit import audit_resource_ref
        from cloudsec_agent.backend.registry import Category
        ref = "arn:aws:iam::000000000000:user/synth-u"
        first = audit_resource_ref("update_access_key",
                                   Category.STATE_CHANGING, ref)
        second = audit_resource_ref("update_access_key",
                                    Category.STATE_CHANGING, ref)
        assert first == second and first

    def test_c13_investigation_scope_unchanged(self):
        from cloudsec_agent.integration.investigation_scope import (
            derive_investigation_scope)
        scope = derive_investigation_scope(_spec())
        assert "update_access_key" not in scope.tool_ids
        assert "iam_list_users" in scope.tool_ids


class TestComposedGeneratedContainment:
    def test_full_path_confirms_then_rejects_foreign(self):
        spec = _spec()
        scope = derive_containment_scope(spec)
        bridge = _bridge(run_id="run-full")
        store = {spec.incident_user: {KEY: "Active"},
                 "guard-user": {"GUARDKEY01": "Active"}}
        prepared = bridge.prepare("a1", _action(spec.incident_user, KEY),
                                  spec.incident_user, KEY,
                                  containment_scope=scope)
        provider = FakeApprovalProvider(
            [_approval(prepared.digest, approval_id="appr-x")])
        fake = FakeExecutionPort(store)
        outcome = bridge.submit(
            prepared,
            grant=grant_for(scope.to_capability(), "run-full:contain"),
            policy_context=_context_for(spec.incident_user, KEY),
            approval_provider=provider,
            executor=ContainmentExecutor(fake),
            protected_user="guard-user", protected_key_id="GUARDKEY01",
            approval_ref="appr-x", current_time=1)
        assert outcome.classification == "confirmed"
        assert fake.states[spec.incident_user] == {KEY: "Inactive"}
        stranger = _spec(seed=3)
        with pytest.raises(ContainmentBridgeError):
            bridge.prepare("a2", _action(stranger.incident_user, KEY),
                           stranger.incident_user, KEY,
                           containment_scope=scope)
        assert store[stranger.incident_user] if stranger.incident_user \
            in store else True
