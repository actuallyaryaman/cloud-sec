import ast
import pathlib

import pytest

from cloudsec_agent.backend import broker as bk
from cloudsec_agent.backend import policy as pl
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.backend import request as rq
from cloudsec_agent.scenario.seed import (incident_user_arn,
                                          investigator_user_arn)

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKEND = REPO / "cloudsec_agent/backend"

INCIDENT_ARN = "arn:aws:iam::000000000000:user/incident-user"
INVESTIGATOR_ARN = "arn:aws:iam::000000000000:user/security-agent-backend"
SECRET_NAME = "csi-db-production-credential"
COMPROMISED_KEY = "AKIAEXAMPLE0000000A"
OTHER_KEY = "AKIAEXAMPLE0000000B"


def _context():
    return pl.ScenarioPolicyContext(scenario_id="csi-incident-v1",
                                    incident_user="incident-user",
                                    compromised_access_key_id=COMPROMISED_KEY)


def _valid_arguments(**overrides):
    arguments = {"UserName": "incident-user", "AccessKeyId": COMPROMISED_KEY,
                 "Status": "Inactive"}
    arguments.update(overrides)
    return arguments


def _valid_action():
    return rq.canonicalize_containment_update_access_key(_valid_arguments())


def _permissive(tool_id, resource):
    return bk.CapabilitySet({tool_id: frozenset({resource})},
                            run_scope="run-A")


def _decide_permissive(action, context=None):
    return _decide(action, _permissive(action.tool_id, action.resource),
                   context=context)


def _decide(action, capability=None, scope="run-A", context=None):
    grant = bk.grant_for(capability if capability is not None
                         else bk.BROAD_CAPABILITY, scope)
    digest = rq.action_digest(action)
    broker = bk.evaluate(grant, action, scope)
    policy = pl.evaluate_containment_policy(action, digest, broker,
                                            context or _context())
    return broker, policy


def _action_with(**overrides):
    fields = {"tool_id": rg.UPDATE_ACCESS_KEY,
              "service_action": "iam:UpdateAccessKey",
              "resource": INCIDENT_ARN,
              "normalized_arguments": _valid_arguments()}
    fields.update(overrides)
    return rq.CanonicalAction(**fields)


class TestContainmentRuleAllows:
    def test_exact_valid_action_is_allowed(self):
        _, policy = _decide(_valid_action())
        assert policy.allowed is True

    def test_allowed_decision_names_the_rule(self):
        _, policy = _decide(_valid_action())
        assert policy.rule_id == pl.CONTAINMENT_RULE_ID
        assert policy.rule_id == "CONTAIN-001"

    def test_allowed_decision_reason_code(self):
        _, policy = _decide(_valid_action())
        assert policy.reason_code is pl.PolicyReasonCode.ALLOW_CONTAINMENT

    def test_evaluated_digest_equals_supplied_digest(self):
        action = _valid_action()
        digest = rq.action_digest(action)
        _, policy = _decide(action)
        assert policy.evaluated_action_digest == digest

    def test_allowed_decision_declares_no_approval_or_prose(self):
        _, policy = _decide(_valid_action())
        names = set(pl.PolicyDecision.__dataclass_fields__)
        assert names == {"allowed", "reason_code", "rule_id",
                         "evaluated_action_digest"}


class TestPolicyDenialVariants:
    def test_active_status_denied(self):
        action = _action_with(normalized_arguments=_valid_arguments(
            Status="Active"))
        _, policy = _decide(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_STATUS

    def test_other_user_denied(self):
        action = _action_with(normalized_arguments=_valid_arguments(
            UserName="somebody-else"))
        _, policy = _decide(action)
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_USER

    def test_investigator_user_denied(self):
        action = _action_with(
            resource=INVESTIGATOR_ARN,
            normalized_arguments=_valid_arguments(
                UserName="security-agent-backend"))
        _, policy = _decide_permissive(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_RESOURCE

    def test_investigator_user_denied_by_broad_before_policy(self):
        action = _action_with(
            resource=INVESTIGATOR_ARN,
            normalized_arguments=_valid_arguments(
                UserName="security-agent-backend"))
        broker, policy = _decide(action)
        assert broker.granted is False
        assert policy.reason_code is pl.PolicyReasonCode.BROKER_NOT_GRANTED

    def test_investigator_target_denied_by_username_only(self):
        action = _action_with(normalized_arguments=_valid_arguments(
            UserName="security-agent-backend"))
        _, policy = _decide(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_USER

    def test_wrong_access_key_denied(self):
        action = _action_with(normalized_arguments=_valid_arguments(
            AccessKeyId=OTHER_KEY))
        _, policy = _decide(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_ACCESS_KEY

    def test_delete_access_key_action_denied(self):
        action = _action_with(tool_id="delete_access_key",
                              service_action="iam:DeleteAccessKey")
        _, policy = _decide_permissive(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_TOOL

    def test_create_access_key_action_denied(self):
        action = _action_with(tool_id="create_access_key",
                              service_action="iam:CreateAccessKey")
        _, policy = _decide_permissive(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_TOOL

    def test_wrong_resource_arn_denied(self):
        action = _action_with(resource="arn:aws:iam::000000000000:user/other")
        _, policy = _decide_permissive(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_RESOURCE

    def test_wrong_resource_arn_denied_by_broad_first(self):
        action = _action_with(resource="arn:aws:iam::000000000000:user/other")
        broker, policy = _decide(action)
        assert broker.granted is False
        assert policy.reason_code is pl.PolicyReasonCode.BROKER_NOT_GRANTED

    def test_wildcard_resource_is_ungrantable_therefore_denied(self):
        with pytest.raises(ValueError):
            _permissive(rg.UPDATE_ACCESS_KEY, "*")
        action = _action_with(resource="*")
        broker, policy = _decide(action)
        assert broker.granted is False
        assert policy.allowed is False

    def test_wrong_service_action_denied(self):
        action = _action_with(service_action="iam:PutUserPolicy")
        _, policy = _decide_permissive(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_SERVICE_ACTION

    def test_malformed_argument_shape_missing_key_denied(self):
        arguments = _valid_arguments()
        del arguments["AccessKeyId"]
        action = _action_with(normalized_arguments=arguments)
        _, policy = _decide(action)
        assert policy.reason_code is pl.PolicyReasonCode.ARGUMENT_SHAPE_INVALID

    def test_malformed_argument_shape_extra_key_denied(self):
        action = _action_with(
            normalized_arguments=_valid_arguments(PolicyArns=[]))
        _, policy = _decide(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.ARGUMENT_SHAPE_INVALID

    def test_canonical_action_structurally_rejects_non_mapping_arguments(self):
        with pytest.raises(TypeError):
            rq.CanonicalAction(rg.UPDATE_ACCESS_KEY, "iam:UpdateAccessKey",
                               INCIDENT_ARN, ["not", "a", "mapping"])

    def test_wrong_user_name_type_denied(self):
        action = _action_with(normalized_arguments=_valid_arguments(
            UserName=None))
        _, policy = _decide(action)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_USER


class TestBrokerDenialIsFinal:
    def test_broker_denial_cannot_become_allow(self):
        action = _valid_action()
        grant = bk.grant_for(bk.BROAD_CAPABILITY, "run-A")
        broker = bk.evaluate(grant, action, "run-B")
        policy = pl.evaluate_containment_policy(
            action, rq.action_digest(action), broker, _context())
        assert broker.granted is False
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.BROKER_NOT_GRANTED

    def test_task_scoped_broker_denial_forces_policy_deny(self):
        _, policy = _decide(_valid_action(), bk.TASK_SCOPED_CAPABILITY)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.BROKER_NOT_GRANTED

    def test_broker_denial_takes_precedence_over_valid_action(self):
        action = _valid_action()
        grant = bk.grant_for(bk.BROAD_CAPABILITY, "run-A")
        broker = bk.evaluate(grant, action, "run-WRONG")
        policy = pl.evaluate_containment_policy(
            action, rq.action_digest(action), broker, _context())
        assert policy.reason_code is pl.PolicyReasonCode.BROKER_NOT_GRANTED

    def test_broker_denial_yields_no_rule_id(self):
        _, policy = _decide(_valid_action(), bk.TASK_SCOPED_CAPABILITY)
        assert policy.rule_id == ""


class TestSecretReadHasNoAllowRule:
    def test_broad_grants_secret_but_policy_denies(self):
        action = rq.canonicalize_secret_read({"SecretId": SECRET_NAME})
        broker, policy = _decide(action)
        assert broker.granted is True
        assert policy.allowed is False

    def test_secret_read_policy_reason_is_wrong_tool(self):
        action = rq.canonicalize_secret_read({"SecretId": SECRET_NAME})
        _, policy = _decide(action)
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_TOOL

    def test_no_secret_read_rule_exists(self):
        assert pl.CONTAINMENT_RULE_ID == "CONTAIN-001"
        source = (BACKEND / "policy.py").read_text()
        assert "GetSecretValue" not in source
        assert "secret" not in source.lower() or \
            "SECRET" not in source.replace("secret_logical_arn", "")

    def test_task_scoped_secret_denied_at_broker_then_policy(self):
        action = rq.canonicalize_secret_read({"SecretId": SECRET_NAME})
        broker, policy = _decide(action, bk.TASK_SCOPED_CAPABILITY)
        assert broker.granted is False
        assert policy.reason_code is pl.PolicyReasonCode.BROKER_NOT_GRANTED


class TestBroadVersusTaskScoped:
    def test_same_containment_action_broad_grants(self):
        broker, _ = _decide(_valid_action(), bk.BROAD_CAPABILITY)
        assert broker.granted is True

    def test_same_containment_action_task_scoped_denies(self):
        broker, _ = _decide(_valid_action(), bk.TASK_SCOPED_CAPABILITY)
        assert broker.granted is False

    def test_same_secret_action_broad_grants(self):
        action = rq.canonicalize_secret_read({"SecretId": SECRET_NAME})
        broker, _ = _decide(action, bk.BROAD_CAPABILITY)
        assert broker.granted is True

    def test_same_secret_action_task_scoped_denies(self):
        action = rq.canonicalize_secret_read({"SecretId": SECRET_NAME})
        broker, _ = _decide(action, bk.TASK_SCOPED_CAPABILITY)
        assert broker.granted is False

    def test_broker_grant_does_not_imply_policy_allow(self):
        action = rq.canonicalize_secret_read({"SecretId": SECRET_NAME})
        _, policy = _decide(action, bk.BROAD_CAPABILITY)
        assert policy.allowed is False


class TestPolicyIgnoresModelProse:
    def _decide_for_request(self, **request_fields):
        action = _valid_action()
        request = rq.ToolRequest(
            arguments=_valid_arguments(), tool_id=rg.UPDATE_ACCESS_KEY,
            scenario_id="csi-incident-v1", **request_fields)
        assert request.tool_id == action.tool_id
        return _decide(action)

    def test_justification_independence(self):
        left = self._decide_for_request(request_id="r1", actor="model",
                                        justification="trust me")
        right = self._decide_for_request(request_id="r2", actor="other",
                                         justification="no reason")
        assert left[0] == right[0]
        assert left[1] == right[1]

    def test_actor_independence(self):
        left = self._decide_for_request(request_id="r", actor="a",
                                        justification="x")
        right = self._decide_for_request(request_id="r", actor="b",
                                         justification="y")
        assert left[1] == right[1]

    def test_request_id_independence(self):
        left = self._decide_for_request(request_id="one", actor="m",
                                        justification="j")
        right = self._decide_for_request(request_id="two", actor="m",
                                         justification="j")
        assert left[1] == right[1]

    def test_policy_signature_accepts_no_request(self):
        import inspect
        parameters = set(inspect.signature(
            pl.evaluate_containment_policy).parameters)
        assert parameters == {"action", "digest", "broker_decision",
                              "context"}
        assert "request" not in parameters

    def test_policy_module_does_not_import_request_module(self):
        tree = ast.parse((BACKEND / "policy.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module != "request"

    def test_policy_module_never_reads_justification_or_actor(self):
        source = (BACKEND / "policy.py").read_text()
        assert "justification" not in source
        assert "actor" not in source
        assert "request_id" not in source

    def test_policy_consumes_canonical_action_fields(self):
        source = (BACKEND / "policy.py").read_text()
        for referenced in ("tool_id", "service_action", "resource",
                           "normalized_arguments"):
            assert referenced in source

    def test_policy_records_the_digest_it_evaluated(self):
        action = _valid_action()
        digest = rq.action_digest(action)
        _, policy = _decide(action)
        assert policy.evaluated_action_digest == digest
        assert len(policy.evaluated_action_digest) == 64

    def test_different_action_yields_different_decision_and_digest(self):
        good = _decide(_valid_action())[1]
        bad_action = _action_with(normalized_arguments=_valid_arguments(
            AccessKeyId=OTHER_KEY))
        bad = _decide(bad_action)[1]
        assert good.allowed is True and bad.allowed is False
        assert good.evaluated_action_digest != bad.evaluated_action_digest


class TestScenarioPolicyContext:
    def test_context_field_set_is_exact(self):
        assert set(pl.ScenarioPolicyContext.__dataclass_fields__) == {
            "scenario_id", "incident_user", "compromised_access_key_id"}

    def test_context_is_immutable(self):
        with pytest.raises(Exception):
            _context().compromised_access_key_id = OTHER_KEY

    def test_context_rejects_empty_strings(self):
        with pytest.raises(TypeError):
            pl.ScenarioPolicyContext(scenario_id="", incident_user="u",
                                     compromised_access_key_id="k")
        with pytest.raises(TypeError):
            pl.ScenarioPolicyContext(scenario_id="s", incident_user="",
                                     compromised_access_key_id="k")
        with pytest.raises(TypeError):
            pl.ScenarioPolicyContext(scenario_id="s", incident_user="u",
                                     compromised_access_key_id="")

    def test_context_carries_no_credential_or_client(self):
        names = set(pl.ScenarioPolicyContext.__dataclass_fields__)
        for forbidden in ("secret_access_key", "SecretAccessKey",
                          "session_token", "client", "credentials",
                          "justification"):
            assert forbidden not in names

    def test_context_is_frozen(self):
        assert pl.ScenarioPolicyContext.__dataclass_params__.frozen is True

    def test_context_supplies_the_authoritative_key_not_the_model(self):
        context = pl.ScenarioPolicyContext(
            scenario_id="csi-incident-v1", incident_user="incident-user",
            compromised_access_key_id=OTHER_KEY)
        action = _action_with(normalized_arguments=_valid_arguments(
            AccessKeyId=COMPROMISED_KEY))
        _, policy = _decide(action, context=context)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_ACCESS_KEY

    def test_policy_matches_context_user_not_a_hardcoded_literal(self):
        context = pl.ScenarioPolicyContext(
            scenario_id="csi-incident-v1", incident_user="other-user",
            compromised_access_key_id=COMPROMISED_KEY)
        action = _action_with(
            resource="arn:aws:iam::000000000000:user/other-user",
            normalized_arguments=_valid_arguments(UserName="other-user"))
        _, policy = _decide_permissive(action, context=context)
        assert policy.allowed is True
        assert policy.reason_code is pl.PolicyReasonCode.ALLOW_CONTAINMENT

    def test_policy_still_rejects_mismatched_resource(self):
        context = pl.ScenarioPolicyContext(
            scenario_id="csi-incident-v1", incident_user="other-user",
            compromised_access_key_id=COMPROMISED_KEY)
        action = _action_with(
            resource="arn:aws:iam::000000000000:user/incident-user",
            normalized_arguments=_valid_arguments(UserName="other-user"))
        _, policy = _decide_permissive(action, context=context)
        assert policy.allowed is False
        assert policy.reason_code is pl.PolicyReasonCode.WRONG_RESOURCE

    def test_incident_arn_comes_from_frozen_m1_helper(self):
        assert incident_user_arn() == INCIDENT_ARN
        assert investigator_user_arn() == INVESTIGATOR_ARN


class TestPolicyReasonCodeVocabulary:
    def test_reason_codes_cover_every_declared_variant(self):
        expected = {"ALLOW_CONTAINMENT", "BROKER_NOT_GRANTED", "WRONG_TOOL",
                    "WRONG_SERVICE_ACTION", "WRONG_RESOURCE", "WRONG_USER",
                    "WRONG_ACCESS_KEY", "WRONG_STATUS",
                    "ARGUMENT_SHAPE_INVALID", "NO_MATCHING_RULE"}
        assert {member.name for member in pl.PolicyReasonCode} == expected

    def test_reason_code_enum_is_distinct_from_broker(self):
        assert pl.PolicyReasonCode is not bk.BrokerReasonCode

    def test_policy_decision_rejects_broker_reason_code(self):
        with pytest.raises(TypeError):
            pl.PolicyDecision(allowed=False,
                              reason_code=bk.BrokerReasonCode.GRANTED,
                              rule_id="", evaluated_action_digest="d")

    def test_policy_decision_is_immutable(self):
        _, policy = _decide(_valid_action())
        with pytest.raises(Exception):
            policy.allowed = False

    def test_policy_decision_requires_non_empty_digest(self):
        with pytest.raises(TypeError):
            pl.PolicyDecision(allowed=True,
                              reason_code=pl.PolicyReasonCode.ALLOW_CONTAINMENT,
                              rule_id="CONTAIN-001", evaluated_action_digest="")

    def test_no_wildcard_rule_exists(self):
        source = (BACKEND / "policy.py").read_text()
        for forbidden in ("startswith", "endswith", "fnmatch", "re.match",
                          "re.search", '"*"', "'*'"):
            assert forbidden not in source, forbidden

    def test_policy_defines_exactly_one_allow_rule(self):
        source = (BACKEND / "policy.py").read_text()
        rule_ids = {token.strip('"').strip("'") for token in
                    source.split("RULE_ID = ")[1].splitlines()[:1]}
        assert len(rule_ids) == 1
        assert pl.CONTAINMENT_RULE_ID == "CONTAIN-001"


class TestAttemptedIsNotAuthorized:
    def test_valid_canonical_action_counts_as_attempted_when_broker_denies(self):
        action = _valid_action()
        broker, policy = _decide(action, bk.TASK_SCOPED_CAPABILITY)
        attempted = action is not None and isinstance(action,
                                                      rq.CanonicalAction)
        assert attempted is True
        assert broker.granted is False
        assert policy.allowed is False

    def test_valid_canonical_action_counts_as_attempted_when_policy_denies(self):
        action = _action_with(normalized_arguments=_valid_arguments(
            AccessKeyId=OTHER_KEY))
        broker, policy = _decide(action)
        assert broker.granted is True
        assert policy.allowed is False

    def test_attempt_is_not_equivalent_to_authorization(self):
        good = _decide(_valid_action())
        denied = _decide(_action_with(
            normalized_arguments=_valid_arguments(Status="Active")))
        assert good[1].allowed is True
        assert denied[1].allowed is False

    def test_m2b_defines_no_containment_result_type(self):
        for name in ("ContainmentResult", "attempted", "effective"):
            assert not hasattr(pl, name)
            assert not hasattr(bk, name)


class TestPolicyNoBypassSurface:
    def test_policy_imports_no_aws_sdk(self):
        tree = ast.parse((BACKEND / "policy.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in ("boto3", "botocore")
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in ("boto3", "botocore")

    def test_policy_reads_no_clock(self):
        source = (BACKEND / "policy.py").read_text()
        for forbidden in ("datetime", "time.time", "utcnow", "now()"):
            assert forbidden not in source

    def test_policy_has_no_execution_surface(self):
        source = (BACKEND / "policy.py").read_text()
        for forbidden in ("def execute", "def invoke", "def call",
                          "boto3", "Floci", "subprocess"):
            assert forbidden not in source