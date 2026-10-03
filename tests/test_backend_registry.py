import copy
import pathlib
import types

import pytest

from cloudsec_agent.backend import registry as rg
from cloudsec_agent.scenario import determinism as d

REPO = pathlib.Path(__file__).resolve().parents[1]

EXPECTED_READ_ONLY = {
    "s3_get_object": "s3:GetObject",
    "s3_list_objects": "s3:ListObjectsV2",
    "iam_get_user": "iam:GetUser",
    "iam_list_access_keys": "iam:ListAccessKeys",
    "iam_get_user_policy": "iam:GetUserPolicy",
    "iam_list_user_policies": "iam:ListUserPolicies",
    "secrets_describe_secret": "secretsmanager:DescribeSecret",
    "logs_get_log_events": "logs:GetLogEvents",
    "lambda_get_function_configuration": "lambda:GetFunctionConfiguration",
}


class TestCategoryEnum:
    def test_three_categories_exist(self):
        assert {member.name for member in rg.Category} == {
            "READ_ONLY", "SENSITIVE_READ", "STATE_CHANGING"}

    def test_category_is_descriptive_metadata(self):
        spec = rg.get_tool(rg.UPDATE_ACCESS_KEY)
        assert spec.category is rg.Category.STATE_CHANGING
        assert isinstance(spec.category, rg.Category)


class TestUpdateAccessKeyRegistration:
    def test_update_access_key_registered_as_state_changing(self):
        assert rg.get_tool(
            rg.UPDATE_ACCESS_KEY).category is rg.Category.STATE_CHANGING

    def test_update_access_key_service_action(self):
        assert rg.get_tool(
            rg.UPDATE_ACCESS_KEY).service_action == "iam:UpdateAccessKey"

    def test_update_access_key_requires_broker(self):
        assert rg.get_tool(rg.UPDATE_ACCESS_KEY).requires_broker is True

    def test_update_access_key_requires_policy(self):
        assert rg.get_tool(rg.UPDATE_ACCESS_KEY).requires_policy is True

    def test_update_access_key_requires_approval(self):
        assert rg.get_tool(rg.UPDATE_ACCESS_KEY).requires_approval is True

    def test_update_access_key_schema_is_exactly_three_arguments(self):
        spec = rg.get_tool(rg.UPDATE_ACCESS_KEY)
        assert spec.required_arguments == ("UserName", "AccessKeyId", "Status")

    def test_update_access_key_has_no_optional_arguments(self):
        assert rg.get_tool(rg.UPDATE_ACCESS_KEY).optional_arguments == ()

    def test_update_access_key_argument_names_are_exactly_three(self):
        assert rg.get_tool(
            rg.UPDATE_ACCESS_KEY).argument_names == (
                "AccessKeyId", "Status", "UserName")

    def test_update_access_key_uses_containment_canonicalizer(self):
        assert rg.get_tool(
            rg.UPDATE_ACCESS_KEY).canonicalizer_id == rg.CONTAINMENT_CANONICALIZER


class TestGetSecretValueRegistration:
    def test_get_secret_value_registered_as_sensitive_read(self):
        assert rg.get_tool(
            rg.GET_SECRET_VALUE).category is rg.Category.SENSITIVE_READ

    def test_get_secret_value_service_action(self):
        assert rg.get_tool(
            rg.GET_SECRET_VALUE).service_action == "secretsmanager:GetSecretValue"

    def test_get_secret_value_requires_broker(self):
        assert rg.get_tool(rg.GET_SECRET_VALUE).requires_broker is True

    def test_get_secret_value_requires_policy(self):
        assert rg.get_tool(rg.GET_SECRET_VALUE).requires_policy is True

    def test_get_secret_value_approval_is_explicitly_false(self):
        assert rg.get_tool(rg.GET_SECRET_VALUE).requires_approval is False

    def test_get_secret_value_remains_enumerable(self):
        assert rg.GET_SECRET_VALUE in rg.tool_ids()
        assert rg.GET_SECRET_VALUE in [spec.tool_id
                                       for spec in rg.all_tools()]

    def test_get_secret_value_is_not_special_cased_out_of_enumeration(self):
        listed = [spec.tool_id for spec in rg.all_tools()]
        assert listed.count(rg.GET_SECRET_VALUE) == 1

    def test_get_secret_value_declares_secret_id_schema(self):
        assert rg.get_tool(
            rg.GET_SECRET_VALUE).required_arguments == ("SecretId",)

    def test_get_secret_value_is_discoverable_by_constant_and_id(self):
        assert rg.GET_SECRET_VALUE == "get_secret_value"
        assert rg.get_tool("get_secret_value") is rg.get_tool(
            rg.GET_SECRET_VALUE)

    def test_get_secret_value_carries_no_credential_material(self):
        spec = rg.get_tool(rg.GET_SECRET_VALUE)
        blob = " ".join(map(str, (spec.tool_id, spec.service_action,
                                  spec.required_arguments,
                                  spec.canonicalizer_id)))
        for forbidden in ("secret_access_key", "SecretString", "password",
                          "token"):
            assert forbidden not in blob


class TestInvestigationToolsRegistration:
    @pytest.mark.parametrize("tool_id,service_action",
                             sorted(EXPECTED_READ_ONLY.items()))
    def test_each_investigation_tool_registered_read_only(self, tool_id,
                                                          service_action):
        spec = rg.get_tool(tool_id)
        assert spec.category is rg.Category.READ_ONLY
        assert spec.service_action == service_action

    def test_all_nine_investigation_tools_present(self):
        for tool_id in EXPECTED_READ_ONLY:
            assert tool_id in rg.tool_ids()

    def test_read_only_tools_require_no_approval(self):
        for tool_id in EXPECTED_READ_ONLY:
            assert rg.get_tool(tool_id).requires_approval is False

    def test_read_only_tools_still_require_broker_and_policy(self):
        for tool_id in EXPECTED_READ_ONLY:
            spec = rg.get_tool(tool_id)
            assert spec.requires_broker is True
            assert spec.requires_policy is True

    def test_tools_for_category_partitions_the_registry(self):
        read = rg.tools_for_category(rg.Category.READ_ONLY)
        sensitive = rg.tools_for_category(rg.Category.SENSITIVE_READ)
        changing = rg.tools_for_category(rg.Category.STATE_CHANGING)
        assert len(read) + len(sensitive) + len(changing) == len(rg.all_tools())
        assert [spec.tool_id for spec in sensitive] == [rg.GET_SECRET_VALUE]
        assert [spec.tool_id for spec in changing] == [rg.UPDATE_ACCESS_KEY]


class TestRegistryApi:
    def test_all_tools_returns_tuple_sorted_by_id(self):
        tools = rg.all_tools()
        assert isinstance(tools, tuple)
        assert [spec.tool_id for spec in tools] == sorted(rg.tool_ids())

    def test_tool_ids_returns_tuple(self):
        assert isinstance(rg.tool_ids(), tuple)

    def test_get_tool_returns_same_object_each_call(self):
        assert rg.get_tool(
            rg.UPDATE_ACCESS_KEY) is rg.get_tool(rg.UPDATE_ACCESS_KEY)

    def test_get_tool_is_hashable_and_frozen(self):
        spec = rg.get_tool(rg.UPDATE_ACCESS_KEY)
        with pytest.raises(Exception):
            spec.category = rg.Category.READ_ONLY

    def test_unknown_tool_raises_tool_not_found(self):
        with pytest.raises(rg.ToolNotFoundError) as exc:
            rg.get_tool("delete_everything")
        assert "delete_everything" in str(exc.value)

    def test_unknown_tool_error_is_narrow(self):
        assert issubclass(rg.ToolNotFoundError, KeyError)
        assert not issubclass(rg.ToolNotFoundError, RuntimeError)

    def test_unhashable_tool_id_raises_tool_not_found(self):
        with pytest.raises(rg.ToolNotFoundError):
            rg.get_tool(["unhashable"])

    def test_non_string_tool_id_raises_tool_not_found(self):
        with pytest.raises(rg.ToolNotFoundError):
            rg.get_tool(None)

    def test_public_api_does_not_expose_backing_mapping(self):
        for exposed in dir(rg):
            if exposed.startswith("_"):
                continue
            value = getattr(rg, exposed)
            assert not isinstance(value, (dict, list, set)), exposed

    def test_returned_tuple_cannot_mutate_registry(self):
        tools = rg.all_tools()
        with pytest.raises(TypeError):
            tools[0] = rg.get_tool(rg.GET_SECRET_VALUE)

    def test_caller_cannot_register_tool_at_runtime(self):
        assert not hasattr(rg, "register_tool")
        assert not hasattr(rg, "register")
        assert not hasattr(rg, "add_tool")

    def test_caller_cannot_overwrite_existing_tool(self):
        original = rg.get_tool(rg.UPDATE_ACCESS_KEY)
        with pytest.raises(Exception):
            original.category = rg.Category.READ_ONLY
        assert rg.get_tool(rg.UPDATE_ACCESS_KEY) is original

    def test_spec_dataclass_rejects_construction_with_extra_fields(self):
        with pytest.raises(TypeError):
            rg.ToolSpec("x", "s:A", rg.Category.READ_ONLY, credential="leak")


class TestRegistryUniqueness:
    def test_no_duplicate_tool_ids(self):
        assert len(rg.tool_ids()) == len(set(rg.tool_ids()))

    def test_no_duplicate_service_actions_in_current_registry(self):
        actions = [spec.service_action for spec in rg.all_tools()]
        assert len(actions) == len(set(actions))

    def test_every_tool_id_is_snake_case(self):
        for tool_id in rg.tool_ids():
            assert tool_id.islower()
            assert " " not in tool_id and "-" not in tool_id

    def test_every_tool_declares_required_arguments(self):
        for spec in rg.all_tools():
            assert spec.required_arguments

    def test_required_and_optional_arguments_do_not_overlap(self):
        for spec in rg.all_tools():
            assert not (set(spec.required_arguments)
                        & set(spec.optional_arguments))

    def test_every_tool_requires_broker_and_policy(self):
        for spec in rg.all_tools():
            assert spec.requires_broker is True
            assert spec.requires_policy is True

    def test_only_state_changing_tool_requires_approval(self):
        for spec in rg.all_tools():
            expected = spec.category is rg.Category.STATE_CHANGING
            assert spec.requires_approval is expected, spec.tool_id


class TestExecutionIdentitySpecification:
    def test_execution_identity_constant_exists(self):
        assert rg.EXECUTION_IDENTITY_USER == "security-containment-executor"

    def test_execution_identity_is_not_incident_user(self):
        assert rg.EXECUTION_IDENTITY_USER != d.RESOURCES.incident_user

    def test_execution_identity_is_not_investigator_user(self):
        assert rg.EXECUTION_IDENTITY_USER != d.RESOURCES.investigator_user

    def test_execution_identity_is_not_in_m1_owned_resources(self):
        from cloudsec_agent.scenario import reset as rs
        assert rg.EXECUTION_IDENTITY_USER not in rs.OWNED.all_names()

    def test_execution_identity_is_not_a_registered_tool_id(self):
        assert rg.EXECUTION_IDENTITY_USER not in rg.tool_ids()

    def test_execution_identity_constant_holds_no_credential(self):
        assert isinstance(rg.EXECUTION_IDENTITY_USER, str)
        for forbidden in ("secret", "AKIA", "password", "token"):
            assert forbidden not in rg.EXECUTION_IDENTITY_USER

    def test_execution_identity_constant_is_a_plain_string(self):
        assert type(rg.EXECUTION_IDENTITY_USER) is str


class TestNoPolicyLogicInRegistry:
    def test_tool_spec_carries_no_executable_policy(self):
        source = (REPO / "cloudsec_agent/backend/registry.py").read_text()
        for forbidden in ("def allow", "def deny", "def authorize",
                          "def decide", "def evaluate"):
            assert forbidden not in source

    def test_tool_spec_has_no_callable_fields(self):
        for spec in rg.all_tools():
            for value in vars(spec).values():
                assert not callable(value)

    def test_no_tool_spec_field_is_named_like_a_decision(self):
        forbidden = {"allowed", "decision", "reason", "rule", "verdict",
                     "approved", "granted"}
        for spec in rg.all_tools():
            assert not set(vars(spec)) & forbidden

    def test_registry_defines_no_broker_or_policy_symbols(self):
        for absent in ("BrokerGrant", "CapabilitySet", "PolicyDecision",
                       "ApprovalProvider", "Executor", "AuditRecord"):
            assert not hasattr(rg, absent)