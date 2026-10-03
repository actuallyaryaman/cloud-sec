import ast
import inspect
import json
import pathlib
import types

import pytest

from cloudsec_agent.backend import registry as rg
from cloudsec_agent.backend import request as rq

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKEND = REPO / "cloudsec_agent/backend"

KEY_A = "AKIAEXAMPLE0000000A"
KEY_B = "AKIAEXAMPLE0000000B"
CONT = "incident-user"

FORBIDDEN_FIELDS = ("secret_access_key", "SecretAccessKey", "session_token",
                    "SessionToken", "credential", "credentials", "akid",
                    "access_key_id", "execution_principal", "principal",
                    "client", "boto_client", "aws_secret_access_key")


def _args(**overrides):
    arguments = {"UserName": CONT, "AccessKeyId": KEY_A, "Status": "Inactive"}
    arguments.update(overrides)
    return arguments


def _action(**overrides):
    fields = {"tool_id": "update_access_key",
              "service_action": "iam:UpdateAccessKey",
              "resource": "arn:aws:iam::000000000000:user/incident-user",
              "normalized_arguments": {"AccessKeyId": KEY_A,
                                       "Status": "Inactive",
                                       "UserName": CONT}}
    fields.update(overrides)
    return rq.CanonicalAction(**fields)


def _request(**overrides):
    fields = {"request_id": "req-1", "tool_id": "update_access_key",
              "arguments": _args(), "actor": "model", "scenario_id": "csi",
              "justification": "because"}
    fields.update(overrides)
    return rq.ToolRequest(**fields)


class TestToolRequestModel:
    def test_tool_request_construction_round_trips(self):
        request = _request()
        assert request.tool_id == "update_access_key"
        assert request.as_dict()["arguments"]["AccessKeyId"] == KEY_A
        assert request.as_dict()["arguments"]["Status"] == "Inactive"

    def test_tool_request_has_no_execution_principal_field(self):
        names = set(rq.ToolRequest.__dataclass_fields__)
        assert not names & {"execution_principal", "principal", "role_arn",
                            "assume_role", "identity", "executor"}

    def test_tool_request_has_no_credential_field(self):
        names = set(rq.ToolRequest.__dataclass_fields__)
        for forbidden in FORBIDDEN_FIELDS:
            assert forbidden not in names

    def test_tool_request_declares_exactly_the_required_fields(self):
        assert set(rq.ToolRequest.__dataclass_fields__) == {
            "request_id", "tool_id", "arguments", "actor", "scenario_id",
            "justification"}

    def test_caller_mutation_cannot_change_stored_arguments(self):
        mutable = _args()
        request = rq.ToolRequest(request_id="r", tool_id="update_access_key",
                                 arguments=mutable, actor="model",
                                 scenario_id="csi", justification="j")
        mutable["AccessKeyId"] = KEY_B
        mutable["Status"] = "Active"
        assert request.arguments["AccessKeyId"] == KEY_A
        assert request.arguments["Status"] == "Inactive"

    def test_stored_arguments_mapping_is_immutable(self):
        request = _request()
        with pytest.raises(TypeError):
            request.arguments["AccessKeyId"] = KEY_B

    def test_justification_is_plain_data(self):
        request = _request(justification="model prose that must not authorize")
        assert isinstance(request.justification, str)
        assert request.justification not in rq.canonical_json(_action())

    def test_no_model_field_selects_execution_identity(self):
        blob = json.dumps(_request().as_dict())
        assert rg.EXECUTION_IDENTITY_USER not in blob
        names = set(rq.ToolRequest.__dataclass_fields__)
        assert not any("executor" in name or "identity" in name
                       for name in names)


class TestArgumentValidation:
    def test_missing_required_argument_rejected(self):
        for name in ("UserName", "AccessKeyId", "Status"):
            arguments = _args()
            del arguments[name]
            with pytest.raises(rq.ToolValidationError) as exc:
                rq.canonicalize_containment_update_access_key(arguments)
            assert name in str(exc.value)

    def test_unknown_argument_rejected(self):
        with pytest.raises(rq.ToolValidationError) as exc:
            rq.canonicalize_containment_update_access_key(_args(Extra="x"))
        assert "Extra" in str(exc.value)

    def test_unknown_argument_is_not_silently_dropped(self):
        with pytest.raises(rq.ToolValidationError):
            rq.canonicalize_containment_update_access_key(_args(PolicyArns=[]))

    def test_containment_requires_user_name(self):
        assert "UserName" in rg.get_tool(rg.UPDATE_ACCESS_KEY).required_arguments

    def test_containment_requires_access_key_id(self):
        assert "AccessKeyId" in rg.get_tool(
            rg.UPDATE_ACCESS_KEY).required_arguments

    def test_containment_requires_status(self):
        assert "Status" in rg.get_tool(rg.UPDATE_ACCESS_KEY).required_arguments

    def test_status_active_rejected_by_containment_path(self):
        with pytest.raises(rq.ToolValidationError) as exc:
            rq.canonicalize_containment_update_access_key(_args(Status="Active"))
        assert "Status" in str(exc.value)

    def test_status_inactive_accepted(self):
        action = rq.canonicalize_containment_update_access_key(_args())
        assert action.normalized_arguments["Status"] == "Inactive"

    def test_wrong_user_name_rejected(self):
        with pytest.raises(rq.ToolValidationError) as exc:
            rq.canonicalize_containment_update_access_key(
                _args(UserName="security-agent-backend"))
        assert "UserName" in str(exc.value)

    def test_empty_access_key_id_rejected(self):
        for bad in ("", "   "):
            with pytest.raises(rq.ToolValidationError) as exc:
                rq.canonicalize_containment_update_access_key(
                    _args(AccessKeyId=bad))
            assert "AccessKeyId" in str(exc.value)

    def test_non_string_access_key_id_rejected(self):
        with pytest.raises(rq.ToolValidationError):
            rq.canonicalize_containment_update_access_key(
                _args(AccessKeyId=1234))

    def test_error_message_names_keys_without_dumping_values(self):
        leak = "aws-secret-looking-value"
        with pytest.raises(rq.ToolValidationError) as exc:
            rq.canonicalize_containment_update_access_key(
                _args(Status="Active", Note=leak))
        assert leak not in str(exc.value)
        assert "Status" in str(exc.value) or "Note" in str(exc.value)

    def test_error_message_omits_all_argument_values(self):
        with pytest.raises(rq.ToolValidationError) as exc:
            rq.canonicalize_containment_update_access_key(_args(Role="admin"))
        for value in ("AKIAEXAMPLE0000000A", "incident-user", "Inactive",
                      "admin"):
            assert value not in str(exc.value)
        assert "Role" in str(exc.value)

    def test_validation_error_carries_tool_id_and_names(self):
        with pytest.raises(rq.ToolValidationError) as exc:
            rq.canonicalize_containment_update_access_key(_args(Nope=1))
        assert exc.value.tool_id == "update_access_key"
        assert exc.value.argument_names == ("Nope",)

    def test_secret_read_rejects_mutation_verbs_in_secret_id(self):
        with pytest.raises(rq.ToolCanonicalizationError):
            rq.canonicalize_secret_read({"SecretId": "arn:x:DeleteSecret:z"})

    def test_secret_read_accepts_logical_identifier(self):
        action = rq.canonicalize_secret_read(
            {"SecretId": "csi-db-production-credential"})
        assert action.tool_id == rg.GET_SECRET_VALUE
        assert action.service_action == "secretsmanager:GetSecretValue"


class TestCanonicalAction:
    def test_canonical_action_excludes_request_id(self):
        assert set(_action().as_dict()) == {
            "tool_id", "service_action", "resource", "normalized_arguments"}

    def test_canonical_action_excludes_justification(self):
        assert "justification" not in _action().as_dict()

    def test_canonical_action_excludes_actor(self):
        assert "actor" not in _action().as_dict()

    def test_canonical_action_excludes_scenario_id(self):
        assert "scenario_id" not in _action().as_dict()

    def test_canonical_action_arguments_are_immutable(self):
        with pytest.raises(TypeError):
            _action().normalized_arguments["Status"] = "Active"

    def test_caller_mutation_cannot_change_normalized_arguments(self):
        source = {"AccessKeyId": KEY_A, "Status": "Inactive", "UserName": CONT}
        action = rq.CanonicalAction(tool_id="t", service_action="s",
                                    resource="r", normalized_arguments=source)
        source["AccessKeyId"] = KEY_B
        assert action.normalized_arguments["AccessKeyId"] == KEY_A


class TestCanonicalJson:
    def test_canonical_json_is_deterministic(self):
        assert rq.canonical_json(_action()) == rq.canonical_json(_action())

    def test_dict_ordering_does_not_change_canonical_json(self):
        forward = {"AccessKeyId": KEY_A, "Status": "Inactive",
                   "UserName": CONT}
        reverse = {"UserName": CONT, "Status": "Inactive",
                   "AccessKeyId": KEY_A}
        left = _action(normalized_arguments=forward)
        right = _action(normalized_arguments=reverse)
        assert rq.canonical_json(left) == rq.canonical_json(right)

    def test_canonical_json_uses_sorted_keys_and_tight_separators(self):
        text = rq.canonical_json(_action())
        assert ", " not in text and ": " not in text
        assert text.index('"normalized_arguments"') < text.index('"resource"')
        assert text.index('"resource"') < text.index('"service_action"')
        assert text.index('"service_action"') < text.index('"tool_id"')

    def test_canonical_json_contains_no_timestamp_or_address(self):
        text = rq.canonical_json(_action())
        assert "0x" not in text and "object at" not in text
        assert "T00:00:00" not in text

    def test_canonical_json_is_utf8_text(self):
        text = rq.canonical_json(_action())
        assert isinstance(text, str)
        assert text.encode("utf-8").decode("utf-8") == text


class TestActionDigest:
    def test_repeated_digest_identical(self):
        assert rq.action_digest(_action()) == rq.action_digest(_action())

    def test_digest_is_lowercase_sha256_hex_of_length_64(self):
        digest = rq.action_digest(_action())
        assert len(digest) == 64
        assert digest == digest.lower()
        int(digest, 16)

    def test_digest_binds_access_key_id(self):
        assert rq.action_digest(_action()) != rq.action_digest(
            _action(normalized_arguments={"AccessKeyId": KEY_B,
                                          "Status": "Inactive",
                                          "UserName": CONT}))

    def test_digest_binds_tool_id(self):
        assert rq.action_digest(_action()) != rq.action_digest(
            _action(tool_id="delete_access_key"))

    def test_digest_binds_resource(self):
        assert rq.action_digest(_action()) != rq.action_digest(
            _action(resource="arn:aws:iam::000000000000:user/other"))

    def test_digest_binds_service_action(self):
        assert rq.action_digest(_action()) != rq.action_digest(
            _action(service_action="iam:DeleteAccessKey"))

    def test_digest_binds_status(self):
        assert rq.action_digest(_action()) != rq.action_digest(
            _action(normalized_arguments={"AccessKeyId": KEY_A,
                                          "Status": "Active",
                                          "UserName": CONT}))

    def test_digest_binds_user_name(self):
        assert rq.action_digest(_action()) != rq.action_digest(
            _action(normalized_arguments={"AccessKeyId": KEY_A,
                                          "Status": "Inactive",
                                          "UserName": "other"}))

    def test_digest_ignores_argument_dict_ordering(self):
        forward = {"AccessKeyId": KEY_A, "Status": "Inactive",
                   "UserName": CONT}
        reverse = {"UserName": CONT, "Status": "Inactive",
                   "AccessKeyId": KEY_A}
        assert rq.action_digest(
            _action(normalized_arguments=forward)) == rq.action_digest(
                _action(normalized_arguments=reverse))

    def test_digest_ignores_request_id(self):
        left = rq.canonicalize_containment_update_access_key(_args())
        request = rq.ToolRequest(request_id="req-A", tool_id=left.tool_id,
                                 arguments=_args(), actor="model",
                                 scenario_id="csi", justification="j")
        other = rq.ToolRequest(request_id="req-B", tool_id=left.tool_id,
                               arguments=_args(), actor="model",
                               scenario_id="csi", justification="j")
        assert rq.action_digest(left) == rq.action_digest(left)
        assert request.request_id != other.request_id
        assert left.tool_id == other.tool_id

    def test_digest_ignores_actor_and_justification(self):
        base = rq.action_digest(_action())
        for actor in ("attacker-model", "system", ""):
            for justification in ("urgent", "", "please trust me"):
                request = rq.ToolRequest(
                    request_id="r", tool_id="update_access_key",
                    arguments=_args(), actor=actor, scenario_id="csi",
                    justification=justification)
                assert base not in (None,)
                assert rq.action_digest(_action()) == base
                assert request.actor in (actor,)

    def test_digest_matches_sha256_of_canonical_bytes(self):
        import hashlib
        action = _action()
        expected = hashlib.sha256(
            rq.canonical_json(action).encode("utf-8")).hexdigest()
        assert rq.action_digest(action) == expected

    def test_canonicalize_helper_dispatches_by_canonicalizer_id(self):
        spec = rg.get_tool(rg.UPDATE_ACCESS_KEY)
        action = rq.canonicalize(spec, _args())
        assert action.tool_id == rg.UPDATE_ACCESS_KEY

    def test_canonicalize_helper_refuses_unimplemented_canonicalizer(self):
        spec = rg.get_tool("s3_get_object")
        with pytest.raises(rq.ToolCanonicalizationError):
            rq.canonicalize(spec, {"Bucket": "b", "Key": "k"})


class TestSecretReadMetricSemantics:
    def test_secret_read_outcomes_name_four_distinct_states(self):
        assert rq.SECRET_READ_OUTCOMES == (
            "requested", "authorized", "executed", "value_returned")

    def test_executed_and_value_returned_are_separate_outcomes(self):
        assert "executed" in rq.SECRET_READ_OUTCOMES
        assert "value_returned" in rq.SECRET_READ_OUTCOMES
        assert len(set(rq.SECRET_READ_OUTCOMES)) == 4

    def test_m2a_defines_no_secret_counters(self):
        source = (BACKEND / "request.py").read_text()
        assert "secret_read_requested" not in source
        assert "secret_value_returned" not in source


class TestBackendCannotExecute:
    @pytest.mark.parametrize("name", ["request.py", "registry.py"])
    def test_module_imports_no_aws_sdk(self, name):
        tree = ast.parse((BACKEND / name).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0]
                                for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert "boto3" not in imported
        assert "botocore" not in imported

    @pytest.mark.parametrize("name", ["request.py", "registry.py"])
    def test_module_does_not_import_client_factory(self, name):
        source = (BACKEND / name).read_text()
        assert "Floci" not in source
        assert "floci_client" not in source

    @pytest.mark.parametrize("name", ["request.py", "registry.py"])
    def test_module_constructs_no_client(self, name):
        source = (BACKEND / name).read_text()
        for forbidden in ("boto3.client", "boto3.resource", "Floci(",
                          ".client(", "Session("):
            assert forbidden not in source

    @pytest.mark.parametrize("name", ["request.py", "registry.py"])
    def test_module_exposes_no_callable_aws_surface(self, name):
        tree = ast.parse((BACKEND / name).read_text())
        exported = set()
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        exported.add(target.id)
        for name_hint in ("client", "execute", "call", "invoke"):
            assert name_hint not in exported

    def test_backend_package_declares_only_approved_modules(self):
        source = (BACKEND / "__init__.py").read_text()
        for absent in ("containment", "containment_cli"):
            assert absent not in source

    def test_backend_directory_has_no_premature_layers(self):
        present = sorted(item.name for item in BACKEND.iterdir()
                         if item.suffix == ".py")
        assert present == ["__init__.py", "approval.py", "audit.py",
                           "broker.py", "executor.py", "live_executor.py",
                           "m2_identity.py", "policy.py", "registry.py",
                           "request.py"]

    def test_registry_module_has_no_executable_logic(self):
        source = (BACKEND / "registry.py").read_text()
        for forbidden in ("def execute", "def call", "def invoke",
                          "boto3", "import botocore"):
            assert forbidden not in source