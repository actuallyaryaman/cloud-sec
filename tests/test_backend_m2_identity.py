import ast
import json
import pathlib

import pytest

from cloudsec_agent.backend import m2_identity as mi
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.scenario import reset as rs
from cloudsec_agent.scenario.seed import incident_user_arn, investigator_user_arn

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKEND = REPO / "cloudsec_agent/backend"

EXECUTOR = "security-containment-executor"
INCIDENT = "incident-user"
INVESTIGATOR = "security-agent-backend"
SECRET_SENTINEL = "fake-sentinel-not-a-real-secret"
NEW_KEY = "AKIANEWEXECUTOR0001"


class FakeClientError(Exception):
    def __init__(self, code, status=403):
        super().__init__(code)
        self.response = {"Error": {"Code": code},
                         "ResponseMetadata": {"HTTPStatusCode": status,
                                              "RequestId": "req-should-not-leak"}}


class FakeIam:
    def __init__(self, users=None, policies=None, keys=None,
                 create_user_error=None, create_user_silent=False,
                 put_policy_error=None, policy_override=None,
                 create_key_error=None, create_key_incomplete=False,
                 list_keys_error=None, list_keys_hides_new=False):
        self.users = dict(users or {})
        self.policies = dict(policies or {})
        self.keys = {name: list(value) for name, value in (keys or {}).items()}
        self.create_user_error = create_user_error
        self.create_user_silent = create_user_silent
        self.put_policy_error = put_policy_error
        self.policy_override = policy_override
        self.create_key_error = create_key_error
        self.create_key_incomplete = create_key_incomplete
        self.list_keys_error = list_keys_error
        self.list_keys_hides_new = list_keys_hides_new
        self.calls = []
        self.secret_counter = 0

    def create_user(self, UserName):
        self.calls.append(("create_user", UserName))
        if self.create_user_error:
            raise self.create_user_error
        self.users[UserName] = {"UserName": UserName}
        if not self.create_user_silent:
            return {"User": {"UserName": UserName},
                    "ResponseMetadata": {"HTTPStatusCode": 200}}
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_user(self, UserName):
        self.calls.append(("get_user", UserName))
        if UserName not in self.users:
            raise FakeClientError("NoSuchEntity", 404)
        return {"User": {"UserName": UserName},
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_user_policy(self, UserName, PolicyName, PolicyDocument):
        self.calls.append(("put_user_policy", UserName, PolicyName))
        if self.put_policy_error:
            raise self.put_policy_error
        self.policies.setdefault(UserName, {})[PolicyName] = PolicyDocument
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_user_policy(self, UserName, PolicyName):
        self.calls.append(("get_user_policy", UserName, PolicyName))
        stored = self.policies.get(UserName, {}).get(PolicyName)
        if stored is None:
            raise FakeClientError("NoSuchEntity", 404)
        document = self.policy_override or stored
        return {"UserName": UserName, "PolicyName": PolicyName,
                "PolicyDocument": document,
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def create_access_key(self, UserName):
        self.calls.append(("create_access_key", UserName))
        if self.create_key_error:
            raise self.create_key_error
        self.secret_counter += 1
        payload = {"AccessKeyId": NEW_KEY,
                   "Status": "Active",
                   "SecretAccessKey": f"{SECRET_SENTINEL}-{self.secret_counter}"}
        if not self.create_key_incomplete:
            self.keys.setdefault(UserName, []).append(dict(payload))
        return {"AccessKey": payload, "ResponseMetadata":
                {"HTTPStatusCode": 200, "RequestId": "req-should-not-leak"}}

    def list_access_keys(self, UserName):
        self.calls.append(("list_access_keys", UserName))
        if self.list_keys_error:
            raise self.list_keys_error
        entries = [dict(item) for item in self.keys.get(UserName, [])]
        if self.list_keys_hides_new:
            entries = [item for item in entries
                       if item["AccessKeyId"] != NEW_KEY]
        return {"AccessKeyMetadata": entries,
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def delete_user_policy(self, UserName, PolicyName):
        self.calls.append(("delete_user_policy", UserName, PolicyName))
        self.policies.get(UserName, {}).pop(PolicyName, None)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def delete_access_key(self, UserName, AccessKeyId):
        self.calls.append(("delete_access_key", UserName, AccessKeyId))
        self.keys[UserName] = [item for item in self.keys.get(UserName, [])
                               if item["AccessKeyId"] != AccessKeyId]
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def delete_user(self, UserName):
        self.calls.append(("delete_user", UserName))
        if UserName not in self.users:
            raise FakeClientError("NoSuchEntity", 404)
        del self.users[UserName]
        self.policies.pop(UserName, None)
        self.keys.pop(UserName, None)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class TestM2OwnedResources:
    def test_owned_users_is_exactly_the_executor(self):
        assert mi.M2Owned.users == (EXECUTOR,)

    def test_owned_includes_only_the_containment_policy(self):
        assert mi.M2Owned.inline_policies == (mi.CONTAINMENT_POLICY_NAME,)

    def test_policy_name_does_not_reuse_m1_policy_names(self):
        m1_names = set(rs.OWNED.inline_policies)
        assert mi.CONTAINMENT_POLICY_NAME not in m1_names

    def test_all_names_is_exact_and_finite(self):
        assert mi.M2Owned.all_names() == (EXECUTOR,
                                          mi.CONTAINMENT_POLICY_NAME)

    def test_ownership_is_exact_membership(self):
        assert mi.M2Owned.is_owned(EXECUTOR) is True
        assert mi.M2Owned.is_owned("security-containment-executor-extra") is False
        assert mi.M2Owned.is_owned("csi-anything") is False

    def test_ownership_has_no_prefix_semantics(self):
        for name in ("security-", "csi-", "security-containment", "*"):
            assert mi.M2Owned.is_owned(name) is False

    def test_m2_ownership_is_disjoint_from_m1_ownership(self):
        assert set(mi.M2Owned.all_names()) & set(rs.OWNED.all_names()) == set()

    def test_executor_user_is_not_in_m1_owned(self):
        assert EXECUTOR not in rs.OWNED.all_names()

    def test_m1_users_are_not_m2_owned(self):
        for name in (INCIDENT, INVESTIGATOR):
            assert mi.M2Owned.is_owned(name) is False

    def test_m2_owned_does_not_inherit_m1(self):
        assert not any(name.startswith("csi-") for name in mi.M2Owned.users)


class TestContainmentPolicyDocument:
    def _document(self):
        return json.loads(mi.containment_policy_document())

    def test_update_access_key_uses_floci_compatible_resource(self):
        for statement in self._document()["Statement"]:
            if statement["Action"] == ["iam:UpdateAccessKey"]:
                assert statement["Resource"] == [mi.FLOCI_IAM_RESOURCE]
                return
        pytest.fail("no UpdateAccessKey statement")

    def test_verification_statements_use_floci_compatible_resource(self):
        for statement in self._document()["Statement"]:
            if "iam:ListAccessKeys" in statement["Action"]:
                assert statement["Resource"] == [mi.FLOCI_IAM_RESOURCE]

    def test_floci_resource_constant_is_wildcard(self):
        assert mi.FLOCI_IAM_RESOURCE == "*"

    def test_every_statement_uses_the_floci_resource(self):
        for statement in self._document()["Statement"]:
            assert statement["Resource"] == [mi.FLOCI_IAM_RESOURCE]

    def test_executor_policy_action_allowlist_is_exact(self):
        granted = sorted(action
                         for statement in self._document()["Statement"]
                         for action in statement["Action"])
        assert granted == sorted(mi.CONTAINMENT_ALLOWED_ACTIONS)

    def test_allowlist_constant_matches_policy_document(self):
        granted = sorted(action
                         for statement in self._document()["Statement"]
                         for action in statement["Action"])
        assert tuple(granted) == tuple(sorted(mi.CONTAINMENT_ALLOWED_ACTIONS))

    def test_allowlist_contains_no_iam_service_glob(self):
        assert "iam:*" not in mi.CONTAINMENT_ALLOWED_ACTIONS

    def test_no_wildcard_action(self):
        for statement in self._document()["Statement"]:
            for action in statement["Action"]:
                assert action != "*"
                assert not action.endswith("*")
                assert ":" in action

    def test_no_iam_service_glob_action(self):
        for statement in self._document()["Statement"]:
            for action in statement["Action"]:
                assert not action.startswith("iam:*")

    def test_statements_are_not_combined_into_one(self):
        assert len(self._document()["Statement"]) == 2

    @pytest.mark.parametrize("forbidden", [
        "iam:UpdateUser", "iam:PutRolePolicy", "iam:PassRole",
        "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
        "iam:AttachGroupPolicy", "iam:PutGroupPolicy",
        "sts:AssumeRole", "iam:CreateServiceLinkedRole"])
    def test_additional_forbidden_action_absent(self, forbidden):
        assert forbidden not in mi.containment_policy_document()

    def test_no_s3_or_lambda_authority_at_all(self):
        document = mi.containment_policy_document()
        for forbidden in ("s3:", "lambda:", "secretsmanager:",
                          "logs:", "sts:", "kms:"):
            assert forbidden not in document

    @pytest.mark.parametrize("forbidden", [
        "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:CreateUser",
        "iam:DeleteUser", "iam:PutUserPolicy", "iam:DeleteUserPolicy",
        "iam:AttachUserPolicy", "iam:DetachUserPolicy",
        "secretsmanager:GetSecretValue", "s3:PutObject",
        "s3:DeleteObject", "lambda:CreateFunction", "lambda:UpdateFunctionCode",
        "iam:CreatePolicy", "iam:DeletePolicy"])
    def test_dangerous_action_absent(self, forbidden):
        assert forbidden not in mi.containment_policy_document()

    def test_read_permissions_are_exactly_the_verification_set(self):
        actions = sorted(action
                         for statement in self._document()["Statement"]
                         for action in statement["Action"]
                         if action != "iam:UpdateAccessKey")
        assert actions == ["iam:GetUser", "iam:ListAccessKeys"]

    def test_resource_scoping_is_delegated_to_the_backend(self):
        for statement in self._document()["Statement"]:
            assert statement["Resource"] == [mi.FLOCI_IAM_RESOURCE]

    def test_get_user_is_included_for_reliable_verification(self):
        document = mi.containment_policy_document()
        assert "iam:GetUser" in document

    def test_policy_document_is_deterministic(self):
        assert mi.containment_policy_document() == \
            mi.containment_policy_document()

    def test_policy_document_is_valid_json(self):
        json.loads(mi.containment_policy_document())

    def test_module_defines_no_wildcard_ownership_helper(self):
        source = (BACKEND / "m2_identity.py").read_text()
        assert "startswith" not in source
        assert "fnmatch" not in source


class TestM2ExecutionCredential:
    def test_credential_field_set_is_exact(self):
        assert set(mi.M2ExecutionCredential.__dataclass_fields__) == {
            "access_key_id", "secret_access_key", "user_name"}

    def test_credential_is_frozen(self):
        assert mi.M2ExecutionCredential.__dataclass_params__.frozen is True

    def test_secret_is_excluded_from_repr(self):
        credential = mi.M2ExecutionCredential(access_key_id=NEW_KEY,
                                              secret_access_key=SECRET_SENTINEL)
        assert SECRET_SENTINEL not in repr(credential)
        assert SECRET_SENTINEL not in str(credential)
        assert "[redacted]" in repr(credential)

    def test_safe_summary_never_exposes_secret(self):
        credential = mi.M2ExecutionCredential(access_key_id=NEW_KEY,
                                              secret_access_key=SECRET_SENTINEL)
        summary = credential.safe_summary()
        assert SECRET_SENTINEL not in json.dumps(summary)
        assert summary["secret_access_key"] == "[not-exposed]"

    def test_as_dict_is_the_safe_summary(self):
        credential = mi.M2ExecutionCredential(access_key_id=NEW_KEY,
                                              secret_access_key=SECRET_SENTINEL)
        assert credential.as_dict() == credential.safe_summary()

    def test_credential_defaults_to_the_executor_identity(self):
        credential = mi.M2ExecutionCredential(access_key_id=NEW_KEY,
                                              secret_access_key="x")
        assert credential.user_name == EXECUTOR

    def test_credential_is_distinct_from_m1_incident_credential(self):
        from cloudsec_agent.scenario.credentials import \
            IncidentRuntimeCredential
        assert mi.M2ExecutionCredential is not IncidentRuntimeCredential

    def test_credential_does_not_construct_clients(self):
        source = (BACKEND / "m2_identity.py").read_text()
        assert "IncidentRuntimeCredential" not in source


class TestSetupLifecycle:
    def test_setup_creates_identity_and_returns_credential(self):
        iam = FakeIam()
        result, credential = mi.setup_executor_identity(iam)
        assert result.ok is True
        assert result.user_created is True
        assert result.policy_confirmed is True
        assert result.access_key_confirmed is True
        assert isinstance(credential, mi.M2ExecutionCredential)

    def test_setup_step_order_is_canonical(self):
        iam = FakeIam()
        mi.setup_executor_identity(iam)
        steps = [call[0] for call in iam.calls]
        assert steps.index("create_user") < steps.index("put_user_policy")
        assert steps.index("put_user_policy") < steps.index(
            "create_access_key")
        assert steps.index("create_access_key") < steps.index(
            "list_access_keys")

    def test_setup_requires_identity_absent_initially(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR}})
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.record.step == "preflight_identity_absent"
        assert exc.value.record.classification is mi.M2SetupClass.ALREADY_ABSENT

    def test_setup_does_not_reuse_existing_identity(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR}})
        with pytest.raises(mi.M2SetupDivergence):
            mi.setup_executor_identity(iam)
        assert not any(call[0] == "create_user" for call in iam.calls)
        assert not any(call[0] == "create_access_key" for call in iam.calls)

    def test_setup_confirms_user_by_independent_readback(self):
        iam = FakeIam()
        mi.setup_executor_identity(iam)
        assert ("get_user", EXECUTOR) in iam.calls

    def test_setup_confirms_policy_by_independent_readback(self):
        iam = FakeIam()
        mi.setup_executor_identity(iam)
        assert ("get_user_policy", EXECUTOR,
                mi.CONTAINMENT_POLICY_NAME) in iam.calls

    def test_setup_confirms_key_by_independent_readback(self):
        iam = FakeIam()
        mi.setup_executor_identity(iam)
        assert ("list_access_keys", EXECUTOR) in iam.calls

    def test_setup_result_never_contains_secret(self):
        iam = FakeIam()
        result, _ = mi.setup_executor_identity(iam)
        assert SECRET_SENTINEL not in json.dumps(result.as_dict())

    def test_setup_result_field_set_is_exact(self):
        assert set(mi.M2IdentitySetupResult.__dataclass_fields__) == {
            "user_created", "policy_confirmed", "access_key_confirmed",
            "access_key_id", "fatal_errors", "first_divergence", "records"}

    def test_executor_identity_absent_helper(self):
        assert mi.executor_identity_absent(FakeIam()) is True
        assert mi.executor_identity_absent(
            FakeIam(users={EXECUTOR: {}})) is False


class TestSetupFailureSemantics:
    def test_create_user_api_error_stops(self):
        iam = FakeIam(create_user_error=FakeClientError("LimitExceeded"))
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.record.classification is mi.M2SetupClass.API_ERROR
        assert not any(call[0] == "put_user_policy" for call in iam.calls)

    def test_empty_success_create_user_stops(self):
        iam = FakeIam(create_user_silent=True)
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.record.classification is mi.M2SetupClass.EMPTY_SUCCESS
        assert exc.value.record.step == "create_user"
        assert not any(call[0] == "put_user_policy" for call in iam.calls)

    def test_create_user_absent_readback_stops(self):
        iam = FakeIam(create_user_silent=True)

        def hidden(UserName):
            raise FakeClientError("NoSuchEntity", 404)

        iam.get_user = hidden
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.record.classification is mi.M2SetupClass.EMPTY_SUCCESS

    def test_put_policy_failure_stops(self):
        iam = FakeIam(put_policy_error=FakeClientError("MalformedPolicy"))
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.record.step == "put_user_policy"
        assert not any(call[0] == "create_access_key" for call in iam.calls)

    def test_policy_readback_mismatch_stops(self):
        iam = FakeIam(policy_override=json.dumps(
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": ["iam:*"],
                            "Resource": ["*"]}]}))
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.record.step == "policy_readback"
        assert exc.value.record.classification is mi.M2SetupClass.EMPTY_SUCCESS

    def test_create_key_failure_stops(self):
        iam = FakeIam(create_key_error=FakeClientError("LimitExceeded"))
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.record.step == "create_access_key"

    def test_create_key_incomplete_payload_stops(self):
        iam = FakeIam(create_key_incomplete=True)
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.record.classification is mi.M2SetupClass.EMPTY_SUCCESS

    def test_key_readback_mismatch_stops(self):
        iam = FakeIam(list_keys_hides_new=True)
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.record.step == "key_readback"

    def test_no_retry_after_first_divergence(self):
        iam = FakeIam(create_user_error=FakeClientError("LimitExceeded"))
        with pytest.raises(mi.M2SetupDivergence):
            mi.setup_executor_identity(iam)
        assert len([call for call in iam.calls if call[0] == "create_user"]) == 1

    def test_divergence_result_carries_no_secret(self):
        iam = FakeIam(create_key_incomplete=True)
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert SECRET_SENTINEL not in json.dumps(exc.value.result.as_dict())

    def test_divergence_result_access_key_id_is_empty(self):
        iam = FakeIam(create_key_incomplete=True)
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.result.access_key_id == ""
        assert exc.value.result.access_key_confirmed is False

    def test_divergence_result_records_partial_progress(self):
        iam = FakeIam(create_key_error=FakeClientError("LimitExceeded"))
        with pytest.raises(mi.M2SetupDivergence) as exc:
            mi.setup_executor_identity(iam)
        assert exc.value.result.user_created is True
        assert exc.value.result.policy_confirmed is True
        assert exc.value.result.ok is False


class TestCleanupLifecycle:
    def test_fully_present_identity_is_removed(self):
        iam = FakeIam()
        mi.setup_executor_identity(iam)
        iam.calls.clear()
        result = mi.cleanup_executor_identity(iam)
        assert result.ok is True
        assert result.user_removed is True
        assert result.policy_removed is True
        assert result.keys_removed == 1
        assert EXECUTOR not in iam.users

    def test_cleanup_step_order_is_canonical(self):
        iam = FakeIam()
        mi.setup_executor_identity(iam)
        iam.calls.clear()
        mi.cleanup_executor_identity(iam)
        steps = [call[0] for call in iam.calls]
        assert steps.index("delete_user_policy") < steps.index("delete_user")
        assert steps.index("delete_access_key") < steps.index("delete_user")

    def test_already_absent_returns_already_absent(self):
        iam = FakeIam()
        result = mi.cleanup_executor_identity(iam)
        assert result.records[0].classification is \
            mi.M2CleanupClass.ALREADY_ABSENT
        assert result.ok is True
        assert result.user_removed is True

    def test_policy_only_partial_state_is_cleaned(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR}},
                      policies={EXECUTOR: {mi.CONTAINMENT_POLICY_NAME: "{}"}})
        result = mi.cleanup_executor_identity(iam)
        assert result.ok is True
        assert result.policy_removed is True
        assert EXECUTOR not in iam.users

    def test_key_only_partial_state_is_cleaned(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR}},
                      keys={EXECUTOR: [{"AccessKeyId": NEW_KEY,
                                         "Status": "Active"}]})
        result = mi.cleanup_executor_identity(iam)
        assert result.keys_removed == 1
        assert EXECUTOR not in iam.users

    def test_multiple_executor_keys_are_all_removed(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR}},
                      keys={EXECUTOR: [
                          {"AccessKeyId": "AKIAEXEC0000000001",
                           "Status": "Active"},
                          {"AccessKeyId": "AKIAEXEC0000000002",
                           "Status": "Inactive"},
                          {"AccessKeyId": "AKIAEXEC0000000003",
                           "Status": "Active"}]})
        result = mi.cleanup_executor_identity(iam)
        assert result.keys_removed == 3
        assert EXECUTOR not in iam.keys

    def test_cleanup_verifies_absence_independently(self):
        iam = FakeIam()
        mi.setup_executor_identity(iam)
        iam.calls.clear()
        mi.cleanup_executor_identity(iam)
        assert ("get_user", EXECUTOR) in iam.calls

    def test_cleanup_never_touches_m1_users(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR},
                             INCIDENT: {"UserName": INCIDENT},
                             INVESTIGATOR: {"UserName": INVESTIGATOR}},
                      keys={INCIDENT: [{"AccessKeyId": "AKIAINCIDENT00001",
                                        "Status": "Active"}],
                            INVESTIGATOR: [{"AccessKeyId": "AKIAINVEST000001",
                                            "Status": "Active"}]})
        mi.cleanup_executor_identity(iam)
        for call in iam.calls:
            assert INCIDENT not in call[1:]
            assert INVESTIGATOR not in call[1:]
        assert INCIDENT in iam.users
        assert INVESTIGATOR in iam.users
        assert len(iam.keys[INCIDENT]) == 1
        assert len(iam.keys[INVESTIGATOR]) == 1

    def test_cleanup_deletes_no_m1_resources(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR},
                             INCIDENT: {"UserName": INCIDENT}})
        mi.cleanup_executor_identity(iam)
        names = [call[1] for call in iam.calls if call[0] == "delete_user"]
        assert names == [EXECUTOR]

    def test_cleanup_uses_no_prefix_matching(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR},
                             "security-containment-executor-extra": {},
                             "csi-unrelated": {}})
        mi.cleanup_executor_identity(iam)
        assert "security-containment-executor-extra" in iam.users
        assert "csi-unrelated" in iam.users

    def test_cleanup_classification_covers_required_cases(self):
        assert {member.name for member in mi.M2CleanupClass} >= {
            "CONFIRMED", "ALREADY_ABSENT", "API_ERROR", "EMPTY_SUCCESS",
            "INCONCLUSIVE"}

    def test_cleanup_result_field_set_is_exact(self):
        assert set(mi.M2IdentityCleanupResult.__dataclass_fields__) == {
            "policy_removed", "keys_removed", "user_removed", "fatal_errors",
            "first_divergence", "records"}

    def test_cleanup_result_never_contains_secret(self):
        iam = FakeIam()
        mi.setup_executor_identity(iam)
        result = mi.cleanup_executor_identity(iam)
        assert SECRET_SENTINEL not in json.dumps(result.as_dict())

    def test_cleanup_failure_stops_further_destructive_actions(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR}},
                      keys={EXECUTOR: [{"AccessKeyId": "AKIAEXEC0000000001",
                                         "Status": "Active"}]})
        original = iam.delete_access_key

        def failing(UserName, AccessKeyId):
            raise FakeClientError("AccessDenied")

        iam.delete_access_key = failing
        result = mi.cleanup_executor_identity(iam)
        assert result.ok is False
        assert result.first_divergence.step == "delete_access_key"
        assert not any(call[0] == "delete_user" for call in iam.calls)
        assert EXECUTOR in iam.users

    def test_cleanup_reports_api_error_classification(self):
        iam = FakeIam(users={EXECUTOR: {"UserName": EXECUTOR}})
        iam.list_access_keys = lambda UserName: (_ for _ in ()).throw(
            FakeClientError("AccessDenied"))
        result = mi.cleanup_executor_identity(iam)
        assert result.first_divergence.classification is \
            mi.M2CleanupClass.API_ERROR


class TestM2EASourceGuards:
    def test_module_imports_no_aws_sdk(self):
        tree = ast.parse((BACKEND / "m2_identity.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in ("boto3", "botocore")
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in ("boto3", "botocore")

    def test_module_constructs_no_client(self):
        source = (BACKEND / "m2_identity.py").read_text()
        for forbidden in ("Floci", "floci_client", "boto3", "Session("):
            assert forbidden not in source, forbidden

    def test_module_does_not_import_m1_reset_or_verify(self):
        source = (BACKEND / "m2_identity.py").read_text()
        for absent in ("scenario.reset", "scenario.verify", "seed_scenario",
                       "CheckStatus", "VerificationReport"):
            assert absent not in source

    def test_module_imports_no_m1_result_types(self):
        tree = ast.parse((BACKEND / "m2_identity.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in ("scenario.reset", "scenario.verify")

    def test_module_reads_no_environment_or_credential_file(self):
        source = (BACKEND / "m2_identity.py").read_text()
        for forbidden in ("os.environ", "getenv", "open(", "json.dump(",
                          "write_text", "tempfile"):
            assert forbidden not in source, forbidden

    def test_module_does_not_reference_the_canonical_endpoint(self):
        source = (BACKEND / "m2_identity.py").read_text()
        assert "4567" not in source
        assert "localhost" not in source

    def test_module_defines_no_containment_orchestration(self):
        source = (BACKEND / "m2_identity.py").read_text()
        for absent in ("contain_containment", "ContainmentResult",
                       "update_access_key("):
            assert absent not in source

    def test_executor_identity_constant_is_unchanged(self):
        assert rg.EXECUTION_IDENTITY_USER == EXECUTOR

    def test_backend_directory_permits_exactly_ten_modules(self):
        present = sorted(item.name for item in BACKEND.iterdir()
                         if item.suffix == ".py")
        assert present == ["__init__.py", "approval.py", "audit.py",
                           "broker.py", "executor.py", "live_executor.py",
                           "m2_identity.py", "policy.py", "registry.py",
                           "request.py"]

    def test_no_containment_cli_exists(self):
        assert not (REPO / "cloudsec_agent/containment_cli.py").exists()


class TestWildcardIamDoesNotBroadenBackendAuthorization:
    def _document(self):
        return json.loads(mi.containment_policy_document())

    def _action(self, **overrides):
        from cloudsec_agent.backend import registry as reg
        from cloudsec_agent.backend import request as rq
        fields = {"tool_id": reg.UPDATE_ACCESS_KEY,
                  "service_action": "iam:UpdateAccessKey",
                  "resource": incident_user_arn(),
                  "normalized_arguments": {"UserName": "incident-user",
                                           "AccessKeyId": "AKIAEXAMPLE0000000A",
                                           "Status": "Inactive"}}
        fields.update(overrides)
        return rq.CanonicalAction(**fields)

    def _broker(self, action):
        from cloudsec_agent.backend import broker as bk
        grant = bk.grant_for(bk.BROAD_CAPABILITY, "run-A")
        return bk.evaluate(grant, action, "run-A")

    def _policy(self, action, broker):
        from cloudsec_agent.backend import policy as pol
        from cloudsec_agent.backend import request as rq
        context = pol.ScenarioPolicyContext("csi-incident-v1", "incident-user",
                                            "AKIAEXAMPLE0000000A")
        return pol.evaluate_containment_policy(action, rq.action_digest(action),
                                               broker, context)

    def test_broker_resource_for_containment_remains_exact_incident_arn(self):
        from cloudsec_agent.backend import broker as bk
        granted = bk.BROAD_CAPABILITY.resources_for("update_access_key")
        assert granted == frozenset({incident_user_arn()})
        assert mi.FLOCI_IAM_RESOURCE not in granted

    def test_broker_does_not_grant_investigator_resource(self):
        from cloudsec_agent.backend import broker as bk
        action = self._action(resource=investigator_user_arn())
        decision = self._broker(action)
        assert decision.granted is False

    def test_broker_does_not_grant_executor_resource(self):
        from cloudsec_agent.backend import broker as bk
        executor_arn = f"arn:aws:iam::000000000000:user/{EXECUTOR}"
        action = self._action(resource=executor_arn)
        assert self._broker(action).granted is False

    def test_broker_does_not_grant_any_wildcard_resource(self):
        from cloudsec_agent.backend import broker as bk
        action = self._action(resource="*")
        assert self._broker(action).granted is False

    def test_policy_still_allows_only_the_exact_containment_action(self):
        action = self._action()
        decision = self._policy(action, self._broker(action))
        assert decision.allowed is True
        assert decision.rule_id == "CONTAIN-001"

    def test_policy_still_denies_investigator_target(self):
        action = self._action(resource=investigator_user_arn())
        decision = self._policy(action, self._broker(action))
        assert decision.allowed is False

    def test_policy_still_denies_another_user(self):
        action = self._action(normalized_arguments={
            "UserName": "somebody-else", "AccessKeyId": "AKIAEXAMPLE0000000A",
            "Status": "Inactive"})
        decision = self._policy(action, self._broker(action))
        assert decision.allowed is False

    def test_policy_still_denies_wrong_access_key(self):
        action = self._action(normalized_arguments={
            "UserName": "incident-user", "AccessKeyId": "AKIAEXAMPLE0000000B",
            "Status": "Inactive"})
        decision = self._policy(action, self._broker(action))
        assert decision.allowed is False

    def test_policy_still_denies_status_active(self):
        action = self._action(normalized_arguments={
            "UserName": "incident-user", "AccessKeyId": "AKIAEXAMPLE0000000A",
            "Status": "Active"})
        decision = self._policy(action, self._broker(action))
        assert decision.allowed is False

    def test_policy_still_denies_wildcard_resource_action(self):
        action = self._action(resource="*")
        decision = self._policy(action, self._broker(action))
        assert decision.allowed is False


class TestIamPolicyDocumentIsNotAnAuthorizationInput:
    def test_broker_module_does_not_read_the_iam_policy_document(self):
        from cloudsec_agent.backend import broker as bk
        source = (BACKEND / "broker.py").read_text()
        for absent in ("containment_policy_document", "FLOCI_IAM_RESOURCE",
                       "m2_identity", "PolicyDocument"):
            assert absent not in source, absent

    def test_policy_module_does_not_read_the_iam_policy_document(self):
        from cloudsec_agent.backend import policy as pol
        source = (BACKEND / "policy.py").read_text()
        for absent in ("containment_policy_document", "FLOCI_IAM_RESOURCE",
                       "m2_identity", "PolicyDocument"):
            assert absent not in source, absent

    def test_approval_module_does_not_read_the_iam_policy_document(self):
        from cloudsec_agent.backend import approval as ap
        source = (BACKEND / "approval.py").read_text()
        for absent in ("containment_policy_document", "FLOCI_IAM_RESOURCE",
                       "PolicyDocument"):
            assert absent not in source, absent

    def test_executor_module_does_not_read_the_iam_policy_document(self):
        from cloudsec_agent.backend import executor as ex
        source = (BACKEND / "executor.py").read_text()
        for absent in ("containment_policy_document", "FLOCI_IAM_RESOURCE",
                       "PolicyDocument"):
            assert absent not in source, absent

    def test_containment_orchestration_does_not_read_the_iam_policy(self):
        source = (REPO / "cloudsec_agent/containment.py").read_text()
        for absent in ("containment_policy_document", "FLOCI_IAM_RESOURCE",
                       "PolicyDocument", "m2_identity"):
            assert absent not in source, absent

    def test_no_authorization_module_parses_policy_json(self):
        for name in ("broker.py", "policy.py", "approval.py", "executor.py"):
            source = (BACKEND / name).read_text()
            assert "import json" not in source, name
            assert "json.loads" not in source, name


class TestParsedPolicyComparisonIsSemantic:
    def test_policy_match_ignores_key_ordering(self):
        document = mi.containment_policy_document()
        reordered = json.dumps(json.loads(document), sort_keys=False,
                               separators=(", ", ": "))
        assert reordered != document
        assert mi._policy_matches(reordered) is True

    def test_policy_match_ignores_whitespace_only_differences(self):
        document = mi.containment_policy_document()
        spaced = json.dumps(json.loads(document), indent=4)
        assert spaced != document
        assert mi._policy_matches(spaced) is True

    def test_policy_match_rejects_semantically_different_document(self):
        assert mi._policy_matches(json.dumps(
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": ["iam:*"],
                            "Resource": ["*"]}]})) is False

    def test_policy_match_rejects_malformed_json(self):
        assert mi._policy_matches("{not json") is False

    def test_policy_match_rejects_non_mapping(self):
        assert mi._policy_matches(["a", "list"]) is False

    def test_m2_source_defines_no_other_iam_resource_value(self):
        source = (BACKEND / "m2_identity.py").read_text()
        assert source.count('"*"') == 1
        assert "arn:aws:iam" not in source


class TestM1LeftUntouched:
    def test_m1_investigator_policy_is_not_referenced_by_m2(self):
        source = (BACKEND / "m2_identity.py").read_text()
        assert "investigator_policy_document" not in source
        assert "csi-investigator-readonly" not in source

    def test_m1_investigator_policy_still_scopes_its_resources(self):
        from cloudsec_agent.scenario.seed import investigator_policy_document
        document = json.loads(investigator_policy_document())
        resources = [resource
                     for statement in document["Statement"]
                     for resource in statement["Resource"]]
        assert mi.FLOCI_IAM_RESOURCE not in resources
        assert incident_user_arn() in resources

    def test_m1_investigator_policy_has_no_wildcard(self):
        from cloudsec_agent.scenario.seed import investigator_policy_document
        assert '"*"' not in investigator_policy_document()

    def test_m1_investigator_policy_is_unaffected_by_the_concession(self):
        from cloudsec_agent.scenario.seed import investigator_policy_document
        document = json.loads(investigator_policy_document())
        actions = [action for statement in document["Statement"]
                   for action in statement["Action"]]
        assert "iam:UpdateAccessKey" not in actions
        assert "secretsmanager:GetSecretValue" not in actions

    def test_m2_concession_does_not_leak_into_m1_policy_documents(self):
        from cloudsec_agent.scenario.seed import (incident_policy_document,
                                                  investigator_policy_document)
        for builder in (incident_policy_document,
                        investigator_policy_document):
            document = json.loads(builder())
            for statement in document["Statement"]:
                assert mi.FLOCI_IAM_RESOURCE not in statement["Resource"]

    def test_m1_policies_use_no_bare_wildcard_resource_element(self):
        from cloudsec_agent.scenario.seed import (incident_policy_document,
                                                  investigator_policy_document)
        for builder in (incident_policy_document,
                        investigator_policy_document):
            document = json.loads(builder())
            for statement in document["Statement"]:
                assert mi.FLOCI_IAM_RESOURCE not in statement["Resource"]

    def test_m1_owned_resources_remain_disjoint_from_m2(self):
        assert set(mi.M2Owned.all_names()) & set(rs.OWNED.all_names()) == set()

    def test_executor_policy_name_is_distinct_from_m1_policy_names(self):
        assert mi.CONTAINMENT_POLICY_NAME not in rs.OWNED.inline_policies
        assert mi.CONTAINMENT_POLICY_NAME != "csi-investigator-readonly"
        assert mi.CONTAINMENT_POLICY_NAME != "csi-incident-scout"
