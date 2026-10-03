import ast
import pathlib

import pytest

from cloudsec_agent.backend import executor as ex
from cloudsec_agent.backend import live_executor as le

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKEND = REPO / "cloudsec_agent/backend"

KEY = "AKIAEXAMPLE0000000A"
SECRET_SENTINEL = "fake-sentinel-not-a-real-secret"


class FakeClientError(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "denied"},
                         "ResponseMetadata": {"HTTPStatusCode": status,
                                              "RequestId": "req-should-not-leak"}}


class FakeIam:
    def __init__(self, keys=None, update_error=None, list_error=None,
                 update_status=200):
        self.keys = keys if keys is not None else [
            {"AccessKeyId": KEY, "Status": "Active",
             "SecretAccessKey": SECRET_SENTINEL,
             "CreateDate": "2026-01-01T00:00:00Z"}]
        self.update_error = update_error
        self.list_error = list_error
        self.update_status = update_status
        self.calls = []

    def list_access_keys(self, UserName):
        self.calls.append(("list_access_keys", UserName))
        if self.list_error:
            raise self.list_error
        return {"AccessKeyMetadata": [dict(entry) if isinstance(entry, dict)
                                      else entry for entry in self.keys],
                "ResponseMetadata": {"HTTPStatusCode": 200,
                                     "RequestId": "req-should-not-leak"}}

    def update_access_key(self, UserName, AccessKeyId, Status):
        self.calls.append(("update_access_key", UserName, AccessKeyId, Status))
        if self.update_error:
            raise self.update_error
        for entry in self.keys:
            if entry["AccessKeyId"] == AccessKeyId:
                entry["Status"] = Status
        return {"ResponseMetadata": {"HTTPStatusCode": self.update_status,
                                     "RequestId": "req-should-not-leak"}}


class TestAdapterSatisfiesExecutionPort:
    def test_adapter_is_an_execution_port(self):
        assert isinstance(le.LiveExecutionPort(FakeIam()), ex.ExecutionPort)

    def test_adapter_is_accepted_by_the_executor(self):
        port = le.LiveExecutionPort(FakeIam())
        executor = ex.ContainmentExecutor(port)
        assert executor.execution_identity == ex.EXECUTION_IDENTITY

    def test_only_two_public_execution_operations(self):
        public = {name for name in dir(le.LiveExecutionPort)
                  if not name.startswith("_")}
        assert public == {"list_access_keys", "update_access_key_status"}

    def test_adapter_has_no_generic_escape_hatch(self):
        for absent in ("call", "invoke", "request", "send", "operation",
                       "client", "resource", "execute"):
            assert not hasattr(le.LiveExecutionPort, absent), absent

    def test_adapter_requires_a_client(self):
        with pytest.raises(TypeError):
            le.LiveExecutionPort(None)

    def test_adapter_only_rejects_a_missing_client(self):
        with pytest.raises(TypeError):
            le.LiveExecutionPort(None)
        assert le.LiveExecutionPort(0) is not None


class TestListAccessKeysNormalisation:
    def test_returns_narrow_safe_states(self):
        port = le.LiveExecutionPort(FakeIam())
        states = port.list_access_keys("incident-user")
        assert isinstance(states, tuple)
        assert all(isinstance(item, le.AccessKeyState) for item in states)
        assert states[0].access_key_id == KEY
        assert states[0].status == "Active"

    def test_access_key_state_field_set_is_exact(self):
        assert set(le.AccessKeyState.__dataclass_fields__) == {
            "access_key_id", "status"}

    def test_raw_response_not_exposed(self):
        port = le.LiveExecutionPort(FakeIam())
        states = port.list_access_keys("incident-user")
        for item in states:
            assert not any(isinstance(value, (dict, list))
                           for value in vars(item).values())

    def test_no_secret_access_key_retained(self):
        port = le.LiveExecutionPort(FakeIam())
        blob = repr(port.list_access_keys("incident-user"))
        assert SECRET_SENTINEL not in blob
        assert "SecretAccessKey" not in blob

    def test_no_create_date_retained(self):
        port = le.LiveExecutionPort(FakeIam())
        assert "CreateDate" not in repr(port.list_access_keys("incident-user"))

    def test_no_request_id_retained(self):
        port = le.LiveExecutionPort(FakeIam())
        blob = repr(port.list_access_keys("incident-user"))
        assert "req-should-not-leak" not in blob

    def test_no_response_metadata_retained(self):
        port = le.LiveExecutionPort(FakeIam())
        blob = repr(port.list_access_keys("incident-user"))
        assert "ResponseMetadata" not in blob

    def test_malformed_entries_are_skipped(self):
        client = FakeIam(keys=[{"AccessKeyId": KEY, "Status": "Active"},
                               {"AccessKeyId": "no-status"},
                               "not-a-dict"])
        states = le.LiveExecutionPort(client).list_access_keys("incident-user")
        assert len(states) == 1

    def test_empty_list_returns_empty_tuple(self):
        port = le.LiveExecutionPort(FakeIam(keys=[]))
        assert port.list_access_keys("incident-user") == ()

    def test_api_error_raises_typed_read_error(self):
        port = le.LiveExecutionPort(
            FakeIam(list_error=FakeClientError("AccessDenied", 403)))
        with pytest.raises(le.PortReadError) as exc:
            port.list_access_keys("incident-user")
        assert exc.value.error_code == "AccessDenied"
        assert exc.value.http_status == 403
        assert exc.value.error_kind == "api"

    def test_transport_error_is_distinguishable(self):
        port = le.LiveExecutionPort(FakeIam(list_error=TimeoutError("slow")))
        with pytest.raises(le.PortReadError) as exc:
            port.list_access_keys("incident-user")
        assert exc.value.error_kind == "transport"

    def test_read_error_carries_no_request_id(self):
        port = le.LiveExecutionPort(
            FakeIam(list_error=FakeClientError("AccessDenied", 403)))
        with pytest.raises(le.PortReadError) as exc:
            port.list_access_keys("incident-user")
        assert "req-should-not-leak" not in str(exc.value)


class TestUpdateNormalisation:
    def test_update_success_is_normalised(self):
        port = le.LiveExecutionPort(FakeIam())
        outcome = port.update_access_key_status("incident-user", KEY,
                                                "Inactive")
        assert isinstance(outcome, le.MutationCallResult)
        assert outcome.succeeded is True
        assert outcome.http_status == 200
        assert outcome.error_code == ""

    def test_mutation_result_field_set_is_exact(self):
        assert set(le.MutationCallResult.__dataclass_fields__) == {
            "succeeded", "http_status", "error_code", "error_kind"}

    def test_concrete_api_error_is_normalised(self):
        port = le.LiveExecutionPort(
            FakeIam(update_error=FakeClientError("AccessDenied", 403)))
        outcome = port.update_access_key_status("incident-user", KEY,
                                                "Inactive")
        assert outcome.succeeded is False
        assert outcome.error_code == "AccessDenied"
        assert outcome.http_status == 403
        assert outcome.error_kind == "api"

    def test_transport_error_is_safely_represented(self):
        port = le.LiveExecutionPort(FakeIam(update_error=TimeoutError("slow")))
        outcome = port.update_access_key_status("incident-user", KEY,
                                                "Inactive")
        assert outcome.succeeded is False
        assert outcome.error_kind == "transport"
        assert outcome.error_code == "TimeoutError"

    def test_unknown_error_does_not_leak_exception_text(self):
        port = le.LiveExecutionPort(
            FakeIam(update_error=RuntimeError("AKIALEAKED000000 secret-value")))
        outcome = port.update_access_key_status("incident-user", KEY,
                                                "Inactive")
        assert outcome.error_code == "RuntimeError"
        assert "AKIALEAKED" not in repr(outcome)
        assert "secret-value" not in repr(outcome)

    def test_update_result_retains_no_raw_response(self):
        port = le.LiveExecutionPort(FakeIam())
        outcome = port.update_access_key_status("incident-user", KEY,
                                                "Inactive")
        assert "req-should-not-leak" not in repr(outcome)
        assert not any(isinstance(value, (dict, list))
                       for value in vars(outcome).values())


class TestAdapterCannotMutateArbitrarily:
    def test_update_only_forwards_three_named_arguments(self):
        client = FakeIam()
        le.LiveExecutionPort(client).update_access_key_status("incident-user",
                                                               KEY, "Inactive")
        assert client.calls == [("update_access_key", "incident-user", KEY,
                                  "Inactive")]

    def test_adapter_cannot_call_an_arbitrary_operation(self):
        client = FakeIam()
        client.delete_user = lambda **kwargs: pytest.fail("not reachable")
        client.put_user_policy = lambda **kwargs: pytest.fail("not reachable")
        port = le.LiveExecutionPort(client)
        with pytest.raises(AttributeError):
            port.delete_user(UserName="incident-user")

    def test_adapter_has_no_service_parameter(self):
        import inspect
        for name in ("list_access_keys", "update_access_key_status"):
            parameters = set(inspect.signature(
                getattr(le.LiveExecutionPort, name)).parameters)
            assert "service" not in parameters
            assert "kwargs" not in parameters

    def test_port_operations_accept_no_arbitrary_kwargs(self):
        import inspect
        for name in ("list_access_keys", "update_access_key_status"):
            signature = inspect.signature(getattr(le.LiveExecutionPort, name))
            kinds = {parameter.kind for parameter in
                     signature.parameters.values()}
            assert inspect.Parameter.VAR_KEYWORD not in kinds
            assert inspect.Parameter.VAR_POSITIONAL not in kinds


class TestAdapterNoClientConstruction:
    def test_module_imports_no_aws_sdk(self):
        tree = ast.parse((BACKEND / "live_executor.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in ("boto3", "botocore")
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in ("boto3", "botocore")

    def test_module_does_not_construct_any_client(self):
        source = (BACKEND / "live_executor.py").read_text()
        for forbidden in ("boto3", "Floci", "floci_client", "Session(",
                          "boto3.client", "boto3.resource"):
            assert forbidden not in source, forbidden

    def test_module_has_no_client_factory_function(self):
        source = (BACKEND / "live_executor.py").read_text()
        for absent in ("def build_client", "def make_client", "def client_for",
                       "def credentials", "assume_role"):
            assert absent not in source

    def test_module_reads_no_environment_or_credential_file(self):
        source = (BACKEND / "live_executor.py").read_text()
        for forbidden in ("os.environ", "getenv", "open(", "load_file",
                          "aws_secret_access_key", "secret_access_key="):
            assert forbidden not in source, forbidden

    def test_adapter_takes_an_already_constructed_client(self):
        import inspect
        parameters = list(inspect.signature(
            le.LiveExecutionPort.__init__).parameters)
        assert parameters == ["self", "iam_client"]

    def test_adapter_does_not_call_client_construction_methods(self):
        source = (BACKEND / "live_executor.py").read_text()
        for absent in ("_client(", ".build_client(", "_make_client("):
            assert absent not in source


class TestExecutorToleranceOfRaisingPort:
    def test_executor_classifies_a_raising_read_as_unreadable(self):
        client = FakeIam(list_error=FakeClientError("AccessDenied", 403))
        action = ex.CanonicalAction(
            "update_access_key", "iam:UpdateAccessKey",
            "arn:aws:iam::000000000000:user/incident-user",
            {"UserName": "incident-user", "AccessKeyId": KEY,
             "Status": "Inactive"})
        digest = "d" * 64
        from cloudsec_agent.backend import approval as ap
        from cloudsec_agent.backend import broker as bk
        from cloudsec_agent.backend import policy as pl
        grant = bk.grant_for(bk.BROAD_CAPABILITY, "run-A")
        broker = bk.evaluate(grant, action, "run-A")
        context = pl.ScenarioPolicyContext("csi-incident-v1", "incident-user",
                                           KEY)
        policy = pl.evaluate_containment_policy(action, digest, broker, context)
        approval = ap.ApprovalDecision(True, ap.ApprovalReasonCode.APPROVED,
                                       digest, "ap-1")
        executor = ex.ContainmentExecutor(le.LiveExecutionPort(client))
        result = executor.execute(action, digest, broker, policy, approval,
                                  "security-agent-backend", "AKIAEXAMPLE0000000B")
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert result.verified_effective is False

    def test_executor_tolerates_raising_protected_read(self):
        client = FakeIam()
        action = ex.CanonicalAction(
            "update_access_key", "iam:UpdateAccessKey",
            "arn:aws:iam::000000000000:user/incident-user",
            {"UserName": "incident-user", "AccessKeyId": KEY,
             "Status": "Inactive"})
        digest = "d" * 64
        from cloudsec_agent.backend import approval as ap
        from cloudsec_agent.backend import broker as bk
        from cloudsec_agent.backend import policy as pl
        grant = bk.grant_for(bk.BROAD_CAPABILITY, "run-A")
        broker = bk.evaluate(grant, action, "run-A")
        context = pl.ScenarioPolicyContext("csi-incident-v1", "incident-user",
                                           KEY)
        policy = pl.evaluate_containment_policy(action, digest, broker, context)
        approval = ap.ApprovalDecision(True, ap.ApprovalReasonCode.APPROVED,
                                       digest, "ap-1")
        original = client.list_access_keys

        def failing(user_name):
            if user_name == "security-agent-backend":
                raise FakeClientError("AccessDenied", 403)
            return original(user_name)

        client.list_access_keys = failing
        executor = ex.ContainmentExecutor(le.LiveExecutionPort(client))
        result = executor.execute(action, digest, broker, policy, approval,
                                  "security-agent-backend", "AKIAEXAMPLE0000000B")
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert result.verified_effective is False
