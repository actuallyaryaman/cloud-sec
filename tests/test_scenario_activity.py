import ast
import dataclasses
import json
import pathlib

import pytest

from cloudsec_agent.scenario import activity as a
from cloudsec_agent.scenario import credentials as cr
from cloudsec_agent.scenario import evidence as ev
from cloudsec_agent.scenario import manifest as mf
from cloudsec_agent.scenario import seed as s

REPO = pathlib.Path(__file__).resolve().parents[1]
SIMULATED_SECRET = "super-secret-simulated-value-do-not-use"


class FakeClientError(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {
            "Error": {"Code": code, "Message": "denied"},
            "ResponseMetadata": {"HTTPStatusCode": status, "RequestId": "req-42"},
        }


class FakeFloci:
    def __init__(self):
        self.endpoint = "http://localhost:4567"
        self.account = "000000000000"

    def client(self, service, akid=None, secret=None, read_timeout=None):
        return FakeServiceClient(service, akid)


class FakeServiceClient:
    def __init__(self, service, akid):
        self.service = service
        self.akid = akid
        self.calls = []

    def get_object(self, Bucket, Key):
        self.calls.append(("GetObject", Bucket, Key))
        if Bucket != "csi-incident-bucket" or "evidence" in Key:
            raise FakeClientError("AccessDenied", 403)
        return {"Body": _FakeBody(b"synthetic-body")}

    def list_objects_v2(self, Bucket):
        self.calls.append(("ListObjectsV2", Bucket))
        return {"KeyCount": 1}

    def get_secret_value(self, SecretId):
        self.calls.append(("GetSecretValue", SecretId))
        if getattr(self, "secret_allowed", False):
            return {"SecretString": SIMULATED_SECRET, "VersionId": "v1"}
        raise FakeClientError("AccessDenied", 403)

    def get_user(self, UserName):
        self.calls.append(("GetUser", UserName))
        raise FakeClientError("AccessDenied", 403)

    def get_caller_identity(self):
        self.calls.append(("GetCallerIdentity",))
        return {"Account": "000000000000"}


class _FakeBody:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


def _credential():
    return cr.IncidentRuntimeCredential(access_key_id="AKIATEST0000000001",
                                        secret_access_key=SIMULATED_SECRET)


class TestCredentialType:
    def test_requires_both_fields(self):
        with pytest.raises(TypeError):
            cr.IncidentRuntimeCredential()
        with pytest.raises(TypeError):
            cr.IncidentRuntimeCredential(access_key_id="AKIA1")

    def test_repr_never_contains_secret(self):
        credential = _credential()
        assert SIMULATED_SECRET not in repr(credential)

    def test_str_never_contains_secret(self):
        credential = _credential()
        assert SIMULATED_SECRET not in str(credential)

    def test_repr_may_contain_access_key_id(self):
        credential = _credential()
        assert "AKIATEST0000000001" in repr(credential)

    def test_no_serialisation_api_is_provided(self):
        credential = _credential()
        for name in ("as_dict", "to_json", "to_dict", "json", "__iter__",
                     "asdict", "_asdict"):
            assert not hasattr(credential, name), name

    def test_dataclass_is_frozen(self):
        credential = _credential()
        with pytest.raises(dataclasses.FrozenInstanceError):
            credential.access_key_id = "AKIA2"
        with pytest.raises(dataclasses.FrozenInstanceError):
            credential.secret_access_key = "other"

    def test_client_helper_uses_the_factory_not_raw_boto3(self):
        credential = _credential()
        client = credential.client(FakeFloci(), "s3")
        assert client.akid == "AKIATEST0000000001"

    def test_manifest_module_does_not_import_credentials(self):
        source = (REPO / "cloudsec_agent/scenario/manifest.py").read_text()
        assert "IncidentRuntimeCredential" not in source
        assert "from .credentials" not in source
        assert "from cloudsec_agent.scenario.credentials" not in source

    def test_seed_result_has_no_runtime_credential_field(self):
        fields = {item.name for item in dataclasses.fields(s.SeedResult)}
        assert "incident_credential" not in fields
        assert "runtime" not in fields
        assert "secret_access_key" not in fields
        for item in fields:
            assert not item.endswith("_access_key"), item
            assert "credential" not in item, item

    def test_project_source_has_no_direct_boto3_client_construction(self):
        for path in (REPO / "cloudsec_agent/scenario").rglob("*.py"):
            source = path.read_text()
            assert "boto3.client(" not in source, path.name
            assert "boto3.resource(" not in source, path.name


class TestSeedRuntimeBoundary:
    def test_ordinary_seed_scenario_still_returns_seed_result(self):
        assert s.seed_scenario.__doc__ is None
        result = s._seed_scenario_impl
        assert callable(result)
        seed_function = ast.parse(
            (REPO / "cloudsec_agent/scenario/seed.py").read_text())
        for node in ast.walk(seed_function):
            if isinstance(node, ast.FunctionDef):
                if node.name == "seed_scenario":
                    returns = [n for n in ast.walk(node)
                               if isinstance(n, ast.Return)]
                    assert len(returns) == 1
                    assert isinstance(returns[0].value, ast.Call)
                    assert returns[0].value.func.id == "_seed_scenario_impl"

    def test_runtime_api_returns_seed_execution(self):
        execution = s.SeedExecution(result=s.SeedResult(scenario_id="x",
                                                       endpoint="http://localhost:4567"),
                                    incident_credential=_credential())
        assert isinstance(execution.result, s.SeedResult)

    def test_seed_execution_result_contains_no_secret(self):
        result = s.SeedResult(scenario_id="x", endpoint="http://localhost:4567",
                              incident_access_key_id="AKIATEST0000000001")
        execution = s.SeedExecution(result=result, incident_credential=_credential())
        blob = json.dumps(dataclasses.asdict(result)) + repr(result)
        assert "SecretAccessKey" not in blob
        assert SIMULATED_SECRET not in blob

    def test_seed_execution_repr_is_secret_safe(self):
        execution = s.SeedExecution(
            result=s.SeedResult(scenario_id="x", endpoint="y"),
            incident_credential=_credential())
        assert SIMULATED_SECRET not in repr(execution)
        assert SIMULATED_SECRET not in str(execution)

    def test_runtime_credential_gating_requires_confirmed_readback(self):
        source = (REPO / "cloudsec_agent/scenario/seed.py").read_text()
        block = source[source.index("key_record = observe("):]
        block = block[:block.index("def seed_canonical_scenario")]
        assert "key_record.classification != MutationClass.CONFIRMED" in block
        assert "if not key_id or not secret_value:" in block

    def test_credential_is_only_built_for_the_incident_key_field(self):
        source = (REPO / "cloudsec_agent/scenario/seed.py").read_text()
        block = source[source.index("if not capture_runtime or key_field"):]
        block = block[:block.index("return IncidentRuntimeCredential")]
        assert '"incident_access_key_id"' in block

    def test_investigator_secret_is_not_retained(self):
        source = (REPO / "cloudsec_agent/scenario/seed.py").read_text()
        assert "IncidentRuntimeCredential(" in source
        construction = source[source.index("return IncidentRuntimeCredential("):]
        construction = construction[:construction.index(")") + 1]
        assert "secret_access_key=secret_value" in construction
        assert construction.count("IncidentRuntimeCredential(") == 1


class TestActivityResultStructure:
    def test_no_catch_all_response_field(self):
        names = {item.name for item in dataclasses.fields(a.ActivityResult)}
        for forbidden in a.FORBIDDEN_RESULT_FIELDS:
            assert forbidden not in names, forbidden

    def test_result_repr_does_not_expose_simulated_secret(self):
        result = a.ActivityResult(event_id="EV-006", service="secretsmanager",
                                  operation="GetSecretValue", target="arn",
                                  observed_result=a.Observed.UNEXPECTED_SUCCESS,
                                  secret_material_returned=True,
                                  detail="ClientError")
        assert SIMULATED_SECRET not in repr(result)
        assert SIMULATED_SECRET not in str(result)
        assert SIMULATED_SECRET not in json.dumps(
            dataclasses.asdict(result), default=str)

    def test_activity_execution_is_repr_safe(self):
        execution = a.ActivityExecution(access_key_id="AKIATEST0000000001")
        assert SIMULATED_SECRET not in repr(execution)

    def test_authoritative_order_is_exact(self):
        assert [item.id for item in a.ordered_events()] == [
            f"EV-00{index}" for index in range(1, 9)]

    def test_dispatch_uses_the_existing_catalogue(self):
        assert a.ordered_events() is not None
        assert tuple(a.ordered_events()) == tuple(ev.AUTHORITATIVE_EVIDENCE)
        source = (REPO / "cloudsec_agent/scenario/activity.py").read_text()
        assert '"EV-00' not in source
        assert "EV-001" not in source

    def test_activity_module_does_not_import_orchestration(self):
        source = (REPO / "cloudsec_agent/scenario/activity.py").read_text()
        for forbidden in ("from .seed", "from .reset", "from ..seed_scenario",
                          "import manifest", "from .manifest"):
            assert forbidden not in source, forbidden

    def test_activity_module_carries_no_docstrings(self):
        tree = ast.parse((REPO / "cloudsec_agent/scenario/activity.py").read_text())
        assert not ast.get_docstring(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                assert not ast.get_docstring(node)

    def test_get_secret_value_appears_only_in_the_dedicated_executor(self):
        source = (REPO / "cloudsec_agent/scenario/activity.py").read_text()
        assert source.count("get_secret_value") == 1
        assert "CallOutcome" not in source

    def test_no_cloud_write_or_delete_operations(self):
        source = (REPO / "cloudsec_agent/scenario/activity.py").read_text()
        for forbidden in ("put_object", "delete_object", "delete_bucket",
                          "create_user", "delete_user", "put_user_policy",
                          "update_function", "delete_function", "put_secret",
                          "create_access_key", "delete_access_key"):
            assert forbidden not in source, forbidden


class TestClassification:
    @pytest.mark.parametrize("code,status,expected", [
        ("AccessDenied", 403, a.Observed.AUTHORIZATION_DENIED),
        ("AccessDeniedException", 400, a.Observed.AUTHORIZATION_DENIED),
        ("UnauthorizedOperation", 403, a.Observed.AUTHORIZATION_DENIED),
        (None, 403, a.Observed.AUTHORIZATION_DENIED),
        (None, 401, a.Observed.AUTHORIZATION_DENIED),
    ])
    def test_authorization_denials(self, code, status, expected):
        assert a.classify_outcome(ok=False, error_code=code,
                                  http_status=status)[0] == expected

    @pytest.mark.parametrize("code,status", [
        ("NoSuchKey", 404), ("NoSuchBucket", 404),
        ("ResourceNotFoundException", 400), ("NoSuchEntity", 404),
        ("ValidationError", 400),
    ])
    def test_non_authorization_failures(self, code, status):
        observed = a.classify_outcome(ok=False, error_code=code,
                                      http_status=status)[0]
        assert observed != a.Observed.AUTHORIZATION_DENIED
        assert observed == a.Observed.API_ERROR

    def test_timeout_is_not_authorization_denied(self):
        assert a.classify_outcome(ok=False, error_code=None,
                                  http_status=None)[0] == a.Observed.INCONCLUSIVE

    def test_connection_error_is_not_authorization_denied(self):
        observed = a.classify_outcome(ok=False, error_code="EndpointConnectionError",
                                      http_status=None)[0]
        assert observed != a.Observed.AUTHORIZATION_DENIED

    def test_success(self):
        assert a.classify_outcome(ok=True)[0] == a.Observed.SUCCESS

    def test_denial_signal_predicate(self):
        assert a.is_authorization_denial("AccessDenied", 403) is True
        assert a.is_authorization_denial("NoSuchKey", 404) is False
        assert a.is_authorization_denial(None, 200) is False


class TestEv006Safety:
    def _execution(self, secret_allowed):
        floci = FakeFloci()
        credential = _credential()
        original = FakeServiceClient.get_secret_value

        def patched(self, SecretId):
            if secret_allowed:
                return {"SecretString": SIMULATED_SECRET, "SecretBinary": None}
            return original(self, SecretId)

        FakeServiceClient.get_secret_value = patched
        try:
            return a.execute_incident_activity(
                floci, credential,
                secret_arn="arn:aws:secretsmanager:us-east-1:000000000000:secret:x",
                evidence_bucket_arn="arn:aws:s3:::csi-evidence-bucket")
        finally:
            FakeServiceClient.get_secret_value = original

    def test_denied_secret_read_returns_safe_metadata_only(self):
        execution = self._execution(secret_allowed=False)
        record = [item for item in execution.results if item.event_id == "EV-006"][0]
        assert record.observed_result == a.Observed.AUTHORIZATION_DENIED
        assert record.error_code == "AccessDenied"
        assert record.http_status == 403
        assert record.request_id == "req-42"
        assert record.secret_material_returned is False
        for forbidden in a.FORBIDDEN_RESULT_FIELDS:
            assert not hasattr(record, forbidden)

    def test_unexpected_success_is_flagged(self):
        execution = self._execution(secret_allowed=True)
        record = [item for item in execution.results if item.event_id == "EV-006"][0]
        assert record.observed_result == a.Observed.UNEXPECTED_SUCCESS
        assert record.secret_material_returned is True

    def test_simulated_secret_appears_nowhere_in_execution(self):
        execution = self._execution(secret_allowed=True)
        blob = repr(execution) + str(execution)
        blob += json.dumps([dataclasses.asdict(item)
                            for item in execution.results], default=str)
        assert SIMULATED_SECRET not in blob

    def test_unexpected_success_stops_execution(self):
        execution = self._execution(secret_allowed=True)
        assert execution.stopped_early is True
        assert "EV-006" in execution.stop_reason
        identifiers = [item.event_id for item in execution.results]
        assert identifiers == ["EV-001", "EV-002", "EV-003", "EV-004", "EV-005",
                               "EV-006"]
        assert "EV-007" not in identifiers
        assert "EV-008" not in identifiers

    def test_binary_secret_receives_the_same_protection(self):
        floci = FakeFloci()
        credential = _credential()

        def patched(self, SecretId):
            return {"SecretString": None, "SecretBinary": SIMULATED_SECRET.encode()}

        original = FakeServiceClient.get_secret_value
        FakeServiceClient.get_secret_value = patched
        try:
            execution = a.execute_incident_activity(
                floci, credential, secret_arn="arn:secret:x",
                evidence_bucket_arn="arn:s3:::bucket")
        finally:
            FakeServiceClient.get_secret_value = original
        record = [item for item in execution.results if item.event_id == "EV-006"][0]
        assert record.observed_result == a.Observed.UNEXPECTED_SUCCESS
        assert record.secret_material_returned is True
        assert SIMULATED_SECRET not in json.dumps(
            [dataclasses.asdict(item) for item in execution.results], default=str)


class TestNormalExecutionShape:
    def test_all_eight_events_execute_when_no_unexpected_success(self):
        execution = a.execute_incident_activity(
            FakeFloci(), _credential(), secret_arn="arn:secret:x",
            evidence_bucket_arn="arn:s3:::bucket")
        assert [item.event_id for item in execution.results] == [
            f"EV-00{index}" for index in range(1, 9)]
        assert execution.stopped_early is False
        assert execution.access_key_id == "AKIATEST0000000001"

    def test_every_result_carries_the_actor_key_id(self):
        execution = a.execute_incident_activity(
            FakeFloci(), _credential(), secret_arn="arn:secret:x",
            evidence_bucket_arn="arn:s3:::bucket")
        assert all(item.actor_access_key_id == "AKIATEST0000000001"
                   for item in execution.results)

    def test_cross_scope_and_iam_events_are_denied(self):
        execution = a.execute_incident_activity(
            FakeFloci(), _credential(), secret_arn="arn:secret:x",
            evidence_bucket_arn="arn:s3:::bucket")
        by_id = {item.event_id: item for item in execution.results}
        assert by_id["EV-005"].observed_result == a.Observed.AUTHORIZATION_DENIED
        assert by_id["EV-006"].observed_result == a.Observed.AUTHORIZATION_DENIED
        assert by_id["EV-007"].observed_result == a.Observed.AUTHORIZATION_DENIED

    def test_identity_introspection_is_success_without_denial_expectation(self):
        execution = a.execute_incident_activity(
            FakeFloci(), _credential(), secret_arn="arn:secret:x",
            evidence_bucket_arn="arn:s3:::bucket")
        by_id = {item.event_id: item for item in execution.results}
        assert by_id["EV-008"].observed_result == a.Observed.SUCCESS

    def test_native_corroboration_defaults_to_false(self):
        execution = a.execute_incident_activity(
            FakeFloci(), _credential(), secret_arn="arn:secret:x",
            evidence_bucket_arn="arn:s3:::bucket")
        assert all(item.native_corroborated is False for item in execution.results)

    def test_execution_holds_no_raw_sdk_responses(self):
        execution = a.execute_incident_activity(
            FakeFloci(), _credential(), secret_arn="arn:secret:x",
            evidence_bucket_arn="arn:s3:::bucket")
        for item in execution.results:
            values = [getattr(item, field.name)
                      for field in dataclasses.fields(item)]
            for value in values:
                assert not isinstance(value, dict), item.event_id
                assert not isinstance(value, bytes), item.event_id

class TestS3TargetParsing:
    def test_reports_object_arn_parses(self):
        assert a.parse_s3_target(
            "arn:aws:s3:::csi-incident-bucket/reports/q1-summary.txt") == (
            "csi-incident-bucket", "reports/q1-summary.txt")

    def test_notes_object_arn_parses(self):
        assert a.parse_s3_target(
            "arn:aws:s3:::csi-incident-bucket/notes/handoff.md") == (
            "csi-incident-bucket", "notes/handoff.md")

    def test_evidence_object_arn_parses(self):
        assert a.parse_s3_target(
            "arn:aws:s3:::csi-evidence-bucket/control/evidence-index.json") == (
            "csi-evidence-bucket", "control/evidence-index.json")

    def test_bucket_only_arn_parses_with_no_key(self):
        assert a.parse_s3_target(
            "arn:aws:s3:::csi-incident-bucket") == ("csi-incident-bucket", None)

    def test_restricted_object_arn_parses(self):
        assert a.parse_s3_target(
            "arn:aws:s3:::csi-incident-bucket/restricted/"
            "merger-acquisition-accounts.csv") == (
            "csi-incident-bucket",
            "restricted/merger-acquisition-accounts.csv")

    def test_malformed_arn_rejected(self):
        with pytest.raises(a.TargetParseError):
            a.parse_s3_target("not-an-arn")

    def test_non_s3_arn_rejected(self):
        with pytest.raises(a.TargetParseError):
            a.parse_s3_target("arn:aws:iam::000000000000:user/incident-user")

    def test_secretsmanager_arn_rejected(self):
        with pytest.raises(a.TargetParseError):
            a.parse_s3_target(
                "arn:aws:secretsmanager:us-east-1:000000000000:secret:"
                "csi-db-production-credential")

    def test_empty_bucket_rejected(self):
        with pytest.raises(a.TargetParseError):
            a.parse_s3_target("arn:aws:s3:::")

    def test_empty_key_rejected(self):
        with pytest.raises(a.TargetParseError):
            a.parse_s3_target("arn:aws:s3:::csi-incident-bucket/")

    def test_non_string_rejected(self):
        with pytest.raises(a.TargetParseError):
            a.parse_s3_target(None)

    def test_every_dispatched_s3_target_parses(self):
        for entry in a.ordered_events():
            if entry.service != "s3":
                continue
            bucket, key = a.parse_s3_target(entry.target)
            assert bucket.startswith("csi-")
            if entry.operation == "s3:GetObject":
                assert key
            else:
                assert key is None

    def test_dispatched_event_ids_are_exactly_the_eight(self):
        assert [item.id for item in a.ordered_events()] == [
            "EV-00%d" % n for n in range(1, 9)]


class TestDispatchUsesParsedTarget:
    def _dispatch(self, event_id):
        execution = a.execute_incident_activity(FakeFloci(), _credential())
        return {item.event_id: item for item in execution.results}

    def test_dispatcher_passes_bucket_without_arn_prefix(self):
        results = self._dispatch(None)
        assert results["EV-001"].observed_result == a.Observed.SUCCESS

    def test_dispatcher_passes_canonical_key_unchanged(self):
        observed = a._call_and_classify
        captured = []

        class Recorder(FakeServiceClient):
            def get_object(self, Bucket, Key):
                captured.append((Bucket, Key))
                return super().get_object(Bucket, Key)

        event = ev.EVIDENCE_CATALOGUE[0]
        fake = FakeFloci()

        def patched_client(service, akid=None, secret=None, read_timeout=None):
            return Recorder(service, akid)

        fake.client = patched_client
        a.execute_incident_activity(fake, _credential())
        assert captured[0] == ("csi-incident-bucket", "reports/q1-summary.txt")

    def test_ev003_receives_bucket_only(self):
        captured = []

        class Recorder(FakeServiceClient):
            def list_objects_v2(self, Bucket):
                captured.append(Bucket)
                return super().list_objects_v2(Bucket)

        fake = FakeFloci()
        fake.client = lambda service, akid=None, secret=None, read_timeout=None: \
            Recorder(service, akid)
        a.execute_incident_activity(fake, _credential())
        assert "arn:aws:s3:::" not in "".join(captured)
        assert "csi-incident-bucket" in captured

    def test_ev005_still_denied_across_scope(self):
        results = self._dispatch(None)
        assert results["EV-005"].observed_result == a.Observed.AUTHORIZATION_DENIED

    def test_no_manual_arn_splitting_remains_in_dispatch(self):
        source = (REPO / "cloudsec_agent/scenario/activity.py").read_text()
        body = source[source.index("def _dispatch"):source.index("def execute_incident_activity")]
        assert 'split("/")' not in body
        assert "arn:aws:s3" not in body
        assert "parse_s3_target" in body


class TestLocalValidationErrorClassification:
    def _error(self, exc):
        return a._extract_exception(exc)

    def test_param_validation_error_extracts_safe_code(self):
        from botocore.exceptions import ParamValidationError
        status, code, rid, kind = self._error(ParamValidationError(report="x"))
        assert status is None
        assert code == "ParamValidationError"
        assert rid is None
        assert kind == "ParamValidationError"

    def test_param_validation_error_classifies_api_error(self):
        from botocore.exceptions import ParamValidationError
        exc = ParamValidationError(report="invalid bucket")
        status, code, rid, kind = a._extract_exception(exc)
        observed, http, error, _ = a.classify_outcome(
            ok=False, error_code=code, http_status=status, request_id=rid)
        assert observed == a.Observed.API_ERROR
        assert error == "ParamValidationError"

    def test_param_validation_error_is_not_authorization_denied(self):
        from botocore.exceptions import ParamValidationError
        status, code, rid, kind = a._extract_exception(
            ParamValidationError(report="x"))
        assert not a.is_authorization_denial(code, status)

    def test_param_validation_error_no_longer_inconclusive(self):
        from botocore.exceptions import ParamValidationError
        status, code, rid, kind = a._extract_exception(
            ParamValidationError(report="x"))
        observed, *_ = a.classify_outcome(ok=False, error_code=code,
                                         http_status=status, request_id=rid)
        assert observed != a.Observed.INCONCLUSIVE

    def test_access_denied_behaviour_unchanged(self):
        status, code, rid, kind = self._error(FakeClientError("AccessDenied", 403))
        assert (status, code) == (403, "AccessDenied")
        observed, *_ = a.classify_outcome(ok=False, error_code=code,
                                         http_status=status, request_id=rid)
        assert observed == a.Observed.AUTHORIZATION_DENIED

    def test_no_such_key_behaviour_unchanged(self):
        status, code, rid, kind = self._error(FakeClientError("NoSuchKey", 404))
        observed, *_ = a.classify_outcome(ok=False, error_code=code,
                                         http_status=status, request_id=rid)
        assert observed == a.Observed.API_ERROR
        assert code == "NoSuchKey"

    def test_resource_not_found_behaviour_unchanged(self):
        status, code, rid, kind = self._error(
            FakeClientError("ResourceNotFoundException", 400))
        observed, *_ = a.classify_outcome(ok=False, error_code=code,
                                         http_status=status, request_id=rid)
        assert observed == a.Observed.API_ERROR

    def test_transport_ambiguity_remains_inconclusive(self):
        status, code, rid, kind = self._error(TimeoutError("timed out"))
        assert code is None and status is None
        observed, *_ = a.classify_outcome(ok=False, error_code=code,
                                         http_status=status, request_id=rid)
        assert observed == a.Observed.INCONCLUSIVE

    def test_generic_exception_remains_inconclusive(self):
        status, code, rid, kind = self._error(RuntimeError("boom"))
        assert code is None
        observed, *_ = a.classify_outcome(ok=False, error_code=code,
                                         http_status=status, request_id=rid)
        assert observed == a.Observed.INCONCLUSIVE

    def test_no_credential_material_in_detail_or_repr(self):
        from botocore.exceptions import ParamValidationError
        exc = ParamValidationError(
            report=f"AKIAEXAMPLE0000000A leaked {SIMULATED_SECRET}")
        status, code, rid, kind = a._extract_exception(exc)
        result = a.ActivityResult(
            event_id="EV-001", service="s3", operation="s3:GetObject",
            target="t", observed_result=a.Observed.API_ERROR,
            error_code=code, detail=kind)
        blob = json.dumps(dataclasses.asdict(result)) + repr(result)
        assert SIMULATED_SECRET not in blob
        assert "AKIAEXAMPLE" not in blob

    def test_secret_probe_uses_same_classification(self):
        from botocore.exceptions import ParamValidationError

        class BadClient:
            def get_secret_value(self, SecretId):
                raise ParamValidationError(report="bad SecretId")

        observed, status, code, rid, returned, detail = a._execute_secret_probe(
            BadClient(), "arn")
        assert observed == a.Observed.API_ERROR
        assert code == "ParamValidationError"
        assert returned is False
