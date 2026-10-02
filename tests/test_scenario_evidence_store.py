import ast
import dataclasses
import json
import pathlib

import pytest

from cloudsec_agent.scenario import activity as a
from cloudsec_agent.scenario import evidence as ev
from cloudsec_agent.scenario import evidence_store as store
from cloudsec_agent.scenario.credentials import IncidentRuntimeCredential

REPO = pathlib.Path(__file__).resolve().parents[1]
KEY_ID = "AKIATEST0000000001"
SIM_SECRET_ACCESS_KEY = "simulated-secret-access-key-value"
SIM_SECRET_STRING = "simulated-secret-string-value"
SIM_SECRET_BINARY = "c2ltdWxhdGVkLXNlY3JldC1iaW5hcnk="


def _result(event_id, **overrides):
    payload = dict(event_id=event_id, service="s3", operation="op",
                   target="target", observed_result=a.Observed.SUCCESS,
                   actor_access_key_id=KEY_ID)
    payload.update(overrides)
    return a.ActivityResult(**payload)


def _execution(count=8, **overrides):
    results = [_result(f"EV-00{index}") for index in range(1, count + 1)]
    return a.ActivityExecution(results=results, access_key_id=KEY_ID,
                               **overrides)


def _prefix(count, **last_overrides):
    results = [_result(f"EV-00{index}") for index in range(1, count + 1)]
    if last_overrides:
        results[-1] = _result(f"EV-00{count}", **last_overrides)
    return results


class _Body:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class FakeS3:
    def __init__(self, put_fails=False, readback_missing=False,
                 readback_garbled=False):
        self.put_fails = put_fails
        self.readback_missing = readback_missing
        self.readback_garbled = readback_garbled
        self.objects = {}
        self.put_keys = []
        self.akid = None

    def put_object(self, Bucket, Key, Body):
        if self.put_fails:
            raise _ClientError("AccessDenied", 403)
        self.objects[(Bucket, Key)] = Body
        self.put_keys.append((Bucket, Key))
        return {"ETag": "etag"}

    def get_object(self, Bucket, Key):
        if self.readback_missing or (Bucket, Key) not in self.objects:
            raise _ClientError("NoSuchKey", 404)
        body = self.objects[(Bucket, Key)]
        if self.readback_garbled:
            body = b"{not json"
        return {"Body": _Body(body)}


class FakeLogs:
    def __init__(self, put_fails=False, readback_missing=False,
                 readback_error=False, extra_messages=(), page_size=None):
        self.put_fails = put_fails
        self.readback_missing = readback_missing
        self.readback_error = readback_error
        self.extra_messages = list(extra_messages)
        self.messages = []
        self.submitted_timestamps = []
        self.filter_calls = 0
        self.get_calls = 0
        self.page_size = page_size

    def put_log_events(self, logGroupName, logStreamName, logEvents):
        if self.put_fails:
            raise _ClientError("AccessDenied", 403)
        for event in logEvents:
            self.submitted_timestamps.append(event["timestamp"])
        self.messages.extend(item["message"] for item in logEvents)
        return {"nextSequenceToken": "token"}

    def filter_log_events(self, *args, **kwargs):
        self.filter_calls += 1
        raise AssertionError(
            "evidence_store must not call filter_log_events; Floci rejects "
            "logStreamName and filterPattern before any request")

    def get_log_events(self, logGroupName, logStreamName, nextToken=None):
        self.get_calls += 1
        if self.readback_error:
            raise _ClientError("ServiceUnavailable", 503)
        pool = self.extra_messages + self.messages
        if self.readback_missing:
            pool = self.extra_messages
        if self.page_size:
            start = int(nextToken) if nextToken else 0
            page = pool[start:start + self.page_size]
            end = start + self.page_size
            token = str(end) if end < len(pool) else None
        else:
            page = pool
            token = None
        payload = {"events": [{"message": item, "timestamp": 0} for item in page]}
        if token:
            payload["nextForwardToken"] = token
        return payload


class _ClientError(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {
            "Error": {"Code": code, "Message": "m"},
            "ResponseMetadata": {"HTTPStatusCode": status, "RequestId": "req-1"},
        }


class FakeFloci:
    def __init__(self, s3=None, logs=None):
        self.endpoint = "http://localhost:4567"
        self.s3 = s3 if s3 is not None else FakeS3()
        self.logs = logs if logs is not None else FakeLogs()

    def client(self, service, akid=None, secret=None, read_timeout=None):
        return {"s3": self.s3, "logs": self.logs}[service]


class TestDocumentConstruction:
    def test_complete_execution_produces_eight_documents(self):
        documents = store.build_evidence_documents(_execution())
        assert len(documents) == 8
        assert [item.event_id for item in documents] == [
            f"EV-00{index}" for index in range(1, 9)]

    def test_catalogue_event_time_and_basis_are_used(self):
        documents = store.build_evidence_documents(_execution())
        for item in documents:
            entry = next(e for e in ev.AUTHORITATIVE_EVIDENCE
                         if e.id == item.event_id)
            assert item.event_time == entry.event_time
            assert item.time_basis == entry.time_basis
            assert item.attacker_controllable == entry.attacker_controllable
            assert item.authoritative is True

    def test_activity_result_cannot_override_catalogue_metadata(self):
        results = [_result("EV-001", service="tampered", operation="tampered",
                           target="tampered")]
        documents = store.build_evidence_documents(results)
        entry = ev.AUTHORITATIVE_EVIDENCE[0]
        assert documents[0].service == entry.service
        assert documents[0].operation == entry.operation
        assert documents[0].target == entry.target
        assert documents[0].event_time == entry.event_time

    def test_observed_fields_are_propagated(self):
        results = [_result(f"EV-00{index}") for index in range(1, 6)]
        results[4] = _result("EV-005",
                             observed_result=a.Observed.AUTHORIZATION_DENIED,
                             http_status=403, error_code="AccessDenied",
                             secret_material_returned=True,
                             native_corroborated=True,
                             actor_access_key_id=KEY_ID)
        document = store.build_evidence_documents(results)[4]
        assert document.observed_result == a.Observed.AUTHORIZATION_DENIED
        assert document.observed_http_status == 403
        assert document.observed_error_code == "AccessDenied"
        assert document.secret_material_returned is True
        assert document.native_corroborated is True
        assert document.actor_access_key_id == KEY_ID

    def test_document_has_no_raw_or_catch_all_field(self):
        names = {item.name for item in dataclasses.fields(store.EvidenceDocument)}
        for forbidden in a.FORBIDDEN_RESULT_FIELDS:
            assert forbidden not in names, forbidden

    def test_detail_is_never_serialized(self):
        results = [_result("EV-001", detail="sensitive-detail-text")]
        document = store.build_evidence_documents(results)[0]
        payload = store.serialize_document(document)
        assert "sensitive-detail-text" not in payload
        assert "detail" not in json.loads(payload)


class TestExecutionValidation:
    def test_duplicate_event_id_is_rejected(self):
        results = [_result("EV-001"), _result("EV-001")]
        with pytest.raises(store.EvidenceValidationError):
            store.build_evidence_documents(results)

    def test_unknown_event_id_is_rejected(self):
        with pytest.raises(store.EvidenceValidationError):
            store.build_evidence_documents([_result("EV-099")])

    def test_out_of_order_is_rejected(self):
        results = [_result("EV-002"), _result("EV-001")]
        with pytest.raises(store.EvidenceValidationError):
            store.build_evidence_documents(results)

    def test_missing_middle_event_is_rejected(self):
        results = [_result("EV-001"), _result("EV-003")]
        with pytest.raises(store.EvidenceValidationError):
            store.build_evidence_documents(results)

    def test_valid_stopped_early_prefix_is_accepted(self):
        documents = store.build_evidence_documents(_execution(6))
        assert [item.event_id for item in documents] == [
            f"EV-00{index}" for index in range(1, 7)]

    def test_stopped_early_non_prefix_is_rejected(self):
        results = [_result("EV-001"), _result("EV-003"), _result("EV-004")]
        with pytest.raises(store.EvidenceValidationError):
            store.build_evidence_documents(results)

    def test_seven_event_prefix_is_accepted_as_partial(self):
        documents = store.build_evidence_documents(_execution(7))
        assert len(documents) == 7
        assert documents[-1].event_id == "EV-007"

    def test_invalid_input_type_is_rejected(self):
        with pytest.raises(store.EvidenceValidationError):
            store.build_evidence_documents({"EV-001": {}})

    def test_non_activity_result_values_are_rejected(self):
        with pytest.raises(store.EvidenceValidationError):
            store.build_evidence_documents([{"id": "EV-001"}])

    def test_list_of_results_is_accepted(self):
        documents = store.build_evidence_documents(
            [_result(f"EV-00{index}") for index in range(1, 9)])
        assert len(documents) == 8


class TestSerializationSafety:
    def _serialized(self):
        documents = store.build_evidence_documents(_prefix(
            6, observed_result=a.Observed.UNEXPECTED_SUCCESS,
            secret_material_returned=True, detail="detail-text"))
        return store.serialize_document(documents[5])

    def test_simulated_material_is_absent(self):
        payload = self._serialized()
        for secret in (SIM_SECRET_ACCESS_KEY, SIM_SECRET_STRING, SIM_SECRET_BINARY):
            assert secret not in payload

    def test_serializer_never_creates_response_secret_fields(self):
        payload = json.loads(self._serialized())
        for forbidden in ("SecretString", "SecretBinary", "SecretAccessKey",
                          "SessionToken"):
            assert forbidden not in payload

    def test_secret_material_flag_is_persisted(self):
        payload = json.loads(self._serialized())
        assert payload["secret_material_returned"] is True

    def test_serializer_does_not_use_asdict_or_vars(self):
        source = (REPO / "cloudsec_agent/scenario/evidence_store.py").read_text()
        assert "asdict(" not in source
        assert "vars(" not in source
        assert "__dict__" not in source

    def test_serialisation_is_deterministic(self):
        documents = store.build_evidence_documents([_result("EV-001")])
        assert store.serialize_document(documents[0]) == \
            store.serialize_document(documents[0])

    def test_cloudwatch_copy_is_marked_and_distinct(self):
        documents = store.build_evidence_documents([_result("EV-001")])
        authoritative = json.loads(store.serialize_document(documents[0]))
        assert documents[0].event_id == "EV-001"
        copy = json.loads(store.serialize_cloudwatch_copy(documents[0]))
        assert authoritative[store.STORAGE_ROLE_FIELD] == \
            store.STORAGE_ROLE_AUTHORITATIVE
        assert copy[store.STORAGE_ROLE_FIELD] == store.STORAGE_ROLE_COPY
        assert copy["id"] == authoritative["id"]
        assert copy["event_time"] == authoritative["event_time"]

    def test_cloudwatch_copy_keeps_synthetic_reference_time(self):
        documents = store.build_evidence_documents([_result("EV-001")])
        copy = json.loads(store.serialize_cloudwatch_copy(documents[0]))
        assert copy["event_time"] == ev.AUTHORITATIVE_EVIDENCE[0].event_time
        assert copy["time_basis"] == "synthetic_reference"


class TestS3Persistence:
    def test_confirmed_on_exact_readback(self):
        fake = FakeFloci()
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is None
        assert result.fatal_errors == []
        assert len(result.confirmed_s3()) == 8
        assert len(fake.s3.put_keys) == 8
        for record in result.s3_records:
            assert record.classification == store.StoreClass.CONFIRMED
            assert record.confirmed is True

    def test_exact_keys_and_bucket(self):
        fake = FakeFloci()
        store.write_evidence(fake, _execution())
        for bucket, key in fake.s3.put_keys:
            assert bucket == "csi-evidence-bucket"
            assert key.startswith("activity/EV-00")
            assert key.endswith(".json")

    def test_put_success_but_missing_object_is_empty_success(self):
        fake = FakeFloci(s3=FakeS3(readback_missing=True))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is not None
        assert result.first_divergence.classification == \
            store.StoreClass.EMPTY_SUCCESS
        assert result.first_divergence.event_id == "EV-001"

    def test_garbled_readback_is_empty_success(self):
        fake = FakeFloci(s3=FakeS3(readback_garbled=True))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.EMPTY_SUCCESS

    def test_put_api_error_is_api_error(self):
        fake = FakeFloci(s3=FakeS3(put_fails=True))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.API_ERROR
        assert result.first_divergence.error_code == "AccessDenied"

    def test_s3_failure_prevents_cloudwatch_write(self):
        fake = FakeFloci(s3=FakeS3(readback_missing=True))
        store.write_evidence(fake, _execution())
        assert fake.logs.messages == []
        assert len(fake.s3.put_keys) == 1

    def test_stop_on_first_divergence(self):
        fake = FakeFloci()
        result = store.write_evidence(fake, _execution(6))
        assert result.first_divergence is None
        assert len(result.confirmed_s3()) == 6
        assert len(result.confirmed_cloudwatch()) == 6


class TestCloudWatchPersistence:
    def test_one_copy_per_confirmed_event(self):
        fake = FakeFloci()
        result = store.write_evidence(fake, _execution())
        assert len(fake.logs.messages) == 8
        assert len(result.confirmed_cloudwatch()) == 8

    def test_copies_are_marked_as_copies(self):
        fake = FakeFloci()
        store.write_evidence(fake, _execution())
        for message in fake.logs.messages:
            payload = json.loads(message)
            assert payload[store.STORAGE_ROLE_FIELD] == \
                store.STORAGE_ROLE_COPY
            assert payload["provenance"] == "synthetic_authoritative"

    def test_copy_contains_no_secret_material(self):
        fake = FakeFloci()
        store.write_evidence(fake, _execution())
        joined = "\n".join(fake.logs.messages)
        for secret in (SIM_SECRET_ACCESS_KEY, SIM_SECRET_STRING, SIM_SECRET_BINARY):
            assert secret not in joined
        assert "SessionToken" not in joined
        assert "SecretString" not in joined

    def test_missing_copy_readback_is_empty_success(self):
        fake = FakeFloci(logs=FakeLogs(readback_missing=True))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is not None
        assert result.first_divergence.classification == \
            store.StoreClass.EMPTY_SUCCESS
        assert result.first_divergence.storage == "cloudwatch"

    def test_log_put_api_error_is_api_error(self):
        fake = FakeFloci(logs=FakeLogs(put_fails=True))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.API_ERROR
        assert result.first_divergence.storage == "cloudwatch"

    def test_cloudwatch_failure_keeps_confirmed_s3_record(self):
        fake = FakeFloci(logs=FakeLogs(put_fails=True))
        result = store.write_evidence(fake, _execution())
        assert result.confirmed_s3() == ["EV-001"]
        assert result.confirmed_cloudwatch() == []
        assert len(fake.s3.put_keys) == 1

    def test_cloudwatch_failure_stops_later_events(self):
        fake = FakeFloci(logs=FakeLogs(put_fails=True))
        store.write_evidence(fake, _execution())
        assert len(fake.s3.put_keys) == 1


class TestResultSafety:
    def test_result_repr_contains_no_secret(self):
        results = _prefix(6, secret_material_returned=True,
                          detail=SIM_SECRET_STRING)
        result = store.write_evidence(FakeFloci(), results)
        blob = repr(result) + str(result) + json.dumps(result.as_dict())
        for secret in (SIM_SECRET_ACCESS_KEY, SIM_SECRET_STRING,
                       SIM_SECRET_BINARY):
            assert secret not in blob

    def test_record_has_no_body_or_raw_field(self):
        names = {item.name for item in dataclasses.fields(store.EvidenceWriteRecord)}
        for forbidden in a.FORBIDDEN_RESULT_FIELDS:
            assert forbidden not in names, forbidden
        assert "body" not in names

    def test_divergence_records_event_and_storage_only(self):
        fake = FakeFloci(s3=FakeS3(readback_missing=True))
        result = store.write_evidence(fake, _execution())
        record = result.first_divergence
        assert record.event_id == "EV-001"
        assert record.storage == "s3"
        assert record.classification == store.StoreClass.EMPTY_SUCCESS

    def test_documents_tuple_is_exposed_for_inspection(self):
        result = store.write_evidence(FakeFloci(), _execution())
        assert len(result.documents) == 8


class TestModuleBoundaries:
    def test_no_direct_boto3_usage(self):
        source = (REPO / "cloudsec_agent/scenario/evidence_store.py").read_text()
        assert "boto3.client(" not in source
        assert "boto3.resource(" not in source
        assert "import boto3" not in source

    def test_module_does_not_import_credentials(self):
        source = (REPO / "cloudsec_agent/scenario/evidence_store.py").read_text()
        assert "credentials" not in source
        assert "IncidentRuntimeCredential" not in source

    def test_no_get_secret_value_call(self):
        source = (REPO / "cloudsec_agent/scenario/evidence_store.py").read_text()
        assert "get_secret_value" not in source

    def test_no_reset_or_seed_logic(self):
        source = (REPO / "cloudsec_agent/scenario/evidence_store.py").read_text()
        for forbidden in ("from .reset", "from .seed", "seed_scenario",
                          "reset_canonical", "create_access_key", "delete_object",
                          "create_user", "delete_user"):
            assert forbidden not in source, forbidden

    def test_no_native_cloudtrail_access(self):
        source = (REPO / "cloudsec_agent/scenario/evidence_store.py").read_text()
        assert "cloudtrail" not in source.lower()
        assert "trail" not in source.lower()

    def test_module_carries_no_docstrings(self):
        tree = ast.parse(
            (REPO / "cloudsec_agent/scenario/evidence_store.py").read_text())
        assert not ast.get_docstring(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                assert not ast.get_docstring(node)

    def test_credential_type_is_never_a_parameter(self):
        signature = ast.parse(
            (REPO / "cloudsec_agent/scenario/evidence_store.py").read_text())
        for node in ast.walk(signature):
            if isinstance(node, ast.FunctionDef):
                for argument in node.args.args:
                    assert argument.arg not in ("credential", "secret_access_key"), \
                        node.name

class TestCloudWatchReadBackContract:
    def test_readback_uses_get_log_events(self):
        fake = FakeFloci()
        store.write_evidence(fake, _execution())
        assert fake.logs.get_calls == 8
        assert fake.logs.filter_calls == 0

    def test_filter_log_events_is_never_called(self):
        fake = FakeFloci()
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is None
        assert fake.logs.filter_calls == 0

    def test_source_contains_no_filter_log_events_call(self):
        source = (REPO / "cloudsec_agent/scenario/evidence_store.py").read_text()
        assert "filter_log_events" not in source

    def test_timestamp_submitted_is_exactly_zero(self):
        fake = FakeFloci()
        store.write_evidence(fake, _execution())
        assert fake.logs.submitted_timestamps == [0] * 8

    def test_submitted_timestamp_is_not_the_current_time(self):
        fake = FakeFloci()
        store.write_evidence(fake, _execution())
        assert all(value == 0 for value in fake.logs.submitted_timestamps)

    def test_synthetic_event_time_inside_message_is_unchanged(self):
        fake = FakeFloci()
        store.write_evidence(fake, _execution())
        for index, message in enumerate(fake.logs.messages, start=1):
            payload = json.loads(message)
            assert payload["event_time"] == ev.AUTHORITATIVE_EVIDENCE[
                index - 1].event_time
            assert payload["time_basis"] == "synthetic_reference"

    def test_native_log_timestamp_is_not_compared_to_synthetic_time(self):
        fake = FakeFloci()
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is None
        for message in fake.logs.messages:
            assert json.loads(message)["event_time"] != 0

    def test_wrong_storage_role_does_not_confirm(self):
        wrong = json.dumps({"id": "EV-001",
                            "storage_role": "authoritative_s3"})
        fake = FakeFloci(logs=FakeLogs(readback_missing=True,
                                       extra_messages=[wrong]))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.EMPTY_SUCCESS
        assert result.first_divergence.event_id == "EV-001"

    def test_wrong_id_with_correct_role_does_not_confirm(self):
        wrong = json.dumps({"id": "EV-099",
                            "storage_role": "cloudwatch_copy"})
        fake = FakeFloci(logs=FakeLogs(readback_missing=True,
                                       extra_messages=[wrong]))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.EMPTY_SUCCESS

    def test_id_only_match_without_role_does_not_confirm(self):
        id_only = json.dumps({"id": "EV-001"})
        fake = FakeFloci(logs=FakeLogs(readback_missing=True,
                                       extra_messages=[id_only]))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.EMPTY_SUCCESS

    def test_malformed_json_message_is_ignored(self):
        fake = FakeFloci(logs=FakeLogs(extra_messages=["{not json", "plain text"]))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is None

    def test_json_scalar_and_list_messages_are_ignored(self):
        fake = FakeFloci(logs=FakeLogs(extra_messages=["[1, 2, 3]", '"scalar"',
                                                 "42"]))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is None

    def test_non_string_message_is_ignored(self):
        fake = FakeFloci(logs=FakeLogs(extra_messages=["{}"]))
        fake.logs.extra_messages.append(None)
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is None

    def test_matching_copy_may_coexist_with_unrelated_messages(self):
        fake = FakeFloci(logs=FakeLogs(extra_messages=["{broken", "[1]"]))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is None
        assert len(result.confirmed_cloudwatch()) == 8

    def test_get_log_events_api_error_is_api_error(self):
        fake = FakeFloci(logs=FakeLogs(readback_error=True))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.API_ERROR
        assert result.first_divergence.error_code == "ServiceUnavailable"

    def test_missing_copy_is_empty_success_not_api_error(self):
        fake = FakeFloci(logs=FakeLogs(readback_missing=True))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.EMPTY_SUCCESS
        assert result.first_divergence.error_code is None

    def test_confirmed_s3_survives_cloudwatch_readback_failure(self):
        fake = FakeFloci(logs=FakeLogs(readback_missing=True))
        result = store.write_evidence(fake, _execution())
        assert result.confirmed_s3() == ["EV-001"]
        assert result.confirmed_cloudwatch() == []
        assert len(fake.s3.put_keys) == 1

    def test_later_events_are_not_written_after_cloudwatch_divergence(self):
        fake = FakeFloci(logs=FakeLogs(readback_missing=True))
        store.write_evidence(fake, _execution())
        assert len(fake.s3.put_keys) == 1
        assert len(fake.logs.messages) == 1

    def test_record_retains_no_raw_log_response(self):
        fake = FakeFloci()
        result = store.write_evidence(fake, _execution())
        for record in result.cloudwatch_records:
            values = list(record.__dict__.values())
            assert not any(isinstance(value, (dict, list)) for value in values)

    def test_no_secret_material_is_persisted(self):
        fake = FakeFloci()
        result = store.write_evidence(fake, _execution())
        blob = json.dumps(result.as_dict()) + "\\n".join(fake.logs.messages)
        for forbidden in ("SecretAccessKey", "SessionToken", "SecretString",
                          "SecretBinary"):
            assert forbidden not in blob


class TestBoundedPaging:
    def test_match_on_second_page_succeeds(self):
        padding = [json.dumps({"id": f"padding-{index}",
                               "storage_role": "unrelated"})
                   for index in range(4)]
        fake = FakeFloci(logs=FakeLogs(page_size=4, extra_messages=padding))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence is None
        assert len(result.confirmed_cloudwatch()) == 8
        assert fake.logs.get_calls > 8

    def test_repeated_next_forward_token_terminates(self):
        logs = FakeLogs(page_size=2)
        original = logs.get_log_events

        def looping(logGroupName, logStreamName, nextToken=None):
            payload = original(logGroupName, logStreamName, nextToken)
            payload["nextForwardToken"] = "same"
            return payload
        logs.get_log_events = looping
        result = store.write_evidence(FakeFloci(logs=logs), _execution())
        assert result.first_divergence is not None

    def test_page_bound_is_respected(self):
        logs = FakeLogs(page_size=1)
        original = logs.get_log_events

        def always_next(logGroupName, logStreamName, nextToken=None):
            payload = original(logGroupName, logStreamName, nextToken)
            payload["nextForwardToken"] = str(int(nextToken or 0) + 1)
            return payload
        logs.get_log_events = always_next
        result = store.write_evidence(FakeFloci(logs=logs), _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.EMPTY_SUCCESS
        assert result.first_divergence.event_id == "EV-004"
        assert result.confirmed_cloudwatch() == ["EV-001", "EV-002", "EV-003"]

    def test_page_bound_constant_is_finite(self):
        assert store.MAX_LOG_PAGES == 3

    def test_no_match_within_bound_is_empty_success(self):
        fake = FakeFloci(logs=FakeLogs(readback_missing=True, page_size=1))
        result = store.write_evidence(fake, _execution())
        assert result.first_divergence.classification == \
            store.StoreClass.EMPTY_SUCCESS
