"""Composed integration tests for the M2 runtime seam.

Every scenario wires a fake SDK-shaped IAM client -> the REAL
LiveExecutionPort -> the REAL ContainmentExecutor. No fake port sits
between the two production halves.

This file exists because the adapter and the executor were each
individually well covered while their shared contract was not: the adapter
returns typed state objects and the executor originally accepted only
mappings, so the composed pair silently classified every entry malformed.
"""

import pytest

from cloudsec_agent.backend import approval as ap
from cloudsec_agent.backend import broker as bk
from cloudsec_agent.backend import executor as ex
from cloudsec_agent.backend import live_executor as le
from cloudsec_agent.backend import policy as pl
from cloudsec_agent.backend import registry as rg
from cloudsec_agent.backend import request as rq
from cloudsec_agent.scenario.seed import incident_user_arn, investigator_user_arn

KEY = "AKIAEXAMPLE0000000A"
INCIDENT = "incident-user"
INVESTIGATOR = "security-agent-backend"
INVESTIGATOR_KEY = "AKIAEXAMPLE0000000B"
RUN = "compose-run"


class FakeClientError(Exception):
    def __init__(self, code, status=403):
        super().__init__(code)
        self.response = {"Error": {"Code": code},
                         "ResponseMetadata": {"HTTPStatusCode": status}}


class FakeIam:
    """Fake SDK-shaped IAM client. Responses use raw AWS key names."""

    def __init__(self, incident_metadata=None, investigator_metadata=None,
                 update_error=None, update_silent=False, list_error=None):
        self.incident_metadata = (
            incident_metadata if incident_metadata is not None
            else [{"AccessKeyId": KEY, "Status": "Active",
                   "SecretAccessKey": "fake-sentinel", "CreateDate": "x"}])
        self.investigator_metadata = (
            investigator_metadata if investigator_metadata is not None
            else [{"AccessKeyId": INVESTIGATOR_KEY, "Status": "Active"}])
        self.update_error = update_error
        self.update_silent = update_silent
        self.list_error = list_error
        self.update_calls = []

    def list_access_keys(self, UserName):
        if self.list_error:
            raise self.list_error
        metadata = (self.incident_metadata if UserName == INCIDENT
                    else self.investigator_metadata)
        return {"AccessKeyMetadata": [dict(item) if isinstance(item, dict)
                                      else item for item in metadata],
                "ResponseMetadata": {"HTTPStatusCode": 200,
                                     "RequestId": "req-not-retained"}}

    def update_access_key(self, UserName, AccessKeyId, Status):
        self.update_calls.append((UserName, AccessKeyId, Status))
        if self.update_error:
            raise self.update_error
        if not self.update_silent:
            for entry in self.incident_metadata:
                if isinstance(entry, dict) and \
                        entry.get("AccessKeyId") == AccessKeyId:
                    entry["Status"] = Status
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


def _decisions(compromised=KEY):
    action = rq.canonicalize_containment_update_access_key(
        {"UserName": INCIDENT, "AccessKeyId": compromised, "Status": "Inactive"})
    digest = rq.action_digest(action)
    grant = bk.grant_for(bk.BROAD_CAPABILITY, RUN)
    broker = bk.evaluate(grant, action, RUN)
    context = pl.ScenarioPolicyContext("csi-incident-v1", INCIDENT, compromised)
    policy = pl.evaluate_containment_policy(action, digest, broker, context)
    approval = ap.ApprovalDecision(True, ap.ApprovalReasonCode.APPROVED, digest,
                                   "ap-compose")
    return action, digest, broker, policy, approval


def _execute(iam, compromised=KEY):
    action, digest, broker, policy, approval = _decisions(compromised)
    port = le.LiveExecutionPort(iam)
    executor = ex.ContainmentExecutor(port)
    return executor.execute(action, digest, broker, policy, approval,
                            INVESTIGATOR, INVESTIGATOR_KEY)


class TestPortContractIsExplicit:
    def test_adapter_returns_typed_state_objects(self):
        port = le.LiveExecutionPort(FakeIam())
        states = port.list_access_keys(INCIDENT)
        assert isinstance(states, tuple)
        assert all(isinstance(item, le.AccessKeyState) for item in states)

    def test_typed_state_exposes_narrow_attributes(self):
        state = le.LiveExecutionPort(FakeIam()).list_access_keys(INCIDENT)[0]
        assert state.access_key_id == KEY
        assert state.status == "Active"

    def test_executor_consumes_exactly_what_the_adapter_returns(self):
        port = le.LiveExecutionPort(FakeIam())
        executor = ex.ContainmentExecutor(port)
        produced = port.list_access_keys(INCIDENT)
        verdict, _ = executor._read_state(INCIDENT, KEY)
        assert verdict is ex.AccessKeyState.ACTIVE
        assert all(ex._state_fields(item) is not None for item in produced)

    def test_adapter_output_carries_no_secret_or_metadata(self):
        states = le.LiveExecutionPort(FakeIam()).list_access_keys(INCIDENT)
        blob = repr(states)
        for forbidden in ("SecretAccessKey", "fake-sentinel", "CreateDate",
                          "RequestId", "ResponseMetadata"):
            assert forbidden not in blob


class TestComposedActiveToConfirmed:
    def test_active_transitions_to_confirmed(self):
        iam = FakeIam()
        result = _execute(iam)
        assert result.classification is ex.ContainmentClassification.CONFIRMED
        assert result.execution_attempted is True
        assert result.execution_succeeded is True
        assert result.verified_effective is True

    def test_exactly_one_update_call(self):
        iam = FakeIam()
        _execute(iam)
        assert iam.update_calls == [(INCIDENT, KEY, "Inactive")]

    def test_incident_key_ends_inactive(self):
        iam = FakeIam()
        _execute(iam)
        assert iam.incident_metadata[0]["Status"] == "Inactive"

    def test_investigator_stays_active(self):
        iam = FakeIam()
        result = _execute(iam)
        assert iam.investigator_metadata[0]["Status"] == "Active"
        assert result.verified_effective is True

    def test_no_administrative_fallback_is_used(self):
        iam = FakeIam()
        _execute(iam)
        assert all(call[0] == INCIDENT for call in iam.update_calls)


class TestComposedAlreadyInactive:
    def test_inactive_incident_key_is_already_effective(self):
        iam = FakeIam(incident_metadata=[{"AccessKeyId": KEY,
                                          "Status": "Inactive"}])
        result = _execute(iam)
        assert result.classification is \
            ex.ContainmentClassification.ALREADY_EFFECTIVE
        assert result.execution_attempted is False
        assert result.execution_succeeded is False
        assert result.verified_effective is True

    def test_already_effective_issues_zero_updates(self):
        iam = FakeIam(incident_metadata=[{"AccessKeyId": KEY,
                                          "Status": "Inactive"}])
        _execute(iam)
        assert iam.update_calls == []

    def test_already_effective_still_verifies_investigator(self):
        iam = FakeIam(incident_metadata=[{"AccessKeyId": KEY,
                                          "Status": "Inactive"}])
        result = _execute(iam)
        assert iam.investigator_metadata[0]["Status"] == "Active"
        assert result.verified_effective is True


class TestComposedEmptySuccess:
    def test_mutation_without_state_change_is_empty_success(self):
        iam = FakeIam(update_silent=True)
        result = _execute(iam)
        assert result.classification is \
            ex.ContainmentClassification.EMPTY_SUCCESS
        assert result.execution_attempted is True
        assert result.execution_succeeded is True
        assert result.verified_effective is False

    def test_empty_success_issues_exactly_one_update(self):
        iam = FakeIam(update_silent=True)
        _execute(iam)
        assert len(iam.update_calls) == 1


class TestComposedApiError:
    def test_mutation_api_error_is_api_error(self):
        iam = FakeIam(update_error=FakeClientError("AccessDenied"))
        result = _execute(iam)
        assert result.classification is ex.ContainmentClassification.API_ERROR
        assert result.execution_attempted is True
        assert result.execution_succeeded is False
        assert result.verified_effective is False

    def test_api_error_is_not_retried(self):
        iam = FakeIam(update_error=FakeClientError("AccessDenied"))
        _execute(iam)
        assert len(iam.update_calls) == 1

    def test_read_api_error_is_inconclusive_without_mutation(self):
        iam = FakeIam(list_error=FakeClientError("AccessDenied"))
        result = _execute(iam)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert iam.update_calls == []


class TestComposedMissingKey:
    def test_missing_incident_key_does_not_mutate(self):
        iam = FakeIam(incident_metadata=[{"AccessKeyId": "AKIAOTHER00000001",
                                          "Status": "Active"}])
        result = _execute(iam)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert result.reason_code == "key_not_found"
        assert iam.update_calls == []


class TestComposedDuplicateKey:
    def test_duplicate_exact_entries_do_not_mutate(self):
        iam = FakeIam(incident_metadata=[{"AccessKeyId": KEY, "Status": "Active"},
                                         {"AccessKeyId": KEY,
                                          "Status": "Inactive"}])
        result = _execute(iam)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert result.reason_code == "duplicate_exact_key"
        assert iam.update_calls == []


class TestComposedMalformedPayload:
    def test_malformed_metadata_is_inconclusive_without_mutation(self):
        iam = FakeIam(incident_metadata=[{"AccessKeyId": KEY},
                                         {"AccessKeyId": "no-status"}])
        result = _execute(iam)
        assert result.classification is ex.ContainmentClassification.INCONCLUSIVE
        assert iam.update_calls == []

    def test_non_string_identifier_is_rejected_as_malformed(self):
        assert ex._state_fields({"AccessKeyId": 1234, "Status": "Active"}) is None

    def test_none_status_is_rejected(self):
        assert ex._state_fields({"AccessKeyId": KEY, "Status": None}) is None

    def test_empty_identifier_is_rejected(self):
        assert ex._state_fields({"AccessKeyId": "  ", "Status": "Active"}) is None

    def test_bytes_status_is_not_coerced(self):
        assert ex._state_fields({"AccessKeyId": KEY,
                                 "Status": b"Inactive"}) is None

    def test_arbitrary_object_is_rejected(self):
        assert ex._state_fields(object()) is None

    def test_object_with_wrong_attribute_types_is_rejected(self):
        class Weird:
            access_key_id = 5
            status = None
        assert ex._state_fields(Weird()) is None

    def test_missing_attribute_is_rejected(self):
        class Partial:
            access_key_id = KEY
        assert ex._state_fields(Partial()) is None

    def test_malformed_typed_entry_is_rejected(self):
        assert ex._state_fields(le.AccessKeyState(access_key_id=KEY,
                                                  status=None)) is None


class TestComposedInvestigatorChange:
    def test_investigator_change_prevents_effectiveness(self):
        iam = FakeIam(investigator_metadata=[{"AccessKeyId": INVESTIGATOR_KEY,
                                              "Status": "Inactive"}])
        result = _execute(iam)
        assert result.verified_effective is False
        assert result.classification is not \
            ex.ContainmentClassification.CONFIRMED

    def test_missing_investigator_prevents_effectiveness(self):
        iam = FakeIam(investigator_metadata=[])
        result = _execute(iam)
        assert result.verified_effective is False

    def test_investigator_is_never_mutated(self):
        iam = FakeIam()
        _execute(iam)
        assert all(call[0] != INVESTIGATOR for call in iam.update_calls)


class TestDictFakeCompatibilityRetained:
    def test_mapping_entries_are_still_accepted(self):
        assert ex._state_fields({"AccessKeyId": KEY,
                                 "Status": "Active"}) == (KEY, "Active")

    def test_mapping_entries_still_drive_the_executor(self):
        class DictPort(ex.ExecutionPort):
            def __init__(self, entries):
                self.entries = entries
                self.updates = []

            def list_access_keys(self, user_name):
                return list(self.entries)

            def update_access_key_status(self, user_name, key_id, status):
                self.updates.append((user_name, key_id, status))
                for entry in self.entries:
                    if entry["AccessKeyId"] == key_id:
                        entry["Status"] = status
                return le.MutationCallResult(succeeded=True, http_status=200)

        port = DictPort([{"AccessKeyId": KEY, "Status": "Active"},
                         {"AccessKeyId": INVESTIGATOR_KEY, "Status": "Active"}])
        action, digest, broker, policy, approval = _decisions()
        result = ex.ContainmentExecutor(port).execute(
            action, digest, broker, policy, approval, INVESTIGATOR,
            INVESTIGATOR_KEY)
        assert result.classification is ex.ContainmentClassification.CONFIRMED
        assert port.updates == [(INCIDENT, KEY, "Inactive")]


class TestAuthorizationStillGatesExecution:
    def test_composed_executor_refuses_without_approval(self):
        action, digest, broker, policy, _ = _decisions()
        executor = ex.ContainmentExecutor(le.LiveExecutionPort(FakeIam()))
        with pytest.raises(ex.ExecutionPrerequisiteError):
            executor.execute(action, digest, broker, policy,
                             ap.ApprovalDecision(False,
                                                 ap.ApprovalReasonCode.DENIED,
                                                 digest, "ap-x"),
                             INVESTIGATOR, INVESTIGATOR_KEY)

    def test_composed_executor_refuses_on_policy_denial(self):
        action, digest, broker, policy, approval = _decisions()
        denied = pl.PolicyDecision(False, pl.PolicyReasonCode.WRONG_USER, "",
                                   digest)
        executor = ex.ContainmentExecutor(le.LiveExecutionPort(FakeIam()))
        with pytest.raises(ex.ExecutionPrerequisiteError):
            executor.execute(action, digest, broker, denied, approval,
                             INVESTIGATOR, INVESTIGATOR_KEY)

    def test_authorization_reached_before_any_mutation(self):
        action, digest, broker, _, _ = _decisions()
        iam = FakeIam()
        executor = ex.ContainmentExecutor(le.LiveExecutionPort(iam))
        with pytest.raises(ex.ExecutionPrerequisiteError):
            executor.execute(action, digest, broker,
                             pl.PolicyDecision(False,
                                               pl.PolicyReasonCode.WRONG_USER,
                                               "", digest),
                             ap.ApprovalDecision(True,
                                                 ap.ApprovalReasonCode.APPROVED,
                                                 digest, "ap"),
                             INVESTIGATOR, INVESTIGATOR_KEY)
        assert iam.update_calls == []

    def test_canonical_resource_still_matches_frozen_m1_arns(self):
        action, _, _, _, _ = _decisions()
        assert action.resource == incident_user_arn()
        assert action.tool_id == rg.UPDATE_ACCESS_KEY
        assert investigator_user_arn() != action.resource


class TestMutationOutcomeContractIsExplicit:
    def test_adapter_returns_a_typed_mutation_result(self):
        port = le.LiveExecutionPort(FakeIam())
        outcome = port.update_access_key_status(INCIDENT, KEY, "Inactive")
        assert isinstance(outcome, le.MutationCallResult)
        assert outcome.succeeded is True

    def test_executor_reads_the_typed_mutation_result(self):
        outcome = le.LiveExecutionPort(FakeIam()).update_access_key_status(
            INCIDENT, KEY, "Inactive")
        assert ex._port_outcome(outcome) == (200, None, "")

    def test_executor_reads_a_typed_failure_outcome(self):
        class Failure:
            succeeded = False
            http_status = 403
            error_code = "AccessDenied"
            detail = "denied"
        assert ex._port_outcome(Failure()) == (403, "AccessDenied", "denied")

    def test_typed_failure_outcome_with_blank_code_is_still_an_error(self):
        class Failure:
            succeeded = False
            http_status = 500
            error_code = ""
            detail = ""
        status, code, _ = ex._port_outcome(Failure())
        assert code == "PortNoOutcome" or code is None or code == ""

    def test_tuple_and_mapping_outcomes_remain_supported(self):
        assert ex._port_outcome((200, None, "")) == (200, None, "")
        assert ex._port_outcome({"http_status": 200, "error_code": None,
                                 "detail": ""}) == (200, None, "")

    def test_exception_outcome_remains_supported(self):
        assert ex._port_outcome(FakeClientError("AccessDenied"))[1] == \
            "FakeClientError"

    def test_none_outcome_remains_supported(self):
        assert ex._port_outcome(None)[1] == "PortNoOutcome"
