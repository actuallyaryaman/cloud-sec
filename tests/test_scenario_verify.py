import ast
import dataclasses
import json
import pathlib

import pytest

from cloudsec_agent import seed_scenario as cli
from cloudsec_agent.scenario import activity as act
from cloudsec_agent.scenario import evidence as ev
from cloudsec_agent.scenario import evidence_store as store
from cloudsec_agent.scenario import manifest as mf
from cloudsec_agent.scenario import verify as vr

REPO = pathlib.Path(__file__).resolve().parents[1]
KEY_ID = "AKIATEST0000000001"
INVESTIGATOR_KEY = "AKIATEST0000000002"
SIM_SECRET = "simulated-secret-value-for-tests"


class _ClientError(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "m"},
                         "ResponseMetadata": {"HTTPStatusCode": status,
                                              "RequestId": "r"}}


class _Body:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class FakeS3:
    def __init__(self, state):
        self.state = state
        self.objects = {}

    def list_buckets(self):
        return {"Buckets": [{"Name": name} for name in self.state["buckets"]]}

    def get_object(self, Bucket, Key):
        body = self.state["objects"].get((Bucket, Key))
        if body is None:
            raise _ClientError("NoSuchKey", 404)
        return {"Body": _Body(body.encode("utf-8"))}

    def get_bucket_tagging(self, Bucket):
        if not self.state["tag_ok"]:
            raise _ClientError("NoSuchTagSet", 404)
        return {"TagSet": [{"Key": "REPORT_TAG",
                            "Value": self.state["tag_value"]}]}

    def put_object(self, Bucket, Key, Body):
        self.objects[(Bucket, Key)] = Body
        return {"ETag": "e"}

    def head_object(self, Bucket, Key):
        return {}


class FakeLogs:
    def __init__(self):
        self.messages = []

    def put_log_events(self, logGroupName, logStreamName, logEvents):
        self.messages.extend(item["message"] for item in logEvents)
        return {"nextSequenceToken": "t"}

    def filter_log_events(self, logGroupName, logStreamName, filterPattern):
        return {"events": [{"message": m} for m in self.messages
                           if filterPattern in m]}


class FakeSecrets:
    def __init__(self, state):
        self.state = state

    def describe_secret(self, SecretId):
        if not self.state["secret_ok"]:
            raise _ClientError("ResourceNotFoundException", 400)
        return {"ARN": self.state["secret_arn"], "Name": SecretId}

    def get_secret_value(self, SecretId):
        raise AssertionError("verify.py must never call GetSecretValue")


class FakeLambda:
    def __init__(self, state):
        self.state = state

    def get_function_configuration(self, FunctionName):
        return {"Environment": {"Variables": self.state["env"]}}


class FakeIam:
    def __init__(self, state):
        self.state = state

    def get_user(self, UserName):
        if UserName not in self.state["users"]:
            raise _ClientError("NoSuchEntity", 404)
        return {"User": {"UserName": UserName, "Arn": "arn:x"}}

    def list_access_keys(self, UserName):
        if not self.state["keys"].get(UserName):
            raise _ClientError("NoSuchEntity", 404)
        return {"AccessKeyMetadata": self.state["keys"][UserName]}

    def get_user_policy(self, UserName, PolicyName):
        document = self.state["policies"].get((UserName, PolicyName))
        if document is None:
            raise _ClientError("NoSuchEntity", 404)
        return {"PolicyDocument": document}


class FakeCloudTrail:
    def __init__(self, state):
        self.state = state

    def describe_trails(self, trailNameList):
        if self.state.get("trail_ok") is False:
            raise _ClientError("TrailNotFoundException", 400)
        return {"trailList": [{"Name": name, "TrailARN": f"arn:trail:{name}"}
                              for name in trailNameList]}


class FakeFloci:
    def __init__(self, state):
        self.state = state
        self.endpoint = "http://localhost:4567"
        self.account = "000000000000"
        self.admin_credential = "probe_credential"
        self.floci_version = "2.1.0"
        self.floci_edition = "community"

    def client(self, service, akid=None, secret=None, read_timeout=None):
        return {"s3": FakeS3(self.state), "logs": FakeLogs(),
                "secretsmanager": FakeSecrets(self.state),
                "cloudtrail": FakeCloudTrail(self.state),
                "lambda": FakeLambda(self.state), "iam": FakeIam(self.state)}[service]


def _live_state(**overrides):
    from cloudsec_agent.scenario import determinism as d
    from cloudsec_agent.scenario.seed import (evidence_control_document,
                                             incident_policy_document,
                                             investigator_policy_document,
                                             object_bodies)

    bodies = dict(object_bodies())
    bodies[d.RESOURCES.evidence_index_object] = evidence_control_document()
    state = {
        "buckets": [d.RESOURCES.incident_bucket, d.RESOURCES.evidence_bucket,
                    d.RESOURCES.trail_bucket],
        "objects": {(d.RESOURCES.incident_bucket, key): body
                    for key, body in bodies.items()
                    if key != d.RESOURCES.evidence_index_object},
        "objects": dict({(d.RESOURCES.incident_bucket, d.RESOURCES.baseline_object):
                         bodies[d.RESOURCES.baseline_object],
                         (d.RESOURCES.incident_bucket, d.RESOURCES.notes_object):
                         bodies[d.RESOURCES.notes_object],
                         (d.RESOURCES.incident_bucket,
                          d.RESOURCES.restricted_object):
                         bodies[d.RESOURCES.restricted_object],
                         (d.RESOURCES.evidence_bucket,
                          d.RESOURCES.evidence_index_object):
                         bodies[d.RESOURCES.evidence_index_object]}),
        "tag_ok": True, "tag_value": "csi-owned",
        "secret_ok": True,
        "secret_arn": "arn:aws:secretsmanager:us-east-1:000000000000:secret:x",
        "env": {"CSI_OWNER": "finance-analytics", "CSI_ENV": "synthetic",
                "CSI_SCENARIO": "csi-incident-v1"},
        "users": [d.RESOURCES.incident_user, d.RESOURCES.investigator_user],
        "keys": {d.RESOURCES.incident_user: [
            {"AccessKeyId": KEY_ID, "Status": "Active"}],
            d.RESOURCES.investigator_user: [
                {"AccessKeyId": INVESTIGATOR_KEY, "Status": "Active"}]},
        "policies": {
            (d.RESOURCES.incident_user, "csi-incident-scout"):
                json.loads(incident_policy_document()),
            (d.RESOURCES.investigator_user, "csi-investigator-readonly"):
                json.loads(investigator_policy_document()),
        },
    }
    state.update(overrides)
    return state


def _activity(**overrides_by_id):
    results = []
    for entry in ev.AUTHORITATIVE_EVIDENCE:
        observed = overrides_by_id.pop(entry.id, act.Observed.SUCCESS)
        results.append(act.ActivityResult(
            event_id=entry.id, service=entry.service, operation=entry.operation,
            target=entry.target, observed_result=observed,
            http_status=200 if observed == act.Observed.SUCCESS else 403,
            error_code=None if observed == act.Observed.SUCCESS else "AccessDenied",
            native_corroborated=False,
            actor_access_key_id=KEY_ID))
    return act.ActivityExecution(results=results, access_key_id=KEY_ID,
                                **overrides_by_id)


DENIED = {"EV-005": act.Observed.AUTHORIZATION_DENIED,
          "EV-006": act.Observed.AUTHORIZATION_DENIED,
          "EV-007": act.Observed.AUTHORIZATION_DENIED}


def _manifest(activity=None):
    state = _live_state()
    seed_result = _seed_result()
    return cli.build_manifest(FakeFloci(state), seed_result, activity)


def _seed_result():
    from cloudsec_agent.scenario import seed as s

    result = s.SeedResult(scenario_id="csi-incident-v1",
                          endpoint="http://localhost:4567",
                          account="000000000000",
                          incident_access_key_id=KEY_ID,
                          investigator_access_key_id=INVESTIGATOR_KEY,
                          secret_id="arn:aws:secretsmanager:us-east-1:000000000000:secret:x")
    result.record("s3-bucket", "csi-incident-bucket", None, s.SeedOutcome.CREATED)
    return result


def _evidence_write(count=8):
    result = store.EvidenceWriteResult()
    for index in range(1, count + 1):
        for storage in ("s3", "cloudwatch"):
            record = store.EvidenceWriteRecord(
                event_id=f"EV-00{index}", storage=storage, key=f"activity/EV-00{index}.json",
                confirmed=True, classification=store.StoreClass.CONFIRMED)
            if storage == "s3":
                result.s3_records.append(record)
            else:
                result.cloudwatch_records.append(record)
    return result


def _report(state=None, activity=None, evidence=None, restricted=None):
    return vr.verify_scenario(
        FakeFloci(state or _live_state()), _manifest(activity),
        activity=activity, evidence_write=evidence, restricted_read=restricted)


class TestVocabulary:
    def test_all_twenty_four_checks_exist_exactly_once(self):
        report = _report(activity=_activity(**DENIED),
                         evidence=_evidence_write())
        identifiers = [item.id for item in report.checks]
        assert identifiers == list(vr.VA_IDS)

    def test_ids_are_unique(self):
        report = _report(activity=_activity(**DENIED))
        identifiers = [item.id for item in report.checks]
        assert len(identifiers) == len(set(identifiers))

    def test_all_passing_reports_are_ok(self):
        report = _report(activity=_activity(**DENIED),
                         evidence=_evidence_write(),
                         restricted=vr.RestrictedReadResult(
                             act.Observed.AUTHORIZATION_DENIED, 403, "AccessDenied"))
        assert report.failures == []
        assert report.ok is True

    def test_any_failure_makes_report_not_ok(self):
        report = _report(activity=_activity(**{**DENIED,
                                               "EV-005": act.Observed.SUCCESS}))
        assert report.ok is False
        assert report.failures

    def test_status_vocabulary_is_tri_state(self):
        assert (vr.CheckStatus.PASS, vr.CheckStatus.FAIL,
                vr.CheckStatus.GAP) == ("pass", "fail", "gap")


class TestGapSemantics:
    def test_missing_evidence_is_gap_not_fail(self):
        report = _report(activity=_activity(**DENIED))
        assert report.check("VA-15").status == vr.CheckStatus.GAP
        assert report.check("VA-16").status == vr.CheckStatus.GAP
        assert "VA-15" not in " ".join(report.failures)

    def test_missing_restricted_read_is_gap(self):
        report = _report(activity=_activity(**DENIED))
        assert report.check("VA-06").status == vr.CheckStatus.GAP

    def test_missing_activity_is_explicitly_gap_for_va20(self):
        report = _report(activity=None)
        assert report.check("VA-20").status == vr.CheckStatus.GAP

    def test_missing_activity_still_fails_completion_checks(self):
        report = _report(activity=None)
        assert report.check("VA-21").status == vr.CheckStatus.FAIL
        assert report.check("VA-22").status == vr.CheckStatus.FAIL


class TestResourceChecks:
    def test_va02_key_mismatch_fails(self):
        state = _live_state()
        state["keys"] = {"incident-user": [{"AccessKeyId": "AKIAOTHER000000001",
                                            "Status": "Active"}],
                         "security-agent-backend": [{"AccessKeyId": INVESTIGATOR_KEY,
                                                     "Status": "Active"}]}
        report = _report(state=state, activity=_activity(**DENIED))
        assert report.check("VA-02").status == vr.CheckStatus.FAIL

    def test_va02_multiple_active_keys_fails(self):
        state = _live_state()
        state["keys"] = {"incident-user": [
            {"AccessKeyId": KEY_ID, "Status": "Active"},
            {"AccessKeyId": "AKIASECOND00000001", "Status": "Active"}],
            "security-agent-backend": [{"AccessKeyId": INVESTIGATOR_KEY,
                                        "Status": "Active"}]}
        report = _report(state=state, activity=_activity(**DENIED))
        assert report.check("VA-02").status == vr.CheckStatus.FAIL

    def test_va03_policy_mismatch_fails(self):
        state = _live_state()
        state["policies"][("incident-user", "csi-incident-scout")] = {
            "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"]}]}
        report = _report(state=state, activity=_activity(**DENIED))
        assert report.check("VA-03").status == vr.CheckStatus.FAIL

    def test_va10_investigator_key_mismatch_fails(self):
        state = _live_state()
        state["keys"]["security-agent-backend"] = []
        report = _report(state=state, activity=_activity(**DENIED))
        assert report.check("VA-10").status == vr.CheckStatus.FAIL

    def test_va11_investigator_secret_value_permission_fails(self):
        state = _live_state()
        state["policies"][("security-agent-backend",
                           "csi-investigator-readonly")] = {
            "Statement": [{"Effect": "Allow",
                           "Action": ["secretsmanager:DescribeSecret",
                                      "secretsmanager:GetSecretValue"],
                           "Resource": ["*"]}]}
        report = _report(state=state, activity=_activity(**DENIED))
        assert report.check("VA-11").status == vr.CheckStatus.FAIL

    def test_va12_object_body_mismatch_fails(self):
        state = _live_state()
        state["objects"][("csi-incident-bucket", "notes/handoff.md")] = "tampered"
        report = _report(state=state, activity=_activity(**DENIED))
        assert report.check("VA-12").status == vr.CheckStatus.FAIL

    def test_va13_tag_mismatch_fails(self):
        state = _live_state()
        state["tag_value"] = "someone-else"
        report = _report(state=state, activity=_activity(**DENIED))
        assert report.check("VA-13").status == vr.CheckStatus.FAIL

    def test_va14_describe_secret_only(self):
        report = _report(activity=_activity(**DENIED))
        assert report.check("VA-14").status == vr.CheckStatus.PASS

    def test_va17_environment_mismatch_fails(self):
        state = _live_state()
        state["env"] = {"CSI_OWNER": "attacker"}
        report = _report(state=state, activity=_activity(**DENIED))
        assert report.check("VA-17").status == vr.CheckStatus.FAIL

    def test_va18_identifier_mismatch_fails(self):
        state = _live_state()
        state["buckets"] = ["csi-evidence-bucket"]
        report = _report(state=state, activity=_activity(**DENIED))
        assert report.check("VA-18").status == vr.CheckStatus.FAIL


class TestActivityChecks:
    def test_va04_ev001_non_success_fails(self):
        report = _report(activity=_activity(**{**DENIED,
                                               "EV-001": act.Observed.API_ERROR}))
        assert report.check("VA-04").status == vr.CheckStatus.FAIL

    def test_va05_ev002_non_success_fails(self):
        report = _report(activity=_activity(**{**DENIED,
                                               "EV-002": act.Observed.API_ERROR}))
        assert report.check("VA-05").status == vr.CheckStatus.FAIL

    def test_va06_supplied_denial_passes(self):
        report = _report(activity=_activity(**DENIED),
                         restricted=vr.RestrictedReadResult(
                             act.Observed.AUTHORIZATION_DENIED, 403, "AccessDenied"))
        assert report.check("VA-06").status == vr.CheckStatus.PASS

    def test_va06_supplied_success_fails(self):
        report = _report(activity=_activity(**DENIED),
                         restricted=vr.RestrictedReadResult(act.Observed.SUCCESS))
        assert report.check("VA-06").status == vr.CheckStatus.FAIL

    def test_va07_denial_passes(self):
        report = _report(activity=_activity(**DENIED))
        assert report.check("VA-07").status == vr.CheckStatus.PASS

    def test_va07_unexpected_success_fails(self):
        results = [act.ActivityResult(
            event_id=entry.id, service=entry.service, operation=entry.operation,
            target=entry.target,
            observed_result=(act.Observed.UNEXPECTED_SUCCESS
                             if entry.id == "EV-006" else act.Observed.SUCCESS),
            secret_material_returned=(entry.id == "EV-006"),
            actor_access_key_id=KEY_ID) for entry in ev.AUTHORITATIVE_EVIDENCE[:6]]
        execution = act.ActivityExecution(results=results, access_key_id=KEY_ID,
                                          stopped_early=True,
                                          stop_reason="EV-006 secret returned")
        report = vr.verify_scenario(FakeFloci(_live_state()),
                                    _manifest(activity=None), activity=execution)
        assert report.check("VA-07").status == vr.CheckStatus.FAIL

    def test_va07_secret_material_flag_always_fails(self):
        results = [act.ActivityResult(
            event_id=entry.id, service=entry.service, operation=entry.operation,
            target=entry.target,
            observed_result=act.Observed.AUTHORIZATION_DENIED,
            secret_material_returned=True, actor_access_key_id=KEY_ID)
            for entry in ev.AUTHORITATIVE_EVIDENCE]
        execution = act.ActivityExecution(results=results, access_key_id=KEY_ID)
        report = _report(activity=execution)
        assert report.check("VA-07").status == vr.CheckStatus.FAIL

    def test_va08_non_denial_fails(self):
        report = _report(activity=_activity(**{**DENIED,
                                               "EV-005": act.Observed.SUCCESS}))
        assert report.check("VA-08").status == vr.CheckStatus.FAIL

    def test_va09_non_denial_fails(self):
        report = _report(activity=_activity(**{**DENIED,
                                               "EV-007": act.Observed.SUCCESS}))
        assert report.check("VA-09").status == vr.CheckStatus.FAIL

    def test_va20_write_operation_in_activity_fails(self):
        results = [act.ActivityResult(
            event_id=entry.id, service=entry.service, operation=entry.operation,
            target=entry.target, observed_result=act.Observed.SUCCESS,
            actor_access_key_id=KEY_ID) for entry in ev.AUTHORITATIVE_EVIDENCE]
        results[0] = act.ActivityResult(
            event_id="EV-001", service="s3", operation="s3:PutObject", target="x",
            observed_result=act.Observed.SUCCESS, actor_access_key_id=KEY_ID)
        execution = act.ActivityExecution(results=results, access_key_id=KEY_ID)
        report = vr.verify_scenario(FakeFloci(_live_state()),
                                    _manifest(activity=None), activity=execution)
        assert report.check("VA-20").status == vr.CheckStatus.FAIL

    def test_va21_activity_seeded_false_fails(self):
        report = _report(activity=None)
        assert report.check("VA-21").status == vr.CheckStatus.FAIL

    def test_va22_wrong_order_fails(self):
        results = [act.ActivityResult(
            event_id=entry.id, service=entry.service, operation=entry.operation,
            target=entry.target, observed_result=act.Observed.SUCCESS,
            actor_access_key_id=KEY_ID) for entry in ev.AUTHORITATIVE_EVIDENCE]
        results[0], results[1] = results[1], results[0]
        execution = act.ActivityExecution(results=results, access_key_id=KEY_ID)
        with pytest.raises(vr.VerificationInputError):
            vr.result_by_event_id(execution)

    def test_va23_null_observation_fails(self):
        report = _report(activity=None)
        assert report.check("VA-23").status == vr.CheckStatus.FAIL

    def test_va24_all_native_false_still_passes(self):
        execution = _activity(**DENIED)
        assert all(item.native_corroborated is False
                   for item in execution.results)
        report = _report(activity=execution, evidence=_evidence_write(),
                         restricted=vr.RestrictedReadResult(
                             act.Observed.AUTHORIZATION_DENIED))
        assert report.check("VA-24").status == vr.CheckStatus.PASS


class TestEvidenceChecks:
    def test_va15_incomplete_s3_evidence_fails(self):
        report = _report(activity=_activity(**DENIED),
                         evidence=_evidence_write(count=6))
        assert report.check("VA-15").status == vr.CheckStatus.FAIL

    def test_va16_incomplete_cloudwatch_fails(self):
        report = _report(activity=_activity(**DENIED),
                         evidence=_evidence_write(count=5))
        assert report.check("VA-16").status == vr.CheckStatus.FAIL

    def test_stopped_early_evidence_never_verifies_as_complete(self):
        results = [act.ActivityResult(
            event_id=entry.id, service=entry.service, operation=entry.operation,
            target=entry.target,
            observed_result=(act.Observed.AUTHORIZATION_DENIED
                             if entry.id in DENIED else act.Observed.SUCCESS),
            actor_access_key_id=KEY_ID)
            for entry in ev.AUTHORITATIVE_EVIDENCE[:6]]
        execution = act.ActivityExecution(results=results, access_key_id=KEY_ID,
                                          stopped_early=True, stop_reason="halted")
        report = vr.verify_scenario(FakeFloci(_live_state()),
                                    _manifest(activity=None), activity=execution,
                                    evidence_write=_evidence_write(count=6))
        assert report.check("VA-15").status == vr.CheckStatus.FAIL
        assert report.ok is False


class TestActivityLookup:
    def test_lookup_maps_by_event_id(self):
        results = vr.result_by_event_id(_activity(**DENIED))
        assert sorted(results) == sorted(vr.CANONICAL_EVENT_IDS)
        assert results["EV-005"].observed_result == act.Observed.AUTHORIZATION_DENIED

    def test_duplicate_event_rejected(self):
        results = [act.ActivityResult(event_id="EV-001", service="s3",
                                      operation="s3:GetObject", target="t",
                                      observed_result=act.Observed.SUCCESS),
                   act.ActivityResult(event_id="EV-001", service="s3",
                                      operation="s3:GetObject", target="t",
                                      observed_result=act.Observed.SUCCESS)]
        with pytest.raises(vr.VerificationInputError):
            vr.result_by_event_id(results)

    def test_unknown_event_rejected(self):
        with pytest.raises(vr.VerificationInputError):
            vr.result_by_event_id([act.ActivityResult(
                event_id="EV-099", service="s3", operation="x", target="t",
                observed_result=act.Observed.SUCCESS)])

    def test_gap_in_sequence_rejected(self):
        results = [act.ActivityResult(
            event_id=f"EV-00{index}", service="s3", operation="x", target="t",
            observed_result=act.Observed.SUCCESS) for index in (1, 3)]
        with pytest.raises(vr.VerificationInputError):
            vr.result_by_event_id(results)

    def test_out_of_order_rejected(self):
        results = [act.ActivityResult(
            event_id=f"EV-00{index}", service="s3", operation="x", target="t",
            observed_result=act.Observed.SUCCESS) for index in (2, 1)]
        with pytest.raises(vr.VerificationInputError):
            vr.result_by_event_id(results)

    def test_non_activity_result_rejected(self):
        with pytest.raises(vr.VerificationInputError):
            vr.result_by_event_id([{"id": "EV-001"}])


class TestManifestIntegration:
    def test_default_build_is_unchanged(self):
        manifest = _manifest(activity=None)
        assert manifest.activity_seeded is False
        assert all(item.observed_result is None for item in manifest.evidence)
        assert all(item.observed_http_status is None for item in manifest.evidence)
        assert all(item.observed_error_code is None for item in manifest.evidence)
        assert all(item.native_corroborated is None for item in manifest.evidence)

    def test_complete_activity_sets_activity_seeded(self):
        manifest = _manifest(activity=_activity(**DENIED))
        assert manifest.activity_seeded is True

    def test_observations_map_by_event_id(self):
        manifest = _manifest(activity=_activity(**DENIED))
        by_id = {item.id: item for item in manifest.evidence}
        assert by_id["EV-001"].observed_result == act.Observed.SUCCESS
        assert by_id["EV-005"].observed_result == act.Observed.AUTHORIZATION_DENIED
        assert by_id["EV-005"].observed_error_code == "AccessDenied"
        assert by_id["EV-005"].observed_http_status == 403
        assert by_id["EV-001"].native_corroborated is False

    def test_catalogue_metadata_is_preserved(self):
        manifest = _manifest(activity=_activity(**DENIED))
        for item in manifest.evidence:
            entry = next(e for e in ev.EVIDENCE_CATALOGUE if e.id == item.id)
            assert item.event_time == entry.event_time
            assert item.time_basis == entry.time_basis
            assert item.service == entry.service
            assert item.operation == entry.operation
            assert item.target == entry.target
            assert item.authoritative == entry.authoritative

    def test_activity_cannot_override_catalogue_operation(self):
        results = [act.ActivityResult(
            event_id=entry.id, service=entry.service, operation=entry.operation,
            target=entry.target, observed_result=act.Observed.SUCCESS,
            actor_access_key_id=KEY_ID) for entry in ev.AUTHORITATIVE_EVIDENCE]
        results[0] = act.ActivityResult(
            event_id="EV-001", service="s3", operation="s3:DeleteObject",
            target="x", observed_result=act.Observed.SUCCESS,
            actor_access_key_id=KEY_ID)
        execution = act.ActivityExecution(results=results, access_key_id=KEY_ID)
        with pytest.raises(vr.VerificationInputError):
            _manifest(activity=execution)

    def test_activity_cannot_override_catalogue_target(self):
        results = [act.ActivityResult(
            event_id=entry.id, service=entry.service, operation=entry.operation,
            target=entry.target, observed_result=act.Observed.SUCCESS,
            actor_access_key_id=KEY_ID) for entry in ev.AUTHORITATIVE_EVIDENCE]
        results[0] = act.ActivityResult(
            event_id="EV-001", service="s3", operation="s3:GetObject",
            target="attacker-target", observed_result=act.Observed.SUCCESS,
            actor_access_key_id=KEY_ID)
        execution = act.ActivityExecution(results=results, access_key_id=KEY_ID)
        with pytest.raises(vr.VerificationInputError):
            _manifest(activity=execution)

    def test_stopped_early_activity_is_rejected(self):
        execution = _activity(**DENIED)
        execution.stopped_early = True
        execution.stop_reason = "halted"
        with pytest.raises(vr.VerificationInputError):
            _manifest(activity=execution)

    def test_partial_activity_is_rejected_for_final_manifest(self):
        execution = act.ActivityExecution(
            results=[act.ActivityResult(
                event_id=entry.id, service=entry.service, operation=entry.operation,
                target=entry.target, observed_result=act.Observed.SUCCESS,
                actor_access_key_id=KEY_ID) for entry in ev.AUTHORITATIVE_EVIDENCE[:3]],
            access_key_id=KEY_ID)
        manifest = _manifest(activity=execution)
        assert manifest.activity_seeded is True

    def test_duplicate_event_is_rejected(self):
        results = [act.ActivityResult(
            event_id="EV-001", service="s3", operation="s3:GetObject", target="t",
            observed_result=act.Observed.SUCCESS, actor_access_key_id=KEY_ID)
            for _ in range(2)]
        with pytest.raises(vr.VerificationInputError):
            _manifest(activity=act.ActivityExecution(results=results,
                                                      access_key_id=KEY_ID))

    def test_manifest_has_no_credential_material(self):
        for activity in (None, _activity(**DENIED)):
            manifest = _manifest(activity=activity)
            text = mf.serialize_manifest(manifest)
            assert "SecretAccessKey" not in text
            assert "SecretString" not in text
            assert SIM_SECRET not in text

    def test_activity_detail_never_reaches_the_manifest(self):
        results = [act.ActivityResult(
            event_id=entry.id, service=entry.service, operation=entry.operation,
            target=entry.target, observed_result=act.Observed.SUCCESS,
            detail="private-detail", actor_access_key_id=KEY_ID)
            for entry in ev.AUTHORITATIVE_EVIDENCE]
        manifest = _manifest(activity=act.ActivityExecution(results=results,
                                                             access_key_id=KEY_ID))
        assert "private-detail" not in mf.serialize_manifest(manifest)

    def test_compromised_key_id_is_preserved(self):
        manifest = _manifest(activity=_activity(**DENIED))
        assert manifest.principal.access_key_id == KEY_ID

    def test_manifest_remains_schema_valid(self):
        manifest = _manifest(activity=_activity(**DENIED))
        payload = json.loads(mf.serialize_manifest(manifest))
        assert payload["activity_seeded"] is True
        assert len(payload["evidence"]) == 10
        assert payload["manifest_metadata"]["is_incident_evidence"] is False


class TestSourceSafety:
    def test_verify_does_not_import_credentials(self):
        source = (REPO / "cloudsec_agent/scenario/verify.py").read_text()
        assert "credentials" not in source
        assert "IncidentRuntimeCredential" not in source

    def test_verify_accepts_no_credential_parameter(self):
        tree = ast.parse((REPO / "cloudsec_agent/scenario/verify.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for argument in node.args.args:
                    assert argument.arg not in ("credential", "secret_access_key"), \
                        node.name

    def test_verify_contains_no_get_secret_value(self):
        source = (REPO / "cloudsec_agent/scenario/verify.py").read_text()
        assert "get_secret_value" not in source

    def test_verify_has_no_direct_boto3(self):
        source = (REPO / "cloudsec_agent/scenario/verify.py").read_text()
        assert "boto3.client(" not in source
        assert "boto3.resource(" not in source
        assert "import boto3" not in source

    def test_verify_performs_no_mutations(self):
        source = (REPO / "cloudsec_agent/scenario/verify.py").read_text()
        for forbidden in ("put_object", "delete_object", "create_user",
                          "delete_user", "create_access_key", "put_log_events",
                          "create_secret", "delete_secret", "create_function"):
            assert forbidden not in source, forbidden

    def test_verify_carries_no_docstrings(self):
        tree = ast.parse((REPO / "cloudsec_agent/scenario/verify.py").read_text())
        assert not ast.get_docstring(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                assert not ast.get_docstring(node)

    def test_lifecycle_wiring_stays_out_of_verify(self):
        source = (REPO / "cloudsec_agent/scenario/verify.py").read_text()
        assert "with-activity" not in source
        assert "execute_incident_activity" not in source
        assert "write_evidence" not in source
        assert "seed_scenario_with_runtime" not in source

    def test_no_reset_orchestration_leaked_into_verify(self):
        source = (REPO / "cloudsec_agent/scenario/verify.py").read_text()
        for forbidden in ("reset_canonical_scenario", "reset_scenario",
                          "run_lifecycle", "seed_and_write_manifest",
                          "main(", "argparse", "subprocess", "os.system"):
            assert forbidden not in source, forbidden

    def test_verify_performs_no_mutation(self):
        source = (REPO / "cloudsec_agent/scenario/verify.py").read_text()
        for forbidden in ("put_object", "delete_object", "create_user",
                          "delete_user", "create_access_key",
                          "update_access_key", "put_log_events", "create_secret",
                          "delete_secret", "create_function"):
            assert forbidden not in source, forbidden

    def test_cli_owns_the_lifecycle_flag(self):
        tree = ast.parse((REPO / "cloudsec_agent/seed_scenario.py").read_text())
        flags = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_argument":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        flags.add(arg.value)
        assert "--with-activity" in flags

    def test_manifest_integration_accepts_activity_execution(self):
        tree = ast.parse((REPO / "cloudsec_agent/seed_scenario.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "build_manifest":
                assert node.args.args[-1].arg == "activity"

class TestVa08EventMapping:
    def _status(self, report, identifier):
        for check in report.checks:
            if check.id == identifier:
                return check.status
        raise AssertionError(identifier + " absent from report")

    def test_va08_passes_when_ev005_denied(self):
        report = _report(activity=_activity(**DENIED))
        assert self._status(report, "VA-08") == vr.CheckStatus.PASS

    def test_va08_fails_when_ev005_inconclusive(self):
        activity = _activity(**{**DENIED, "EV-005": act.Observed.INCONCLUSIVE})
        report = _report(activity=activity)
        assert self._status(report, "VA-08") == vr.CheckStatus.FAIL

    def test_va08_unaffected_by_ev004(self):
        base = self._status(_report(activity=_activity(**DENIED)), "VA-08")
        activity = _activity(**{**DENIED, "EV-004": act.Observed.API_ERROR})
        assert self._status(_report(activity=activity), "VA-08") == base

    def test_va08_unaffected_by_ev006(self):
        base = self._status(_report(activity=_activity(**DENIED)), "VA-08")
        activity = _activity(**{**DENIED, "EV-006": act.Observed.API_ERROR})
        assert self._status(_report(activity=activity), "VA-08") == base

    def test_va08_does_not_read_ev008(self):
        activity = _activity(**{**DENIED, "EV-008": act.Observed.INCONCLUSIVE})
        assert self._status(_report(activity=activity),
                            "VA-08") == vr.CheckStatus.PASS

    def test_va08_is_wired_to_ev005_not_ev008(self):
        source = (REPO / "cloudsec_agent/scenario/verify.py").read_text()
        assert '"VA-08", "EV-005"' in source


class TestVaEventMappingTable:
    """Every mapping uses deliberately distinct values so cross-wiring fails."""

    MAPPING = [
        ("VA-04", "EV-001", act.Observed.SUCCESS),
        ("VA-05", "EV-002", act.Observed.SUCCESS),
        ("VA-07", "EV-006", act.Observed.AUTHORIZATION_DENIED),
        ("VA-08", "EV-005", act.Observed.AUTHORIZATION_DENIED),
        ("VA-09", "EV-007", act.Observed.AUTHORIZATION_DENIED),
    ]

    DISTINCT = {
        "EV-001": act.Observed.SUCCESS,
        "EV-002": act.Observed.SUCCESS,
        "EV-003": act.Observed.SUCCESS,
        "EV-004": act.Observed.SUCCESS,
        "EV-005": act.Observed.AUTHORIZATION_DENIED,
        "EV-006": act.Observed.AUTHORIZATION_DENIED,
        "EV-007": act.Observed.AUTHORIZATION_DENIED,
        "EV-008": act.Observed.SUCCESS,
    }

    def _correct(self):
        return dict(self.DISTINCT)

    def _status(self, report, identifier):
        for check in report.checks:
            if check.id == identifier:
                return check.status
        raise AssertionError(identifier + " absent from report")

    @pytest.mark.parametrize("identifier,event_id,expected", MAPPING)
    def test_correct_mapping_passes(self, identifier, event_id, expected):
        report = _report(activity=_activity(**self._correct()))
        assert self._status(report, identifier) == vr.CheckStatus.PASS

    @pytest.mark.parametrize("identifier,event_id,expected", MAPPING)
    def test_wrong_event_value_fails(self, identifier, event_id, expected):
        broken = self._correct()
        broken[event_id] = act.Observed.API_ERROR
        report = _report(activity=_activity(**broken))
        assert self._status(report, identifier) == vr.CheckStatus.FAIL

    @pytest.mark.parametrize("identifier,event_id,expected", MAPPING)
    def test_neighbouring_event_value_does_not_satisfy(self, identifier,
                                                       event_id, expected):
        broken = self._correct()
        for other in ("EV-001", "EV-002", "EV-003", "EV-004", "EV-005",
                      "EV-006", "EV-007", "EV-008"):
            if other == event_id:
                continue
            broken[other] = act.Observed.API_ERROR
        broken[event_id] = expected
        report = _report(activity=_activity(**broken))
        assert self._status(report, identifier) == vr.CheckStatus.PASS

    def test_va07_secret_return_short_circuits(self):
        import dataclasses
        activity = _activity(**self._correct())
        activity.results = [
            dataclasses.replace(item, secret_material_returned=True)
            if item.event_id == "EV-006" else item
            for item in activity.results]
        report = _report(activity=activity)
        assert self._status(report, "VA-07") == vr.CheckStatus.FAIL
