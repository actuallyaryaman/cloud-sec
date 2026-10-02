import gzip
import json
import time

from ..authz import Identity, ensure_bucket, policy, statement
from ..result import CallOutcome

TRAIL = "cloudsec-probe-trail"
TRAIL_BUCKET = "cloudsec-trail-logs"
SOURCE_BUCKET = "cloudsec-trail-source"
SOURCE_KEY = "probe/event.txt"
LOG_GROUP = "cloudsec-probe-group"
CONFIG_RECORDER = "cloudsec-probe-recorder"
CONFIG_RULE = "cloudsec-probe-rule"
FLUSH_POLL_SECONDS = 15
FLUSH_TIMEOUT_SECONDS = 240


def probe_cloudwatch_logs(floci, matrix, suffix):
    gaps = []
    operations = {}
    authz = {}
    signals = {}
    client = floci.client("logs")
    group = f"{LOG_GROUP}-{suffix}"

    created = CallOutcome.capture("logs", "CreateLogGroup", lambda c: c.create_log_group(
        logGroupName=group))
    operations["CreateLogGroup"] = created.to_dict()
    if not created.ok:
        gaps.append(f"CloudWatch Logs CreateLogGroup failed: {created.error_code}")
        return _result(False, operations, authz, gaps, signals, {})

    stream = CallOutcome.capture("logs", "CreateLogStream", lambda c: c.create_log_stream(
        logGroupName=group, logStreamName="probe"))
    operations["CreateLogStream"] = stream.to_dict()
    operations["DescribeLogStreams"] = _capture(client, "DescribeLogStreams",
                                                lambda c: c.describe_log_streams(
                                                    logGroupName=group))
    marker = f"cloudsec-synthetic-marker-{suffix}"
    put = CallOutcome.capture("logs", "PutLogEvents", lambda c: c.put_log_events(
        logGroupName=group, logStreamName="probe",
        logEvents=[{"timestamp": int(time.time() * 1000), "message": marker}]))
    operations["PutLogEvents"] = put.to_dict()
    filtered = CallOutcome.capture("logs", "FilterLogEvents", lambda c: c.filter_log_events(
        logGroupName=group, filterPattern=marker))
    operations["FilterLogEvents"] = filtered.to_dict()
    found = bool(filtered.ok and filtered.raw.get("events"))
    operations["FilterLogEventsFoundMarker"] = {
        "operation": "FilterLogEvents", "ok": found}
    if not found:
        gaps.append("CloudWatch Logs FilterLogEvents did not return the synthetic marker")
    operations["GetLogEvents"] = _capture(client, "GetLogEvents", lambda c: c.get_log_events(
        logGroupName=group, logStreamName="probe"))

    availability = {"logs_deny_observed": True}
    arn = f"arn:aws:logs:{floci.region()}:{floci.account}:log-group:{group}:log-stream:probe"
    deny_identity = Identity(floci, f"logsdeny{suffix}")
    if not deny_identity.create():
        availability["logs_deny_observed"] = None
        authz["explicit_deny"] = {"error": "identity creation failed"}
    else:
        confirmed = deny_identity.put_inline_policy("logs-deny", policy([
            statement("Allow", "logs:PutLogEvents", arn),
            statement("Deny", "logs:PutLogEvents", arn),
        ]))
        outcome = CallOutcome.capture("logs", "PutLogEvents", lambda c: c.put_log_events(
            logGroupName=group, logStreamName="probe",
            logEvents=[{"timestamp": int(time.time() * 1000), "message": "denied"}]),
            deny_identity.client("logs"))
        check = CallOutcome.capture("logs", "FilterLogEvents", lambda c: c.filter_log_events(
            logGroupName=group, filterPattern="denied"), client)
        state_changed = bool(check.ok and check.raw.get("events"))
        authz["explicit_deny"] = matrix.record(
            "CW-C", "logs:PutLogEvents", "logs", "iam-user-deny", deny_identity.arn, arn,
            "deny", outcome, state_changed=state_changed, policy_confirmed=confirmed,
            signals=["logs_deny"],
            notes="re-read the group to see whether the denied write landed")
        availability["logs_deny_observed"] = authz["explicit_deny"]["classification"]
        deny_identity.delete()

    deleted = CallOutcome.capture("logs", "DeleteLogGroup", lambda c: c.delete_log_group(
        logGroupName=group))
    operations["DeleteLogGroup"] = deleted.to_dict()
    signals["logs"] = availability
    return _result(True, operations, authz, gaps, signals, {})


def setup_cloudtrail(floci, suffix):
    state = {"trail_bucket": f"{TRAIL_BUCKET}-{suffix}",
             "source_bucket": f"{SOURCE_BUCKET}-{suffix}", "started": False, "gaps": []}
    s3 = floci.client("s3")
    trail = floci.client("cloudtrail")
    for bucket in (state["trail_bucket"], state["source_bucket"]):
        outcome = ensure_bucket(s3, bucket)
        if not outcome.ok:
            state["gaps"].append(f"CloudTrail setup: could not create {bucket}: "
                                 f"{outcome.error_code}")
            return state

    CallOutcome.capture("cloudtrail", "StopLogging", lambda c: c.stop_logging(
        Name=TRAIL))
    CallOutcome.capture("cloudtrail", "DeleteTrail", lambda c: c.delete_trail(
        Name=TRAIL))
    created = CallOutcome.capture("cloudtrail", "CreateTrail", lambda c: c.create_trail(
        Name=TRAIL, S3BucketName=state["trail_bucket"],
        IsMultiRegionTrail=False, IncludeGlobalServiceEvents=False))
    state["create_trail"] = created.to_dict()
    if not created.ok:
        state["gaps"].append(
            f"CloudTrail CreateTrail unsupported: {created.error_code}")
        return state

    selectors = CallOutcome.capture("cloudtrail", "PutEventSelectors",
                                    lambda c: c.put_event_selectors(
                                        TrailName=TRAIL,
                                        EventSelectors=[{
                                            "ReadWriteType": "All",
                                            "IncludeManagementEvents": True,
                                            "DataResources": [{
                                                "Type": "AWS::S3::Object",
                                                "Values": [f"arn:aws:s3:::{state['source_bucket']}/"]}],
                                        }]))
    state["put_event_selectors"] = selectors.to_dict()
    started = CallOutcome.capture("cloudtrail", "StartLogging", lambda c: c.start_logging(
        Name=TRAIL))
    state["start_logging"] = started.to_dict()
    state["started"] = bool(started.ok)
    status = CallOutcome.capture("cloudtrail", "GetTrailStatus", lambda c: c.get_trail_status(
        Name=TRAIL))
    state["get_trail_status"] = status.to_dict()
    state["is_logging"] = status.raw.get("IsLogging") if status.ok else None
    got = CallOutcome.capture("cloudtrail", "GetEventSelectors", lambda c: c.get_event_selectors(
        TrailName=TRAIL))
    state["get_event_selectors"] = got.to_dict()
    state["event_selectors_roundtrip"] = bool(got.ok and got.raw.get("EventSelectors"))
    listed = CallOutcome.capture("cloudtrail", "ListTrails", lambda c: c.list_trails())
    state["list_trails"] = listed.to_dict()
    state["trail_arn"] = created.raw.get("TrailARN") if created.ok else None
    return state


def perform_marked_actions(floci, state, suffix):
    s3 = floci.client("s3")
    iam = floci.client("iam")
    bucket = state["source_bucket"]
    actions = {}
    actions["PutObject"] = CallOutcome.capture("s3", "PutObject", lambda c: c.put_object(
        Bucket=bucket, Key=SOURCE_KEY, Body=b"cloudsec-synthetic-trail-body")).to_dict()
    actions["GetObject"] = CallOutcome.capture("s3", "GetObject", lambda c: c.get_object(
        Bucket=bucket, Key=SOURCE_KEY)).to_dict()
    actions["HeadObject"] = CallOutcome.capture("s3", "HeadObject", lambda c: c.head_object(
        Bucket=bucket, Key=SOURCE_KEY)).to_dict()
    actions["CreateUser"] = CallOutcome.capture("iam", "CreateUser", lambda c: c.create_user(
        UserName=f"cloudsec-trail-{suffix}")).to_dict()
    actions["ListUsers"] = CallOutcome.capture("iam", "ListUsers", lambda c: c.list_users(
    )).to_dict()

    denied = Identity(floci, f"traildenied{suffix}")
    state["denied_attempt"] = {}
    if denied.create():
        confirmed = denied.put_inline_policy("trail-deny", policy([
            statement("Allow", "s3:*", "*"),
            statement("Deny", "s3:GetObject", "*"),
        ]))
        outcome = CallOutcome.capture("s3", "GetObject", lambda c: c.get_object(
            Bucket=bucket, Key=SOURCE_KEY), denied.client("s3"))
        state["denied_attempt"] = {
            "policy_confirmed": confirmed,
            "outcome": outcome.to_dict(),
        }
        denied.delete()
    else:
        state["denied_attempt"] = {"error": "identity creation failed"}
    return actions


def finalize_cloudtrail(floci, state, suffix, marked_actions):
    operations = {}
    gaps = list(state.get("gaps", []))
    s3 = floci.client("s3")
    trail = floci.client("cloudtrail")
    bucket = state["trail_bucket"]

    looked_up = CallOutcome.capture("cloudtrail", "LookupEvents", lambda c: c.lookup_events(
        MaxResults=50))
    operations["LookupEvents"] = looked_up.to_dict()
    lookup_events = looked_up.raw.get("Events", []) if looked_up.ok else []
    operations["LookupEventsCount"] = len(lookup_events)

    records, waited = _collect_records(s3, bucket)
    operations["FlushWaitSeconds"] = waited
    operations["TrailObjectKeys"] = sorted(records.keys())
    operations["TrailRecordCount"] = sum(len(v) for v in records.values())

    event_names = []
    request_ids = []
    access_denied = []
    for entries in records.values():
        for record in entries:
            name = record.get("eventName")
            if name:
                event_names.append(name)
            request_id = record.get("requestID") or record.get("requestId")
            if request_id:
                request_ids.append(request_id)
            error = record.get("errorCode")
            if error:
                access_denied.append({"eventName": name, "errorCode": error})
    operations["EventNamesObserved"] = sorted(set(event_names))
    operations["UniqueEventNames"] = len(set(event_names))
    operations["RequestIdsObserved"] = len(set(request_ids))
    operations["RecordsCarryingErrorCode"] = access_denied[:10]
    operations["SampleRecordShape"] = _sample_shape(records)

    observations = {
        "trail_started": state.get("started"),
        "trail_is_logging": state.get("is_logging"),
        "management_events_requested": True,
        "s3_data_events_selected": f"arn:aws:s3:::{state['source_bucket']}/",
        "put_object_seen": "PutObject" in event_names,
        "get_object_seen": "GetObject" in event_names,
        "head_object_seen": "HeadObject" in event_names,
        "iam_create_user_seen": any(
            n in ("CreateUser", "CreateUserV2") for n in event_names),
        "iam_list_users_seen": "ListUsers" in event_names,
        "iam_denied_attempt": state.get("denied_attempt"),
        "denied_attempt_seen_in_trail": any(
            entry.get("errorCode") == "AccessDenied" for entry in access_denied),
        "lookup_events_returned": len(lookup_events),
        "lookup_events_shape": _lookup_shape(lookup_events),
    }
    if not records:
        gaps.append(
            "CloudTrail produced no readable trail objects under AWSLogs/ within "
            f"{FLUSH_TIMEOUT_SECONDS}s")
    if not observations["put_object_seen"]:
        gaps.append("CloudTrail trail files did not contain the marked S3 PutObject")
    if not any((observations["iam_create_user_seen"], observations["iam_list_users_seen"])):
        gaps.append(
            "CloudTrail trail files contained no IAM management events although "
            "IncludeManagementEvents was requested")

    stopped = CallOutcome.capture("cloudtrail", "StopLogging", lambda c: c.stop_logging(
        Name=TRAIL))
    operations["StopLogging"] = stopped.to_dict()
    described = CallOutcome.capture("cloudtrail", "DescribeTrails", lambda c: c.describe_trails(
        trailNameList=[TRAIL]))
    operations["DescribeTrails"] = described.to_dict()
    deleted = CallOutcome.capture("cloudtrail", "DeleteTrail", lambda c: c.delete_trail(
        Name=TRAIL))
    operations["DeleteTrail"] = deleted.to_dict()
    _delete_bucket(s3, bucket)
    _delete_bucket(s3, state["source_bucket"])

    authz = {}
    if state.get("denied_attempt", {}).get("outcome"):
        authz["denied_attempt"] = state["denied_attempt"]["outcome"]
    return _result(bool(records), operations, authz, gaps, {}, observations)


def _collect_records(s3, bucket):
    deadline = time.monotonic() + FLUSH_TIMEOUT_SECONDS
    started = time.monotonic()
    records: dict[str, list] = {}
    while time.monotonic() < deadline:
        records = {}
        listed = CallOutcome.capture("s3", "ListObjectsV2", lambda c: c.list_objects_v2(
            Bucket=bucket, Prefix="AWSLogs/"))
        if listed.ok:
            for item in listed.raw.get("Contents", []):
                key = item["Key"]
                if not key.endswith(".json.gz"):
                    continue
                def call(client, key=key):
                    body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
                    return json.loads(gzip.decompress(body))
                fetched = CallOutcome.capture("s3", "GetObjectTrailFile", call, s3)
                if fetched.ok:
                    payload = fetched.raw
                    entries = payload.get("Records") if isinstance(payload, dict) else payload
                    records[key] = [e for e in (entries or []) if isinstance(e, dict)]
        if records and any(r.get("eventName") for entries in records.values() for r in entries):
            break
        time.sleep(FLUSH_POLL_SECONDS)
    return records, round(time.monotonic() - started)


def _sample_shape(records):
    for entries in records.values():
        for record in entries:
            return {
                "eventVersion": record.get("eventVersion"),
                "eventSource": record.get("eventSource"),
                "eventTime": record.get("eventTime"),
                "eventName": record.get("eventName"),
                "awsRegion": record.get("awsRegion"),
                "userIdentity_keys": sorted((record.get("userIdentity") or {}).keys()),
                "requestParameters_present": bool(record.get("requestParameters")),
                "errorCode_present": bool(record.get("errorCode")),
                "keys": sorted(record.keys()),
            }
    return None


def _lookup_shape(events):
    if not events:
        return None
    return sorted(events[0].keys())


def _delete_bucket(s3, bucket):
    listed = CallOutcome.capture("s3", "ListObjectsV2", lambda c: c.list_objects_v2(
        Bucket=bucket))
    if listed.ok:
        for item in listed.raw.get("Contents", []):
            CallOutcome.capture("s3", "DeleteObject", lambda c: c.delete_object(
                Bucket=bucket, Key=item["Key"]))
    CallOutcome.capture("s3", "DeleteBucket", lambda c: c.delete_bucket(Bucket=bucket))


def probe_config(floci, matrix, suffix):
    gaps = []
    operations = {}
    authz = {}
    signals = {}
    client = floci.client("config")

    put_recorder = CallOutcome.capture("config", "PutConfigurationRecorder",
                                       lambda c: c.put_configuration_recorder(
                                           ConfigurationRecorder={
                                               "name": CONFIG_RECORDER,
                                               "roleARN": f"arn:aws:iam::{floci.account}"
                                                          ":role/cloudsec-config-role",
                                               "recordingGroup": {
                                                   "allSupported": True,
                                                   "includeGlobalResourceTypes": True}}))
    operations["PutConfigurationRecorder"] = put_recorder.to_dict()
    start = CallOutcome.capture("config", "StartConfigurationRecorder",
                                lambda c: c.start_configuration_recorder(
                                    ConfigurationRecorderName=CONFIG_RECORDER))
    operations["StartConfigurationRecorder"] = start.to_dict()
    described = CallOutcome.capture("config", "DescribeConfigurationRecorders",
                                    lambda c: c.describe_configuration_recorders())
    operations["DescribeConfigurationRecorders"] = described.to_dict()
    status = CallOutcome.capture("config", "DescribeConfigurationRecorderStatus",
                                 lambda c: c.describe_configuration_recorder_status())
    operations["DescribeConfigurationRecorderStatus"] = status.to_dict()
    recording_state = None
    if status.ok:
        recorders = status.raw.get("ConfigurationRecordersStatus", [])
        recording_state = recorders[0].get("recording") if recorders else None
    operations["RecorderRecording"] = {"operation": "DescribeConfigurationRecorderStatus",
                                        "observed_recording": recording_state}

    delivery = CallOutcome.capture("config", "PutDeliveryChannel", lambda c: c.put_delivery_channel(
        DeliveryChannel={
            "name": f"{CONFIG_RECORDER}-delivery",
            "s3BucketName": f"cloudsec-config-{suffix}",
            "configSnapshotDeliveryProperties": {"deliveryFrequency": "Six_Hours"}}))
    operations["PutDeliveryChannel"] = delivery.to_dict()
    described_delivery = CallOutcome.capture("config", "DescribeDeliveryChannels",
                                             lambda c: c.describe_delivery_channels())
    operations["DescribeDeliveryChannels"] = described_delivery.to_dict()
    delivery_roundtrip = False
    if described_delivery.ok:
        channels = described_delivery.raw.get("DeliveryChannels", [])
        delivery_roundtrip = any(ch.get("name", "").startswith(CONFIG_RECORDER)
                                 for ch in channels)
    operations["DeliveryChannelRoundTrip"] = {
        "operation": "DescribeDeliveryChannels", "ok": delivery_roundtrip}
    if not delivery_roundtrip:
        gaps.append("AWS Config delivery channel did not round-trip through Describe")

    resource = f"arn:aws:s3:::cloudsec-sts-bucket-{suffix}"
    put_rule = CallOutcome.capture("config", "PutConfigRule", lambda c: c.put_config_rule(
        ConfigRule={"ConfigRuleName": CONFIG_RULE,
                    "Source": {"Owner": "CUSTOM_POLICY",
                               "SourceIdentifier": "cloudsec-probe"},
                    "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
                    "InputParameters": "{}"}))
    operations["PutConfigRule"] = put_rule.to_dict()
    described_rules = CallOutcome.capture("config", "DescribeConfigRules",
                                          lambda c: c.describe_config_rules(
                                              ConfigRuleNames=[CONFIG_RULE]))
    operations["DescribeConfigRules"] = described_rules.to_dict()
    before = CallOutcome.capture("config", "DescribeComplianceByConfigRule",
                                 lambda c: c.describe_compliance_by_config_rule(
                                     ConfigRuleNames=[CONFIG_RULE]))
    operations["DescribeComplianceByConfigRuleBefore"] = before.to_dict()
    compliance_before = [_compliance(e) for e in before.raw.get(
        "ComplianceByConfigRules", [])] if before.ok else None
    operations["ComplianceBeforeEvaluations"] = compliance_before
    operations["ComplianceBeforeIsInsufficientData"] = (
        compliance_before == ["INSUFFICIENT_DATA"] if compliance_before is not None else None)

    operations["StartConfigRulesEvaluation"] = _capture(
        client, "StartConfigRulesEvaluation",
        lambda c: c.start_config_rules_evaluation(ConfigRuleNames=[CONFIG_RULE]))
    eval_status = CallOutcome.capture("config", "DescribeConfigRuleEvaluationStatus",
                                      lambda c: c.describe_config_rule_evaluation_status(
                                          ConfigRuleNames=[CONFIG_RULE]))
    operations["DescribeConfigRuleEvaluationStatus"] = eval_status.to_dict()

    put_eval = CallOutcome.capture("config", "PutEvaluations", lambda c: c.put_evaluations(
        ResultToken=CONFIG_RULE,
        Evaluations=[_evaluation(resource, "COMPLIANT")]))
    operations["PutEvaluations"] = put_eval.to_dict()
    after = CallOutcome.capture("config", "DescribeComplianceByConfigRule",
                                lambda c: c.describe_compliance_by_config_rule(
                                    ConfigRuleNames=[CONFIG_RULE]))
    operations["DescribeComplianceByConfigRuleAfter"] = after.to_dict()
    compliance_after = [_compliance(e) for e in after.raw.get(
        "ComplianceByConfigRules", [])] if after.ok else None
    operations["ComplianceAfterEvaluations"] = compliance_after
    operations["ComplianceReflectsSubmittedEvaluation"] = (
        "COMPLIANT" in (compliance_after or []) if compliance_after is not None else None)
    operations["ComplianceResourceObserved"] = (
        after.raw.get("ComplianceByConfigRules", [{}])[0].get("Compliance", {}).get(
            "ComplianceResourceId")
        if after.ok and after.raw.get("ComplianceByConfigRules") else None)
    details = CallOutcome.capture("config", "GetComplianceDetailsByConfigRule",
                                  lambda c: c.get_compliance_details_by_config_rule(
                                      ConfigRuleNames=[CONFIG_RULE]), client)
    operations["GetComplianceDetailsByConfigRule"] = details.to_dict()
    operations["EvaluationResultsCount"] = len(
        details.raw.get("EvaluationResults", [])) if details.ok else None
    recorder_items = CallOutcome.capture("config", "ListDiscoveredResources",
                                         lambda c: c.list_discovered_resources(
                                             resourceType="AWS::S3::Bucket"), client)
    operations["AutoRecordedConfigurationItems"] = {
        "operation": "ListDiscoveredResources",
        "ok": recorder_items.ok,
        "count": len(recorder_items.raw.get("resourceIdentifiers", []))
        if recorder_items.ok else None,
        "note": "a running recorder with no discovered resources means Floci does not "
                "capture configuration changes itself"}
    if recorder_items.ok and not recorder_items.raw.get("resourceIdentifiers"):
        gaps.append(
            "a configuration recorder reported recording but ListDiscoveredResources "
            "returned nothing; Floci stores submitted evaluations rather than "
            "capturing resource configuration")

    for name, func in (
        ("GetResourceConfigHistory", lambda c: c.get_resource_config_history(
            resourceId=resource, resourceType="AWS::S3::Bucket")),
        ("SelectResourceConfig", lambda c: c.select_resource_config(
            Expression="SELECT * FROM {} WHERE resourceId = '{}'".format(
                "AWS::S3::Bucket", resource))),
        ("ListDiscoveredResources", lambda c: c.list_discovered_resources(
            resourceType="AWS::S3::Bucket")),
        ("DescribeDeliveryChannelStatus", lambda c: c.describe_delivery_channel_status(
            DeliveryChannelNames=[f"{CONFIG_RECORDER}-delivery"])),
    ):
        outcome = CallOutcome.capture("config", name, func, client)
        operations[name] = outcome.to_dict()
        if not outcome.ok:
            operations[name]["observed_error_code"] = outcome.error_code

    availability = {"config_deny_observed": True}
    deny_identity = Identity(floci, f"configdeny{suffix}")
    if not deny_identity.create():
        availability["config_deny_observed"] = None
        authz["explicit_deny"] = {"error": "identity creation failed"}
    else:
        confirmed = deny_identity.put_inline_policy("config-deny", policy([
            statement("Allow", "config:*", "*"),
            statement("Deny", "config:PutEvaluations", "*"),
        ]))
        outcome = CallOutcome.capture("config", "PutEvaluations",
                                      lambda c: c.put_evaluations(
                                          ResultToken=CONFIG_RULE,
                                          Evaluations=[_evaluation(resource, "NON_COMPLIANT")]),
                                      deny_identity.client("config"))
        recheck = CallOutcome.capture("config", "DescribeComplianceByResource",
                                      lambda c: c.describe_compliance_by_resource(
                                          ResourceId=resource, Limit=50))
        state_changed = False
        if recheck.ok:
            state_changed = any(e.get("ComplianceStatus") == "NON_COMPLIANT" for e in
                                recheck.raw.get("ComplianceByResources", []))
        authz["explicit_deny"] = matrix.record(
            "CFG-C", "config:PutEvaluations", "config", "iam-user-deny",
            deny_identity.arn, resource, "deny", outcome,
            state_changed=state_changed, policy_confirmed=confirmed,
            signals=["config_deny"],
            notes="re-read compliance to see whether the denied submission landed")
        availability["config_deny_observed"] = authz["explicit_deny"]["classification"]
        deny_identity.delete()

    CallOutcome.capture("config", "DeleteConfigRule", lambda c: c.delete_config_rule(
        ConfigRuleName=CONFIG_RULE))
    CallOutcome.capture("config", "DeleteEvaluationResults", lambda c: c.delete_evaluation_results(
        ConfigRuleName=CONFIG_RULE))
    CallOutcome.capture("config", "StopConfigurationRecorder",
                        lambda c: c.stop_configuration_recorder(
                            ConfigurationRecorderName=CONFIG_RECORDER))
    CallOutcome.capture("config", "DeleteConfigurationRecorder",
                        lambda c: c.delete_configuration_recorder(
                            ConfigurationRecorderName=CONFIG_RECORDER))
    delete_channel = CallOutcome.capture("config", "DeleteDeliveryChannel",
                                         lambda c: c.delete_delivery_channel(
                                             DeliveryChannelName=f"{CONFIG_RECORDER}-delivery"))
    operations["DeleteDeliveryChannel"] = delete_channel.to_dict()
    if not delete_channel.ok and delete_channel.error_code:
        gaps.append(f"Config cleanup: DeleteDeliveryChannel returned {delete_channel.error_code}")
    stop_after = CallOutcome.capture("config", "DescribeConfigurationRecorderStatus",
                                     lambda c: c.describe_configuration_recorder_status())
    operations["RecorderStatusAfterCleanup"] = stop_after.to_dict()

    signals["config"] = availability
    return _result(True, operations, authz, gaps, signals, {})


def _compliance(entry):
    inner = entry.get("Compliance") or {}
    return inner.get("ComplianceType", entry.get("ComplianceStatus"))


def _evaluation(resource_id, compliance):
    return {
        "ComplianceResourceType": "AWS::S3::Bucket",
        "ComplianceResourceId": resource_id,
        "ComplianceType": compliance,
        "OrderingTimestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
    }


def _capture(client, operation, func):
    service = client.meta.service_model.service_name
    return CallOutcome.capture(service, operation, func, client).to_dict()


def _result(available, operations, authz, gaps, signals, observations):
    result = {"available": available, "operations": operations, "authorization": authz,
              "gaps": gaps, "enforcement_signals": signals}
    if observations:
        result["observations"] = observations
    return result