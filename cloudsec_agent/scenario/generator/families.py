__all__ = [
    "build_family",
]

from . import naming
from .models import (DIFFICULTY_EASY, FAMILY_BENIGN,
                     FAMILY_CREDENTIAL_COMPROMISE, FAMILY_DATA_ACCESS_ANOMALY,
                     FAMILY_RECON_HEAVY)


def _incident_policy_document(bucket, group) -> str:
    import json
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow",
             "Action": ["s3:ListBucket", "s3:GetObject"],
             "Resource": [f"arn:aws:s3:::{bucket}",
                          f"arn:aws:s3:::{bucket}/*"]},
            {"Effect": "Allow",
             "Action": ["logs:FilterLogEvents", "logs:GetLogEvents"],
             "Resource": ["*"]}]}, sort_keys=True)


def _common_resources(rng):
    user = naming.user_name(rng)
    return {
        "incident_user": user,
        "investigator_user": naming.investigator_name(rng),
        "bucket": naming.bucket_name(rng),
        "incident_policy": naming.policy_name(rng, user),
        "secret_name": naming.secret_name(rng),
        "function_name": naming.function_name(rng),
        "log_group": naming.log_group(rng),
        "log_stream": naming.log_stream(rng),
    }


def _notes_object(prefix, index):
    return {
        "key": f"{prefix}/handoff-{index:02d}.md",
        "body": ("Reporting handoff notes.\n"
                 "Check the quarterly summary before the next cycle.\n"),
    }


def _report_object(rng, prefix, unusual=False):
    if unusual:
        key = f"unusual/extern-share/{naming.hex_token(rng, 6)}.txt"
    else:
        key = naming.object_key(rng, prefix)
    return {"key": key,
            "body": "Quarterly reporting summary.\nStatus: reviewed.\n"}


def _credential_compromise(rng, medium):
    res = _common_resources(rng)
    actor = naming.actor_label(rng)
    prefix = f"reports-{naming.hex_token(rng, 4)}"
    objects = [_notes_object(prefix, 1),
               _report_object(rng, prefix)]
    if medium:
        objects.append(_report_object(rng, prefix))
        objects.append(_notes_object(prefix, 2))
    events = [
        {"actor": naming.benign_actor(rng), "key": None,
         "operation": "s3:ListObjectsV2", "target": res["bucket"],
         "result": "success", "kind": "benign"},
        {"actor": actor, "key": "incident",
         "operation": "s3:ListObjectsV2", "target": res["bucket"],
         "result": "success", "kind": "anomaly"},
        {"actor": actor, "key": "incident",
         "operation": "s3:GetObject", "target": objects[1]["key"],
         "result": "success", "kind": "anomaly"},
    ]
    if medium:
        events.append({"actor": naming.benign_actor(rng), "key": None,
                       "operation": "s3:GetObject",
                       "target": objects[0]["key"], "result": "success",
                       "kind": "benign"})
    return {
        "resources": res,
        "objects": objects,
        "events": events,
        "malicious": True,
        "principal": res["incident_user"],
        "key_owner": res["incident_user"],
        "actor_map": {actor: res["incident_user"]},
        "truth_label": "credential compromise with anomalous access",
        "briefing_note": "",
    }


def _recon_heavy(rng, medium):
    base = _credential_compromise(rng, medium)
    res = base["resources"]
    actor = next(key for key, value in base["actor_map"].items()
                 if value == res["incident_user"])
    recon = [
        {"actor": actor, "key": None,
         "operation": "s3:ListObjectsV2",
         "target": res["bucket"], "result": "success", "kind": "recon"},
        {"actor": actor, "key": None,
         "operation": "iam:ListUserPolicies",
         "target": res["incident_user"], "result": "denied",
         "kind": "recon"},
        {"actor": actor, "key": None,
         "operation": "lambda:GetFunctionConfiguration",
         "target": res["function_name"], "result": "success",
         "kind": "recon"},
    ]
    events = recon + base["events"]
    if medium:
        rng.shuffle(events)
    base["events"] = events
    base["truth_label"] = ("credential compromise preceded by "
                           "reconnaissance")
    return base


def _data_access_anomaly(rng, medium):
    res = _common_resources(rng)
    actor = naming.actor_label(rng)
    prefix = f"reports-{naming.hex_token(rng, 4)}"
    target = _report_object(rng, prefix, unusual=True)
    objects = [_notes_object(prefix, 1), target]
    if medium:
        objects.append(_report_object(rng, prefix))
    events = [
        {"actor": naming.benign_actor(rng), "key": None,
         "operation": "s3:ListObjectsV2", "target": res["bucket"],
         "result": "success", "kind": "benign"},
        {"actor": actor, "key": "incident",
         "operation": "s3:GetObject", "target": target["key"],
         "result": "success", "kind": "anomaly"},
    ]
    if medium:
        events.append({"actor": naming.benign_actor(rng), "key": None,
                       "operation": "s3:GetObject",
                       "target": objects[0]["key"], "result": "success",
                       "kind": "benign"})
    return {
        "resources": res,
        "objects": objects,
        "events": events,
        "malicious": True,
        "principal": res["incident_user"],
        "key_owner": res["incident_user"],
        "actor_map": {actor: res["incident_user"]},
        "truth_label": "anomalous data access with compromised credential",
        "briefing_note": "",
    }


def _benign(rng, medium):
    res = _common_resources(rng)
    prefix = f"reports-{naming.hex_token(rng, 4)}"
    objects = [_notes_object(prefix, 1),
               _report_object(rng, prefix)]
    if medium:
        objects.append(_report_object(rng, prefix))
    actor = naming.benign_actor(rng)
    events = [
        {"actor": actor, "key": None,
         "operation": "s3:ListObjectsV2", "target": res["bucket"],
         "result": "success", "kind": "benign"},
        {"actor": naming.benign_actor(rng), "key": None,
         "operation": "s3:GetObject", "target": objects[1]["key"],
         "result": "success", "kind": "benign"},
    ]
    if medium:
        events.append({"actor": naming.benign_actor(rng), "key": None,
                       "operation": "lambda:GetFunctionConfiguration",
                       "target": res["function_name"], "result": "success",
                       "kind": "benign"})
    return {
        "resources": res,
        "objects": objects,
        "events": events,
        "malicious": False,
        "principal": None,
        "key_owner": None,
        "actor_map": {},
        "truth_label": "legitimate reporting activity, no compromise",
        "briefing_note": (" A new reporting job was recently onboarded "
                          "in this account."),
    }


def build_family(family, rng, medium):
    if family == FAMILY_CREDENTIAL_COMPROMISE:
        return _credential_compromise(rng, medium)
    if family == FAMILY_RECON_HEAVY:
        return _recon_heavy(rng, medium)
    if family == FAMILY_DATA_ACCESS_ANOMALY:
        return _data_access_anomaly(rng, medium)
    if family == FAMILY_BENIGN:
        return _benign(rng, medium)
    raise ValueError("unknown family")


def incident_policy_for(bucket, group) -> str:
    return _incident_policy_document(bucket, group)
