__all__ = [
    "GeneratedVerification",
    "verify_generated",
]

from dataclasses import dataclass, field


@dataclass
class GeneratedVerification:
    scenario_id: str
    checks: object = field(default_factory=list)
    failures: object = field(default_factory=list)

    def __post_init__(self):
        object.__setattr__(self, "checks", list(self.checks or []))
        object.__setattr__(self, "failures", list(self.failures or []))

    @property
    def ok(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict:
        return {"scenario_id": self.scenario_id,
                "checks": list(self.checks),
                "failures": list(self.failures)}


def verify_generated(client, spec) -> GeneratedVerification:
    expected = spec.expected
    report = GeneratedVerification(scenario_id=spec.scenario_id)
    expected_users = list(expected.users)
    expected_keys = list(expected.object_keys)
    expected_events = expected.log_event_count or 0
    bucket = spec.bucket
    group = spec.log_group
    stream = spec.log_stream

    def check(identifier, description, status, detail=None):
        report.checks.append({"id": identifier, "description": description,
                              "status": status, "detail": detail})
        if status != "pass":
            report.failures.append(f"{identifier}: {detail}")

    try:
        users = client.client("iam").list_users().get("Users", [])
    except Exception:
        users = None
    if users is None:
        check("VG-01", "users listed", "fail", "list_users failed")
        return report
    names = {item.get("UserName") for item in users if isinstance(item,
                                                                  dict)}
    missing = [name for name in expected_users if name not in names]
    check("VG-01", "expected users present",
          "pass" if not missing else "fail",
          None if not missing else f"missing={missing}")

    def active_count(user):
        try:
            listed = client.client("iam").list_access_keys(
                UserName=user).get("AccessKeyMetadata", [])
        except Exception:
            return None
        return sum(1 for item in listed if isinstance(item, dict) and
                   item.get("Status") == "Active")

    incident_expected = expected.incident_key_active_count
    investigator_expected = expected.investigator_key_active_count
    incident_got = active_count(expected_users[0]) if expected_users \
        else None
    check("VG-02", "incident key active",
          "pass" if incident_got == incident_expected else "fail",
          f"expected={incident_expected} got={incident_got}")
    investigator_got = active_count(expected_users[1]) \
        if len(expected_users) > 1 else None
    check("VG-03", "investigator key active",
          "pass" if investigator_got == investigator_expected else "fail",
          f"expected={investigator_expected} got={investigator_got}")
    try:
        listed = client.client("s3").list_objects_v2(
            Bucket=bucket).get("Contents", [])
        keys = sorted(item.get("Key") for item in listed
                      if isinstance(item, dict))
    except Exception:
        keys = None
    check("VG-04", "expected objects present",
          "pass" if keys == sorted(expected_keys) else "fail",
          f"expected={sorted(expected_keys)} got={keys}")
    try:
        events = client.client("logs").get_log_events(
            logGroupName=group, logStreamName=stream).get("events", [])
        count = len(events) if isinstance(events, list) else None
    except Exception:
        count = None
    check("VG-05", "expected log events present",
          "pass" if count == expected_events else "fail",
          f"expected={expected_events} got={count}")
    secret = expected.secret_name
    try:
        described = client.client("secretsmanager").describe_secret(
            SecretId=secret)
        secret_ok = bool(described.get("ARN"))
    except Exception:
        secret_ok = False
    check("VG-06", "secret describable",
          "pass" if secret_ok else "fail", None)
    function = expected.function_name
    try:
        configured = client.client("lambda").get_function_configuration(
            FunctionName=function)
        function_ok = bool(configured.get("FunctionArn"))
    except Exception:
        function_ok = False
    check("VG-07", "function present",
          "pass" if function_ok else "fail", None)
    policy = expected.policy_name
    try:
        documented = client.client("iam").get_user_policy(
            UserName=expected_users[0], PolicyName=policy)
        policy_ok = bool((documented.get("PolicyDocument") or {}).get(
            "Statement"))
    except Exception:
        policy_ok = False
    check("VG-08", "incident policy present",
          "pass" if policy_ok else "fail", None)
    return report
