__all__ = [
    "CallOutcome",
    "ENFORCEMENT_KEYS",
    "AuthorizationMatrix",
    "classify_enforcement",
    "normalize_enforcement",
    "merge_gaps",
]

from dataclasses import dataclass, field

from .redaction import redact

ENFORCEMENT_KEYS = (
    "identity_allow_observed",
    "implicit_deny_observed",
    "explicit_deny_observed",
    "resource_scoping_observed",
    "sts_trust_enforcement_observed",
    "sts_role_restrictions_observed",
    "unresolved_action_behavior",
)


@dataclass
class CallOutcome:
    operation: str
    service: str | None = None
    ok: bool | None = None
    status: int | None = None
    exception: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    request_id: str | None = None
    result_summary: dict = field(default_factory=dict)
    detail: str | None = None
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def capture(cls, service: str, operation: str, func, client=None, *args, **kwargs):
        outcome = cls(operation=operation, service=service)
        try:
            if client is None:
                from .floci_client import default_client

                client = default_client(service)
            payload = func(client, *args, **kwargs)
            outcome.ok = True
            outcome.raw = payload if isinstance(payload, dict) else {}
            outcome.result_summary = _summarise(payload)
        except Exception as exc:  # noqa: BLE001
            outcome.ok = False
            outcome.exception = type(exc).__name__
            response = getattr(exc, "response", None)
            if isinstance(response, dict):
                outcome.status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
                outcome.request_id = (
                    response.get("ResponseMetadata", {}).get("RequestId")
                    or response.get("RequestId")
                )
                error = response.get("Error") or {}
                outcome.error_code = error.get("Code")
                outcome.error_message = error.get("Message")
            outcome.detail = redact(str(exc))[:300]
        return outcome

    @property
    def denied(self) -> bool:
        if self.ok:
            return False
        code = (self.error_code or "").lower()
        return code in {
            "accessdenied",
            "accessdeniedexception",
            "unauthorizedoperation",
            "accessdeniederror",
            "forbidden",
            "403",
        } or (self.status in (401, 403))

    def to_dict(self) -> dict:
        data = {
            "operation": self.operation,
            "service": self.service,
            "ok": self.ok,
            "status": self.status,
            "exception": self.exception,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "request_id": self.request_id,
            "result_summary": self.result_summary,
            "detail": self.detail,
        }
        return {key: redact(value) for key, value in data.items()}


def _summarise(payload) -> dict:
    if payload is None:
        return {}
    if isinstance(payload, (str, int, float, bool)):
        return {"value": redact(str(payload))[:200]}
    if isinstance(payload, (list, tuple)):
        return {"count": len(payload)}
    if isinstance(payload, dict):
        keys = ("Arn", "Name", "UserName", "RoleName", "BucketName", "KeyId",
                "SecretId", "Name", "VersionId", "GroupName", "TrailName",
                "Account", "PolicyArn", "InstanceProfileName", "State")
        out = {k: redact(payload[k]) for k in keys if k in payload}
        for count_key in ("Contents", "Users", "Roles", "Policies", "Secrets",
                          "trailList", "Recorders", "deliveryChannels",
                          "ConfigurationItems", "Keys"):
            if count_key in payload and isinstance(payload[count_key], list):
                out[f"{count_key}_count"] = len(payload[count_key])
        return out
    return {"type": type(payload).__name__}


def classify_enforcement(expected: str, observed_allowed: bool | None,
                         policy_confirmed: bool | None) -> bool | None:
    if observed_allowed is None:
        return None
    if expected == "allow" and observed_allowed:
        return True
    if expected == "deny" and not observed_allowed:
        return True
    if policy_confirmed is not True:
        return None
    return False


def normalize_enforcement(enforcement: dict) -> dict:
    return {key: enforcement.get(key) for key in ENFORCEMENT_KEYS}


def merge_gaps(*groups) -> list:
    seen = set()
    out = []
    for group in groups:
        for gap in group or []:
            text = redact(str(gap))
            if text not in seen:
                seen.add(text)
                out.append(text)
    return out


def aggregate_values(values: list) -> bool | None:
    if not values:
        return None
    if any(value is False for value in values):
        return False
    if all(value is True for value in values):
        return True
    return None


class AuthorizationMatrix:
    def __init__(self):
        self._cases: list[dict] = []

    def record(self, label, operation, service, principal_type, principal,
               resource, expected, outcome: CallOutcome, state_changed=None,
               policy_confirmed=None, signals=(), notes="") -> dict:
        if outcome.ok:
            allowed = True
        elif outcome.error_code is not None:
            allowed = False
        else:
            allowed = None
        classification = classify_enforcement(expected, allowed, policy_confirmed)
        case = {
            "label": label,
            "service": service,
            "operation": operation,
            "principal_type": principal_type,
            "principal": redact(principal or ""),
            "target_resource": redact(resource or ""),
            "expected_aws_outcome": expected,
            "actual_allowed": allowed,
            "http_status": outcome.status,
            "exception": outcome.exception,
            "error_code": outcome.error_code,
            "request_id": outcome.request_id,
            "state_changed": state_changed,
            "policy_confirmed": policy_confirmed,
            "signals": list(signals),
            "classification": classification,
            "notes": redact(notes),
        }
        self._cases.append(case)
        return case

    def cases(self) -> list:
        return list(self._cases)

    def to_dict(self) -> dict:
        return {"cases": self.cases()}

    def aggregate(self) -> dict:
        buckets: dict[str, list] = {}
        for case in self._cases:
            for signal in case["signals"]:
                buckets.setdefault(signal, []).append(case["classification"])
        return {key: aggregate_values(values) for key, values in buckets.items()}