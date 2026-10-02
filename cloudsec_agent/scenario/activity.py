__all__ = [
    "Observed",
    "AUTHORIZATION_DENIED_CODES",
    "ActivityResult",
    "ActivityExecution",
    "S3_ARN_PREFIX",
    "TargetParseError",
    "parse_s3_target",
    "classify_outcome",
    "is_authorization_denial",
    "ordered_events",
    "execute_incident_activity",
]

from dataclasses import dataclass, field

from botocore.exceptions import ParamValidationError

from .evidence import AUTHORITATIVE_EVIDENCE, Actor

S3_ARN_PREFIX = "arn:aws:s3:::"

LOCAL_VALIDATION_ERRORS = (ParamValidationError,)


class TargetParseError(ValueError):
    pass

AUTHORIZATION_DENIED_CODES = frozenset({
    "AccessDenied", "AccessDeniedException", "AccessDeniedError",
    "UnauthorizedOperation", "Forbidden", "NotAuthorized", "UnauthorizedException",
})

FORBIDDEN_RESULT_FIELDS = ("raw", "response", "payload", "body", "data",
                           "result_data", "metadata_dict")


class Observed:
    SUCCESS = "success"
    AUTHORIZATION_DENIED = "authorization_denied"
    API_ERROR = "api_error"
    UNEXPECTED_SUCCESS = "unexpected_success"
    INCONCLUSIVE = "inconclusive"


def is_authorization_denial(error_code: str | None, http_status: int | None) -> bool:
    if error_code and str(error_code) in AUTHORIZATION_DENIED_CODES:
        return True
    if error_code:
        return False
    return http_status in (401, 403)


def classify_outcome(*, ok: bool, error_code: str | None = None,
                     http_status: int | None = None,
                     request_id: str | None = None,
                     exception: str | None = None) -> tuple:
    if ok:
        return Observed.SUCCESS, http_status, error_code, request_id
    if is_authorization_denial(error_code, http_status):
        return Observed.AUTHORIZATION_DENIED, http_status, error_code, request_id
    if error_code or http_status:
        return Observed.API_ERROR, http_status, error_code, request_id
    return Observed.INCONCLUSIVE, http_status, error_code, request_id


@dataclass(frozen=True)
class ActivityResult:
    event_id: str
    service: str
    operation: str
    target: str
    observed_result: str
    http_status: int | None = None
    error_code: str | None = None
    request_id: str | None = None
    native_corroborated: bool = False
    secret_material_returned: bool = False
    actor_access_key_id: str | None = None
    detail: str | None = None


@dataclass
class ActivityExecution:
    results: list = field(default_factory=list)
    access_key_id: str | None = None
    stopped_early: bool = False
    stop_reason: str | None = None


def ordered_events() -> list:
    return list(AUTHORITATIVE_EVIDENCE)


def parse_s3_target(target: str) -> tuple:
    if not isinstance(target, str) or not target.startswith(S3_ARN_PREFIX):
        raise TargetParseError(f"not an S3 ARN: {target!r}")
    bucket, separator, key = target[len(S3_ARN_PREFIX):].partition("/")
    if not bucket:
        raise TargetParseError(f"S3 ARN has an empty bucket: {target!r}")
    if separator and not key:
        raise TargetParseError(f"S3 object ARN has an empty key: {target!r}")
    return bucket, (key if separator else None)


def _extract_exception(exc):
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        if isinstance(exc, LOCAL_VALIDATION_ERRORS):
            kind = type(exc).__name__
            return None, kind, None, kind
        return None, None, None, type(exc).__name__
    metadata = response.get("ResponseMetadata") or {}
    error = response.get("Error") or {}
    return (metadata.get("HTTPStatusCode"), error.get("Code"),
            metadata.get("RequestId"), type(exc).__name__)


def _call_and_classify(client, operation, func):
    try:
        func(client)
    except Exception as exc:  # noqa: BLE001
        status, code, request_id, kind = _extract_exception(exc)
        observed, http_status, error_code, rid = classify_outcome(
            ok=False, error_code=code, http_status=status, request_id=request_id)
        return observed, http_status, error_code, rid, f"{kind}"
    return Observed.SUCCESS, None, None, None, None


def _execute_secret_probe(client, secret_id):
    try:
        response = client.get_secret_value(SecretId=secret_id)
    except Exception as exc:  # noqa: BLE001
        status, code, request_id, kind = _extract_exception(exc)
        observed, http_status, error_code, rid = classify_outcome(
            ok=False, error_code=code, http_status=status, request_id=request_id)
        return observed, http_status, error_code, rid, False, f"{kind}"
    returned = bool(response.get("SecretString") or response.get("SecretBinary"))
    response.clear()
    del response
    return Observed.UNEXPECTED_SUCCESS, None, None, None, returned, None


def _dispatch(event, credential, floci, evidence_bucket_arn, secret_arn):
    client = credential.client(floci, event.service)
    if event.service == "s3":
        bucket, key = parse_s3_target(event.target)
        if event.operation == "s3:GetObject":
            if key is None:
                raise TargetParseError(
                    "s3:GetObject requires an object ARN, not a bucket ARN")
            func = lambda c, b=bucket, k=key: c.get_object(
                Bucket=b, Key=k)["Body"].read()
            observed, status, code, rid, detail = _call_and_classify(
                client, event.operation, func)
        else:
            func = lambda c, b=bucket: c.list_objects_v2(Bucket=b)
            observed, status, code, rid, detail = _call_and_classify(
                client, event.operation, func)
    elif event.service == "secretsmanager":
        observed, status, code, rid, returned, detail = _execute_secret_probe(
            client, secret_arn)
        return observed, status, code, rid, returned, detail
    elif event.service == "iam":
        func = lambda c, t=event.target: c.get_user(UserName=t.rsplit("/", 1)[1])
        observed, status, code, rid, detail = _call_and_classify(
            client, event.operation, func)
    else:
        func = lambda c: c.get_caller_identity()
        observed, status, code, rid, detail = _call_and_classify(
            client, event.operation, func)
    return observed, status, code, rid, False, detail


def execute_incident_activity(floci, credential, secret_arn: str | None = None,
                              evidence_bucket_arn: str | None = None) -> ActivityExecution:
    execution = ActivityExecution(access_key_id=credential.access_key_id)
    for event in ordered_events():
        observed, status, code, rid, returned, detail = _dispatch(
            event, credential, floci, evidence_bucket_arn, secret_arn)
        result = ActivityResult(
            event_id=event.id, service=event.service, operation=event.operation,
            target=event.target, observed_result=observed, http_status=status,
            error_code=code, request_id=rid, native_corroborated=False,
            secret_material_returned=returned,
            actor_access_key_id=credential.access_key_id, detail=detail)
        execution.results.append(result)
        if observed == Observed.UNEXPECTED_SUCCESS:
            execution.stopped_early = True
            execution.stop_reason = (
                f"{event.id} unexpectedly returned secret material; "
                f"remaining events were not executed")
            break
    return execution