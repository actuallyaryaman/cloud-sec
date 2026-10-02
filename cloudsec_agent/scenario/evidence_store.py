__all__ = [
    "StoreClass",
    "StorageRole",
    "EvidenceDocument",
    "EvidenceWriteRecord",
    "EvidenceWriteResult",
    "EvidenceValidationError",
    "build_evidence_documents",
    "serialize_document",
    "serialize_cloudwatch_copy",
    "write_evidence",
]

import json
from dataclasses import dataclass, field

from .activity import ActivityExecution, ActivityResult
from .determinism import RESOURCES
from .evidence import AUTHORITATIVE_EVIDENCE

AUTHORITATIVE_ROLE = "synthetic_authoritative"
STORAGE_ROLE_FIELD = "storage_role"
STORAGE_ROLE_AUTHORITATIVE = "authoritative_s3"
STORAGE_ROLE_COPY = "cloudwatch_copy"
EVIDENCE_PREFIX = "activity"
SERIALISED_FIELDS = (
    "id", "event_time", "time_basis", "actor", "actor_access_key_id",
    "service", "operation", "target", "observed_result", "observed_http_status",
    "observed_error_code", "native_corroborated", "authoritative", "required",
    "attacker_controllable", "provenance", "secret_material_returned",
    "storage_role",
)


class StoreClass:
    CONFIRMED = "CONFIRMED"
    API_ERROR = "API_ERROR"
    EMPTY_SUCCESS = "EMPTY_SUCCESS"
    INCONCLUSIVE = "INCONCLUSIVE"


class StorageRole:
    AUTHORITATIVE = STORAGE_ROLE_AUTHORITATIVE
    COPY = STORAGE_ROLE_COPY


class EvidenceValidationError(ValueError):
    pass


@dataclass(frozen=True)
class EvidenceDocument:
    event_id: str
    event_time: str | None
    time_basis: str
    actor: str
    actor_access_key_id: str | None
    service: str
    operation: str
    target: str
    observed_result: str
    observed_http_status: int | None
    observed_error_code: str | None
    native_corroborated: bool
    authoritative: bool
    required: bool
    attacker_controllable: bool
    provenance: str
    secret_material_returned: bool

    @property
    def key(self) -> str:
        return f"{EVIDENCE_PREFIX}/{self.event_id}.json"

    @property
    def bucket(self) -> str:
        return RESOURCES.evidence_bucket

    def payload(self) -> dict:
        return {
            "id": self.event_id,
            "event_time": self.event_time,
            "time_basis": self.time_basis,
            "actor": self.actor,
            "actor_access_key_id": self.actor_access_key_id,
            "service": self.service,
            "operation": self.operation,
            "target": self.target,
            "observed_result": self.observed_result,
            "observed_http_status": self.observed_http_status,
            "observed_error_code": self.observed_error_code,
            "native_corroborated": self.native_corroborated,
            "authoritative": self.authoritative,
            "required": self.required,
            "attacker_controllable": self.attacker_controllable,
            "provenance": self.provenance,
            "secret_material_returned": self.secret_material_returned,
            STORAGE_ROLE_FIELD: STORAGE_ROLE_AUTHORITATIVE,
        }


@dataclass
class EvidenceWriteRecord:
    event_id: str
    storage: str
    key: str | None = None
    put_http_status: int | None = None
    readback_http_status: int | None = None
    confirmed: bool = False
    classification: str = StoreClass.INCONCLUSIVE
    error_code: str | None = None

    def as_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "storage": self.storage,
            "key": self.key,
            "put_http_status": self.put_http_status,
            "readback_http_status": self.readback_http_status,
            "confirmed": self.confirmed,
            "classification": self.classification,
            "error_code": self.error_code,
        }

    def summary(self) -> str:
        return (f"{self.classification:<14} {self.storage:<12} "
                f"{self.event_id} key={self.key} "
                f"put={self.put_http_status} read={self.readback_http_status} "
                f"err={self.error_code}")


@dataclass
class EvidenceWriteResult:
    s3_records: list = field(default_factory=list)
    cloudwatch_records: list = field(default_factory=list)
    fatal_errors: list = field(default_factory=list)
    first_divergence: object = None
    documents: tuple = ()

    def confirmed_s3(self) -> list:
        return [item.event_id for item in self.s3_records if item.confirmed]

    def confirmed_cloudwatch(self) -> list:
        return [item.event_id for item in self.cloudwatch_records if item.confirmed]

    def as_dict(self) -> dict:
        return {
            "s3_records": [item.as_dict() for item in self.s3_records],
            "cloudwatch_records": [item.as_dict() for item in self.cloudwatch_records],
            "confirmed_s3": self.confirmed_s3(),
            "confirmed_cloudwatch": self.confirmed_cloudwatch(),
            "fatal_errors": list(self.fatal_errors),
            "first_divergence": (self.first_divergence.as_dict()
                                 if self.first_divergence is not None else None),
        }


def _catalogue(event_id):
    for item in AUTHORITATIVE_EVIDENCE:
        if item.id == event_id:
            return item
    raise EvidenceValidationError(f"unknown evidence id: {event_id!r}")


def build_evidence_documents(activity) -> tuple:
    if isinstance(activity, ActivityExecution):
        results = list(activity.results)
    elif isinstance(activity, (list, tuple)):
        results = list(activity)
    else:
        raise EvidenceValidationError(
            "evidence documents require an ActivityExecution or ActivityResult list")
    for item in results:
        if not isinstance(item, ActivityResult):
            raise EvidenceValidationError(
                f"evidence documents require ActivityResult values, got "
                f"{type(item).__name__}")

    identifiers = [item.event_id for item in results]
    duplicates = {name for name in identifiers if identifiers.count(name) > 1}
    if duplicates:
        raise EvidenceValidationError(f"duplicate event ids: {sorted(duplicates)}")
    for name in identifiers:
        _catalogue(name)

    canonical = [item.id for item in AUTHORITATIVE_EVIDENCE]
    if identifiers != canonical[:len(identifiers)]:
        raise EvidenceValidationError(
            f"evidence must be a strict catalogue prefix in order; got {identifiers}")

    documents = []
    for result in results:
        entry = _catalogue(result.event_id)
        documents.append(EvidenceDocument(
            event_id=entry.id,
            event_time=entry.event_time,
            time_basis=entry.time_basis,
            actor=entry.actor,
            actor_access_key_id=result.actor_access_key_id,
            service=entry.service,
            operation=entry.operation,
            target=entry.target,
            observed_result=result.observed_result,
            observed_http_status=result.http_status,
            observed_error_code=result.error_code,
            native_corroborated=bool(result.native_corroborated),
            authoritative=entry.authoritative,
            required=entry.required,
            attacker_controllable=entry.attacker_controllable,
            provenance=AUTHORITATIVE_ROLE,
            secret_material_returned=bool(result.secret_material_returned),
        ))
    return tuple(documents)


def _dump(payload) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n"


def serialize_document(document: EvidenceDocument) -> str:
    return _dump(document.payload())


def serialize_cloudwatch_copy(document: EvidenceDocument) -> str:
    payload = document.payload()
    payload[STORAGE_ROLE_FIELD] = STORAGE_ROLE_COPY
    return _dump(payload)


def _status(call):
    raw = call.raw or {}
    return raw.get("ResponseMetadata", {}).get("HTTPStatusCode")


def _fail(result, record, event_id, storage, call, readback_ok, detail=None):
    record.readback_http_status = detail.get("status") if detail else None
    if not call.ok:
        record.classification = StoreClass.API_ERROR
    elif readback_ok is False:
        record.classification = StoreClass.EMPTY_SUCCESS
    else:
        record.classification = StoreClass.INCONCLUSIVE
    result.fatal_errors.append(
        f"{record.classification} at {storage} for {event_id}: "
        f"error={record.error_code}")
    if result.first_divergence is None:
        result.first_divergence = record
    return result


def write_evidence(floci, activity) -> EvidenceWriteResult:
    from ..result import CallOutcome

    documents = build_evidence_documents(activity)
    result = EvidenceWriteResult(documents=documents)
    s3 = floci.client("s3")
    logs = floci.client("logs")
    group = RESOURCES.log_group
    stream = RESOURCES.log_stream

    for document in documents:
        body = serialize_document(document).encode("utf-8")
        put = CallOutcome.capture("s3", "PutObject", lambda c, b=document.bucket,
                                  k=document.key, v=body: c.put_object(
                                      Bucket=b, Key=k, Body=v), s3)
        record = EvidenceWriteRecord(event_id=document.event_id, storage="s3",
                                     key=document.key,
                                     put_http_status=_status(put),
                                     error_code=put.error_code)
        result.s3_records.append(record)
        if not put.ok:
            return _fail(result, record, document.event_id, "s3", put, None)

        expected = document.payload()
        got = CallOutcome.capture("s3", "GetObject", lambda c, b=document.bucket,
                                  k=document.key: {
                                      "body": c.get_object(Bucket=b, Key=k)[
                                          "Body"].read().decode("utf-8")}, s3)
        record.readback_http_status = _status(got)
        matched = False
        if got.ok:
            try:
                matched = json.loads(got.raw.get("body")) == expected
            except ValueError:
                matched = False
        if not got.ok or not matched:
            return _fail(result, record, document.event_id, "s3", put, matched)
        record.confirmed = True
        record.classification = StoreClass.CONFIRMED

        copy_body = serialize_cloudwatch_copy(document).encode("utf-8")
        submitted = CallOutcome.capture(
            "logs", "PutLogEvents", lambda c: c.put_log_events(
                logGroupName=group, logStreamName=stream,
                logEvents=[{"timestamp": 0, "message": copy_body.decode("utf-8")}]),
            logs)
        copy_record = EvidenceWriteRecord(
            event_id=document.event_id, storage="cloudwatch",
            key=f"{group}/{stream}", put_http_status=_status(submitted),
            error_code=submitted.error_code)
        result.cloudwatch_records.append(copy_record)
        if not submitted.ok:
            return _fail(result, copy_record, document.event_id, "cloudwatch",
                         submitted, None)

        copy_record.readback_http_status = _locate_copy(
            logs, group, stream, document, copy_record)
        if not copy_record.confirmed:
            copy_record.classification = (StoreClass.API_ERROR
                                          if copy_record.error_code
                                          else StoreClass.EMPTY_SUCCESS)
            result.fatal_errors.append(
                f"{copy_record.classification} at cloudwatch for "
                f"{document.event_id}: error={copy_record.error_code}")
            if result.first_divergence is None:
                result.first_divergence = copy_record
            return result
        copy_record.classification = StoreClass.CONFIRMED
    return result


MAX_LOG_PAGES = 3


def _message_matches(message, document) -> bool:
    if not isinstance(message, str):
        return False
    try:
        decoded = json.loads(message)
    except ValueError:
        return False
    if not isinstance(decoded, dict):
        return False
    return (decoded.get("id") == document.event_id
            and decoded.get(STORAGE_ROLE_FIELD) == STORAGE_ROLE_COPY)


def _locate_copy(logs, group, stream, document, record) -> int | None:
    from ..result import CallOutcome

    token = None
    status = None
    for _ in range(MAX_LOG_PAGES):
        kwargs = {"logGroupName": group, "logStreamName": stream}
        if token:
            kwargs["nextToken"] = token
        got = CallOutcome.capture("logs", "GetLogEvents",
                                  lambda c, k=kwargs: c.get_log_events(**k), logs)
        raw = got.raw or {}
        status = raw.get("ResponseMetadata", {}).get("HTTPStatusCode") or status
        if not got.ok:
            record.error_code = got.error_code
            return status
        for event in raw.get("events", []) or []:
            if _message_matches(event.get("message"), document):
                record.confirmed = True
                return status
        following = raw.get("nextForwardToken")
        if not following or following == token:
            break
        token = following
    return status