__all__ = [
    "AccessKeyState",
    "MutationCallResult",
    "LiveExecutionPort",
    "PortReadError",
]

from dataclasses import dataclass

from .executor import ExecutionPort


@dataclass(frozen=True)
class AccessKeyState:
    access_key_id: str
    status: str

    def as_dict(self) -> dict:
        return {"access_key_id": self.access_key_id, "status": self.status}


@dataclass(frozen=True)
class MutationCallResult:
    succeeded: bool
    http_status: object = None
    error_code: str = ""
    error_kind: str = ""

    def as_dict(self) -> dict:
        return {"succeeded": self.succeeded, "http_status": self.http_status,
                "error_code": self.error_code, "error_kind": self.error_kind}


def _error_fields(exc):
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        metadata = response.get("ResponseMetadata") or {}
        error = response.get("Error") or {}
        return (metadata.get("HTTPStatusCode"), error.get("Code"), "api")
    return (None, type(exc).__name__, "transport")


class PortReadError(RuntimeError):
    def __init__(self, http_status, error_code, error_kind):
        self.http_status = http_status
        self.error_code = error_code
        self.error_kind = error_kind
        super().__init__(f"list_access_keys failed: {error_kind}")


class LiveExecutionPort(ExecutionPort):
    def __init__(self, iam_client):
        if iam_client is None:
            raise TypeError("iam_client must be an already-constructed client")
        self._iam = iam_client

    def list_access_keys(self, user_name) -> tuple:
        try:
            raw = self._iam.list_access_keys(UserName=user_name)
        except Exception as exc:  # noqa: BLE001
            status, code, kind = _error_fields(exc)
            raise PortReadError(status, code, kind) from None
        entries = (raw or {}).get("AccessKeyMetadata") or ()
        return tuple(AccessKeyState(access_key_id=entry["AccessKeyId"],
                                    status=entry["Status"])
                     for entry in entries
                     if isinstance(entry, dict)
                     and "AccessKeyId" in entry and "Status" in entry)

    def update_access_key_status(self, user_name, access_key_id,
                                 status) -> MutationCallResult:
        try:
            raw = self._iam.update_access_key(UserName=user_name,
                                              AccessKeyId=access_key_id,
                                              Status=status)
        except Exception as exc:  # noqa: BLE001
            http_status, code, kind = _error_fields(exc)
            return MutationCallResult(succeeded=False, http_status=http_status,
                                      error_code=code, error_kind=kind)
        http_status = ((raw or {}).get("ResponseMetadata") or {}).get(
            "HTTPStatusCode")
        return MutationCallResult(succeeded=True, http_status=http_status,
                                  error_kind="")


class _PortReadError(RuntimeError):
    def __init__(self, http_status, error_code, error_kind):
        self.http_status = http_status
        self.error_code = error_code
        self.error_kind = error_kind
        super().__init__(f"list_access_keys failed: {error_kind}")