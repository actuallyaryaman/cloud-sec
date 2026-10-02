__all__ = [
    "UnsafeEndpointError",
    "EndpointUnavailable",
    "Floci",
    "LOCAL_HOSTS",
    "ALLOWED_SCHEMES",
    "REGION",
    "assert_local_endpoint",
    "wait_for_endpoint",
    "build_report",
]

import os
import socket
import time
from urllib.parse import urlsplit

os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

import boto3
from botocore.config import Config

from .redaction import redact

LOCAL_HOSTS = frozenset(
    {"localhost", "127.0.0.1", "::1", "host.docker.internal", "floci"}
)
ALLOWED_SCHEMES = frozenset({"http"})
REGION = "us-east-1"

PROBE_AKID = "CLOUDSECPROBEKEY000001"
PROBE_SECRET = "cloudsec-probe-synthetic-secret-value"
PROBE_SESSION = "cloudsec-probe-synthetic-session-token"
CANDIDATE_AKIDS = (
    ("probe_credential", PROBE_AKID, PROBE_SECRET),
    ("test_credential", "test", "test"),
    ("account_root_credential", "000000000000", "cloudsec-probe-synthetic-secret-value"),
)


class UnsafeEndpointError(RuntimeError):
    pass


class EndpointUnavailable(RuntimeError):
    pass


def _normalise(endpoint: str) -> str:
    return endpoint.rstrip("/")


def assert_local_endpoint(endpoint: str) -> str:
    parts = urlsplit(_normalise(endpoint))
    if parts.scheme not in ALLOWED_SCHEMES:
        raise UnsafeEndpointError(f"scheme not permitted: {parts.scheme!r}")
    host = (parts.hostname or "").lower()
    if host not in LOCAL_HOSTS:
        raise UnsafeEndpointError(f"host not permitted: {host!r}")
    return _normalise(endpoint)


_DEFAULT_CLIENTS: dict[str, object] = {}


def default_client(service: str):
    client = _DEFAULT_CLIENTS.get(service)
    if client is None:
        raise EndpointUnavailable(
            f"no probe-credential client registered for {service}; "
            f"every client must come from Floci.client")
    return client


class Floci:
    def __init__(self, endpoint: str, read_timeout: int = 20, connect_timeout: int = 5):
        self.endpoint = assert_local_endpoint(endpoint)
        parts = urlsplit(self.endpoint)
        self._host = (parts.hostname or "").lower()
        self._port = parts.port or 80
        self._read_timeout = read_timeout
        self._connect_timeout = connect_timeout
        self._clients: dict[tuple, object] = {}
        self._arn = None
        self._user_id = None
        self.account = None
        self.admin_akid = PROBE_AKID
        self.admin_secret = PROBE_SECRET
        self.admin_credential = "probe_credential"
        self.floci_version = None
        self.floci_edition = None
        self.floci_services = None
        self.enforcement_hint = None
        self.health_raw = None
        self.credential_selection = None

    def _guard(self, request, **_kwargs):
        parts = urlsplit(getattr(request, "url", ""))
        host = (parts.hostname or "").lower()
        if host not in LOCAL_HOSTS:
            raise UnsafeEndpointError(f"blocked non-local request host: {host!r}")
        if parts.port and parts.port != self._port:
            raise UnsafeEndpointError(
                f"blocked cross-port request: {host}:{parts.port} != {self._port}"
            )

    def client(self, service: str, akid: str = PROBE_AKID, secret: str = PROBE_SECRET,
               token: str | None = None, read_timeout: int | None = None):
        key = (service, akid, token or "")
        cached = self._clients.get(key)
        if cached is not None:
            return cached
        session = boto3.session.Session()
        session.events.register("before-send.*.*", self._guard)
        kwargs = dict(
            region_name=REGION,
            endpoint_url=self.endpoint,
            aws_access_key_id=akid,
            aws_secret_access_key=secret,
            config=Config(
                signature_version="v4",
                retries={"max_attempts": 2, "mode": "standard"},
                read_timeout=read_timeout or self._read_timeout,
                connect_timeout=self._connect_timeout,
            ),
        )
        if token:
            kwargs["aws_session_token"] = token
        client = session.client(service, **kwargs)
        self._clients[key] = client
        if akid == self.admin_akid and not token:
            _DEFAULT_CLIENTS[service] = client
        return client

    def select_admin_credential(self) -> dict:
        from .result import CallOutcome

        self.admin_akid = PROBE_AKID
        observations = []
        chosen = None
        for label, akid, secret in CANDIDATE_AKIDS:
            client = self.client("sts", akid=akid, secret=secret)
            caller = CallOutcome.capture("sts", "GetCallerIdentity",
                                        lambda c: c.get_caller_identity(), client)
            iam = CallOutcome.capture("iam", "ListUsers", lambda c: c.list_users(),
                                      self.client("iam", akid=akid, secret=secret))
            sts_probe = CallOutcome.capture("sts", "AssumeRole", lambda c: c.assume_role(
                RoleArn=f"arn:aws:iam::{self.account}:role/cloudsec-nonexistent-probe",
                RoleSessionName="probe"), client)
            record = {
                "credential_shape": label,
                "access_key_id": redact(akid),
                "get_caller_identity": caller.to_dict(),
                "iam_list_users": iam.to_dict(),
                "sts_assume_role_missing_role": sts_probe.to_dict(),
                "administrative_capability": bool(iam.ok),
            }
            observations.append(record)
            if chosen is None and iam.ok:
                chosen = (label, akid, secret)
        if chosen is None:
            raise EndpointUnavailable(
                "no candidate credential could list IAM users on this endpoint; "
                "cannot establish administrative capability")
        self.admin_credential = chosen[0]
        self.admin_akid = chosen[1]
        self.admin_secret = chosen[2]
        clear_clients()
        for service in ("sts", "iam", "s3", "secretsmanager", "kms", "logs",
                        "cloudtrail", "config", "lambda"):
            _DEFAULT_CLIENTS[service] = self.client(
                service, akid=self.admin_akid, secret=self.admin_secret)
        return {"selected": self.admin_credential, "candidates": observations}

    def health(self) -> dict:
        import json
        import urllib.error
        import urllib.request

        last = None
        for path in ("/_floci/health", "/_localstack/health"):
            url = f"{self.endpoint}{path}"
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    body = response.read().decode("utf-8", "replace")
                data = json.loads(body)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                last = exc
                continue
            self.health_raw = data
            if isinstance(data, dict):
                self.floci_version = data.get("version")
                self.floci_edition = data.get("edition")
                services = data.get("services")
                self.floci_services = services if isinstance(services, dict) else None
                iam = (self.floci_services or {}).get("iam")
                if isinstance(iam, dict):
                    self.enforcement_hint = iam.get(
                        "enforcement-enabled", iam.get("enforcement_enabled")
                    )
            return data
        raise EndpointUnavailable(f"no Floci health endpoint at {self.endpoint}: {last}")

    def describe_identity(self) -> None:
        identity = self.client("sts").get_caller_identity()
        self.account = identity.get("Account")
        self._arn = identity.get("Arn")
        self._user_id = identity.get("UserId")
        if not self.account:
            raise EndpointUnavailable(
                "emulator returned no Account from GetCallerIdentity; "
                "cannot confirm this is the intended local environment"
            )

    def connect(self) -> dict:
        self.health()
        self.describe_identity()
        self.credential_selection = self.select_admin_credential()
        return self.identity_block()

    def identity_block(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "account": redact(self.account),
            "arn": redact(self._arn),
            "user_id": redact(self._user_id),
            "floci": {"version": self.floci_version, "edition": self.floci_edition},
        }

    def region(self) -> str:
        return REGION

    def probe_service(self, service: str, func, *args, **kwargs) -> dict:
        from .result import CallOutcome

        name = getattr(func, "__name__", service)
        try:
            client = self.client(service)
        except Exception as exc:  # noqa: BLE001
            return {
                "operation": name,
                "ok": False,
                "status": None,
                "exception": type(exc).__name__,
                "error_code": None,
                "request_id": None,
                "detail": redact(str(exc))[:300],
            }
        return CallOutcome.capture(service, name, func, client, *args, **kwargs).to_dict()

    def close(self) -> None:
        for client in self._clients.values():
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        self._clients.clear()


def clear_clients() -> None:
    _DEFAULT_CLIENTS.clear()


def wait_for_endpoint(endpoint: str, timeout: int = 120) -> None:
    assert_local_endpoint(endpoint)
    parts = urlsplit(_normalise(endpoint))
    host = parts.hostname or "localhost"
    port = parts.port or 80
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3):
                return
        except OSError:
            time.sleep(2)
    raise EndpointUnavailable(f"nothing accepting connections on {endpoint}")


def build_report(floci: Floci, services: dict, enforcement: dict,
                 important_gaps: list, probe_label: str | None = None,
                 started_at: str | None = None, finished_at: str | None = None) -> dict:
    from .result import normalize_enforcement

    return {
        "probe_version": 1,
        "probe_label": probe_label,
        "endpoint": floci.endpoint,
        "account": redact(floci.account),
        "identity": {"arn": redact(floci._arn), "user_id": redact(floci._user_id)},
        "probe_credential_akid": redact(PROBE_AKID),
        "floci": {
            "version": floci.floci_version,
            "edition": floci.floci_edition,
            "services": floci.floci_services,
            "iam_enforcement_hint": floci.enforcement_hint,
        },
        "started_at": started_at,
        "finished_at": finished_at,
        "services": services,
        "iam_enforcement": normalize_enforcement(enforcement),
        "important_gaps": important_gaps,
    }