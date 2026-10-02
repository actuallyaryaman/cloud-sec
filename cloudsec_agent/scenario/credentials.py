__all__ = ["IncidentRuntimeCredential"]

from dataclasses import dataclass, field

SENSITIVE_FIELDS = ("secret_access_key",)


@dataclass(frozen=True)
class IncidentRuntimeCredential:
    access_key_id: str
    secret_access_key: str = field(repr=False)

    def client(self, floci, service: str, read_timeout: int | None = None):
        return floci.client(service, akid=self.access_key_id,
                            secret=self.secret_access_key,
                            read_timeout=read_timeout)

    def safe_summary(self) -> dict:
        return {"access_key_id": self.access_key_id,
                "secret_access_key": "[not-exposed]"}

    def __repr__(self) -> str:
        return (f"IncidentRuntimeCredential(access_key_id="
                f"{self.access_key_id!r}, secret_access_key=[redacted])")

    __str__ = __repr__