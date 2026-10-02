__all__ = ["redact", "register_secret", "clear_secrets"]

import re

_SECRETS: dict[str, str] = {}

_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|ANPA|AGPA)[0-9A-Z]{8,}\b"),
    re.compile(r"\b(?:aws_secret_access_key|aws_session_token|SecretAccessKey|SessionToken|secret_string|SecretString|SecretBinary|password|token)\b(\"?\s*[:=]\s*\"?)([^\s\"',}]+)"),
)


def register_secret(value: str) -> None:
    if value and len(value) >= 6:
        _SECRETS[value] = "[REDACTED]"


def clear_secrets() -> None:
    _SECRETS.clear()


def redact(value):
    if isinstance(value, str):
        out = value
        for secret, mask in _SECRETS.items():
            out = out.replace(secret, mask)
        out = _PATTERNS[0].sub("[REDACTED-AKID]", out)
        out = _PATTERNS[1].sub(lambda m: m.group(1) + "[REDACTED]", out)
        return out
    if isinstance(value, dict):
        return {redact(k): redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value