__all__ = [
    "API_KEY_VAR",
    "MODEL_VAR",
    "KILO_KEY_VAR",
    "KILO_MODEL_VAR",
    "OPENROUTER_KEY_VAR",
    "OPENROUTER_MODEL_VAR",
    "ENV_LOCAL_NAME",
    "KNOWN_PROVIDERS",
    "ModelSettings",
    "config_path",
    "load_model_settings",
    "read_api_key_file",
    "load_api_key",
    "ensure_api_key_env",
    "read_key_file",
    "load_key",
    "ensure_key_env",
    "resolve_model_value",
    "resolve_provider",
]

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

API_KEY_VAR = "GEMINI_API_KEY"
MODEL_VAR = "CLOUDSEC_GEMINI_MODEL"
KILO_KEY_VAR = "KILO_API_KEY"
KILO_MODEL_VAR = "CLOUDSEC_KILO_MODEL"
OPENROUTER_KEY_VAR = "OPENROUTER_API_KEY"
OPENROUTER_MODEL_VAR = "CLOUDSEC_OPENROUTER_MODEL"
ENV_LOCAL_NAME = ".env.local"
KNOWN_PROVIDERS = ("google", "kilo", "openrouter")


@dataclass(frozen=True)
class ModelSettings:
    provider: str = "google"
    model: object = None
    temperature: object = None
    max_output_tokens: object = None
    adapter_version: object = None
    prompt_version: object = None


def config_path(root=None) -> Path:
    base = Path(root) if root is not None else Path.cwd()
    return base / "config" / "model.toml"


def load_model_settings(path=None) -> ModelSettings:
    target = Path(path) if path is not None else config_path()
    try:
        raw = target.read_bytes()
    except OSError:
        return ModelSettings()
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise ValueError("invalid model configuration")
    if not isinstance(parsed, dict):
        raise ValueError("invalid model configuration")
    table = parsed.get("model", {})
    if not isinstance(table, dict):
        raise ValueError("invalid model configuration")
    known = ("provider", "model", "temperature", "max_output_tokens",
             "adapter_version", "prompt_version")
    values = {}
    for name in known:
        value = table.get(name)
        if value is not None and not isinstance(value, (str, int, float)):
            raise ValueError("invalid model configuration")
        if isinstance(value, bool):
            raise ValueError("invalid model configuration")
        values[name] = value
    merged = {"provider": "google"}
    merged.update({name: value for name, value in values.items()
                   if value is not None})
    return ModelSettings(**merged)


def read_key_file(var, path=None):
    target = Path(path) if path is not None else Path.cwd() / ENV_LOCAL_NAME
    try:
        text = target.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, separator, value = stripped.partition("=")
        if not separator:
            continue
        if name.strip() != var:
            continue
        cleaned = value.strip()
        if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and \
                cleaned[0] in ("'", '"'):
            cleaned = cleaned[1:-1]
        return cleaned or None
    return None


def read_api_key_file(path=None):
    return read_key_file(API_KEY_VAR, path)


def load_key(var, env=None, path=None):
    mapping = env if env is not None else os.environ
    try:
        configured = mapping.get(var, "")
    except AttributeError:
        configured = ""
    if isinstance(configured, str) and configured.strip():
        return configured.strip()
    return read_key_file(var, path)


def load_api_key(env=None, path=None):
    return load_key(API_KEY_VAR, env, path)


def load_kilo_key(env=None, path=None):
    return load_key(KILO_KEY_VAR, env, path)


def ensure_key_env(var) -> bool:
    if isinstance(os.environ.get(var, ""), str) and \
            os.environ.get(var, "").strip():
        return True
    value = read_key_file(var)
    if value:
        os.environ[var] = value
        return True
    return False


def ensure_api_key_env() -> bool:
    return ensure_key_env(API_KEY_VAR)


def ensure_kilo_key_env() -> bool:
    return ensure_key_env(KILO_KEY_VAR)


def resolve_model_value(explicit=None, env_value="", settings=None,
                        fallback=""):
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    if isinstance(env_value, str) and env_value.strip():
        return env_value.strip()
    if settings is not None:
        configured = getattr(settings, "model", None)
        if isinstance(configured, str) and configured.strip():
            return configured.strip()
    return fallback


def resolve_provider(explicit=None, settings=None, fallback="google") -> str:
    if isinstance(explicit, str) and explicit.strip():
        name = explicit.strip().lower()
        if name not in KNOWN_PROVIDERS:
            raise ValueError("unknown provider")
        return name
    if settings is not None:
        configured = getattr(settings, "provider", None)
        if isinstance(configured, str) and configured.strip():
            name = configured.strip().lower()
            if name not in KNOWN_PROVIDERS:
                raise ValueError("unknown provider")
            return name
    return fallback
