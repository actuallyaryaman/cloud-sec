"""Interactive local model configuration setup (stdlib only)."""

import getpass
import os
import stat
import sys
import tomllib
from pathlib import Path

DEFAULT_MODEL = "gemini-3.8-flash"
CONFIG_RELATIVE = Path("config") / "model.toml"
ENV_LOCAL_NAME = ".env.local"
KEY_NAME = "GEMINI_API_KEY"

MODEL_FIELDS = ("provider", "model", "temperature", "max_output_tokens",
                "adapter_version", "prompt_version")


def _is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(prompt, default=""):
    try:
        answer = input(prompt)
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(2)
    return answer.strip() or default


def _ask_yes_no(prompt) -> bool:
    return _ask(prompt).lower() in ("y", "yes")


def _read_settings(path):
    try:
        with open(path, "rb") as handle:
            parsed = tomllib.load(handle)
    except OSError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    table = parsed.get("model", {})
    if not isinstance(table, dict):
        return {}
    return {name: table[name] for name in MODEL_FIELDS if name in table}


def _write_settings(path, settings):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["[model]"]
    for name in MODEL_FIELDS:
        value = settings.get(name)
        if isinstance(value, str):
            lines.append(f'{name} = "{value}"')
        elif isinstance(value, (int, float)):
            lines.append(f"{name} = {value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _read_key_file(path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, separator, value = stripped.partition("=")
        if separator and name.strip() == KEY_NAME:
            cleaned = value.strip()
            if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and \
                    cleaned[0] in ("'", '"'):
                cleaned = cleaned[1:-1]
            return cleaned or None
    return None


def _write_key_file(path, key):
    try:
        existing = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        existing = []
    kept = [line for line in existing
            if line.strip().partition("=")[0].strip() != KEY_NAME]
    payload = ("\n".join(kept + [f"{KEY_NAME}={key}"]) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def main() -> int:
    root = Path.cwd()
    config_path = root / CONFIG_RELATIVE
    env_path = root / ENV_LOCAL_NAME
    settings = _read_settings(config_path)
    if "model" not in settings:
        settings = dict(settings)
        settings.setdefault("model", DEFAULT_MODEL)
        _write_settings(config_path, settings)
    current = settings.get("model", DEFAULT_MODEL)
    print(f"Configured model: {current}")
    model = current
    if _is_tty() and _ask("Change model? [y/N]: ").lower() in ("y", "yes"):
        model = _ask(f"Gemini model [{current}]: ", default=current)
    if model != settings.get("model"):
        settings = dict(settings)
        settings["model"] = model
        _write_settings(config_path, settings)
        print(f"Model updated: {model}")
    if isinstance(os.environ.get(KEY_NAME, ""), str) and \
            os.environ.get(KEY_NAME, "").strip():
        print("Gemini API key is provided by the environment.")
        return 0
    existing = _read_key_file(env_path)
    if existing:
        print("Gemini API key is already configured.")
        if not _is_tty():
            return 0
        replace = _ask("Replace it? [y/N]: ").lower() in ("y", "yes")
        if not replace:
            return 0
    elif not _is_tty():
        print("Gemini API key is missing and input is not interactive.",
              file=sys.stderr)
        return 2
    key = getpass.getpass("Gemini API key: ")
    if not isinstance(key, str) or not key.strip():
        print("Empty key is not stored.", file=sys.stderr)
        return 2
    _write_key_file(env_path, key.strip())
    print(f"Stored {KEY_NAME} in {ENV_LOCAL_NAME}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
