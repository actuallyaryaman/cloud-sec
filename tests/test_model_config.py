"""M6CFG local model configuration: pure tests, no provider calls."""

import importlib.util
import json
import os
import stat

import pytest

from cloudsec_agent.providers import gemini as adapter
from cloudsec_agent.providers import model_config as cfg
from cloudsec_agent.providers.gemini import GeminiModelPort

CANARY = "CANARY-KEY-VALUE-XYZ"


@pytest.fixture(autouse=True)
def _no_provider_clients(monkeypatch):
    try:
        from google import genai
    except ImportError:
        return

    def _blocked(*args, **kwargs):
        raise AssertionError("config tests must not create clients")

    monkeypatch.setattr(genai, "Client", _blocked)


def _write_toml(root, body):
    config = root / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "model.toml").write_text(body, encoding="utf-8")


def _toml_for(model="gemini-3.8-flash"):
    return ("[model]\nprovider = \"google\"\n"
            f"model = \"{model}\"\ntemperature = 0.0\n"
            "max_output_tokens = 2048\nadapter_version = \"m6a-v1\"\n"
            "prompt_version = \"m6a-sys-v1\"\n")


def _load_setup():
    path = os.path.join(os.getcwd(), "scripts", "setup_model_config.py")
    spec = importlib.util.spec_from_file_location("setup_model_config",
                                                  path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _setup_run(monkeypatch, tmp_path, inputs, key_entries,
               is_tty=True, env_key=None):
    setup = _load_setup()
    monkeypatch.chdir(tmp_path)
    answers = list(inputs)
    monkeypatch.setattr("builtins.input",
                        lambda prompt="": answers.pop(0))
    entered = []

    class FakeGetpass:
        @staticmethod
        def getpass(prompt=""):
            entered.append(prompt)
            return key_entries.pop(0)

    monkeypatch.setattr(setup, "getpass", FakeGetpass)
    monkeypatch.setattr(setup, "_is_tty", lambda: is_tty)
    if env_key is None:
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    else:
        monkeypatch.setenv("GEMINI_API_KEY", env_key)
    code = setup.main()
    return setup, code, entered


class TestSecretSeparation:
    def test_key_never_enters_model_toml(self, monkeypatch, tmp_path,
                                         capsys):
        _write_toml(tmp_path, _toml_for())
        _, code, _ = _setup_run(monkeypatch, tmp_path,
                                inputs=["n", "n", "n"], key_entries=[CANARY])
        assert code == 0
        text = (tmp_path / "config" / "model.toml").read_text(
            encoding="utf-8")
        assert "CANARY" not in text
        assert "GEMINI" not in text
        assert "CANARY" not in capsys.readouterr().out

    def test_key_never_enters_env_example(self):
        text = open(".env.example", encoding="utf-8").read()
        assert "GEMINI_API_KEY=" in text
        assert text.count("=") >= 1
        value = [line for line in text.splitlines()
                 if line.startswith("GEMINI_API_KEY=")][0]
        assert value == "GEMINI_API_KEY="

    def test_env_local_ignored_by_git(self):
        text = open(".gitignore", encoding="utf-8").read()
        assert ".env.local" in text.split()


class TestInteractiveSetup:
    def test_setup_uses_hidden_input(self, monkeypatch, tmp_path):
        _write_toml(tmp_path, _toml_for())
        _, code, entered = _setup_run(
            monkeypatch, tmp_path, inputs=["n", "n"], key_entries=[CANARY])
        assert code == 0
        assert len(entered) == 1
        stored = (tmp_path / ".env.local").read_text(encoding="utf-8")
        assert f"GEMINI_API_KEY={CANARY}" in stored

    def test_existing_key_never_displayed(self, monkeypatch, tmp_path,
                                          capsys):
        _write_toml(tmp_path, _toml_for())
        (tmp_path / ".env.local").write_text(
            f"GEMINI_API_KEY={CANARY}\n", encoding="utf-8")
        _, code, entered = _setup_run(monkeypatch, tmp_path,
                                      inputs=["n", "n", "n"], key_entries=[])
        assert code == 0
        assert entered == []
        assert "CANARY" not in capsys.readouterr().out
        assert "CANARY" not in capsys.readouterr().err

    def test_replacement_defaults_to_no(self, monkeypatch, tmp_path):
        _write_toml(tmp_path, _toml_for())
        before = f"GEMINI_API_KEY={CANARY}\n"
        (tmp_path / ".env.local").write_text(before, encoding="utf-8")
        _, code, _ = _setup_run(monkeypatch, tmp_path,
                                inputs=["n", "n", ""], key_entries=[])
        assert code == 0
        assert (tmp_path / ".env.local").read_text(
            encoding="utf-8") == before

    def test_model_prompt_defaults_and_enter_preserves(
            self, monkeypatch, tmp_path, capsys):
        _write_toml(tmp_path, _toml_for(model="gemini-x-model"))
        before = (tmp_path / "config" / "model.toml").read_text(
            encoding="utf-8")
        _, code, _ = _setup_run(monkeypatch, tmp_path,
                                inputs=["n", "y", ""], key_entries=[CANARY])
        assert code == 0
        out = capsys.readouterr().out
        assert "Configured model: gemini-x-model" in out
        after = (tmp_path / "config" / "model.toml").read_text(
            encoding="utf-8")
        assert after == before

    @pytest.mark.skipif(os.name != "posix",
                        reason="posix permission bits only")
    def test_env_local_mode_restrictive(self, monkeypatch, tmp_path):
        _write_toml(tmp_path, _toml_for())
        _, code, _ = _setup_run(monkeypatch, tmp_path,
                                inputs=["n", "n"], key_entries=[CANARY])
        assert code == 0
        mode = stat.S_IMODE(os.stat(tmp_path / ".env.local").st_mode)
        assert mode == 0o600

    def test_non_tty_missing_key_fails_safely(self, monkeypatch, tmp_path,
                                              capsys):
        _write_toml(tmp_path, _toml_for())
        _, code, _ = _setup_run(monkeypatch, tmp_path, inputs=[],
                                key_entries=[], is_tty=False)
        assert code == 2
        assert not (tmp_path / ".env.local").exists()
        assert "not interactive" in capsys.readouterr().err


class TestPrecedence:
    def test_env_key_overrides_file(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env.local").write_text(
            "GEMINI_API_KEY=file-key\n", encoding="utf-8")
        assert cfg.load_api_key(env={"GEMINI_API_KEY": "env-key"}) == \
            "env-key"

    def test_explicit_model_beats_env_and_config(self, monkeypatch,
                                                 tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_toml(tmp_path, _toml_for(model="gemini-toml-model"))
        monkeypatch.setenv("CLOUDSEC_GEMINI_MODEL", "gemini-env-model")
        assert cfg.resolve_model_value(
            explicit="gemini-explicit", env_value="gemini-env-model",
            settings=cfg.load_model_settings(),
            fallback="gemini-fallback") == "gemini-explicit"

    def test_env_model_beats_toml(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_toml(tmp_path, _toml_for(model="gemini-toml-model"))
        monkeypatch.setenv("CLOUDSEC_GEMINI_MODEL", "gemini-env-model")
        assert adapter.resolve_model_name() == "gemini-env-model"

    def test_toml_used_without_override(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_toml(tmp_path, _toml_for(model="gemini-toml-model"))
        monkeypatch.delenv("CLOUDSEC_GEMINI_MODEL", raising=False)
        assert adapter.resolve_model_name() == "gemini-toml-model"

    def test_no_shell_evaluation(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env.local").write_text(
            "GEMINI_API_KEY=$(evil) && rm -rf ~\n", encoding="utf-8")
        assert cfg.load_api_key(env={}) == "$(evil) && rm -rf ~"

    def test_no_key_in_exceptions(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("GEMINI_API_KEY", CANARY)
        (tmp_path / "config").mkdir(exist_ok=True)
        (tmp_path / "config" / "model.toml").write_bytes(b"[[[")
        try:
            cfg.load_model_settings()
        except ValueError as exc:
            assert str(exc) == "invalid model configuration"
            assert "CANARY" not in str(exc)
        else:
            raise AssertionError("malformed TOML must raise")


class TestAdapterIntegration:
    def test_temperature_and_tokens_from_toml(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        body = ("[model]\nmodel = \"gemini-toml-model\"\n"
                "temperature = 0.5\nmax_output_tokens = 512\n")
        _write_toml(tmp_path, body)
        monkeypatch.delenv("CLOUDSEC_GEMINI_MODEL", raising=False)
        port = GeminiModelPort(client=object())
        assert port.model_name == "gemini-toml-model"
        assert port.temperature == 0.5
        assert port._max_output_tokens == 512

    def test_explicit_sampling_beats_toml(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        body = ("[model]\ntemperature = 0.5\nmax_output_tokens = 512\n")
        _write_toml(tmp_path, body)
        port = GeminiModelPort(client=object(), temperature=0.0,
                               max_output_tokens=128)
        assert port.temperature == 0.0
        assert port._max_output_tokens == 128

    def test_missing_key_is_auth_error(self, monkeypatch, tmp_path):
        from cloudsec_agent.agent.model_port import ModelContext
        from cloudsec_agent.providers.gemini import GeminiProviderError
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        port = GeminiModelPort()
        with pytest.raises(GeminiProviderError) as excinfo:
            port.complete(ModelContext(run_id="r", turn_number=1,
                                       observations=()))
        assert excinfo.value.code == "auth_error"
        assert "CANARY" not in str(excinfo.value)

    def test_file_key_reaches_sdk_construction(self, monkeypatch, tmp_path):
        import json
        from types import SimpleNamespace
        from cloudsec_agent.agent.model_port import ModelContext
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env.local").write_text(
            "GEMINI_API_KEY=file-key-123\n", encoding="utf-8")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("CLOUDSEC_GEMINI_MODEL", raising=False)
        seen = {}
        payload = {"compromised_principal": "u",
                   "compromised_access_key_id": "k", "confidence": 0.5,
                   "findings": [], "evidence_refs": [],
                   "recommended_action": None,
                   "rationale_summary": "r"}

        class FakeModels:
            def generate_content(self, **kwargs):
                seen["key"] = os.environ.get("GEMINI_API_KEY")
                part = SimpleNamespace(text="```json\n" +
                                            json.dumps(payload) + "\n```",
                                       function_call=None)
                content = SimpleNamespace(parts=[part])
                return SimpleNamespace(candidates=[SimpleNamespace(
                    content=content)], usage_metadata=None)

        class FakeClient:
            def __init__(self, *args, **kwargs):
                seen["constructed"] = True
                self.models = FakeModels()

        try:
            from google import genai
        except ImportError:
            pytest.skip("google SDK not installed")
        monkeypatch.setattr(genai, "Client", FakeClient)
        port = GeminiModelPort()
        try:
            port.complete(ModelContext(run_id="r", turn_number=1,
                                       observations=()))
        except Exception:
            pass
        assert seen.get("constructed") is True
        assert seen.get("key") == "file-key-123"
