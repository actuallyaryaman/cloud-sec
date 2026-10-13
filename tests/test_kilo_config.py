"""M6G Kilo config, precedence, and setup tests. No network."""

import importlib.util
import os
import stat

import pytest

from cloudsec_agent.providers import create_model_port
from cloudsec_agent.providers.gemini import GeminiModelPort
from cloudsec_agent.providers.kilo import KiloModelPort
from cloudsec_agent.providers import model_config as cfg


@pytest.fixture(autouse=True)
def _no_live_clients(monkeypatch):
    try:
        import openai
    except ImportError:
        pass
    else:
        monkeypatch.setattr(openai, "OpenAI", lambda *a, **k: (_ for _ in (
        )).throw(AssertionError("no live clients")))


def _write_toml(root, body):
    config = root / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "model.toml").write_text(body, encoding="utf-8")


def _load_setup():
    path = os.path.join(os.getcwd(), "scripts", "setup_model_config.py")
    spec = importlib.util.spec_from_file_location("setup_model_config_kilo",
                                                  path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _setup_run(monkeypatch, tmp_path, inputs, key_entries, is_tty=True):
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
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("KILO_API_KEY", raising=False)
    code = setup.main()
    return setup, code, entered


class TestKiloKeyPrecedence:
    def test_process_env_wins(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env.local").write_text(
            "KILO_API_KEY=file-key\n", encoding="utf-8")
        assert cfg.load_kilo_key(env={"KILO_API_KEY": "env-key"}) == \
            "env-key"

    def test_file_fallback(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env.local").write_text(
            "KILO_API_KEY=file-key\n", encoding="utf-8")
        assert cfg.load_kilo_key(env={}) == "file-key"

    def test_missing_key_is_none(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        assert cfg.load_kilo_key(env={}) is None

    def test_gemini_key_path_unchanged(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env.local").write_text(
            "GEMINI_API_KEY=gemini-key\n", encoding="utf-8")
        assert cfg.load_api_key(env={}) == "gemini-key"
        assert cfg.load_kilo_key(env={}) is None


class TestProviderSelection:
    def test_toml_kilo_selects_kilo(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_toml(tmp_path, "[model]\nprovider = \"kilo\"\n")
        port = create_model_port(client=object())
        assert isinstance(port, KiloModelPort)

    def test_toml_google_selects_gemini(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_toml(tmp_path, "[model]\nprovider = \"google\"\n")
        port = create_model_port(client=object())
        assert isinstance(port, GeminiModelPort)

    def test_explicit_provider_wins(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_toml(tmp_path, "[model]\nprovider = \"google\"\n")
        port = create_model_port(provider="kilo", client=object())
        assert isinstance(port, KiloModelPort)

    def test_unknown_provider_rejected(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_toml(tmp_path, "[model]\nprovider = \"other\"\n")
        with pytest.raises(ValueError):
            create_model_port(client=object())

    def test_kilo_model_chain(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_toml(tmp_path, "[model]\nmodel = \"toml-model\"\n")
        monkeypatch.setenv("CLOUDSEC_KILO_MODEL", "env-model")
        assert KiloModelPort(client=object()).model_name == "env-model"
        monkeypatch.delenv("CLOUDSEC_KILO_MODEL")
        assert KiloModelPort(client=object()).model_name == "toml-model"


class TestKiloSetup:
    def test_kilo_key_hidden_input(self, monkeypatch, tmp_path, capsys):
        _write_toml(tmp_path, "[model]\nprovider = \"kilo\"\n")
        _, code, entered = _setup_run(
            monkeypatch, tmp_path, inputs=["n", "n"],
            key_entries=["CANARY-KILO-KEY"])
        assert code == 0
        assert len(entered) == 1
        assert "Kilo" in entered[0]
        stored = (tmp_path / ".env.local").read_text(encoding="utf-8")
        assert "KILO_API_KEY=CANARY-KILO-KEY" in stored
        assert "CANARY" not in capsys.readouterr().out

    def test_existing_kilo_key_preserved(self, monkeypatch, tmp_path,
                                         capsys):
        _write_toml(tmp_path, "[model]\nprovider = \"kilo\"\n")
        before = "KILO_API_KEY=CANARY-KILO-KEY\n"
        (tmp_path / ".env.local").write_text(before, encoding="utf-8")
        _, code, entered = _setup_run(
            monkeypatch, tmp_path, inputs=["n", "n", "n"], key_entries=[])
        assert code == 0
        assert entered == []
        assert (tmp_path / ".env.local").read_text(
            encoding="utf-8") == before
        assert "CANARY" not in capsys.readouterr().out

    def test_kilo_replace_works(self, monkeypatch, tmp_path):
        _write_toml(tmp_path, "[model]\nprovider = \"kilo\"\n")
        (tmp_path / ".env.local").write_text(
            "GEMINI_API_KEY=keep-me\nKILO_API_KEY=old\n", encoding="utf-8")
        _, code, _ = _setup_run(
            monkeypatch, tmp_path, inputs=["n", "n", "y"],
            key_entries=["CANARY-NEW-KEY"])
        assert code == 0
        stored = (tmp_path / ".env.local").read_text(encoding="utf-8")
        assert "GEMINI_API_KEY=keep-me" in stored
        assert "KILO_API_KEY=CANARY-NEW-KEY" in stored
        assert "KILO_API_KEY=old\n" not in stored

    def test_provider_change_flow(self, monkeypatch, tmp_path):
        _write_toml(tmp_path, "[model]\nprovider = \"google\"\n"
                              "model = \"gemini-3.8-flash\"\n")
        _, code, _ = _setup_run(
            monkeypatch, tmp_path, inputs=["y", "kilo", "n", "n"],
            key_entries=["CANARY-KILO-KEY"])
        assert code == 0
        text = (tmp_path / "config" / "model.toml").read_text(
            encoding="utf-8")
        assert 'provider = "kilo"' in text
        assert "nvidia/nemotron-3-ultra-550b-a55b:free" in text

    @pytest.mark.skipif(os.name != "posix",
                        reason="posix permission bits only")
    def test_kilo_key_file_mode(self, monkeypatch, tmp_path):
        _write_toml(tmp_path, "[model]\nprovider = \"kilo\"\n")
        _, code, _ = _setup_run(monkeypatch, tmp_path, inputs=["n", "n"],
                                key_entries=["CANARY-KILO-KEY"])
        assert code == 0
        mode = stat.S_IMODE(os.stat(tmp_path / ".env.local").st_mode)
        assert mode == 0o600

    def test_non_tty_missing_kilo_key_fails(self, monkeypatch, tmp_path,
                                            capsys):
        _write_toml(tmp_path, "[model]\nprovider = \"kilo\"\n")
        _, code, _ = _setup_run(monkeypatch, tmp_path, inputs=[],
                                key_entries=[], is_tty=False)
        assert code == 2
        assert not (tmp_path / ".env.local").exists()

    def test_no_api_key_option(self):
        text = open("scripts/setup_model_config.py",
                    encoding="utf-8").read()
        assert "--api-key" not in text
        assert "api-key" not in text
