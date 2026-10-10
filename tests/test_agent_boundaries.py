"""Source and import boundary tests for Agent V1.

Production agent code must discover identifiers through tools: no
scenario literals, no manifest access, no direct cloud access.
"""

import ast
import os
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
AGENT_DIR = REPO / "cloudsec_agent" / "agent"

# Scenario-specific literals the agent must never hardcode. Tests use
# synthetic fixtures; production code must discover values via tools.
FORBIDDEN_LITERALS = [
    "incident-user",
    "security-agent-backend",
    "csi-",
    "csi-db-production-credential",
]

# Cloud and execution surfaces the agent must never touch directly.
FORBIDDEN_IMPORTS = [
    "boto3",
    "botocore",
    "floci_client",
    "LiveExecutionPort",
    "subprocess",
]

MANIFEST_MARKERS = [
    "scenario.manifest",
    "scenario/manifest",
    "manifest.json",
]


def _fresh_session_modules(extra_import):
    """Modules present after importing only extra_import, fresh process."""
    code = ("import sys; "
            f"import {extra_import}; "
            "print('\\n'.join(sorted(sys.modules)))")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True, cwd=str(REPO),
                          env=env, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return set(proc.stdout.splitlines())


def _agent_sources():
    return sorted(AGENT_DIR.glob("*.py"))


def _read_all():
    return {path.name: path.read_text(encoding="utf-8")
            for path in _agent_sources()}


def _imported_module_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


class TestNoScenarioHardcoding:
    def test_no_scenario_literals_in_production_source(self):
        sources = _read_all()
        assert sources, "agent package must contain source files"
        for name, text in sources.items():
            for literal in FORBIDDEN_LITERALS:
                assert literal not in text, \
                    f"{name} hardcodes scenario literal {literal!r}"

    def test_no_live_access_key_pattern_in_production_source(self):
        pattern = re.compile(r"AKIA[0-9A-Z]{8,}")
        for name, text in _read_all().items():
            assert not pattern.search(text), \
                f"{name} contains an access-key-like literal"

    def test_no_single_principal_or_secret_attempt_assumption(self):
        blob = "\n".join(_read_all().values()).lower()
        assert "exactly one" not in blob
        assert "must exist" not in blob
        assert "secret attempt" not in blob


class TestNoManifestAccess:
    def test_no_manifest_reference_in_source(self):
        for name, text in _read_all().items():
            for marker in MANIFEST_MARKERS:
                assert marker not in text, \
                    f"{name} references {marker!r}"

    def test_no_manifest_import_at_runtime(self):
        modules = _fresh_session_modules(
            "cloudsec_agent.agent.orchestrator")
        assert "cloudsec_agent.scenario.manifest" not in modules

    def test_no_manifest_import_in_ast(self):
        for path in _agent_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for name in _imported_module_names(tree):
                assert "manifest" not in name, \
                    f"{path.name} imports {name!r}"


class TestNoDirectCloudAccess:
    def test_no_cloud_surface_in_source(self):
        for name, text in _read_all().items():
            for marker in FORBIDDEN_IMPORTS:
                assert marker not in text, \
                    f"{name} references cloud surface {marker!r}"

    def test_no_cloud_import_in_ast(self):
        for path in _agent_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = _imported_module_names(tree)
            for name in imported:
                top = name.split(".")[0]
                assert top not in {"boto3", "botocore", "subprocess"}, \
                    f"{path.name} imports {name!r}"
            assert "cloudsec_agent.backend" not in imported, \
                f"{path.name} couples to the trusted backend"
            assert "cloudsec_agent.scenario" not in imported, \
                f"{path.name} couples to scenario ground truth"

    def test_no_cloud_module_pulled_in_at_runtime(self):
        modules = _fresh_session_modules(
            "cloudsec_agent.agent.orchestrator")
        for module in modules:
            top = module.split(".")[0]
            assert top not in {"boto3", "botocore"}, \
                f"agent import pulled in {module!r}"
            assert "floci_client" not in module, \
                f"agent import pulled in {module!r}"


class TestAuditSeparation:
    def test_agent_event_and_audit_record_stay_distinct(self):
        from cloudsec_agent.agent.events import AgentEvent
        from cloudsec_agent.backend.audit import AuditRecord
        assert AgentEvent is not AuditRecord
        assert AgentEvent.__module__.startswith("cloudsec_agent.agent")
        assert AuditRecord.__module__.startswith("cloudsec_agent.backend")
        assert not issubclass(AgentEvent, AuditRecord)
        assert not issubclass(AuditRecord, AgentEvent)

    def test_agent_payload_rejects_backend_forbidden_fields(self):
        from cloudsec_agent.agent.events import AgentEvent, AgentEventKind
        from cloudsec_agent.backend.audit import require_safe_field_names
        event = AgentEvent(event_id="e1", run_id="r1", sequence=0,
                           kind=AgentEventKind.TOOL_REQUESTED,
                           timestamp=0.0,
                           payload={"call_id": "c1", "request_id": "r",
                                    "tool_id": "iam_get_user"})
        require_safe_field_names(event.payload.keys())
