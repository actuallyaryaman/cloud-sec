import ast
import pathlib

import pytest

from cloudsec_agent.floci_client import (LOCAL_HOSTS, UnsafeEndpointError,
                                        assert_local_endpoint)

PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "cloudsec_agent"
APPROVED = "floci_client.py"
FORBIDDEN = ("boto3.client(", "boto3.resource(")


@pytest.mark.parametrize("endpoint", [
    "http://localhost:4566",
    "http://127.0.0.1:4567",
    "http://[::1]:4566",
    "http://host.docker.internal:4566",
    "http://floci:4566",
])
def test_local_endpoints_are_accepted(endpoint):
    assert assert_local_endpoint(endpoint) == endpoint


@pytest.mark.parametrize("endpoint", [
    "http://s3.amazonaws.com",
    "https://localhost:4566",
    "http://169.254.169.254",
    "http://example.com:4566",
    "http://192.168.1.10:4566",
    "http://localhost.evil.example:4566",
])
def test_non_local_endpoints_are_refused(endpoint):
    with pytest.raises(UnsafeEndpointError):
        assert_local_endpoint(endpoint)


def test_trailing_slash_is_normalised():
    assert assert_local_endpoint("http://localhost:4566/") == "http://localhost:4566"


def test_allowed_host_set_is_exactly_the_local_set():
    assert LOCAL_HOSTS == frozenset(
        {"localhost", "127.0.0.1", "::1", "host.docker.internal", "floci"})


def test_client_never_targets_a_non_local_host(monkeypatch):
    from cloudsec_agent.floci_client import Floci

    floci = Floci("http://localhost:4566")
    captured = {}

    class FakeRequest:
        url = "https://s3.us-east-1.amazonaws.com/bucket"

    with pytest.raises(UnsafeEndpointError):
        floci._guard(FakeRequest())
    captured["done"] = True
    assert captured["done"]

    class GoodRequest:
        url = "http://localhost:4566/bucket"

    floci._guard(GoodRequest())

    class WrongPort:
        url = "http://localhost:9999/bucket"

    with pytest.raises(UnsafeEndpointError):
        floci._guard(WrongPort())


def test_floci_rejects_unsafe_endpoint_before_building_a_client():
    from cloudsec_agent.floci_client import Floci

    with pytest.raises(UnsafeEndpointError):
        Floci("http://169.254.169.254")


def _attribute_calls(tree, attribute):
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == attribute:
                owner = node.func.value
                if isinstance(owner, ast.Name) and owner.id == "boto3":
                    found.append(node.lineno)
    return found


def test_no_direct_boto3_clients_outside_the_factory():
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.name == APPROVED:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for attribute in ("client", "resource"):
            for lineno in _attribute_calls(tree, attribute):
                offenders.append(f"{path.relative_to(PACKAGE)}:{lineno} boto3.{attribute}(")
    assert not offenders, "direct boto3 construction outside floci_client.py: " + ", ".join(
        offenders)


def test_no_boto3_module_level_default_session():
    for path in sorted(PACKAGE.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for forbidden in ("boto3.client(", "boto3.resource(", "boto3.Session(",
                          "boto3.setup_default_session"):
            assert forbidden not in text, f"{path.name} uses {forbidden}"


def test_source_files_contain_no_comments():
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert not ast.get_docstring(tree), f"{path.name} has a module docstring"
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assert not ast.get_docstring(node), f"{path.name}:{node.lineno} docstring"