import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import probes
from .floci_client import (EndpointUnavailable, Floci, UnsafeEndpointError,
                           build_report, clear_clients, wait_for_endpoint)
from .redaction import clear_secrets, redact
from .result import AuthorizationMatrix, merge_gaps, normalize_enforcement

ARTIFACT_DIR = "artifacts"
TARGETS = [
    ("http://localhost:4566", "stock"),
    ("http://localhost:4567", "iam-enforced"),
]
SIGNAL_TO_FIELD = {
    "identity_allow": "identity_allow_observed",
    "implicit_deny": "implicit_deny_observed",
    "explicit_deny": "explicit_deny_observed",
    "resource_scoping_allow": "resource_scoping_observed",
    "resource_scoping_deny": "resource_scoping_observed",
    "sts_trust_enforcement": "sts_trust_enforcement_observed",
    "sts_role_restrictions": "sts_role_restrictions_observed",
    "sts_role_scoping": "sts_role_restrictions_observed",
}
SERVICE_ORDER = ("iam", "sts", "s3", "secretsmanager", "kms", "cloudwatch_logs",
                 "cloudtrail", "config", "lambda", "credentials")


def _now():
    return datetime.now(timezone.utc).isoformat()


def run_target(endpoint, label, verbose=True):
    clear_secrets()
    clear_clients()
    floci = Floci(endpoint)
    matrix = AuthorizationMatrix()
    services = {}
    important_gaps = []
    started = _now()

    identity = floci.connect()
    if verbose:
        print(f"endpoint          : {identity['endpoint']}")
        print(f"floci             : version={identity['floci']['version']} "
              f"edition={identity['floci']['edition']}")
        print(f"account           : {identity['account']}")
        print(f"caller arn        : {identity['arn']}")
        print(f"probe label       : {label}")
        print(f"admin credential  : {floci.admin_credential}")
        print(f"iam hint (health) : {floci.enforcement_hint}")
        print("-" * 78)

    suffix = endpoint.rsplit(":", 1)[-1]

    trail_state = probes.setup_cloudtrail(floci, suffix)
    if verbose and not trail_state.get("started"):
        print("cloudtrail        : trail did not start; trail findings will be partial")

    services["iam"] = probes.probe_iam(floci, suffix)
    services["sts"] = probes.probe_sts(floci, matrix, suffix)
    services["credentials"] = probes.probe_unknown_credentials(floci, suffix)
    services["credentials"]["credential_selection"] = floci.credential_selection
    services["s3"] = probes.probe_s3(floci, matrix, suffix)
    services["secretsmanager"] = probes.probe_secrets_manager(floci, matrix, suffix)
    services["kms"] = probes.probe_kms(floci, matrix, suffix)
    services["cloudwatch_logs"] = probes.probe_cloudwatch_logs(floci, matrix, suffix)
    marked = probes.perform_marked_actions(floci, trail_state, suffix)
    services["cloudtrail"] = probes.finalize_cloudtrail(floci, trail_state, suffix, marked)
    services["config"] = probes.probe_config(floci, matrix, suffix)
    services["lambda"] = probes.probe_lambda(floci, matrix, suffix)

    aggregation = matrix.aggregate()
    enforcement = {field: aggregation.get(signal)
                   for signal, field in SIGNAL_TO_FIELD.items()}
    unresolved = _unresolved_action_probe(floci, matrix, suffix)
    services["credentials"]["unresolved_action"] = {
        "observations": unresolved["observations"],
        "definition": unresolved.get("definition"),
    }
    enforcement["unresolved_action_behavior"] = unresolved["classification"]
    if unresolved["gaps"]:
        services["credentials"]["gaps"] = merge_gaps(
            services["credentials"].get("gaps"), unresolved["gaps"])

    for name, service in services.items():
        important_gaps.extend(f"[{name}] {gap}" for gap in service.get("gaps", []))

    report = build_report(floci, services, enforcement, merge_gaps(important_gaps),
                          probe_label=label, started_at=started, finished_at=_now())
    report["authorization_matrix"] = matrix.to_dict()
    report["enforcement_by_service"] = _by_service(services)
    floci.close()
    return report


def _by_service(services):
    out = {}
    for name, service in services.items():
        signals = service.get("enforcement_signals") or {}
        if len(signals) == 1 and isinstance(next(iter(signals.values())), dict):
            signals = next(iter(signals.values()))
        if signals:
            out[name] = signals
    return out


def _unresolved_action_probe(floci, matrix, suffix):
    observations = []
    implicit = [c for c in matrix.cases() if c["signals"] == ["implicit_deny"]]
    enforcement_off = any(c["policy_confirmed"] is True and c["classification"] is False
                          for c in implicit)
    for case in matrix.cases():
        if case["expected_aws_outcome"] != "deny" or case["policy_confirmed"] is not True:
            continue
        if any("policy_deny" in signal for signal in case["signals"]):
            continue
        observations.append({
            "service": case["service"],
            "operation": case["operation"],
            "error_code": case["error_code"],
            "honored": case["classification"],
        })
    if enforcement_off:
        return {"observations": observations, "classification": None,
                "definition": "an action whose verified explicit Deny was not honoured is "
                              "treated as evidence that the IAM resolver did not map it",
                "gaps": ["a verified implicit deny was not enforced on this endpoint, so "
                         "policy evaluation is inactive here and action resolution "
                         "cannot be assessed"]}
    if not observations:
        return {"observations": [], "classification": None,
                "definition": "an action whose verified explicit Deny was not honoured is "
                              "treated as evidence that the IAM resolver did not map it",
                "gaps": ["no Deny test completed with a verified policy, so the "
                         "unresolved-action behaviour could not be established"]}
    unresolvable = [o for o in observations if o["honored"] is False]
    classification = False if unresolvable else True
    gaps = []
    if unresolvable:
        gaps.append(
            "at least one action was allowed despite a verified explicit Deny, which is "
            "consistent with Floci's IAM resolver not mapping that action and treating "
            "unresolved actions as permitted: "
            + ", ".join(sorted({o["operation"] for o in unresolvable})))
    return {"observations": observations, "classification": classification,
            "definition": "an action whose verified explicit Deny was not honoured is "
                          "treated as evidence that the IAM resolver did not map it",
            "gaps": gaps}


def _artifact_path(label):
    suffix = "" if label == "stock" else f".{label}"
    return os.path.join(ARTIFACT_DIR, f"floci-capabilities{suffix}.json")


def _write(report, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = redact(report)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False, default=str)
        handle.write("\n")
    return path


def _crud_grade(service):
    if not service:
        return "n/a"
    if not service.get("available"):
        return "no"
    operations = service.get("operations") or {}
    if not operations:
        return "yes"
    ok = sum(1 for op in operations.values()
             if isinstance(op, dict) and op.get("ok"))
    return f"{ok}/{len(operations)}"


def _api_grade(service):
    if not service:
        return "no"
    if not service.get("available"):
        return "no"
    return "yes"


def _mark(value):
    if value is True:
        return "yes"
    if value is False:
        return "NO"
    return "?"


def _matrix_rows(reports):
    labels = list(reports.keys())
    rows = {}
    for label in labels:
        for case in reports[label].get("authorization_matrix", {}).get("cases", []):
            rows.setdefault((case["label"], case["operation"], case["principal_type"],
                             case["target_resource"]), {})[label] = case
    ordered = sorted(rows.items(), key=lambda item: (item[0][0][0], item[0][1]))
    return ordered


def print_comparison(reports, paths):
    labels = list(reports.keys())
    width = 34
    header = f"{'Service':<22}" + "".join(f"{lab:>{max(width, 16)}}" for lab in labels)
    print()
    print("=" * 78)
    print("SERVICE CAPABILITY COMPARISON")
    print("=" * 78)
    print(header)
    print("-" * 78)
    rows = [
        ("endpoint", lambda r: r["endpoint"]),
        ("floci version", lambda r: r["floci"]["version"]),
        ("floci edition", lambda r: r["floci"]["edition"]),
        ("account", lambda r: r["account"]),
    ]
    for name in SERVICE_ORDER:
        if name not in reports[labels[0]]["services"]:
            continue
        rows.append((f"{name}: basic API", lambda r, n=name: _api_grade(
            r["services"].get(n))))
        rows.append((f"{name}: CRUD ops ok", lambda r, n=name: _crud_grade(
            r["services"].get(n))))
    for name in SERVICE_ORDER:
        if name not in reports[labels[0]]["services"]:
            continue
        rows.append((f"{name}: IAM Allow", lambda r, n=name: _mark(
            _first_signal(r, n, "allow"))))
        rows.append((f"{name}: IAM Deny", lambda r, n=name: _mark(
            _first_signal(r, n, "deny"))))
    rows.append(("cloudtrail: events seen", lambda r: _ct_count(r)))
    for label, row in rows:
        print(f"{label:<22}" + "".join(
            f"{str(row(reports[l]))[:max(width, 16)]:>{max(width, 16)}}" for l in labels))
    print()
    print("=" * 78)
    print("IAM ENFORCEMENT SUMMARY")
    print("=" * 78)
    print(f"{'finding':<34}" + "".join(f"{lab:>{max(width, 16)}}" for lab in labels))
    print("-" * 78)
    for key in ("identity_allow_observed", "implicit_deny_observed",
                "explicit_deny_observed", "resource_scoping_observed",
                "sts_trust_enforcement_observed", "sts_role_restrictions_observed",
                "unresolved_action_behavior"):
        print(f"{key:<34}" + "".join(
            f"{_mark(reports[l]['iam_enforcement'][key]):>{max(width, 16)}}"
            for l in labels))
    print()
    print("=" * 78)
    print("AUTHORIZATION MATRIX A-F")
    print("=" * 78)
    print(f"{'case':<6}{'operation':<32}{'principal':<22}" +
          "".join(f"{lab:>{max(width, 16)}}" for lab in labels))
    print("-" * 78)
    for key, per_label in _matrix_rows(reports):
        label, operation, principal, resource = key
        for lab in labels:
            case = per_label.get(lab)
            if case is None:
                cell = "-"
            else:
                cell = (f"{_mark(case['classification'])} "
                        f"{(case['error_code'] or case['exception'] or 'allowed')[:18]}")
            print(f"{label:<6}{operation[:30]:<32}{principal[:20]:<22}" if lab == labels[0]
                  else "", end="")
            print(f"{cell:>{max(width, 16)}}", end="")
        print(f"   <- {resource[:70]}")
    print()
    print("-" * 78)
    print("ARTIFACTS")
    for path in paths:
        print(f"  {path}")
    print()
    for label in labels:
        gaps = reports[label].get("important_gaps") or []
        print(f"{label} important gaps ({len(gaps)}):")
        for gap in gaps:
            print(f"  - {gap}")
        print()


def _ct_count(report):
    operations = report["services"].get("cloudtrail", {}).get("operations", {})
    seen = operations.get("EventNamesObserved") or []
    return f"{len(seen)} names"


def _first_signal(report, service, kind):
    signals = report.get("enforcement_by_service", {}).get(service) or {}
    for key, value in signals.items():
        if kind in key:
            return value
    return None


def main(argv=None):
    global ARTIFACT_DIR

    parser = argparse.ArgumentParser(
        prog="python -m cloudsec_agent.floci_probe",
        description="Probe a local Floci AWS emulator for capability and IAM enforcement")
    parser.add_argument("--endpoint", action="append", dest="endpoints",
                        help="probe a single endpoint instead of the default pair")
    parser.add_argument("--label", default=None,
                        help="artifact label when probing a single endpoint")
    parser.add_argument("--artifacts", default=ARTIFACT_DIR,
                        help="directory for JSON artifacts")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if args.endpoints:
        targets = [(endpoint, args.label or f"custom-{index}")
                   for index, endpoint in enumerate(args.endpoints)]
    else:
        targets = list(TARGETS)

    ARTIFACT_DIR = args.artifacts

    reports = {}
    paths = []
    failures = []
    for endpoint, label in targets:
        if not args.quiet:
            print(f"\n=== probing {label} at {endpoint} ===")
        try:
            wait_for_endpoint(endpoint)
            floci = Floci(endpoint)
            floci.health()
            del floci
            report = run_target(endpoint, label, verbose=not args.quiet)
        except UnsafeEndpointError as exc:
            print(f"REFUSING ENDPOINT {endpoint}: {exc}", file=sys.stderr)
            return 2
        except EndpointUnavailable as exc:
            print(f"FLOCI UNREACHABLE at {endpoint}: {exc}", file=sys.stderr)
            failures.append(endpoint)
            continue
        path = _artifact_path(label)
        try:
            paths.append(_write(report, path))
        except OSError as exc:
            print(f"CANNOT WRITE ARTIFACT {path}: {exc}", file=sys.stderr)
            return 3
        reports[label] = report

    if reports:
        print_comparison(reports, paths)
        comparison = _artifacts_dir() / "floci-capabilities.comparison.json"
        try:
            paths.append(str(_write(_comparison(reports), comparison)))
        except OSError as exc:
            print(f"CANNOT WRITE COMPARISON ARTIFACT: {exc}", file=sys.stderr)
            return 3
        print(f"comparison written: {comparison}")

    if not reports:
        print("no endpoint produced a report", file=sys.stderr)
        return 4
    return 1 if failures else 0


def _artifacts_dir():
    class _Dir(str):
        def __truediv__(self, other):
            return _Dir(f"{self}/{other}")

    return _Dir(ARTIFACT_DIR)


def _comparison(reports):
    labels = list(reports.keys())
    fields = ["identity_allow_observed", "implicit_deny_observed",
              "explicit_deny_observed", "resource_scoping_observed",
              "sts_trust_enforcement_observed", "sts_role_restrictions_observed",
              "unresolved_action_behavior"]
    return {
        "probe_version": 1,
        "generated_at": _now(),
        "endpoints": {label: reports[label]["endpoint"] for label in labels},
        "floci": {label: {k: reports[label]["floci"].get(k)
                          for k in ("version", "edition", "iam_enforcement_hint")}
                  for label in labels},
        "iam_enforcement": {
            field: {label: reports[label]["iam_enforcement"][field] for label in labels}
            for field in fields
        },
        "differences": {
            field: {label: reports[label]["iam_enforcement"][field] for label in labels}
            for field in fields
            if len({reports[label]["iam_enforcement"][field] for label in labels}) > 1
        },
        "important_gaps": {label: reports[label]["important_gaps"] for label in labels},
    }


if __name__ == "__main__":
    sys.exit(main())