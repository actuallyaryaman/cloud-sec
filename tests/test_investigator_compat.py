"""Pure proofs for the investigator-read compatibility amendment.

The Floci-facing IAM Resource representation changed for exactly the
proven actions. Logical capabilities, broker grants, backend policy,
agent code, and result projection are all unchanged.
"""

import json

from cloudsec_agent.backend.broker import TASK_SCOPED_CAPABILITY
from cloudsec_agent.scenario import seed as s


def statements():
    return json.loads(s.investigator_policy_document())["Statement"]


def actions_of(effect=None):
    out = []
    for item in statements():
        if effect is None or item["Effect"] == effect:
            out.extend(item["Action"])
    return out


def resources_for(actions):
    wanted = set(actions)
    out = []
    for item in statements():
        if wanted & set(item["Action"]):
            out.extend(item["Resource"])
    return out


class TestActionAllowlistUnchanged:
    def test_exact_read_actions_present(self):
        actions = actions_of()
        for action in ("s3:GetObject", "s3:ListBucket", "s3:GetBucketTagging",
                       "logs:FilterLogEvents", "logs:GetLogEvents",
                       "lambda:GetFunctionConfiguration",
                       "secretsmanager:DescribeSecret",
                       "iam:GetUser", "iam:ListAccessKeys",
                       "iam:GetUserPolicy", "iam:ListUserPolicies"):
            assert action in actions, action

    def test_no_secret_or_mutation_actions(self):
        actions = actions_of()
        assert "secretsmanager:GetSecretValue" not in actions
        assert "iam:UpdateAccessKey" not in actions
        for prefix in ("iam:Create", "iam:Delete", "iam:Put",
                       "iam:Attach", "iam:Update", "s3:Put", "s3:Delete",
                       "s3:Create", "lambda:Create", "lambda:Update",
                       "lambda:Delete", "lambda:Invoke",
                       "secretsmanager:Put", "secretsmanager:Delete"):
            assert not any(item.startswith(prefix) for item in actions), \
                prefix

    def test_no_wildcard_action(self):
        assert "*" not in actions_of()


class TestCompatibilityScope:
    def test_iam_compat_constant_is_bare_wildcard(self):
        assert s.FLOCI_INVESTIGATOR_IAM_RESOURCE == "*"
        assert s.FLOCI_INVESTIGATOR_LOGS_RESOURCE == "*"

    def test_wildcard_only_on_proven_iam_actions(self):
        resources = resources_for(("iam:GetUser", "iam:ListAccessKeys",
                                   "iam:GetUserPolicy",
                                   "iam:ListUserPolicies"))
        assert resources == [s.FLOCI_INVESTIGATOR_IAM_RESOURCE]

    def test_wildcard_only_on_proven_logs_action(self):
        resources = resources_for(("logs:GetLogEvents",))
        assert resources == [s.FLOCI_INVESTIGATOR_LOGS_RESOURCE]

    def test_filter_logs_keeps_scoped_resource(self):
        resources = resources_for(("logs:FilterLogEvents",))
        assert s.FLOCI_INVESTIGATOR_LOGS_RESOURCE not in resources
        assert any("csi-audit-log" in item for item in resources)

    def test_s3_statements_keep_exact_resources(self):
        resources = resources_for(("s3:GetObject", "s3:ListBucket",
                                   "s3:GetBucketTagging"))
        assert "*" not in resources
        assert any("csi-evidence-bucket" in item for item in resources)
        assert any("csi-trail-sink" in item for item in resources)

    def test_secret_and_lambda_statements_keep_exact_resources(self):
        resources = resources_for(("secretsmanager:DescribeSecret",
                                   "lambda:GetFunctionConfiguration"))
        assert "*" not in resources

    def test_incident_policy_untouched(self):
        for statement in json.loads(
                s.incident_policy_document())["Statement"]:
            assert "*" not in statement["Resource"]


class TestBackendBoundariesUnchanged:
    def test_broker_still_exact_resource_constrained(self):
        assert "update_access_key" not in TASK_SCOPED_CAPABILITY.tool_ids
        assert "get_secret_value" not in TASK_SCOPED_CAPABILITY.tool_ids
        assert len(TASK_SCOPED_CAPABILITY.tool_ids) == 9

    def test_agent_package_stays_backend_independent(self):
        import ast
        import pathlib
        agent = pathlib.Path(__file__).resolve().parents[1] / \
            "cloudsec_agent" / "agent"
        for path in sorted(agent.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            assert "cloudsec_agent.backend" not in imported, path.name
            assert "cloudsec_agent.scenario" not in imported, path.name

    def test_live_gate_file_unchanged_shape(self):
        import pathlib
        text = (pathlib.Path(__file__).resolve().parent /
                "test_agent_backend_live.py").read_text(encoding="utf-8")
        assert "InvestigationStatus.COMPLETE" in text
        assert "run-m5b-live-1" in text
