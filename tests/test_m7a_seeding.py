"""M7A seeding/verification against in-memory fake Floci. No Docker."""

import json

import pytest

from cloudsec_agent.scenario.generator import (
    GENERATOR_VERSION, generate_scenario)
from cloudsec_agent.scenario.generator.seeding import (
    generated_investigator_policy, seed_generated)
from cloudsec_agent.scenario.generator.verifier import verify_generated


class FakeService:
    def __init__(self, state, name):
        self._state = state
        self._name = name
        self.calls = []

    def _record(self, operation, ok=True, payload=None):
        self.calls.append(operation)
        return dict(payload or {})


class FakeIam(FakeService):
    def create_user(self, UserName):
        users = self._state.setdefault("users", {})
        if UserName in users:
            raise RuntimeError("EntityAlreadyExists")
        users[UserName] = {"policies": {}, "keys": []}
        return {"User": {"UserName": UserName}}

    def get_user(self, UserName):
        if UserName not in self._state.get("users", {}):
            raise RuntimeError("NoSuchEntity")
        return {"User": {"UserName": UserName}}

    def put_user_policy(self, UserName, PolicyName, PolicyDocument):
        self._state["users"][UserName]["policies"][PolicyName] = \
            json.loads(PolicyDocument)
        return {}

    def get_user_policy(self, UserName, PolicyName):
        return {"PolicyDocument": self._state["users"][UserName][
            "policies"][PolicyName]}

    def create_access_key(self, UserName):
        index = len(self._state["users"][UserName]["keys"])
        key_id = f"AKIA-FAKE-{UserName[:4].upper()}-{index:04d}"
        self._state["users"][UserName]["keys"].append(
            {"AccessKeyId": key_id, "Status": "Active"})
        return {"AccessKey": {"AccessKeyId": key_id,
                              "SecretAccessKey": "fake-secret"}}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": list(
            self._state["users"][UserName]["keys"])}

    def update_access_key(self, UserName, AccessKeyId, Status):
        for item in self._state["users"][UserName]["keys"]:
            if item["AccessKeyId"] == AccessKeyId:
                item["Status"] = Status
        return {}

    def list_users(self):
        return {"Users": [{"UserName": name}
                          for name in self._state.get("users", {})]}

    def create_role(self, RoleName, AssumeRolePolicyDocument):
        self._state.setdefault("roles", {})[RoleName] = True
        return {"Role": {"RoleName": RoleName}}


class FakeS3(FakeService):
    def create_bucket(self, Bucket):
        self._state.setdefault("buckets", {})[Bucket] = {}
        return {"Location": Bucket}

    def list_objects_v2(self, Bucket):
        objects = self._state.get("buckets", {}).get(Bucket, {})
        return {"Contents": [{"Key": key} for key in objects],
                "KeyCount": len(objects)}

    def put_object(self, Bucket, Key, Body):
        self._state["buckets"][Bucket][Key] = Body
        return {"ETag": "fake-etag"}

    def get_object(self, Bucket, Key):
        return {"Body": self._state["buckets"][Bucket][Key]}


class FakeSecrets(FakeService):
    def create_secret(self, Name, SecretString):
        self._state.setdefault("secrets", {})[Name] = SecretString
        return {"ARN": f"arn:aws:secretsmanager:us-east-1:000000000000:"
                       f"secret:{Name}"}

    def describe_secret(self, SecretId):
        if SecretId not in self._state.get("secrets", {}):
            raise RuntimeError("ResourceNotFoundException")
        return {"ARN": f"arn:aws:secretsmanager:us-east-1:000000000000:"
                       f"secret:{SecretId}"}


class FakeLogs(FakeService):
    def create_log_group(self, logGroupName):
        self._state.setdefault("groups", {})[logGroupName] = {}
        return {}

    def describe_log_groups(self):
        return {"logGroups": [{"logGroupName": name}
                              for name in self._state.get("groups", {})]}

    def create_log_stream(self, logGroupName, logStreamName):
        self._state["groups"][logGroupName][logStreamName] = []
        return {}

    def describe_log_streams(self, logGroupName):
        return {"logStreams": [{"logStreamName": name} for name in
                               self._state.get("groups", {}).get(
                                   logGroupName, {})]}

    def put_log_events(self, logGroupName, logStreamName, logEvents):
        self._state["groups"][logGroupName][logStreamName].extend(
            logEvents)
        return {"nextSequenceToken": "fake"}

    def get_log_events(self, logGroupName, logStreamName):
        return {"events": list(self._state["groups"][logGroupName]
                               [logStreamName])}


class FakeLambda(FakeService):
    def create_function(self, FunctionName, **kwargs):
        self._state.setdefault("functions", {})[FunctionName] = dict(
            kwargs)
        return {"FunctionArn": f"arn:aws:lambda:us-east-1:000000000000:"
                               f"function:{FunctionName}"}

    def get_function_configuration(self, FunctionName):
        if FunctionName not in self._state.get("functions", {}):
            raise RuntimeError("ResourceNotFoundException")
        return {"FunctionArn": f"arn:aws:lambda:us-east-1:000000000000:"
                               f"function:{FunctionName}"}


class FakeFloci:
    endpoint = "http://localhost:4567"
    account = "000000000000"

    def __init__(self):
        self._state = {}
        self._services = {}

    def client(self, service):
        if service not in self._services:
            makers = {"iam": FakeIam, "s3": FakeS3,
                      "secretsmanager": FakeSecrets, "logs": FakeLogs,
                      "lambda": FakeLambda}
            self._services[service] = makers[service](self._state,
                                                      service)
        return self._services[service]

    def health(self):
        return True


def _seeded(family="credential_compromise", seed=1, difficulty="easy"):
    spec = generate_scenario(GENERATOR_VERSION, seed, family, difficulty)
    floci = FakeFloci()
    result = seed_generated(floci, spec)
    assert result.ok, result.fatal_errors
    return spec, floci, result


class TestSeeder:
    @pytest.mark.parametrize("family,seed", [
        ("credential_compromise", 1), ("recon_heavy", 11),
        ("data_access_anomaly", 21), ("benign", 31)])
    def test_g19_seeds_required_state(self, family, seed):
        spec, floci, result = _seeded(family, seed)
        assert spec.incident_user in floci._state["users"]
        assert spec.investigator_user in floci._state["users"]
        assert spec.bucket in floci._state["buckets"]
        assert spec.secret_name in floci._state["secrets"]
        assert spec.function_name in floci._state["functions"]
        assert result.created_key_ids[spec.incident_user]

    def test_g20_compromised_key_begins_active(self):
        spec, floci, _ = _seeded()
        keys = floci._state["users"][spec.incident_user]["keys"]
        assert len(keys) == 1 and keys[0]["Status"] == "Active"

    def test_g21_investigator_key_begins_active(self):
        spec, floci, _ = _seeded()
        keys = floci._state["users"][spec.investigator_user]["keys"]
        assert len(keys) == 1 and keys[0]["Status"] == "Active"

    def test_g22_benign_has_no_mutation_requirement(self):
        spec, floci, _ = _seeded("benign", 31)
        assert spec.ground_truth.action_tool_id is None
        report = verify_generated(floci, spec)
        assert report.ok

    def test_g18_benign_verifies_without_mutation(self):
        spec, floci, _ = _seeded("benign", 32)
        mutations = [call for service in floci._services.values()
                     for call in service.calls]
        assert "update_access_key" not in str(mutations).lower()
        assert verify_generated(floci, spec).ok


class TestGeneratedInvestigatorPolicy:
    def test_merged_doc_covers_generated_resources(self):
        import json
        doc = json.loads(generated_investigator_policy(
            "m7a-case-abc123", "m7a-secret-xyz"))
        blob = json.dumps(doc)
        assert "m7a-case-abc123" in blob
        assert "secret:m7a-secret-xyz" in blob
        assert "csi-incident-bucket" in blob

    def test_m1_base_document_unchanged(self):
        from cloudsec_agent.scenario.seed import (
            investigator_policy_document)
        assert "m7a-case" not in investigator_policy_document()

    def test_seeded_policy_readable(self):
        spec, floci, _ = _seeded()
        stored = floci.client("iam").get_user_policy(
            UserName=spec.investigator_user,
            PolicyName="m7a-investigator-readonly")
        blob = json.dumps(stored["PolicyDocument"])
        assert spec.bucket in blob
        assert spec.secret_name in blob


class TestVerifier:
    @pytest.mark.parametrize("family,seed", [
        ("credential_compromise", 1), ("recon_heavy", 12),
        ("data_access_anomaly", 23), ("benign", 33)])
    def test_g23_expected_state_verifies(self, family, seed):
        spec, floci, _ = _seeded(family, seed)
        report = verify_generated(floci, spec)
        assert report.ok, report.failures
        assert len(report.checks) == 8

    def test_g24_missing_object_fails(self):
        spec, floci, _ = _seeded()
        first = next(iter(floci._state["buckets"][spec.bucket]))
        del floci._state["buckets"][spec.bucket][first]
        report = verify_generated(floci, spec)
        assert not report.ok
        assert any(item.startswith("VG-04") for item in report.failures)

    def test_g24_missing_log_fails(self):
        spec, floci, _ = _seeded()
        floci._state["groups"][spec.log_group][spec.log_stream].pop()
        report = verify_generated(floci, spec)
        assert not report.ok
        assert any(item.startswith("VG-05") for item in report.failures)

    def test_g25_wrong_key_status_fails(self):
        spec, floci, _ = _seeded()
        floci._state["users"][spec.incident_user]["keys"][0][
            "Status"] = "Inactive"
        report = verify_generated(floci, spec)
        assert not report.ok
        assert any(item.startswith("VG-02") for item in report.failures)

    def test_g26_verifier_hides_ground_truth(self):
        spec, floci, _ = _seeded()
        report = verify_generated(floci, spec)
        blob = str(report.as_dict())
        assert spec.ground_truth.principal not in blob
        assert "update_access_key" not in blob
        assert "compromised" not in blob.lower()
