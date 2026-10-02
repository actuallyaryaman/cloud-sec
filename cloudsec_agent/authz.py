__all__ = ["Identity", "assume_role", "normalize_document", "ensure_bucket"]

import json

from .redaction import register_secret
from .result import CallOutcome

TEST_KEY_NAME = "probe-secret-value"
ALREADY_EXISTS = {"BucketAlreadyOwnedByYou", "BucketAlreadyExists", "409"}


def ensure_bucket(s3, bucket) -> CallOutcome:
    head = CallOutcome.capture("s3", "HeadBucket", lambda c: c.head_bucket(Bucket=bucket), s3)
    if head.ok:
        return CallOutcome(operation="CreateBucket", service="s3", ok=True,
                           result_summary={"BucketName": bucket, "reused": True})
    created = CallOutcome.capture("s3", "CreateBucket", lambda c: c.create_bucket(
        Bucket=bucket), s3)
    if created.ok or created.error_code in ALREADY_EXISTS:
        return CallOutcome(operation="CreateBucket", service="s3", ok=True,
                           result_summary={"BucketName": bucket, "reused": False})
    return created


def normalize_document(document):
    if isinstance(document, str):
        try:
            return json.loads(document)
        except ValueError:
            return document
    return document


def statement(effect, actions, resources):
    return {
        "Effect": effect,
        "Action": actions if isinstance(actions, list) else [actions],
        "Resource": resources if isinstance(resources, list) else [resources],
    }


def policy(statements, version="2012-10-17"):
    return json.dumps({"Version": version, "Statement": statements})


class Identity:
    def __init__(self, floci, label, admin=None):
        self.floci = floci
        self.label = label
        self.user_name = f"cloudsec-{label}"
        self.arn = None
        self.access_key_id = None
        self.secret_access_key = None
        self.iam = admin or floci.client("iam")
        self.inline_policies: dict[str, bool] = {}
        self.managed_policies: list[str] = []

    def _call(self, operation, func):
        return CallOutcome.capture("iam", operation, func, self.iam)

    def create(self) -> bool:
        created = self._call("CreateUser", lambda c: c.create_user(
            UserName=self.user_name))
        if created.ok:
            self.arn = f"arn:aws:iam::{self.floci.account}:user/{self.user_name}"
        else:
            lookup = self._call("GetUser", lambda c: c.get_user(UserName=self.user_name))
            if lookup.ok:
                self.arn = lookup.raw.get("User", {}).get("Arn")
        if not self.arn:
            return False
        key = self._call("CreateAccessKey", lambda c: c.create_access_key(
            UserName=self.user_name))
        if not key.ok:
            return False
        self.access_key_id = key.raw["AccessKey"]["AccessKeyId"]
        self.secret_access_key = key.raw["AccessKey"]["SecretAccessKey"]
        register_secret(self.secret_access_key)
        return True

    def put_inline_policy(self, name, document) -> bool:
        outcome = self._call("PutUserPolicy", lambda c: c.put_user_policy(
            UserName=self.user_name, PolicyName=name, PolicyDocument=document))
        self.inline_policies[name] = bool(outcome.ok)
        if not outcome.ok:
            return False
        return self.verify_inline_policy(name, document)

    def verify_inline_policy(self, name, document=None) -> bool:
        stored = self._call("GetUserPolicy", lambda c: c.get_user_policy(
            UserName=self.user_name, PolicyName=name))
        if not stored.ok:
            self.inline_policies[name] = False
            return False
        found = normalize_document(stored.raw.get("PolicyDocument"))
        expected = normalize_document(document)
        if isinstance(found, dict) and isinstance(expected, dict):
            ok = found.get("Statement") == expected.get("Statement")
        else:
            ok = found is not None
        self.inline_policies[name] = bool(ok)
        return self.inline_policies[name]

    def attach_managed_policy(self, name, document) -> str | None:
        arn = f"arn:aws:iam::{self.floci.account}:policy/{name}"
        self._call("CreatePolicy", lambda c: c.create_policy(
            PolicyName=name, PolicyDocument=document))
        attached = self._call("AttachUserPolicy", lambda c: c.attach_user_policy(
            UserName=self.user_name, PolicyArn=arn))
        if not attached.ok:
            return None
        listed = self._call("ListAttachedUserPolicies",
                            lambda c: c.list_attached_user_policies(
                                UserName=self.user_name))
        if not listed.ok:
            return None
        if not any(entry["PolicyArn"] == arn
                   for entry in listed.raw.get("AttachedPolicies", [])):
            return None
        self.managed_policies.append(arn)
        return arn

    def has_policy(self) -> bool:
        listed = self._call("ListUserPolicies",
                            lambda c: c.list_user_policies(UserName=self.user_name))
        names = list(listed.raw.get("PolicyNames", [])) if listed.ok else []
        return bool(names) or bool(self.managed_policies)

    def client(self, service: str, read_timeout: int | None = None):
        return self.floci.client(
            service,
            akid=self.access_key_id,
            secret=self.secret_access_key,
            read_timeout=read_timeout,
        )

    def delete(self) -> None:
        for name in list(self.inline_policies):
            self._call("DeleteUserPolicy", lambda c: c.delete_user_policy(
                UserName=self.user_name, PolicyName=name))
        for arn in list(self.managed_policies):
            self._call("DetachUserPolicy", lambda c: c.detach_user_policy(
                UserName=self.user_name, PolicyArn=arn))
            self._call("DeletePolicy", lambda c: c.delete_policy(PolicyArn=arn))
        keys = self._call("ListAccessKeys",
                          lambda c: c.list_access_keys(UserName=self.user_name))
        if keys.ok:
            for meta in keys.raw.get("AccessKeyMetadata", []):
                self._call("DeleteAccessKey", lambda c: c.delete_access_key(
                    UserName=self.user_name, AccessKeyId=meta["AccessKeyId"]))
        self._call("DeleteUser", lambda c: c.delete_user(UserName=self.user_name))


def assume_role(floci, role_arn, session_name, duration_seconds=None,
                policy=None, caller=None):
    sts = caller or floci.client("sts")
    kwargs = dict(RoleArn=role_arn, RoleSessionName=session_name)
    if duration_seconds:
        kwargs["DurationSeconds"] = duration_seconds
    if policy:
        kwargs["Policy"] = policy
    outcome = CallOutcome.capture("sts", "AssumeRole", lambda c: c.assume_role(**kwargs),
                              sts)
    if not outcome.ok:
        return None, outcome
    payload = outcome.raw["Credentials"]
    register_secret(payload["SecretAccessKey"])
    register_secret(payload.get("SessionToken", ""))
    return {
        "access_key_id": payload["AccessKeyId"],
        "secret_access_key": payload["SecretAccessKey"],
        "session_token": payload.get("SessionToken"),
        "expiration": payload.get("Expiration").isoformat()
        if payload.get("Expiration") else None,
        "assumed_role_arn": outcome.raw.get("AssumedRoleUser", {}).get("Arn"),
        "packed_policy_size": outcome.raw.get("PackedPolicySize"),
    }, outcome
