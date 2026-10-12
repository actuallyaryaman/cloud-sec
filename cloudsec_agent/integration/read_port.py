__all__ = [
    "MAX_BODY_CHARS",
    "MAX_KEYS",
    "MAX_ACCESS_KEYS",
    "MAX_POLICIES",
    "MAX_USERS",
    "MAX_LOG_EVENTS",
    "MAX_STRING_CHARS",
    "ReadPortError",
    "BackendReadPort",
    "FakeReadPort",
    "FlociReadPort",
]

from abc import ABC, abstractmethod

MAX_BODY_CHARS = 8192
MAX_KEYS = 100
MAX_ACCESS_KEYS = 10
MAX_POLICIES = 20
MAX_USERS = 100
MAX_LOG_EVENTS = 50
MAX_STRING_CHARS = 2000


class ReadPortError(Exception):
    def __init__(self, code):
        if code not in ("access_denied", "not_found", "backend_error"):
            raise ValueError(f"unknown read failure code: {code!r}")
        self.code = code
        super().__init__(code)


def _text(value, limit=MAX_STRING_CHARS):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value[:limit]
    if hasattr(value, "isoformat"):
        try:
            return str(value.isoformat())[:limit]
        except Exception:
            return None
    return None


def _bounded_list(items, limit):
    kept = list(items or [])[:limit]
    return kept, len(list(items or [])) > limit


class BackendReadPort(ABC):
    @abstractmethod
    def list_objects(self, bucket, prefix=None):
        raise NotImplementedError

    @abstractmethod
    def get_object(self, bucket, key):
        raise NotImplementedError

    @abstractmethod
    def get_user(self, user_name):
        raise NotImplementedError

    @abstractmethod
    def list_access_keys(self, user_name):
        raise NotImplementedError

    @abstractmethod
    def get_user_policy(self, user_name, policy_name):
        raise NotImplementedError

    @abstractmethod
    def list_user_policies(self, user_name):
        raise NotImplementedError

    @abstractmethod
    def list_users(self):
        raise NotImplementedError

    @abstractmethod
    def describe_secret(self, secret_id):
        raise NotImplementedError

    @abstractmethod
    def get_log_events(self, log_group, log_stream):
        raise NotImplementedError

    @abstractmethod
    def get_function_configuration(self, function_name):
        raise NotImplementedError


class FakeReadPort(BackendReadPort):
    def __init__(self, handler):
        self._handler = handler
        self.calls = []

    def _run(self, method, **kwargs):
        self.calls.append((method, dict(kwargs)))
        outcome = self._handler(method, dict(kwargs))
        if isinstance(outcome, BaseException):
            raise outcome
        if not isinstance(outcome, dict):
            raise TypeError("handler must return a dict")
        return outcome

    def list_objects(self, bucket, prefix=None):
        return self._run("list_objects", bucket=bucket, prefix=prefix)

    def get_object(self, bucket, key):
        return self._run("get_object", bucket=bucket, key=key)

    def get_user(self, user_name):
        return self._run("get_user", user_name=user_name)

    def list_access_keys(self, user_name):
        return self._run("list_access_keys", user_name=user_name)

    def get_user_policy(self, user_name, policy_name):
        return self._run("get_user_policy", user_name=user_name,
                         policy_name=policy_name)

    def list_user_policies(self, user_name):
        return self._run("list_user_policies", user_name=user_name)

    def list_users(self):
        return self._run("list_users")

    def describe_secret(self, secret_id):
        return self._run("describe_secret", secret_id=secret_id)

    def get_log_events(self, log_group, log_stream):
        return self._run("get_log_events", log_group=log_group,
                         log_stream=log_stream)

    def get_function_configuration(self, function_name):
        return self._run("get_function_configuration",
                         function_name=function_name)


def _failure(error_code):
    code = str(error_code or "")
    if "Denied" in code or "Forbidden" in code or "Unauthorized" in code \
            or code in ("403", "401"):
        return ReadPortError("access_denied")
    if "NoSuch" in code or "NotFound" in code or "NotExist" in code \
            or code in ("404", "NoSuchKey", "NoSuchEntity",
                        "ResourceNotFoundException"):
        return ReadPortError("not_found")
    return ReadPortError("backend_error")


class FlociReadPort(BackendReadPort):
    def __init__(self, client_factory):
        self._clients = client_factory

    def _client(self, service):
        client = self._clients(service)
        if client is None:
            raise ReadPortError("backend_error")
        return client

    @staticmethod
    def _call(func):
        try:
            return func()
        except ReadPortError:
            raise
        except Exception as exc:
            response = getattr(exc, "response", None)
            code = None
            if isinstance(response, dict):
                error = response.get("Error") or {}
                code = error.get("Code")
            raise _failure(code)

    def list_objects(self, bucket, prefix=None):
        def run():
            client = self._client("s3")
            params = {"Bucket": bucket, "MaxKeys": MAX_KEYS + 1}
            if prefix:
                params["Prefix"] = prefix
            raw = client.list_objects_v2(**params)
            names = [item.get("Key", "")[:MAX_STRING_CHARS]
                     for item in raw.get("Contents", [])
                     if isinstance(item.get("Key"), str)]
            return {"bucket": bucket[:MAX_STRING_CHARS],
                    "keys": names[:MAX_KEYS],
                    "count": len(names),
                    "truncated": len(names) > MAX_KEYS}
        return self._call(run)

    def get_object(self, bucket, key):
        def run():
            client = self._client("s3")
            raw = client.get_object(Bucket=bucket, Key=key)
            body = raw.get("Body")
            if body is None:
                raise ReadPortError("backend_error")
            try:
                payload = body.read(MAX_BODY_CHARS + 1)
            finally:
                try:
                    body.close()
                except Exception:
                    pass
            truncated = len(payload) > MAX_BODY_CHARS
            text = payload[:MAX_BODY_CHARS].decode("utf-8", "replace")
            return {"bucket": bucket[:MAX_STRING_CHARS],
                    "key": key[:MAX_STRING_CHARS],
                    "body": text,
                    "size": len(payload),
                    "truncated": truncated}
        return self._call(run)

    def get_user(self, user_name):
        def run():
            raw = self._client("iam").get_user(UserName=user_name)
            user = raw.get("User") or {}
            return {"user_name": _text(user.get("UserName")),
                    "user_id": _text(user.get("UserId")),
                    "arn": _text(user.get("Arn")),
                    "create_date": _text(user.get("CreateDate")),
                    "truncated": False}
        return self._call(run)

    def list_access_keys(self, user_name):
        def run():
            raw = self._client("iam").list_access_keys(UserName=user_name)
            rows = []
            for item in raw.get("AccessKeyMetadata", []):
                rows.append({
                    "access_key_id": _text(item.get("AccessKeyId")),
                    "status": _text(item.get("Status")),
                    "create_date": _text(item.get("CreateDate"))})
            return {"user_name": user_name[:MAX_STRING_CHARS],
                    "access_keys": rows[:MAX_ACCESS_KEYS],
                    "count": len(rows),
                    "truncated": len(rows) > MAX_ACCESS_KEYS}
        return self._call(run)

    def get_user_policy(self, user_name, policy_name):
        def run():
            raw = self._client("iam").get_user_policy(
                UserName=user_name, PolicyName=policy_name)
            document = raw.get("PolicyDocument")
            if isinstance(document, dict):
                import json
                document = json.dumps(document, sort_keys=True,
                                      ensure_ascii=False, allow_nan=False,
                                      default=str)
            return {"user_name": user_name[:MAX_STRING_CHARS],
                    "policy_name": policy_name[:MAX_STRING_CHARS],
                    "policy_document": _text(document),
                    "truncated": isinstance(document, str)
                    and len(document) > MAX_STRING_CHARS}
        return self._call(run)

    def list_user_policies(self, user_name):
        def run():
            raw = self._client("iam").list_user_policies(UserName=user_name)
            names = [name[:MAX_STRING_CHARS]
                     for name in raw.get("PolicyNames", [])
                     if isinstance(name, str)]
            return {"user_name": user_name[:MAX_STRING_CHARS],
                    "policy_names": names[:MAX_POLICIES],
                    "count": len(names),
                    "truncated": len(names) > MAX_POLICIES}
        return self._call(run)

    def list_users(self):
        def run():
            raw = self._client("iam").list_users()
            rows = []
            for item in raw.get("Users", []):
                if not isinstance(item, dict):
                    continue
                rows.append({
                    "user_name": _text(item.get("UserName")),
                    "arn": _text(item.get("Arn")),
                    "create_date": _text(item.get("CreateDate"))})
            return {"users": rows[:MAX_USERS],
                    "count": len(rows),
                    "truncated": len(rows) > MAX_USERS}
        return self._call(run)

    def describe_secret(self, secret_id):
        def run():
            raw = self._client("secretsmanager").describe_secret(
                SecretId=secret_id)
            return {"name": _text(raw.get("Name")),
                    "arn": _text(raw.get("ARN")),
                    "description": _text(raw.get("Description")),
                    "created_date": _text(raw.get("CreatedDate")),
                    "truncated": False}
        return self._call(run)

    def get_log_events(self, log_group, log_stream):
        def run():
            raw = self._client("logs").get_log_events(
                logGroupName=log_group, logStreamName=log_stream,
                limit=MAX_LOG_EVENTS + 1)
            kept, over = _bounded_list(
                [{"timestamp": _text(item.get("timestamp")),
                  "message": _text(item.get("message"))}
                 for item in raw.get("events", [])
                 if isinstance(item, dict)], MAX_LOG_EVENTS)
            return {"log_group": log_group[:MAX_STRING_CHARS],
                    "log_stream": log_stream[:MAX_STRING_CHARS],
                    "events": kept,
                    "count": len(kept),
                    "truncated": over}
        return self._call(run)

    def get_function_configuration(self, function_name):
        def run():
            raw = self._client("lambda").get_function_configuration(
                FunctionName=function_name)
            return {"function_name": _text(raw.get("FunctionName")),
                    "runtime": _text(raw.get("Runtime")),
                    "handler": _text(raw.get("Handler")),
                    "description": _text(raw.get("Description")),
                    "timeout": _text(raw.get("Timeout")),
                    "truncated": False}
        return self._call(run)
