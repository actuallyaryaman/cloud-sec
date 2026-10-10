__all__ = [
    "READ_METHODS",
    "MAX_JUSTIFICATION_CHARS",
    "RealBackendToolPort",
    "canonical_read_resource",
]

from ..agent.tool_port import (BackendToolRequest, ToolPort, ToolResult)
from ..backend.audit import (AuditLog, AuditRecord, AuditStage, StageState,
                             audit_resource_ref)
from ..backend.broker import (TASK_SCOPED_CAPABILITY, evaluate, grant_for)
from ..backend.registry import Category, ToolNotFoundError, get_tool
from ..backend.request import (CanonicalAction, ToolRequest, action_digest,
                               canonicalize_secret_read, validate_arguments)
from ..scenario.seed import incident_user_arn
from .read_port import MAX_STRING_CHARS, BackendReadPort, ReadPortError

READ_METHODS = {
    "s3_get_object": "get_object",
    "s3_list_objects": "list_objects",
    "iam_get_user": "get_user",
    "iam_list_access_keys": "list_access_keys",
    "iam_get_user_policy": "get_user_policy",
    "iam_list_user_policies": "list_user_policies",
    "secrets_describe_secret": "describe_secret",
    "logs_get_log_events": "get_log_events",
    "lambda_get_function_configuration": "get_function_configuration",
}

MAX_JUSTIFICATION_CHARS = 200

_STRIPPED_KEY_PARTS = ("secretstring", "secretbinary", "secretaccesskey",
                       "secretvalue", "sessiontoken", "credential",
                       "password", "privatekey", "responsemetadata")


def canonical_read_resource(tool_id, arguments):
    if tool_id == "s3_get_object":
        return f"arn:aws:s3:::{arguments['Bucket']}/{arguments['Key']}"
    if tool_id == "s3_list_objects":
        return f"arn:aws:s3:::{arguments['Bucket']}"
    if tool_id in ("iam_get_user", "iam_list_access_keys",
                   "iam_get_user_policy", "iam_list_user_policies"):
        return incident_user_arn().rsplit("/", 1)[0] + \
            f"/{arguments['UserName']}"
    if tool_id == "secrets_describe_secret":
        return arguments["SecretId"]
    if tool_id == "logs_get_log_events":
        return (f"arn:aws:logs:us-east-1:000000000000:log-group:"
                f"{arguments['logGroupName']}:log-stream:"
                f"{arguments['logStreamName']}")
    if tool_id == "lambda_get_function_configuration":
        return (f"arn:aws:lambda:us-east-1:000000000000:function:"
                f"{arguments['FunctionName']}")
    raise KeyError(f"no read resource mapping for {tool_id!r}")


def _bound_value(value, depth):
    if isinstance(value, str):
        return value[:MAX_STRING_CHARS], len(value) > MAX_STRING_CHARS
    if isinstance(value, (int, float, bool)) or value is None:
        return value, False
    if depth <= 0:
        return None, True
    if isinstance(value, list):
        kept = []
        clipped = len(value) > 100
        for item in value[:100]:
            bound, hit = _bound_value(item, depth - 1)
            clipped = clipped or hit
            if bound is not None:
                kept.append(bound)
        return kept, clipped
    if isinstance(value, dict):
        kept = {}
        clipped = len(value) > 100
        for key, item in list(value.items())[:100]:
            if not isinstance(key, str):
                clipped = True
                continue
            parts = "".join(ch for ch in key.lower() if ch.isalnum())
            if any(part in parts for part in _STRIPPED_KEY_PARTS):
                continue
            bound, hit = _bound_value(item, depth - 1)
            clipped = clipped or hit
            if bound is not None:
                kept[key] = bound
        return kept, clipped
    return None, False


def _final_bounds(data):
    if not isinstance(data, dict):
        return {"truncated": True}
    truncated = bool(data.get("truncated"))
    clipped = {}
    for key, value in data.items():
        if not isinstance(key, str):
            truncated = True
            continue
        parts = "".join(ch for ch in key.lower() if ch.isalnum())
        if any(part in parts for part in _STRIPPED_KEY_PARTS):
            continue
        bound, hit = _bound_value(value, 2)
        truncated = truncated or hit
        if bound is not None:
            clipped[key] = bound
    clipped["truncated"] = truncated
    return clipped


class RealBackendToolPort(ToolPort):
    def __init__(self, read_port, *, run_scope, audit_log=None,
                 actor="agent", scenario_id="local"):
        if not isinstance(read_port, BackendReadPort):
            raise TypeError("read_port must be a BackendReadPort")
        if not isinstance(run_scope, str) or not run_scope:
            raise ValueError("run_scope must be a non-empty string")
        if not isinstance(actor, str) or not actor:
            raise ValueError("actor must be a non-empty string")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("scenario_id must be a non-empty string")
        self._reads = read_port
        self._run_scope = run_scope
        self._actor = actor
        self._scenario_id = scenario_id
        self._log = audit_log if audit_log is not None else AuditLog()
        self._audit_count = 0

    @property
    def audits(self):
        return self._log.records()

    def _record(self, request_id, tool_id, resource_ref, digest,
                requires_approval, stage, state, **codes):
        self._audit_count += 1
        self._log.append(AuditRecord(
            audit_id=f"audit-{self._audit_count:06d}",
            request_id=request_id, run_id=self._run_scope,
            scenario_id=self._scenario_id, tool_id=tool_id,
            resource_ref=resource_ref, action_digest=digest,
            requires_approval=requires_approval, stage=stage, state=state,
            **codes))

    def execute(self, invocation):
        if not isinstance(invocation, BackendToolRequest):
            raise TypeError("RealBackendToolPort expects BackendToolRequest")
        try:
            spec = get_tool(invocation.tool_id)
        except (ToolNotFoundError, KeyError, TypeError):
            return ToolResult(ok=False, classification="validation_error",
                              safe_error="unknown tool_id")
        if spec.category is Category.STATE_CHANGING:
            return ToolResult(ok=False,
                              classification="refused_state_changing",
                              safe_error="state-changing tools are refused")
        try:
            validated = validate_arguments(spec, dict(invocation.arguments))
        except (ValueError, TypeError):
            return ToolResult(ok=False, classification="validation_error",
                              safe_error="arguments failed validation")
        request = ToolRequest(
            request_id=invocation.request_id, tool_id=invocation.tool_id,
            arguments=validated, actor=self._actor,
            scenario_id=self._scenario_id,
            justification=invocation.justification[
                :MAX_JUSTIFICATION_CHARS])
        if spec.category is Category.SENSITIVE_READ:
            return self._sensitive(request, spec, validated)
        return self._read(request, spec, validated)

    def _action(self, spec, resource, validated):
        action = CanonicalAction(
            tool_id=spec.tool_id, service_action=spec.service_action,
            resource=resource, normalized_arguments=dict(validated))
        return action, action_digest(action)

    def _broker(self, action):
        grant = grant_for(TASK_SCOPED_CAPABILITY, self._run_scope)
        return grant, evaluate(grant, action, self._run_scope)

    def _sensitive(self, request, spec, validated):
        try:
            action = canonicalize_secret_read(validated)
        except (ValueError, TypeError):
            return ToolResult(ok=False, classification="validation_error",
                              safe_error="arguments failed validation")
        digest = action_digest(action)
        ref = audit_resource_ref(spec.tool_id, spec.category, action.resource)
        self._record(request.request_id, spec.tool_id, ref, digest,
                     spec.requires_approval, AuditStage.CANONICALIZED,
                     StageState(attempted=True))
        _, broker = self._broker(action)
        self._record(request.request_id, spec.tool_id, ref, digest,
                     spec.requires_approval, AuditStage.BROKER_DECIDED,
                     StageState(attempted=True,
                                broker_granted=broker.granted),
                     broker_reason_code=broker.reason_code.value)
        return ToolResult(ok=False, classification="broker_denied",
                          safe_error="broker denied the request")

    def _read(self, request, spec, validated):
        try:
            resource = canonical_read_resource(spec.tool_id, validated)
        except (KeyError, TypeError):
            return ToolResult(ok=False, classification="validation_error",
                              safe_error="arguments failed validation")
        action, digest = self._action(spec, resource, validated)
        ref = audit_resource_ref(spec.tool_id, spec.category, resource)
        self._record(request.request_id, spec.tool_id, ref, digest,
                     spec.requires_approval, AuditStage.CANONICALIZED,
                     StageState(attempted=True))
        _, broker = self._broker(action)
        self._record(request.request_id, spec.tool_id, ref, digest,
                     spec.requires_approval, AuditStage.BROKER_DECIDED,
                     StageState(attempted=True,
                                broker_granted=broker.granted),
                     broker_reason_code=broker.reason_code.value)
        if not broker.granted:
            return ToolResult(ok=False, classification="broker_denied",
                              safe_error="broker denied the request")
        method = getattr(self._reads, READ_METHODS[spec.tool_id])
        try:
            raw = method(**_read_kwargs(spec.tool_id, validated))
        except ReadPortError as failed:
            self._record(
                request.request_id, spec.tool_id, ref, digest,
                spec.requires_approval, AuditStage.VERIFICATION_DECIDED,
                StageState(attempted=True, broker_granted=True,
                           effective=False),
                verification_status="not_effective")
            return _read_failure(failed.code)
        except Exception:
            self._record(
                request.request_id, spec.tool_id, ref, digest,
                spec.requires_approval, AuditStage.VERIFICATION_DECIDED,
                StageState(attempted=True, broker_granted=True,
                           effective=False),
                verification_status="not_effective")
            return _read_failure("backend_error")
        self._record(request.request_id, spec.tool_id, ref, digest,
                     spec.requires_approval, AuditStage.VERIFICATION_DECIDED,
                     StageState(attempted=True, broker_granted=True,
                                effective=True),
                     verification_status="effective")
        return ToolResult(ok=True, classification="success",
                          data=_final_bounds(raw))


def _read_kwargs(tool_id, validated):
    if tool_id == "s3_get_object":
        return {"bucket": validated["Bucket"], "key": validated["Key"]}
    if tool_id == "s3_list_objects":
        params = {"bucket": validated["Bucket"]}
        if validated.get("Prefix"):
            params["prefix"] = validated["Prefix"]
        return params
    if tool_id in ("iam_get_user", "iam_list_access_keys",
                   "iam_list_user_policies"):
        return {"user_name": validated["UserName"]}
    if tool_id == "iam_get_user_policy":
        return {"user_name": validated["UserName"],
                "policy_name": validated["PolicyName"]}
    if tool_id == "secrets_describe_secret":
        return {"secret_id": validated["SecretId"]}
    if tool_id == "logs_get_log_events":
        return {"log_group": validated["logGroupName"],
                "log_stream": validated["logStreamName"]}
    return {"function_name": validated["FunctionName"]}


def _read_failure(code):
    if code == "access_denied":
        return ToolResult(ok=False, classification="access_denied",
                          safe_error="backend denied the read")
    if code == "not_found":
        return ToolResult(ok=False, classification="not_found",
                          safe_error="read target was not found")
    return ToolResult(ok=False, classification="backend_error",
                      safe_error="read failed")
