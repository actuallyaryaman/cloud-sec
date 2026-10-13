__all__ = [
    "Category",
    "ToolSpec",
    "ToolNotFoundError",
    "CANONICALIZER_UNSET",
    "CONTAINMENT_CANONICALIZER",
    "SECRET_READ_CANONICALIZER",
    "RESOURCE_CANONICALIZER",
    "EXECUTION_IDENTITY_USER",
    "UPDATE_ACCESS_KEY",
    "GET_SECRET_VALUE",
    "get_tool",
    "all_tools",
    "tool_ids",
    "tools_for_category",
]

from dataclasses import dataclass
from enum import Enum

CANONICALIZER_UNSET = "none"
CONTAINMENT_CANONICALIZER = "containment_update_access_key"
SECRET_READ_CANONICALIZER = "secret_read"
RESOURCE_CANONICALIZER = "resource"

EXECUTION_IDENTITY_USER = "security-containment-executor"

UPDATE_ACCESS_KEY = "update_access_key"
GET_SECRET_VALUE = "get_secret_value"


class Category(str, Enum):
    READ_ONLY = "read_only"
    SENSITIVE_READ = "sensitive_read"
    STATE_CHANGING = "state_changing"


class ToolNotFoundError(KeyError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    service_action: str
    category: Category
    required_arguments: tuple = ()
    optional_arguments: tuple = ()
    requires_broker: bool = True
    requires_policy: bool = True
    requires_approval: bool = False
    canonicalizer_id: str = CANONICALIZER_UNSET
    description: str = ""

    @property
    def argument_names(self) -> tuple:
        return tuple(sorted(self.required_arguments + self.optional_arguments))


READ_ONLY_SPECS = (
    ToolSpec("s3_get_object", "s3:GetObject", Category.READ_ONLY,
             required_arguments=("Bucket", "Key"),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Reads one object body from a storage bucket. "
                         "Needs the bucket name and an object key."),
    ToolSpec("s3_list_objects", "s3:ListObjectsV2", Category.READ_ONLY,
             required_arguments=("Bucket",),
             optional_arguments=("Prefix",),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Lists object keys in a storage bucket. Needs "
                         "the bucket name; use returned keys for reads."),
    ToolSpec("iam_get_user", "iam:GetUser", Category.READ_ONLY,
             required_arguments=("UserName",),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Inspects a known IAM identity. Needs the exact IAM user name "
                         "established as such, not another observed actor, "
                         "session, or credential identifier."),
    ToolSpec("iam_list_access_keys", "iam:ListAccessKeys",
             Category.READ_ONLY,
             required_arguments=("UserName",),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Lists access keys of a known IAM identity. "
                         "Needs the exact IAM user name established as "
                         "such, not another observed actor, session, or "
                         "credential identifier."),
    ToolSpec("iam_get_user_policy", "iam:GetUserPolicy", Category.READ_ONLY,
             required_arguments=("UserName", "PolicyName"),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Reads one inline policy of a known IAM identity. "
                         "Needs the IAM user name established as such, "
                         "not another observed actor, session, or "
                         "credential identifier, and a policy name."),
    ToolSpec("iam_list_user_policies", "iam:ListUserPolicies",
             Category.READ_ONLY, required_arguments=("UserName",),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Lists inline policy names of a known IAM "
                         "identity. Needs the exact IAM user name "
                         "established as such, not another observed "
                         "actor, session, or credential identifier."),
    ToolSpec("iam_list_users", "iam:ListUsers", Category.READ_ONLY,
             required_arguments=(),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Enumerates IAM user identities visible to the "
                         "investigator. Use when the relevant user name "
                         "is not yet known."),
    ToolSpec("secrets_describe_secret", "secretsmanager:DescribeSecret",
             Category.READ_ONLY, required_arguments=("SecretId",),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Describes secret metadata without revealing the "
                         "value. Needs the secret identifier."),
    ToolSpec("logs_get_log_events", "logs:GetLogEvents", Category.READ_ONLY,
             required_arguments=("logGroupName", "logStreamName"),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Reads log events from a log stream. Needs the "
                         "log group and stream names."),
    ToolSpec("lambda_get_function_configuration",
             "lambda:GetFunctionConfiguration", Category.READ_ONLY,
             required_arguments=("FunctionName",),
             canonicalizer_id=RESOURCE_CANONICALIZER,
             description="Reads configuration of a serverless function. "
                         "Needs the function name."),
)
SENSITIVE_READ_SPECS = (
    ToolSpec(GET_SECRET_VALUE, "secretsmanager:GetSecretValue",
             Category.SENSITIVE_READ, required_arguments=("SecretId",),
             requires_approval=False,
             canonicalizer_id=SECRET_READ_CANONICALIZER,
             description="Retrieves a secret value. Sensitive read."),
)

STATE_CHANGING_SPECS = (
    ToolSpec(UPDATE_ACCESS_KEY, "iam:UpdateAccessKey",
             Category.STATE_CHANGING,
             required_arguments=("UserName", "AccessKeyId", "Status"),
             optional_arguments=(),
             requires_approval=True,
             canonicalizer_id=CONTAINMENT_CANONICALIZER,
             description="Changes access-key state. Containment path only."),
)

_TOOLS = {spec.tool_id: spec
          for spec in (READ_ONLY_SPECS + SENSITIVE_READ_SPECS
                       + STATE_CHANGING_SPECS)}


def get_tool(tool_id: str) -> ToolSpec:
    try:
        return _TOOLS[tool_id]
    except (KeyError, TypeError):
        raise ToolNotFoundError(f"unknown tool_id: {tool_id!r}") from None


def all_tools() -> tuple:
    return tuple(_TOOLS[tool_id] for tool_id in sorted(_TOOLS))


def tool_ids() -> tuple:
    return tuple(sorted(_TOOLS))


def tools_for_category(category: Category) -> tuple:
    return tuple(spec for spec in all_tools() if spec.category is category)