"""Deterministic fakes for Agent V1 pure tests. Test scripting only."""

from cloudsec_agent.agent.model_port import (ModelPort, ModelPortError,
                                             ModelTurn)
from cloudsec_agent.agent.tool_port import (BackendToolRequest, ToolPort,
                                            ToolResult)


class FakeModelPort(ModelPort):
    """Replays a scripted list of ModelTurn values or raised errors."""

    def __init__(self, script):
        self._script = list(script)
        self.contexts = []

    def complete(self, context):
        self.contexts.append(context)
        if not self._script:
            raise ModelPortError("script exhausted")
        item = self._script.pop(0)
        if isinstance(item, BaseException):
            raise item
        if not isinstance(item, ModelTurn):
            raise ModelPortError("script item is not a ModelTurn")
        return item


class FakeToolPort(ToolPort):
    """Records invocations; answers via a handler function."""

    def __init__(self, handler):
        self._handler = handler
        self.invocations = []

    def execute(self, invocation):
        if not isinstance(invocation, BackendToolRequest):
            raise TypeError("FakeToolPort expects BackendToolRequest")
        self.invocations.append(invocation)
        outcome = self._handler(invocation)
        if isinstance(outcome, BaseException):
            raise outcome
        if not isinstance(outcome, ToolResult):
            raise TypeError("handler must return a ToolResult")
        return outcome


def ok_result(data=None, classification="success"):
    return ToolResult(ok=True, classification=classification,
                      data=dict(data or {}))


def denied_result(reason="policy denied the request"):
    return ToolResult(ok=False, classification="policy_denied",
                      data={}, safe_error=reason)
