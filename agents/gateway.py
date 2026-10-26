"""Tool gateway: the only way an LLM agent can touch anything.

An LLM agent never gets an S3 client, an HTTP client, or any other raw
actuator. It is handed a set of *tools*, and every tool runs through this
gateway, which asks Sentinel for a decision before the underlying operation
happens. There is no unguarded path: the model's only way to act is to call a
tool, and every tool is checked.

This mirrors the "agent's tools sit behind a policy proxy" design that Drata
(MCP proxy) and Noma describe. Here the proxy is in-process, so each agent
keeps its own IAM identity; what the agent's own code can still do with that
identity (bypass the gateway) is covered separately by CloudTrail detection.

A tool is registered with:
  * name, description, JSON parameter schema  -> shown to the model
  * action + resource(args)                   -> what Sentinel checks
  * impl(args)                                 -> the real operation

When the model calls a tool, the gateway returns a structured result. A denied
or held-then-rejected call is NOT an exception to the model: it comes back as a
normal tool result saying it was blocked and why, so the model can change course
instead of crashing. That is the graded-response idea (Island): block, but tell
the agent why.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from .common import RunLog

# Content-bearing actions whose payload Sentinel should inspect (DLP, output checks).
_CONTENT_ACTIONS = {"write", "output", "message", "network"}


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]                       # JSON Schema for the arguments
    action: str                                      # Sentinel action: read/write/list/...
    impl: Callable[..., Any]
    resource: Callable[[dict[str, Any]], str] | None = None
    record_count: Callable[[dict[str, Any]], int] | None = None
    content: Callable[[dict[str, Any], Any], str] | None = None   # payload to inspect
    reads_untrusted: bool = False                    # result is outside-world content

    def schema(self) -> dict[str, Any]:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description, "parameters": self.parameters}}


@dataclass
class GatewayResult:
    ok: bool
    tool: str
    content: str                   # text handed back to the model
    blocked: bool = False


@dataclass
class ToolGateway:
    """Holds an agent's tools and runs each call through Sentinel."""

    sentinel: Any
    run: RunLog
    max_untrusted_chars: int = 6000
    tools: dict[str, Tool] = field(default_factory=dict)

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def tool(self, name: str, description: str, parameters: dict[str, Any], action: str, **kw: Any):
        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.register(Tool(name=name, description=description, parameters=parameters,
                               action=action, impl=fn, **kw))
            return fn
        return deco

    def schemas(self) -> list[dict[str, Any]]:
        return [t.schema() for t in self.tools.values()]

    def execute(self, name: str, args: dict[str, Any]) -> GatewayResult:
        from sentinel_sdk import ActionDenied, ActionRejected, SentinelUnavailable
        tool = self.tools.get(name)
        if tool is None:
            return GatewayResult(False, name, f"No such tool '{name}'.")
        resource = tool.resource(args) if tool.resource else ""
        rc = tool.record_count(args) if tool.record_count else 1
        pre_content = ""
        if tool.action in _CONTENT_ACTIONS and tool.content is not None:
            # For writes, the content to inspect is in the args (the doc being written).
            try:
                pre_content = tool.content(args, None)
            except Exception:
                pre_content = ""

        try:
            decision = self.sentinel.check(tool.action, resource, tool=name, arguments=_safe(args),
                                           record_count=rc, content=pre_content)
        except ActionDenied as e:
            reason = str((e.decision or {}).get("reason") or e)
            self.run.step(tool.action, resource, "DENIED by Sentinel", reason)
            return GatewayResult(False, name, f"BLOCKED by the security monitor: {reason}. "
                                 "Do not retry this; it is outside your permitted actions.", blocked=True)
        except ActionRejected as e:
            reason = str((e.decision or {}).get("reason") or e)
            self.run.step(tool.action, resource, "REJECTED / not approved in time", reason)
            return GatewayResult(False, name, f"A human reviewer did not approve this action: {reason}.",
                                 blocked=True)
        except SentinelUnavailable as e:
            self.run.step(tool.action, resource, "NOT RUN: monitor unreachable (fail closed)", str(e))
            return GatewayResult(False, name, "The security monitor is unreachable, so this action was "
                                 "not allowed. Stop and report that you could not proceed safely.",
                                 blocked=True)

        verdict = "ALLOWED, flagged" if decision.get("mode") == "FLAG" else "ALLOWED"
        if decision.get("approval"):
            verdict = f"ALLOWED after approval by {decision['approval'].get('resolved_by')}"
        try:
            out = tool.impl(**args)
        except Exception as e:
            self.run.step(tool.action, resource, f"tool error: {type(e).__name__}", str(e)[:200])
            return GatewayResult(False, name, f"The tool failed: {type(e).__name__}: {e}")
        self.run.step(tool.action, resource, verdict)

        text = out if isinstance(out, str) else json.dumps(out, default=str)
        if tool.reads_untrusted:
            # Result is outside-world content: let Sentinel screen it for injected
            # instructions before it influences the model's next move.
            self.sentinel.observe_input(text, source=name)
            text = text[: self.max_untrusted_chars]
        return GatewayResult(True, name, text)


def _safe(args: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in (args or {}).items():
        out[str(k)] = v if isinstance(v, (str, int, float, bool, type(None))) else json.dumps(v, default=str)[:2000]
    return out
