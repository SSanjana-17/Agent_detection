"""Framework-free adapter for hand-written tool loops.

Works with the Anthropic Messages API, OpenAI function calling, Bedrock
Converse tool use, CrewAI custom tools, or any loop where *your* code
executes the tool the model chose:

    toolbox = GuardedToolbox(sentinel)

    @toolbox.tool("read", resource=lambda a: f"s3://example-bank-lending/{a['application_id']}/file.json")
    def get_application(application_id: str) -> dict: ...

    @toolbox.tool("network", untrusted_output=True)
    def fetch_url(url: str) -> str: ...

    # inside the loop, for each tool_use block the model returned:
    result = toolbox.execute(block.name, block.input)   # never raises on denial
    # -> {"ok": False, "error": "..."} goes back to the model as the tool result
"""
from __future__ import annotations

from typing import Any, Callable

from ..client import ActionDenied, ActionRejected, Sentinel, SentinelUnavailable, _safe_str
from ..resources import resource_from_args


class GuardedToolbox:
    def __init__(self, sentinel: Sentinel) -> None:
        self.sentinel = sentinel
        self._tools: dict[str, dict[str, Any]] = {}

    def tool(self, action: str | None = None, *, name: str | None = None,
             resource: Callable[[dict[str, Any]], str] | None = None,
             untrusted_output: bool = False) -> Callable[[Callable], Callable]:
        def deco(fn: Callable) -> Callable:
            self._tools[name or fn.__name__] = {"fn": fn, "action": action or (name or fn.__name__),
                                                "resource": resource, "untrusted": untrusted_output}
            return fn
        return deco

    def register(self, name: str, fn: Callable, action: str | None = None, **kw: Any) -> None:
        self.tool(action, name=name, **kw)(fn)

    @property
    def names(self) -> list[str]:
        return list(self._tools)

    def execute(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        args = dict(arguments or {})
        spec = self._tools.get(name)
        if spec is None:
            return {"ok": False, "error": f"unknown tool '{name}'"}
        res = spec["resource"](args) if spec["resource"] else resource_from_args(args)
        try:
            self.sentinel.check(spec["action"], res, tool=name, arguments=args)
        except (ActionDenied, ActionRejected, SentinelUnavailable) as exc:
            return {"ok": False, "blocked": True,
                    "error": f"Blocked by Sentinel security policy: {exc}. Do not retry this action."}
        try:
            out = spec["fn"](**args)
        except Exception as exc:
            self.sentinel.report(spec["action"], res, tool=name, output=str(exc), status="error")
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        if spec["untrusted"]:
            self.sentinel.observe_input(_safe_str(out), source=name)
        self.sentinel.report(spec["action"], res, tool=name, output=out)
        return {"ok": True, "result": out}
