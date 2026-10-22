"""LangChain / LangGraph adapter.

    from sentinel_sdk.adapters.langchain import guard_tools
    tools = guard_tools([search_tool, read_customer_tool], sentinel,
                        actions={"read_customer": "read"},
                        untrusted=["search"])
    agent = create_react_agent(llm, tools)      # LangGraph prebuilt, or any executor

Each tool is replaced by a ``StructuredTool`` with the same name, description
and argument schema whose body asks Sentinel first. A denial is returned to
the model as the tool's result (so it can explain or re-plan) unless
``raise_on_deny=True``.
"""
from __future__ import annotations

from typing import Any, Callable

from ..client import ActionDenied, ActionRejected, Sentinel, SentinelUnavailable, _safe_str
from ..resources import resource_from_args


def guard_tool(tool: Any, sentinel: Sentinel, *, action: str | None = None,
               resource: Callable[[dict[str, Any]], str] | None = None,
               untrusted_output: bool = False, raise_on_deny: bool = False) -> Any:
    from langchain_core.tools import StructuredTool

    name = tool.name
    act = action or name

    def _res(kwargs: dict[str, Any]) -> str:
        return resource(kwargs) if resource else resource_from_args(kwargs)

    def _denied(exc: Exception) -> str:
        if raise_on_deny:
            raise exc
        return f"ERROR: this action was blocked by the Sentinel security policy ({exc}). Do not retry it."

    def run(**kwargs: Any) -> Any:
        res = _res(kwargs)
        try:
            sentinel.check(act, res, tool=name, arguments=kwargs)
        except (ActionDenied, ActionRejected, SentinelUnavailable) as exc:
            return _denied(exc)
        out = tool.invoke(kwargs)
        if untrusted_output:
            sentinel.observe_input(_safe_str(out), source=name)
        sentinel.report(act, res, tool=name, output=out)
        return out

    async def arun(**kwargs: Any) -> Any:
        import asyncio
        res = _res(kwargs)
        try:
            await asyncio.to_thread(sentinel.check, act, res, tool=name, arguments=kwargs)
        except (ActionDenied, ActionRejected, SentinelUnavailable) as exc:
            return _denied(exc)
        out = await tool.ainvoke(kwargs)
        if untrusted_output:
            sentinel.observe_input(_safe_str(out), source=name)
        sentinel.report(act, res, tool=name, output=out)
        return out

    return StructuredTool.from_function(
        func=run, coroutine=arun, name=name, description=tool.description,
        args_schema=getattr(tool, "args_schema", None), return_direct=getattr(tool, "return_direct", False))


def guard_tools(tools: list[Any], sentinel: Sentinel, *, actions: dict[str, str] | None = None,
                resources: dict[str, Callable[[dict[str, Any]], str]] | None = None,
                untrusted: list[str] | None = None, raise_on_deny: bool = False) -> list[Any]:
    actions, resources, untrusted_set = actions or {}, resources or {}, set(untrusted or [])
    return [guard_tool(t, sentinel, action=actions.get(t.name), resource=resources.get(t.name),
                       untrusted_output=t.name in untrusted_set, raise_on_deny=raise_on_deny)
            for t in tools]
