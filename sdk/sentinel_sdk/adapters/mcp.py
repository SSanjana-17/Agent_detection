"""MCP client adapter: guard every ``call_tool`` on an MCP ClientSession.

    from mcp import ClientSession
    from sentinel_sdk.adapters.mcp import GuardedSession

    async with ClientSession(read, write) as raw:
        await raw.initialize()
        session = GuardedSession(raw, sentinel, server="crm")
        result = await session.call_tool("get_customer", {"customer_id": "C-17"})

Other attributes are proxied to the wrapped session unchanged.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable

from ..client import Sentinel, _safe_str
from ..resources import resource_from_args


class GuardedSession:
    def __init__(self, session: Any, sentinel: Sentinel, server: str = "mcp", *,
                 resource_for: Callable[[str, dict[str, Any]], str] | None = None,
                 untrusted_tools: set[str] | None = None, untrusted_all: bool = True) -> None:
        self._session = session
        self._sentinel = sentinel
        self._server = server
        self._resource_for = resource_for
        self._untrusted = untrusted_tools or set()
        self._untrusted_all = untrusted_all

    def __getattr__(self, item: str) -> Any:
        return getattr(self._session, item)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None, **kw: Any) -> Any:
        args = arguments or {}
        tool = f"mcp__{self._server}__{name}"
        resource = (self._resource_for(name, args) if self._resource_for else
                    resource_from_args(args) or f"mcp://{self._server}/{name}")
        await asyncio.to_thread(self._sentinel.check, tool, resource, tool=tool, arguments=args)
        result = await self._session.call_tool(name, args, **kw)
        text = _content_text(result)
        if self._untrusted_all or name in self._untrusted:
            self._sentinel.observe_input(text, source=tool)
        self._sentinel.report(tool, resource, tool=tool, output=text,
                              status="error" if getattr(result, "isError", False) else "ok")
        return result


def _content_text(result: Any) -> str:
    parts = getattr(result, "content", None)
    if not parts:
        return _safe_str(result)
    return "\n".join(getattr(p, "text", "") or _safe_str(p) for p in parts)
