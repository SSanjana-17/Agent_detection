"""Claude Agent SDK adapter (PreToolUse / PostToolUse hooks).

    from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
    from sentinel_sdk import Sentinel
    from sentinel_sdk.adapters.claude_agent_sdk import sentinel_hooks

    sentinel = Sentinel(endpoint=..., agent_id="kyc-agent")
    options = ClaudeAgentOptions(hooks=sentinel_hooks(sentinel))

Every tool call (built-in, MCP or custom) is checked before it runs. A DENY
or a rejected HOLD becomes ``permissionDecision: "deny"`` with Sentinel's
reason, which Claude sees and can explain. Tool results are reported after
execution and registered as untrusted input, so an injected instruction in a
fetched page is screened before the agent's *next* action.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ..client import ActionDenied, ActionRejected, Sentinel, SentinelUnavailable, _safe_str

# Built-in tool -> (Sentinel action, argument holding the resource)
TOOL_MAP: dict[str, tuple[str, str]] = {
    "Read": ("read", "file_path"),
    "Write": ("write", "file_path"),
    "Edit": ("write", "file_path"),
    "MultiEdit": ("write", "file_path"),
    "NotebookEdit": ("write", "notebook_path"),
    "Glob": ("list", "path"),
    "Grep": ("list", "path"),
    "LS": ("list", "path"),
    "Bash": ("execute", "command"),
    "WebFetch": ("network", "url"),
    "WebSearch": ("network", "query"),
    "Agent": ("message", "description"),
    "Task": ("message", "description"),
}

# Tools whose output is content from outside the trust boundary.
UNTRUSTED_OUTPUT_TOOLS = {"WebFetch", "WebSearch", "Read", "Bash", "Grep"}


def _classify(tool_name: str, tool_input: dict[str, Any]) -> tuple[str, str, str]:
    """Return (action, resource, content) for a Claude tool call."""
    if tool_name in TOOL_MAP:
        action, key = TOOL_MAP[tool_name]
        resource = str(tool_input.get(key, "") or tool_input.get("path", "") or "")
        if tool_name == "WebSearch":
            resource = "https://search"  # searches are network egress without a fixed host
        content = str(tool_input.get("content") or tool_input.get("new_string") or "")
        if tool_name == "Bash":
            content = resource
        return action, resource, content
    # MCP tools: mcp__<server>__<action>; let Sentinel infer the verb from the name
    from ..resources import resource_from_args
    return tool_name, resource_from_args(tool_input), ""


def sentinel_hooks(sentinel: Sentinel, hold_timeout_seconds: int | None = None) -> dict[str, list[Any]]:
    from claude_agent_sdk import HookMatcher

    async def pre_tool_use(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
        tool = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input") or {}
        action, resource, content = _classify(tool, tool_input)
        try:
            await asyncio.to_thread(sentinel.check, action, resource, tool=tool, content=content,
                                    arguments=tool_input)
            return {}
        except (ActionDenied, ActionRejected, SentinelUnavailable) as exc:
            return {
                "systemMessage": f"Sentinel blocked {tool}: {exc}",
                "hookSpecificOutput": {
                    "hookEventName": input_data.get("hook_event_name", "PreToolUse"),
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Blocked by Sentinel security policy: {exc}",
                },
            }

    async def post_tool_use(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
        tool = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input") or {}
        output = input_data.get("tool_response")
        action, resource, _ = _classify(tool, tool_input)
        if tool in UNTRUSTED_OUTPUT_TOOLS or tool.startswith("mcp__"):
            sentinel.observe_input(_safe_str(output), source=tool)
        sentinel.report(action, resource, tool=tool, output=output)
        return {}

    timeout = hold_timeout_seconds or int(sentinel.hold_max_wait_seconds) + 30
    return {
        "PreToolUse": [HookMatcher(hooks=[pre_tool_use], timeout=timeout)],
        "PostToolUse": [HookMatcher(hooks=[post_tool_use])],
    }
