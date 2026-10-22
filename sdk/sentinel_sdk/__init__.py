"""Sentinel SDK — put every AI-agent action behind a policy check.

Framework-agnostic core (``Sentinel.check`` / ``@sentinel.guard``) with
adapters for the Claude Agent SDK, LangChain/LangGraph, MCP clients and
hand-written tool loops (Anthropic, OpenAI, Bedrock, CrewAI).
"""
from .client import (ActionDenied, ActionRejected, Sentinel, SentinelError,
                     SentinelUnavailable)
from .transport import HttpTransport, LocalTransport, TransportError

__all__ = ["Sentinel", "SentinelError", "ActionDenied", "ActionRejected", "SentinelUnavailable",
           "HttpTransport", "LocalTransport", "TransportError"]
__version__ = "1.0.0"
