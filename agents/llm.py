"""LLM backend and the tool-calling agent loop.

The agent loop is provider-agnostic: it talks to any OpenAI-compatible
chat-completions endpoint (Groq by default). Tests pass a ``ScriptedLLM`` so no
network is needed and the agent's choices are deterministic.

The loop:
  1. send the system goal + conversation + the gateway's tool schemas
  2. the model replies with text and/or tool calls
  3. each tool call goes through the gateway (-> Sentinel) and the result,
     including any "blocked, because..." message, goes back to the model
  4. repeat until the model stops calling tools or the step budget runs out

Problems are not scripted: the model decides which tools to call and with what
arguments. When it reaches for data it shouldn't, mis-files a loan, or is swayed
by text inside an application, Sentinel catches it at the tool call.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from .common import RunLog
from .gateway import ToolGateway


class LLM(Protocol):
    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Return an assistant message dict: {content, tool_calls?}."""


@dataclass
class GroqLLM:
    """OpenAI-compatible chat completions. Works with any OpenAI-compatible endpoint;
    defaults to Google Gemini (generous free-tier token limits). Set base_url + model
    (or the LLM_BASE_URL / LLM_MODEL env vars) to point at another provider."""

    api_key: str
    model: str = "gemini-3.5-flash-lite"
    base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai"
    temperature: float = 0.4
    timeout: float = 90.0
    max_retries: int = 2

    def complete(self, messages, tools):
        payload = {"model": self.model, "messages": messages, "temperature": self.temperature,
                   "reasoning_effort": "low"}  # keep Gemini's "thinking" short so tool calls return quickly
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        body = json.dumps(payload).encode()
        # A real User-Agent is required: the API sits behind a CDN that returns 403
        # to the default urllib agent from a datacenter IP (e.g. Lambda).
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {self.api_key}",
                                              "Content-Type": "application/json",
                                              "Accept": "application/json",
                                              "User-Agent": "sentinel-demo-agent/1.0 (+aws-lambda)"})
        last = None
        for attempt in range(self.max_retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 (fixed host)
                    return json.loads(r.read())["choices"][0]["message"]
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode("utf-8", "replace")[:300]
                except Exception:
                    pass
                last = RuntimeError(f"HTTP {e.code} from LLM API: {detail or e.reason}")
                if e.code in (429, 500, 502, 503) and attempt < self.max_retries - 1:
                    # 429 is the per-minute token cap on the free tier. Honour Retry-After
                    # so we wait exactly until the window resets, then continue.
                    retry_after = None
                    try:
                        retry_after = float((e.headers or {}).get("retry-after"))
                    except (TypeError, ValueError):
                        retry_after = None
                    wait = retry_after + 1 if retry_after else (7 if e.code == 429 else 2) * (attempt + 1)
                    time.sleep(min(wait, 65))
                    continue
                raise last
            except (urllib.error.URLError, TimeoutError) as e:
                last = e
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"LLM request failed: {last}")


@dataclass
class ScriptedLLM:
    """Deterministic LLM for tests. `script` is a function (step, last_tool_results)
    -> assistant message dict, so a test can make the agent choose exactly the tool
    calls that exercise a scenario, with no network."""

    script: Any

    def __init__(self, turns: list[dict[str, Any]] | None = None, fn: Any = None) -> None:
        self._turns = list(turns or [])
        self._fn = fn
        self._i = 0

    def complete(self, messages, tools):
        if self._fn is not None:
            return self._fn(messages, tools)
        msg = self._turns[min(self._i, len(self._turns) - 1)]
        self._i += 1
        return msg


def tool_call(name: str, **args: Any) -> dict[str, Any]:
    import json as _j
    return {"content": None, "tool_calls": [
        {"id": f"c{name}", "type": "function",
         "function": {"name": name, "arguments": _j.dumps(args)}}]}


def say(text: str) -> dict[str, Any]:
    return {"content": text, "tool_calls": None}


_KEY_CACHE: dict[str, str] = {}


def _load_key() -> str:
    key = os.environ.get("LLM_API_KEY", "")
    if key:
        return key
    arn = os.environ.get("LLM_SECRET_ARN") or os.environ.get("LLM_SECRET_NAME")
    if not arn:
        raise RuntimeError("no LLM_API_KEY, LLM_SECRET_ARN or LLM_SECRET_NAME set")
    if arn in _KEY_CACHE:
        return _KEY_CACHE[arn]
    import boto3
    val = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"].strip()
    if val.startswith("{"):
        d = json.loads(val)
        val = d.get("api_key") or d.get("LLM_API_KEY") or next(iter(d.values()))
    _KEY_CACHE[arn] = val
    return val


def groq_from_env() -> GroqLLM:
    return GroqLLM(api_key=_load_key(),
                   model=os.environ.get("LLM_MODEL", "gemini-3.5-flash-lite"),
                   base_url=os.environ.get("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai"))


@dataclass
class AgentResult:
    final_text: str
    steps: int
    stopped: str          # "done" | "step_limit" | "blocked" | "error"


def run_agent(llm: LLM, gateway: ToolGateway, system: str, task: str, run: RunLog,
              max_steps: int = 14) -> AgentResult:
    """Drive the model through the task, routing every tool call via the gateway."""
    messages: list[dict[str, Any]] = [{"role": "system", "content": system},
                                      {"role": "user", "content": task}]
    tools = gateway.schemas()
    final = ""
    for step in range(max_steps):
        try:
            msg = llm.complete(messages, tools)
        except Exception as e:
            run.step("llm", "", f"model error: {type(e).__name__}", str(e)[:200])
            return AgentResult(final, step, "error")
        messages.append({"role": "assistant", "content": msg.get("content") or "",
                         "tool_calls": msg.get("tool_calls")})
        calls = msg.get("tool_calls") or []
        if not calls:
            final = (msg.get("content") or "").strip()
            return AgentResult(final, step, "done")
        for call in calls:
            fn = call["function"]
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            result = gateway.execute(fn["name"], args if isinstance(args, dict) else {})
            messages.append({"role": "tool", "tool_call_id": call.get("id", fn["name"]),
                             "name": fn["name"], "content": result.content})
    return AgentResult(final, max_steps, "step_limit")
