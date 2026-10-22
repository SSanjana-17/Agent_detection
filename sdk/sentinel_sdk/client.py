"""The Sentinel client every agent embeds.

    from sentinel_sdk import Sentinel

    sentinel = Sentinel(endpoint="https://xxxx.execute-api.ap-south-1.amazonaws.com/prod",
                        agent_id="loan-agent")

    with sentinel.task("APP-1042", "Summarise credit file for application APP-1042"):
        sentinel.check("read", resource="s3://example-bank-lending/APP-1042/credit.json")
        data = s3.get_object(...)          # only runs if Sentinel allowed it

Every call is checked *before* it runs. DENY raises ``ActionDenied``; HOLD
blocks until a human approves (returns) or rejects/expiry (raises
``ActionRejected``). If Sentinel is unreachable the SDK fails closed by
default and raises ``SentinelUnavailable``.
"""
from __future__ import annotations

import atexit
import contextlib
import contextvars
import functools
import inspect
import logging
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from .resources import infer_record_count, resource_from_args
from .transport import HttpTransport, LocalTransport, Transport, TransportError

log = logging.getLogger("sentinel_sdk")

_task: contextvars.ContextVar["_TaskCtx | None"] = contextvars.ContextVar("sentinel_task", default=None)


@dataclass
class _TaskCtx:
    task_id: str
    description: str
    untrusted: list[str] = field(default_factory=list)


class SentinelError(Exception):
    def __init__(self, message: str, decision: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.decision = decision or {}


class ActionDenied(SentinelError):
    """Sentinel blocked the action (BLOCK or QUARANTINE)."""


class ActionRejected(SentinelError):
    """A held action was rejected by a human or expired without approval."""


class SentinelUnavailable(SentinelError):
    """Sentinel could not be reached and the client is failing closed."""


class Sentinel:
    def __init__(self, endpoint: str | None = None, agent_id: str = "", *,
                 transport: Transport | None = None, region: str | None = None,
                 auth: str = "iam", api_token: str | None = None, fail_mode: str = "closed",
                 timeout: float = 3.0, hold_poll_seconds: float = 3.0,
                 hold_max_wait_seconds: float = 3600.0, session_id: str | None = None,
                 report_events: bool = True, max_content_chars: int = 20000,
                 boto3_session: Any = None) -> None:
        if not agent_id:
            raise ValueError("agent_id is required")
        if transport is None:
            if not endpoint:
                raise ValueError("endpoint or transport is required")
            transport = HttpTransport(endpoint, region=region, auth=auth, api_token=api_token,
                                      timeout=timeout, session=boto3_session)
        if fail_mode not in ("closed", "open"):
            raise ValueError("fail_mode must be 'closed' or 'open'")
        self.transport = transport
        self.agent_id = agent_id
        self.fail_mode = fail_mode
        self.hold_poll_seconds = hold_poll_seconds
        self.hold_max_wait_seconds = hold_max_wait_seconds
        self.session_id = session_id or uuid.uuid4().hex
        self.max_content_chars = max_content_chars
        self._reports: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=10000)
        self._reporter: threading.Thread | None = None
        self._hb_stop = threading.Event()
        self._hb_thread: threading.Thread | None = None
        self._report_enabled = report_events
        # Used when no task() scope is active (e.g. framework hooks running in
        # separate asyncio tasks), so untrusted inputs are never silently lost.
        self._default_ctx = _TaskCtx(task_id="", description="")
        atexit.register(self.close)

    # -------------------------------------------------------------- factories
    @classmethod
    def local(cls, agent_id: str, policy_path: str = "policies/policy.yaml", **kw: Any) -> "Sentinel":
        """Embedded mode: the full engine runs in-process (no network)."""
        return cls(agent_id=agent_id, transport=LocalTransport(policy_path=policy_path), **kw)

    # ------------------------------------------------------------ task scope
    @contextlib.contextmanager
    def task(self, task_id: str, description: str = "") -> Iterator[None]:
        """Scope actions to a task; the LLM judge compares actions to this description."""
        token = _task.set(_TaskCtx(task_id=task_id, description=description))
        try:
            yield
        finally:
            _task.reset(token)

    def observe_input(self, text: str, source: str = "") -> None:
        """Register untrusted content the agent just read (web page, email, tool output).

        It is attached to the next ``check`` so Sentinel can catch prompt injection
        *before* the agent acts on it.
        """
        ctx = _task.get() or self._default_ctx
        snippet = (f"[{source}] " if source else "") + (text or "")[: self.max_content_chars]
        ctx.untrusted.append(snippet)
        del ctx.untrusted[:-5]  # keep the last few inputs

    # ------------------------------------------------------------ decisions
    def check(self, action: str, resource: str = "", *, tool: str = "", content: str = "",
              arguments: dict[str, Any] | None = None, record_count: int = 1,
              inputs: str | None = None, metadata: dict[str, Any] | None = None,
              wait_on_hold: bool = True) -> dict[str, Any]:
        """Ask Sentinel whether an action may proceed. Returns the decision if allowed."""
        ctx = _task.get() or self._default_ctx
        untrusted = inputs if inputs is not None else ("\n---\n".join(ctx.untrusted) if ctx else "")
        event = {
            "event_id": uuid.uuid4().hex, "agent_id": self.agent_id, "action": action,
            "resource": resource, "tool": tool, "content": (content or "")[: self.max_content_chars],
            "arguments": _jsonable(arguments or {}), "record_count": int(record_count or 1),
            "inputs": untrusted[: self.max_content_chars * 2],
            "task_id": ctx.task_id if ctx else "", "task_description": ctx.description if ctx else "",
            "session_id": self.session_id, "phase": "pre", "source": "sdk",
            "timestamp": time.time(), "metadata": metadata or {},
        }
        try:
            decision = self.transport.request("POST", "/v1/decide", event)
        except TransportError as exc:
            if self.fail_mode == "open":
                log.warning("Sentinel unavailable, failing OPEN for %s %s: %s", action, resource, exc)
                return {"verdict": "ALLOW", "mode": "LOG", "reason": "fail-open", "findings": []}
            raise SentinelUnavailable(f"Sentinel unavailable; action blocked (fail closed): {exc}") from exc

        if ctx is not None and decision.get("verdict") != "DENY":
            ctx.untrusted.clear()  # inputs have been screened

        verdict = decision.get("verdict")
        if verdict == "ALLOW":
            return decision
        if verdict == "DENY":
            raise ActionDenied(f"Sentinel denied {action} on '{resource or tool}': {decision.get('reason')}",
                               decision)
        if verdict == "HOLD":
            if not wait_on_hold:
                raise ActionRejected("action is on hold awaiting human approval", decision)
            return self.wait_for_approval(decision)
        raise SentinelError(f"unexpected verdict {verdict!r}", decision)

    def wait_for_approval(self, decision: dict[str, Any]) -> dict[str, Any]:
        ap_id = decision.get("approval_id")
        if not ap_id:
            raise ActionRejected("held without approval id", decision)
        log.warning("Action held for human approval (%s): %s", ap_id, decision.get("reason"))
        deadline = time.time() + self.hold_max_wait_seconds
        while time.time() < deadline:
            try:
                ap = self.transport.request("GET", f"/v1/approvals/{ap_id}")
            except TransportError as exc:
                log.warning("approval poll failed: %s", exc)
                ap = {"status": "PENDING"}
            status = ap.get("status")
            if status == "APPROVED":
                decision = dict(decision, verdict="ALLOW", approval=ap)
                return decision
            if status in ("REJECTED", "EXPIRED"):
                raise ActionRejected(
                    f"held action {status.lower()} by {ap.get('resolved_by') or 'policy'}"
                    + (f": {ap.get('comment')}" if ap.get("comment") else ""), dict(decision, approval=ap))
            time.sleep(self.hold_poll_seconds)
        raise ActionRejected("gave up waiting for approval", decision)

    def check_output(self, text: str, destination: str = "") -> dict[str, Any]:
        """Screen a final answer / message before it leaves the agent (DLP)."""
        return self.check("output", resource=destination, content=text)

    # --------------------------------------------------------- post-events
    def report(self, action: str, resource: str = "", *, tool: str = "", output: Any = None,
               record_count: int | None = None, status: str = "ok",
               metadata: dict[str, Any] | None = None) -> None:
        """Report a completed action (non-blocking). Feeds baselines and async detection."""
        if not self._report_enabled:
            return
        ctx = _task.get()
        text = output if isinstance(output, str) else ("" if output is None else _safe_str(output))
        ev = {
            "event_id": uuid.uuid4().hex, "agent_id": self.agent_id, "action": action,
            "resource": resource, "tool": tool, "content": text[: self.max_content_chars],
            "record_count": int(record_count if record_count is not None else infer_record_count(output)),
            "task_id": ctx.task_id if ctx else "", "task_description": ctx.description if ctx else "",
            "session_id": self.session_id, "phase": "post", "source": "sdk",
            "timestamp": time.time(), "metadata": dict(metadata or {}, status=status),
        }
        self._ensure_reporter()
        try:
            self._reports.put_nowait(ev)
        except queue.Full:
            log.error("Sentinel report queue full; dropping event")

    def _ensure_reporter(self) -> None:
        if self._reporter is None or not self._reporter.is_alive():
            self._reporter = threading.Thread(target=self._report_loop, name="sentinel-reporter",
                                              daemon=True)
            self._reporter.start()

    def _report_loop(self) -> None:
        batch: list[dict[str, Any]] = []
        while True:
            try:
                item = self._reports.get(timeout=1.0)
            except queue.Empty:
                item = "tick"  # type: ignore[assignment]
            if item is None:
                self._send(batch)
                return
            if item != "tick":
                batch.append(item)  # type: ignore[arg-type]
            if len(batch) >= 50 or (batch and item == "tick"):
                self._send(batch)
                batch = []

    def _send(self, batch: list[dict[str, Any]]) -> None:
        if not batch:
            return
        try:
            self.transport.request("POST", "/v1/events", {"events": batch})
        except Exception as exc:
            log.error("failed to report %d events to Sentinel: %s", len(batch), exc)

    def flush(self, timeout: float = 5.0) -> None:
        if self._reporter and self._reporter.is_alive():
            self._reports.put(None)
            self._reporter.join(timeout)
            self._reporter = None

    # ------------------------------------------------------------- heartbeat
    def heartbeat(self, status: str = "ok", detail: str = "") -> dict[str, Any]:
        ctx = _task.get()
        resp = self.transport.request("POST", "/v1/heartbeat", {
            "agent_id": self.agent_id, "task_id": ctx.task_id if ctx else "",
            "status": status, "detail": detail})
        if resp.get("status") == "QUARANTINED":
            log.error("This agent is QUARANTINED by Sentinel: %s", resp.get("reason"))
        return resp

    def start_heartbeat(self, interval_seconds: float = 60.0) -> None:
        if self._hb_thread and self._hb_thread.is_alive():
            return
        self._hb_stop.clear()

        def loop() -> None:
            while True:
                try:
                    self.heartbeat()
                except Exception as exc:
                    log.warning("heartbeat failed: %s", exc)
                if self._hb_stop.wait(interval_seconds):
                    return

        self._hb_thread = threading.Thread(target=loop, name="sentinel-heartbeat", daemon=True)
        self._hb_thread.start()

    def close(self) -> None:
        self._hb_stop.set()
        self.flush()

    # ------------------------------------------------------------- decorator
    def guard(self, action: str | None = None, *, resource: str | Callable[..., str] | None = None,
              tool: str | None = None, record_count: Callable[..., int] | None = None,
              report: bool = True, untrusted_output: bool = False) -> Callable:
        """Wrap any function so it only runs when Sentinel allows it.

            @sentinel.guard("read", resource=lambda key: f"s3://bucket/{key}")
            def load_customer(key): ...

        ``untrusted_output=True`` registers the return value as untrusted input
        (web fetches, email readers) so the next action is screened for injection.
        """
        def deco(fn: Callable) -> Callable:
            name = tool or fn.__name__
            sig = inspect.signature(fn)

            def _prepare(args: tuple, kwargs: dict) -> tuple[str, dict[str, Any], int]:
                bound = sig.bind_partial(*args, **kwargs)
                arguments = {k: v for k, v in bound.arguments.items() if k not in ("self", "cls")}
                if callable(resource):
                    res = resource(*args, **kwargs)
                elif resource is not None:
                    res = resource.format(**arguments) if "{" in resource else resource
                else:
                    res = resource_from_args(arguments)
                rc = record_count(*args, **kwargs) if record_count else 1
                return res, arguments, rc

            def _after(res: str, result: Any) -> None:
                if untrusted_output:
                    self.observe_input(_safe_str(result), source=name)
                if report:
                    self.report(action or name, res, tool=name, output=result)

            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def aw(*args: Any, **kwargs: Any) -> Any:
                    res, arguments, rc = _prepare(args, kwargs)
                    self.check(action or name, res, tool=name, arguments=arguments, record_count=rc)
                    result = await fn(*args, **kwargs)
                    _after(res, result)
                    return result
                return aw

            @functools.wraps(fn)
            def w(*args: Any, **kwargs: Any) -> Any:
                res, arguments, rc = _prepare(args, kwargs)
                self.check(action or name, res, tool=name, arguments=arguments, record_count=rc)
                result = fn(*args, **kwargs)
                _after(res, result)
                return result
            return w
        return deco


def _safe_str(x: Any, limit: int = 20000) -> str:
    try:
        s = x if isinstance(x, str) else repr(x)
    except Exception:
        s = f"<{type(x).__name__}>"
    return s[:limit]


def _jsonable(d: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in d.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[str(k)] = v if not isinstance(v, str) else v[:5000]
        elif isinstance(v, (list, tuple, dict)):
            out[str(k)] = _safe_str(v, 5000)
        else:
            out[str(k)] = f"<{type(v).__name__}>"
    return out
