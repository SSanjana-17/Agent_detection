"""Shared plumbing for the demo agents.

Each agent is an ordinary Lambda function with its own IAM role. Before every
S3 operation it asks Sentinel (through the SDK, signed with that role) whether
it may proceed; the S3 call only happens if Sentinel allows it.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

log = logging.getLogger("agent")
log.setLevel(logging.INFO)


@dataclass
class RunLog:
    """A step-by-step record of what the agent did, returned to the caller."""

    agent: str
    mode: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    started: float = field(default_factory=time.time)

    def step(self, action: str, resource: str, outcome: str, detail: str = "") -> None:
        entry = {"t": round(time.time() - self.started, 3), "action": action, "resource": resource,
                 "outcome": outcome}
        if detail:
            entry["detail"] = detail
        self.steps.append(entry)
        log.info(json.dumps({"agent": self.agent, **entry}))

    def result(self, outcome: str, **extra: Any) -> dict[str, Any]:
        out = {"agent": self.agent, "mode": self.mode, "outcome": outcome,
               "duration_s": round(time.time() - self.started, 2), "steps": self.steps, **extra}
        log.info(json.dumps({"agent": self.agent, "outcome": outcome}))
        return out


def make_sentinel(agent_id: str):
    """Sentinel client signed with this Lambda's own IAM role (SigV4)."""
    from sentinel_sdk import Sentinel
    return Sentinel(endpoint=os.environ["SENTINEL_ENDPOINT"], agent_id=agent_id,
                    hold_max_wait_seconds=float(os.environ.get("HOLD_MAX_WAIT", "240")),
                    hold_poll_seconds=3.0, timeout=5.0)


def make_s3():
    import boto3
    return boto3.client("s3")


def s3_uri(bucket: str, key: str) -> str:
    return f"s3://{bucket}/{key}"


def guarded(sentinel, run: RunLog, action: str, resource: str, fn: Callable[[], Any], *,
            record_count: int = 1, content: str = "", wait_on_hold: bool = True) -> Any:
    """Ask Sentinel, then (only if allowed) do the real operation.

    Raises the SDK's ActionDenied / ActionRejected / SentinelUnavailable so the
    agent stops; nothing touches S3 unless Sentinel said yes.
    """
    from sentinel_sdk import ActionDenied, ActionRejected, SentinelUnavailable
    try:
        decision = sentinel.check(action, resource, tool=f"s3:{action}", record_count=record_count,
                                  content=content, wait_on_hold=wait_on_hold)
    except ActionDenied as e:
        run.step(action, resource, "DENIED by Sentinel", str(e.decision.get("reason", e)))
        raise
    except ActionRejected as e:
        held = (e.decision or {}).get("approval") is None
        run.step(action, resource, "HELD by Sentinel for human approval" if held and not wait_on_hold
                 else "REJECTED by reviewer (or not reviewed in time)",
                 str((e.decision or {}).get("reason") or e))
        raise
    except SentinelUnavailable as e:
        run.step(action, resource, "NOT RUN: Sentinel unreachable (fail closed)", str(e))
        raise
    verdict = "ALLOWED, flagged for review" if decision.get("mode") == "FLAG" else "ALLOWED"
    if decision.get("approval"):
        verdict = f"ALLOWED after approval by {decision['approval'].get('resolved_by')}"
    result = fn()
    run.step(action, resource, verdict)
    return result


def start(sentinel, run: RunLog, task_id: str) -> str | None:
    """Heartbeat first. A quarantined agent does not start work."""
    try:
        hb = sentinel.heartbeat(status="ok", detail=f"starting {task_id}")
    except Exception as e:  # Sentinel unreachable: fail closed
        run.step("heartbeat", "", "NOT RUN: Sentinel unreachable (fail closed)", str(e))
        return "sentinel_unreachable"
    if hb.get("status") == "QUARANTINED":
        run.step("heartbeat", "", "QUARANTINED: agent will not run until released", hb.get("reason", ""))
        return "quarantined"
    run.step("heartbeat", "", "ok")
    return None
