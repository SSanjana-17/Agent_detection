"""Health checks: catch agents that stop doing their work.

Runs on a schedule (EventBridge, every minute in AWS). An agent with a
``heartbeat_seconds`` setting must call ``heartbeat()`` at least that often;
missing two intervals raises an alert. Agents that report an error status or
stay on one task far longer than expected are also surfaced.
"""
from __future__ import annotations

from typing import Any

from .models import Finding, Severity
from .policy import Policy
from .rules import C_HEALTH


def evaluate_health(policy: Policy, heartbeats: dict[str, dict[str, Any]],
                    now: float, stall_factor: float = 2.0) -> list[tuple[str, Finding]]:
    out: list[tuple[str, Finding]] = []
    for agent in policy.agents.values():
        if not agent.heartbeat_seconds:
            continue
        hb = heartbeats.get(agent.agent_id)
        limit = agent.heartbeat_seconds * stall_factor
        if hb is None:
            out.append((agent.agent_id, Finding(
                detector="health", rule_id="health.never_reported", severity=Severity.MEDIUM,
                title="Agent has never reported",
                detail=f"'{agent.agent_id}' requires a heartbeat every {agent.heartbeat_seconds}s "
                       f"but has never sent one.",
                controls=[C_HEALTH])))
            continue
        age = now - float(hb["at"])
        if age > limit:
            sev = Severity.HIGH if agent.risk_tier in ("high", "critical") else Severity.MEDIUM
            out.append((agent.agent_id, Finding(
                detector="health", rule_id="health.heartbeat_missed", severity=sev,
                title="Agent stopped responding",
                detail=f"No heartbeat from '{agent.agent_id}' for {int(age)}s "
                       f"(expected every {agent.heartbeat_seconds}s). Last task: "
                       f"{hb.get('task_id') or 'n/a'}.",
                controls=[C_HEALTH], evidence={"seconds_since": int(age)})))
        elif str(hb.get("status", "ok")).lower() in ("error", "failed", "degraded"):
            out.append((agent.agent_id, Finding(
                detector="health", rule_id="health.agent_error", severity=Severity.MEDIUM,
                title="Agent reports failure",
                detail=f"'{agent.agent_id}' reported status '{hb.get('status')}': "
                       f"{str(hb.get('detail', ''))[:300]}",
                controls=[C_HEALTH])))
    return out
