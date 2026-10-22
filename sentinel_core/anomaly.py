"""Behavioural detection: hard rate limits plus learned per-agent baselines.

Rate limits come from policy and fire immediately. Statistical checks only
fire once an agent has a mature baseline (``min_samples`` events), so a new
agent is governed by policy alone until Sentinel has learned what normal
looks like for it.
"""
from __future__ import annotations

import datetime as _dt
from collections import Counter
from typing import Any
from zoneinfo import ZoneInfo

from .models import ActionEvent, Finding, Severity
from .policy import AgentPolicy, Policy
from .rules import C_BEHAVIOUR, C_DLP, C_HEALTH
from .store import BehaviorSnapshot, resource_prefix

DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "min_samples": 200,          # events before statistical checks engage
    "min_minutes": 30,           # active minutes before burst checks engage
    "record_z": 6.0,             # z-score on records per action
    "record_z_critical": 12.0,
    "burst_z": 4.0,
    "burst_ratio": 3.0,
    "loop_repeats": 8,           # same action+tool+resource in recent window
}


def action_signature(ev: ActionEvent, action: str, resource: str) -> str:
    """Identity of an action for loop detection: same verb, tool, target *and* payload.

    Actions with no target and no payload (e.g. bare LLM calls) have no signature,
    because repeating them is normal.
    """
    import hashlib
    payload = (ev.content or "") + repr(sorted((ev.arguments or {}).items()))
    if not resource and not ev.content and not ev.arguments:
        return ""
    return f"{action}|{ev.tool}|{resource}|{hashlib.sha1(payload.encode()).hexdigest()[:10]}"


def _cfg(policy: Policy) -> dict[str, Any]:
    c = dict(DEFAULTS)
    c.update(policy.anomaly or {})
    return c


def _in_working_hours(wh: dict[str, str], ts: float) -> bool:
    tz = ZoneInfo(wh.get("tz", "UTC"))
    local = _dt.datetime.fromtimestamp(ts, tz)
    start = _dt.time.fromisoformat(wh.get("start", "00:00"))
    end = _dt.time.fromisoformat(wh.get("end", "23:59"))
    days = wh.get("days")
    if days and local.strftime("%a").lower()[:3] not in [d.lower()[:3] for d in days]:
        return False
    t = local.time()
    return start <= t <= end if start <= end else (t >= start or t <= end)


def evaluate_behavior(ev: ActionEvent, agent: AgentPolicy | None, policy: Policy,
                      snap: BehaviorSnapshot, action: str, resource: str) -> list[Finding]:
    if agent is None:
        return []
    cfg = _cfg(policy)
    if not cfg.get("enabled", True):
        return []
    out: list[Finding] = []
    cls = policy.classify(resource) if resource else None
    sensitive = bool(cls and cls.level >= 3)
    rl = agent.rate_limits

    # ---- hard limits (snapshot excludes the current event, so add it) --------
    n_min = snap.actions_last_minute + 1
    if rl.actions_per_minute and n_min > rl.actions_per_minute:
        out.append(Finding(
            detector="behavior", rule_id="rate.actions_per_minute", severity=Severity.HIGH,
            title="Action rate limit exceeded",
            detail=f"{n_min} actions in the last minute (limit {rl.actions_per_minute}).",
            controls=[C_BEHAVIOUR], evidence={"observed": n_min, "limit": rl.actions_per_minute}))

    rec_hour = snap.records_last_hour + max(ev.record_count, 0)
    if rl.records_per_hour and rec_hour > rl.records_per_hour:
        out.append(Finding(
            detector="behavior", rule_id="rate.records_per_hour",
            severity=Severity.CRITICAL if sensitive else Severity.HIGH,
            title="Record volume limit exceeded",
            detail=f"{rec_hour} records accessed in the last hour (limit {rl.records_per_hour}).",
            controls=[C_BEHAVIOUR, C_DLP], evidence={"observed": rec_hour, "limit": rl.records_per_hour}))

    distinct = snap.distinct_resources_last_hour + (0 if snap.resource_seen_this_hour else 1)
    if rl.distinct_resources_per_hour and distinct > rl.distinct_resources_per_hour:
        out.append(Finding(
            detector="behavior", rule_id="rate.distinct_resources",
            severity=Severity.HIGH,
            title="Resource enumeration",
            detail=f"{distinct} distinct resources touched this hour "
                   f"(limit {rl.distinct_resources_per_hour}) — consistent with scanning.",
            controls=[C_BEHAVIOUR, C_DLP], evidence={"observed": distinct}))

    # ---- statistical baselines --------------------------------------------
    bl = snap.baseline
    if bl.n >= cfg["min_samples"]:
        std = max(bl.rec_std, 1.0)
        z = (ev.record_count - bl.rec_mean) / std
        if z >= cfg["record_z"]:
            sev = Severity.HIGH if (z >= cfg["record_z_critical"] or sensitive) else Severity.MEDIUM
            out.append(Finding(
                detector="behavior", rule_id="anomaly.record_volume", severity=sev,
                title="Unusual record volume",
                detail=f"Action touches {ev.record_count} records; this agent normally touches "
                       f"{bl.rec_mean:.1f} ± {bl.rec_std:.1f} (z={z:.1f}).",
                controls=[C_BEHAVIOUR], evidence={"z": round(z, 2), "mean": bl.rec_mean}))

        if not snap.resource_seen_before and sensitive:
            out.append(Finding(
                detector="behavior", rule_id="anomaly.new_sensitive_resource", severity=Severity.MEDIUM,
                title=f"New kind of access to {cls.name if cls else ''} data",
                detail=f"After {bl.n} observed actions, this is the first time the agent has done "
                       f"'{action}' on {cls.name if cls else ''} data under this grant ('{resource}').",
                controls=[C_BEHAVIOUR]))

    if bl.minutes >= cfg["min_minutes"] and bl.rate_mean > 0:
        thresh = max(bl.rate_mean + cfg["burst_z"] * bl.rate_std, bl.rate_mean * cfg["burst_ratio"])
        if n_min > thresh and n_min >= 10:
            out.append(Finding(
                detector="behavior", rule_id="anomaly.burst", severity=Severity.MEDIUM,
                title="Activity burst",
                detail=f"{n_min} actions this minute vs a normal {bl.rate_mean:.1f}/min.",
                controls=[C_BEHAVIOUR], evidence={"observed": n_min, "mean": bl.rate_mean}))

    # ---- working hours ---------------------------------------------------
    if agent.working_hours and not _in_working_hours(agent.working_hours, ev.timestamp):
        out.append(Finding(
            detector="behavior", rule_id="anomaly.off_hours",
            severity=Severity.MEDIUM if sensitive else Severity.LOW,
            title="Activity outside working hours",
            detail=f"Agent acted outside its scheduled window {agent.working_hours}.",
            controls=[C_BEHAVIOUR]))

    # ---- loops / stuck agents -----------------------------------------------
    key = action_signature(ev, action, resource)
    repeats = Counter(snap.recent)[key] + 1 if key else 0
    if repeats >= cfg["loop_repeats"]:
        out.append(Finding(
            detector="health", rule_id="health.loop", severity=Severity.MEDIUM,
            title="Agent appears stuck in a loop",
            detail=f"Same action repeated {repeats} times in its last {len(snap.recent) + 1} actions.",
            controls=[C_HEALTH], evidence={"repeats": repeats}))
    return out
