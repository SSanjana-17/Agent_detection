"""State store interface plus a thread-safe in-memory implementation.

``Store`` is the contract every backend implements. ``DynamoStore``
(``sentinel_core.aws.dynamo``) is the production backend; ``MemoryStore``
backs the local server, the embedded SDK mode and the test-suite.
"""
from __future__ import annotations

import abc
import hashlib
import math
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from .models import (ActionEvent, AgentStatus, ApprovalStatus, Decision, Mode,
                     Severity)

RECENT_WINDOW = 25            # recent actions kept for loop detection
SEEN_CAP = 5000               # max remembered resource prefixes per agent


def resource_prefix(resource: str) -> str:
    """Coarse 'area' of a resource, used for novelty detection and alert grouping.

    ``s3://bucket/kyc/C-1/a.pdf`` -> ``s3://bucket/kyc``; ``/data/customers/pii/a`` ->
    ``/data/customers``. Per-customer folders must not each count as "new", or an
    agent doing normal work would look anomalous on every new customer.
    """
    if not resource:
        return ""
    head, sep, path = resource.partition("://")
    if sep:
        host, _, rest = path.partition("/")
        base, depth = f"{head}://{host}", 1
    else:
        base, rest, depth = "", resource, 2
    dirs = [s for s in rest.split("/") if s][:-1][:depth]
    if not dirs:
        return base or resource
    return f"{base}/{'/'.join(dirs)}"


def resource_key(resource: str) -> str:
    return hashlib.sha256(resource.encode()).hexdigest()[:24]


@dataclass
class Baseline:
    n: int = 0                    # events observed
    rec_mean: float = 0.0         # Welford mean of record_count
    rec_m2: float = 0.0
    rate_mean: float = 0.0        # EWMA of actions per active minute
    rate_var: float = 0.0
    minutes: int = 0              # active minutes folded into the EWMA

    @property
    def rec_std(self) -> float:
        return math.sqrt(self.rec_m2 / (self.n - 1)) if self.n > 1 else 0.0

    @property
    def rate_std(self) -> float:
        return math.sqrt(max(self.rate_var, 0.0))

    def add_records(self, x: float) -> None:
        self.n += 1
        d = x - self.rec_mean
        self.rec_mean += d / self.n
        self.rec_m2 += d * (x - self.rec_mean)

    def add_minute(self, count: float, alpha: float = 0.1) -> None:
        if self.minutes == 0:
            self.rate_mean, self.rate_var = count, 0.0
        else:
            d = count - self.rate_mean
            self.rate_mean += alpha * d
            self.rate_var = (1 - alpha) * (self.rate_var + alpha * d * d)
        self.minutes += 1

    def to_dict(self) -> dict[str, Any]:
        return dict(n=self.n, rec_mean=self.rec_mean, rec_m2=self.rec_m2,
                    rate_mean=self.rate_mean, rate_var=self.rate_var, minutes=self.minutes)

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "Baseline":
        d = d or {}
        return cls(n=int(d.get("n", 0)), rec_mean=float(d.get("rec_mean", 0)),
                   rec_m2=float(d.get("rec_m2", 0)), rate_mean=float(d.get("rate_mean", 0)),
                   rate_var=float(d.get("rate_var", 0)), minutes=int(d.get("minutes", 0)))


@dataclass
class BehaviorSnapshot:
    actions_last_minute: int = 0
    records_last_hour: int = 0
    distinct_resources_last_hour: int = 0
    resource_seen_before: bool = True
    resource_seen_this_hour: bool = True
    baseline: Baseline = field(default_factory=Baseline)
    recent: list[str] = field(default_factory=list)   # "action|tool|resource"

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions_last_minute": self.actions_last_minute,
            "records_last_hour": self.records_last_hour,
            "distinct_resources_last_hour": self.distinct_resources_last_hour,
            "resource_seen_before": self.resource_seen_before,
            "baseline": self.baseline.to_dict(),
        }


class Store(abc.ABC):
    """Persistence contract. All timestamps are epoch seconds."""

    # agents -------------------------------------------------------------
    @abc.abstractmethod
    def get_agent_status(self, agent_id: str) -> tuple[AgentStatus, str]: ...

    @abc.abstractmethod
    def set_agent_status(self, agent_id: str, status: AgentStatus, reason: str,
                         actor: str) -> None: ...

    @abc.abstractmethod
    def list_agent_states(self) -> dict[str, dict[str, Any]]: ...

    # behaviour ------------------------------------------------------------
    @abc.abstractmethod
    def behavior_snapshot(self, agent_id: str, resource: str, now: float,
                          area: str | None = None) -> BehaviorSnapshot: ...

    @abc.abstractmethod
    def record_activity(self, event: ActionEvent, action: str, resource: str,
                        mediated: bool, now: float, granted: bool = True,
                        area: str | None = None) -> None:
        """Update counters. ``granted`` False = attempt denied, records not counted."""

    @abc.abstractmethod
    def was_mediated(self, agent_id: str, resource: str, since: float) -> bool: ...

    # decisions / alerts -----------------------------------------------------
    @abc.abstractmethod
    def put_decision(self, decision: Decision, event: ActionEvent) -> None: ...

    @abc.abstractmethod
    def get_decision(self, decision_id: str) -> dict[str, Any] | None: ...

    @abc.abstractmethod
    def list_decisions(self, limit: int = 100, agent_id: str | None = None,
                       min_mode: Mode = Mode.LOG, since: float = 0) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    def create_alert(self, decision: Decision, event: ActionEvent) -> str: ...

    @abc.abstractmethod
    def list_alerts(self, status: str | None = "OPEN", limit: int = 200) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    def update_alert(self, alert_id: str, status: str, actor: str, note: str = "") -> dict[str, Any]: ...

    @abc.abstractmethod
    def claim_alert_slot(self, key: str, ttl_seconds: int, now: float) -> bool:
        """Dedup/throttle: True if no alert with ``key`` was sent in the window."""

    # approvals ------------------------------------------------------------
    @abc.abstractmethod
    def create_approval(self, decision: Decision, event: ActionEvent, expires_at: float) -> str: ...

    @abc.abstractmethod
    def get_approval(self, approval_id: str) -> dict[str, Any] | None: ...

    @abc.abstractmethod
    def list_approvals(self, status: str | None = "PENDING", limit: int = 200) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    def resolve_approval(self, approval_id: str, status: ApprovalStatus, actor: str,
                         comment: str = "") -> dict[str, Any]: ...

    @abc.abstractmethod
    def set_approval_token(self, approval_id: str, token: str) -> None: ...

    # health ---------------------------------------------------------------
    @abc.abstractmethod
    def record_heartbeat(self, agent_id: str, now: float, task_id: str = "",
                         status: str = "ok", detail: str = "") -> None: ...

    @abc.abstractmethod
    def get_heartbeats(self) -> dict[str, dict[str, Any]]: ...

    # compliance -----------------------------------------------------------
    @abc.abstractmethod
    def put_control_result(self, result: dict[str, Any]) -> None: ...

    @abc.abstractmethod
    def latest_control_results(self) -> dict[str, dict[str, Any]]: ...

    @abc.abstractmethod
    def control_history(self, control_id: str, limit: int = 50) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    def put_risk(self, risk: dict[str, Any]) -> None: ...

    @abc.abstractmethod
    def list_risks(self) -> list[dict[str, Any]]: ...


# ===========================================================================
# In-memory implementation
# ===========================================================================


class MemoryStore(Store):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.agents: dict[str, dict[str, Any]] = {}
        self.minute_buckets: dict[str, dict[int, list[int]]] = defaultdict(dict)  # agent->min->[count,records]
        self.hour_resources: dict[str, dict[int, set[str]]] = defaultdict(dict)
        self.baselines: dict[str, Baseline] = defaultdict(Baseline)
        self.seen: dict[str, set[str]] = defaultdict(set)
        self.recent: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=RECENT_WINDOW))
        self.mediated: dict[tuple[str, str], float] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.decision_order: list[str] = []
        self.alerts: dict[str, dict[str, Any]] = {}
        self.alert_slots: dict[str, float] = {}
        self.approvals: dict[str, dict[str, Any]] = {}
        self.heartbeats: dict[str, dict[str, Any]] = {}
        self.control_results: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.risks: dict[str, dict[str, Any]] = {}

    # agents
    def get_agent_status(self, agent_id):
        with self._lock:
            a = self.agents.get(agent_id)
            if not a:
                return AgentStatus.ACTIVE, ""
            return AgentStatus(a["status"]), a.get("reason", "")

    def set_agent_status(self, agent_id, status, reason, actor):
        with self._lock:
            a = self.agents.setdefault(agent_id, {"agent_id": agent_id})
            a.update(status=status.value, reason=reason, changed_by=actor, changed_at=time.time())

    def list_agent_states(self):
        with self._lock:
            return {k: dict(v) for k, v in self.agents.items()}

    # behaviour
    def behavior_snapshot(self, agent_id, resource, now, area=None):
        with self._lock:
            minute, hour = int(now // 60), int(now // 3600)
            buckets = self.minute_buckets[agent_id]
            last_min = buckets.get(minute, [0, 0])[0]
            rec_hour = sum(v[1] for m, v in buckets.items() if m > minute - 60)
            res = set()
            for h in (hour, hour - 1):
                res |= self.hour_resources[agent_id].get(h, set())
            prefix = area if area is not None else resource_prefix(resource)
            this_hour = self.hour_resources[agent_id].get(hour, set())
            return BehaviorSnapshot(
                resource_seen_this_hour=(not resource) or resource in this_hour,
                actions_last_minute=last_min,
                records_last_hour=rec_hour,
                distinct_resources_last_hour=len(this_hour),
                resource_seen_before=(not prefix) or prefix in self.seen[agent_id],
                baseline=Baseline.from_dict(self.baselines[agent_id].to_dict()),
                recent=list(self.recent[agent_id]),
            )

    def record_activity(self, event, action, resource, mediated, now, granted=True, area=None):
        with self._lock:
            aid = event.agent_id
            minute, hour = int(now // 60), int(now // 3600)
            buckets = self.minute_buckets[aid]
            if minute not in buckets:
                prev = buckets.get(minute - 1)
                bl = self.baselines[aid]
                if prev:
                    bl.add_minute(prev[0])
                # prune old buckets
                for m in [m for m in buckets if m < minute - 120]:
                    del buckets[m]
                buckets[minute] = [0, 0]
            buckets[minute][0] += 1
            if granted:
                buckets[minute][1] += max(int(event.record_count), 0)
                self.baselines[aid].add_records(float(event.record_count))
            if resource:
                self.hour_resources[aid].setdefault(hour, set()).add(resource)
                for h in [h for h in self.hour_resources[aid] if h < hour - 2]:
                    del self.hour_resources[aid][h]
                if len(self.seen[aid]) < SEEN_CAP and granted:
                    self.seen[aid].add(area if area is not None else resource_prefix(resource))
                if mediated:
                    self.mediated[(aid, resource_key(resource))] = now
            self.recent[aid].append(_sig(event, action, resource))

    def was_mediated(self, agent_id, resource, since):
        with self._lock:
            ts = self.mediated.get((agent_id, resource_key(resource)))
            return ts is not None and ts >= since

    # decisions
    def put_decision(self, decision, event):
        with self._lock:
            rec = decision.to_dict()
            rec["event"] = _event_summary(event)
            self.decisions[decision.decision_id] = rec
            self.decision_order.append(decision.decision_id)
            if len(self.decision_order) > 50_000:
                old = self.decision_order.pop(0)
                self.decisions.pop(old, None)

    def get_decision(self, decision_id):
        with self._lock:
            d = self.decisions.get(decision_id)
            return dict(d) if d else None

    def list_decisions(self, limit=100, agent_id=None, min_mode=Mode.LOG, since=0):
        with self._lock:
            out = []
            for did in reversed(self.decision_order):
                d = self.decisions[did]
                if d["timestamp"] < since:
                    break
                if agent_id and d["agent_id"] != agent_id:
                    continue
                if Mode[d["mode"]] < min_mode:
                    continue
                out.append(dict(d))
                if len(out) >= limit:
                    break
            return out

    def create_alert(self, decision, event):
        with self._lock:
            aid = uuid.uuid4().hex
            top = max(decision.findings, key=lambda f: f.severity) if decision.findings else None
            self.alerts[aid] = {
                "alert_id": aid, "decision_id": decision.decision_id,
                "agent_id": decision.agent_id, "severity": decision.severity.name,
                "mode": decision.mode.name, "verdict": decision.verdict.value,
                "title": top.title if top else decision.reason,
                "rule_id": top.rule_id if top else "",
                "detail": decision.reason, "status": "OPEN",
                "approval_id": decision.approval_id,
                "resource": event.resource, "created_at": decision.timestamp,
                "history": [],
            }
            return aid

    def list_alerts(self, status="OPEN", limit=200):
        with self._lock:
            items = [dict(a) for a in self.alerts.values() if status is None or a["status"] == status]
            items.sort(key=lambda a: a["created_at"], reverse=True)
            return items[:limit]

    def update_alert(self, alert_id, status, actor, note=""):
        with self._lock:
            a = self.alerts[alert_id]
            a["history"].append({"from": a["status"], "to": status, "actor": actor,
                                 "note": note, "at": time.time()})
            a["status"] = status
            return dict(a)

    def claim_alert_slot(self, key, ttl_seconds, now):
        with self._lock:
            ts = self.alert_slots.get(key)
            if ts is not None and now - ts < ttl_seconds:
                return False
            self.alert_slots[key] = now
            return True

    # approvals
    def create_approval(self, decision, event, expires_at):
        with self._lock:
            ap_id = uuid.uuid4().hex
            self.approvals[ap_id] = {
                "approval_id": ap_id, "decision_id": decision.decision_id,
                "agent_id": decision.agent_id, "status": ApprovalStatus.PENDING.value,
                "severity": decision.severity.name, "reason": decision.reason,
                "findings": [f.to_dict() for f in decision.findings],
                "event": _event_summary(event), "created_at": decision.timestamp,
                "expires_at": expires_at, "resolved_by": None, "resolved_at": None,
                "comment": "", "task_token": None,
            }
            return ap_id

    def get_approval(self, approval_id):
        with self._lock:
            a = self.approvals.get(approval_id)
            if a and a["status"] == "PENDING" and time.time() > a["expires_at"]:
                a.update(status="EXPIRED", resolved_by="system:timeout", resolved_at=time.time())
            return dict(a) if a else None

    def list_approvals(self, status="PENDING", limit=200):
        with self._lock:
            for a in self.approvals.values():
                if a["status"] == "PENDING" and time.time() > a["expires_at"]:
                    a.update(status="EXPIRED", resolved_by="system:timeout", resolved_at=time.time())
            items = [dict(a) for a in self.approvals.values() if status is None or a["status"] == status]
            items.sort(key=lambda a: a["created_at"], reverse=True)
            return items[:limit]

    def resolve_approval(self, approval_id, status, actor, comment=""):
        with self._lock:
            a = self.approvals.get(approval_id)
            if a is None:
                raise KeyError(approval_id)
            if a["status"] != "PENDING":
                raise ValueError(f"approval already {a['status']}")
            a.update(status=status.value, resolved_by=actor, resolved_at=time.time(), comment=comment)
            return dict(a)

    def set_approval_token(self, approval_id, token):
        with self._lock:
            self.approvals[approval_id]["task_token"] = token

    # health
    def record_heartbeat(self, agent_id, now, task_id="", status="ok", detail=""):
        with self._lock:
            self.heartbeats[agent_id] = {"agent_id": agent_id, "at": now, "task_id": task_id,
                                         "status": status, "detail": detail}

    def get_heartbeats(self):
        with self._lock:
            return {k: dict(v) for k, v in self.heartbeats.items()}

    # compliance
    def put_control_result(self, result):
        with self._lock:
            self.control_results[result["control_id"]].append(dict(result))

    def latest_control_results(self):
        with self._lock:
            return {k: dict(v[-1]) for k, v in self.control_results.items() if v}

    def control_history(self, control_id, limit=50):
        with self._lock:
            return [dict(r) for r in self.control_results.get(control_id, [])[-limit:]][::-1]

    def put_risk(self, risk):
        with self._lock:
            self.risks[risk["risk_id"]] = dict(risk)

    def list_risks(self):
        with self._lock:
            return [dict(r) for r in self.risks.values()]


def _sig(event: ActionEvent, action: str, resource: str) -> str:
    from .anomaly import action_signature
    return action_signature(event, action, resource)


def _event_summary(event: ActionEvent) -> dict[str, Any]:
    """Event fields safe to persist: content is truncated and never stored raw."""
    from .pii import redact_text
    return {
        "event_id": event.event_id, "agent_id": event.agent_id, "action": event.action,
        "tool": event.tool, "resource": event.resource, "task_id": event.task_id,
        "task_description": (event.task_description or "")[:500],
        "record_count": event.record_count, "phase": event.phase, "source": event.source,
        "principal": event.principal, "session_id": event.session_id,
        "content_preview": redact_text((event.content or "")[:400]),
        "arguments_preview": redact_text(str(event.arguments)[:400]) if event.arguments else "",
        "timestamp": event.timestamp,
    }


event_summary = _event_summary
