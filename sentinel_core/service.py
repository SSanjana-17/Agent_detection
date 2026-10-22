"""SentinelService: the application layer behind every API.

Transport-independent: the AWS Lambda handlers, the local development server
and the tests all call this class. It owns identity checks, the decision
engine, alerting, evidence, approvals, quarantine and compliance views.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .alerts import AlertRouter
from .compliance import (CONTROL_INDEX, CONTROLS, DEFAULT_RISKS, FRAMEWORKS,
                         ComplianceContext, evaluate_risk, framework_scores,
                         run_all)
from .engine import DecisionEngine
from .health import evaluate_health
from .judge import LLMJudge
from .models import (ActionEvent, AgentStatus, ApprovalStatus, Decision,
                     Finding, Mode, Severity, Verdict)
from .policy import Policy
from .rules import C_INVENTORY
from .store import Store

log = logging.getLogger(__name__)

APPROVER_GROUP = "sentinel-approvers"
ADMIN_GROUP = "sentinel-admins"


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Identity:
    kind: str                      # "agent" | "human" | "local" | "system"
    principal: str = ""            # IAM ARN for agents, email/username for humans
    groups: list[str] = field(default_factory=list)

    @property
    def is_human(self) -> bool:
        return self.kind in ("human", "local")

    def require_group(self, *groups: str) -> None:
        if self.kind == "local":
            return
        if self.kind != "human" or not (set(groups) & set(self.groups)):
            raise ApiError(403, f"requires membership of {' or '.join(groups)}")

    def require_human(self) -> None:
        if not self.is_human:
            raise ApiError(403, "console endpoints require a signed-in human user")


class EvidenceSink(Protocol):
    def __call__(self, rtype: str, payload: dict[str, Any], partition: str) -> None: ...


class ApprovalWorkflow(Protocol):
    def start(self, approval: dict[str, Any]) -> None: ...

    def complete(self, approval: dict[str, Any]) -> None: ...


class SentinelService:
    def __init__(self, policy_provider: Callable[[], Policy], store: Store,
                 judge_factory: Callable[[Policy], LLMJudge | None] | None = None,
                 alert_router: AlertRouter | None = None,
                 evidence_sink: EvidenceSink | None = None,
                 approval_workflow: ApprovalWorkflow | None = None,
                 dashboard_url: str = "", clock: Callable[[], float] = time.time) -> None:
        self.policy_provider = policy_provider
        self.store = store
        self.judge_factory = judge_factory
        self.alerts = alert_router
        self.evidence = evidence_sink
        self.workflow = approval_workflow
        self.dashboard_url = dashboard_url
        self.clock = clock
        self._engine: DecisionEngine | None = None
        self._engine_fp: str | None = None

    # -------------------------------------------------------------- engine
    @property
    def policy(self) -> Policy:
        return self.policy_provider()

    @property
    def engine(self) -> DecisionEngine:
        pol = self.policy
        if self._engine is None or self._engine_fp != pol.fingerprint:
            judge = self.judge_factory(pol) if self.judge_factory else None
            eng = DecisionEngine(pol, self.store, judge=judge, clock=self.clock)
            eng.on_decision(self._after_decision)
            if self._engine_fp is not None and self._engine_fp != pol.fingerprint:
                self._emit("policy_change", {"from": self._engine_fp, "to": pol.fingerprint,
                                             "organization": pol.organization}, "policy")
            self._engine, self._engine_fp = eng, pol.fingerprint
        return self._engine

    def _emit(self, rtype: str, payload: dict[str, Any], partition: str) -> None:
        if self.evidence is None:
            return
        try:
            self.evidence(rtype, payload, partition)
        except Exception:
            log.exception("evidence emit failed (%s)", rtype)

    def _after_decision(self, d: Decision, ev: ActionEvent) -> None:
        if d.mode >= Mode.FLAG:
            if self.alerts:
                self.alerts.handle(d, ev)
            self._emit("decision", {"decision": d.to_dict(), "event": _evidence_event(ev)}, d.agent_id)
        if d.verdict == Verdict.HOLD and d.approval_id and self.workflow:
            ap = self.store.get_approval(d.approval_id)
            if ap:
                try:
                    self.workflow.start(ap)
                except Exception:
                    log.exception("could not start approval workflow for %s", d.approval_id)
        if d.mode == Mode.QUARANTINE:
            self._emit("quarantine", {"agent_id": d.agent_id, "decision_id": d.decision_id,
                                      "reason": d.reason, "actor": "sentinel"}, d.agent_id)

    # ---------------------------------------------------------- agent APIs
    def _check_identity(self, ev: ActionEvent, ident: Identity) -> Decision | None:
        """An agent may only act as itself: the IAM caller must map to agent_id."""
        if ident.kind != "agent":
            return None
        pol = self.policy
        mapped = pol.agent_for_principal(ident.principal) if ident.principal else None
        if mapped is not None and mapped.agent_id == ev.agent_id:
            return None
        claimed = pol.agents.get(ev.agent_id)
        if mapped is None and claimed is not None and not claimed.principals:
            return None  # agent has no principal binding configured
        detail = (f"Caller '{ident.principal}' is registered as '{mapped.agent_id}' but claimed to be "
                  f"'{ev.agent_id}'." if mapped else
                  f"Caller '{ident.principal}' is not bound to agent '{ev.agent_id}'.")
        f = Finding(detector="identity", rule_id="identity.spoofing", severity=Severity.CRITICAL,
                    mode=Mode.BLOCK, title="Agent identity mismatch", detail=detail,
                    controls=[C_INVENTORY])
        d = Decision(event_id=ev.event_id, agent_id=ev.agent_id, verdict=Verdict.DENY,
                     mode=Mode.BLOCK, severity=Severity.CRITICAL, findings=[f], reason=f.title)
        self.store.put_decision(d, ev)
        self._after_decision(d, ev)
        if mapped is not None:  # the real agent tried to impersonate another: quarantine it
            self.store.set_agent_status(mapped.agent_id, AgentStatus.QUARANTINED,
                                        f"impersonated '{ev.agent_id}' (decision {d.decision_id})",
                                        "sentinel")
            self._emit("quarantine", {"agent_id": mapped.agent_id, "decision_id": d.decision_id,
                                      "reason": "identity spoofing", "actor": "sentinel"}, mapped.agent_id)
        return d

    def decide(self, body: dict[str, Any], ident: Identity) -> dict[str, Any]:
        try:
            ev = ActionEvent.from_dict(body)
        except (TypeError, ValueError) as exc:
            raise ApiError(400, f"invalid event: {exc}")
        if ident.kind == "agent" and ident.principal and not ev.principal:
            ev.principal = ident.principal
        spoof = self._check_identity(ev, ident)
        if spoof is not None:
            return spoof.to_dict()
        return self.engine.decide(ev).to_dict()

    def report(self, body: dict[str, Any], ident: Identity) -> dict[str, Any]:
        """Post-execution events (tool results, outputs). Analysed, never blocking."""
        events = body.get("events") if isinstance(body.get("events"), list) else [body]
        out = []
        for raw in events[:100]:
            raw = dict(raw)
            raw["phase"] = "post"
            res = self.decide(raw, ident)
            out.append({"event_id": res["event_id"], "mode": res["mode"], "severity": res["severity"]})
        return {"accepted": len(out), "results": out}

    def ingest_cloudtrail(self, detail: dict[str, Any]) -> dict[str, Any] | None:
        """Turn a CloudTrail S3 data event into a Sentinel event and decide on it."""
        ev = cloudtrail_to_event(detail, self.policy)
        if ev is None:
            return None
        return self.engine.decide(ev).to_dict()

    def heartbeat(self, body: dict[str, Any], ident: Identity) -> dict[str, Any]:
        agent_id = str(body.get("agent_id", ""))
        if not agent_id:
            raise ApiError(400, "agent_id required")
        if ident.kind == "agent" and ident.principal:
            mapped = self.policy.agent_for_principal(ident.principal)
            if mapped and mapped.agent_id != agent_id:
                raise ApiError(403, "heartbeat identity mismatch")
        self.store.record_heartbeat(agent_id, self.clock(), str(body.get("task_id", "")),
                                    str(body.get("status", "ok")), str(body.get("detail", "")))
        status, reason = self.store.get_agent_status(agent_id)
        return {"agent_id": agent_id, "status": status.value, "reason": reason}

    def approval_status(self, approval_id: str, ident: Identity) -> dict[str, Any]:
        ap = self.store.get_approval(approval_id)
        if not ap:
            raise ApiError(404, "approval not found")
        if ident.kind == "agent" and ident.principal:
            mapped = self.policy.agent_for_principal(ident.principal)
            if mapped and mapped.agent_id != ap["agent_id"]:
                raise ApiError(403, "not your approval")
        return {k: ap[k] for k in ("approval_id", "status", "agent_id", "decision_id", "expires_at",
                                   "resolved_by", "resolved_at", "comment") if k in ap}

    # -------------------------------------------------------- human APIs
    def resolve_approval(self, approval_id: str, approve: bool, comment: str,
                         ident: Identity) -> dict[str, Any]:
        ident.require_group(APPROVER_GROUP, ADMIN_GROUP)
        ap = self.store.get_approval(approval_id)
        if not ap:
            raise ApiError(404, "approval not found")
        if ident.principal and ident.principal in (ap["agent_id"], f"agent:{ap['agent_id']}"):
            raise ApiError(403, "an agent cannot approve its own action")
        status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
        try:
            ap = self.store.resolve_approval(approval_id, status, ident.principal or "local", comment)
        except ValueError as exc:
            raise ApiError(409, str(exc))
        if self.workflow:
            try:
                self.workflow.complete(ap)
            except Exception:
                log.exception("workflow completion failed for %s", approval_id)
        self._emit("approval", {"approval_id": approval_id, "status": status.value,
                                "actor": ident.principal or "local", "comment": comment[:500],
                                "agent_id": ap["agent_id"], "decision_id": ap["decision_id"]},
                   ap["agent_id"])
        ap.pop("task_token", None)
        return ap

    def set_quarantine(self, agent_id: str, quarantine: bool, reason: str,
                       ident: Identity) -> dict[str, Any]:
        ident.require_group(APPROVER_GROUP, ADMIN_GROUP)
        if not reason.strip():
            raise ApiError(400, "a reason is required")
        status = AgentStatus.QUARANTINED if quarantine else AgentStatus.ACTIVE
        actor = ident.principal or "local"
        self.store.set_agent_status(agent_id, status, reason, actor)
        self._emit("quarantine" if quarantine else "release",
                   {"agent_id": agent_id, "reason": reason[:500], "actor": actor}, agent_id)
        return {"agent_id": agent_id, "status": status.value, "reason": reason, "changed_by": actor}

    def update_alert(self, alert_id: str, status: str, note: str, ident: Identity) -> dict[str, Any]:
        ident.require_human()
        status = status.upper()
        if status not in ("OPEN", "ACKNOWLEDGED", "RESOLVED"):
            raise ApiError(400, "status must be OPEN, ACKNOWLEDGED or RESOLVED")
        try:
            rec = self.store.update_alert(alert_id, status, ident.principal or "local", note)
        except KeyError:
            raise ApiError(404, "alert not found")
        self._emit("alert_update", {"alert_id": alert_id, "status": status,
                                    "actor": ident.principal or "local", "note": note[:500]},
                   rec.get("agent_id", "alerts"))
        return rec

    def agents_view(self) -> list[dict[str, Any]]:
        pol = self.policy
        states = self.store.list_agent_states()
        hbs = self.store.get_heartbeats()
        now = self.clock()
        recent = self.store.list_decisions(limit=1000, since=now - 86400)
        counts: dict[str, dict[str, int]] = {}
        for d in recent:
            c = counts.setdefault(d["agent_id"], {"actions": 0, "flagged": 0, "blocked": 0, "held": 0})
            c["actions"] += 1
            if Mode[d["mode"]] >= Mode.FLAG:
                c["flagged"] += 1
            if d["verdict"] == "DENY":
                c["blocked"] += 1
            if d["verdict"] == "HOLD":
                c["held"] += 1
        out = []
        ids = set(pol.agents) | set(states) | set(counts)
        for aid in sorted(ids):
            a = pol.agents.get(aid)
            st = states.get(aid, {})
            hb = hbs.get(aid)
            out.append({
                "agent_id": aid, "registered": a is not None,
                "description": a.description if a else "", "owner": a.owner if a else "",
                "risk_tier": a.risk_tier if a else "unknown",
                "clearance": a.max_clearance if a else None,
                "status": st.get("status", "ACTIVE"), "status_reason": st.get("reason", ""),
                "last_heartbeat": hb["at"] if hb else None,
                "heartbeat_seconds": a.heartbeat_seconds if a else None,
                "healthy": (not a or not a.heartbeat_seconds or
                            (hb is not None and now - hb["at"] <= a.heartbeat_seconds * 2)),
                "activity_24h": counts.get(aid, {"actions": 0, "flagged": 0, "blocked": 0, "held": 0}),
                "permissions": [{"actions": p.actions, "resources": p.resources,
                                 "max_records_per_action": p.max_records_per_action,
                                 "requires_approval": p.requires_approval}
                                for p in (a.permissions if a else [])],
            })
        return out

    def overview(self) -> dict[str, Any]:
        now = self.clock()
        decisions = self.store.list_decisions(limit=2000, since=now - 86400)
        alerts = self.store.list_alerts(status="OPEN", limit=500)
        pending = self.store.list_approvals(status="PENDING", limit=200)
        results = self.store.latest_control_results()
        agents = self.agents_view()
        by_sev: dict[str, int] = {}
        for a in alerts:
            by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
        timeline: dict[int, dict[str, int]] = {}
        for d in decisions:
            h = int(d["timestamp"] // 3600) * 3600
            t = timeline.setdefault(h, {"allowed": 0, "flagged": 0, "held": 0, "blocked": 0})
            if d["verdict"] == "DENY":
                t["blocked"] += 1
            elif d["verdict"] == "HOLD":
                t["held"] += 1
            elif Mode[d["mode"]] >= Mode.FLAG:
                t["flagged"] += 1
            else:
                t["allowed"] += 1
        p95 = sorted(d["latency_ms"] for d in decisions)
        return {
            "generated_at": now,
            "agents": {"total": len(agents),
                       "quarantined": sum(1 for a in agents if a["status"] == "QUARANTINED"),
                       "unhealthy": sum(1 for a in agents if not a["healthy"]),
                       "unregistered": sum(1 for a in agents if not a["registered"])},
            "decisions_24h": {"total": len(decisions),
                              "blocked": sum(1 for d in decisions if d["verdict"] == "DENY"),
                              "held": sum(1 for d in decisions if d["verdict"] == "HOLD"),
                              "flagged": sum(1 for d in decisions
                                             if d["verdict"] == "ALLOW" and Mode[d["mode"]] >= Mode.FLAG),
                              "p95_latency_ms": round(p95[int(len(p95) * 0.95)] if p95 else 0, 2)},
            "open_alerts": {"total": len(alerts), "by_severity": by_sev},
            "pending_approvals": len(pending),
            "compliance": {fw: {"score": s["score"], "framework": s["framework"]}
                           for fw, s in framework_scores(results).items()},
            "controls": {"passing": sum(1 for r in results.values() if r["status"] == "PASS"),
                         "failing": sum(1 for r in results.values() if r["status"] == "FAIL"),
                         "warning": sum(1 for r in results.values() if r["status"] == "WARN"),
                         "total": len(CONTROLS)},
            "timeline": [{"hour": h, **v} for h, v in sorted(timeline.items())],
        }

    def compliance_view(self) -> dict[str, Any]:
        results = self.store.latest_control_results()
        controls = []
        for c in CONTROLS:
            r = results.get(c.id)
            controls.append({"id": c.id, "name": c.name, "objective": c.objective,
                             "owner_role": c.owner_role, "frameworks": c.frameworks,
                             "status": r["status"] if r else "UNTESTED",
                             "checks": r["checks"] if r else [],
                             "tested_at": r["tested_at"] if r else None})
        return {"frameworks": framework_scores(results), "controls": controls,
                "framework_names": FRAMEWORKS}

    def control_detail(self, control_id: str) -> dict[str, Any]:
        c = CONTROL_INDEX.get(control_id)
        if not c:
            raise ApiError(404, "unknown control")
        return {"id": c.id, "name": c.name, "objective": c.objective, "owner_role": c.owner_role,
                "frameworks": c.frameworks, "history": self.store.control_history(control_id)}

    def risks_view(self) -> list[dict[str, Any]]:
        results = self.store.latest_control_results()
        risks = self.store.list_risks() or DEFAULT_RISKS
        return sorted((evaluate_risk(r, results) for r in risks),
                      key=lambda r: r["residual_score"], reverse=True)

    def upsert_risk(self, body: dict[str, Any], ident: Identity) -> dict[str, Any]:
        ident.require_group(ADMIN_GROUP, APPROVER_GROUP)
        required = ("risk_id", "title", "likelihood", "impact", "controls")
        missing = [k for k in required if k not in body]
        if missing:
            raise ApiError(400, f"missing fields: {missing}")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(body["risk_id"])):
            raise ApiError(400, "invalid risk_id")
        for k in ("likelihood", "impact"):
            if not 1 <= int(body[k]) <= 5:
                raise ApiError(400, f"{k} must be 1-5")
        unknown = [c for c in body["controls"] if c not in CONTROL_INDEX]
        if unknown:
            raise ApiError(400, f"unknown controls: {unknown}")
        if not self.store.list_risks():
            for r in DEFAULT_RISKS:
                self.store.put_risk(r)
        risk = {k: body[k] for k in ("risk_id", "title", "description", "likelihood", "impact",
                                     "controls", "owner", "treatment") if k in body}
        risk["updated_by"] = ident.principal or "local"
        self.store.put_risk(risk)
        self._emit("risk_update", risk, "risks")
        return evaluate_risk(risk, self.store.latest_control_results())

    def policy_view(self) -> dict[str, Any]:
        pol = self.policy
        return {"fingerprint": pol.fingerprint, "organization": pol.organization,
                "version": pol.version, "document": pol.raw}

    # --------------------------------------------------------- scheduled
    _HEALTH_RULES = ("health.heartbeat_missed", "health.never_reported", "health.agent_error")

    def run_health_checks(self) -> list[dict[str, Any]]:
        """Raise one alert when an agent becomes unhealthy, none while it stays that way,
        and resolve it automatically when the agent recovers."""
        now = self.clock()
        out = []
        open_alerts: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for status in ("OPEN", "ACKNOWLEDGED"):
            for a in self.store.list_alerts(status=status, limit=1000):
                if a.get("rule_id") in self._HEALTH_RULES:
                    open_alerts.setdefault((a["agent_id"], a["rule_id"]), []).append(a)

        current = evaluate_health(self.policy, self.store.get_heartbeats(), now)
        still_failing = {(agent_id, f.rule_id) for agent_id, f in current}
        for key, alerts in open_alerts.items():
            if key not in still_failing:
                for a in alerts:
                    try:
                        self.store.update_alert(a["alert_id"], "RESOLVED", "sentinel:auto",
                                                "Agent is healthy again; resolved automatically.")
                    except KeyError:
                        pass

        for agent_id, finding in current:
            if (agent_id, finding.rule_id) in open_alerts:
                continue  # already alerted; don't repeat every minute
            ev = ActionEvent(agent_id=agent_id, action="heartbeat", source="heartbeat",
                             phase="post", resource=f"agent://{agent_id}")
            mode = self.policy.mode_for(finding.severity)
            mode = min(mode, Mode.FLAG)  # health problems alert; they never quarantine
            d = Decision(event_id=ev.event_id, agent_id=agent_id, verdict=Verdict.ALLOW,
                         mode=mode, severity=finding.severity, findings=[finding], reason=finding.title)
            self.store.put_decision(d, ev)
            if self.alerts:
                self.alerts.handle(d, ev)
            out.append(d.to_dict())
        return out

    def run_control_tests(self, aws_checks: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        ctx = ComplianceContext(policy=self.policy, store=self.store, now=self.clock(),
                                aws=aws_checks or {})
        results = [r.to_dict() for r in run_all(ctx)]
        for r in results:
            self.store.put_control_result(r)
            self._emit("control_test", r, "controls")
        return results


# ------------------------------------------------------------------ helpers


def _evidence_event(ev: ActionEvent) -> dict[str, Any]:
    from .store import event_summary
    return event_summary(ev)


_CT_ACTIONS = {
    "GetObject": ("read", 1), "HeadObject": ("read", 1), "SelectObjectContent": ("read", 1),
    "GetObjectAttributes": ("read", 1), "ListObjects": ("list", 1), "ListObjectsV2": ("list", 1),
    "PutObject": ("write", 1), "CopyObject": ("write", 1), "CompleteMultipartUpload": ("write", 1),
    "DeleteObject": ("delete", 1), "DeleteObjects": ("delete", 1),
    "PutObjectAcl": ("iam", 1), "PutBucketPolicy": ("iam", 1),
}


def cloudtrail_to_event(detail: dict[str, Any], policy: Policy) -> ActionEvent | None:
    name = detail.get("eventName", "")
    if name not in _CT_ACTIONS:
        return None
    params = detail.get("requestParameters") or {}
    bucket = params.get("bucketName", "")
    key = params.get("key", "")
    if not bucket:
        return None
    resource = f"s3://{bucket}/{key}" if key else f"s3://{bucket}"
    ui = detail.get("userIdentity") or {}
    arn = ui.get("arn", "") or (ui.get("sessionContext", {}).get("sessionIssuer", {}) or {}).get("arn", "")
    # Only care about data Sentinel classifies, otherwise every S3 read is noise.
    cls = policy.classify(resource)
    if cls is None or cls.level < 2:
        return None
    agent = policy.agent_for_principal(arn) if arn else None
    action, _ = _CT_ACTIONS[name]
    return ActionEvent(
        agent_id=agent.agent_id if agent else f"principal:{arn or 'unknown'}",
        action=action, tool=f"s3:{name}", resource=resource, phase="post",
        source="cloudtrail", principal=arn,
        timestamp=_ct_time(detail.get("eventTime")),
        metadata={"cloudtrail_event_id": detail.get("eventID", ""),
                  "source_ip": detail.get("sourceIPAddress", ""),
                  "user_agent": (detail.get("userAgent") or "")[:200]})


def _ct_time(s: str | None) -> float:
    if not s:
        return time.time()
    import datetime as dt
    try:
        return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return time.time()
