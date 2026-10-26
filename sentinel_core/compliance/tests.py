"""Continuous control tests (run hourly by EventBridge in AWS).

Each test inspects the *live* configuration and recent activity and returns
PASS / FAIL / WARN with the evidence that justifies the result — the same
model Vanta and Drata use for infrastructure controls, applied to agents.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..models import Mode, Severity
from ..policy import Policy
from ..store import Store
from .controls import CONTROL_INDEX, CONTROLS, FRAMEWORKS


@dataclass
class ComplianceContext:
    policy: Policy
    store: Store
    now: float = field(default_factory=time.time)
    # Results of AWS-side checks gathered by the scheduler Lambda, e.g.
    # {"evidence_object_lock": True, "cloudtrail_data_events": True, "evidence_chain_ok": True}
    aws: dict[str, Any] = field(default_factory=dict)
    alert_sla_seconds: dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 3600, "HIGH": 4 * 3600, "MEDIUM": 72 * 3600})


@dataclass
class TestResult:
    control_id: str
    status: str                  # PASS | FAIL | WARN
    checks: list[dict[str, Any]]
    tested_at: float

    def to_dict(self) -> dict[str, Any]:
        c = CONTROL_INDEX[self.control_id]
        return {"control_id": self.control_id, "name": c.name, "status": self.status,
                "checks": self.checks, "tested_at": self.tested_at,
                "frameworks": c.frameworks}


class _Checks:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def check(self, name: str, ok: bool, detail: str = "", warn_only: bool = False) -> None:
        status = "PASS" if ok else ("WARN" if warn_only else "FAIL")
        self.items.append({"check": name, "status": status, "detail": detail})

    @property
    def status(self) -> str:
        sts = {i["status"] for i in self.items}
        return "FAIL" if "FAIL" in sts else "WARN" if "WARN" in sts else "PASS"


def _mode_of(policy: Policy, rule_id: str, default_sev: Severity) -> Mode:
    o = policy.override(rule_id)
    if o and not o.enabled:
        return Mode.LOG - 1  # type: ignore[operator]  # sentinel value: disabled
    if o and o.mode is not None:
        return o.mode
    return policy.mode_for(o.severity if o and o.severity else default_sev)


def _rule_enabled(policy: Policy, rule_id: str) -> bool:
    o = policy.override(rule_id)
    return o is None or o.enabled


def _stale_alerts(ctx: ComplianceContext, rule_prefixes: tuple[str, ...]) -> list[dict[str, Any]]:
    stale = []
    for a in ctx.store.list_alerts(status="OPEN", limit=1000):
        if not a.get("rule_id", "").startswith(rule_prefixes):
            continue
        sla = ctx.alert_sla_seconds.get(a["severity"])
        if sla and ctx.now - float(a["created_at"]) > sla:
            stale.append(a)
    return stale


# ---------------------------------------------------------------- tests


def t_inventory(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    agents = list(ctx.policy.agents.values())
    c.check("agents registered", bool(agents), f"{len(agents)} agents in inventory")
    missing_owner = [a.agent_id for a in agents if not a.owner]
    c.check("every agent has an owner", not missing_owner, f"missing: {missing_owner}" if missing_owner else "")
    missing_desc = [a.agent_id for a in agents if not a.description]
    c.check("every agent has a documented purpose", not missing_desc,
            f"missing: {missing_desc}" if missing_desc else "")
    c.check("unregistered agents are blocked",
            ctx.policy.unknown_agent_mode >= Mode.BLOCK,
            f"unknown_agent mode = {ctx.policy.unknown_agent_mode.name}")
    recent_unknown = [d for d in ctx.store.list_decisions(limit=500, since=ctx.now - 86400)
                      if any(f["rule_id"] == "agent.unregistered" for f in d["findings"])]
    c.check("no unregistered agent activity in 24h", not recent_unknown,
            f"{len(recent_unknown)} attempts by unregistered agents", warn_only=True)
    return c


def t_least_privilege(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    wildcard = [a.agent_id for a in ctx.policy.agents.values()
                for p in a.permissions if "*" in p.actions and any(r in ("*", "**") for r in p.resources)]
    c.check("no agent has wildcard access to everything", not wildcard,
            f"wildcard grants: {wildcard}" if wildcard else "")
    unbounded = []
    for a in ctx.policy.agents.values():
        for p in a.permissions:
            touches_restricted = any(
                (cl := ctx.policy.classify(r.replace("**", "x").replace("*", "x"))) and cl.level >= 4
                for r in p.resources)
            if touches_restricted and {"read", "list", "*"} & set(p.actions) and not p.max_records_per_action:
                unbounded.append(a.agent_id)
    c.check("restricted-data reads are bounded per action", not unbounded,
            f"unbounded: {sorted(set(unbounded))}" if unbounded else "")
    c.check("unauthorised access rule enforced",
            _rule_enabled(ctx.policy, "access.unauthorized") and _rule_enabled(ctx.policy, "access.clearance_exceeded"))
    stale = _stale_alerts(ctx, ("access.",))
    c.check("access alerts triaged within SLA", not stale, f"{len(stale)} overdue")
    return c


def t_dlp(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    m = _mode_of(ctx.policy, "dlp.pii_exfiltration", Severity.CRITICAL)
    c.check("PII exfiltration is blocked", m >= Mode.BLOCK, f"mode = {getattr(m, 'name', 'DISABLED')}")
    m2 = _mode_of(ctx.policy, "dlp.pii_in_outbound", Severity.HIGH)
    c.check("PII in outbound data is at least flagged", m2 >= Mode.FLAG, f"mode = {getattr(m2, 'name', 'DISABLED')}")
    stale = _stale_alerts(ctx, ("dlp.",))
    c.check("DLP alerts triaged within SLA", not stale, f"{len(stale)} overdue")
    return c


def t_egress(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    allowed = ctx.policy.allowed_egress
    c.check("egress allow-list defined", bool(allowed), f"{len(allowed)} destinations")
    c.check("egress allow-list has no global wildcard", not any(d.strip() in ("*", "*.*") for d in allowed))
    m = _mode_of(ctx.policy, "egress.unapproved_destination", Severity.HIGH)
    c.check("unapproved egress held or blocked", m >= Mode.HOLD, f"mode = {getattr(m, 'name', 'DISABLED')}")
    return c


def t_privilege(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    m = _mode_of(ctx.policy, "iam.privilege_escalation", Severity.CRITICAL)
    c.check("privilege escalation blocked", m >= Mode.BLOCK, f"mode = {getattr(m, 'name', 'DISABLED')}")
    iam_grants = [a.agent_id for a in ctx.policy.agents.values()
                  for p in a.permissions if "iam" in p.actions or "*" in p.actions]
    c.check("no agent is granted IAM actions", not iam_grants,
            f"agents with iam/* grants: {iam_grants}" if iam_grants else "", warn_only=True)
    return c


def t_secrets(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    m = _mode_of(ctx.policy, "dlp.secret_leak", Severity.CRITICAL)
    c.check("secret leakage blocked", m >= Mode.BLOCK, f"mode = {getattr(m, 'name', 'DISABLED')}")
    return c


def t_behaviour(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    c.check("anomaly detection enabled", bool(ctx.policy.anomaly.get("enabled", True)))
    no_limits = [a.agent_id for a in ctx.policy.agents.values()
                 if a.risk_tier in ("high", "critical")
                 and not (a.rate_limits.actions_per_minute and a.rate_limits.records_per_hour)]
    c.check("high-risk agents have rate limits", not no_limits,
            f"missing limits: {no_limits}" if no_limits else "")
    stale = _stale_alerts(ctx, ("rate.", "anomaly."))
    c.check("behaviour alerts triaged within SLA", not stale, f"{len(stale)} overdue")
    return c


def t_injection(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    m = _mode_of(ctx.policy, "injection.prompt_injection", Severity.HIGH)
    c.check("prompt-injection detection active", m >= Mode.FLAG, f"mode = {getattr(m, 'name', 'DISABLED')}")
    c.check("injected actions held or blocked", m >= Mode.HOLD, warn_only=True)
    return c


def t_oversight(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    c.check("HIGH severity requires human approval or stricter",
            ctx.policy.mode_for(Severity.HIGH) >= Mode.HOLD,
            f"HIGH -> {ctx.policy.mode_for(Severity.HIGH).name}")
    c.check("held actions fail closed within 24h", 0 < ctx.policy.hold_timeout_seconds <= 86400,
            f"timeout {ctx.policy.hold_timeout_seconds}s")
    resolved = [a for a in ctx.store.list_approvals(status=None, limit=500)
                if a["status"] in ("APPROVED", "REJECTED")]
    self_approved = [a["approval_id"] for a in resolved
                     if (a.get("resolved_by") or "") in (a["agent_id"], f"agent:{a['agent_id']}")]
    c.check("no agent approved its own action", not self_approved, f"{self_approved}" if self_approved else "")
    no_actor = [a["approval_id"] for a in resolved if not a.get("resolved_by")]
    c.check("every approval records a human approver", not no_actor)
    quarantined = [k for k, v in ctx.store.list_agent_states().items() if v["status"] == "QUARANTINED"]
    c.check("no agents quarantined awaiting review", not quarantined,
            f"quarantined: {quarantined}" if quarantined else "", warn_only=True)
    return c


def t_health(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    hb = ctx.store.get_heartbeats()
    required = [a for a in ctx.policy.agents.values() if a.heartbeat_seconds]
    late = [a.agent_id for a in required
            if a.agent_id not in hb or ctx.now - hb[a.agent_id]["at"] > a.heartbeat_seconds * 2]
    c.check("agents with heartbeats are reporting", not late, f"late/missing: {late}" if late else "",
            warn_only=True)
    no_hb = [a.agent_id for a in ctx.policy.agents.values()
             if a.risk_tier in ("high", "critical") and not a.heartbeat_seconds]
    c.check("high-risk agents have heartbeat monitoring", not no_hb, f"{no_hb}" if no_hb else "")
    return c


def t_audit(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    if "evidence_object_lock" in ctx.aws:
        c.check("evidence bucket has Object Lock (COMPLIANCE)", bool(ctx.aws["evidence_object_lock"]),
                str(ctx.aws.get("evidence_object_lock_detail", "")))
    else:
        c.check("evidence bucket has Object Lock (COMPLIANCE)", False, "not verified in this environment",
                warn_only=True)
    if "evidence_chain_ok" in ctx.aws:
        c.check("evidence hash chain verifies", bool(ctx.aws["evidence_chain_ok"]),
                str(ctx.aws.get("evidence_chain_detail", "")))
    if "cloudtrail_data_events" in ctx.aws:
        c.check("CloudTrail data events on protected data", bool(ctx.aws["cloudtrail_data_events"]),
                str(ctx.aws.get("cloudtrail_detail", "")))
    m = _mode_of(ctx.policy, "bypass.unmediated_access", Severity.CRITICAL)
    c.check("guardrail bypass is blocked/quarantined", m >= Mode.BLOCK, f"mode = {getattr(m, 'name', 'DISABLED')}")
    return c


def t_alignment(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    j = ctx.policy.judge or {}
    c.check("task-alignment judge enabled", bool(j.get("enabled", False)))
    tiers = set(j.get("inline_for_risk_tiers", []))
    high = [a.agent_id for a in ctx.policy.agents.values()
            if a.risk_tier in ("high", "critical") and a.risk_tier not in tiers]
    c.check("judge covers all high-risk agents", not high, f"uncovered: {high}" if high else "")
    if "judge_available" in ctx.aws:
        c.check("judge model reachable", bool(ctx.aws["judge_available"]),
                str(ctx.aws.get("judge_detail", "")), warn_only=True)
    return c


def t_output_validation(ctx: ComplianceContext) -> _Checks:
    c = _Checks()
    checks = ctx.policy.output_checks
    c.check("decision validation rules defined", bool(checks),
            f"{len(checks)} output check(s)" if checks else "no output checks in policy", warn_only=True)
    m = _mode_of(ctx.policy, "output.loan_policy_breach", Severity.HIGH)
    c.check("rule-breaking decisions held or blocked", m >= Mode.HOLD,
            f"mode = {getattr(m, 'name', 'DISABLED')}")
    stale = _stale_alerts(ctx, ("output.",))
    c.check("decision alerts triaged within SLA", not stale, f"{len(stale)} overdue")
    return c


TESTS: dict[str, Callable[[ComplianceContext], _Checks]] = {
    "AGT-01": t_inventory, "AGT-02": t_least_privilege, "AGT-03": t_dlp, "AGT-04": t_egress,
    "AGT-05": t_privilege, "AGT-06": t_secrets, "AGT-07": t_behaviour, "AGT-08": t_injection,
    "AGT-09": t_oversight, "AGT-10": t_health, "AGT-11": t_audit, "AGT-12": t_alignment,
    "AGT-13": t_output_validation,
}


def run_all(ctx: ComplianceContext) -> list[TestResult]:
    out = []
    for control in CONTROLS:
        fn = TESTS[control.id]
        try:
            checks = fn(ctx)
            out.append(TestResult(control.id, checks.status, checks.items, ctx.now))
        except Exception as exc:  # a broken test is a failing control, not a crash
            out.append(TestResult(control.id, "FAIL",
                                  [{"check": "test execution", "status": "FAIL", "detail": str(exc)[:300]}],
                                  ctx.now))
    return out


def framework_scores(results: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per-framework readiness: share of mapped controls currently passing."""
    scores = {}
    for fw, label in FRAMEWORKS.items():
        mapped = [c for c in CONTROLS if fw in c.frameworks]
        passing = [c.id for c in mapped if results.get(c.id, {}).get("status") == "PASS"]
        warning = [c.id for c in mapped if results.get(c.id, {}).get("status") == "WARN"]
        failing = [c.id for c in mapped if results.get(c.id, {}).get("status") == "FAIL"]
        untested = [c.id for c in mapped if c.id not in results]
        req = sorted({r for c in mapped for r in c.frameworks[fw]})
        scores[fw] = {
            "framework": label, "controls": len(mapped), "passing": passing, "warning": warning,
            "failing": failing, "untested": untested, "requirements": req,
            "score": round(100 * (len(passing) + 0.5 * len(warning)) / len(mapped)) if mapped else 0,
        }
    return scores
