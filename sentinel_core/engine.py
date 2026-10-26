"""The decision engine: combines every detection layer into one verdict.

Pipeline for each action:

1. quarantine check   - a quarantined agent is denied outright
2. rules              - policy, classification, DLP, egress, privilege (deterministic)
3. behaviour          - rate limits, baselines, novelty, off-hours, loops
4. injection          - untrusted inputs scanned for instruction injection
5. LLM judge          - inline for high-risk agents on sensitive actions
6. policy overrides   - per-rule enable/severity/mode from the policy file
7. response           - strictest mode wins: LOG < FLAG < HOLD < BLOCK < QUARANTINE

Side-effects (quarantining, approvals, activity counters, alerts, evidence)
happen here or in registered ``on_decision`` hooks, so the same engine runs
in Lambda, the local server and the embedded SDK.
"""
from __future__ import annotations

import concurrent.futures as cf
import logging
import time
from typing import Callable

from .anomaly import evaluate_behavior
from .injection import evaluate_injection
from .validators import evaluate_outputs
from .judge import LLMJudge
from .models import (ActionEvent, AgentStatus, Decision, Finding, Mode,
                     Severity, Verdict)
from .policy import Policy
from .rules import C_AUDIT, C_INVENTORY, C_LEAST_PRIV, evaluate_rules
from .store import BehaviorSnapshot, Store

log = logging.getLogger(__name__)

DecisionHook = Callable[[Decision, ActionEvent], None]

_JUDGE_POOL = cf.ThreadPoolExecutor(max_workers=8, thread_name_prefix="sentinel-judge")


class DecisionEngine:
    def __init__(self, policy: Policy, store: Store, judge: LLMJudge | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.policy = policy
        self.store = store
        self.judge = judge
        self.clock = clock
        self.hooks: list[DecisionHook] = []

    def on_decision(self, hook: DecisionHook) -> None:
        self.hooks.append(hook)

    # ------------------------------------------------------------------ main
    def decide(self, ev: ActionEvent) -> Decision:
        t0 = time.perf_counter()
        now = self.clock()
        findings: list[Finding] = []

        status, reason = self.store.get_agent_status(ev.agent_id)
        if status in (AgentStatus.QUARANTINED, AgentStatus.DISABLED):
            findings.append(Finding(
                detector="engine", rule_id="agent.quarantined", severity=Severity.CRITICAL,
                mode=Mode.BLOCK, title=f"Agent is {status.value.lower()}",
                detail=f"'{ev.agent_id}' is {status.value}: {reason}. All actions are denied "
                       f"until a human releases it.",
                controls=[C_INVENTORY]))

        ctx, rule_findings = evaluate_rules(ev, self.policy)
        findings.extend(rule_findings)

        snap: BehaviorSnapshot | None = None
        area = self._area(ev, ctx)
        if ctx.agent is not None:
            try:
                snap = self.store.behavior_snapshot(ev.agent_id, ctx.resource, now, area=area)
                findings.extend(evaluate_behavior(ev, ctx.agent, self.policy, snap,
                                                  ctx.action, ctx.resource))
            except Exception as exc:
                log.exception("behaviour layer failed")
                findings.append(Finding(
                    detector="engine", rule_id="engine.behavior_unavailable", severity=Severity.LOW,
                    title="Behaviour layer unavailable", detail=str(exc)[:200]))

        findings.extend(evaluate_injection(ev))
        findings.extend(evaluate_outputs(ev, ctx.action, ctx.resource, self.policy.output_checks))

        if ev.source == "cloudtrail":
            findings.extend(self._bypass_findings(ev, ctx.agent is not None, ctx.resource, now))

        if (self.judge and ev.phase == "pre" and ev.source == "sdk"
                and self.judge.should_run_inline(ctx.agent, ctx.action, ctx.resource)
                and not any(f.severity >= Severity.CRITICAL for f in findings)):
            fut = _JUDGE_POOL.submit(self.judge.evaluate, ev, ctx.agent, ctx.action,
                                     ctx.resource, snap)
            try:
                findings.extend(fut.result(timeout=self.judge.inline_timeout_s))
            except cf.TimeoutError:
                findings.append(Finding(
                    detector="judge", rule_id="judge.timeout", severity=Severity.INFO,
                    title="LLM judge timed out",
                    detail=f"No verdict within {self.judge.inline_timeout_s*1000:.0f} ms; "
                           f"decision made on deterministic layers.", controls=[]))

        findings = self._apply_overrides(findings)
        decision = self._resolve(ev, findings)
        decision.latency_ms = (time.perf_counter() - t0) * 1000

        self._side_effects(decision, ev, ctx.action, ctx.resource, now, area)
        return decision

    def _area(self, ev: ActionEvent, ctx) -> str:
        """Stable 'kind of access' for novelty: data classification + permission grant used.

        Folder names (customer ids, application ids) churn constantly in normal work,
        so novelty is measured on *which grant on which class of data* an agent uses.
        """
        if not ctx.resource or ctx.agent is None:
            return ""
        cls = self.policy.classify(ctx.resource)
        perm = ctx.agent.find_permission(ctx.action, ctx.resource, ev.tool)
        idx = ctx.agent.permissions.index(perm) if perm else -1
        return f"{cls.name if cls else 'UNCLASSIFIED'}|{ctx.action}|grant{idx}"

    # -------------------------------------------------------------- helpers
    def _bypass_findings(self, ev: ActionEvent, known: bool, resource: str,
                         now: float) -> list[Finding]:
        """CloudTrail saw an access: was it mediated by Sentinel?"""
        if not known:
            if ev.principal and self.policy.is_trusted_principal(ev.principal):
                return []
            return [Finding(
                detector="cloudtrail", rule_id="bypass.unknown_principal", severity=Severity.HIGH,
                title="Protected data accessed by unmapped identity",
                detail=f"'{ev.principal}' accessed '{resource}' and is neither a registered agent "
                       f"nor a trusted principal.", controls=[C_AUDIT, C_LEAST_PRIV])]
        window = float(self.policy.raw.get("bypass_window_seconds", 300))
        if self.store.was_mediated(ev.agent_id, resource, now - window):
            return []
        return [Finding(
            detector="cloudtrail", rule_id="bypass.unmediated_access", severity=Severity.CRITICAL,
            title="Agent accessed data without going through Sentinel",
            detail=f"CloudTrail shows '{ev.agent_id}' ({ev.principal}) performing {ev.action} on "
                   f"'{resource}' with no matching Sentinel decision in the last {int(window)}s. "
                   f"The agent bypassed its guardrail.",
            controls=[C_AUDIT, C_LEAST_PRIV])]

    def _apply_overrides(self, findings: list[Finding]) -> list[Finding]:
        out = []
        for f in findings:
            o = self.policy.override(f.rule_id) or self.policy.override(f.rule_id.split(".")[0] + ".*")
            if o is not None:
                if not o.enabled:
                    continue
                if o.severity is not None:
                    f.severity = o.severity
                if o.mode is not None:
                    f.mode = o.mode
            out.append(f)
        return out

    def _resolve(self, ev: ActionEvent, findings: list[Finding]) -> Decision:
        if not findings:
            return Decision(event_id=ev.event_id, agent_id=ev.agent_id, verdict=Verdict.ALLOW,
                            mode=Mode.LOG, severity=Severity.INFO, reason="No policy concerns.")
        mode = max((f.mode if f.mode is not None else self.policy.mode_for(f.severity))
                   for f in findings)
        severity = max(f.severity for f in findings)
        if ev.phase != "pre":
            # Already happened: we can't hold or block it, so escalate visibility.
            verdict = Verdict.ALLOW
            if mode == Mode.HOLD or mode == Mode.BLOCK:
                mode = Mode.FLAG if severity < Severity.CRITICAL else Mode.QUARANTINE
        elif mode >= Mode.BLOCK:
            verdict = Verdict.DENY
        elif mode == Mode.HOLD:
            verdict = Verdict.HOLD
        else:
            verdict = Verdict.ALLOW
        ranked = sorted(findings, key=lambda f: f.severity, reverse=True)
        reason = "; ".join(f.title for f in ranked[:3] if f.severity > Severity.INFO) or ranked[0].title
        return Decision(event_id=ev.event_id, agent_id=ev.agent_id, verdict=verdict,
                        mode=mode, severity=severity, findings=ranked, reason=reason)

    def _side_effects(self, d: Decision, ev: ActionEvent, action: str, resource: str,
                      now: float, area: str | None = None) -> None:
        try:
            if d.mode == Mode.QUARANTINE:
                cur, _ = self.store.get_agent_status(ev.agent_id)
                if cur == AgentStatus.ACTIVE:
                    self.store.set_agent_status(ev.agent_id, AgentStatus.QUARANTINED,
                                                f"{d.reason} (decision {d.decision_id})",
                                                actor="sentinel")
            if d.verdict == Verdict.HOLD:
                d.approval_id = self.store.create_approval(
                    d, ev, expires_at=now + self.policy.hold_timeout_seconds)
            self.store.record_activity(ev, action, resource,
                                       mediated=(ev.source == "sdk" and d.verdict != Verdict.DENY),
                                       now=now,
                                       granted=(d.verdict == Verdict.ALLOW or ev.phase != "pre"),
                                       area=area)
            self.store.put_decision(d, ev)
        except Exception:
            log.exception("failed to persist decision side-effects")
            raise
        for hook in self.hooks:
            try:
                hook(d, ev)
            except Exception:
                log.exception("decision hook %s failed", getattr(hook, "__name__", hook))
