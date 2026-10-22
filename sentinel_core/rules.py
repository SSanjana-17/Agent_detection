"""Deterministic policy rules — the fast, explainable first line of defence.

Each rule inspects an ``ActionEvent`` against the ``Policy`` and returns zero
or more ``Finding`` objects. Rules never call the network, so they run inline
in the decision path in well under a millisecond.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .models import ActionEvent, ActionType, Finding, Severity
from .pii import HIGH_RISK_KINDS, scan_pii, scan_secrets
from .policy import (AgentPolicy, Policy, domain_allowed, domain_of,
                     normalize_resource)

# Compliance control ids (defined in compliance/controls.py)
C_INVENTORY = "AGT-01"
C_LEAST_PRIV = "AGT-02"
C_DLP = "AGT-03"
C_EGRESS = "AGT-04"
C_PRIV_MGMT = "AGT-05"
C_SECRETS = "AGT-06"
C_BEHAVIOUR = "AGT-07"
C_INJECTION = "AGT-08"
C_OVERSIGHT = "AGT-09"
C_HEALTH = "AGT-10"
C_AUDIT = "AGT-11"
C_ALIGNMENT = "AGT-12"

# ------------------------------------------------------------ action typing

_VERB_MAP: list[tuple[str, re.Pattern[str]]] = [
    (ActionType.IAM.value, re.compile(
        r"(?i)(iam|assume_?role|attach_?(user|role)?_?policy|put_?(user|role)_?policy|"
        r"create_?access_?key|grant|chmod|chown|sudo|set_?permission|add_?to_?group)")),
    (ActionType.DELETE.value, re.compile(r"(?i)(delete|remove|drop|truncate|purge|destroy|rm\b|unlink)")),
    (ActionType.NETWORK.value, re.compile(
        r"(?i)(http|fetch_?url|web_?fetch|request|upload|webhook|curl|wget|send_?email|smtp|post_?to|ftp)")),
    (ActionType.MESSAGE.value, re.compile(r"(?i)(send_?message|notify|slack|chat|reply|handoff)")),
    (ActionType.WRITE.value, re.compile(
        r"(?i)(write|put|update|create|insert|save|append|edit|modify|upsert|copy|move)")),
    (ActionType.LIST.value, re.compile(r"(?i)(list|ls\b|scan|glob|search|find|enumerate)")),
    (ActionType.READ.value, re.compile(r"(?i)(read|get|fetch|load|query|select|open|download|cat\b|view)")),
    (ActionType.EXECUTE.value, re.compile(r"(?i)(exec|run|shell|bash|eval|invoke|spawn|subprocess)")),
]

_KNOWN_ACTIONS = {a.value for a in ActionType}


def normalize_action(event: ActionEvent) -> str:
    a = (event.action or "").strip().lower()
    if a in _KNOWN_ACTIONS and a != ActionType.TOOL_CALL.value:
        return a
    name = event.tool or event.action
    for verb, rx in _VERB_MAP:
        if rx.search(name or ""):
            return verb
    return ActionType.TOOL_CALL.value


# ------------------------------------------------------------ rule context


@dataclass
class RuleContext:
    policy: Policy
    agent: AgentPolicy | None
    action: str               # normalised action type
    resource: str             # normalised resource


RuleFn = Callable[[ActionEvent, RuleContext], list[Finding]]

_SEVERITY_BY_LEVEL = {4: Severity.CRITICAL, 3: Severity.HIGH, 2: Severity.MEDIUM,
                      1: Severity.LOW, 0: Severity.LOW}

_EGRESS_ACTIONS = {ActionType.NETWORK.value, ActionType.MESSAGE.value}
_DATA_LEAVING = {ActionType.NETWORK.value, ActionType.MESSAGE.value,
                 ActionType.OUTPUT.value, ActionType.WRITE.value}


def rule_unknown_agent(ev: ActionEvent, ctx: RuleContext) -> list[Finding]:
    if ctx.agent is not None or ev.source == "cloudtrail":
        return []  # CloudTrail identities are judged by the bypass check instead
    return [Finding(
        detector="rules", rule_id="agent.unregistered", severity=Severity.CRITICAL,
        mode=ctx.policy.unknown_agent_mode,
        title="Unregistered agent",
        detail=f"Agent '{ev.agent_id}' is not in the agent inventory. Every agent must be "
               f"registered with an owner and permissions before it may act.",
        controls=[C_INVENTORY],
    )]


def rule_access(ev: ActionEvent, ctx: RuleContext) -> list[Finding]:
    """Unauthorised resource access, clearance and bulk-record limits."""
    if ctx.agent is None or ctx.action in _EGRESS_ACTIONS or ctx.action == ActionType.OUTPUT.value:
        return []
    if not ctx.resource and ctx.action in (ActionType.LLM_CALL.value,):
        return []
    findings: list[Finding] = []
    cls = ctx.policy.classify(ctx.resource) if ctx.resource else None
    level = cls.level if cls else 0
    cls_name = cls.name if cls else "UNCLASSIFIED"

    perm = ctx.agent.find_permission(ctx.action, ctx.resource, ev.tool)
    if perm is None:
        sev = _SEVERITY_BY_LEVEL.get(level, Severity.MEDIUM)
        sev = max(sev, Severity.MEDIUM)
        findings.append(Finding(
            detector="rules", rule_id="access.unauthorized", severity=sev,
            title=f"Unauthorised {ctx.action} on {cls_name} data" if cls else
                  f"Unauthorised {ctx.action}",
            detail=f"Agent '{ev.agent_id}' has no permission to {ctx.action} "
                   f"'{ctx.resource or ev.tool}' (classification: {cls_name}).",
            controls=[C_LEAST_PRIV],
            evidence={"classification": cls_name, "level": level},
        ))
    elif perm.requires_approval:
        findings.append(Finding(
            detector="rules", rule_id="access.requires_approval", severity=Severity.HIGH,
            title="Action requires human approval",
            detail=f"Policy requires a human to approve '{ctx.action}' on '{ctx.resource}'.",
            controls=[C_OVERSIGHT],
        ))

    if cls and level > ctx.agent.max_clearance:
        findings.append(Finding(
            detector="rules", rule_id="access.clearance_exceeded", severity=Severity.CRITICAL,
            title=f"{cls_name} data above agent clearance",
            detail=f"'{ctx.resource}' is classified {cls_name} (level {level}); agent "
                   f"'{ev.agent_id}' is cleared to level {ctx.agent.max_clearance} only.",
            controls=[C_LEAST_PRIV, C_DLP],
            evidence={"classification": cls_name, "level": level,
                      "agent_clearance": ctx.agent.max_clearance},
        ))

    if perm and perm.max_records_per_action and ev.record_count > perm.max_records_per_action:
        sev = Severity.CRITICAL if level >= 4 else Severity.HIGH
        findings.append(Finding(
            detector="rules", rule_id="access.bulk_records", severity=sev,
            title="Bulk record access",
            detail=f"Action touches {ev.record_count} records; the limit for this permission "
                   f"is {perm.max_records_per_action}.",
            controls=[C_DLP, C_BEHAVIOUR],
            evidence={"record_count": ev.record_count, "limit": perm.max_records_per_action},
        ))
    return findings


def rule_egress(ev: ActionEvent, ctx: RuleContext) -> list[Finding]:
    if ctx.action != ActionType.NETWORK.value:
        return []
    domain = domain_of(ev.resource)
    allowed = list(ctx.policy.allowed_egress) + (ctx.agent.allowed_egress if ctx.agent else [])
    if domain and domain_allowed(domain, allowed):
        return []
    return [Finding(
        detector="rules", rule_id="egress.unapproved_destination", severity=Severity.HIGH,
        title="Outbound call to unapproved destination",
        detail=f"Agent '{ev.agent_id}' attempted to contact '{domain or ev.resource}', which is "
               f"not on the egress allow-list.",
        controls=[C_EGRESS],
        evidence={"domain": domain},
    )]


def rule_pii_leaving(ev: ActionEvent, ctx: RuleContext) -> list[Finding]:
    """PII in data that is leaving the agent (network, messages, outputs, writes)."""
    if ctx.action not in _DATA_LEAVING:
        return []
    text = ev.content or ""
    if ev.arguments:
        text += "\n" + " ".join(str(v) for v in ev.arguments.values())
    report = scan_pii(text)
    if not report:
        return []

    # Writing PII back to a location classified to hold it is normal business.
    if ctx.action == ActionType.WRITE.value and ctx.resource:
        cls = ctx.policy.classify(ctx.resource)
        if cls and cls.level >= 4:
            return []

    high_risk = [k for k in report.kinds if k in HIGH_RISK_KINDS]
    external = False
    if ctx.action == ActionType.NETWORK.value:
        domain = domain_of(ev.resource)
        allowed = list(ctx.policy.allowed_egress) + (ctx.agent.allowed_egress if ctx.agent else [])
        external = not (domain and domain_allowed(domain, allowed))

    if external and (high_risk or report.total >= 3):
        sev, rule_id, title = Severity.CRITICAL, "dlp.pii_exfiltration", "PII exfiltration attempt"
    elif high_risk or report.total >= 10:
        sev, rule_id, title = Severity.HIGH, "dlp.pii_in_outbound", "Sensitive PII in outbound data"
    else:
        sev, rule_id, title = Severity.MEDIUM, "dlp.pii_in_outbound", "PII in outbound data"

    return [Finding(
        detector="rules.dlp", rule_id=rule_id, severity=sev, title=title,
        detail=f"{report.total} PII item(s) of type {', '.join(report.kinds)} found in a "
               f"'{ctx.action}' by agent '{ev.agent_id}' to '{ev.resource or 'output'}'.",
        controls=[C_DLP] + ([C_EGRESS] if external else []),
        evidence={"pii": report.to_dict(), "external": external},
    )]


def rule_secrets(ev: ActionEvent, ctx: RuleContext) -> list[Finding]:
    if ctx.action not in _DATA_LEAVING:
        return []
    text = (ev.content or "") + " " + " ".join(str(v) for v in (ev.arguments or {}).values())
    kinds = scan_secrets(text)
    if not kinds:
        return []
    return [Finding(
        detector="rules.dlp", rule_id="dlp.secret_leak", severity=Severity.CRITICAL,
        title="Credential or secret in outbound data",
        detail=f"Detected {', '.join(kinds)} in data leaving agent '{ev.agent_id}'.",
        controls=[C_SECRETS, C_DLP],
        evidence={"secret_types": kinds},
    )]


def rule_privilege(ev: ActionEvent, ctx: RuleContext) -> list[Finding]:
    if ctx.action != ActionType.IAM.value:
        return []
    if ctx.agent and ctx.agent.find_permission(ActionType.IAM.value, ctx.resource, ev.tool):
        return []
    return [Finding(
        detector="rules", rule_id="iam.privilege_escalation", severity=Severity.CRITICAL,
        title="Privilege escalation attempt",
        detail=f"Agent '{ev.agent_id}' attempted a permission/credential change "
               f"('{ev.tool or ev.action}' on '{ctx.resource}').",
        controls=[C_PRIV_MGMT],
    )]


def rule_destructive(ev: ActionEvent, ctx: RuleContext) -> list[Finding]:
    """Permitted deletes on sensitive data are still surfaced for oversight."""
    if ctx.action != ActionType.DELETE.value or ctx.agent is None:
        return []
    cls = ctx.policy.classify(ctx.resource) if ctx.resource else None
    if not cls or cls.level < 3:
        return []
    if not ctx.agent.find_permission(ctx.action, ctx.resource, ev.tool):
        return []  # already covered by access.unauthorized
    return [Finding(
        detector="rules", rule_id="data.destructive_on_sensitive", severity=Severity.MEDIUM,
        title=f"Delete on {cls.name} data",
        detail=f"Agent '{ev.agent_id}' is deleting '{ctx.resource}' ({cls.name}).",
        controls=[C_OVERSIGHT, C_AUDIT],
    )]


ALL_RULES: list[RuleFn] = [
    rule_unknown_agent, rule_access, rule_egress, rule_pii_leaving,
    rule_secrets, rule_privilege, rule_destructive,
]


def evaluate_rules(ev: ActionEvent, policy: Policy) -> tuple[RuleContext, list[Finding]]:
    agent = policy.agents.get(ev.agent_id)
    ctx = RuleContext(policy=policy, agent=agent, action=normalize_action(ev),
                      resource=normalize_resource(ev.resource))
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(ev, ctx))
    return ctx, findings
