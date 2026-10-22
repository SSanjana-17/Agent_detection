"""Alert routing: email (SNS), Slack, and AWS Security Hub.

Every decision at FLAG or above becomes an alert record. Notifications are
de-duplicated per agent + rule + location for a short window, except for
HOLD and QUARANTINE decisions, which always notify because a human has to
act on them.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from typing import Any, Protocol

from .models import ActionEvent, Decision, Mode, Severity
from .store import Store, resource_prefix

log = logging.getLogger(__name__)

_EMOJI = {Severity.CRITICAL: ":rotating_light:", Severity.HIGH: ":warning:",
          Severity.MEDIUM: ":large_yellow_circle:", Severity.LOW: ":information_source:",
          Severity.INFO: ":information_source:"}
_ACTION_TEXT = {
    Mode.FLAG: "Action allowed and flagged for review.",
    Mode.HOLD: "Action is ON HOLD until a human approves or rejects it.",
    Mode.BLOCK: "Action was BLOCKED.",
    Mode.QUARANTINE: "Action was BLOCKED and the agent has been QUARANTINED.",
}


class Notifier(Protocol):
    name: str

    def send(self, alert: dict[str, Any]) -> None: ...


def build_alert(decision: Decision, event: ActionEvent, alert_id: str,
                dashboard_url: str = "") -> dict[str, Any]:
    top = decision.findings[0] if decision.findings else None
    base = dashboard_url.rstrip("/")
    link = f"{base}/#/alerts/{alert_id}" if base else ""
    approve_link = (f"{base}/#/approvals/{decision.approval_id}"
                    if base and decision.approval_id else "")
    return {
        "alert_id": alert_id,
        "decision_id": decision.decision_id,
        "agent_id": decision.agent_id,
        "severity": decision.severity.name,
        "mode": decision.mode.name,
        "verdict": decision.verdict.value,
        "title": top.title if top else decision.reason,
        "rule_id": top.rule_id if top else "",
        "summary": decision.reason,
        "details": [f"[{f.severity.name}] {f.title}: {f.detail}" for f in decision.findings[:5]
                    if f.severity > Severity.INFO],
        "controls": sorted({c for f in decision.findings for c in f.controls}),
        "action": event.action, "tool": event.tool, "resource": event.resource,
        "task_id": event.task_id, "principal": event.principal, "source": event.source,
        "response": _ACTION_TEXT.get(decision.mode, ""),
        "approval_id": decision.approval_id,
        "link": link, "approve_link": approve_link,
        "timestamp": decision.timestamp,
    }


class SNSNotifier:
    """Publishes to an SNS topic; subscribe security-team emails to the topic."""

    name = "email"

    def __init__(self, topic_arn: str, client: Any = None) -> None:
        import boto3
        self.topic_arn = topic_arn
        self.client = client or boto3.client("sns")

    def send(self, alert: dict[str, Any]) -> None:
        subject = f"[Sentinel {alert['severity']}] {alert['title']} — {alert['agent_id']}"[:99]
        lines = [
            alert["response"], "",
            f"Agent:     {alert['agent_id']}",
            f"Action:    {alert['action']} {alert['tool']}".rstrip(),
            f"Resource:  {alert['resource'] or '-'}",
            f"Task:      {alert['task_id'] or '-'}",
            f"Source:    {alert['source']}",
            f"Controls:  {', '.join(alert['controls']) or '-'}", "",
            "Findings:", *[f"  - {d}" for d in alert["details"]], "",
        ]
        if alert["approve_link"]:
            lines.append(f"Review and approve/reject: {alert['approve_link']}")
        if alert["link"]:
            lines.append(f"Alert: {alert['link']}")
        lines.append(f"Decision id: {alert['decision_id']}")
        self.client.publish(
            TopicArn=self.topic_arn, Subject=subject, Message="\n".join(lines),
            MessageAttributes={
                "severity": {"DataType": "String", "StringValue": alert["severity"]},
                "mode": {"DataType": "String", "StringValue": alert["mode"]},
            })


class SlackNotifier:
    """Slack incoming-webhook notifier (Block Kit)."""

    name = "slack"

    def __init__(self, webhook_url: str, timeout: float = 4.0) -> None:
        if not webhook_url.startswith("https://hooks.slack.com/"):
            raise ValueError("Slack webhook URL must start with https://hooks.slack.com/")
        self.webhook_url = webhook_url
        self.timeout = timeout

    def payload(self, alert: dict[str, Any]) -> dict[str, Any]:
        sev = Severity[alert["severity"]]
        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text",
                                        "text": f"{alert['severity']}: {alert['title']}"[:150]}},
            {"type": "section", "text": {"type": "mrkdwn",
                                         "text": f"{_EMOJI[sev]} *{alert['response']}*"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Agent*\n`{alert['agent_id']}`"},
                {"type": "mrkdwn", "text": f"*Action*\n{alert['action']} {alert['tool']}".rstrip()},
                {"type": "mrkdwn", "text": f"*Resource*\n`{(alert['resource'] or '-')[:200]}`"},
                {"type": "mrkdwn", "text": f"*Controls*\n{', '.join(alert['controls']) or '-'}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
                                         "text": "\n".join(f"• {d}" for d in alert["details"])[:2900] or "-"}},
        ]
        buttons = []
        if alert["approve_link"]:
            buttons.append({"type": "button", "style": "primary",
                            "text": {"type": "plain_text", "text": "Review held action"},
                            "url": alert["approve_link"]})
        if alert["link"]:
            buttons.append({"type": "button", "text": {"type": "plain_text", "text": "Open alert"},
                            "url": alert["link"]})
        if buttons:
            blocks.append({"type": "actions", "elements": buttons})
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": f"decision `{alert['decision_id']}` · source {alert['source']}"}]})
        return {"text": f"Sentinel {alert['severity']}: {alert['title']} ({alert['agent_id']})",
                "blocks": blocks}

    def send(self, alert: dict[str, Any]) -> None:
        body = json.dumps(self.payload(alert)).encode()
        req = urllib.request.Request(self.webhook_url, data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (fixed host)
            if resp.status >= 300:
                raise RuntimeError(f"Slack returned {resp.status}")


class SecurityHubNotifier:
    """Imports alerts into AWS Security Hub as ASFF findings."""

    name = "securityhub"
    _LABEL = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
              "INFO": "INFORMATIONAL"}

    def __init__(self, account_id: str, region: str, client: Any = None) -> None:
        import boto3
        self.account_id, self.region = account_id, region
        self.client = client or boto3.client("securityhub", region_name=region)

    def send(self, alert: dict[str, Any]) -> None:
        now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(alert["timestamp"]))
        self.client.batch_import_findings(Findings=[{
            "SchemaVersion": "2018-10-08",
            "Id": f"sentinel/{alert['alert_id']}",
            "ProductArn": f"arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default",
            "GeneratorId": f"sentinel/{alert['rule_id']}",
            "AwsAccountId": self.account_id,
            "Types": ["Unusual Behaviors/Application", "Sensitive Data Identifications"],
            "CreatedAt": now, "UpdatedAt": now,
            "Severity": {"Label": self._LABEL[alert["severity"]]},
            "Title": alert["title"][:256],
            "Description": (alert["summary"] + " | " + alert["response"])[:1024],
            "SourceUrl": alert["link"] or None,
            "Resources": [{"Type": "Other", "Id": f"agent/{alert['agent_id']}",
                           "Details": {"Other": {"resource": (alert["resource"] or "-")[:1024],
                                                 "decision_id": alert["decision_id"]}}}],
        }])


class AlertRouter:
    def __init__(self, store: Store, notifiers: list[Notifier], dashboard_url: str = "",
                 dedup_seconds: int = 300, min_mode: Mode = Mode.FLAG) -> None:
        self.store = store
        self.notifiers = notifiers
        self.dashboard_url = dashboard_url
        self.dedup_seconds = dedup_seconds
        self.min_mode = min_mode

    def __call__(self, decision: Decision, event: ActionEvent) -> dict[str, Any] | None:
        return self.handle(decision, event)

    def handle(self, decision: Decision, event: ActionEvent) -> dict[str, Any] | None:
        if decision.mode < self.min_mode:
            return None
        alert_id = self.store.create_alert(decision, event)
        alert = build_alert(decision, event, alert_id, self.dashboard_url)
        must_notify = decision.mode in (Mode.HOLD, Mode.QUARANTINE)
        key = f"{decision.agent_id}|{alert['rule_id']}|{resource_prefix(event.resource)}"
        if not must_notify and not self.store.claim_alert_slot(key, self.dedup_seconds, time.time()):
            log.info("alert %s suppressed (duplicate within %ss)", alert_id, self.dedup_seconds)
            return alert
        for n in self.notifiers:
            try:
                n.send(alert)
            except Exception:
                log.exception("notifier %s failed for alert %s", n.name, alert_id)
        return alert


def notifiers_from_env(env: dict[str, str] | None = None) -> list[Notifier]:
    """Build notifiers from Lambda environment variables."""
    env = dict(os.environ if env is None else env)
    out: list[Notifier] = []
    if env.get("ALERT_TOPIC_ARN"):
        out.append(SNSNotifier(env["ALERT_TOPIC_ARN"]))
    url = env.get("SLACK_WEBHOOK_URL", "")
    if not url and env.get("SLACK_WEBHOOK_SECRET_ARN"):
        url = _read_secret(env["SLACK_WEBHOOK_SECRET_ARN"])
    if url.startswith("https://hooks.slack.com/"):
        out.append(SlackNotifier(url))
    elif url:
        log.warning("Slack webhook not configured correctly; Slack alerts disabled")
    if env.get("SECURITY_HUB_ENABLED", "").lower() == "true" and env.get("AWS_ACCOUNT_ID"):
        out.append(SecurityHubNotifier(env["AWS_ACCOUNT_ID"], env.get("AWS_REGION", "ap-south-1")))
    return out


_SECRET_CACHE: dict[str, tuple[float, str]] = {}


def _read_secret(arn: str, ttl: float = 300) -> str:
    hit = _SECRET_CACHE.get(arn)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    import boto3
    val = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"].strip()
    if val.startswith("{"):
        val = json.loads(val).get("webhook_url", "")
    _SECRET_CACHE[arn] = (time.time(), val)
    return val
