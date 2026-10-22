"""Core data models shared by every Sentinel component.

Everything an agent does is described as an ``ActionEvent``. The decision
engine turns an event into a ``Decision`` made up of ``Finding`` objects.
These models are plain dataclasses with explicit (de)serialisation so they
can cross Lambda, SQS, DynamoDB and HTTP boundaries without surprises.
"""
from __future__ import annotations

import enum
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


class Mode(enum.IntEnum):
    """Response modes, ordered by strictness so ``max()`` picks the strictest."""

    LOG = 0          # action proceeds, recorded only
    FLAG = 1         # action proceeds, alert raised
    HOLD = 2         # action paused until a human approves / rejects
    BLOCK = 3        # action denied
    QUARANTINE = 4   # action denied and agent suspended until reviewed

    @classmethod
    def parse(cls, value: str | int | "Mode") -> "Mode":
        if isinstance(value, Mode):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


class Verdict(str, enum.Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"


class ActionType(str, enum.Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    LIST = "list"
    EXECUTE = "execute"
    NETWORK = "network"        # outbound HTTP / egress
    MESSAGE = "message"        # agent-to-agent or agent-to-human message
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"    # generic, unknown semantics
    IAM = "iam"                # permission / credential changes
    OUTPUT = "output"          # final output produced by the agent


def _now() -> float:
    return time.time()


def _new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class ActionEvent:
    """One thing an agent is about to do (pre) or has done (post)."""

    agent_id: str
    action: str                      # ActionType value or free text tool name
    resource: str = ""               # path / URI / table / URL / tool name
    tool: str = ""                   # tool name as the framework calls it
    task_id: str = ""                # the task the agent is working on
    task_description: str = ""       # natural-language task, used by the judge
    arguments: dict[str, Any] = field(default_factory=dict)
    content: str = ""                # payload being written / sent / output text
    inputs: str = ""                 # untrusted content the agent just ingested
    record_count: int = 1            # how many records this action touches
    phase: str = "pre"               # "pre" (before execution) or "post"
    source: str = "sdk"              # sdk | cloudtrail | heartbeat
    session_id: str = ""
    principal: str = ""              # IAM principal / service account
    event_id: str = field(default_factory=_new_id)
    timestamp: float = field(default_factory=_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionEvent":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in data.items() if k in known}
        if "agent_id" not in clean or not clean["agent_id"]:
            raise ValueError("agent_id is required")
        if "action" not in clean or not clean["action"]:
            raise ValueError("action is required")
        clean["record_count"] = int(clean.get("record_count", 1) or 1)
        clean["timestamp"] = float(clean.get("timestamp") or _now())
        return cls(**clean)


@dataclass
class Finding:
    """A single detector's opinion about an event."""

    detector: str          # e.g. "rules.unauthorized_resource"
    rule_id: str           # stable id used for policy overrides and controls
    severity: Severity
    title: str
    detail: str
    mode: Mode | None = None          # explicit mode override from policy
    controls: list[str] = field(default_factory=list)  # compliance control ids
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["mode"] = self.mode.name if self.mode is not None else None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            detector=d["detector"],
            rule_id=d["rule_id"],
            severity=Severity.parse(d["severity"]),
            title=d["title"],
            detail=d["detail"],
            mode=Mode.parse(d["mode"]) if d.get("mode") else None,
            controls=list(d.get("controls") or []),
            evidence=dict(d.get("evidence") or {}),
        )


@dataclass
class Decision:
    event_id: str
    agent_id: str
    verdict: Verdict
    mode: Mode
    severity: Severity
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""
    decision_id: str = field(default_factory=_new_id)
    approval_id: str | None = None     # set when verdict == HOLD
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=_now)

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "verdict": self.verdict.value,
            "mode": self.mode.name,
            "severity": self.severity.name,
            "findings": [f.to_dict() for f in self.findings],
            "reason": self.reason,
            "approval_id": self.approval_id,
            "latency_ms": round(self.latency_ms, 3),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Decision":
        return cls(
            decision_id=d["decision_id"],
            event_id=d["event_id"],
            agent_id=d["agent_id"],
            verdict=Verdict(d["verdict"]),
            mode=Mode.parse(d["mode"]),
            severity=Severity.parse(d["severity"]),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            reason=d.get("reason", ""),
            approval_id=d.get("approval_id"),
            latency_ms=float(d.get("latency_ms", 0.0)),
            timestamp=float(d.get("timestamp", _now())),
        )


class AgentStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"
    DISABLED = "DISABLED"


class ApprovalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
