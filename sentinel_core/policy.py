"""Policy model: who may do what, to which data, and how Sentinel responds.

Policies are YAML documents (see ``policies/``). They describe:

* data classifications  - which resources hold restricted data (e.g. PII)
* agents                - the inventory of agents and their permissions
* egress                - which outbound destinations are allowed
* response              - severity -> response mode, plus per-rule overrides

Resource patterns are globs: ``*`` matches within one path segment and
``**`` matches across segments. Patterns are matched against the
*normalised* resource string, so ``s3://bucket/a/../pii/x`` cannot be used to
dodge a rule on ``s3://bucket/pii/**``.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse

import yaml

from .models import Mode, Severity

# --------------------------------------------------------------------------
# Resource normalisation and glob matching
# --------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$")


def normalize_resource(resource: str) -> str:
    """Canonicalise a resource string so path tricks can't evade matching.

    * URL-decodes (``%2e%2e`` -> ``..``) repeatedly
    * collapses ``.``/``..`` segments and duplicate slashes
    * lower-cases the scheme and host (paths stay case-sensitive)
    * converts Windows separators
    """
    if not resource:
        return ""
    r = resource.strip()
    for _ in range(3):  # defeat double-encoding
        decoded = unquote(r)
        if decoded == r:
            break
        r = decoded
    r = r.replace("\\", "/")
    m = _SCHEME_RE.match(r)
    if m:
        scheme, rest = m.group(1).lower(), m.group(2)
        if scheme in ("http", "https"):
            p = urlparse(f"{scheme}://{rest}")
            # leading '//' survives posixpath.normpath (POSIX rule) — collapse it
            path = posixpath.normpath("/" + p.path.lstrip("/")) if p.path else ""
            path = "" if path == "." else path
            return f"{scheme}://{(p.hostname or '').lower()}{path}"
        host, _, path = rest.partition("/")
        path = posixpath.normpath("/" + path.lstrip("/")) if path else ""
        path = "" if path == "/" else path
        return f"{scheme}://{host.lower()}{path}"
    norm = posixpath.normpath(r)
    if r.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return norm


@lru_cache(maxsize=4096)
def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    pattern = normalize_resource(pattern) if "*" not in pattern else pattern
    out = ["^"]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                # '/**' at the end also matches the directory itself
                if i + 2 == len(pattern) and out and out[-1] == "/":
                    out[-1] = "(?:/.*)?"
                else:
                    out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def glob_match(pattern: str, resource: str) -> bool:
    if pattern == "*" or pattern == "**":
        return True
    return bool(_glob_to_regex(pattern).match(resource))


def any_match(patterns: Iterable[str], resource: str) -> bool:
    return any(glob_match(p, resource) for p in patterns)


def domain_of(resource: str) -> str:
    """Extract the host for network actions (URLs or bare hostnames)."""
    if not resource:
        return ""
    if "://" not in resource:
        resource = "https://" + resource
    try:
        return (urlparse(resource).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def domain_allowed(domain: str, allowed: Iterable[str]) -> bool:
    for pat in allowed:
        pat = pat.lower().strip()
        if pat == domain:
            return True
        if pat.startswith("*.") and (domain.endswith(pat[1:]) or domain == pat[2:]):
            return True
    return False


# --------------------------------------------------------------------------
# Policy objects
# --------------------------------------------------------------------------


@dataclass
class Classification:
    name: str
    level: int                      # 0 public .. 4 restricted
    resources: list[str]
    description: str = ""


@dataclass
class Permission:
    actions: list[str]
    resources: list[str]
    tools: list[str] = field(default_factory=list)
    max_records_per_action: int | None = None
    requires_approval: bool = False   # always HOLD, even though permitted

    def matches(self, action: str, resource: str, tool: str) -> bool:
        if "*" not in self.actions and action not in self.actions:
            return False
        if self.tools and tool and not any_match(self.tools, tool):
            return False
        if self.resources and not any_match(self.resources, resource):
            return False
        return True


@dataclass
class RateLimits:
    actions_per_minute: int | None = None
    records_per_hour: int | None = None
    distinct_resources_per_hour: int | None = None


@dataclass
class AgentPolicy:
    agent_id: str
    description: str
    owner: str = ""
    risk_tier: str = "medium"
    max_clearance: int = 1
    permissions: list[Permission] = field(default_factory=list)
    rate_limits: RateLimits = field(default_factory=RateLimits)
    heartbeat_seconds: int | None = None
    working_hours: dict[str, str] | None = None   # {"tz": "...", "start": "08:00", "end": "20:00"}
    allowed_egress: list[str] = field(default_factory=list)
    can_receive_untrusted_input: bool = True
    principals: list[str] = field(default_factory=list)   # IAM ARNs (globs) this agent runs as

    def find_permission(self, action: str, resource: str, tool: str) -> Permission | None:
        for p in self.permissions:
            if p.matches(action, resource, tool):
                return p
        return None


@dataclass
class RuleOverride:
    enabled: bool = True
    severity: Severity | None = None
    mode: Mode | None = None


@dataclass
class Policy:
    version: int
    organization: str
    classifications: list[Classification]
    agents: dict[str, AgentPolicy]
    allowed_egress: list[str]
    severity_modes: dict[Severity, Mode]
    rule_overrides: dict[str, RuleOverride]
    unknown_agent_mode: Mode = Mode.QUARANTINE
    hold_timeout_seconds: int = 900
    fail_mode: str = "closed"
    anomaly: dict[str, Any] = field(default_factory=dict)
    judge: dict[str, Any] = field(default_factory=dict)
    trusted_principals: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ lookups
    def classify(self, resource: str) -> Classification | None:
        """Highest-level classification whose pattern matches the resource."""
        best: Classification | None = None
        for c in self.classifications:
            if any_match(c.resources, resource) and (best is None or c.level > best.level):
                best = c
        return best

    def agent_for_principal(self, arn: str) -> AgentPolicy | None:
        for a in self.agents.values():
            if a.principals and any_match(a.principals, arn):
                return a
        return None

    def is_trusted_principal(self, arn: str) -> bool:
        return any(glob_match(p, arn) for p in self.trusted_principals)

    def classification_by_name(self, name: str) -> Classification | None:
        for c in self.classifications:
            if c.name == name:
                return c
        return None

    def mode_for(self, severity: Severity) -> Mode:
        return self.severity_modes.get(severity, Mode.FLAG)

    def override(self, rule_id: str) -> RuleOverride | None:
        return self.rule_overrides.get(rule_id)

    @property
    def fingerprint(self) -> str:
        blob = json.dumps(self.raw, sort_keys=True, default=str).encode()
        return hashlib.sha256(blob).hexdigest()[:16]


class PolicyError(ValueError):
    pass


_DEFAULT_SEVERITY_MODES = {
    Severity.INFO: Mode.LOG,
    Severity.LOW: Mode.LOG,
    Severity.MEDIUM: Mode.FLAG,
    Severity.HIGH: Mode.HOLD,
    Severity.CRITICAL: Mode.QUARANTINE,
}

_VALID_ACTIONS = {
    "*", "read", "write", "delete", "list", "execute", "network", "message",
    "llm_call", "tool_call", "iam", "output",
}


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise PolicyError(msg)


def parse_policy(doc: dict[str, Any]) -> Policy:
    _require(isinstance(doc, dict), "policy must be a mapping")
    defaults = doc.get("defaults", {}) or {}

    classifications: list[Classification] = []
    levels: dict[str, int] = {"PUBLIC": 0}
    for c in doc.get("classifications", []) or []:
        _require("name" in c and "level" in c, f"classification needs name+level: {c}")
        cl = Classification(
            name=str(c["name"]),
            level=int(c["level"]),
            resources=[str(r) for r in c.get("resources", [])],
            description=str(c.get("description", "")),
        )
        classifications.append(cl)
        levels[cl.name] = cl.level

    def clearance(v: Any) -> int:
        if isinstance(v, int):
            return v
        _require(str(v) in levels, f"unknown clearance '{v}'")
        return levels[str(v)]

    agents: dict[str, AgentPolicy] = {}
    for a in doc.get("agents", []) or []:
        _require("id" in a, f"agent needs an id: {a}")
        perms = []
        for p in a.get("permissions", []) or []:
            acts = [str(x).lower() for x in p.get("actions", ["*"])]
            bad = set(acts) - _VALID_ACTIONS
            _require(not bad, f"agent {a['id']}: unknown actions {bad}")
            perms.append(Permission(
                actions=acts,
                resources=[str(r) for r in p.get("resources", [])],
                tools=[str(t) for t in p.get("tools", [])],
                max_records_per_action=p.get("max_records_per_action"),
                requires_approval=bool(p.get("requires_approval", False)),
            ))
        rl = a.get("rate_limits", {}) or {}
        ap = AgentPolicy(
            agent_id=str(a["id"]),
            description=str(a.get("description", "")),
            owner=str(a.get("owner", "")),
            risk_tier=str(a.get("risk_tier", "medium")),
            max_clearance=clearance(a.get("max_clearance", 1)),
            permissions=perms,
            rate_limits=RateLimits(
                actions_per_minute=rl.get("actions_per_minute"),
                records_per_hour=rl.get("records_per_hour"),
                distinct_resources_per_hour=rl.get("distinct_resources_per_hour"),
            ),
            heartbeat_seconds=a.get("heartbeat_seconds"),
            working_hours=a.get("working_hours"),
            allowed_egress=[str(d) for d in a.get("allowed_egress", [])],
            can_receive_untrusted_input=bool(a.get("can_receive_untrusted_input", True)),
            principals=[str(x) for x in a.get("principals", [])],
        )
        _require(ap.agent_id not in agents, f"duplicate agent id {ap.agent_id}")
        agents[ap.agent_id] = ap

    sev_modes = dict(_DEFAULT_SEVERITY_MODES)
    for k, v in (defaults.get("severity_modes") or {}).items():
        sev_modes[Severity.parse(k)] = Mode.parse(v)

    overrides: dict[str, RuleOverride] = {}
    for rule_id, o in (doc.get("rules") or {}).items():
        o = o or {}
        overrides[str(rule_id)] = RuleOverride(
            enabled=bool(o.get("enabled", True)),
            severity=Severity.parse(o["severity"]) if o.get("severity") else None,
            mode=Mode.parse(o["mode"]) if o.get("mode") else None,
        )

    fail_mode = str(defaults.get("fail_mode", "closed")).lower()
    _require(fail_mode in ("closed", "open"), "fail_mode must be closed|open")

    return Policy(
        version=int(doc.get("version", 1)),
        organization=str(doc.get("organization", "")),
        classifications=classifications,
        agents=agents,
        allowed_egress=[str(d) for d in (doc.get("egress", {}) or {}).get("allowed_domains", [])],
        severity_modes=sev_modes,
        rule_overrides=overrides,
        unknown_agent_mode=Mode.parse(defaults.get("unknown_agent", "QUARANTINE")),
        hold_timeout_seconds=int(defaults.get("hold_timeout_seconds", 900)),
        fail_mode=fail_mode,
        anomaly=dict(doc.get("anomaly", {}) or {}),
        judge=dict(doc.get("judge", {}) or {}),
        trusted_principals=[str(x) for x in doc.get("trusted_principals", []) or []],
        raw=doc,
    )


def load_policy(path: str | Path) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_policy(yaml.safe_load(fh))


def load_policy_text(text: str) -> Policy:
    return parse_policy(yaml.safe_load(text))
