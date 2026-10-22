"""HTTP routing shared by the API Gateway Lambda and the local server.

Agent endpoints (IAM / SigV4 auth in AWS):
    POST /v1/decide                     decide on an action before it runs
    POST /v1/events                     report completed actions (async analysis)
    POST /v1/heartbeat                  liveness
    GET  /v1/approvals/{id}             poll a held action

Console endpoints (Cognito auth in AWS):
    GET  /v1/overview
    GET  /v1/agents
    POST /v1/agents/{id}/quarantine     body: {reason}
    POST /v1/agents/{id}/release        body: {reason}
    GET  /v1/decisions?agent_id=&min_mode=&limit=
    GET  /v1/decisions/{id}
    GET  /v1/alerts?status=
    POST /v1/alerts/{id}                body: {status, note}
    GET  /v1/approvals?status=
    POST /v1/approvals/{id}/approve     body: {comment}
    POST /v1/approvals/{id}/reject      body: {comment}
    GET  /v1/compliance
    GET  /v1/controls/{id}
    GET  /v1/risks
    POST /v1/risks
    GET  /v1/policy
    GET  /v1/health
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable

from .models import Mode
from .service import ApiError, Identity, SentinelService

log = logging.getLogger(__name__)

Handler = Callable[[SentinelService, dict[str, str], dict[str, str], dict[str, Any], Identity], Any]
_ROUTES: list[tuple[str, re.Pattern[str], Handler, str]] = []
_ID = r"(?P<id>[A-Za-z0-9_.:@-]{1,128})"


def route(method: str, pattern: str, audience: str):
    def deco(fn: Handler) -> Handler:
        _ROUTES.append((method, re.compile("^" + pattern.replace("{id}", _ID) + "$"), fn, audience))
        return fn
    return deco


def _int(q: dict[str, str], key: str, default: int, lo: int = 1, hi: int = 2000) -> int:
    try:
        return max(lo, min(hi, int(q.get(key, default))))
    except ValueError:
        raise ApiError(400, f"{key} must be an integer")


# ------------------------------------------------------------ agent routes

@route("POST", "/v1/decide", "agent")
def _decide(svc, p, q, body, ident):
    return svc.decide(body, ident)


@route("POST", "/v1/events", "agent")
def _events(svc, p, q, body, ident):
    return svc.report(body, ident)


@route("POST", "/v1/heartbeat", "agent")
def _heartbeat(svc, p, q, body, ident):
    return svc.heartbeat(body, ident)


@route("GET", "/v1/approvals/{id}", "any")
def _approval(svc, p, q, body, ident):
    if ident.is_human:
        ap = svc.store.get_approval(p["id"])
        if not ap:
            raise ApiError(404, "approval not found")
        ap.pop("task_token", None)
        return ap
    return svc.approval_status(p["id"], ident)


# ---------------------------------------------------------- console routes

@route("GET", "/v1/overview", "human")
def _overview(svc, p, q, body, ident):
    return svc.overview()


@route("GET", "/v1/agents", "human")
def _agents(svc, p, q, body, ident):
    return {"agents": svc.agents_view()}


@route("POST", "/v1/agents/{id}/quarantine", "human")
def _quarantine(svc, p, q, body, ident):
    return svc.set_quarantine(p["id"], True, str(body.get("reason", "")), ident)


@route("POST", "/v1/agents/{id}/release", "human")
def _release(svc, p, q, body, ident):
    return svc.set_quarantine(p["id"], False, str(body.get("reason", "")), ident)


@route("GET", "/v1/decisions", "human")
def _decisions(svc, p, q, body, ident):
    try:
        mm = Mode.parse(q.get("min_mode", "LOG"))
    except KeyError:
        raise ApiError(400, "invalid min_mode")
    return {"decisions": svc.store.list_decisions(limit=_int(q, "limit", 100, hi=1000),
                                                  agent_id=q.get("agent_id") or None, min_mode=mm)}


@route("GET", "/v1/decisions/{id}", "human")
def _decision(svc, p, q, body, ident):
    d = svc.store.get_decision(p["id"])
    if not d:
        raise ApiError(404, "decision not found")
    return d


@route("GET", "/v1/alerts", "human")
def _alerts(svc, p, q, body, ident):
    status = q.get("status", "OPEN").upper()
    return {"alerts": svc.store.list_alerts(status=None if status == "ALL" else status,
                                            limit=_int(q, "limit", 200, hi=1000))}


@route("POST", "/v1/alerts/{id}", "human")
def _alert_update(svc, p, q, body, ident):
    return svc.update_alert(p["id"], str(body.get("status", "")), str(body.get("note", "")), ident)


@route("GET", "/v1/approvals", "human")
def _approvals(svc, p, q, body, ident):
    status = q.get("status", "PENDING").upper()
    items = svc.store.list_approvals(status=None if status == "ALL" else status,
                                     limit=_int(q, "limit", 200, hi=1000))
    for a in items:
        a.pop("task_token", None)
    return {"approvals": items}


@route("POST", "/v1/approvals/{id}/approve", "human")
def _approve(svc, p, q, body, ident):
    return svc.resolve_approval(p["id"], True, str(body.get("comment", "")), ident)


@route("POST", "/v1/approvals/{id}/reject", "human")
def _reject(svc, p, q, body, ident):
    return svc.resolve_approval(p["id"], False, str(body.get("comment", "")), ident)


@route("GET", "/v1/compliance", "human")
def _compliance(svc, p, q, body, ident):
    return svc.compliance_view()


@route("GET", "/v1/controls/{id}", "human")
def _control(svc, p, q, body, ident):
    return svc.control_detail(p["id"])


@route("GET", "/v1/risks", "human")
def _risks(svc, p, q, body, ident):
    return {"risks": svc.risks_view()}


@route("POST", "/v1/risks", "human")
def _risk_upsert(svc, p, q, body, ident):
    return svc.upsert_risk(body, ident)


@route("GET", "/v1/policy", "human")
def _policy(svc, p, q, body, ident):
    return svc.policy_view()


@route("GET", "/v1/health", "any")
def _health(svc, p, q, body, ident):
    return {"ok": True, "policy": svc.policy.fingerprint}


# ----------------------------------------------------------------- dispatch

def dispatch(svc: SentinelService, method: str, path: str, query: dict[str, str] | None,
             raw_body: str | bytes | None, ident: Identity) -> tuple[int, dict[str, Any]]:
    path = "/" + path.strip("/")
    query = query or {}
    try:
        body: dict[str, Any] = {}
        if raw_body:
            if len(raw_body) > 1_000_000:
                raise ApiError(413, "request body too large")
            body = json.loads(raw_body)
            if not isinstance(body, dict):
                raise ApiError(400, "body must be a JSON object")
        allowed_methods = set()
        for m, rx, fn, audience in _ROUTES:
            match = rx.match(path)
            if not match:
                continue
            allowed_methods.add(m)
            if m != method:
                continue
            if audience == "human":
                ident.require_human()
            elif audience == "agent" and ident.kind not in ("agent", "local", "system"):
                raise ApiError(403, "agent endpoint")
            return 200, fn(svc, match.groupdict(), query, body, ident)
        if allowed_methods:
            raise ApiError(405, "method not allowed")
        raise ApiError(404, "not found")
    except ApiError as e:
        return e.status, {"error": e.message}
    except json.JSONDecodeError:
        return 400, {"error": "invalid JSON"}
    except Exception:
        log.exception("unhandled error on %s %s", method, path)
        return 500, {"error": "internal error"}
