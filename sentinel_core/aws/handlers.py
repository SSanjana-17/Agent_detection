"""AWS Lambda entry points.

    api_handler          API Gateway (REST) proxy for agent + console APIs
    stream_handler       SQS FIFO consumer: evidence chain + async analysis of reported events
    cloudtrail_handler   EventBridge: CloudTrail S3 data events -> bypass detection
    scheduler_handler    EventBridge schedule: health checks (1 min), control tests (1 h)
    approval_handler     Step Functions tasks for the hold-until-approved workflow
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import boto3

from ..evidence import EvidenceWriter
from ..models import ApprovalStatus
from ..router import dispatch
from ..service import Identity
from .runtime import QueueSink, build_service

logging.getLogger().setLevel(os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("sentinel")

_CORS = {
    "Access-Control-Allow-Origin": os.environ.get("CORS_ORIGIN", "*"),
    "Access-Control-Allow-Headers": "Authorization,Content-Type,X-Amz-Date,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
}


def _identity(event: dict[str, Any]) -> Identity:
    ctx = event.get("requestContext") or {}
    claims = ((ctx.get("authorizer") or {}).get("claims")) or {}
    if claims:
        groups = claims.get("cognito:groups") or ""
        if isinstance(groups, str):
            groups = [g for g in groups.replace("[", "").replace("]", "").replace(",", " ").split() if g]
        return Identity(kind="human", principal=claims.get("email") or claims.get("cognito:username", ""),
                        groups=list(groups))
    ident = ctx.get("identity") or {}
    arn = ident.get("userArn") or ident.get("caller") or ""
    if arn:
        return Identity(kind="agent", principal=arn)
    return Identity(kind="anonymous")


def _resp(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {"statusCode": status, "headers": {"Content-Type": "application/json", **_CORS},
            "body": json.dumps(body, default=str)}


# ------------------------------------------------------------------ API

def api_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    method = event.get("httpMethod", "GET")
    if method == "OPTIONS":
        return _resp(200, {})
    path = event.get("path", "/")
    # API Gateway exposes /agent/* (IAM auth) and /console/* (Cognito auth);
    # the prefix only selects the authorizer, the route table is shared.
    for prefix in ("/agent/", "/console/"):
        if path.startswith(prefix):
            path = "/" + path[len(prefix):]
            break
    ident = _identity(event)
    if ident.kind == "anonymous":
        return _resp(401, {"error": "unauthenticated"})
    query = event.get("queryStringParameters") or {}
    raw = event.get("body")
    if event.get("isBase64Encoded") and raw:
        import base64
        raw = base64.b64decode(raw).decode()

    # Reported (post-execution) events are analysed asynchronously off the queue.
    if method == "POST" and path.rstrip("/").endswith("/v1/events") and os.environ.get("QUEUE_URL"):
        try:
            body = json.loads(raw or "{}")
            events = body.get("events") if isinstance(body.get("events"), list) else [body]
            QueueSink(os.environ["QUEUE_URL"]).put_events(
                events[:500], {"kind": ident.kind, "principal": ident.principal})
            return _resp(202, {"accepted": len(events[:500])})
        except Exception as exc:
            log.exception("failed to enqueue events")
            return _resp(503, {"error": f"could not enqueue: {exc}"})

    status, body = dispatch(build_service(), method, path, query, raw, ident)
    return _resp(status, body)


# --------------------------------------------------------------- stream

def stream_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """SQS FIFO consumer. Each message group is one evidence chain, processed in order."""
    by_group: dict[str, list[tuple[str, float, dict[str, Any]]]] = {}
    ids_by_group: dict[str, list[str]] = {}
    failures: list[dict[str, str]] = []
    failed_groups: set[str] = set()
    writer = EvidenceWriter(os.environ["EVIDENCE_BUCKET"], os.environ["TABLE_NAME"])

    for rec in event.get("Records", []):
        group = (rec.get("attributes") or {}).get("MessageGroupId", "sentinel")
        msg_id = rec["messageId"]
        if group in failed_groups:
            # FIFO: once a message in a group fails, retry everything after it too
            failures.append({"itemIdentifier": msg_id})
            continue
        items = by_group.setdefault(group, [])
        ids_by_group.setdefault(group, []).append(msg_id)
        try:
            msg = json.loads(rec["body"])
            if msg.get("kind") == "evidence":
                items.append((msg["type"], float(msg["at"]), msg["payload"]))
            elif msg.get("kind") == "post_event":
                local: list[tuple[str, float, dict[str, Any]]] = []

                def sink(rtype, payload, partition, _l=local):
                    _l.append((rtype, time.time(), payload))

                svc = build_service(evidence_sink=sink, use_cache=False)
                idn = msg.get("identity") or {}
                svc.report(msg["event"], Identity(kind=idn.get("kind", "agent"),
                                                  principal=idn.get("principal", "")))
                items.extend(local)
        except Exception:
            log.exception("failed to process message %s", msg_id)
            failed_groups.add(group)
            failures.append({"itemIdentifier": msg_id})

    for group, items in by_group.items():
        if not items:
            continue
        try:
            writer.append(group, items)
        except Exception:
            log.exception("failed to write evidence for group %s", group)
            done = {f["itemIdentifier"] for f in failures}
            failures.extend({"itemIdentifier": m} for m in ids_by_group[group] if m not in done)
    return {"batchItemFailures": failures}


# ------------------------------------------------------------ cloudtrail

def cloudtrail_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    detail = event.get("detail") or {}
    res = build_service().ingest_cloudtrail(detail)
    if res and res["mode"] != "LOG":
        log.warning("cloudtrail finding: %s %s %s", res["agent_id"], res["mode"], res["reason"])
    return {"processed": res is not None}


# ------------------------------------------------------------- scheduler

def _aws_checks(full: bool) -> dict[str, Any]:
    out: dict[str, Any] = {}
    bucket = os.environ.get("EVIDENCE_BUCKET")
    if bucket:
        try:
            cfg = boto3.client("s3").get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]
            rule = (cfg.get("Rule") or {}).get("DefaultRetention") or {}
            out["evidence_object_lock"] = cfg.get("ObjectLockEnabled") == "Enabled" and rule.get("Mode") == "COMPLIANCE"
            out["evidence_object_lock_detail"] = f"{rule.get('Mode')} {rule.get('Days') or rule.get('Years')}"
        except Exception as exc:
            out["evidence_object_lock"] = False
            out["evidence_object_lock_detail"] = str(exc)[:200]
    trail = os.environ.get("TRAIL_ARN")
    if trail:
        try:
            ct = boto3.client("cloudtrail")
            status = ct.get_trail_status(Name=trail)
            sel = ct.get_event_selectors(TrailName=trail)
            has_data = bool(sel.get("AdvancedEventSelectors")) or any(
                s.get("DataResources") for s in sel.get("EventSelectors", []))
            out["cloudtrail_data_events"] = bool(status.get("IsLogging")) and has_data
            out["cloudtrail_detail"] = f"logging={status.get('IsLogging')} data_events={has_data}"
        except Exception as exc:
            out["cloudtrail_data_events"] = False
            out["cloudtrail_detail"] = str(exc)[:200]
    if full and bucket:
        try:
            res = EvidenceWriter(bucket, os.environ["TABLE_NAME"]).verify()
            out["evidence_chain_ok"] = res["ok"]
            bad = {k: v["error"] for k, v in res["chains"].items() if not v["ok"]}
            out["evidence_chain_detail"] = (f"{sum(v['records'] for v in res['chains'].values())} records "
                                            f"in {len(res['chains'])} chains" + (f"; errors {bad}" if bad else ""))
        except Exception as exc:
            out["evidence_chain_ok"] = False
            out["evidence_chain_detail"] = str(exc)[:200]
    if os.environ.get("BEDROCK_MODEL_ID"):
        try:
            from ..judge import BedrockBackend
            BedrockBackend().complete("Reply with {}", "ping", 5)
            out["judge_available"] = True
        except Exception as exc:
            out["judge_available"] = False
            out["judge_detail"] = str(exc)[:200]
    return out


def scheduler_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    job = event.get("job", "health")
    svc = build_service()
    if job == "health":
        res = svc.run_health_checks()
        return {"job": job, "findings": len(res)}
    if job == "controls":
        full = bool(event.get("verify_evidence", False))
        res = svc.run_control_tests(_aws_checks(full))
        return {"job": job, "results": {r["control_id"]: r["status"] for r in res}}
    raise ValueError(f"unknown job {job}")


# -------------------------------------------------------------- approvals

def approval_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Step Functions tasks.

    step=wait     (waitForTaskToken) register the token; resolves immediately if a
                  human already decided before the token arrived
    step=expire   timeout reached: reject the held action (fail closed)
    step=finalize record the outcome on the evidence chain
    """
    svc = build_service()
    step = event["step"]
    ap_id = event["approval_id"]
    if step == "wait":
        token = event["task_token"]
        svc.store.set_approval_token(ap_id, token)
        ap = svc.store.get_approval(ap_id)
        if ap and ap["status"] != "PENDING":
            boto3.client("stepfunctions").send_task_success(
                taskToken=token, output=json.dumps({"approval_id": ap_id, "status": ap["status"],
                                                    "resolved_by": ap.get("resolved_by")}))
        return {"registered": True}
    if step == "expire":
        try:
            ap = svc.store.resolve_approval(ap_id, ApprovalStatus.EXPIRED, "system:timeout",
                                            "No human decision before the hold timeout; rejected.")
        except ValueError:
            ap = svc.store.get_approval(ap_id) or {}
        svc._emit("approval", {"approval_id": ap_id, "status": ap.get("status", "EXPIRED"),
                               "actor": "system:timeout", "agent_id": ap.get("agent_id")},
                  ap.get("agent_id") or "approvals")
        return {"approval_id": ap_id, "status": ap.get("status", "EXPIRED")}
    if step == "finalize":
        ap = svc.store.get_approval(ap_id) or {}
        return {"approval_id": ap_id, "status": ap.get("status"), "resolved_by": ap.get("resolved_by")}
    raise ValueError(f"unknown step {step}")
