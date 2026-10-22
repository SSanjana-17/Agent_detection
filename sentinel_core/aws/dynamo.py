"""DynamoDB implementation of ``Store`` (single-table design).

Key layout (PK / SK):

    AGENT#<id>   STATUS            quarantine state            GSI1: AGENTS / <id>
    AGENT#<id>   MIN#<minute>      action + record counters    TTL 3h
    AGENT#<id>   HOUR#<hour>       string set of resource keys TTL 3h
    AGENT#<id>   BASELINE          learned behaviour stats
    AGENT#<id>   SEEN#<prefixkey>  resource prefix seen        TTL 180d
    AGENT#<id>   RECENT#<ts>       recent action signature     TTL 30m
    AGENT#<id>   MED#<reskey>      last mediated access        TTL 2h
    AGENT#<id>   HEARTBEAT         last heartbeat              GSI1: HEARTBEATS / <id>
    DEC#<id>     META              decision                    GSI1: DEC#<yyyymmdd> / <ts>
    ALERT#<id>   META              alert                       GSI1: ALERT#<status> / <ts>
    SLOT#<key>   SLOT              alert de-duplication        TTL
    APPROVAL#<id> META             held action                 GSI1: APPROVAL#<status> / <ts>
    CONTROL#<id> RES#<ts>          control test result
    CONTROL#<id> LATEST            latest result               GSI1: CONTROLS / <id>
    RISK#<id>    META              risk register entry         GSI1: RISKS / <id>

Complex payloads are stored as a JSON string in ``data``; only key
attributes and counters are native DynamoDB types.
"""
from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import json
import time
import uuid
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from ..anomaly import action_signature
from ..models import (ActionEvent, AgentStatus, ApprovalStatus, Decision, Mode)
from ..store import (RECENT_WINDOW, Baseline, BehaviorSnapshot, Store,
                     event_summary, resource_key, resource_prefix)

_POOL = cf.ThreadPoolExecutor(max_workers=6, thread_name_prefix="sentinel-ddb")

LOG_DECISION_TTL = 7 * 86400
FLAGGED_DECISION_TTL = 400 * 86400


def _d(x: float | int) -> Decimal:
    return Decimal(str(x))


def _day(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y%m%d")


def _tsk(ts: float, ident: str) -> str:
    return f"{ts:017.3f}#{ident}"


class DynamoStore(Store):
    def __init__(self, table_name: str, region: str | None = None, resource: Any = None) -> None:
        ddb = resource or boto3.resource("dynamodb", region_name=region)
        self.table = ddb.Table(table_name)
        self.client = self.table.meta.client
        self.table_name = table_name

    # ------------------------------------------------------------- agents
    def get_agent_status(self, agent_id):
        item = self.table.get_item(Key={"PK": f"AGENT#{agent_id}", "SK": "STATUS"},
                                   ConsistentRead=True).get("Item")
        if not item:
            return AgentStatus.ACTIVE, ""
        return AgentStatus(item["status"]), item.get("reason", "")

    def set_agent_status(self, agent_id, status, reason, actor):
        now = time.time()
        self.table.put_item(Item={
            "PK": f"AGENT#{agent_id}", "SK": "STATUS", "GSI1PK": "AGENTS", "GSI1SK": agent_id,
            "agent_id": agent_id, "status": status.value, "reason": reason[:1000],
            "changed_by": actor, "changed_at": _d(now),
        })

    def list_agent_states(self):
        out = {}
        for item in self._query_gsi("AGENTS"):
            out[item["agent_id"]] = {
                "agent_id": item["agent_id"], "status": item["status"],
                "reason": item.get("reason", ""), "changed_by": item.get("changed_by"),
                "changed_at": float(item.get("changed_at", 0)),
            }
        return out

    # ---------------------------------------------------------- behaviour
    def behavior_snapshot(self, agent_id, resource, now, area=None):
        pk = f"AGENT#{agent_id}"
        minute, hour = int(now // 60), int(now // 3600)
        prefix = area if area is not None else resource_prefix(resource)

        def minutes():
            return self.table.query(
                KeyConditionExpression=Key("PK").eq(pk) & Key("SK").between(
                    f"MIN#{minute - 59:012d}", f"MIN#{minute:012d}"),
                ProjectionExpression="#sk, #c, #r",
                ExpressionAttributeNames={"#sk": "SK", "#c": "cnt", "#r": "rec"}).get("Items", [])

        def recent():
            return self.table.query(
                KeyConditionExpression=Key("PK").eq(pk) & Key("SK").begins_with("RECENT#"),
                ScanIndexForward=False, Limit=RECENT_WINDOW,
                ProjectionExpression="#s",
                ExpressionAttributeNames={"#s": "sig"}).get("Items", [])

        def singles():
            keys = [{"PK": pk, "SK": "BASELINE"}, {"PK": pk, "SK": f"HOUR#{hour}"}]
            if prefix:
                keys.append({"PK": pk, "SK": f"SEEN#{resource_key(prefix)}"})
            resp = self.client.batch_get_item(RequestItems={self.table_name: {"Keys": keys}})
            return {i["SK"]: i for i in resp.get("Responses", {}).get(self.table_name, [])}

        f_min, f_rec, f_one = _POOL.submit(minutes), _POOL.submit(recent), _POOL.submit(singles)
        mins, rec, one = f_min.result(), f_rec.result(), f_one.result()

        cur = f"MIN#{minute:012d}"
        last_min = next((int(m["cnt"]) for m in mins if m["SK"] == cur), 0)
        rec_hour = sum(int(m.get("rec", 0)) for m in mins)
        hour_set = set(one.get(f"HOUR#{hour}", {}).get("res", set()))
        bl_item = one.get("BASELINE")
        baseline = Baseline.from_dict(json.loads(bl_item["data"])) if bl_item else Baseline()
        return BehaviorSnapshot(
            actions_last_minute=last_min,
            records_last_hour=rec_hour,
            distinct_resources_last_hour=len(hour_set),
            resource_seen_before=(not prefix) or f"SEEN#{resource_key(prefix)}" in one,
            resource_seen_this_hour=(not resource) or resource_key(resource) in hour_set,
            baseline=baseline,
            recent=[r["sig"] for r in reversed(rec)],
        )

    def record_activity(self, event, action, resource, mediated, now, granted=True, area=None):
        pk = f"AGENT#{event.agent_id}"
        minute, hour = int(now // 60), int(now // 3600)
        records = max(int(event.record_count), 0) if granted else 0
        resp = self.table.update_item(
            Key={"PK": pk, "SK": f"MIN#{minute:012d}"},
            UpdateExpression="ADD cnt :one, rec :rec SET #ttl = :ttl",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={":one": 1, ":rec": records, ":ttl": int(now) + 3 * 3600},
            ReturnValues="UPDATED_NEW")
        first_in_minute = int(resp["Attributes"]["cnt"]) == 1

        writes: list[dict[str, Any]] = [{
            "PK": pk, "SK": f"RECENT#{now:017.6f}#{uuid.uuid4().hex[:6]}",
            "sig": action_signature(event, action, resource)[:600], "ttl": int(now) + 1800}]
        if resource:
            self.table.update_item(
                Key={"PK": pk, "SK": f"HOUR#{hour}"},
                UpdateExpression="ADD res :r SET #ttl = :ttl",
                ExpressionAttributeNames={"#ttl": "ttl"},
                ExpressionAttributeValues={":r": {resource_key(resource)}, ":ttl": int(now) + 3 * 3600})
            prefix = area if area is not None else resource_prefix(resource)
            if prefix and granted:
                writes.append({"PK": pk, "SK": f"SEEN#{resource_key(prefix)}", "prefix": prefix[:900],
                               "ttl": int(now) + 180 * 86400})
            if mediated:
                writes.append({"PK": pk, "SK": f"MED#{resource_key(resource)}", "at": _d(now),
                               "ttl": int(now) + 7200})
        with self.table.batch_writer() as bw:
            for w in writes:
                bw.put_item(Item=w)
        self._update_baseline(pk, minute, records if granted else None, first_in_minute)

    def _update_baseline(self, pk: str, minute: int, records: int | None,
                         first_in_minute: bool, attempts: int = 3) -> None:
        if records is None and not first_in_minute:
            return
        prev_cnt = None
        if first_in_minute:
            prev = self.table.get_item(Key={"PK": pk, "SK": f"MIN#{minute - 1:012d}"}).get("Item")
            prev_cnt = int(prev["cnt"]) if prev else None
        for _ in range(attempts):
            item = self.table.get_item(Key={"PK": pk, "SK": "BASELINE"}, ConsistentRead=True).get("Item")
            version = int(item["ver"]) if item else 0
            bl = Baseline.from_dict(json.loads(item["data"])) if item else Baseline()
            if records is not None:
                bl.add_records(float(records))
            if prev_cnt:
                bl.add_minute(prev_cnt)
            try:
                self.table.put_item(
                    Item={"PK": pk, "SK": "BASELINE", "data": json.dumps(bl.to_dict()), "ver": version + 1},
                    ConditionExpression=Attr("ver").not_exists() | Attr("ver").eq(version))
                return
            except ClientError as e:
                if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
        # Lost the race repeatedly: baselines are statistical, dropping one sample is fine.

    def was_mediated(self, agent_id, resource, since):
        item = self.table.get_item(
            Key={"PK": f"AGENT#{agent_id}", "SK": f"MED#{resource_key(resource)}"},
            ConsistentRead=True).get("Item")
        return bool(item) and float(item["at"]) >= since

    # ---------------------------------------------------------- decisions
    def put_decision(self, decision, event):
        rec = decision.to_dict()
        rec["event"] = event_summary(event)
        ttl = LOG_DECISION_TTL if decision.mode == Mode.LOG else FLAGGED_DECISION_TTL
        self.table.put_item(Item={
            "PK": f"DEC#{decision.decision_id}", "SK": "META",
            "GSI1PK": f"DEC#{_day(decision.timestamp)}",
            "GSI1SK": _tsk(decision.timestamp, decision.decision_id),
            "agent_id": decision.agent_id, "mode_rank": int(decision.mode),
            "ts": _d(decision.timestamp), "data": json.dumps(rec, default=str),
            "ttl": int(decision.timestamp) + ttl,
        })

    def get_decision(self, decision_id):
        item = self.table.get_item(Key={"PK": f"DEC#{decision_id}", "SK": "META"}).get("Item")
        return json.loads(item["data"]) if item else None

    def list_decisions(self, limit=100, agent_id=None, min_mode=Mode.LOG, since=0):
        out: list[dict[str, Any]] = []
        now = time.time()
        start = max(since, now - 30 * 86400)
        day = now
        while day >= start - 86400 and len(out) < limit:
            filt = Attr("mode_rank").gte(int(min_mode))
            if agent_id:
                filt = filt & Attr("agent_id").eq(agent_id)
            kwargs: dict[str, Any] = dict(
                IndexName="GSI1",
                KeyConditionExpression=Key("GSI1PK").eq(f"DEC#{_day(day)}") &
                Key("GSI1SK").gte(f"{since:017.3f}"),
                ScanIndexForward=False, FilterExpression=filt)
            while len(out) < limit:
                resp = self.table.query(**kwargs)
                out.extend(json.loads(i["data"]) for i in resp.get("Items", []))
                if "LastEvaluatedKey" not in resp:
                    break
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            day -= 86400
        return out[:limit]

    # -------------------------------------------------------------- alerts
    def create_alert(self, decision, event):
        aid = uuid.uuid4().hex
        top = decision.findings[0] if decision.findings else None
        rec = {
            "alert_id": aid, "decision_id": decision.decision_id, "agent_id": decision.agent_id,
            "severity": decision.severity.name, "mode": decision.mode.name,
            "verdict": decision.verdict.value, "title": top.title if top else decision.reason,
            "rule_id": top.rule_id if top else "", "detail": decision.reason,
            "status": "OPEN", "approval_id": decision.approval_id, "resource": event.resource,
            "created_at": decision.timestamp, "history": [],
        }
        self.table.put_item(Item={
            "PK": f"ALERT#{aid}", "SK": "META", "GSI1PK": "ALERT#OPEN",
            "GSI1SK": _tsk(decision.timestamp, aid), "data": json.dumps(rec, default=str)})
        return aid

    def list_alerts(self, status="OPEN", limit=200):
        statuses = [status] if status else ["OPEN", "ACKNOWLEDGED", "RESOLVED"]
        out = []
        for s in statuses:
            out.extend(json.loads(i["data"]) for i in self._query_gsi(f"ALERT#{s}", limit=limit))
        out.sort(key=lambda a: a["created_at"], reverse=True)
        return out[:limit]

    def update_alert(self, alert_id, status, actor, note=""):
        item = self.table.get_item(Key={"PK": f"ALERT#{alert_id}", "SK": "META"},
                                   ConsistentRead=True).get("Item")
        if not item:
            raise KeyError(alert_id)
        rec = json.loads(item["data"])
        rec["history"].append({"from": rec["status"], "to": status, "actor": actor,
                               "note": note[:1000], "at": time.time()})
        rec["status"] = status
        self.table.put_item(Item={
            "PK": item["PK"], "SK": "META", "GSI1PK": f"ALERT#{status}",
            "GSI1SK": item["GSI1SK"], "data": json.dumps(rec, default=str)})
        return rec

    def claim_alert_slot(self, key, ttl_seconds, now):
        try:
            self.table.put_item(
                Item={"PK": f"SLOT#{key}", "SK": "SLOT", "at": _d(now), "ttl": int(now + ttl_seconds)},
                ConditionExpression=Attr("PK").not_exists() | Attr("at").lt(_d(now - ttl_seconds)))
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    # ----------------------------------------------------------- approvals
    def create_approval(self, decision, event, expires_at):
        ap_id = uuid.uuid4().hex
        rec = {
            "approval_id": ap_id, "decision_id": decision.decision_id,
            "agent_id": decision.agent_id, "status": "PENDING",
            "severity": decision.severity.name, "reason": decision.reason,
            "findings": [f.to_dict() for f in decision.findings],
            "event": event_summary(event), "created_at": decision.timestamp,
            "expires_at": expires_at, "resolved_by": None, "resolved_at": None, "comment": "",
        }
        self.table.put_item(Item={
            "PK": f"APPROVAL#{ap_id}", "SK": "META", "GSI1PK": "APPROVAL#PENDING",
            "GSI1SK": _tsk(decision.timestamp, ap_id), "status": "PENDING",
            "expires_at": _d(expires_at), "data": json.dumps(rec, default=str)})
        return ap_id

    def _approval_item(self, approval_id):
        return self.table.get_item(Key={"PK": f"APPROVAL#{approval_id}", "SK": "META"},
                                   ConsistentRead=True).get("Item")

    def get_approval(self, approval_id):
        item = self._approval_item(approval_id)
        if not item:
            return None
        rec = json.loads(item["data"])
        rec["status"] = item["status"]
        if rec["status"] == "PENDING" and time.time() > float(item["expires_at"]):
            try:
                return self.resolve_approval(approval_id, ApprovalStatus.EXPIRED, "system:timeout")
            except ValueError:
                return self.get_approval(approval_id)
        rec["task_token"] = item.get("task_token")
        return rec

    def list_approvals(self, status="PENDING", limit=200):
        statuses = [status] if status else ["PENDING", "APPROVED", "REJECTED", "EXPIRED"]
        out = []
        for s in statuses:
            for i in self._query_gsi(f"APPROVAL#{s}", limit=limit):
                rec = json.loads(i["data"])
                rec["status"] = i["status"]
                if rec["status"] == "PENDING" and time.time() > float(i["expires_at"]):
                    if status == "PENDING":
                        continue
                    rec["status"] = "EXPIRED"
                out.append(rec)
        out.sort(key=lambda a: a["created_at"], reverse=True)
        return out[:limit]

    def resolve_approval(self, approval_id, status, actor, comment=""):
        item = self._approval_item(approval_id)
        if not item:
            raise KeyError(approval_id)
        rec = json.loads(item["data"])
        now = time.time()
        rec.update(status=status.value, resolved_by=actor, resolved_at=now, comment=comment[:1000])
        try:
            self.table.update_item(
                Key={"PK": item["PK"], "SK": "META"},
                UpdateExpression="SET #s = :s, GSI1PK = :g, #d = :d",
                ConditionExpression=Attr("status").eq("PENDING"),
                ExpressionAttributeNames={"#s": "status", "#d": "data"},
                ExpressionAttributeValues={":s": status.value, ":g": f"APPROVAL#{status.value}",
                                           ":d": json.dumps(rec, default=str)})
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ValueError(f"approval already {self._approval_item(approval_id)['status']}")
            raise
        rec["task_token"] = item.get("task_token")
        return rec

    def set_approval_token(self, approval_id, token):
        self.table.update_item(
            Key={"PK": f"APPROVAL#{approval_id}", "SK": "META"},
            UpdateExpression="SET task_token = :t",
            ExpressionAttributeValues={":t": token})

    # -------------------------------------------------------------- health
    def record_heartbeat(self, agent_id, now, task_id="", status="ok", detail=""):
        self.table.put_item(Item={
            "PK": f"AGENT#{agent_id}", "SK": "HEARTBEAT", "GSI1PK": "HEARTBEATS",
            "GSI1SK": agent_id, "agent_id": agent_id, "at": _d(now), "task_id": task_id[:200],
            "status": status[:40], "detail": detail[:1000]})

    def get_heartbeats(self):
        return {i["agent_id"]: {"agent_id": i["agent_id"], "at": float(i["at"]),
                                "task_id": i.get("task_id", ""), "status": i.get("status", "ok"),
                                "detail": i.get("detail", "")}
                for i in self._query_gsi("HEARTBEATS")}

    # ---------------------------------------------------------- compliance
    def put_control_result(self, result):
        ts = float(result.get("tested_at", time.time()))
        cid = result["control_id"]
        blob = json.dumps(result, default=str)
        with self.table.batch_writer() as bw:
            bw.put_item(Item={"PK": f"CONTROL#{cid}", "SK": f"RES#{ts:017.3f}", "data": blob,
                              "ttl": int(ts) + 400 * 86400})
            bw.put_item(Item={"PK": f"CONTROL#{cid}", "SK": "LATEST", "GSI1PK": "CONTROLS",
                              "GSI1SK": cid, "data": blob})

    def latest_control_results(self):
        return {json.loads(i["data"])["control_id"]: json.loads(i["data"])
                for i in self._query_gsi("CONTROLS")}

    def control_history(self, control_id, limit=50):
        resp = self.table.query(
            KeyConditionExpression=Key("PK").eq(f"CONTROL#{control_id}") & Key("SK").begins_with("RES#"),
            ScanIndexForward=False, Limit=limit)
        return [json.loads(i["data"]) for i in resp.get("Items", [])]

    def put_risk(self, risk):
        self.table.put_item(Item={"PK": f"RISK#{risk['risk_id']}", "SK": "META", "GSI1PK": "RISKS",
                                  "GSI1SK": risk["risk_id"], "data": json.dumps(risk, default=str)})

    def list_risks(self):
        return [json.loads(i["data"]) for i in self._query_gsi("RISKS")]

    # ------------------------------------------------------------- helpers
    def _query_gsi(self, pk: str, limit: int | None = None) -> list[dict[str, Any]]:
        kwargs: dict[str, Any] = dict(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(pk),
                                      ScanIndexForward=False)
        items: list[dict[str, Any]] = []
        while True:
            resp = self.table.query(**kwargs)
            items.extend(resp.get("Items", []))
            if "LastEvaluatedKey" not in resp or (limit and len(items) >= limit):
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        return items[:limit] if limit else items
