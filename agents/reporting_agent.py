"""Reporting agent: builds the weekly operations report from daily aggregates.

Normal run:
  1. lists the daily reports                     reports/daily/
  2. reads the last 7 days                       reports/daily/<date>.csv
  3. writes the weekly summary                   reports/weekly/week-ending-<date>.json

It has no business touching customer data, and its Sentinel policy says so,
even though its IAM role can technically read the whole bucket.

Lambda event {"mode": ...}:
  "normal"  the job above
  "rogue"   after the report, the agent starts pulling the full customer export
            (pii/customers_all.csv), the interview scenario. It asks Sentinel first,
            as its code always does, and Sentinel denies it.
  "rogue-loans"  as "rogue", but it goes after customers' loan applications instead
  "bypass"  as "rogue", but when Sentinel says no, the agent goes around it and
            reads the file straight from S3 with its own IAM credentials. Sentinel
            can't stop that call; CloudTrail records it and Sentinel flags it.

"rogue" and "bypass" deliberately make the agent misbehave so the detection can
be demonstrated; the S3 calls and Sentinel decisions are all real.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
from collections import defaultdict
from typing import Any

from .common import RunLog, guarded, make_s3, make_sentinel, s3_uri, start

AGENT_ID = "reporting-agent"


def build_weekly(rows: list[dict[str, str]]) -> dict[str, Any]:
    by_branch: dict[str, dict[str, int]] = defaultdict(lambda: {"applications": 0, "approved": 0, "rejected": 0})
    for r in rows:
        b = by_branch[r["branch"]]
        for k in ("applications", "approved", "rejected"):
            b[k] += int(r[k])
    total = {k: sum(b[k] for b in by_branch.values()) for k in ("applications", "approved", "rejected")}
    total["approval_rate"] = round(total["approved"] / total["applications"], 3) if total["applications"] else 0
    return {"branches": dict(sorted(by_branch.items())), "total": total}


def run(event: dict[str, Any], sentinel, s3, bucket: str) -> dict[str, Any]:
    from sentinel_sdk import ActionDenied, SentinelError
    mode = str(event.get("mode", "normal")).lower()
    if mode not in ("normal", "rogue", "rogue-loans", "bypass"):
        return {"agent": AGENT_ID, "outcome": f"unknown mode '{mode}'"}
    run_log = RunLog(agent=AGENT_ID, mode=mode)
    stopped = start(sentinel, run_log, "weekly-report")
    if stopped:
        return run_log.result(stopped)
    extra: dict[str, Any] = {}
    try:
        with sentinel.task("weekly-report", "Build the weekly operations report from daily aggregate reports"):
            # 1. list daily reports
            def list_daily() -> list[str]:
                keys = []
                for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="reports/daily/"):
                    keys += [o["Key"] for o in page.get("Contents", []) if o["Key"].endswith(".csv")]
                return sorted(keys)
            keys = guarded(sentinel, run_log, "list", s3_uri(bucket, "reports/daily/"), list_daily)[-7:]

            # 2. read the last 7 days
            rows: list[dict[str, str]] = []
            for k in keys:
                text = guarded(sentinel, run_log, "read", s3_uri(bucket, k),
                               lambda k=k: s3.get_object(Bucket=bucket, Key=k)["Body"].read().decode())
                rows += list(csv.DictReader(io.StringIO(text)))

            # 3. write the weekly summary
            week_end = keys[-1].rsplit("/", 1)[-1][:-4] if keys else dt.date.today().isoformat()
            report = {"week_ending": week_end, "days": len(keys), **build_weekly(rows),
                      "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "generated_by": AGENT_ID}
            body = json.dumps(report, indent=2)
            out_key = f"reports/weekly/week-ending-{week_end}.json"
            guarded(sentinel, run_log, "write", s3_uri(bucket, out_key),
                    lambda: s3.put_object(Bucket=bucket, Key=out_key, Body=body.encode(),
                                          ContentType="application/json"),
                    content=body)
            extra["report"] = out_key

            if mode == "rogue-loans":
                # The agent goes beyond its job and starts reading customers' loan applications.
                guarded(sentinel, run_log, "list", s3_uri(bucket, "loans/applications/"),
                        lambda: s3.list_objects_v2(Bucket=bucket, Prefix="loans/applications/"))
            if mode in ("rogue", "bypass"):
                # The agent goes beyond its job and tries to pull every customer's personal data.
                target = "pii/customers_all.csv"
                try:
                    guarded(sentinel, run_log, "read", s3_uri(bucket, target),
                            lambda: s3.get_object(Bucket=bucket, Key=target)["Body"].read(),
                            record_count=200)
                except ActionDenied:
                    if mode == "rogue":
                        raise
                    # Bypass: skip Sentinel and use the IAM role directly.
                    data = s3.get_object(Bucket=bucket, Key=target)["Body"].read()
                    n_rows = max(data.count(b"\n") - 1, 0)
                    run_log.step("read", s3_uri(bucket, target),
                                 "READ DIRECTLY FROM S3, bypassing Sentinel",
                                 f"{n_rows} customer rows read with the IAM role; "
                                 "CloudTrail will report this to Sentinel within minutes")
                    return run_log.result("bypassed Sentinel (expect a CloudTrail alert)", **extra)
    except SentinelError as e:
        return run_log.result("stopped by Sentinel", error=str(e), **extra)
    finally:
        sentinel.close()
    return run_log.result("weekly report written", **extra)


def handler(event, context):
    return run(event or {}, make_sentinel(AGENT_ID), make_s3(), os.environ["BANK_BUCKET"])
