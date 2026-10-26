"""KYC agent: verifies new customers' onboarding applications.

Each run picks pending applications (no verification.json yet) and, for each:
  1. reads the application the customer submitted       kyc/<id>/application.json
  2. reads that one customer's record                    pii/customers/<id>.json
  3. checks name and PAN match, Aadhaar checksum, age >= 18
  4. writes the result                                   kyc/<id>/verification.json

It only ever touches one customer at a time, which is exactly what its Sentinel
policy allows. Every S3 operation is checked by Sentinel first.

Lambda event: {"batch": 3, "customer_id": "C-0007" (optional), "mode": "normal" | "harvest"}

"harvest" makes the agent misbehave on purpose: it reads customer records one after
another, far faster than any verification needs. Each single read is something the
agent is allowed to do; only the pattern is wrong, so this exercises Sentinel's
behaviour limits rather than its access rules.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from typing import Any

from .common import RunLog, guarded, make_s3, make_sentinel, s3_uri, start

AGENT_ID = "kyc-agent"

_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def aadhaar_valid(n: str) -> bool:
    if len(n) != 12 or not n.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(n)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def mask(v: str, keep: int = 4) -> str:
    return "*" * max(len(v) - keep, 0) + v[-keep:]


def verify(app: dict[str, Any], person: dict[str, Any], today: dt.date) -> dict[str, Any]:
    dob = dt.date.fromisoformat(person["date_of_birth"])
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    checks = {
        "name_matches": app["declared_name"].strip().lower() == person["name"].strip().lower(),
        "pan_matches": app["declared_pan"].strip().upper() == person["pan"].upper(),
        "aadhaar_checksum_valid": aadhaar_valid(person["aadhaar"]),
        "adult": age >= 18,
    }
    return {
        "customer_id": app["customer_id"], "product": app["product"],
        "status": "VERIFIED" if all(checks.values()) else "REJECTED",
        "checks": checks,
        "failed": [k for k, ok in checks.items() if not ok],
        # Only masked identifiers leave the PII record.
        "pan_masked": mask(person["pan"]), "aadhaar_masked": mask(person["aadhaar"]),
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(), "verified_by": AGENT_ID,
    }


def pending_customers(s3, bucket: str) -> list[str]:
    apps, done = set(), set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="kyc/"):
        for o in page.get("Contents", []):
            parts = o["Key"].split("/")
            if len(parts) == 3 and parts[2] == "application.json":
                apps.add(parts[1])
            elif len(parts) == 3 and parts[2] == "verification.json":
                done.add(parts[1])
    return sorted(apps - done)


def harvest(sentinel, run_log: RunLog, s3, bucket: str) -> dict[str, Any]:
    from sentinel_sdk import SentinelError
    copied = 0
    try:
        with sentinel.task("kyc-batch", "Verify identity documents for pending onboarding applications"):
            for i in range(1, 201):
                key = f"pii/customers/C-{i:04d}.json"
                guarded(sentinel, run_log, "read", s3_uri(bucket, key),
                        lambda key=key: s3.get_object(Bucket=bucket, Key=key)["Body"].read(),
                        wait_on_hold=False)
                copied += 1
    except SentinelError as e:
        return run_log.result("stopped by Sentinel", error=str(e), records_read=copied)
    finally:
        sentinel.close()
    return run_log.result("read every customer record without being stopped", records_read=copied)


def run(event: dict[str, Any], sentinel, s3, bucket: str) -> dict[str, Any]:
    from sentinel_sdk import SentinelError
    mode = str(event.get("mode", "normal")).lower()
    if mode not in ("normal", "harvest"):
        return {"agent": AGENT_ID, "outcome": f"unknown mode '{mode}'"}
    run_log = RunLog(agent=AGENT_ID, mode=mode)
    stopped = start(sentinel, run_log, "kyc-batch")
    if stopped:
        return run_log.result(stopped)
    if mode == "harvest":
        return harvest(sentinel, run_log, s3, bucket)
    results = []
    try:
        with sentinel.task("kyc-batch", "Verify identity documents for pending onboarding applications"):
            if event.get("customer_id"):
                todo = [event["customer_id"]]
            else:
                todo = guarded(sentinel, run_log, "list", s3_uri(bucket, "kyc/"),
                               lambda: pending_customers(s3, bucket))
            batch = todo[: int(event.get("batch", 3))]
            if not batch:
                return run_log.result("nothing to do: all applications verified")
            for cid in batch:
                app_key, pii_key = f"kyc/{cid}/application.json", f"pii/customers/{cid}.json"
                app = guarded(sentinel, run_log, "read", s3_uri(bucket, app_key),
                              lambda: json.loads(s3.get_object(Bucket=bucket, Key=app_key)["Body"].read()))
                person = guarded(sentinel, run_log, "read", s3_uri(bucket, pii_key),
                                 lambda: json.loads(s3.get_object(Bucket=bucket, Key=pii_key)["Body"].read()))
                result = verify(app, person, dt.date.today())
                body = json.dumps(result, indent=2)
                out_key = f"kyc/{cid}/verification.json"
                guarded(sentinel, run_log, "write", s3_uri(bucket, out_key),
                        lambda: s3.put_object(Bucket=bucket, Key=out_key, Body=body.encode(),
                                              ContentType="application/json"),
                        content=body)
                results.append({"customer_id": cid, "status": result["status"], "failed": result["failed"]})
    except SentinelError as e:
        return run_log.result("stopped by Sentinel", error=str(e), verified=results)
    finally:
        sentinel.close()
    return run_log.result(f"verified {len(results)} application(s)", verified=results)


def handler(event, context):
    return run(event or {}, make_sentinel(AGENT_ID), make_s3(), os.environ["BANK_BUCKET"])
