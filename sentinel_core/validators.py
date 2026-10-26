"""Output checks: validate what an agent *decides*, not just what it touches.

Access rules can't tell a correct loan approval from a wrong one; both are the
same write to the same path. Output checks inspect the content an agent is about
to write against business rules held in Sentinel's policy, so a buggy or
manipulated agent can't save a decision that breaks them.

Policy:

    output_checks:
      - id: loan-decisions
        resources: ["s3://bank-*/loans/decisions/*.json"]
        validator: loan_decision
        params: {products: {...}, purpose_keywords: {...}}

Sentinel keeps its own copy of the rules on purpose: an agent that loads the
wrong rules, or has its rules file tampered with, is still checked against the
bank's real ones.

Limitation: validators check the decision's internal consistency and its fit
with the rules. They trust the input figures the agent copied into the decision
(credit score, income, ...); verifying those against the source records would
need Sentinel to read the bank's data itself.
"""
from __future__ import annotations

import json
import math
from typing import Any, Callable

from .models import ActionEvent, Finding, Severity

C_OUTPUT = "AGT-13"

Validator = Callable[[dict[str, Any], dict[str, Any], ActionEvent], list[Finding]]


def _f(rule: str, sev: Severity, title: str, detail: str, **evidence: Any) -> Finding:
    return Finding(detector="output", rule_id=rule, severity=sev, title=title, detail=detail,
                   controls=[C_OUTPUT], evidence=evidence)


def _emi(amount: float, rate: float, months: int) -> float:
    r = rate / 12 / 100
    if r == 0:
        return amount / months
    f = math.pow(1 + r, months)
    return amount * r * f / (f - 1)


def _classify(purpose: str, keywords: dict[str, list[str]]) -> str | None:
    text = f" {purpose.lower()} "
    for category, words in keywords.items():
        if any(w in text for w in words):
            return category
    return None


def loan_decision(doc: dict[str, Any], params: dict[str, Any], ev: ActionEvent) -> list[Finding]:
    products: dict[str, dict[str, Any]] = params.get("products", {})
    keywords: dict[str, list[str]] = params.get("purpose_keywords", {})
    out: list[Finding] = []
    loan = doc.get("loan_id", "?")
    category = doc.get("category")
    if category not in products:
        return [_f("output.loan_unknown_product", Severity.HIGH, "Loan booked under an unknown product",
                   f"{loan}: category '{category}' is not one of the bank's loan products.")]

    # 1. Is the loan in the right category for what the money is for?
    expected = _classify(str(doc.get("purpose", "")), keywords) if keywords else None
    rules_cat = category
    if expected and expected != category:
        out.append(_f("output.loan_misclassified", Severity.MEDIUM, "Loan filed under the wrong product",
                      f"{loan}: purpose \"{doc.get('purpose')}\" is a {expected} loan, but the agent booked "
                      f"it as {category}.", expected=expected, booked=category))
        rules_cat = expected                       # judge the decision by the rules that should apply
    p = products[rules_cat]

    decision = doc.get("decision")
    if decision != "APPROVED":
        return out

    # 2. Does an approval satisfy the product's rules?
    breaches: list[str] = []
    amount, tenure = float(doc.get("amount_inr") or 0), int(doc.get("tenure_months") or 0)
    score = int(doc.get("credit_score") or 0)
    if score < p["min_credit_score"]:
        breaches.append(f"credit score {score} is below the {rules_cat} minimum of {p['min_credit_score']}")
    if amount > p["max_amount"]:
        breaches.append(f"amount ₹{amount:,.0f} exceeds the {rules_cat} limit of ₹{p['max_amount']:,}")
    if tenure > p["max_tenure_months"]:
        breaches.append(f"tenure {tenure} months exceeds {p['max_tenure_months']}")
    needs_col = p.get("collateral") == "required" or (
        p.get("collateral") == "above_threshold" and amount > p.get("collateral_threshold", 0))
    col_val = doc.get("collateral_value_inr")
    if needs_col and not col_val:
        breaches.append(f"no collateral, which {rules_cat} loans of this size require")
    if col_val and amount / float(col_val) > p.get("max_ltv", 1.0) + 1e-9:
        breaches.append(f"loan-to-value {amount / float(col_val):.0%} exceeds {p['max_ltv']:.0%}")
    if p.get("requires_land_records") and not doc.get("land_records_submitted"):
        breaches.append("land records were not submitted")

    rate = doc.get("interest_rate")
    if rate is None:
        breaches.append("approved without an interest rate")
    else:
        rate = float(rate)
        if not (p["rate_min"] - 1e-9 <= rate <= p["rate_max"] + 1e-9):
            out.append(_f("output.loan_rate_out_of_band", Severity.HIGH, "Interest rate outside the product band",
                          f"{loan}: {rate}% is outside the {rules_cat} band of {p['rate_min']}–{p['rate_max']}%.",
                          rate=rate, band=[p["rate_min"], p["rate_max"]], product=rules_cat))
        if tenure and doc.get("monthly_income_inr"):
            foir = (float(doc.get("existing_emi_inr") or 0) + _emi(amount, rate, tenure)) / float(doc["monthly_income_inr"])
            if foir > p["max_foir"] + 1e-6:
                breaches.append(f"repayments would take {foir:.0%} of income (limit {p['max_foir']:.0%})")
            stated = doc.get("foir")
            if stated is not None and abs(float(stated) - foir) > 0.02:
                out.append(_f("output.loan_inconsistent", Severity.MEDIUM, "Decision's own numbers don't add up",
                              f"{loan}: stated FOIR {float(stated):.1%} but the figures give {foir:.1%}.",
                              stated=stated, computed=round(foir, 3)))

    if breaches:
        out.append(_f("output.loan_policy_breach", Severity.HIGH, "Loan approved against the bank's rules",
                      f"{loan} ({rules_cat}): " + "; ".join(breaches) + ".", breaches=breaches,
                      product=rules_cat))
    return out


VALIDATORS: dict[str, Validator] = {"loan_decision": loan_decision}


def evaluate_outputs(ev: ActionEvent, action: str, resource: str, checks: list[dict[str, Any]]) -> list[Finding]:
    if action not in ("write", "output", "message") or not checks:
        return []
    from .policy import any_match
    findings: list[Finding] = []
    for chk in checks:
        if not any_match(chk["resources"], resource):
            continue
        try:
            doc = json.loads(ev.content or "")
            if not isinstance(doc, dict):
                raise ValueError("not a JSON object")
        except (ValueError, TypeError) as e:
            findings.append(_f("output.unreadable", Severity.MEDIUM, "Agent output could not be checked",
                               f"Output for check '{chk['id']}' is not valid JSON ({e}).", check=chk["id"]))
            continue
        for f in VALIDATORS[chk["validator"]](doc, chk.get("params") or {}, ev):
            f.evidence.setdefault("check", chk["id"])
            findings.append(f)
    return findings
