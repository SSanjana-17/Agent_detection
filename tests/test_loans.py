"""Loan agent, Sentinel's decision checks, and the extra rogue scenarios."""
import json
import threading
import time
from pathlib import Path

import pytest
import yaml

from agents import kyc_agent, loan_agent, reporting_agent
from demo.generate_data import PRODUCTS, PURPOSE_KEYWORDS, PURPOSES
from sentinel_core.models import ActionEvent, AgentStatus, Severity
from sentinel_core.service import Identity
from sentinel_core.validators import loan_decision
from test_demo_agents import BUCKET, bank, client  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parent.parent
PARAMS = {"products": PRODUCTS, "purpose_keywords": PURPOSE_KEYWORDS}
EV = ActionEvent(agent_id="loan-agent", action="write")


def rules_from_s3(s3):
    return json.loads(s3.get_object(Bucket=BUCKET, Key="config/loan_products.json")["Body"].read())


def good_home_loan(**over):
    d = {"loan_id": "L-9", "purpose": "buying a 2BHK flat in Whitefield", "category": "home",
         "decision": "APPROVED", "interest_rate": 8.75, "amount_inr": 4000000, "tenure_months": 240,
         "credit_score": 780, "monthly_income_inr": 150000, "existing_emi_inr": 0,
         "collateral_type": "property", "collateral_value_inr": 6000000, "land_records_submitted": None}
    d["foir"] = round((0 + loan_agent.emi(4000000, 8.75, 240)) / 150000, 3)
    d.update(over)
    return d


# ------------------------------------------------------------ policy sync

def test_sentinel_rules_match_the_banks_rules():
    pol = yaml.safe_load((ROOT / "policies" / "policy.yaml").read_text())
    params = pol["output_checks"][0]["params"]
    assert params["products"] == PRODUCTS, "policy loan rules drifted from demo/generate_data.py"
    assert params["purpose_keywords"] == PURPOSE_KEYWORDS


@pytest.mark.parametrize("category,purposes", PURPOSES.items())
def test_every_purpose_text_classifies_correctly(category, purposes):
    for p in purposes:
        assert loan_agent.classify(p, PURPOSE_KEYWORDS) == category, p


# ------------------------------------------------------------ validator

def test_valid_approval_passes():
    assert loan_decision(good_home_loan(), PARAMS, EV) == []


@pytest.mark.parametrize("over,needle", [
    ({"credit_score": 640}, "credit score 640"),
    ({"collateral_value_inr": None, "collateral_type": None}, "no collateral"),
    ({"collateral_value_inr": 4200000}, "loan-to-value"),
    ({"amount_inr": 25000000, "collateral_value_inr": 40000000}, "exceeds the home limit"),
    ({"monthly_income_inr": 40000}, "repayments would take"),
])
def test_rule_breaking_approval_is_caught(over, needle):
    doc = good_home_loan(**over)
    doc["foir"] = round(loan_agent.emi(doc["amount_inr"], 8.75, 240) / doc["monthly_income_inr"], 3)
    fs = loan_decision(doc, PARAMS, EV)
    breach = next(f for f in fs if f.rule_id == "output.loan_policy_breach")
    assert breach.severity == Severity.HIGH and needle in breach.detail, breach.detail


def test_rate_outside_band_and_bad_arithmetic():
    fs = {f.rule_id for f in loan_decision(good_home_loan(interest_rate=12.5), PARAMS, EV)}
    assert "output.loan_rate_out_of_band" in fs
    fs = {f.rule_id for f in loan_decision(good_home_loan(foir=0.05), PARAMS, EV)}
    assert "output.loan_inconsistent" in fs


def test_misfiled_education_loan_is_flagged_and_judged_by_education_rules():
    doc = {"loan_id": "L-5", "purpose": "MBA tuition fees at a business school", "category": "personal",
           "decision": "APPROVED", "interest_rate": 13.25, "amount_inr": 900000, "tenure_months": 60,
           "credit_score": 730, "monthly_income_inr": 200000, "existing_emi_inr": 0,
           "collateral_value_inr": 1200000}
    fs = {f.rule_id: f for f in loan_decision(doc, PARAMS, EV)}
    assert fs["output.loan_misclassified"].severity == Severity.MEDIUM
    assert "8.5–11.0%" in fs["output.loan_rate_out_of_band"].detail


def test_rejections_are_not_held():
    assert loan_decision(good_home_loan(decision="REJECTED", credit_score=500), PARAMS, EV) == []


def test_unreadable_output_is_flagged(bank):
    _, svc = bank
    d = svc.decide({"agent_id": "loan-agent", "action": "write", "content": "not json",
                    "resource": f"s3://{BUCKET}/loans/decisions/L-0001.json"}, Identity(kind="local"))
    assert any(f["rule_id"] == "output.unreadable" for f in d["findings"])


# ------------------------------------------------------------ loan agent

def test_loan_agent_decides_applications(bank):
    s3, svc = bank
    out = loan_agent.run({"mode": "normal", "batch": 6}, client(svc, "loan-agent"), s3, BUCKET)
    assert out["outcome"] == "decided 6 application(s)", out
    assert {d["decision"] for d in out["decided"]} <= {"APPROVED", "REJECTED", "PENDING_KYC (will retry)"}
    for d in out["decided"]:
        if d["decision"].startswith("PENDING_KYC"):
            continue
        doc = json.loads(s3.get_object(Bucket=BUCKET, Key=f"loans/decisions/{d['loan_id']}.json")["Body"].read())
        assert doc["category"] in PRODUCTS
        assert "applicant_name" not in doc and "pan" not in doc, "decisions carry no personal identifiers"
        # Sentinel's independent check agrees with every decision the correct agent makes
        assert not [f for f in loan_decision(doc, PARAMS, EV) if f.severity >= Severity.HIGH], doc
    assert all(d["verdict"] == "ALLOW" for d in svc.store.list_decisions(limit=200, agent_id="loan-agent"))


def test_correct_agent_never_breaks_the_rules_across_all_applications(bank):
    s3, _ = bank
    rules = rules_from_s3(s3)
    for i in range(1, 121):
        app = json.loads(s3.get_object(Bucket=BUCKET, Key=f"loans/applications/L-{i:04d}.json")["Body"].read())
        result = loan_agent.evaluate(app, {"status": "VERIFIED"}, rules)
        bad = [f for f in loan_decision(result, PARAMS, EV) if f.severity >= Severity.HIGH]
        assert not bad, (app["loan_id"], [f.detail for f in bad])


def test_faulty_approval_is_held_for_a_human(bank):
    s3, svc = bank
    out = loan_agent.run({"mode": "faulty-approval"}, client(svc, "loan-agent"), s3, BUCKET)
    held = [s for s in out["steps"] if "REJECTED by reviewer" in s["outcome"] or "HELD" in s["outcome"]]
    assert held, out
    assert out["decided"][0]["decision"].startswith("NOT SAVED")
    ap = svc.store.list_approvals(status=None)[0]
    assert any(f["rule_id"] == "output.loan_policy_breach" for f in ap["findings"])
    loan_id = out["decided"][0]["loan_id"]
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET, Prefix="loans/decisions/").get("Contents", [])]
    assert f"loans/decisions/{loan_id}.json" not in keys, "the bad approval was never saved"


def test_human_can_approve_a_held_decision(bank, human):
    s3, svc = bank
    sentinel = client(svc, "loan-agent")
    sentinel.hold_max_wait_seconds = 5

    def approver():
        for _ in range(200):
            pending = svc.store.list_approvals("PENDING")
            if pending:
                svc.resolve_approval(pending[0]["approval_id"], True, "exception approved by credit head", human)
                return
            time.sleep(0.02)

    threading.Thread(target=approver).start()
    out = loan_agent.run({"mode": "faulty-approval"}, sentinel, s3, BUCKET)
    assert out["decided"][0]["decision"] == "APPROVED"
    assert any("after approval by" in s["outcome"] for s in out["steps"])


def test_mixup_is_caught(bank):
    s3, svc = bank
    out = loan_agent.run({"mode": "mixup"}, client(svc, "loan-agent"), s3, BUCKET)
    assert out["decided"], out
    rules = {f["rule_id"] for d in svc.store.list_decisions(limit=50, agent_id="loan-agent")
             for f in d["findings"]}
    assert "output.loan_misclassified" in rules


def test_loan_agent_exfiltration_is_blocked_and_quarantined(bank):
    s3, svc = bank
    out = loan_agent.run({"mode": "exfiltrate", "batch": 1}, client(svc, "loan-agent"), s3, BUCKET)
    assert out["outcome"] == "stopped by Sentinel"
    assert out["steps"][-1]["action"] == "network" and out["steps"][-1]["outcome"] == "DENIED by Sentinel"
    assert svc.store.get_agent_status("loan-agent")[0] == AgentStatus.QUARANTINED
    d = svc.store.list_decisions(limit=1, agent_id="loan-agent")[0]
    assert {"dlp.pii_exfiltration", "egress.unapproved_destination"} <= {f["rule_id"] for f in d["findings"]}


# ------------------------------------------------------------ other rogue scenarios

def test_kyc_harvest_is_held_by_behaviour_limits(bank):
    s3, svc = bank
    out = kyc_agent.run({"mode": "harvest"}, client(svc, "kyc-agent"), s3, BUCKET)
    assert out["outcome"] == "stopped by Sentinel", out
    # How many records get through before the rate rule trips depends on timing: the limit
    # is per-minute real-time, so under load (e.g. the full suite) the window advances as
    # reads are spaced out and a few more get through. Allow a generous range — what matters
    # is that the harvest is held by the rate rule, which the asserts around this enforce.
    assert 50 <= out["records_read"] <= 200, out["records_read"]
    ap = svc.store.list_approvals("PENDING")[0]
    assert any(f["rule_id"] == "rate.actions_per_minute" for f in ap["findings"])


def test_reporting_agent_going_for_loans_is_quarantined(bank):
    s3, svc = bank
    out = reporting_agent.run({"mode": "rogue-loans"}, client(svc, "reporting-agent"), s3, BUCKET)
    assert out["outcome"] == "stopped by Sentinel"
    assert out["steps"][-1]["resource"].endswith("loans/applications/")
    assert svc.store.get_agent_status("reporting-agent")[0] == AgentStatus.QUARANTINED


def test_loan_agent_cannot_read_customer_pii_directly(bank):
    _, svc = bank
    from sentinel_sdk import ActionDenied
    with pytest.raises(ActionDenied):
        client(svc, "loan-agent").check("read", f"s3://{BUCKET}/pii/customers/C-0001.json")
