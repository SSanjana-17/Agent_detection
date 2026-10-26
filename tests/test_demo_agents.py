"""The two demo agents doing real work on (emulated) S3 through a real Sentinel engine
loaded with the deployed demo policy."""
import json
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from agents import kyc_agent, reporting_agent
from demo.generate_data import generate
from sentinel_core.models import AgentStatus
from sentinel_core.policy import load_policy
from sentinel_core.service import SentinelService
from sentinel_core.store import MemoryStore
from sentinel_sdk import Sentinel
from sentinel_sdk.transport import HttpTransport, LocalTransport

ROOT = Path(__file__).resolve().parent.parent
BUCKET = "sentinel-demo-bank-123456789012"
REPORTING_ARN = "arn:aws:sts::123456789012:assumed-role/sentinel-demo-reporting-agent/sentinel-demo-reporting-agent"
KYC_ARN = "arn:aws:sts::123456789012:assumed-role/sentinel-demo-kyc-agent/sentinel-demo-kyc-agent"


@pytest.fixture
def bank(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    with mock_aws():
        s3 = boto3.client("s3", region_name="ap-south-1")
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
        data = generate(tmp_path / "data")
        for f in data.rglob("*"):
            if f.is_file():
                s3.put_object(Bucket=BUCKET, Key=f.relative_to(data).as_posix(), Body=f.read_bytes())
        pol = load_policy(ROOT / "policies" / "policy.yaml")
        svc = SentinelService(lambda: pol, MemoryStore())
        yield s3, svc


def client(svc, agent):
    return Sentinel(agent_id=agent, transport=LocalTransport(service=svc),
                    hold_max_wait_seconds=1, hold_poll_seconds=0.1)


def test_kyc_agent_verifies_customers(bank):
    s3, svc = bank
    out = kyc_agent.run({"batch": 3}, client(svc, "kyc-agent"), s3, BUCKET)
    assert out["outcome"] == "verified 3 application(s)", out
    assert all(s["outcome"].startswith("ALLOWED") for s in out["steps"] if s["action"] != "heartbeat")
    for v in out["verified"]:
        doc = json.loads(s3.get_object(Bucket=BUCKET, Key=f"kyc/{v['customer_id']}/verification.json")["Body"].read())
        assert doc["status"] in ("VERIFIED", "REJECTED")
        assert "*" in doc["pan_masked"], "only masked identifiers are written"
    # next run moves on to the next pending customers
    out2 = kyc_agent.run({"batch": 2}, client(svc, "kyc-agent"), s3, BUCKET)
    assert {v["customer_id"] for v in out2["verified"]}.isdisjoint({v["customer_id"] for v in out["verified"]})
    decisions = svc.store.list_decisions(limit=100, agent_id="kyc-agent")
    assert decisions and all(d["verdict"] == "ALLOW" for d in decisions)


def test_kyc_agent_catches_mismatched_application(bank):
    s3, svc = bank

    def doc(key):
        return json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())

    mismatched = next(f"C-{i:04d}" for i in range(1, 201)
                      if doc(f"kyc/C-{i:04d}/application.json")["declared_pan"]
                      != doc(f"pii/customers/C-{i:04d}.json")["pan"])
    out = kyc_agent.run({"customer_id": mismatched}, client(svc, "kyc-agent"), s3, BUCKET)
    assert out["verified"][0]["status"] == "REJECTED"
    assert "pan_matches" in out["verified"][0]["failed"]


def test_rate_limit_holds_a_runaway_kyc_agent(bank):
    """40 back-to-back runs exceed 60 actions/minute: Sentinel holds the agent for a human."""
    s3, svc = bank
    outcomes = [kyc_agent.run({"customer_id": f"C-{i:04d}"}, client(svc, "kyc-agent"), s3, BUCKET)["outcome"]
                for i in range(1, 41)]
    assert "stopped by Sentinel" in outcomes
    assert any(a["status"] in ("EXPIRED", "PENDING") for a in svc.store.list_approvals(status=None))


def test_kyc_agent_cannot_pull_full_customer_export(bank):
    s3, svc = bank
    from sentinel_sdk import ActionDenied
    s = client(svc, "kyc-agent")
    with pytest.raises(ActionDenied):
        s.check("read", f"s3://{BUCKET}/pii/customers_all.csv", record_count=200)


def test_reporting_agent_normal_run(bank):
    s3, svc = bank
    out = reporting_agent.run({"mode": "normal"}, client(svc, "reporting-agent"), s3, BUCKET)
    assert out["outcome"] == "weekly report written", out
    report = json.loads(s3.get_object(Bucket=BUCKET, Key=out["report"])["Body"].read())
    assert report["days"] == 7 and report["total"]["applications"] > 0
    assert len([s for s in out["steps"] if s["action"] == "read"]) == 7


def test_interview_scenario_reporting_agent_goes_for_pii(bank):
    s3, svc = bank
    out = reporting_agent.run({"mode": "rogue"}, client(svc, "reporting-agent"), s3, BUCKET)
    assert out["outcome"] == "stopped by Sentinel"
    denied = [s for s in out["steps"] if s["outcome"] == "DENIED by Sentinel"]
    assert denied and denied[0]["resource"].endswith("pii/customers_all.csv")
    assert svc.store.get_agent_status("reporting-agent")[0] == AgentStatus.QUARANTINED
    d = svc.store.list_decisions(limit=1, agent_id="reporting-agent")[0]
    assert d["mode"] == "QUARANTINE" and {"access.unauthorized", "access.clearance_exceeded"} <= {
        f["rule_id"] for f in d["findings"]}
    # A quarantined agent doesn't start its next scheduled run.
    again = reporting_agent.run({"mode": "normal"}, client(svc, "reporting-agent"), s3, BUCKET)
    assert again["outcome"] == "quarantined"


def test_bypass_is_caught_from_cloudtrail(bank):
    s3, svc = bank
    out = reporting_agent.run({"mode": "bypass"}, client(svc, "reporting-agent"), s3, BUCKET)
    assert out["outcome"].startswith("bypassed Sentinel")
    assert any("bypassing Sentinel" in s["outcome"] for s in out["steps"])
    # The direct S3 read appears in CloudTrail; Sentinel finds no matching decision for it.
    d = svc.ingest_cloudtrail({
        "eventName": "GetObject", "eventSource": "s3.amazonaws.com",
        "requestParameters": {"bucketName": BUCKET, "key": "pii/customers_all.csv"},
        "userIdentity": {"arn": REPORTING_ARN}})
    assert d["agent_id"] == "reporting-agent"
    assert any(f["rule_id"] == "bypass.unmediated_access" for f in d["findings"])


def test_kyc_reads_through_sentinel_are_not_flagged_as_bypass(bank):
    s3, svc = bank
    out = kyc_agent.run({"customer_id": "C-0005"}, client(svc, "kyc-agent"), s3, BUCKET)
    assert out["verified"]
    d = svc.ingest_cloudtrail({
        "eventName": "GetObject", "requestParameters": {"bucketName": BUCKET, "key": "pii/customers/C-0005.json"},
        "userIdentity": {"arn": KYC_ARN}})
    assert d["mode"] == "LOG"


def test_seed_data_role_is_trusted(bank):
    s3, svc = bank
    d = svc.ingest_cloudtrail({
        "eventName": "PutObject", "requestParameters": {"bucketName": BUCKET, "key": "pii/customers/C-0001.json"},
        "userIdentity": {"arn": "arn:aws:sts::123456789012:assumed-role/SentinelDemo-CustomCDKBucketDeployment8693BB-ab/x"}})
    assert d["mode"] == "LOG"


def test_agents_fail_closed_when_sentinel_unreachable(bank):
    s3, _ = bank
    dead = Sentinel(agent_id="kyc-agent", transport=HttpTransport("http://127.0.0.1:1", auth="none",
                                                                  timeout=0.2, retries=0))
    def verified():
        keys = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix="kyc/"):
            keys += [o["Key"] for o in page.get("Contents", []) if o["Key"].endswith("verification.json")]
        return set(keys)
    before = verified()
    out = kyc_agent.run({"batch": 1}, dead, s3, BUCKET)
    assert out["outcome"] == "sentinel_unreachable"
    assert verified() == before, "nothing was written while Sentinel was unreachable"


def test_demo_policy_maps_lambda_roles_to_agents():
    pol = load_policy(ROOT / "policies" / "policy.yaml")
    assert pol.agent_for_principal(KYC_ARN).agent_id == "kyc-agent"
    assert pol.agent_for_principal(REPORTING_ARN).agent_id == "reporting-agent"
    assert pol.agent_for_principal("arn:aws:sts::1:assumed-role/other-role/x") is None
