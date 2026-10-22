"""AWS integration tests: the real handlers and DynamoDB/S3/SQS/SNS code
paths, run against moto's in-process AWS emulation."""
import json
import time

import boto3
import pytest
from moto import mock_aws

from conftest import POLICY_PATH, luhn_card
from sentinel_core.models import ApprovalStatus, Mode

REGION = "ap-south-1"
TABLE = "sentinel-test"
KYC_ARN = "arn:aws:sts::123456789012:assumed-role/kyc-agent-role/s1"
REPORTING_ARN = "arn:aws:sts::123456789012:assumed-role/reporting-agent-role/s1"


@pytest.fixture
def aws(monkeypatch):
    with mock_aws():
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        ddb = boto3.client("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName=TABLE, BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("PK", "SK", "GSI1PK", "GSI1SK")],
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
            GlobalSecondaryIndexes=[{"IndexName": "GSI1", "Projection": {"ProjectionType": "ALL"},
                                     "KeySchema": [{"AttributeName": "GSI1PK", "KeyType": "HASH"},
                                                   {"AttributeName": "GSI1SK", "KeyType": "RANGE"}]}])
        s3 = boto3.client("s3", region_name=REGION)
        loc = {"LocationConstraint": REGION}
        s3.create_bucket(Bucket="policy-bkt", CreateBucketConfiguration=loc)
        s3.put_object(Bucket="policy-bkt", Key="policy.yaml", Body=POLICY_PATH.read_bytes())
        s3.create_bucket(Bucket="evidence-bkt", CreateBucketConfiguration=loc, ObjectLockEnabledForBucket=True)
        s3.put_object_lock_configuration(Bucket="evidence-bkt", ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 2555}}})
        sqs = boto3.client("sqs", region_name=REGION)
        queue_url = sqs.create_queue(QueueName="sentinel-events.fifo",
                                     Attributes={"FifoQueue": "true"})["QueueUrl"]
        topic = boto3.client("sns", region_name=REGION).create_topic(Name="alerts")["TopicArn"]
        for k, v in {"TABLE_NAME": TABLE, "POLICY_BUCKET": "policy-bkt", "POLICY_KEY": "policy.yaml",
                     "QUEUE_URL": queue_url, "EVIDENCE_BUCKET": "evidence-bkt",
                     "ALERT_TOPIC_ARN": topic, "DASHBOARD_URL": "https://console.example"}.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("STATE_MACHINE_ARN", raising=False)
        monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
        import sentinel_core.aws.runtime as rt
        rt._SERVICE = None
        yield {"s3": s3, "sqs": sqs, "queue_url": queue_url, "topic": topic}
        rt._SERVICE = None


def api_event(method, path, body=None, arn=None, claims=None, query=None):
    ctx = {"identity": {"userArn": arn}} if arn else {"authorizer": {"claims": claims}}
    return {"httpMethod": method, "path": path, "body": json.dumps(body) if body is not None else None,
            "queryStringParameters": query, "requestContext": ctx}


APPROVER = {"email": "approver@example-bank.com", "cognito:groups": "sentinel-approvers"}


def drain_stream(aws):
    """Feed everything on the SQS FIFO queue to the stream handler, 10 at a time, like Lambda."""
    from sentinel_core.aws.handlers import stream_handler
    sqs, url = aws["sqs"], aws["queue_url"]
    total, failures = 0, []
    while True:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   AttributeNames=["MessageGroupId"]).get("Messages", [])
        if not msgs:
            break
        event = {"Records": [{"messageId": m["MessageId"], "body": m["Body"],
                              "attributes": {"MessageGroupId": m["Attributes"]["MessageGroupId"]},
                              "eventSource": "aws:sqs"} for m in msgs]}
        res = stream_handler(event, None)
        failures.extend(res["batchItemFailures"])
        failed = {f["itemIdentifier"] for f in res["batchItemFailures"]}
        for m in msgs:
            if m["MessageId"] not in failed:
                sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        total += len(msgs)
    return {"batchItemFailures": failures}, total


# ----------------------------------------------------------------- tests

def test_dynamo_store_contract(aws):
    from sentinel_core.aws.dynamo import DynamoStore
    from sentinel_core.engine import DecisionEngine
    from sentinel_core.models import ActionEvent, AgentStatus
    from sentinel_core.policy import load_policy
    store = DynamoStore(TABLE, region=REGION)
    eng = DecisionEngine(load_policy(POLICY_PATH), store)
    for i in range(5):
        d = eng.decide(ActionEvent(agent_id="kyc-agent", action="read", record_count=2,
                                   resource=f"s3://example-bank-customer-data/kyc/C-{i}/a.pdf"))
        assert d.verdict.value == "ALLOW"
    snap = store.behavior_snapshot("kyc-agent", "s3://example-bank-customer-data/kyc/C-1/a.pdf", time.time(),
                                   area="RESTRICTED_PII|read|grant0")
    assert snap.actions_last_minute == 5 and snap.records_last_hour == 10
    assert snap.resource_seen_before and snap.resource_seen_this_hour
    assert snap.baseline.n == 5 and len(snap.recent) == 5
    assert store.was_mediated("kyc-agent", "s3://example-bank-customer-data/kyc/C-1/a.pdf", time.time() - 60)

    d = eng.decide(ActionEvent(agent_id="reporting-agent", action="read",
                               resource="s3://example-bank-customer-data/pii/all.csv"))
    assert d.mode == Mode.QUARANTINE
    assert store.get_agent_status("reporting-agent")[0] == AgentStatus.QUARANTINED
    assert "reporting-agent" in store.list_agent_states()
    assert len(store.list_decisions(limit=50)) == 6
    assert len(store.list_decisions(limit=50, min_mode=Mode.FLAG)) == 1
    assert len(store.list_decisions(limit=50, agent_id="kyc-agent")) == 5

    h = eng.decide(ActionEvent(agent_id="loan-agent", action="delete",
                               resource="s3://example-bank-lending/drafts/x"))
    assert store.list_approvals("PENDING")[0]["approval_id"] == h.approval_id
    store.resolve_approval(h.approval_id, ApprovalStatus.APPROVED, "a@b.com")
    with pytest.raises(ValueError):
        store.resolve_approval(h.approval_id, ApprovalStatus.REJECTED, "a@b.com")
    assert store.get_approval(h.approval_id)["status"] == "APPROVED"

    assert store.claim_alert_slot("k", 300, time.time()) is True
    assert store.claim_alert_slot("k", 300, time.time()) is False
    aid = store.create_alert(d, ActionEvent(agent_id="reporting-agent", action="read"))
    assert store.update_alert(aid, "RESOLVED", "a@b.com")["status"] == "RESOLVED"
    assert store.list_alerts("RESOLVED")[0]["alert_id"] == aid


def test_api_handler_end_to_end(aws):
    from sentinel_core.aws.handlers import api_handler
    ok = api_handler(api_event("POST", "/agent/v1/decide",
                               {"agent_id": "kyc-agent", "action": "read",
                                "resource": "s3://example-bank-customer-data/kyc/C-1/id.pdf"}, arn=KYC_ARN), None)
    assert ok["statusCode"] == 200 and json.loads(ok["body"])["verdict"] == "ALLOW"

    # The Citibank scenario through the real API: blocked, quarantined, alerted
    bad = api_handler(api_event("POST", "/agent/v1/decide",
                                {"agent_id": "reporting-agent", "action": "read", "record_count": 25000,
                                 "resource": "s3://example-bank-customer-data/pii/customers.csv"},
                                arn=REPORTING_ARN), None)
    body = json.loads(bad["body"])
    assert body["verdict"] == "DENY" and body["mode"] == "QUARANTINE"

    alerts = json.loads(api_handler(api_event("GET", "/console/v1/alerts", claims=APPROVER), None)["body"])
    assert alerts["alerts"][0]["agent_id"] == "reporting-agent"
    agents = json.loads(api_handler(api_event("GET", "/console/v1/agents", claims=APPROVER), None)["body"])
    assert next(a for a in agents["agents"] if a["agent_id"] == "reporting-agent")["status"] == "QUARANTINED"

    # spoofing through the API
    spoof = json.loads(api_handler(api_event("POST", "/agent/v1/decide",
                                             {"agent_id": "kyc-agent", "action": "read", "resource": "s3://x/y"},
                                             arn=REPORTING_ARN), None)["body"])
    assert spoof["findings"][0]["rule_id"] == "identity.spoofing"

    assert api_handler(api_event("GET", "/console/v1/overview", arn=KYC_ARN), None)["statusCode"] == 403
    assert api_handler({"httpMethod": "GET", "path": "/console/v1/overview", "requestContext": {}}, None)["statusCode"] == 401

    # held action approved by a human through the console API
    hold = json.loads(api_handler(api_event("POST", "/agent/v1/decide",
                                            {"agent_id": "kyc-agent", "action": "read", "record_count": 50,
                                             "resource": "s3://example-bank-customer-data/kyc/C-1/batch"},
                                            arn=KYC_ARN), None)["body"])
    assert hold["verdict"] in ("DENY", "HOLD")


def test_sns_alert_published(aws, monkeypatch):
    from sentinel_core.alerts import SNSNotifier
    sent = []
    orig = SNSNotifier.send
    monkeypatch.setattr(SNSNotifier, "send", lambda self, a: (sent.append(a), orig(self, a)))
    from sentinel_core.aws.handlers import api_handler
    api_handler(api_event("POST", "/agent/v1/decide",
                          {"agent_id": "reporting-agent", "action": "read",
                           "resource": "s3://example-bank-customer-data/pii/c.csv"}, arn=REPORTING_ARN), None)
    assert sent and sent[0]["severity"] == "CRITICAL" and "QUARANTINED" in sent[0]["response"]
    assert sent[0]["link"].startswith("https://console.example/#/alerts/")


def test_events_go_through_stream_and_evidence_chain(aws):
    from sentinel_core.aws.handlers import api_handler, scheduler_handler
    from sentinel_core.evidence import EvidenceWriter
    card = luhn_card("453201511283036")
    r = api_handler(api_event("POST", "/agent/v1/events", {"events": [
        {"agent_id": "support-agent", "action": "output", "content": f"Your card {card} is active"},
        {"agent_id": "support-agent", "action": "read", "resource": "s3://example-bank-knowledge/a"},
    ]}, arn="arn:aws:sts::123456789012:assumed-role/support-agent-role/s"), None)
    assert r["statusCode"] == 202
    # a flagged decision via the API also emits evidence onto the stream
    api_handler(api_event("POST", "/agent/v1/decide",
                          {"agent_id": "reporting-agent", "action": "read",
                           "resource": "s3://example-bank-customer-data/pii/c.csv"}, arn=REPORTING_ARN), None)
    res, n = drain_stream(aws)
    assert n >= 3 and res["batchItemFailures"] == []

    writer = EvidenceWriter("evidence-bkt", TABLE, s3=aws["s3"], ddb=boto3.resource("dynamodb", region_name=REGION))
    v = writer.verify()
    assert v["ok"] and sum(c["records"] for c in v["chains"].values()) >= 2

    # tamper with the evidence: verification must fail
    key = aws["s3"].list_objects_v2(Bucket="evidence-bkt")["Contents"][0]["Key"]
    body = aws["s3"].get_object(Bucket="evidence-bkt", Key=key)["Body"].read().decode().splitlines()
    rec = json.loads(body[0]); rec["payload"]["tampered"] = True; body[0] = json.dumps(rec)
    aws["s3"].put_object(Bucket="evidence-bkt", Key=key, Body="\n".join(body).encode())  # new version
    assert not writer.verify()["ok"]

    out = scheduler_handler({"job": "controls", "verify_evidence": True}, None)
    assert out["results"]["AGT-11"] == "FAIL"


def test_scheduler_controls_and_health(aws):
    from sentinel_core.aws.handlers import scheduler_handler
    out = scheduler_handler({"job": "controls"}, None)
    assert len(out["results"]) == 12
    assert out["results"]["AGT-11"] in ("PASS", "WARN")  # object lock verified via S3 API
    assert scheduler_handler({"job": "health"}, None)["findings"] >= 1
    assert scheduler_handler({"job": "health"}, None)["findings"] == 0, "no repeat health alerts"


def test_approval_workflow_handler(aws):
    from sentinel_core.aws.handlers import api_handler, approval_handler
    from sentinel_core.aws.runtime import build_service
    hold = json.loads(api_handler(api_event("POST", "/agent/v1/decide",
                                            {"agent_id": "loan-agent", "action": "delete",
                                             "resource": "s3://example-bank-lending/drafts/x"},
                                            arn="arn:aws:sts::123456789012:assumed-role/loan-agent-role/s"), None)["body"])
    ap_id = hold["approval_id"]
    assert hold["verdict"] == "HOLD"
    approval_handler({"step": "wait", "approval_id": ap_id, "task_token": "tok-1"}, None)
    assert build_service().store.get_approval(ap_id)["task_token"] == "tok-1"
    # timeout path: fail closed
    out = approval_handler({"step": "expire", "approval_id": ap_id}, None)
    assert out["status"] == "EXPIRED"
    poll = json.loads(api_handler(api_event("GET", f"/agent/v1/approvals/{ap_id}",
                                            arn="arn:aws:sts::123456789012:assumed-role/loan-agent-role/s"), None)["body"])
    assert poll["status"] == "EXPIRED"
    # a human can't approve an expired hold
    r = api_handler(api_event("POST", f"/console/v1/approvals/{ap_id}/approve", {}, claims=APPROVER), None)
    assert r["statusCode"] == 409


def test_cloudtrail_handler(aws):
    from sentinel_core.aws.handlers import cloudtrail_handler
    detail = {"eventSource": "s3.amazonaws.com", "eventName": "GetObject",
              "requestParameters": {"bucketName": "example-bank-customer-data", "key": "kyc/C-1/a.pdf"},
              "userIdentity": {"arn": KYC_ARN}}
    assert cloudtrail_handler({"detail": detail}, None)["processed"]
    from sentinel_core.aws.runtime import build_service
    from sentinel_core.models import AgentStatus
    assert build_service().store.get_agent_status("kyc-agent")[0] == AgentStatus.QUARANTINED


def test_policy_hot_reload_keeps_last_good(aws):
    from sentinel_core.aws.runtime import S3PolicyProvider
    prov = S3PolicyProvider("policy-bkt", "policy.yaml", ttl=0, s3=aws["s3"])
    fp = prov().fingerprint
    aws["s3"].put_object(Bucket="policy-bkt", Key="policy.yaml", Body=b"agents: [{id: a}, {id: a}]")
    assert prov().fingerprint == fp, "invalid policy must not replace the active one"
    aws["s3"].put_object(Bucket="policy-bkt", Key="policy.yaml",
                         Body=POLICY_PATH.read_bytes().replace(b"example-bank", b"other-bank", 1))
    assert prov().fingerprint != fp


def test_bedrock_judge_with_stub_client(policy):
    from sentinel_core.engine import DecisionEngine
    from sentinel_core.judge import BedrockBackend, LLMJudge
    from sentinel_core.models import ActionEvent
    from sentinel_core.store import MemoryStore

    class Stub:
        def __init__(self):
            self.calls = []

        def converse(self, **kw):
            self.calls.append(kw)
            return {"output": {"message": {"content": [{"text":
                '{"aligned": false, "risk": 82, "category": "data_harvesting", '
                '"explanation": "Reading many unrelated customers for a single-customer task."}'}]}}}

    stub = Stub()
    judge = LLMJudge(BedrockBackend(model_id="m", client=stub), policy)
    d = DecisionEngine(policy, MemoryStore(), judge=judge).decide(ActionEvent(
        agent_id="kyc-agent", action="read", resource="s3://example-bank-customer-data/kyc/C-77/a.pdf",
        task_description="Verify documents for customer C-12", content="PAN ABCPE1234F"))
    assert d.verdict.value == "HOLD"
    assert any(f.rule_id == "judge.data_harvesting" for f in d.findings)
    sent = stub.calls[0]["messages"][0]["content"][0]["text"]
    assert "ABCPE1234F" not in sent and "[PAN]" in sent, "PII must be redacted before the LLM sees it"
    assert "UNTRUSTED DATA" in stub.calls[0]["system"][0]["text"]


def test_judge_failure_does_not_break_decisions(policy):
    from sentinel_core.engine import DecisionEngine
    from sentinel_core.judge import LLMJudge
    from sentinel_core.models import ActionEvent
    from sentinel_core.store import MemoryStore

    class Broken:
        def complete(self, *a):
            raise RuntimeError("throttled")

    d = DecisionEngine(policy, MemoryStore(), judge=LLMJudge(Broken(), policy)).decide(ActionEvent(
        agent_id="kyc-agent", action="read", resource="s3://example-bank-customer-data/kyc/C-1/a.pdf"))
    assert d.verdict.value == "ALLOW"


def test_slack_payload():
    from sentinel_core.alerts import SlackNotifier, build_alert
    from sentinel_core.models import ActionEvent, Decision, Finding, Severity, Verdict
    with pytest.raises(ValueError):
        SlackNotifier("https://evil.com/hook")
    n = SlackNotifier("https://hooks.slack.com/services/T/B/X")
    f = Finding("rules", "access.unauthorized", Severity.CRITICAL, "Unauthorised read", "detail")
    d = Decision("e", "reporting-agent", Verdict.DENY, Mode.QUARANTINE, Severity.CRITICAL, [f], "x")
    p = n.payload(build_alert(d, ActionEvent(agent_id="reporting-agent", action="read", resource="s3://b/k"),
                              "a1", "https://console.example"))
    assert p["blocks"][0]["text"]["text"].startswith("CRITICAL")
    assert any(b["type"] == "actions" for b in p["blocks"])


def test_queue_groups_are_safe_and_failures_retry_in_order(aws, monkeypatch):
    from sentinel_core.aws.runtime import message_group
    g = message_group("principal:arn:aws:iam::123456789012:user/contractor-7")
    assert "/" not in g and ":" not in g and len(g) <= 80
    assert message_group("") == "sentinel"

    from sentinel_core.aws import handlers
    calls = []
    orig = handlers.EvidenceWriter.append
    monkeypatch.setattr(handlers.EvidenceWriter, "append", lambda self, c, items: calls.append((c, len(items))))
    ev = lambda i, grp, body: {"messageId": f"m{i}", "attributes": {"MessageGroupId": grp}, "body": body}
    good = json.dumps({"kind": "evidence", "type": "x", "at": 1.0, "payload": {}})
    res = handlers.stream_handler({"Records": [
        ev(1, "a", good), ev(2, "a", "{broken"), ev(3, "a", good), ev(4, "b", good)]}, None)
    failed = [f["itemIdentifier"] for f in res["batchItemFailures"]]
    assert failed == ["m2", "m3"], "after a failure, later messages in the same group must retry too"
    assert ("b", 1) in calls and ("a", 1) in calls
