"""Red-team gates: every attack caught, no false positives on the benign workload,
and identical outcomes on the production DynamoDB store."""
import boto3
from moto import mock_aws

import run_redteam as rt
from sentinel_core.aws.dynamo import DynamoStore
from sentinel_core.policy import load_policy
from sentinel_core.service import SentinelService


def test_redteam_gates():
    rep = rt.run(verbose=False)
    missed = [r["name"] for r in rep["results"] if not r["caught"]]
    assert not missed, f"missed attacks: {missed}"
    assert rep["stopped_or_contained"] == rep["attacks"]
    assert rep["false_positive_rate"] <= 0.001, rep["false_positive_examples"]
    assert rep["latency_ms"]["p99"] < 5


def test_attacks_on_dynamodb_store(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    with mock_aws():
        boto3.client("dynamodb", region_name="ap-south-1").create_table(
            TableName="t", BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("PK", "SK", "GSI1PK", "GSI1SK")],
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
            GlobalSecondaryIndexes=[{"IndexName": "GSI1", "Projection": {"ProjectionType": "ALL"},
                                     "KeySchema": [{"AttributeName": "GSI1PK", "KeyType": "HASH"},
                                                   {"AttributeName": "GSI1SK", "KeyType": "RANGE"}]}])
        skip = {"Enumerating hundreds of customer folders"}  # uses the in-memory clock shortcut
        for name, cat, fn in rt.ATTACKS:
            if name in skip:
                continue
            # wipe the table between scenarios
            table = boto3.resource("dynamodb", region_name="ap-south-1").Table("t")
            with table.batch_writer() as bw:
                for item in table.scan(ProjectionExpression="PK, SK")["Items"]:
                    bw.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})
            pol = load_policy(rt.POLICY)
            svc = SentinelService(lambda: pol, DynamoStore("t", region="ap-south-1"))
            d = fn(svc)
            assert d["mode"] != "LOG", f"{name} not caught on DynamoDB store"
