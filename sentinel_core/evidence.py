"""Tamper-evident audit evidence.

Every flagged decision, approval, quarantine, release, policy change and
control-test result is appended to a hash chain: each record carries the
SHA-256 of the previous record, so deleting, reordering or editing any record
breaks every hash after it. Batches are written to S3 with Object Lock in
COMPLIANCE mode, so not even the account root user can alter or delete them
during the retention period.

Events arrive on an SQS FIFO queue; each message group is processed in order,
never concurrently, so each group owns one chain and writes are serialised. The chain
head is kept in DynamoDB with a conditional write as a safety net.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Iterable

GENESIS = "0" * 64


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def record_hash(prev_hash: str, seq: int, chain: str, rtype: str, at: float,
                payload: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode())
    h.update(canonical({"seq": seq, "chain": chain, "type": rtype, "at": at, "payload": payload}))
    return h.hexdigest()


@dataclass
class ChainHead:
    seq: int = 0
    hash: str = GENESIS


def build_records(chain: str, head: ChainHead,
                  items: Iterable[tuple[str, float, dict[str, Any]]]) -> tuple[list[dict[str, Any]], ChainHead]:
    """Chain ``(type, at, payload)`` items onto ``head``; returns records and new head."""
    out = []
    seq, prev = head.seq, head.hash
    for rtype, at, payload in items:
        seq += 1
        h = record_hash(prev, seq, chain, rtype, at, payload)
        out.append({"seq": seq, "chain": chain, "type": rtype, "at": at,
                    "prev_hash": prev, "hash": h, "payload": payload})
        prev = h
    return out, ChainHead(seq=seq, hash=prev)


@dataclass
class VerifyResult:
    ok: bool
    records: int
    error: str = ""
    first_bad_seq: int | None = None


def verify_chain(records: list[dict[str, Any]], expected_start: ChainHead | None = None) -> VerifyResult:
    if not records:
        return VerifyResult(ok=True, records=0)
    records = sorted(records, key=lambda r: r["seq"])
    prev_hash = (expected_start or ChainHead()).hash
    prev_seq = (expected_start or ChainHead()).seq
    if expected_start is None:
        prev_hash, prev_seq = records[0]["prev_hash"], records[0]["seq"] - 1
    for r in records:
        if r["seq"] != prev_seq + 1:
            return VerifyResult(False, len(records), f"gap or duplicate before seq {r['seq']}", r["seq"])
        if r["prev_hash"] != prev_hash:
            return VerifyResult(False, len(records), f"broken link at seq {r['seq']}", r["seq"])
        h = record_hash(r["prev_hash"], r["seq"], r["chain"], r["type"], r["at"], r["payload"])
        if h != r["hash"]:
            return VerifyResult(False, len(records), f"record {r['seq']} was modified", r["seq"])
        prev_hash, prev_seq = r["hash"], r["seq"]
    return VerifyResult(ok=True, records=len(records))


class EvidenceWriter:
    """Appends evidence batches to S3 (Object Lock) with the head in DynamoDB."""

    def __init__(self, bucket: str, table_name: str, s3: Any = None, ddb: Any = None,
                 prefix: str = "evidence") -> None:
        import boto3
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.s3 = s3 or boto3.client("s3")
        self.table = (ddb or boto3.resource("dynamodb")).Table(table_name)

    def _head(self, chain: str) -> tuple[ChainHead, bool]:
        item = self.table.get_item(Key={"PK": f"CHAIN#{chain}", "SK": "HEAD"},
                                   ConsistentRead=True).get("Item")
        if not item:
            return ChainHead(), False
        return ChainHead(seq=int(item["seq"]), hash=item["hash"]), True

    def append(self, chain: str, items: list[tuple[str, float, dict[str, Any]]]) -> list[dict[str, Any]]:
        if not items:
            return []
        from boto3.dynamodb.conditions import Attr
        head, exists = self._head(chain)
        records, new_head = build_records(chain, head, items)
        day = dt.datetime.fromtimestamp(time.time(), dt.timezone.utc)
        key = (f"{self.prefix}/{day:%Y/%m/%d}/{chain}/"
               f"{records[0]['seq']:012d}-{records[-1]['seq']:012d}.jsonl")
        body = "\n".join(json.dumps(r, sort_keys=True, default=str) for r in records) + "\n"
        # Claim the sequence range first; a lost race leaves no orphan object.
        cond = Attr("seq").eq(head.seq) if exists else Attr("PK").not_exists()
        self.table.put_item(
            Item={"PK": f"CHAIN#{chain}", "SK": "HEAD", "seq": new_head.seq, "hash": new_head.hash,
                  "last_key": key, "updated_at": str(time.time()),
                  "GSI1PK": "CHAINS", "GSI1SK": chain},
            ConditionExpression=cond)
        self.s3.put_object(
            Bucket=self.bucket, Key=key, Body=body.encode(), ContentType="application/x-ndjson",
            ChecksumAlgorithm="SHA256",
            Metadata={"chain": chain, "first-seq": str(records[0]["seq"]),
                      "last-seq": str(records[-1]["seq"]), "head-hash": new_head.hash})
        return records

    # ------------------------------------------------------------ reading
    def list_chains(self) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key
        resp = self.table.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq("CHAINS"))
        return [{"chain": i["GSI1SK"], "seq": int(i["seq"]), "hash": i["hash"],
                 "last_key": i.get("last_key")} for i in resp.get("Items", [])]

    def read_chain(self, chain: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        paginator = self.s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=f"{self.prefix}/"):
            for obj in page.get("Contents", []):
                if f"/{chain}/" not in obj["Key"]:
                    continue
                body = self.s3.get_object(Bucket=self.bucket, Key=obj["Key"])["Body"].read()
                records.extend(json.loads(line) for line in body.decode().splitlines() if line)
        records.sort(key=lambda r: r["seq"])
        return records

    def verify(self) -> dict[str, Any]:
        """Verify every chain end-to-end and against its recorded head."""
        results = {}
        for c in self.list_chains():
            recs = self.read_chain(c["chain"])
            res = verify_chain(recs, ChainHead())
            if res.ok and recs and recs[-1]["hash"] != c["hash"]:
                res = VerifyResult(False, len(recs), "S3 records do not reach the recorded head")
            if res.ok and len(recs) != c["seq"]:
                res = VerifyResult(False, len(recs), f"expected {c['seq']} records, found {len(recs)}")
            results[c["chain"]] = {"ok": res.ok, "records": res.records, "error": res.error}
        return {"ok": all(r["ok"] for r in results.values()), "chains": results,
                "verified_at": time.time()}
