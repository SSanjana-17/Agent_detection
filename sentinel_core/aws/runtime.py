"""Builds a fully wired SentinelService from Lambda environment variables."""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Callable

import boto3

from ..alerts import AlertRouter, notifiers_from_env
from ..judge import BedrockBackend, LLMJudge
from ..policy import Policy, load_policy, load_policy_text
from ..service import SentinelService
from .dynamo import DynamoStore

log = logging.getLogger(__name__)


class S3PolicyProvider:
    """Loads the policy YAML from S3, re-checking the ETag at most every ``ttl`` seconds.

    If a new version fails to parse, the last good policy stays in force and the
    error is logged — a typo in a policy edit must never disable enforcement.
    """

    def __init__(self, bucket: str, key: str, ttl: float = 30.0, s3: Any = None) -> None:
        self.bucket, self.key, self.ttl = bucket, key, ttl
        self.s3 = s3 or boto3.client("s3")
        self._policy: Policy | None = None
        self._etag: str | None = None
        self._checked = 0.0
        self._lock = threading.Lock()

    def __call__(self) -> Policy:
        now = time.time()
        if self._policy is not None and now - self._checked < self.ttl:
            return self._policy
        with self._lock:
            if self._policy is not None and now - self._checked < self.ttl:
                return self._policy
            try:
                kwargs: dict[str, Any] = {"Bucket": self.bucket, "Key": self.key}
                if self._etag:
                    kwargs["IfNoneMatch"] = self._etag
                obj = self.s3.get_object(**kwargs)
                text = obj["Body"].read().decode()
                pol = load_policy_text(text)
                self._policy, self._etag = pol, obj.get("ETag")
                log.info("policy loaded: %s (%s)", pol.fingerprint, self._etag)
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code not in ("304", "NotModified"):
                    if self._policy is None:
                        raise
                    log.error("policy reload failed, keeping last good policy: %s", exc)
            self._checked = now
            assert self._policy is not None
            return self._policy


_GROUP_RE = __import__("re").compile(r"[^A-Za-z0-9_.-]")


def message_group(partition: str) -> str:
    """SQS FIFO group id / evidence chain name: safe charset, bounded length."""
    g = _GROUP_RE.sub("_", partition or "sentinel")[:80]
    return g or "sentinel"


class QueueSink:
    """Evidence/async events go onto an SQS FIFO queue.

    Messages in the same group (one per agent, plus 'controls', 'policy', ...) are
    delivered in order and never processed concurrently, so each group owns one
    evidence hash chain and writes to it are naturally serialised.
    """

    def __init__(self, queue_url: str, client: Any = None) -> None:
        self.url = queue_url
        self.client = client or boto3.client("sqs")

    def __call__(self, rtype: str, payload: dict[str, Any], partition: str) -> None:
        self.client.send_message(
            QueueUrl=self.url, MessageGroupId=message_group(partition),
            MessageDeduplicationId=uuid.uuid4().hex,
            MessageBody=json.dumps({"kind": "evidence", "type": rtype, "at": time.time(),
                                    "payload": payload}, default=str))

    def put_events(self, events: list[dict[str, Any]], identity: dict[str, Any]) -> None:
        entries = [{"Id": str(i), "MessageGroupId": message_group(str(e.get("agent_id", "unknown"))),
                    "MessageDeduplicationId": uuid.uuid4().hex,
                    "MessageBody": json.dumps({"kind": "post_event", "event": e, "identity": identity},
                                              default=str)} for i, e in enumerate(events)]
        failed = 0
        for i in range(0, len(entries), 10):
            resp = self.client.send_message_batch(QueueUrl=self.url, Entries=entries[i:i + 10])
            failed += len(resp.get("Failed", []))
        if failed:
            raise RuntimeError(f"{failed} events not accepted by the queue")


class StepFunctionsWorkflow:
    def __init__(self, state_machine_arn: str, client: Any = None) -> None:
        self.arn = state_machine_arn
        self.client = client or boto3.client("stepfunctions")

    def start(self, approval: dict[str, Any]) -> None:
        self.client.start_execution(
            stateMachineArn=self.arn, name=f"hold-{approval['approval_id']}",
            input=json.dumps({"approval_id": approval["approval_id"],
                              "timeout_seconds": max(60, int(approval["expires_at"] - time.time()))}))

    def complete(self, approval: dict[str, Any]) -> None:
        token = approval.get("task_token")
        if not token:
            return  # the wait task will see the resolution when it registers its token
        self.client.send_task_success(
            taskToken=token, output=json.dumps({"approval_id": approval["approval_id"],
                                                "status": approval["status"],
                                                "resolved_by": approval.get("resolved_by")}))


def _judge_factory() -> Callable[[Policy], LLMJudge | None]:
    model = os.environ.get("BEDROCK_MODEL_ID", "")
    backend_holder: dict[str, BedrockBackend] = {}

    def make(policy: Policy) -> LLMJudge | None:
        if not model or not (policy.judge or {}).get("enabled", False):
            return None
        if "b" not in backend_holder:
            backend_holder["b"] = BedrockBackend(model_id=model)
        return LLMJudge(backend_holder["b"], policy)
    return make


_SERVICE: SentinelService | None = None


def build_service(evidence_sink: Callable[..., None] | None = None,
                  use_cache: bool = True) -> SentinelService:
    global _SERVICE
    if use_cache and _SERVICE is not None and evidence_sink is None:
        return _SERVICE
    env = os.environ
    store = DynamoStore(env["TABLE_NAME"])
    if env.get("POLICY_BUCKET"):
        provider: Callable[[], Policy] = S3PolicyProvider(env["POLICY_BUCKET"],
                                                          env.get("POLICY_KEY", "policy.yaml"))
    else:
        pol = load_policy(env.get("POLICY_PATH", "policies/policy.yaml"))
        provider = lambda: pol  # noqa: E731
    sink = evidence_sink
    if sink is None and env.get("QUEUE_URL"):
        sink = QueueSink(env["QUEUE_URL"])
    workflow = StepFunctionsWorkflow(env["STATE_MACHINE_ARN"]) if env.get("STATE_MACHINE_ARN") else None
    dashboard = env.get("DASHBOARD_URL", "")
    router = AlertRouter(store, notifiers_from_env(), dashboard_url=dashboard,
                         dedup_seconds=int(env.get("ALERT_DEDUP_SECONDS", "300")))
    svc = SentinelService(provider, store, judge_factory=_judge_factory(), alert_router=router,
                          evidence_sink=sink, approval_workflow=workflow, dashboard_url=dashboard)
    if use_cache and evidence_sink is None:
        _SERVICE = svc
    return svc
