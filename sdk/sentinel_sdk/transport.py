"""Transports: how the SDK reaches Sentinel.

* ``HttpTransport``  — the deployed API. Signs requests with AWS SigV4 using the
  agent's own IAM role, so Sentinel knows *which* agent is calling and an agent
  cannot claim another agent's identity.
* ``LocalTransport`` — runs the decision engine in-process (development, unit
  tests of your agents, air-gapped use). Same decisions, same API.
"""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from typing import Any, Protocol
from urllib.parse import urlencode, urlparse


class TransportError(Exception):
    """Sentinel could not be reached or returned a server error."""


class Transport(Protocol):
    def request(self, method: str, path: str, body: dict[str, Any] | None = None,
                query: dict[str, str] | None = None) -> dict[str, Any]: ...


class HttpTransport:
    def __init__(self, endpoint: str, region: str | None = None, auth: str = "iam",
                 api_token: str | None = None, timeout: float = 3.0, retries: int = 2,
                 session: Any = None) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.auth = auth
        self.api_token = api_token
        self.region = region
        self._session = session
        if auth == "iam":
            try:
                import boto3  # noqa: F401
                from botocore.auth import SigV4Auth  # noqa: F401
            except ImportError as e:  # pragma: no cover
                raise ImportError("auth='iam' needs boto3: pip install boto3") from e
            host = urlparse(self.endpoint).hostname or ""
            if not self.region:
                parts = host.split(".")
                self.region = parts[2] if len(parts) > 3 and parts[1] == "execute-api" else "ap-south-1"

    def _sign(self, method: str, url: str, data: bytes | None) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.auth == "iam":
            import boto3
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            session = self._session or boto3.Session()
            creds = session.get_credentials()
            if creds is None:
                raise TransportError("no AWS credentials available to sign Sentinel requests")
            req = AWSRequest(method=method, url=url, data=data, headers=headers)
            SigV4Auth(creds.get_frozen_credentials(), "execute-api", self.region).add_auth(req)
            return dict(req.headers.items())
        if self.auth == "token" and self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers

    def request(self, method, path, body=None, query=None):
        url = self.endpoint + path + (("?" + urlencode(query)) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                headers = self._sign(method, url, data)
                req = urllib.request.Request(url, data=data, method=method, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                    return json.loads(resp.read() or b"{}")
            except urllib.error.HTTPError as e:
                payload = e.read()
                if 400 <= e.code < 500 and e.code != 429:
                    try:
                        msg = json.loads(payload).get("error", "")
                    except ValueError:
                        msg = payload[:200].decode(errors="replace")
                    raise TransportError(f"Sentinel rejected request ({e.code}): {msg}") from e
                last = e
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = e
            if attempt < self.retries:
                time.sleep(min(0.1 * (2 ** attempt) + random.random() * 0.05, 1.0))
        raise TransportError(f"Sentinel unreachable at {self.endpoint}: {last}")


class LocalTransport:
    """In-process Sentinel. Requires the ``sentinel_core`` package."""

    def __init__(self, policy_path: str | None = None, policy: Any = None, store: Any = None,
                 service: Any = None, as_principal: str = "") -> None:
        from sentinel_core.policy import load_policy
        from sentinel_core.service import Identity, SentinelService
        from sentinel_core.store import MemoryStore
        if service is None:
            pol = policy or load_policy(policy_path or "policies/policy.yaml")
            service = SentinelService(lambda: pol, store or MemoryStore())
        self.service = service
        self._ident = Identity(kind="local", principal=as_principal or "local")

    def request(self, method, path, body=None, query=None):
        from sentinel_core.router import dispatch
        status, resp = dispatch(self.service, method, path, query or {},
                                json.dumps(body) if body is not None else None, self._ident)
        if status >= 500:
            raise TransportError(resp.get("error", "internal error"))
        if status >= 400:
            raise TransportError(f"Sentinel rejected request ({status}): {resp.get('error')}")
        return resp
