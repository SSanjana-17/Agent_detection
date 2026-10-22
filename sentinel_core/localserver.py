"""Local Sentinel server for development and integration testing.

    python -m sentinel_core.localserver --policy policies/policy.yaml --port 8787

Serves the same API as the AWS deployment (in-memory store, no auth) plus
the dashboard at http://localhost:8787/. Not for production: there is no
authentication, and state is lost on restart.
"""
from __future__ import annotations

import argparse
import json
import logging
import mimetypes
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from .alerts import AlertRouter
from .compliance import DEFAULT_RISKS
from .policy import load_policy
from .router import dispatch
from .service import Identity, SentinelService
from .store import MemoryStore

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


class _ConsoleNotifier:
    name = "console"

    def send(self, alert):
        logging.getLogger("sentinel.alerts").warning(
            "ALERT [%s/%s] %s — %s (%s)", alert["severity"], alert["mode"], alert["agent_id"],
            alert["title"], alert["resource"])


def make_service(policy_path: str) -> SentinelService:
    store = MemoryStore()
    for r in DEFAULT_RISKS:
        store.put_risk(r)
    policy = load_policy(policy_path)
    router = AlertRouter(store, [_ConsoleNotifier()], dashboard_url="")
    return SentinelService(lambda: policy, store, alert_router=router)


def serve(policy_path: str, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    svc = make_service(policy_path)
    svc.run_control_tests()
    ident = Identity(kind="local", principal="local-dev")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # quieter logs
            logging.getLogger("sentinel.http").debug(fmt, *args)

        def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self._send(204, b"")

        def _api(self, method: str) -> None:
            u = urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else None
            status, body = dispatch(svc, method, u.path, dict(parse_qsl(u.query)), raw, ident)
            self._send(status, json.dumps(body, default=str).encode())

        def do_GET(self):
            u = urlparse(self.path)
            if u.path.startswith("/v1/"):
                return self._api("GET")
            if u.path == "/config.json":
                return self._send(200, json.dumps({"apiUrl": "", "auth": "none"}).encode())
            rel = u.path.lstrip("/") or "index.html"
            target = (DASHBOARD_DIR / rel).resolve()
            if not str(target).startswith(str(DASHBOARD_DIR)) or not target.is_file():
                target = DASHBOARD_DIR / "index.html"
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            self._send(200, target.read_bytes(), ctype)

        def do_POST(self):
            self._api("POST")

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.service = svc  # type: ignore[attr-defined]

    def periodic():
        while True:
            threading.Event().wait(60)
            try:
                svc.run_health_checks()
                svc.run_control_tests()
            except Exception:
                logging.exception("periodic job failed")

    threading.Thread(target=periodic, daemon=True).start()
    return httpd


def main() -> None:
    ap = argparse.ArgumentParser(description="Run Sentinel locally")
    ap.add_argument("--policy", default=os.environ.get("POLICY_PATH", "policies/policy.yaml"))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    httpd = serve(args.policy, args.host, args.port)
    print(f"Sentinel local server on http://{args.host}:{args.port}  (dashboard + API, no auth)")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
