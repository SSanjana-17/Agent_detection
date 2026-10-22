"""Post-deploy smoke test. Non-destructive: it never triggers a quarantine.

    python scripts/smoke_test.py --endpoint <AgentEndpoint> --agent-id kyc-agent \
        --allowed-resource s3://yourbank-customer-data/kyc/SMOKE/test.json

Run it with credentials for the agent's IAM role. Any other identity will be
treated as an impersonation attempt, which is exactly what Sentinel should do.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk"))

from sentinel_sdk import Sentinel  # noqa: E402
from sentinel_sdk.transport import HttpTransport  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--agent-id", required=True)
    ap.add_argument("--allowed-resource", default="")
    args = ap.parse_args()

    t = HttpTransport(args.endpoint)
    ok = True

    t0 = time.perf_counter()
    h = t.request("GET", "/v1/health")
    print(f"health       ok={h.get('ok')} policy={h.get('policy')}  ({(time.perf_counter() - t0) * 1000:.0f} ms)")

    s = Sentinel(agent_id=args.agent_id, transport=t)
    hb = s.heartbeat(detail="smoke test")
    print(f"heartbeat    agent status {hb['status']}")
    ok &= hb["status"] == "ACTIVE"

    if args.allowed_resource:
        lat = []
        for _ in range(10):
            t0 = time.perf_counter()
            d = s.check("read", args.allowed_resource)
            lat.append((time.perf_counter() - t0) * 1000)
        lat.sort()
        print(f"decide       verdict {d['verdict']}  p50 {lat[4]:.0f} ms  max {lat[-1]:.0f} ms")
        ok &= d["verdict"] == "ALLOW"

    out = s.check("output", content="Smoke test output with no personal data.")
    print(f"output check verdict {out['verdict']}")
    ok &= out["verdict"] == "ALLOW"
    s.close()
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
