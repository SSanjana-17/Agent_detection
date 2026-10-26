#!/usr/bin/env bash
# Run one of the demo agents in AWS now and show what it did, step by step.
#
#   scripts/run_agent.sh kyc                        verify the next 3 pending customers
#   scripts/run_agent.sh kyc harvest                reads customer records far too fast (behaviour limits)
#   scripts/run_agent.sh loan                       decide the next 3 loan applications
#   scripts/run_agent.sh loan faulty-approval       a bug approves a loan that breaks the rules (held)
#   scripts/run_agent.sh loan mixup                 a bug books a land loan as a cheaper home loan (held)
#   scripts/run_agent.sh loan exfiltrate            tries to send applicants' details outside (quarantined)
#   scripts/run_agent.sh reporting                  build the weekly report
#   scripts/run_agent.sh reporting rogue            the interview scenario: goes for the customer export
#   scripts/run_agent.sh reporting rogue-loans      goes for customers' loan applications
#   scripts/run_agent.sh reporting bypass           goes around Sentinel (caught via CloudTrail)
#
# Held actions wait up to 4 minutes: approve or reject them in the console meanwhile.
set -euo pipefail
REGION="${AWS_REGION:-ap-south-1}"
AGENT="${1:-}"; MODE="${2:-normal}"
case "$AGENT" in
  kyc)       FN=sentinel-demo-kyc-agent;       PAYLOAD="{\"mode\": \"$MODE\", \"batch\": 3}" ;;
  loan)      FN=sentinel-demo-loan-agent;      PAYLOAD="{\"mode\": \"$MODE\", \"batch\": 3}" ;;
  reporting) FN=sentinel-demo-reporting-agent; PAYLOAD="{\"mode\": \"$MODE\"}" ;;
  *) sed -n '2,14p' "$0"; exit 1 ;;
esac
OUT="$(mktemp)"
echo "Invoking $FN ($MODE) in $REGION... (held actions wait for you in the console)"
aws lambda invoke --region "$REGION" --function-name "$FN" --cli-read-timeout 330 \
  --cli-binary-format raw-in-base64-out --payload "$PAYLOAD" "$OUT" >/dev/null
python3 - "$OUT" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
if "steps" not in r:
    print(json.dumps(r, indent=2)); sys.exit()
print(f"\n{r['agent']}  (mode: {r.get('mode')})")
for s in r["steps"]:
    print(f"  {s['t']:>6.2f}s  {s['action']:<8} {s['outcome']:<44} {s['resource']}")
    if s.get("detail"):
        print(f"            {s['detail'][:180]}")
print(f"\nOutcome: {r['outcome']}  ({r['duration_s']}s)")
for v in r.get("verified", []):
    print(f"  {v['customer_id']}: {v['status']}" + (f"  failed: {', '.join(v['failed'])}" if v['failed'] else ""))
for d in r.get("decided", []):
    rate = f" at {d['interest_rate']}%" if d.get("interest_rate") else ""
    failed = f"  failed: {', '.join(d['failed'])}" if d.get("failed") else ""
    print(f"  {d['loan_id']}: {d['category']} loan {d['decision']}{rate}{failed}")
if r.get("report"):
    print(f"  report: {r['report']}")
if "records_read" in r:
    print(f"  customer records read: {r['records_read']}")
PY
rm -f "$OUT"
