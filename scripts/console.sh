#!/usr/bin/env bash
# Open the Sentinel console from this machine (use when the stack was deployed
# with CONSOLE_HOSTING=local). Sign-in still goes through Cognito with MFA.
set -euo pipefail
cd "$(dirname "$0")/.."
STACK="${STACK_NAME:-Sentinel}"
if [ -f cdk-outputs.json ]; then
  CFG="$(python3 -c 'import json;o=json.load(open("cdk-outputs.json"));print(next(iter(o.values()))["ConsoleConfig"])')"
else
  echo "No cdk-outputs.json; reading settings from the ${STACK} stack in AWS..."
  CFG="$(aws cloudformation describe-stacks --stack-name "$STACK" --region "${AWS_REGION:-ap-south-1}" \
        --query "Stacks[0].Outputs[?OutputKey=='ConsoleConfig'].OutputValue" --output text 2>/dev/null || true)"
  if [ -z "$CFG" ] || [ "$CFG" = "None" ]; then
    echo "The ${STACK} stack isn't deployed (or has no console settings). Run scripts/deploy.sh first."
    exit 1
  fi
fi
printf '%s' "$CFG" | python3 -c 'import json,sys;c=json.load(sys.stdin);json.dump(c,open("dashboard/config.json","w"),indent=2);print("Console connected to",c["apiUrl"])'
echo "Console running at http://localhost:8787/  (Ctrl+C to stop)"
( sleep 1; open "http://localhost:8787/" 2>/dev/null || true ) &
# Serve with no-store so edited app.js/styles.css always load fresh (no stale cache).
exec python3 - <<'PY'
import functools, http.server
class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, must-revalidate")
        super().end_headers()
http.server.test(HandlerClass=functools.partial(H, directory="dashboard"),
                 bind="127.0.0.1", port=8787)
PY
