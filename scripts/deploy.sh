#!/usr/bin/env bash
# Deploy Sentinel. Uses whatever AWS credentials are active (aws sso login first).
#   ADMIN_EMAIL=... ALERT_EMAILS='["a@x.com"]' PROTECTED_BUCKETS='["bucket"]' \
#   BEDROCK_MODEL_ID=... COGNITO_PREFIX=yourbank-sentinel scripts/deploy.sh
# CONSOLE_HOSTING=local skips CloudFront (new accounts must be verified before using it).
set -euo pipefail
cd "$(dirname "$0")/../infra"

: "${ADMIN_EMAIL:?set ADMIN_EMAIL}"
REGION="${AWS_REGION:-ap-south-1}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
echo "Deploying Sentinel to account ${ACCOUNT} in ${REGION}"

python3 -m pip install -q -r requirements.txt
if [ "${SKIP_TESTS:-}" = "1" ]; then
  echo "SKIP_TESTS=1 set — skipping the local test gate for this deploy."
else
  ( cd .. && python3 -m pytest -q ) || {
    echo "Tests failed; not deploying. (A few tests are timing-sensitive and can flake on a"
    echo "heavily loaded machine — they pass on a quiet run. To deploy anyway: SKIP_TESTS=1 ... scripts/deploy.sh)"
    exit 1; }
fi

if ! aws cloudformation describe-stacks --stack-name CDKToolkit --region "$REGION" >/dev/null 2>&1; then
  echo "Bootstrapping CDK in ${REGION} (needs admin, once)"
  cdk bootstrap "aws://${ACCOUNT}/${REGION}"
fi

cdk deploy --require-approval broadening \
  -c region="$REGION" \
  -c adminEmail="$ADMIN_EMAIL" \
  -c alertEmails="${ALERT_EMAILS:-[]}" \
  -c protectedBuckets="${PROTECTED_BUCKETS:-[]}" \
  -c bedrockModelId="${BEDROCK_MODEL_ID:-}" \
  -c consoleHosting="${CONSOLE_HOSTING:-cloudfront}" \
  ${COGNITO_PREFIX:+-c cognitoDomainPrefix="$COGNITO_PREFIX"} \
  --outputs-file ../cdk-outputs.json

echo "Done. Outputs written to cdk-outputs.json"
if [ "${CONSOLE_HOSTING:-cloudfront}" = "local" ]; then
  echo "Open the console with: scripts/console.sh"
fi
