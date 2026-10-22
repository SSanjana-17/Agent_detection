#!/usr/bin/env bash
# Checks that every AWS service Sentinel uses is available to this account.
# Read-only: each check is a harmless "list" call. Run before deploying.
REGION="${AWS_REGION:-ap-south-1}"
pass=0; fail=0; blocked=()

check() {  # name, command...
  local name="$1"; shift
  local out
  if out="$("$@" --region "$REGION" 2>&1 >/dev/null)"; then
    printf "  ok       %s\n" "$name"; pass=$((pass+1))
  elif grep -qiE "SubscriptionRequired|needs a subscription|not subscribed|OptInRequired" <<<"$out"; then
    printf "  BLOCKED  %s  (not available on this account's plan)\n" "$name"; fail=$((fail+1)); blocked+=("$name")
  elif grep -qiE "AccessDenied|not authorized|UnauthorizedOperation" <<<"$out"; then
    printf "  DENIED   %s  (IAM user lacks permission: %s)\n" "$name" "$(head -1 <<<"$out" | cut -c1-120)"; fail=$((fail+1)); blocked+=("$name")
  else
    printf "  ERROR    %s  (%s)\n" "$name" "$(head -1 <<<"$out" | cut -c1-140)"; fail=$((fail+1)); blocked+=("$name")
  fi
}

echo "Checking AWS services Sentinel needs in ${REGION}..."
check "Identity (STS)"         aws sts get-caller-identity
check "CloudFormation"         aws cloudformation list-stacks --max-items 1
check "S3"                     aws s3api list-buckets --max-items 1
check "DynamoDB"               aws dynamodb list-tables --max-items 1
check "SQS"                    aws sqs list-queues --max-results 1
check "SNS"                    aws sns list-topics
check "Lambda"                 aws lambda list-functions --max-items 1
check "API Gateway"            aws apigateway get-rest-apis --limit 1
check "Step Functions"         aws stepfunctions list-state-machines --max-results 1
check "EventBridge"            aws events list-rules --limit 1
check "KMS"                    aws kms list-keys --limit 1
check "Secrets Manager"        aws secretsmanager list-secrets --max-results 1
check "Cognito"                aws cognito-idp list-user-pools --max-results 1
check "CloudWatch Logs"        aws logs describe-log-groups --limit 1
check "CloudWatch Alarms"      aws cloudwatch describe-alarms --max-records 1
check "X-Ray"                  aws xray get-sampling-rules
check "IAM"                    aws iam list-roles --max-items 1
echo "Optional:"
check "CloudTrail (bypass detection)" aws cloudtrail describe-trails
check "Bedrock (LLM judge)"    aws bedrock list-foundation-models --by-provider anthropic
check "CloudFront (hosted console)" aws cloudfront list-distributions --max-items 1
check "Kinesis (not used any more)" aws kinesis list-streams --max-results 1

echo
echo "${pass} available, ${fail} not available."
if [ ${#blocked[@]} -gt 0 ]; then
  echo "Not available: ${blocked[*]}"
fi
