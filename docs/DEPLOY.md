# Deploying Sentinel to AWS (ap-south-1)

You need about 30 minutes for the deployment itself, plus the manual Bedrock step if you want the LLM judge.

## 1. Before you start

- **Tools:** an AWS account, Python 3.11+, Node.js 18+, the AWS CLI v2, and the CDK CLI (`npm i -g aws-cdk`).
- **Credentials:** sign in on your own machine. AWS IAM Identity Center is preferable:
  ```bash
  aws configure sso          # once
  aws sso login --profile sentinel-deploy
  export AWS_PROFILE=sentinel-deploy
  ```
  Use a dedicated deploy identity. [`deployer-policy.json`](deployer-policy.json) is the least-privilege policy for running deploys once the account is bootstrapped. Bootstrapping itself needs an administrator, once per account and region.
- **Bedrock access (manual, needed for the LLM judge):**
  1. In the AWS console, open Amazon Bedrock in **Asia Pacific (Mumbai)** and go to **Model access**.
  2. Enable an Anthropic Claude model and accept the terms.
  3. Copy the model's **inference profile ID** (the APAC cross-region profile).
  
  You will pass this ID as `bedrockModelId`. Without it, Sentinel runs every other layer and skips the judge.

## 2. Configure

Edit `policies/policy.yaml`:

- Replace the example bucket names, agent ids and IAM role ARNs with yours.
- Every agent your organisation runs must appear under `agents:`, with its `principals:` (the IAM role it runs as). Anything not listed is quarantined on first use.
- List the buckets that hold customer data under `classifications`. Pass the same bucket names as `protectedBuckets` below, so CloudTrail watches them for bypass.

## 3. Deploy

```bash
cd infra
pip install -r requirements.txt
cdk bootstrap aws://<ACCOUNT_ID>/ap-south-1            # once per account/region (admin)

cdk deploy \
  -c adminEmail=secops-lead@yourbank.com \
  -c 'alertEmails=["secops@yourbank.com","ai-governance@yourbank.com"]' \
  -c 'protectedBuckets=["yourbank-customer-data"]' \
  -c bedrockModelId=<inference-profile-id-from-step-1> \
  -c cognitoDomainPrefix=yourbank-sentinel
```

Or run `scripts/deploy.sh` with the same settings in environment variables.

The stack outputs:

| Output | Use |
|---|---|
| `AgentEndpoint` | `Sentinel(endpoint=...)` in every agent |
| `AgentInvokePolicyArn` | attach to every agent's IAM role |
| `ConsoleUrl` | the security console |
| `SlackSecretArn` | where your Slack webhook goes |
| `PolicyBucketName` | where `policy.yaml` lives (edit to change policy) |
| `EvidenceBucketName` | WORM evidence for auditors |

## 4. After deploy

1. **Confirm the email subscriptions.** SNS sends a confirmation link to each address in `alertEmails`.
2. **Turn on Slack.** In Slack, create an incoming webhook for your security channel, then run:
   ```bash
   aws secretsmanager put-secret-value --secret-id <SlackSecretArn> \
     --secret-string '{"webhook_url":"https://hooks.slack.com/services/..."}'
   ```
   Sentinel picks it up within 5 minutes; no redeploy is needed.
3. **Sign in to the console.** The admin user receives a temporary password by email. On first sign-in Cognito requires a new password and a TOTP authenticator, because MFA is mandatory.
4. **Add approvers.** Create each approver in the Cognito user pool and add them to `sentinel-approvers`, or to `sentinel-viewers` for read-only access.
5. **Connect agents.** Attach `AgentInvokePolicyArn` to each agent's role and follow [INTEGRATE.md](INTEGRATE.md).
6. **Smoke test:**
   ```bash
   python scripts/smoke_test.py --endpoint <AgentEndpoint> --agent-id <a registered agent>
   ```

## Changing policy

```bash
aws s3 cp policies/policy.yaml s3://<PolicyBucketName>/policy.yaml
```

- The new policy is live within 30 seconds.
- If the file has an error, Sentinel logs it and keeps enforcing the previous valid policy.
- The policy bucket is versioned, and every policy change is written to the evidence chain.

## What gets created

The stack creates:

- **API:** API Gateway (REST, regional), with IAM auth on `/agent/*` and Cognito on `/console/*`.
- **Compute:** 5 Lambda functions (Python 3.12, arm64, X-Ray).
- **Storage:** DynamoDB (on-demand, PITR, deletion protection), an SQS FIFO event queue with a dead-letter queue, S3 buckets for policy (versioned), evidence (Object Lock COMPLIANCE) and access logs.
- **Workflow and scheduling:** a Step Functions approval workflow and EventBridge schedules.
- **Bypass detection:** a CloudTrail data-event trail on the protected buckets.
- **Alerting:** SNS and Secrets Manager.
- **Console:** Cognito (MFA required), plus CloudFront and S3 with security headers.
- **Monitoring:** CloudWatch alarms on Sentinel itself (API 5xx, p99 latency, queue lag, dead letters, function errors).
- **Encryption:** everything with a customer-managed KMS key that rotates.

Resources holding audit data are retained if the stack is deleted.

## Cost

At about 100k agent actions a day, the bill is dominated by:

- Lambda and API Gateway requests
- the KMS key (about $1 a month); SQS, DynamoDB and Lambda stay within the free tier at light use
- the Bedrock judge, which only runs for high-risk agents on sensitive actions

Run the AWS Pricing Calculator with your own volumes before you go to production.
