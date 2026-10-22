# Sentinel

Sentinel is a governance agent for fleets of AI agents. It sits in front of every action your agents take, decides in about a millisecond whether the action may run, and flags, holds, blocks or quarantines anything outside policy. It keeps a tamper-proof audit trail and continuously tests compliance controls, in the spirit of Vanta and Drata, but aimed at what your agents are actually doing.

**The banking case it was built for:** a reporting agent that has never touched customer data suddenly starts reading the customer PII folder. Sentinel denies the read before any data is returned, quarantines the agent, and alerts the security team by email and Slack. Every later action by that agent is blocked until a named human releases it, and each step is written to an evidence log that cannot be altered.

## What it catches

| Layer | Examples | Speed |
|---|---|---|
| Policy rules | Access outside an agent's grants, data above its clearance, bulk record pulls, path-traversal tricks, privilege escalation, unapproved egress | Inline, <1 ms |
| Data loss prevention | Aadhaar, PAN, card numbers, SSN, IBAN, account numbers, emails and phones (checksum-validated), plus API keys and tokens in anything leaving an agent | Inline |
| Behaviour | Rate and volume limits, slow harvesting, enumeration, learned per-agent baselines, new kinds of access, off-hours activity, loops | Inline |
| Prompt injection | Instructions hidden in emails, pages and tool output, including base64, HTML comments and invisible Unicode tag characters | Inline, before the next action |
| LLM judge (Bedrock) | "Allowed, but does this make sense for the task?" for high-risk agents. Inputs are redacted before the model sees them, and the judge itself is hardened against injection | Inline with timeout |
| Identity | Unregistered agents, and agents impersonating other agents (callers are bound to their IAM role) | Inline |
| Bypass | CloudTrail S3 data events cross-checked against Sentinel decisions, so an agent that reads S3 directly with its role is caught | Seconds |
| Health | Missed heartbeats, error states, stuck loops | Every minute |

## Responses

Each rule maps to one of five response modes. The defaults are set by severity, and the policy can override any rule.

- **Log**: the action runs and is recorded.
- **Flag**: the action runs and an alert goes out.
- **Hold**: the agent waits until a human approves or rejects the action in the console. If nobody decides before the timeout, the action is rejected.
- **Block**: the action is denied.
- **Quarantine**: the action is denied, and the agent is suspended until a human releases it with a recorded reason.

## Compliance layer

- **12 agent-governance controls**, mapped to SOC 2, ISO 27001:2022, ISO 42001:2023, PCI DSS 4.0.1 and the NIST AI RMF.
- **Control tests** run hourly against the live configuration, and every daily run verifies the evidence chain end to end.
- **Risk register**: residual risk is recalculated from the status of the controls that treat each risk.
- **Evidence**: a hash chain stored in S3 with Object Lock in COMPLIANCE mode, retained for 7 years by default.

## Tested

```
$ python -m pytest            # 95 tests: unit, AWS integration (moto), framework adapters, red-team gates
$ python tests/redteam/run_redteam.py
Detection: 26/26 caught, 26 stopped or contained
Benign workload: 3000 actions, 0 false positives (0.000%)
Decision latency (in-process): p50 0.09 ms, p95 0.16 ms, p99 0.23 ms
```

Read these numbers with two caveats:

- **The benign workload is synthetic** and matches the example policy. On real traffic, run new agents in Flag mode first and tune their rate limits before you enforce.
- **Latency is engine time only.** Through API Gateway and Lambda, expect roughly 20–60 ms per decision.

## Layout

```
sentinel_core/         decision engine, detectors, compliance, evidence, API
  aws/                 DynamoDB store, Lambda handlers, runtime wiring
sdk/sentinel_sdk/      client library agents embed (+ adapters)
policies/policy.yaml   who may do what — edit this for your bank
infra/                 AWS CDK app (one stack, ap-south-1 by default)
dashboard/             security console (static, served by CloudFront)
tests/                 unit, integration, red-team
docs/                  DEPLOY.md, INTEGRATE.md, POLICY.md
```

## Quick start

**Local, no AWS needed:**

```bash
pip install -r requirements-dev.txt
python -m sentinel_core.localserver --policy policies/policy.yaml
# console + API on http://127.0.0.1:8787
```

**Deploy to AWS:** see [docs/DEPLOY.md](docs/DEPLOY.md).

**Wire your agents in:** see [docs/INTEGRATE.md](docs/INTEGRATE.md). The core is framework-agnostic, and there are adapters for the Claude Agent SDK, LangChain/LangGraph, MCP clients and hand-written tool loops.

## Design notes

- **Fail closed.** If the SDK can't reach Sentinel, the action is denied. Held actions that time out are rejected. A bad policy edit never replaces the last good policy.
- **Untrusted data stays data.** Agent-supplied strings are never rendered as HTML in the console. Anything sent to the LLM judge is redacted and fenced as untrusted.
- **Server time, not client time.** Rate limits and baselines use Sentinel's clock, so an agent can't backdate its own events.
- **Separation of duties.** Agents call `/agent/*` with their IAM role, and humans use `/console/*` behind Cognito with MFA. An agent can never approve its own held action.
