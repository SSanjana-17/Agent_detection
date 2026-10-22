# Policy reference

The policy is one YAML file. Start from `policies/policy.yaml`, which models a retail bank.

## Top level

| Key | Meaning |
|---|---|
| `defaults.unknown_agent` | Response when an agent that isn't in the inventory acts (default `QUARANTINE`) |
| `defaults.fail_mode` | Advice to SDKs when Sentinel is unreachable: `closed` (deny) or `open` (allow) |
| `defaults.hold_timeout_seconds` | How long a held action waits for a human before it is rejected |
| `defaults.severity_modes` | Default response for each severity: `LOG`, `FLAG`, `HOLD`, `BLOCK`, `QUARANTINE` |
| `bypass_window_seconds` | How recent a Sentinel decision must be to explain a CloudTrail access |
| `classifications` | Named data classes with a `level` (0–4) and resource globs. The highest matching level wins |
| `egress.allowed_domains` | Outbound destinations every agent may reach (`*.domain` allowed) |
| `trusted_principals` | IAM identities allowed to touch protected data outside Sentinel (ETL, break-glass) |
| `agents` | The agent inventory (below) |
| `rules` | Per-rule overrides: `{enabled, severity, mode}`; `family.*` applies to a whole family |
| `anomaly` | `min_samples`, `record_z`, `burst_z`, `loop_repeats`, `enabled` |
| `judge` | `enabled`, `inline_for_risk_tiers`, `inline_timeout_ms`, `flag_risk`, `hold_risk`, `block_risk` |

## Agent entry

```yaml
- id: kyc-agent
  description: Verifies identity documents, one customer at a time.   # the judge reads this
  owner: kyc-platform@bank.com
  risk_tier: high              # high/critical agents get the inline LLM judge
  max_clearance: RESTRICTED_PII
  principals: ["arn:aws:sts::*:assumed-role/kyc-agent-role/**"]
  heartbeat_seconds: 120
  working_hours: {tz: Asia/Kolkata, start: "08:00", end: "22:00", days: [mon, tue, wed, thu, fri]}
  allowed_egress: ["api.partner-kyc.example"]
  permissions:
    - actions: [read, list]          # read write delete list execute network message llm_call tool_call iam output
      resources: ["s3://bank-customer-data/kyc/**"]
      tools: []                      # optional tool-name globs
      max_records_per_action: 5
      requires_approval: false       # true = always HOLD for a human
  rate_limits: {actions_per_minute: 60, records_per_hour: 300, distinct_resources_per_hour: 200}
```

**Globs:**
- `*` matches within one path segment.
- `**` matches across segments.

**Normalisation:** resources are normalised before matching, so these tricks cannot escape a pattern:
- `..` segments
- URL-encoding, including double encoding
- duplicate slashes
- backslashes

## Rule ids

| Family | Rules |
|---|---|
| Agent | `agent.unregistered`, `agent.quarantined`, `identity.spoofing` |
| Access | `access.unauthorized`, `access.clearance_exceeded`, `access.bulk_records`, `access.requires_approval` |
| Data loss | `dlp.pii_in_outbound`, `dlp.pii_exfiltration`, `dlp.secret_leak`, `data.destructive_on_sensitive` |
| Network and IAM | `egress.unapproved_destination`, `iam.privilege_escalation` |
| Rates | `rate.actions_per_minute`, `rate.records_per_hour`, `rate.distinct_resources` |
| Anomaly | `anomaly.record_volume`, `anomaly.burst`, `anomaly.new_sensitive_resource`, `anomaly.off_hours` |
| Injection | `injection.prompt_injection` |
| Judge | `judge.<category>` (`task_drift`, `data_harvesting`, `exfiltration`, `privilege_abuse`, `injection_influence`, `destructive`, `other`), `judge.timeout`, `judge.unavailable` |
| Bypass | `bypass.unmediated_access`, `bypass.unknown_principal` |
| Health | `health.heartbeat_missed`, `health.never_reported`, `health.agent_error`, `health.loop` |

## Rolling out a new agent

1. Add the agent with conservative permissions.
2. For its first week, set its rate and anomaly rules to `FLAG`, for example `rate.*: {mode: FLAG}`.
3. Review the alerts it raises, then tighten its limits to observed volume plus headroom.
4. Remove the overrides so the normal `HOLD`/`QUARANTINE` responses apply.
