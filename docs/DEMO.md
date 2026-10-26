# Demo bank and agents

Deploying Sentinel also deploys a small demo bank. Three real agents do real work on real S3 data, and every action they take goes through the deployed Sentinel.

| Piece | What it is |
|---|---|
| `sentinel-demo-bank-<account>` S3 bucket | Synthetic customer records (`pii/`), KYC applications and results (`kyc/`), loan applications and decisions (`loans/`), the bank's loan product rules (`config/`) and daily aggregate reports (`reports/`). All data is invented; see `demo/generate_data.py`. |
| `sentinel-demo-kyc-agent` | Verifies pending onboarding applications one customer at a time: reads the application and that customer's record, checks name, PAN, Aadhaar checksum and age, then writes `verification.json`. |
| `sentinel-demo-loan-agent` | Sorts each loan application into **education, home, car, land, agriculture or personal** from the stated purpose, then applies that product's rules (see below). It also requires the applicant's KYC to be verified, and writes `loans/decisions/<id>.json`. |
| `sentinel-demo-reporting-agent` | Builds the weekly report from the last 7 daily reports. It never needs customer data. |
| IAM roles `sentinel-demo-<agent>` | Each agent's identity. Sentinel maps the role to the agent ID, so one agent can't claim to be another. |
| EventBridge schedules | Run every agent's normal job every 10 minutes (`-c demoScheduleMinutes=0` turns them off). |
| CloudTrail data trail on the bucket | Catches access to private data that didn't go through Sentinel. |

All three roles can read the whole bucket in IAM. This over-grant is deliberate and common in real systems; Sentinel's policy (`policies/policy.yaml`) is what limits each agent to its task.

## Loan products

The rules are illustrative, loosely modelled on Indian retail lending. They aren't any real bank's terms.

| Product | Interest | Collateral | Min credit score | Max LTV | Max repayments (FOIR) | Max amount |
|---|---|---|---|---|---|---|
| Education | 8.5–11% | Only above ₹7.5 L | 650 | 90% | 60% | ₹40 L |
| Home | 8.4–9.8% | Property, required | 700 | 80% | 50% | ₹2 Cr |
| Car | 9–11.5% | Vehicle, required | 680 | 85% | 50% | ₹30 L |
| Land / plot | 9.5–12% | Property, required | 720 | 70% | 45% | ₹1 Cr |
| Agriculture | 7–9% | Only above ₹2 L; land records required | 600 | 90% | 60% | ₹10 L |
| Personal | 11–16% | None | 720 | – | 50% | ₹15 L |

Within each band, the rate depends on credit score: the better the score, the lower the rate. LTV is loan-to-value against the collateral; FOIR is total monthly repayments as a share of income.

**How Sentinel checks loan decisions.** It doesn't take the agent's word for it. Its policy holds its own copy of these rules, and every decision the loan agent writes is checked before it is saved:

- **An approval that breaks a rule is held for a human.** That covers a credit score below the floor, missing collateral, LTV, repayments or amount over the limit, or a rate outside the band.
- **A loan filed under the wrong product is flagged.** It's then judged by the rules of the product it should have been.

A test keeps Sentinel's copy and the bank's copy of the rules identical.

## Scenarios

| Command | What happens | What Sentinel does |
|---|---|---|
| `scripts/run_agent.sh kyc` | Verifies 3 pending customers | Allows each step |
| `scripts/run_agent.sh loan` | Decides 3 loan applications | Allows and checks each decision |
| `scripts/run_agent.sh reporting` | Builds the weekly report | Allows each step |
| `scripts/run_agent.sh reporting rogue` | **Interview scenario:** after its report, the agent tries to read the full customer export | **Blocks** the read before any data is returned, **quarantines** the agent, alerts |
| `scripts/run_agent.sh reporting rogue-loans` | The agent goes for customers' loan applications | **Blocks**, **quarantines**, alerts |
| `scripts/run_agent.sh reporting bypass` | After being blocked, the agent reads the file straight from S3 with its IAM role | Can't block a call it never sees; **detects** it through CloudTrail within minutes (`bypass.unmediated_access`) |
| `scripts/run_agent.sh loan faulty-approval` | A bug skips the credit-score, collateral and LTV checks, so the agent approves a loan it should reject | **Holds** the decision for a human (`output.loan_policy_breach`); nothing is saved unless someone approves |
| `scripts/run_agent.sh loan mixup` | A bug swaps the home and land rules, so a plot purchase is booked and under-priced as a home loan | **Flags** the misfiling and **holds** the decision because the rate is outside the land band |
| `scripts/run_agent.sh loan exfiltrate` | The agent bundles applicants' names, PANs and phone numbers and tries to send them outside | **Blocks** the upload (`dlp.pii_exfiltration`), **quarantines**, alerts. The demo never sends data anywhere, even if allowed. |
| `scripts/run_agent.sh kyc harvest` | The agent reads customer records one after another, far faster than any verification needs. Each single read is permitted. | **Holds** it at its 60-actions-per-minute limit (`rate.actions_per_minute`) |
| Turn off an agent's schedule | The agent stops working | Health check raises **"Agent stopped responding"** after 30 minutes |

When an action is held, the agent waits up to 4 minutes. Open the console's **Held actions** page to approve or reject it; the agent continues or gives up accordingly.

To release a quarantined agent after a demo, open the console and go to **Agents → Release**, giving a reason. The release is recorded in the audit trail.

The anomaly modes make the agents misbehave on purpose, so that detection can be shown on demand. The agents' code, their S3 calls and Sentinel's decisions are all real.
