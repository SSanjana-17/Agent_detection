# Connecting agents to Sentinel

Every agent embeds the Sentinel SDK. Before a tool runs, the SDK asks Sentinel for a decision. A denial raises an exception, a hold waits for a human, and an allow returns at once.

```bash
pip install ./sdk boto3
```

```python
from sentinel_sdk import Sentinel
sentinel = Sentinel(endpoint="https://<id>.execute-api.ap-south-1.amazonaws.com/prod/agent",
                    agent_id="kyc-agent")          # requests are signed with the agent's IAM role
sentinel.start_heartbeat(60)                       # needed if the policy sets heartbeat_seconds
```

## Rules that make it work

1. **Resource strings match policy patterns.** Use `s3://bucket/key` for S3 and `dynamodb://table/key` for DynamoDB. The CloudTrail bypass check compares these exact forms.
2. **Wrap work in a task.** `with sentinel.task(task_id, "plain-English task")` gives the LLM judge the agent's assignment to compare actions against.
3. **Register untrusted input.** Mark content the agent reads from outside (emails, web pages, uploaded documents, MCP results) with `sentinel.observe_input(text)`, or use `untrusted_output=True` on the tool. Sentinel then screens it for injected instructions before the agent's next action. The adapters below do this automatically.
4. **Screen final answers.** Call `sentinel.check_output(answer)` before an answer leaves the agent, so PII and secrets can't slip out in the response.

## Any Python code: decorator

```python
@sentinel.guard("read", resource=lambda customer_id: f"s3://yourbank-customer-data/kyc/{customer_id}/profile.json")
def load_profile(customer_id): ...

@sentinel.guard("network", untrusted_output=True)
def fetch_url(url): ...
```

## Claude Agent SDK

```python
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from sentinel_sdk.adapters.claude_agent_sdk import sentinel_hooks

options = ClaudeAgentOptions(hooks=sentinel_hooks(sentinel))
async with ClaudeSDKClient(options=options) as client:
    with sentinel.task("ONB-2231", "Verify identity documents for customer C-2231"):
        await client.query("...")
```

Each tool call, whether built-in, MCP or custom, goes through a `PreToolUse` hook. A denial comes back to Claude as `permissionDecision: "deny"` with Sentinel's reason. Tool results are reported through `PostToolUse` and treated as untrusted input.

## LangChain / LangGraph

```python
from sentinel_sdk.adapters.langchain import guard_tools
tools = guard_tools([lookup_customer, web_search], sentinel,
                    actions={"lookup_customer": "read"},
                    resources={"lookup_customer": lambda a: f"dynamodb://customers/{a['customer_id']}"},
                    untrusted=["web_search"])
agent = create_react_agent(llm, tools)
```

## MCP clients

```python
from sentinel_sdk.adapters.mcp import GuardedSession
session = GuardedSession(raw_session, sentinel, server="crm")
await session.call_tool("get_customer", {"customer_id": "C-17"})
```

## Hand-written tool loops (Anthropic, OpenAI, Bedrock Converse, CrewAI)

```python
from sentinel_sdk.adapters.toolbox import GuardedToolbox
box = GuardedToolbox(sentinel)

@box.tool("read", resource=lambda a: f"s3://yourbank-lending/{a['application_id']}/credit.json")
def get_credit_file(application_id): ...

result = box.execute(tool_use.name, tool_use.input)   # {"ok": False, "blocked": True, ...} if denied
```

## What the agent sees

| Outcome | SDK behaviour |
|---|---|
| Allow | returns the decision |
| Flag | returns; an alert is raised in the background |
| Hold | blocks until a human approves (returns) or rejects/timeout (`ActionRejected`) |
| Block / Quarantine | raises `ActionDenied` with the reason |
| Sentinel unreachable | raises `SentinelUnavailable` (fail closed). Set `fail_mode="open"` only for non-critical agents |

## Testing your agents offline

```python
sentinel = Sentinel.local("kyc-agent", policy_path="policies/policy.yaml")
```

This runs the full decision engine in-process, so unit tests can assert that your agent is stopped when it misbehaves.
