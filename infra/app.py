#!/usr/bin/env python3
"""CDK entry point. Configuration comes from cdk.json "context" or -c flags:

    cdk deploy -c adminEmail=secops@bank.com -c alertEmails='["secops@bank.com"]' \
               -c protectedBuckets='["example-bank-customer-data"]' \
               -c bedrockModelId=<inference profile id>
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import aws_cdk as cdk  # noqa: E402

from build_lambda import build  # noqa: E402
from sentinel_stack import SentinelStack  # noqa: E402

app = cdk.App()


def ctx(name: str, default=None):
    v = app.node.try_get_context(name)
    if isinstance(v, str) and v.strip().startswith("["):
        return json.loads(v)
    return default if v is None else v


config = {
    "adminEmail": ctx("adminEmail", ""),
    "alertEmails": ctx("alertEmails", []),
    "protectedBuckets": ctx("protectedBuckets", []),
    "bedrockModelId": ctx("bedrockModelId", ""),
    "evidenceRetentionDays": ctx("evidenceRetentionDays", 2555),
    "cognitoDomainPrefix": ctx("cognitoDomainPrefix", None) or None,
    "securityHub": str(ctx("securityHub", "false")).lower() == "true",
    "consoleHosting": ctx("consoleHosting", "cloudfront"),
}
config = {k: v for k, v in config.items() if v is not None}

lambda_dir = build(arch="arm64")

SentinelStack(
    app, ctx("stackName", "Sentinel"), lambda_dir=str(lambda_dir), config=config,
    env=cdk.Environment(account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
                        region=ctx("region", os.environ.get("CDK_DEFAULT_REGION", "ap-south-1"))),
    description="Sentinel: AI agent governance, monitoring and enforcement",
)
app.synth()
