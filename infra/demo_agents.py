"""Demo bank + three real agents, deployed next to Sentinel.

  * an S3 bucket holding synthetic customer data, KYC applications and reports
  * kyc-agent, loan-agent and reporting-agent as Lambda functions, each with its own IAM role
    (the role is the agent's identity: Sentinel maps the role ARN to the agent id)
  * EventBridge schedules so the agents do their job every few minutes

The agents' IAM roles may read the whole bucket on purpose. Narrowing each agent
to its task is Sentinel's job; CloudTrail bypass detection covers the agent that
goes around Sentinel and uses its IAM permissions directly.
"""
from __future__ import annotations

from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from constructs import Construct

AGENTS = {
    "kyc-agent": {"handler": "agents.kyc_agent.handler", "write_prefix": "kyc/*",
                  "schedule_input": {"batch": 3}},
    "loan-agent": {"handler": "agents.loan_agent.handler", "write_prefix": "loans/decisions/*",
                   "schedule_input": {"mode": "normal", "batch": 3}},
    "reporting-agent": {"handler": "agents.reporting_agent.handler", "write_prefix": "reports/*",
                        "schedule_input": {"mode": "normal"}},
}


class DemoAgents(Construct):
    def __init__(self, scope: Construct, cid: str, *, agent_code_dir: str, data_dir: str,
                 sentinel_endpoint: str, agent_invoke_policy: iam.IManagedPolicy,
                 schedule_minutes: int = 10, **kw) -> None:
        super().__init__(scope, cid, **kw)
        stack = Stack.of(self)

        self.bucket = s3.Bucket(
            self, "BankData", bucket_name=f"sentinel-demo-bank-{stack.account}",
            encryption=s3.BucketEncryption.S3_MANAGED, enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY, auto_delete_objects=True)
        s3deploy.BucketDeployment(
            self, "SeedData", destination_bucket=self.bucket, prune=False,
            sources=[s3deploy.Source.asset(data_dir)], memory_limit=512)

        code = lambda_.Code.from_asset(agent_code_dir)
        self.functions: dict[str, lambda_.Function] = {}
        for agent_id, spec in AGENTS.items():
            name = f"sentinel-demo-{agent_id}"
            role = iam.Role(
                self, f"{agent_id}-role", role_name=name,
                assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                description=f"Identity of the {agent_id}; Sentinel maps this role to the agent",
                managed_policies=[
                    iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
                    agent_invoke_policy])
            # Deliberately broad read (a realistic over-grant); Sentinel enforces the task scope.
            self.bucket.grant_read(role)
            self.bucket.grant_put(role, spec["write_prefix"])
            log_group = logs.LogGroup(self, f"{agent_id}-logs", log_group_name=f"/aws/lambda/{name}",
                                      retention=logs.RetentionDays.ONE_MONTH,
                                      removal_policy=RemovalPolicy.DESTROY)
            fn = lambda_.Function(
                self, f"{agent_id}-fn", function_name=name, role=role,
                runtime=lambda_.Runtime.PYTHON_3_12, architecture=lambda_.Architecture.ARM_64,
                code=code, handler=spec["handler"], memory_size=256, timeout=Duration.minutes(5),
                log_group=log_group,
                environment={"SENTINEL_ENDPOINT": sentinel_endpoint, "BANK_BUCKET": self.bucket.bucket_name,
                             "HOLD_MAX_WAIT": "240"})
            fn.node.add_dependency(log_group)
            if schedule_minutes > 0:
                events.Rule(self, f"{agent_id}-schedule", rule_name=f"{name}-schedule",
                            description=f"Runs the {agent_id}'s normal job",
                            schedule=events.Schedule.rate(Duration.minutes(schedule_minutes)),
                            targets=[targets.LambdaFunction(
                                fn, event=events.RuleTargetInput.from_object(spec["schedule_input"]),
                                retry_attempts=0)])
            self.functions[agent_id] = fn
