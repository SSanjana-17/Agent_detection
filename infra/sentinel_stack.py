"""AWS CDK stack for Sentinel.

Everything Sentinel needs in one stack: API, compute, state, evidence,
alerting, approval workflow, CloudTrail bypass detection, the console and
monitoring. All data is encrypted with a customer-managed KMS key.
"""
from __future__ import annotations

from pathlib import Path

from aws_cdk import (ArnFormat, CfnOutput, Duration, RemovalPolicy, Stack, Tags)
from aws_cdk import aws_apigateway as apigw
from aws_cdk import aws_cloudfront as cf
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_cloudtrail as cloudtrail
from aws_cdk import aws_cloudwatch as cw
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_lambda_event_sources as les
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from aws_cdk import aws_secretsmanager as sm
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subs
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from constructs import Construct


def cdk_json(stack: Stack, obj: dict) -> str:
    return stack.to_json_string(obj)

ROOT = Path(__file__).resolve().parent.parent


class SentinelStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, lambda_dir: str, config: dict, **kw) -> None:
        super().__init__(scope, cid, **kw)
        Tags.of(self).add("app", "sentinel")

        alert_emails: list[str] = config.get("alertEmails", [])
        admin_email: str = config.get("adminEmail", "")
        protected_buckets: list[str] = config.get("protectedBuckets", [])
        model_id: str = config.get("bedrockModelId", "")
        retention_days: int = int(config.get("evidenceRetentionDays", 2555))
        domain_prefix: str = config.get("cognitoDomainPrefix", f"sentinel-{self.account}")
        security_hub: bool = bool(config.get("securityHub", False))
        # "cloudfront": host the console on CloudFront. "local": no hosting; open the
        # console from your machine with scripts/console.sh (needed while a new AWS
        # account is still awaiting CloudFront verification).
        console_hosting: str = str(config.get("consoleHosting", "cloudfront")).lower()
        local_console = "http://localhost:8787"
        arch = lambda_.Architecture.ARM_64

        # ------------------------------------------------------------ crypto
        key = kms.Key(self, "Key", alias="alias/sentinel", enable_key_rotation=True,
                      description="Sentinel data encryption", removal_policy=RemovalPolicy.RETAIN)
        key.grant_encrypt_decrypt(iam.ServicePrincipal("sns.amazonaws.com"))
        key.grant_encrypt_decrypt(iam.ServicePrincipal("cloudwatch.amazonaws.com"))  # alarms -> SNS
        key.grant_encrypt_decrypt(iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com"))

        # ------------------------------------------------------------- state
        table = ddb.TableV2(
            self, "Table",
            partition_key=ddb.Attribute(name="PK", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="SK", type=ddb.AttributeType.STRING),
            billing=ddb.Billing.on_demand(),
            encryption=ddb.TableEncryptionV2.customer_managed_key(key),
            point_in_time_recovery_specification=ddb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True),
            deletion_protection=True,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN,
            global_secondary_indexes=[ddb.GlobalSecondaryIndexPropsV2(
                index_name="GSI1",
                partition_key=ddb.Attribute(name="GSI1PK", type=ddb.AttributeType.STRING),
                sort_key=ddb.Attribute(name="GSI1SK", type=ddb.AttributeType.STRING))],
        )

        # Evidence + async analysis queue. FIFO: each message group (one per agent,
        # plus 'controls', 'policy', ...) is delivered in order and never processed
        # concurrently, so each group owns one evidence hash chain.
        dead_letters = sqs.Queue(
            self, "EventsDLQ", fifo=True, encryption=sqs.QueueEncryption.KMS, encryption_master_key=key,
            retention_period=Duration.days(14), enforce_ssl=True)
        events_queue = sqs.Queue(
            self, "EventsQueue", fifo=True, encryption=sqs.QueueEncryption.KMS, encryption_master_key=key,
            deduplication_scope=sqs.DeduplicationScope.MESSAGE_GROUP,
            fifo_throughput_limit=sqs.FifoThroughputLimit.PER_MESSAGE_GROUP_ID,
            visibility_timeout=Duration.minutes(12), retention_period=Duration.days(14), enforce_ssl=True,
            dead_letter_queue=sqs.DeadLetterQueue(queue=dead_letters, max_receive_count=10))

        access_logs = s3.Bucket(
            self, "AccessLogs", encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL, enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(400))],
            removal_policy=RemovalPolicy.RETAIN)

        policy_bucket = s3.Bucket(
            self, "PolicyBucket", versioned=True, encryption=s3.BucketEncryption.KMS,
            encryption_key=key, bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL, enforce_ssl=True,
            server_access_logs_bucket=access_logs, server_access_logs_prefix="policy/",
            removal_policy=RemovalPolicy.RETAIN)
        s3deploy.BucketDeployment(
            self, "PolicyDeploy", destination_bucket=policy_bucket, prune=False,
            sources=[s3deploy.Source.asset(str(ROOT / "policies"))])

        evidence_bucket = s3.Bucket(
            self, "EvidenceBucket", versioned=True, encryption=s3.BucketEncryption.KMS,
            encryption_key=key, bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL, enforce_ssl=True,
            object_lock_enabled=True,
            object_lock_default_retention=s3.ObjectLockRetention.compliance(Duration.days(retention_days)),
            server_access_logs_bucket=access_logs, server_access_logs_prefix="evidence/",
            lifecycle_rules=[s3.LifecycleRule(transitions=[s3.Transition(
                storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
                transition_after=Duration.days(90))])],
            removal_policy=RemovalPolicy.RETAIN)

        # ----------------------------------------------------------- alerting
        topic = sns.Topic(self, "AlertTopic", display_name="Sentinel alerts", master_key=key)
        for email in alert_emails:
            topic.add_subscription(subs.EmailSubscription(email))
        slack_secret = sm.Secret(
            self, "SlackWebhook", encryption_key=key,
            description="Slack incoming-webhook URL for Sentinel alerts (set the value after deploy)",
            secret_string_value=None,
            generate_secret_string=sm.SecretStringGenerator(
                secret_string_template='{"webhook_url": "REPLACE_WITH_SLACK_WEBHOOK_URL"}',
                generate_string_key="unused"))

        # ------------------------------------------------------------ console
        site_bucket = dist = None
        if console_hosting == "cloudfront":
            site_bucket = s3.Bucket(
                self, "ConsoleBucket", encryption=s3.BucketEncryption.S3_MANAGED,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL, enforce_ssl=True,
                removal_policy=RemovalPolicy.DESTROY, auto_delete_objects=True)
            headers = cf.ResponseHeadersPolicy(
                self, "SecurityHeaders",
                security_headers_behavior=cf.ResponseSecurityHeadersBehavior(
                    content_security_policy=cf.ResponseHeadersContentSecurityPolicy(
                        content_security_policy=(
                            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                            "img-src 'self' data:; connect-src 'self' https://*.amazonaws.com "
                            "https://*.amazoncognito.com; frame-ancestors 'none'; base-uri 'none'"),
                        override=True),
                    strict_transport_security=cf.ResponseHeadersStrictTransportSecurity(
                        access_control_max_age=Duration.days(365), include_subdomains=True, override=True),
                    content_type_options=cf.ResponseHeadersContentTypeOptions(override=True),
                    frame_options=cf.ResponseHeadersFrameOptions(frame_option=cf.HeadersFrameOption.DENY, override=True),
                    referrer_policy=cf.ResponseHeadersReferrerPolicy(
                        referrer_policy=cf.HeadersReferrerPolicy.NO_REFERRER, override=True)))
            dist = cf.Distribution(
                self, "Console", default_root_object="index.html",
                default_behavior=cf.BehaviorOptions(
                    origin=origins.S3BucketOrigin.with_origin_access_control(site_bucket),
                    viewer_protocol_policy=cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    response_headers_policy=headers,
                    cache_policy=cf.CachePolicy.CACHING_DISABLED))
            console_url = f"https://{dist.distribution_domain_name}"
        else:
            console_url = local_console

        pool = cognito.UserPool(
            self, "Users", self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            mfa=cognito.Mfa.REQUIRED, mfa_second_factor=cognito.MfaSecondFactor(sms=False, otp=True),
            password_policy=cognito.PasswordPolicy(min_length=14, require_digits=True,
                                                   require_lowercase=True, require_uppercase=True,
                                                   require_symbols=True,
                                                   temp_password_validity=Duration.days(3)),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            removal_policy=RemovalPolicy.RETAIN)
        domain = pool.add_domain("Domain", cognito_domain=cognito.CognitoDomainOptions(
            domain_prefix=domain_prefix))
        client = pool.add_client(
            "Console", generate_secret=False,
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
                callback_urls=sorted({f"{console_url}/", f"{local_console}/"}),
                logout_urls=sorted({f"{console_url}/", f"{local_console}/"})),
            id_token_validity=Duration.hours(1), access_token_validity=Duration.hours(1),
            refresh_token_validity=Duration.hours(12), prevent_user_existence_errors=True)
        for g, desc in (("sentinel-admins", "Full control"),
                        ("sentinel-approvers", "Approve/reject held actions, quarantine/release agents"),
                        ("sentinel-viewers", "Read-only")):
            cognito.CfnUserPoolGroup(self, f"Group-{g}", user_pool_id=pool.user_pool_id,
                                     group_name=g, description=desc)
        if admin_email:
            user = cognito.CfnUserPoolUser(
                self, "AdminUser", user_pool_id=pool.user_pool_id, username=admin_email,
                desired_delivery_mediums=["EMAIL"],
                user_attributes=[cognito.CfnUserPoolUser.AttributeTypeProperty(name="email", value=admin_email),
                                 cognito.CfnUserPoolUser.AttributeTypeProperty(name="email_verified", value="true")])
            attach = cognito.CfnUserPoolUserToGroupAttachment(
                self, "AdminInAdmins", user_pool_id=pool.user_pool_id, username=admin_email,
                group_name="sentinel-admins")
            attach.node.add_dependency(user)
            attach.node.add_dependency(self.node.find_child("Group-sentinel-admins"))

        # ---------------------------------------------------------- compute
        code = lambda_.Code.from_asset(lambda_dir)
        env = {
            "TABLE_NAME": table.table_name,
            "POLICY_BUCKET": policy_bucket.bucket_name,
            "POLICY_KEY": "policy.yaml",
            "QUEUE_URL": events_queue.queue_url,
            "EVIDENCE_BUCKET": evidence_bucket.bucket_name,
            "ALERT_TOPIC_ARN": topic.topic_arn,
            "SLACK_WEBHOOK_SECRET_ARN": slack_secret.secret_arn,
            "BEDROCK_MODEL_ID": model_id,
            "DASHBOARD_URL": console_url,
            "CORS_ORIGIN": console_url,
            "SECURITY_HUB_ENABLED": "true" if security_hub else "false",
            "AWS_ACCOUNT_ID": self.account,
            "LOG_LEVEL": "INFO",
            "POWERTOOLS_SERVICE_NAME": "sentinel",
        }

        def fn(name: str, handler: str, timeout: int, memory: int = 1024, extra_env: dict | None = None):
            log_group = logs.LogGroup(self, f"{name}Logs", retention=logs.RetentionDays.ONE_YEAR,
                                      encryption_key=key, removal_policy=RemovalPolicy.RETAIN)
            f = lambda_.Function(
                self, name, runtime=lambda_.Runtime.PYTHON_3_12, architecture=arch, code=code,
                handler=f"sentinel_core.aws.handlers.{handler}", memory_size=memory,
                timeout=Duration.seconds(timeout), environment={**env, **(extra_env or {})},
                tracing=lambda_.Tracing.ACTIVE, log_group=log_group,
                environment_encryption=key)
            table.grant_read_write_data(f)
            policy_bucket.grant_read(f)
            events_queue.grant_send_messages(f)
            topic.grant_publish(f)
            slack_secret.grant_read(f)
            key.grant_encrypt_decrypt(f)
            if model_id:
                f.add_to_role_policy(iam.PolicyStatement(
                    actions=["bedrock:InvokeModel", "bedrock:Converse"],
                    resources=[f"arn:aws:bedrock:*::foundation-model/*",
                               f"arn:aws:bedrock:*:{self.account}:inference-profile/*"]))
            if security_hub:
                f.add_to_role_policy(iam.PolicyStatement(
                    actions=["securityhub:BatchImportFindings"], resources=["*"]))
            return f

        approval_fn = fn("ApprovalFn", "approval_handler", 30)
        stream_fn = fn("StreamFn", "stream_handler", 120)
        evidence_bucket.grant_put(stream_fn)
        evidence_bucket.grant_read(stream_fn)
        stream_fn.add_event_source(les.SqsEventSource(
            events_queue, batch_size=10, report_batch_item_failures=True))

        # ------------------------------------------------ approval workflow
        wait = tasks.LambdaInvoke(
            self, "WaitForHuman", lambda_function=approval_fn,
            integration_pattern=sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            payload=sfn.TaskInput.from_object({
                "step": "wait", "approval_id": sfn.JsonPath.string_at("$.approval_id"),
                "task_token": sfn.JsonPath.task_token}),
            task_timeout=sfn.Timeout.at("$.timeout_seconds"), result_path="$.resolution")
        expire = tasks.LambdaInvoke(
            self, "ExpireHold", lambda_function=approval_fn,
            payload=sfn.TaskInput.from_object({"step": "expire",
                                               "approval_id": sfn.JsonPath.string_at("$.approval_id")}),
            result_path="$.resolution")
        finalize = tasks.LambdaInvoke(
            self, "Finalize", lambda_function=approval_fn,
            payload=sfn.TaskInput.from_object({"step": "finalize",
                                               "approval_id": sfn.JsonPath.string_at("$.approval_id")}),
            result_path="$.final")
        wait.add_catch(expire, errors=["States.Timeout"], result_path="$.error")
        expire.next(finalize)
        sm_logs = logs.LogGroup(self, "ApprovalFlowLogs", retention=logs.RetentionDays.ONE_YEAR,
                                removal_policy=RemovalPolicy.RETAIN)
        machine_name = f"sentinel-approval-flow-{self.region}"
        machine = sfn.StateMachine(
            self, "ApprovalFlow", state_machine_name=machine_name, definition_body=sfn.DefinitionBody.from_chainable(wait.next(finalize)),
            timeout=Duration.days(2), tracing_enabled=True,
            logs=sfn.LogOptions(destination=sm_logs, level=sfn.LogLevel.ERROR))
        # Granted by name to avoid a function <-> state machine dependency cycle.
        approval_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["states:SendTaskSuccess", "states:SendTaskFailure", "states:SendTaskHeartbeat"],
            resources=[self.format_arn(service="states", resource="stateMachine",
                                       resource_name=machine_name,
                                       arn_format=ArnFormat.COLON_RESOURCE_NAME)]))

        api_fn = fn("ApiFn", "api_handler", 29, memory=1536,
                    extra_env={"STATE_MACHINE_ARN": machine.state_machine_arn})
        machine.grant_start_execution(api_fn)
        machine.grant_task_response(api_fn)

        cloudtrail_fn = fn("CloudTrailFn", "cloudtrail_handler", 30)
        scheduler_fn = fn("SchedulerFn", "scheduler_handler", 300)
        evidence_bucket.grant_read(scheduler_fn)
        scheduler_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["s3:GetBucketObjectLockConfiguration"], resources=[evidence_bucket.bucket_arn]))

        # ------------------------------------------------------------- API
        api_logs = logs.LogGroup(self, "ApiAccessLogs", retention=logs.RetentionDays.ONE_YEAR,
                                 removal_policy=RemovalPolicy.RETAIN)
        api = apigw.RestApi(
            self, "Api", rest_api_name="sentinel",
            endpoint_types=[apigw.EndpointType.REGIONAL],
            deploy_options=apigw.StageOptions(
                stage_name="prod", throttling_rate_limit=2000, throttling_burst_limit=4000,
                tracing_enabled=True, metrics_enabled=True,
                access_log_destination=apigw.LogGroupLogDestination(api_logs),
                access_log_format=apigw.AccessLogFormat.json_with_standard_fields(
                    caller=True, http_method=True, ip=True, protocol=True, request_time=True,
                    resource_path=True, response_length=True, status=True, user=True)),
            cloud_watch_role=True)
        integ = apigw.LambdaIntegration(api_fn, proxy=True)

        agent_res = api.root.add_resource("agent")
        agent_res.add_proxy(default_integration=integ, any_method=False).add_method(
            "ANY", integ, authorization_type=apigw.AuthorizationType.IAM)

        authorizer = apigw.CognitoUserPoolsAuthorizer(self, "ConsoleAuth", cognito_user_pools=[pool])
        console_res = api.root.add_resource("console", default_cors_preflight_options=apigw.CorsOptions(
            allow_origins=sorted({console_url, local_console}), allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"]))
        console_proxy = console_res.add_resource("{proxy+}", default_cors_preflight_options=apigw.CorsOptions(
            allow_origins=sorted({console_url, local_console}), allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"]))
        for m in ("GET", "POST"):
            console_proxy.add_method(m, integ, authorizer=authorizer,
                                     authorization_type=apigw.AuthorizationType.COGNITO)

        # Attach this to every agent's IAM role.
        agent_policy = iam.ManagedPolicy(
            self, "AgentInvokePolicy", description="Lets an AI agent call Sentinel's agent API",
            statements=[iam.PolicyStatement(
                actions=["execute-api:Invoke"],
                resources=[api.arn_for_execute_api(method="*", path="/agent/*", stage="prod")])])

        # -------------------------------------------------------- dashboard
        console_config = {
            "apiUrl": f"{api.url}console",
            "auth": "cognito",
            "region": self.region,
            "cognitoDomain": f"https://{domain.domain_name}.auth.{self.region}.amazoncognito.com",
            "clientId": client.user_pool_client_id,
        }
        if dist is not None:
            s3deploy.BucketDeployment(
                self, "ConsoleDeploy", destination_bucket=site_bucket, distribution=dist,
                sources=[s3deploy.Source.asset(str(ROOT / "dashboard")),
                         s3deploy.Source.json_data("config.json", console_config)])
        CfnOutput(self, "ConsoleConfig", value=cdk_json(self, console_config),
                  description="dashboard/config.json for running the console locally")

        # -------------------------------------------------- bypass detection
        trail_arn = ""
        if protected_buckets:
            trail_bucket = s3.Bucket(
                self, "TrailBucket", encryption=s3.BucketEncryption.KMS, encryption_key=key,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL, enforce_ssl=True,
                versioned=True, removal_policy=RemovalPolicy.RETAIN)
            key.grant_encrypt_decrypt(iam.ServicePrincipal("cloudtrail.amazonaws.com"))
            trail = cloudtrail.Trail(
                self, "DataTrail", bucket=trail_bucket, encryption_key=key,
                include_global_service_events=False, is_multi_region_trail=False,
                enable_file_validation=True, management_events=cloudtrail.ReadWriteType.NONE)
            for b in protected_buckets:
                trail.add_s3_event_selector(
                    [cloudtrail.S3EventSelector(bucket=s3.Bucket.from_bucket_name(self, f"Protected-{b}", b))],
                    include_management_events=False, read_write_type=cloudtrail.ReadWriteType.ALL)
            trail_arn = trail.trail_arn
            events.Rule(
                self, "S3DataAccessRule",
                event_pattern=events.EventPattern(
                    source=["aws.s3"], detail_type=["AWS API Call via CloudTrail"],
                    detail={"eventSource": ["s3.amazonaws.com"],
                            "requestParameters": {"bucketName": protected_buckets}}),
                targets=[targets.LambdaFunction(cloudtrail_fn, retry_attempts=4)])
            scheduler_fn.add_environment("TRAIL_ARN", trail_arn)
            scheduler_fn.add_to_role_policy(iam.PolicyStatement(
                actions=["cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors"],
                resources=[trail_arn]))

        # --------------------------------------------------------- schedules
        events.Rule(self, "HealthEveryMinute", schedule=events.Schedule.rate(Duration.minutes(1)),
                    targets=[targets.LambdaFunction(scheduler_fn, event=events.RuleTargetInput.from_object(
                        {"job": "health"}))])
        events.Rule(self, "ControlsHourly", schedule=events.Schedule.rate(Duration.hours(1)),
                    targets=[targets.LambdaFunction(scheduler_fn, event=events.RuleTargetInput.from_object(
                        {"job": "controls"}))])
        events.Rule(self, "ControlsDailyFull", schedule=events.Schedule.cron(minute="17", hour="20"),
                    targets=[targets.LambdaFunction(scheduler_fn, event=events.RuleTargetInput.from_object(
                        {"job": "controls", "verify_evidence": True}))])

        # -------------------------------------------- monitoring of Sentinel
        alarm_action = cw_actions.SnsAction(topic)
        alarms = [
            cw.Alarm(self, "ApiErrors", metric=api.metric_server_error(period=Duration.minutes(1)),
                     threshold=5, evaluation_periods=1,
                     alarm_description="Sentinel API returning 5xx — agents may be failing closed"),
            cw.Alarm(self, "ApiLatency", metric=api.metric_latency(period=Duration.minutes(5), statistic="p99"),
                     threshold=1500, evaluation_periods=3,
                     alarm_description="Sentinel decision latency p99 above 1.5s"),
            cw.Alarm(self, "QueueLag", metric=events_queue.metric_approximate_age_of_oldest_message(
                period=Duration.minutes(5), statistic="Maximum"), threshold=300, evaluation_periods=2,
                alarm_description="Evidence/async analysis is more than 5 minutes behind"),
            cw.Alarm(self, "DeadLetters", metric=dead_letters.metric_approximate_number_of_messages_visible(
                period=Duration.minutes(5), statistic="Maximum"), threshold=1, evaluation_periods=1,
                alarm_description="Evidence events failed repeatedly and were parked in the dead-letter queue"),
        ]
        for f in (api_fn, stream_fn, cloudtrail_fn, scheduler_fn, approval_fn):
            alarms.append(cw.Alarm(self, f"{f.node.id}Errors", metric=f.metric_errors(period=Duration.minutes(5)),
                                   threshold=1, evaluation_periods=1,
                                   alarm_description=f"Errors in Sentinel {f.node.id}"))
        for a in alarms:
            a.add_alarm_action(alarm_action)

        # ---------------------------------------------------------- outputs
        CfnOutput(self, "AgentEndpoint", value=f"{api.url}agent",
                  description="Sentinel(endpoint=...) for agents (SigV4/IAM auth)")
        CfnOutput(self, "ConsoleUrl", value=console_url)
        CfnOutput(self, "AgentInvokePolicyArn", value=agent_policy.managed_policy_arn,
                  description="Attach to every agent's IAM role")
        CfnOutput(self, "PolicyBucketName", value=policy_bucket.bucket_name)
        CfnOutput(self, "EvidenceBucketName", value=evidence_bucket.bucket_name)
        CfnOutput(self, "SlackSecretArn", value=slack_secret.secret_arn,
                  description="Put your Slack webhook URL here")
        CfnOutput(self, "UserPoolId", value=pool.user_pool_id)
        CfnOutput(self, "TableName", value=table.table_name)
        CfnOutput(self, "AlertTopicArn", value=topic.topic_arn)
