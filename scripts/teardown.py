#!/usr/bin/env python3
"""Remove Sentinel from an AWS account completely.

    python scripts/teardown.py                    # Sentinel stack + leftovers
    python scripts/teardown.py --include-cdk      # also the CDK bootstrap (CDKToolkit)
    python scripts/teardown.py --dry-run          # only show what would be deleted

What it does, in order:
  1. deletes the Sentinel CloudFormation stack (waits for it)
  2. deletes resources the stack keeps on purpose, and leftovers from failed
     deploys: DynamoDB tables, S3 buckets, Cognito user pools, log groups,
     queues, and schedules the KMS key for deletion (AWS minimum: 7 days)
  3. evidence held under S3 Object Lock (COMPLIANCE mode) cannot be deleted by
     anyone until its retention ends; those buckets get a lifecycle rule so S3
     removes the records automatically when the lock expires.

Nothing is deleted until you type the confirmation phrase.
"""
from __future__ import annotations

import argparse
import sys
import time

import boto3
from botocore.exceptions import ClientError

STACK = "Sentinel"
BUCKET_PREFIX = "sentinel-"
NAME_PREFIX = "Sentinel-"
KMS_DESCRIPTION = "Sentinel data encryption"


def err_code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "")


# ----------------------------------------------------------------- discovery

def find_stack(cf, name):
    try:
        s = cf.describe_stacks(StackName=name)["Stacks"][0]
        return s["StackStatus"]
    except ClientError as e:
        if "does not exist" in str(e):
            return None
        raise


def find_tables(ddb):
    out = []
    for page in ddb.get_paginator("list_tables").paginate():
        out += [t for t in page["TableNames"] if t.startswith(NAME_PREFIX + "Table")]
    return out


def find_buckets(s3):
    return [b["Name"] for b in s3.list_buckets().get("Buckets", []) if b["Name"].startswith(BUCKET_PREFIX)]


def find_cdk_bucket(s3, account, region):
    name = f"cdk-hnb659fds-assets-{account}-{region}"
    return name if any(b["Name"] == name for b in s3.list_buckets().get("Buckets", [])) else None


def find_user_pools(cog):
    out = []
    for page in cog.get_paginator("list_user_pools").paginate(MaxResults=60):
        for p in page["UserPools"]:
            try:
                d = cog.describe_user_pool(UserPoolId=p["Id"])["UserPool"]
            except ClientError:
                continue
            if (d.get("UserPoolTags") or {}).get("app") == "sentinel":
                out.append((p["Id"], d.get("Domain")))
    return out


def find_log_groups(logs):
    out = []
    for prefix in (NAME_PREFIX, "/aws/lambda/" + NAME_PREFIX):
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix):
            out += [g["logGroupName"] for g in page["logGroups"]]
    return out


def find_queues(sqs):
    return sqs.list_queues(QueueNamePrefix=NAME_PREFIX).get("QueueUrls", [])


def find_kms_keys(kms):
    out = []
    for page in kms.get_paginator("list_keys").paginate():
        for k in page["Keys"]:
            try:
                m = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            except ClientError:
                continue
            if (m.get("KeyManager") == "CUSTOMER" and m.get("Description") == KMS_DESCRIPTION
                    and m.get("KeyState") not in ("PendingDeletion", "PendingReplicaDeletion")):
                out.append(k["KeyId"])
    return out


# ------------------------------------------------------------------ deletion

def empty_and_delete_bucket(s3, name) -> str:
    """Delete every object version, then the bucket. Returns a short outcome."""
    locked = 0
    try:
        lock = s3.get_object_lock_configuration(Bucket=name)["ObjectLockConfiguration"]
        has_lock = lock.get("ObjectLockEnabled") == "Enabled"
    except ClientError:
        has_lock = False
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        for i in range(0, len(objs), 1000):
            resp = s3.delete_objects(Bucket=name, Delete={"Objects": objs[i:i + 1000], "Quiet": True})
            locked += len(resp.get("Errors", []))
    if locked:
        if has_lock:
            # Can't delete before retention ends: have S3 remove them as soon as it does.
            s3.put_bucket_lifecycle_configuration(Bucket=name, LifecycleConfiguration={"Rules": [{
                "ID": "expire-after-object-lock", "Status": "Enabled", "Filter": {"Prefix": ""},
                "Expiration": {"Days": 2556},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 2556},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]})
            return f"KEPT: {locked} audit record(s) are under a 7-year compliance lock; set to auto-delete when it ends"
        return f"KEPT: {locked} object(s) could not be deleted"
    try:
        s3.delete_bucket(Bucket=name)
        return "deleted"
    except ClientError as e:
        return f"KEPT: {err_code(e)}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Remove Sentinel from this AWS account")
    ap.add_argument("--region", default=None)
    ap.add_argument("--include-cdk", action="store_true", help="also remove the CDK bootstrap stack")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args()

    session = boto3.Session(region_name=args.region or None)
    region = session.region_name or "ap-south-1"
    sts, cf = session.client("sts"), session.client("cloudformation", region_name=region)
    s3, ddb = session.client("s3", region_name=region), session.client("dynamodb", region_name=region)
    cog, logs = session.client("cognito-idp", region_name=region), session.client("logs", region_name=region)
    sqs, kms = session.client("sqs", region_name=region), session.client("kms", region_name=region)
    account = sts.get_caller_identity()["Account"]

    stack = find_stack(cf, STACK)
    cdk_stack = find_stack(cf, "CDKToolkit") if args.include_cdk else None
    print(f"Account {account}, region {region}\n")
    print("Will delete:")
    print(f"  CloudFormation stack  {STACK}: {stack or 'not found'}")
    if args.include_cdk:
        print(f"  CloudFormation stack  CDKToolkit: {cdk_stack or 'not found'}")
    if args.dry_run or not args.yes:
        # Show leftovers that exist right now (the stack's own resources go with the stack).
        for label, items in (("DynamoDB tables", find_tables(ddb)), ("S3 buckets", find_buckets(s3)),
                             ("Cognito user pools", [p for p, _ in find_user_pools(cog)]),
                             ("Log groups", find_log_groups(logs)), ("SQS queues", find_queues(sqs)),
                             ("KMS keys (7-day scheduled deletion)", find_kms_keys(kms))):
            print(f"  {label:<38} {len(items)}")
            for i in items[:8]:
                print(f"      {i}")
    if args.dry_run:
        print("\nDry run: nothing deleted.")
        return 0
    if not args.yes:
        phrase = "delete sentinel"
        typed = input(f"\nThis cannot be undone. Type '{phrase}' to continue: ").strip().lower()
        if typed != phrase:
            print("Cancelled. Nothing was deleted.")
            return 1

    # 1. the stack
    if stack and stack != "DELETE_COMPLETE":
        print(f"\nDeleting stack {STACK} (a few minutes)...")
        cf.delete_stack(StackName=STACK)
        try:
            cf.get_waiter("stack_delete_complete").wait(StackName=STACK,
                                                        WaiterConfig={"Delay": 15, "MaxAttempts": 120})
            print("  stack deleted")
        except Exception as e:
            print(f"  stack deletion did not finish cleanly: {e}\n  Continuing with leftovers.")

    # 2. leftovers (rescan after the stack is gone)
    results: list[tuple[str, str, str]] = []
    for t in find_tables(ddb):
        try:
            ddb.update_table(TableName=t, DeletionProtectionEnabled=False)
            ddb.get_waiter("table_exists").wait(TableName=t)
            ddb.delete_table(TableName=t)
            results.append(("DynamoDB table", t, "deleted"))
        except ClientError as e:
            results.append(("DynamoDB table", t, f"KEPT: {err_code(e)}"))
    for b in find_buckets(s3):
        results.append(("S3 bucket", b, empty_and_delete_bucket(s3, b)))
    for pool_id, domain in find_user_pools(cog):
        try:
            if domain:
                cog.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
            cog.delete_user_pool(UserPoolId=pool_id)
            results.append(("Cognito user pool", pool_id, "deleted"))
        except ClientError as e:
            results.append(("Cognito user pool", pool_id, f"KEPT: {err_code(e)}"))
    for g in find_log_groups(logs):
        try:
            logs.delete_log_group(logGroupName=g)
            results.append(("Log group", g, "deleted"))
        except ClientError as e:
            results.append(("Log group", g, f"KEPT: {err_code(e)}"))
    for q in find_queues(sqs):
        try:
            sqs.delete_queue(QueueUrl=q)
            results.append(("SQS queue", q.rsplit("/", 1)[-1], "deleted"))
        except ClientError as e:
            results.append(("SQS queue", q, f"KEPT: {err_code(e)}"))
    for k in find_kms_keys(kms):
        try:
            kms.schedule_key_deletion(KeyId=k, PendingWindowInDays=7)
            results.append(("KMS key", k, "scheduled for deletion in 7 days"))
        except ClientError as e:
            results.append(("KMS key", k, f"KEPT: {err_code(e)}"))

    # 3. optional: CDK bootstrap
    if args.include_cdk and cdk_stack:
        b = find_cdk_bucket(s3, account, region)
        if b:
            results.append(("S3 bucket", b, empty_and_delete_bucket(s3, b)))
        try:
            ecr = session.client("ecr", region_name=region)
            repo = f"cdk-hnb659fds-container-assets-{account}-{region}"
            ecr.delete_repository(repositoryName=repo, force=True)
        except ClientError:
            pass
        cf.delete_stack(StackName="CDKToolkit")
        try:
            cf.get_waiter("stack_delete_complete").wait(StackName="CDKToolkit",
                                                        WaiterConfig={"Delay": 10, "MaxAttempts": 60})
            results.append(("CloudFormation stack", "CDKToolkit", "deleted"))
        except Exception as e:
            results.append(("CloudFormation stack", "CDKToolkit", f"KEPT: {e}"))

    print("\nResult:")
    for kind, name, outcome in results:
        print(f"  {kind:<22} {name[:60]:<60} {outcome}")
    if not results:
        print("  no leftovers found")
    kept = [r for r in results if r[2].startswith("KEPT")]
    print("\nDone." + (" Some items were kept; see above." if kept else " Sentinel is fully removed."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
