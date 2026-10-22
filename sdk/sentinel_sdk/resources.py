"""Helpers that turn tool arguments into a Sentinel resource string.

Resource strings should use the same form Sentinel's policy uses — for S3,
``s3://bucket/key`` — so CloudTrail cross-checks line up with SDK decisions.
"""
from __future__ import annotations

from typing import Any

_PATH_KEYS = ("resource", "uri", "url", "path", "file_path", "filepath", "filename", "file",
              "object_key", "key", "table", "table_name", "collection", "endpoint", "to", "recipient",
              "command")


def resource_from_args(args: dict[str, Any]) -> str:
    if not args:
        return ""
    bucket = args.get("bucket") or args.get("Bucket") or args.get("bucket_name")
    key = args.get("key") or args.get("Key") or args.get("object_key") or args.get("prefix")
    if bucket:
        return f"s3://{bucket}/{key}" if key else f"s3://{bucket}"
    table = args.get("table") or args.get("table_name") or args.get("TableName")
    if table:
        return f"dynamodb://{table}"
    for k in _PATH_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def infer_record_count(output: Any) -> int:
    """Best-effort count of records returned by a tool."""
    if output is None:
        return 0
    if isinstance(output, (list, tuple, set)):
        return len(output)
    if isinstance(output, dict):
        for k in ("Items", "items", "records", "rows", "results", "data", "Contents"):
            v = output.get(k)
            if isinstance(v, list):
                return len(v)
        return 1
    if isinstance(output, str):
        lines = output.count("\n")
        return max(1, lines) if lines > 1 and ("," in output or "\t" in output) else 1
    return 1
