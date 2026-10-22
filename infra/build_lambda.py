"""Build the Lambda deployment folder: sentinel_core + pinned dependencies.

Runs automatically from ``infra/app.py`` before synthesis, so ``cdk deploy``
works without Docker. Dependencies are fetched as manylinux wheels for the
Lambda architecture, so building on macOS or Windows produces a valid package.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "build" / "lambda"
REQUIREMENTS = ["PyYAML==6.0.2"]   # boto3/botocore come from the Lambda runtime
PLATFORM = {"arm64": "manylinux2014_aarch64", "x86_64": "manylinux2014_x86_64"}


def _source_hash() -> str:
    h = hashlib.sha256()
    for p in sorted((ROOT / "sentinel_core").rglob("*.py")):
        h.update(p.relative_to(ROOT).as_posix().encode())
        h.update(p.read_bytes())
    h.update(" ".join(REQUIREMENTS).encode())
    return h.hexdigest()


def build(arch: str = "arm64", python_version: str = "3.12") -> Path:
    stamp = OUT / ".build-hash"
    digest = _source_hash() + arch + python_version
    if stamp.exists() and stamp.read_text() == digest:
        return OUT
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "--no-compile", "--target", str(OUT),
         "--platform", PLATFORM[arch], "--implementation", "cp", "--python-version", python_version,
         "--only-binary=:all:", *REQUIREMENTS],
        check=True)
    shutil.copytree(ROOT / "sentinel_core", OUT / "sentinel_core",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "localserver.py"))
    stamp.write_text(digest)
    return OUT


if __name__ == "__main__":
    print(build(*(sys.argv[1:3])))
