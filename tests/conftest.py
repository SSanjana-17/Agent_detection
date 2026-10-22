import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "sdk")]
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-south-1")
os.environ.setdefault("AWS_REGION", "ap-south-1")

from sentinel_core.engine import DecisionEngine  # noqa: E402
from sentinel_core.models import ActionEvent  # noqa: E402
from sentinel_core.policy import load_policy  # noqa: E402
from sentinel_core.service import Identity, SentinelService  # noqa: E402
from sentinel_core.store import MemoryStore  # noqa: E402

POLICY_PATH = ROOT / "policies" / "policy.yaml"

# ---------------------------------------------------------------- data helpers
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]


def aadhaar(base11: str) -> str:
    """Synthetic Aadhaar number with a valid Verhoeff check digit."""
    c = 0
    for i, ch in enumerate(reversed(base11)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return base11 + str(_INV[c])


def luhn_card(prefix15: str) -> str:
    digits = [int(x) for x in prefix15]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return prefix15 + str((10 - total % 10) % 10)


@pytest.fixture
def policy():
    return load_policy(POLICY_PATH)


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def engine(policy, store):
    return DecisionEngine(policy, store)


@pytest.fixture
def service(policy, store):
    return SentinelService(lambda: policy, store)


@pytest.fixture
def human():
    return Identity(kind="human", principal="analyst@example-bank.com", groups=["sentinel-approvers"])


def ev(**kw) -> ActionEvent:
    return ActionEvent(**kw)
