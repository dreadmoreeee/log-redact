import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _luhn_sum_ok(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


@pytest.fixture
def luhn():
    """Build a Luhn-valid number from a payload by computing the check digit."""
    def make(payload):
        for c in "0123456789":
            if _luhn_sum_ok(payload + c):
                return payload + c
        raise AssertionError
    return make


@pytest.fixture
def luhn_invalid(luhn):
    """Same payload, but with a wrong check digit."""
    def make(payload):
        good = luhn(payload)
        return payload + str((int(good[-1]) + 1) % 10)
    return make
