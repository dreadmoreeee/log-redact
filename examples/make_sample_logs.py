"""Generate synthetic logs (invented data only) into examples/out/.

    python examples/make_sample_logs.py

Cards and SINs are computed at runtime (Luhn check digit), never stored.
"""

import base64
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from log_redact.detectors import luhn_check_digit  # noqa: E402

OUT = HERE / "out"


# Publicly documented payment-processor test card numbers only.
TEST_CARDS = [
    "4111 1111 1111 1111",
    "4242 4242 4242 4242",
    "5555 5555 5555 4444",
    "3782 822463 10005",
    "378282246310005",
    "6011 1111 1111 1117",
]
# Publicly documented example SIN.
EXAMPLE_SIN = "046 454 286"


def _luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


for _c in TEST_CARDS:
    assert _luhn(_c.replace(" ", "")), _c
assert _luhn(EXAMPLE_SIN.replace(" ", ""))


def card(rng):
    return rng.choice(TEST_CARDS)


def sin(rng):
    # A leading 0 is never issued, so these cannot belong to anyone.
    if rng.random() < 0.5:
        return EXAMPLE_SIN
    payload = "0" + "".join(rng.choice("0123456789") for _ in range(7))
    n = payload + luhn_check_digit(payload)
    assert _luhn(n)
    return f"{n[:3]} {n[3:6]} {n[6:]}"


def jwt(rng):
    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(bytes(rng.randrange(256) for _ in range(24))).decode().rstrip("=")
    return ".".join([seg({"alg": "HS256", "typ": "JWT"}), seg({"sub": "demo-user"}), sig])


def main(n=200, seed=7):
    rng = random.Random(seed)
    OUT.mkdir(exist_ok=True)
    users = ["alice", "bob", "carol", "dave"]
    ips = ["192.0.2.", "198.51.100.", "203.0.113."]
    paths = ["/", "/login", "/api/items", "/cart", "/health"]
    with open(OUT / "access.log", "w", encoding="utf-8") as fh:
        for i in range(n):
            ip = rng.choice(ips) + str(rng.randint(1, 250))
            ts = f"29/Sep/2026:10:{i // 60 % 60:02d}:{i % 60:02d} +0000"
            p = rng.choice(paths)
            if i % 5 == 0:
                p = f"/reset?token={rng.getrandbits(48):x}&user={rng.choice(users)}@example.com"
            elif i % 7 == 0:
                p = f"/oauth/cb?code={rng.getrandbits(40):x}&state=abc"
            auth = ""
            if i % 9 == 0:
                auth = f' "Authorization: Bearer {rng.getrandbits(96):024x}"'
            fh.write(f'{ip} - - [{ts}] "GET {p} HTTP/1.1" 200 {rng.randint(200, 9000)}{auth}\n')
    with open(OUT / "app.jsonl", "w", encoding="utf-8") as fh:
        for i in range(n):
            u = rng.choice(users)
            rec = {"ts": f"2026-09-29T10:00:{i % 60:02d}Z", "level": "INFO",
                   "user": {"id": i, "email": f"{u}@example.com"},
                   "client_ip": rng.choice(ips) + str(rng.randint(1, 250)),
                   "headers": {"authorization": f"Bearer {rng.getrandbits(96):024x}"},
                   "msg": f"checkout by {u}@example.com"}
            if i % 4 == 0:
                rec["msg"] += f" card {card(rng)} phone 613-555-01{rng.randint(10, 99)}"
            if i % 11 == 0:
                rec["msg"] += f" SIN {sin(rng)}"
            if i % 13 == 0:
                rec["token"] = jwt(rng)
            if i % 17 == 0:
                rec["db"] = f"postgres://svc:hunter{i}@db.example.com/app"
            fh.write(json.dumps(rec) + "\n")
            if i % 25 == 0:
                fh.write(f"plain text line: retry from 2001:db8::{i:x} for {u}@example.ca\n")
    print(f"wrote {OUT / 'access.log'} and {OUT / 'app.jsonl'}")


if __name__ == "__main__":
    main()
