import json
import subprocess
import sys
import tracemalloc
from pathlib import Path

from log_redact import Config, Redactor

ROOT = Path(__file__).resolve().parent.parent


def gen_lines(n):
    for i in range(n):
        if i % 2:
            yield json.dumps({"i": i, "user": {"email": f"u{i}@example.com"},
                              "ip": f"192.0.2.{i % 250 + 1}"}) + "\n"
        else:
            yield f"2026-09-29 12:00:00 req {i} from 198.51.100.{i % 250 + 1} u{i}@example.com\n"


def test_stream_large_generator_is_lazy():
    r = Redactor(Config())
    n = 100_000
    tracemalloc.start()
    count = 0
    for out in r.redact_lines(gen_lines(n)):
        assert "example.com" not in out
        count += 1
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert count == n
    rep = r.report()
    assert rep["by_type"]["email"] == n
    assert rep["by_type"]["ipv4"] == n
    assert peak < 20_000_000  # nothing accumulates per line


def test_large_file_through_cli(tmp_path):
    src = tmp_path / "big.log"
    n = 30_000
    with open(src, "w", encoding="utf-8") as fh:
        fh.writelines(gen_lines(n))
    dst = tmp_path / "big.out"
    rep = tmp_path / "rep.json"
    import os
    env = dict(os.environ, PYTHONUTF8="1", PYTHONPATH=str(ROOT))
    p = subprocess.run([sys.executable, "-m", "log_redact", str(src), "-o", str(dst),
                        "--report", str(rep)], env=env, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    with open(dst, encoding="utf-8") as fh:
        lines = sum(1 for _ in fh)
    assert lines == n
    assert "example.com" not in dst.read_text(encoding="utf-8")
    assert json.loads(rep.read_text())["by_type"]["email"] == n
