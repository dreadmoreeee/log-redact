import json
import subprocess
import sys
from pathlib import Path

from log_redact.cli import main

ROOT = Path(__file__).resolve().parent.parent


def run_module(args, stdin="", env_extra=None):
    import os
    env = dict(os.environ, PYTHONUTF8="1", PYTHONPATH=str(ROOT))
    env.update(env_extra or {})
    return subprocess.run([sys.executable, "-m", "log_redact", *args], input=stdin,
                          capture_output=True, text=True, encoding="utf-8", env=env)


def test_stdin_stdout_and_report_on_stderr():
    p = run_module([], "hello bob@example.com\n")
    assert p.returncode == 0
    assert p.stdout == "hello [EMAIL]\n"
    assert "email: 1" in p.stderr and "bob" not in p.stderr


def test_fail_if_found_exit_codes():
    assert run_module(["--fail-if-found", "--quiet"], "bob@example.com\n").returncode == 1
    assert run_module(["--fail-if-found", "--quiet"], "nothing here\n").returncode == 0


def test_bad_usage_exit_2():
    assert run_module(["--disable", "nope"], "x\n").returncode == 2
    assert run_module(["--mode", "pseudonymize"], "x\n").returncode == 2  # no key
    assert run_module(["--pattern", "broken"], "x\n").returncode == 2
    assert run_module(["--pattern", "x=("], "x\n").returncode == 2


def test_pseudonymize_key_env_and_file(tmp_path):
    a = run_module(["--mode", "pseudonymize", "--quiet"], "bob@example.com\n",
                   {"LOG_REDACT_KEY": "abc"})
    b = run_module(["--mode", "pseudonymize", "--quiet"], "bob@example.com\n",
                   {"LOG_REDACT_KEY": "abc"})
    c = run_module(["--mode", "pseudonymize", "--quiet"], "bob@example.com\n",
                   {"LOG_REDACT_KEY": "abd"})
    assert a.stdout == b.stdout != c.stdout
    kf = tmp_path / "key.txt"
    kf.write_text("abc\n")
    d = run_module(["--mode", "pseudonymize", "--quiet", "--key-file", str(kf)],
                   "bob@example.com\n")
    assert d.stdout == a.stdout


def test_files_output_report_and_config(tmp_path):
    src = tmp_path / "in.log"
    src.write_text("a@example.com\nORD-77 from 192.0.2.9\n", encoding="utf-8")
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"patterns": {"order": r"ORD-\d+"}, "keep_ip_prefix": True}))
    out = tmp_path / "out.log"
    rep = tmp_path / "rep.json"
    rc = main([str(src), "-o", str(out), "--report", str(rep), "--config", str(cfg),
               "--json-key", "x"])
    assert rc == 0
    assert out.read_text(encoding="utf-8") == "[EMAIL]\n[ORDER] from 192.0.2.[IPV4]\n"
    data = json.loads(rep.read_text())
    assert data["by_type"] == {"email": 1, "ipv4": 1, "order": 1}


def test_list_detectors(capsys):
    assert main(["--list-detectors"]) == 0
    out = capsys.readouterr().out
    assert "postal_code\toff" in out and "email\ton" in out
