"""Command line interface."""

import argparse
import json
import os
import sys

from . import __version__
from .core import BUILTIN, Config, Redactor

DEFAULT_KEY_ENV = "LOG_REDACT_KEY"


def _split(values):
    out = []
    for v in values or []:
        out.extend(x.strip() for x in v.split(",") if x.strip())
    return out


def build_parser():
    p = argparse.ArgumentParser(
        prog="log-redact",
        description="Redact personal data and secrets from logs and text files.",
    )
    p.add_argument("files", nargs="*", help="input files ('-' or none = stdin)")
    p.add_argument("-o", "--output", help="output file (default stdout)")
    p.add_argument("--mode", choices=["mask", "pseudonymize"], help="default: mask")
    p.add_argument("--key-env", help=f"env var holding the HMAC key (default {DEFAULT_KEY_ENV})")
    p.add_argument("--key-file", help="file holding the HMAC key")
    p.add_argument("--enable", action="append", help="enable detector(s), comma separated")
    p.add_argument("--disable", action="append", help="disable detector(s), comma separated")
    p.add_argument("--only", action="append", help="run only these detector(s)")
    p.add_argument("--keep-ip-prefix", action="store_true",
                   help="keep the /24 (IPv4) or /48 (IPv6) prefix")
    p.add_argument("--sin-context", action="store_true",
                   help="only flag SINs preceded by a SIN-like keyword")
    p.add_argument("--pattern", action="append", metavar="NAME=REGEX",
                   help="custom regex detector (repeatable)")
    p.add_argument("--json-key", action="append", metavar="PATH",
                   help="JSON key path always fully redacted, e.g. user.email (wildcards ok)")
    p.add_argument("--no-json", action="store_true", help="treat every line as plain text")
    p.add_argument("--config", help="JSON config file")
    p.add_argument("--report", metavar="FILE", help="write the count report as JSON")
    p.add_argument("--quiet", action="store_true", help="no report on stderr")
    p.add_argument("--fail-if-found", action="store_true",
                   help="exit 1 if anything was redacted")
    p.add_argument("--list-detectors", action="store_true")
    p.add_argument("--version", action="version", version=f"log-redact {__version__}")
    return p


def _load_key(args, mode):
    if mode != "pseudonymize":
        return b""
    if args.key_file:
        with open(args.key_file, "rb") as fh:
            key = fh.read().strip()
    else:
        key = os.environ.get(args.key_env or DEFAULT_KEY_ENV, "").encode("utf-8")
    if not key:
        raise ValueError("pseudonymize mode needs a key: set "
                         f"{args.key_env or DEFAULT_KEY_ENV} or use --key-file")
    return key


def build_config(args):
    conf = {}
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            conf = json.load(fh)
    patterns = dict(conf.get("patterns", {}))
    for item in args.pattern or []:
        name, sep, rx = item.partition("=")
        if not sep or not name.strip() or not rx:
            raise ValueError(f"--pattern needs NAME=REGEX, got: {item!r}")
        patterns[name.strip()] = rx
    mode = args.mode or conf.get("mode", "mask")
    return Config(
        mode=mode,
        key=_load_key(args, mode),
        enable=set(conf.get("enable", [])) | set(_split(args.enable)),
        disable=set(conf.get("disable", [])) | set(_split(args.disable)),
        only=set(conf.get("only", [])) | set(_split(args.only)),
        keep_ip_prefix=args.keep_ip_prefix or conf.get("keep_ip_prefix", False),
        sin_context=args.sin_context or conf.get("sin_context", False),
        patterns=patterns,
        json_keys=list(conf.get("json_keys", [])) + list(args.json_key or []),
        json_mode=not (args.no_json or conf.get("no_json", False)),
    )


def _iter_inputs(files):
    for name in files or ["-"]:
        if name == "-":
            yield from sys.stdin
        else:
            with open(name, encoding="utf-8", errors="surrogateescape", newline="") as fh:
                yield from fh


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.list_detectors:
        for name, (_, on) in sorted(BUILTIN.items(), key=lambda kv: kv[1][0]):
            print(f"{name}\t{'on' if on else 'off'}")
        return 0
    try:
        redactor = Redactor(build_config(args))
    except Exception as exc:  # bad config, missing key, bad regex
        print(f"log-redact: error: {exc}", file=sys.stderr)
        return 2

    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="surrogateescape", newline="")
    to_file = bool(args.output)
    try:
        if to_file:
            out = open(args.output, "w", encoding="utf-8", errors="surrogateescape", newline="")
        else:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="surrogateescape", newline="")
            out = sys.stdout
        try:
            for line in redactor.redact_lines(_iter_inputs(args.files)):
                out.write(line)
        finally:
            if to_file:
                out.close()
            else:
                out.flush()
    except OSError as exc:
        print(f"log-redact: error: {exc}", file=sys.stderr)
        return 2

    rep = redactor.report()
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2)
            fh.write("\n")
    elif not args.quiet:
        print(f"log-redact: {rep['total']} redaction(s) in "
              f"{rep['lines_with_redactions']}/{rep['lines']} line(s)", file=sys.stderr)
        for name, n in rep["by_type"].items():
            print(f"  {name}: {n}", file=sys.stderr)
    return 1 if (args.fail_if_found and rep["total"]) else 0
