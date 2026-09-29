"""Redaction engine: text mode, JSON-lines mode, pseudonymization, reporting."""

import fnmatch
import hashlib
import hmac
import json
from collections import Counter
from dataclasses import dataclass, field

from . import detectors as d

# name -> (priority, enabled by default). Lower priority number wins an overlap.
BUILTIN = {
    "jwt": (10, True),
    "bearer": (11, True),
    "api_key": (12, True),
    "url_password": (13, True),
    "query_param": (14, True),
    "email": (20, True),
    "credit_card": (21, True),
    "sin": (22, True),
    "ipv6": (23, True),
    "ipv4": (24, True),
    "phone": (25, True),
    "postal_code": (26, False),
}
CUSTOM_PRIORITY = 1
JSON_KEY_LABEL = "json_key"


@dataclass
class Config:
    mode: str = "mask"                          # "mask" or "pseudonymize"
    key: bytes = b""
    enable: set = field(default_factory=set)    # extra detectors (e.g. postal_code)
    disable: set = field(default_factory=set)
    only: set = field(default_factory=set)      # if non-empty, exactly these
    keep_ip_prefix: bool = False
    sin_context: bool = False
    patterns: dict = field(default_factory=dict)  # NAME -> regex
    json_keys: list = field(default_factory=list)
    json_mode: bool = True

    def active(self):
        if self.only:
            return set(self.only)
        names = {n for n, (_, on) in BUILTIN.items() if on} | set(self.enable)
        return names - set(self.disable)


class Redactor:
    def __init__(self, cfg):
        if cfg.mode not in ("mask", "pseudonymize"):
            raise ValueError("mode must be 'mask' or 'pseudonymize'")
        if cfg.mode == "pseudonymize" and not cfg.key:
            raise ValueError("pseudonymize mode needs a key")
        unknown = (set(cfg.enable) | set(cfg.disable) | set(cfg.only)) - set(BUILTIN)
        if unknown:
            raise ValueError("unknown detector(s): " + ", ".join(sorted(unknown)))
        self.cfg = cfg
        self.counts = Counter()
        self.lines = 0
        self.lines_changed = 0
        self._json_keys = [k.lower() for k in cfg.json_keys]
        finders = {
            "email": d.find_email, "phone": d.find_phone, "credit_card": d.find_card,
            "sin": d.make_sin_finder(cfg.sin_context),
            "ipv4": d.make_ipv4_finder(cfg.keep_ip_prefix),
            "ipv6": d.make_ipv6_finder(cfg.keep_ip_prefix),
            "jwt": d.find_jwt, "bearer": d.find_bearer, "api_key": d.find_api_key,
            "url_password": d.find_url_password, "query_param": d.find_query_param,
            "postal_code": d.find_postal,
        }
        self._active = [(BUILTIN[n][0], n, finders[n]) for n in cfg.active()]
        for name, rx in cfg.patterns.items():
            self._active.append((CUSTOM_PRIORITY, name.lower(), d.make_custom_finder(rx)))
        self._active.sort(key=lambda t: t[0])

    # ------------------------------------------------------------ tokens
    def _token(self, label, value):
        if self.cfg.mode == "mask":
            return "[" + label.upper() + "]"
        norm = value
        if label == "email":
            norm = value.lower()
        elif label in ("phone", "credit_card", "sin"):
            norm = "".join(c for c in value if c.isdigit())
        msg = (label + ":" + norm).encode("utf-8", "surrogateescape")
        mac = hmac.new(self.cfg.key, msg, hashlib.sha256).hexdigest()
        return label.upper() + "_" + mac[:6]

    # ------------------------------------------------------------ text
    def redact_text(self, text):
        if not text or not self._active:
            return text
        cands = []
        for prio, name, finder in self._active:
            for s, e, prefix in finder(text):
                cands.append((prio, -(e - s), s, e, name, prefix))
        if not cands:
            return text
        cands.sort()
        taken = []
        for _, _, s, e, name, prefix in cands:
            if any(s < te and ts < e for ts, te, _, _ in taken):
                continue
            taken.append((s, e, name, prefix))
        taken.sort()
        out, pos = [], 0
        for s, e, name, prefix in taken:
            out.append(text[pos:s])
            out.append(prefix + self._token(name, text[s:e]))
            self.counts[name] += 1
            pos = e
        out.append(text[pos:])
        return "".join(out)

    # ------------------------------------------------------------ json
    def _key_match(self, path):
        p = ".".join(path).lower()
        return any(fnmatch.fnmatchcase(p, pat) for pat in self._json_keys)

    def _walk(self, obj, path):
        if isinstance(obj, dict):
            res = {}
            for k, v in obj.items():
                sub = path + (str(k),)
                if self._json_keys and self._key_match(sub):
                    res[k] = self._full(v)
                else:
                    res[k] = self._walk(v, sub)
            return res
        if isinstance(obj, list):
            return [self._walk(v, path) for v in obj]
        if isinstance(obj, str):
            return self.redact_text(obj)
        return obj

    def _full(self, value):
        if value is None:
            return None
        self.counts[JSON_KEY_LABEL] += 1
        return self._token(JSON_KEY_LABEL, json.dumps(value, sort_keys=True))

    def redact_line(self, line):
        """Redact one line (without its line terminator)."""
        self.lines += 1
        before = sum(self.counts.values())
        out = None
        s = line.lstrip()
        if self.cfg.json_mode and s[:1] in ("{", "["):
            try:
                obj = json.loads(s)
            except ValueError:
                obj = None
            if obj is not None:
                new = self._walk(obj, ())
                out = json.dumps(new, ensure_ascii=False) \
                    if sum(self.counts.values()) != before else line
        if out is None:
            out = self.redact_text(line)
        if sum(self.counts.values()) != before:
            self.lines_changed += 1
        return out

    def redact_lines(self, lines):
        """Stream: iterate text lines (terminators kept), yield redacted lines."""
        for raw in lines:
            body = raw.rstrip("\r\n")
            yield self.redact_line(body) + raw[len(body):]

    # ------------------------------------------------------------ report
    def report(self):
        by_type = dict(sorted(self.counts.items()))
        return {
            "total": sum(by_type.values()),
            "by_type": by_type,
            "lines": self.lines,
            "lines_with_redactions": self.lines_changed,
        }
