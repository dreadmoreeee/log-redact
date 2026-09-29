"""Detectors: each finder yields (start, end, keep_prefix) spans for one data type."""

import ipaddress
import re

# ---------------------------------------------------------------- helpers


def luhn_ok(digits):
    """Return True if the digit string passes the Luhn check."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def luhn_check_digit(payload):
    """Check digit that makes payload + digit pass Luhn (used by tests and demo)."""
    for c in "0123456789":
        if luhn_ok(payload + c):
            return c
    raise ValueError("unreachable")


# ---------------------------------------------------------------- patterns

EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)

NANP_RE = re.compile(
    r"(?<![\w.+-])(?:\+?1[\s.-]?)?(?:\([2-9]\d{2}\)\s?|[2-9]\d{2}[\s.-])"
    r"[2-9]\d{2}[\s.-]\d{4}(?![\w]|[.-]\d)"
)
E164_RE = re.compile(r"(?<![\w+])\+[1-9](?:[\s.-]?\d){7,14}(?!\d)")

CARD_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,20}(?!\d)")
SIN_RE = re.compile(r"(?<![\d-])\d{3}([ -])\d{3}\1\d{3}(?![\d]|-\d)")
SIN_CONTEXT_RE = re.compile(
    r"\b(?:sin|s\.i\.n\.?|social\s+insurance|nas|assurance\s+sociale)\b", re.I
)

_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\w.])(?:{_OCT}\.){{3}}{_OCT}(?![\w]|\.\d)")
IPV6_CAND_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:]{2,39}(?![\w:])")

JWT_RE = re.compile(r"(?<![\w-])eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*")
BEARER_AUTH_RE = re.compile(
    r"(?i)\bauthorization\b[\"']?\s*[:=]\s*[\"']?bearer\s+([\w.~+/=-]{8,})"
)
BEARER_BARE_RE = re.compile(r"(?i)(?<![\w-])bearer\s+([\w.~+/=-]{16,})")

API_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"|xox[bparos]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r")(?![A-Za-z0-9_])"
)

URL_PASS_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@?#]*:([^\s/@?#]+)@"
)

SENSITIVE_PARAMS = (
    "token|key|api_key|apikey|password|passwd|secret|session|sid|code|auth|access_token"
)
QUERY_RE = re.compile(rf"(?i)(?<=[?&;])(?:{SENSITIVE_PARAMS})=([^\s&#;\"'<>]+)")

POSTAL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][ -]?"
    r"\d[ABCEGHJ-NPRSTV-Z]\d(?![A-Za-z0-9])"
)

# ---------------------------------------------------------------- finders


def find_email(text):
    for m in EMAIL_RE.finditer(text):
        yield m.start(), m.end(), ""


def find_phone(text):
    for m in NANP_RE.finditer(text):
        yield m.start(), m.end(), ""
    for m in E164_RE.finditer(text):
        if 8 <= sum(c.isdigit() for c in m.group()) <= 15:
            yield m.start(), m.end(), ""


def find_card(text):
    for m in CARD_RE.finditer(text):
        s = m.group()
        idx = [i for i, c in enumerate(s) if c.isdigit()]
        n = len(idx)
        done = False
        for length in range(min(n, 19), 12, -1):
            for st in range(n - length + 1):
                a, b = idx[st], idx[st + length - 1] + 1
                sub = s[a:b]
                digits = "".join(c for c in sub if c.isdigit())
                seps = {c for c in sub if not c.isdigit()}
                if sub[0] in "23456" and len(seps) <= 1 and luhn_ok(digits):
                    yield m.start() + a, m.start() + b, ""
                    done = True
                    break
            if done:
                break


def make_sin_finder(context):
    def find_sin(text):
        for m in SIN_RE.finditer(text):
            if not luhn_ok("".join(c for c in m.group() if c.isdigit())):
                continue
            if context and not SIN_CONTEXT_RE.search(text[max(0, m.start() - 40):m.start()]):
                continue
            yield m.start(), m.end(), ""
    return find_sin


def make_ipv4_finder(keep_prefix):
    def find_ipv4(text):
        for m in IPV4_RE.finditer(text):
            prefix = m.group().rsplit(".", 1)[0] + "." if keep_prefix else ""
            yield m.start(), m.end(), prefix
    return find_ipv4


def make_ipv6_finder(keep_prefix):
    def find_ipv6(text):
        for m in IPV6_CAND_RE.finditer(text):
            s = m.group()
            if s.count(":") < 2:
                continue
            try:
                addr = ipaddress.IPv6Address(s)
            except ValueError:
                continue
            prefix = ""
            if keep_prefix:
                g = addr.exploded.split(":")[:3]
                prefix = ":".join(x.lstrip("0") or "0" for x in g) + "::"
            yield m.start(), m.end(), prefix
    return find_ipv6


def find_jwt(text):
    for m in JWT_RE.finditer(text):
        yield m.start(), m.end(), ""


def find_bearer(text):
    for rx in (BEARER_AUTH_RE, BEARER_BARE_RE):
        for m in rx.finditer(text):
            yield m.start(1), m.end(1), ""


def find_api_key(text):
    for m in API_KEY_RE.finditer(text):
        yield m.start(), m.end(), ""


def find_url_password(text):
    for m in URL_PASS_RE.finditer(text):
        yield m.start(1), m.end(1), ""


def find_query_param(text):
    for m in QUERY_RE.finditer(text):
        yield m.start(1), m.end(1), ""


def find_postal(text):
    for m in POSTAL_RE.finditer(text):
        yield m.start(), m.end(), ""


def make_custom_finder(regex):
    rx = re.compile(regex)

    def find_custom(text):
        for m in rx.finditer(text):
            if m.end() > m.start():
                yield m.start(), m.end(), ""
    return find_custom
