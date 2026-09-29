# log-redact

Redact personal data and secrets from logs and text files before you share them. Pure Python standard library, no dependencies. Streams line by line, so large files and pipes are fine.

## Install and run

No install needed: from the project folder, `python -m log_redact ...`. Or `pip install .` to get the `log-redact` command. Python 3.10+.

```
log-redact access.log -o access.redacted.log
cat app.jsonl | log-redact --json-key user.email --json-key headers.authorization > safe.jsonl
LOG_REDACT_KEY=my-secret log-redact --mode pseudonymize app.log > safe.log
log-redact build.log --quiet --fail-if-found > /dev/null    # CI gate
```

## Detectors

Each one can be turned off with `--disable NAME` (or run alone with `--only NAME`). `--list-detectors` prints them.

| Name | Finds |
|---|---|
| `email` | email addresses |
| `phone` | NANP (`613-555-0142`, `(506) 555-0123`) and international E.164 (`+44 20 7946 0958`) |
| `credit_card` | 13-19 digits, spaces or dashes allowed, Luhn-checked |
| `sin` | Canadian SIN, 3-3-3 groups, Luhn-checked; `--sin-context` also requires a keyword ("SIN", "social insurance", "NAS") just before it |
| `ipv4`, `ipv6` | IP addresses; `--keep-ip-prefix` keeps the /24 (IPv4) or /48 (IPv6) |
| `jwt` | JSON Web Tokens |
| `bearer` | `Authorization: Bearer ...` tokens (value only) |
| `api_key` | `sk_live_`/`sk_test_`/`pk_live_`, `ghp_`/`github_pat_`, `AKIA`, `xoxb-`/`xoxp-`, `AIza`, `glpat-` |
| `url_password` | `scheme://user:pass@host` (keeps the user, redacts the password) |
| `query_param` | values of `token`, `key`, `api_key`, `password`, `passwd`, `secret`, `session`, `sid`, `code`, `auth`, ... |
| `postal_code` | Canadian postal codes (off by default: `--enable postal_code`) |
| custom | `--pattern NAME=REGEX` (repeatable) or `"patterns"` in a config file |

Overlaps are resolved by priority (custom, then secrets, then personal data), so a value is never redacted twice.

## Modes

- **mask** (default): `[EMAIL]`.
- **pseudonymize**: `EMAIL_3f9a1c`. The same value always gives the same token (HMAC-SHA256 of type + normalized value, first 6 hex digits), so logs stay analyzable. The key comes from `LOG_REDACT_KEY`, another variable via `--key-env NAME`, or a file via `--key-file`. Different key, different tokens. Keep the key private: whoever has it can confirm guesses.

## JSON lines

Each line that parses as JSON is walked recursively and every string value is redacted. `--json-key PATH` fully redacts a value (string, number, or a whole object) whatever it contains: dotted paths like `user.email` or `headers.authorization` (case-insensitive, `*` wildcards, arrays are transparent). Lines that are not JSON fall back to text mode. Lines with nothing to redact are passed through byte for byte. `--no-json` turns this off.

## Report and exit codes

Counts per type only, never values: on stderr, or as JSON with `--report file.json`. `--quiet` silences stderr.

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | `--fail-if-found` and something was redacted |
| 2 | bad usage, config, key or regex |

## Config file

`--config file.json` (see `examples/config.json`): `mode`, `enable`, `disable`, `only`, `keep_ip_prefix`, `sin_context`, `patterns`, `json_keys`, `no_json`. Command-line flags add to it. A CI example is in `examples/ci-example.yml`.

## Measured result

`python examples/make_sample_logs.py` generates a synthetic access log (200 lines) and a JSON-lines app log (208 lines), all invented data (`example.com`, documentation IP ranges, `555-01xx` phones; cards are publicly documented test numbers, SINs are the documented example SIN or numbers starting with 0, which are never issued). Then the CLI was run in both modes. Excerpts:

Access log, before:

```
198.51.100.243 - - [29/Sep/2026:10:00:00 +0000] "GET /reset?token=a6a36513270e&user=alice@example.com HTTP/1.1" 200 1742 "Authorization: Bearer 892f902bd23f0824128b2f33"
```

mask:

```
[IPV4] - - [29/Sep/2026:10:00:00 +0000] "GET /reset?token=[QUERY_PARAM]&user=[EMAIL] HTTP/1.1" 200 1742 "Authorization: Bearer [BEARER]"
```

pseudonymize:

```
IPV4_f57e2e - - [29/Sep/2026:10:00:00 +0000] "GET /reset?token=QUERY_PARAM_e11bee&user=EMAIL_d357db HTTP/1.1" 200 1742 "Authorization: Bearer BEARER_6bc6f7"
```

JSON-lines log, before:

```
{"ts": "2026-09-29T10:00:00Z", "level": "INFO", "user": {"id": 0, "email": "alice@example.com"}, "client_ip": "192.0.2.128", "headers": {"authorization": "Bearer a5acd341aca99fd0e2856ec6"}, "msg": "checkout by alice@example.com card 3782 822463 10005 phone 613-555-0120 SIN 046 454 286", "token": "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiZGVtby11c2VyIn0.2b10_BGt17nKZQOVImn9Zp9jdu5xh5c3", "db": "postgres://svc:hunter0@db.example.com/app"}
```

mask (`--json-key user.email --json-key headers.authorization`):

```
{"ts": "2026-09-29T10:00:00Z", "level": "INFO", "user": {"id": 0, "email": "[JSON_KEY]"}, "client_ip": "[IPV4]", "headers": {"authorization": "[JSON_KEY]"}, "msg": "checkout by [EMAIL] card [CREDIT_CARD] phone [PHONE] SIN [SIN]", "token": "[JWT]", "db": "postgres://svc:[URL_PASSWORD]@db.example.com/app"}
```

pseudonymize (same flags, key `demo-key`):

```
{"ts": "2026-09-29T10:00:00Z", "level": "INFO", "user": {"id": 0, "email": "JSON_KEY_ff973e"}, "client_ip": "IPV4_18c020", "headers": {"authorization": "JSON_KEY_392957"}, "msg": "checkout by EMAIL_d357db card CREDIT_CARD_4c6718 phone PHONE_6a0220 SIN SIN_966761", "token": "JWT_e265f4", "db": "postgres://svc:URL_PASSWORD_0af749@db.example.com/app"}
```

Note `EMAIL_d357db` is the same token for `alice@example.com` in both logs. Per-type report for both files together (stderr):

```
log-redact: 1289 redaction(s) in 408/408 line(s)
  bearer: 23
  credit_card: 50
  email: 248
  ipv4: 400
  ipv6: 8
  json_key: 400
  jwt: 16
  phone: 50
  query_param: 63
  sin: 19
  url_password: 12
```

Tests: `python -m pytest -q -p no:cacheprovider --import-mode=importlib .` gives `39 passed in 24.42s` (synthetic data only, no network; includes a large generated file).

## Limitations

- **Regex-based, no guarantee of complete redaction.** It will miss things (names, street addresses, free-text secrets, unusual formats) and can flag harmless text (for example a number that happens to pass Luhn, or a 4-part version string that looks like an IPv4). Review the output before sharing anything sensitive.
- Names and postal addresses are not detected. Postal codes are optional and can collide with other tokens.
- The Luhn check cuts false positives but is not proof that a number is a real card or SIN. `--sin-context` cuts more, at the risk of missing SINs with no keyword nearby.
- JSON output is re-serialized when a line changes (key order kept, spacing normalized, non-ASCII kept as is). Redaction acts on values, not on JSON keys.
- Redaction is per line: a value split across lines is not seen.
- Pseudonyms are 24 bits: fine for analysis, but collisions are possible in very large logs.

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
