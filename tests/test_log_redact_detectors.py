import base64
import json

from log_redact import Config, Redactor


def red(text, **kw):
    return Redactor(Config(**kw)).redact_text(text)


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def test_email():
    assert red("contact jane.doe+x@example.com now") == "contact [EMAIL] now"
    assert red("no at sign here, 5 @ 6") == "no at sign here, 5 @ 6"


def test_phone_nanp_and_e164():
    assert red("call 613-555-0142 today") == "call [PHONE] today"
    assert red("call (506) 555-0123 today") == "call [PHONE] today"
    assert red("call +1 613 555 0100") == "call [PHONE]"
    assert red("intl +442079460958 ok") == "intl [PHONE] ok"
    assert red("intl +44 20 7946 0958 ok") == "intl [PHONE] ok"


def test_credit_card_luhn(luhn, luhn_invalid):
    good = luhn("41111111111111")
    assert len(good) == 15
    good16 = luhn("411111111111111")
    spaced = " ".join(good16[i:i + 4] for i in range(0, 16, 4))
    dashed = "-".join(good16[i:i + 4] for i in range(0, 16, 4))
    assert red(f"card {good16} end") == "card [CREDIT_CARD] end"
    assert red(f"card {spaced} end") == "card [CREDIT_CARD] end"
    assert red(f"card {dashed} end") == "card [CREDIT_CARD] end"
    bad = luhn_invalid("411111111111111")
    assert red(f"card {bad} end") == f"card {bad} end"


def test_card_next_to_other_number(luhn):
    c = luhn("411111111111111")
    assert red(f"{c} 200") == "[CREDIT_CARD] 200"


def test_sin_luhn_and_context(luhn, luhn_invalid):
    s = luhn("12345678")
    grouped = f"{s[:3]} {s[3:6]} {s[6:]}"
    dashed = f"{s[:3]}-{s[3:6]}-{s[6:]}"
    assert red(f"id {grouped}") == "id [SIN]"
    assert red(f"id {dashed}") == "id [SIN]"
    bad = luhn_invalid("12345678")
    badg = f"{bad[:3]} {bad[3:6]} {bad[6:]}"
    assert red(f"id {badg}") == f"id {badg}"
    # context-aware: needs a keyword before it
    assert red(f"ref {grouped}", sin_context=True) == f"ref {grouped}"
    assert red(f"SIN: {grouped}", sin_context=True) == "SIN: [SIN]"
    assert red(f"social insurance number {dashed}", sin_context=True).endswith("[SIN]")


def test_ipv4_and_prefix():
    assert red("from 192.0.2.44 ok") == "from [IPV4] ok"
    assert red("from 198.51.100.7", keep_ip_prefix=True) == "from 198.51.100.[IPV4]"
    assert red("from 203.0.113.250:8080") == "from [IPV4]:8080"


def test_ipv6_and_prefix():
    assert red("from 2001:db8::1 ok") == "from [IPV6] ok"
    assert red("from 2001:db8:abcd:12::5", keep_ip_prefix=True) == "from 2001:db8:abcd::[IPV6]"


def test_jwt():
    tok = ".".join([b64({"alg": "HS256"}), b64({"sub": "u1"}), "c2lnbmF0dXJl"])
    assert red(f"jwt={tok} end") == "jwt=[JWT] end"


def test_bearer():
    assert red("Authorization: Bearer abcDEF123456xyz") == "Authorization: Bearer [BEARER]"
    assert red("authorization=bearer AbCdEf12") == "authorization=bearer [BEARER]"


def test_api_keys():
    keys = [
        "sk_" + "live_" + "A1b2C3d4E5f6G7h8",
        "sk_" + "test_" + "A1b2C3d4E5f6G7h8",
        "pk_" + "live_" + "A1b2C3d4E5f6G7h8",
        "gh" + "p_" + "a" * 36,
        "github_" + "pat_" + "B" * 30,
        "AK" + "IA" + "ABCDEFGHIJKLMNOP",
        "xo" + "xb-" + "1234567890-abcdefghij",
        "AI" + "za" + "x" * 35,
        "gl" + "pat-" + "z" * 20,
    ]
    for k in keys:
        assert red(f"key {k} end") == "key [API_KEY] end", k


def test_url_password_keeps_user():
    out = red("db postgres://alice:S3cr3t!pw@db.example.com:5432/app")
    assert out == "db postgres://alice:[URL_PASSWORD]@db.example.com:5432/app"
    assert "S3cr3t" not in out


def test_query_params_value_only():
    out = red("GET /cb?code=abc123&name=bob&token=zzz9&sid=42 HTTP/1.1")
    assert out == ("GET /cb?code=[QUERY_PARAM]&name=bob&token=[QUERY_PARAM]"
                   "&sid=[QUERY_PARAM] HTTP/1.1")
    assert red("/x?keyword=hello&passwords=1") == "/x?keyword=hello&passwords=1"


def test_postal_code_off_by_default():
    assert red("zip E1V 3A1") == "zip E1V 3A1"
    assert red("zip E1V 3A1", enable={"postal_code"}) == "zip [POSTAL_CODE]"


def test_custom_pattern():
    out = red("order ORD-12345 done", patterns={"order": r"ORD-\d+"})
    assert out == "order [ORDER] done"


def test_negatives_timestamps_versions():
    lines = [
        "2026-09-29 12:34:56,789 INFO started",
        "2026-09-29T12:34:56Z",
        "version 1.2.3 build 2.10.1",
        "python 3.12.4 released",
        "epoch 1700000000",
        "mac aa:bb:cc:dd:ee:ff",
        "took 12:30:45",
    ]
    for line in lines:
        assert red(line) == line


def test_disable_and_only():
    text = "a@example.com 192.0.2.1"
    assert red(text, disable={"email"}) == "a@example.com [IPV4]"
    assert red(text, only={"email"}) == "[EMAIL] 192.0.2.1"


def test_overlap_priority():
    # password inside URL must not be double-redacted as an email or query value
    out = red("https://bob:pw123@host.example.com/x?token=abc")
    assert out == "https://bob:[URL_PASSWORD]@host.example.com/x?token=[QUERY_PARAM]"
    # api key inside a query value: one redaction, by the higher-priority detector
    r = Redactor(Config())
    k = "sk_" + "live_" + "A1b2C3d4E5f6G7h8"
    assert r.redact_text(f"/x?key={k}") == "/x?key=[API_KEY]"
    assert r.report()["total"] == 1


def test_unknown_detector_rejected():
    import pytest
    with pytest.raises(ValueError):
        Redactor(Config(disable={"nope"}))
