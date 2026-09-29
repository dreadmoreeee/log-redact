import json

import pytest

from log_redact import Config, Redactor


def mk(**kw):
    return Redactor(Config(**kw))


def test_pseudonym_deterministic_and_shaped():
    r1 = mk(mode="pseudonymize", key=b"k1")
    r2 = mk(mode="pseudonymize", key=b"k1")
    a = r1.redact_text("mail bob@example.com")
    assert a == r2.redact_text("mail bob@example.com")
    assert a.startswith("mail EMAIL_") and len(a.split("EMAIL_")[1]) == 6
    # same value twice in one text -> same token, different value -> different token
    out = r1.redact_text("bob@example.com bob@example.com carol@example.com").split()
    assert out[0] == out[1] != out[2]


def test_pseudonym_case_insensitive_email():
    r = mk(mode="pseudonymize", key=b"k1")
    assert r.redact_text("Bob@Example.com") == r.redact_text("bob@example.com")


def test_pseudonym_depends_on_key():
    a = mk(mode="pseudonymize", key=b"key-one").redact_text("bob@example.com")
    b = mk(mode="pseudonymize", key=b"key-two").redact_text("bob@example.com")
    assert a != b


def test_pseudonym_needs_key():
    with pytest.raises(ValueError):
        mk(mode="pseudonymize")


def test_pseudonym_phone_normalised():
    r = mk(mode="pseudonymize", key=b"k")
    assert r.redact_text("613-555-0142") == r.redact_text("(613) 555.0142".replace("(613) ", "613-"))


def test_json_string_values_recursive():
    r = mk()
    line = json.dumps({"msg": "hi bob@example.com", "n": 5,
                       "deep": {"list": ["203.0.113.9", {"x": "ok"}]}})
    out = json.loads(r.redact_line(line))
    assert out["msg"] == "hi [EMAIL]"
    assert out["n"] == 5
    assert out["deep"]["list"] == ["[IPV4]", {"x": "ok"}]


def test_json_key_paths():
    r = mk(json_keys=["user.email", "headers.authorization", "secrets",
                          "list.user.email"])
    line = json.dumps({
        "user": {"email": "x", "name": "Bob"},
        "email": "top-level-not-matched",
        "headers": {"Authorization": "Basic Zm9vOmJhcg==", "accept": "*/*"},
        "secrets": {"a": 1, "b": [2, 3]},
        "list": [{"user": {"email": "y"}}],
    })
    out = json.loads(r.redact_line(line))
    assert out["user"] == {"email": "[JSON_KEY]", "name": "Bob"}
    assert out["email"] == "top-level-not-matched"
    assert out["headers"]["Authorization"] == "[JSON_KEY]"
    assert out["headers"]["accept"] == "*/*"
    assert out["secrets"] == "[JSON_KEY]"
    # arrays are transparent in the path
    assert out["list"][0]["user"]["email"] == "[JSON_KEY]"
    assert r.report()["by_type"]["json_key"] == 4


def test_json_key_pseudonymized_is_deterministic():
    r = mk(mode="pseudonymize", key=b"k", json_keys=["user.email"])
    a = json.loads(r.redact_line('{"user": {"email": "same"}}'))["user"]["email"]
    b = json.loads(r.redact_line('{"user": {"email": "same"}}'))["user"]["email"]
    c = json.loads(r.redact_line('{"user": {"email": "other"}}'))["user"]["email"]
    assert a == b != c and a.startswith("JSON_KEY_")


def test_json_untouched_line_kept_verbatim():
    r = mk()
    line = '{"a":   1,  "b": "fine"}'
    assert r.redact_line(line) == line


def test_non_json_falls_back_to_text():
    r = mk()
    assert r.redact_line("{not json bob@example.com") == "{not json [EMAIL]"
    assert r.redact_line("[INFO] bob@example.com") == "[INFO] [EMAIL]"


def test_no_json_mode():
    r = mk(json_mode=False, json_keys=["a"])
    out = r.redact_line('{"a": "x", "m": "bob@example.com"}')
    assert '"a": "x"' in out and "[EMAIL]" in out


def test_report_counts_only_no_values():
    r = mk()
    r.redact_line("bob@example.com and carol@example.com from 192.0.2.5")
    rep = r.report()
    assert rep["by_type"] == {"email": 2, "ipv4": 1}
    assert rep["total"] == 3 and rep["lines_with_redactions"] == 1
    blob = json.dumps(rep)
    assert "example.com" not in blob and "192.0.2" not in blob


def test_eol_preserved():
    r = mk()
    out = list(r.redact_lines(["a@example.com\r\n", "b@example.com\n", "c@example.com"]))
    assert out == ["[EMAIL]\r\n", "[EMAIL]\n", "[EMAIL]"]
