"""Offline tests for the verify/ package (no network)."""

from __future__ import annotations

import verify  # noqa: F401  (registers verifiers + rotators)
from verify.core import (
    ACTIVE,
    INACTIVE,
    INVALID_MATERIAL,
    LOCALLY_DERIVED,
    ROTATORS,
    SKIPPED,
    UNKNOWN,
    VERIFIERS,
    HttpClient,
    Response,
    fingerprint,
    sniff_topic,
)
from verify.sinks import write_sink
from verify.verifiers import custom


class FakeHttp:
    """Stands in for HttpClient; returns canned responses, records calls."""

    def __init__(self, responder):
        self.calls = []
        self._responder = responder

    def request(self, method, url, *, headers=None, data=None, basic_auth=None):
        self.calls.append((method, url, headers, data, basic_auth))
        return self._responder(method, url, headers, data, basic_auth)


# --- registry -------------------------------------------------------------- #

def test_core_topics_registered():
    for topic in ("github", "aws", "slack", "stripe", "openai", "twilio"):
        assert topic in VERIFIERS
        assert topic in ROTATORS


def test_sniff_detects_shapes():
    assert sniff_topic("ghp_" + "a" * 36) == ["github"]
    assert sniff_topic("xoxb-123456789-abcdefghij") == ["slack"]
    assert sniff_topic("not-a-known-secret") == []


# --- generic http verifier ------------------------------------------------- #

def _run(topic, status=None, body="", error=None, extra=None):
    resp = Response(status=status, body=body, error=error)
    http = FakeHttp(lambda *a: resp)
    return VERIFIERS[topic].func("the-secret", extra or {}, http), http


def test_github_active_inactive_unknown():
    res, _ = _run("github", status=200, body='{"login":"octocat","id":1}')
    assert res.status == ACTIVE and res.identity["login"] == "octocat"

    res, _ = _run("github", status=401)
    assert res.status == INACTIVE

    res, _ = _run("github", status=None, error="timed out")
    assert res.status == UNKNOWN


def test_github_403_is_unknown_not_inactive():
    # 403 from /user is rate limiting, not a bad credential
    res, _ = _run("github", status=403)
    assert res.status == UNKNOWN


# --- json-interpreted verifiers -------------------------------------------- #

def test_slack_ok_flag():
    res, _ = _run("slack", status=200, body='{"ok":true,"team":"T1","user":"U1"}')
    assert res.status == ACTIVE and res.identity["team"] == "T1"

    res, _ = _run("slack", status=200, body='{"ok":false,"error":"invalid_auth"}')
    assert res.status == INACTIVE


def test_stripe_reports_mode():
    http = FakeHttp(lambda *a: Response(status=200, body='{"id":"acct_1","country":"US"}'))
    res = custom.stripe("sk_live_abc", {}, http)
    assert res.status == ACTIVE and res.identity["mode"] == "live"


# --- multi-part credentials ------------------------------------------------ #

def test_twilio_requires_sid():
    res, _ = _run("twilio", status=200)  # no --id
    assert res.status == SKIPPED

    http = FakeHttp(lambda *a: Response(status=200, body='{"friendly_name":"x","status":"active"}'))
    res = VERIFIERS["twilio"].func("token", {"id": "AC123"}, http)
    assert res.status == ACTIVE
    # verified via basic auth, SID as username
    assert http.calls[0][4] == ("AC123", "token")


def test_aws_requires_access_key_id():
    res, _ = _run("aws", status=200)
    assert res.status == SKIPPED


def test_aws_sigv4_known_signing_key():
    """Reproduce AWS's documented signing-key derivation test vector."""
    secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    k_date = custom._sign(("AWS4" + secret).encode(), "20120215")
    k_region = custom._sign(k_date, "us-east-1")
    k_service = custom._sign(k_region, "iam")
    k_signing = custom._sign(k_service, "aws4_request")
    assert k_signing.hex() == "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"


def test_aws_signs_and_posts_to_sts():
    http = FakeHttp(lambda *a: Response(
        status=200,
        body="<Arn>arn:aws:iam::123:user/x</Arn><Account>123</Account>",
    ))
    res = VERIFIERS["aws"].func("secretkey", {"id": "AKIA" + "A" * 16}, http)
    assert res.status == ACTIVE
    assert res.identity["account"] == "123"
    method, url, headers, data, _ = http.calls[0]
    assert method == "POST" and url == "https://sts.amazonaws.com/"
    assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIA")


# --- rotation self-revoke -------------------------------------------------- #

def test_slack_self_revoke():
    rot = ROTATORS["slack"]
    http = FakeHttp(lambda *a: Response(status=200, body='{"ok":true,"revoked":true}'))
    res = rot.self_revoke("xoxb-x", {}, http)
    assert res.status == "revoked"
    assert http.calls[0][1] == "https://slack.com/api/auth.revoke"


# --- sinks ----------------------------------------------------------------- #

def test_dotenv_sink_upsert(tmp_path):
    env = tmp_path / ".env"
    env.write_text("OTHER=keep\nTOKEN=old\n")
    write_sink(f"dotenv:{env}#TOKEN", "new", show=False)
    text = env.read_text()
    assert "TOKEN=new" in text and "OTHER=keep" in text and "TOKEN=old" not in text


def test_file_sink(tmp_path):
    out = tmp_path / "secret.txt"
    write_sink(f"file:{out}", "value123")
    assert out.read_text() == "value123"


def test_fingerprint_masks():
    fp = fingerprint("ghp_abcdefghijklmnop")
    assert fp.startswith("ghp_") and "…" in fp and "klmnop" not in fp


# --- strength (entropy + generation) --------------------------------------- #

def test_generate_length_and_charset():
    from verify import strength
    v = strength.generate(length=40, charset="hex")
    assert len(v) == 40 and all(c in "0123456789abcdef" for c in v)


def test_generate_by_bits_is_strong():
    from verify import strength
    v = strength.generate(bits=256, charset="base62")
    # 256 bits over a 62-symbol alphabet needs ceil(256/log2(62)) = 43 chars
    assert len(v) == 43
    assert strength.estimated_bits(v) >= 256


def test_generate_rejects_unknown_charset():
    import pytest
    from verify import strength
    with pytest.raises(ValueError):
        strength.generate(length=10, charset="nope")


def test_entropy_classification_and_monotonic():
    from verify import strength
    assert strength.classify(10)[0] == "very weak"
    assert strength.classify(200)[0] == "very strong"
    weak = strength.estimated_bits("aaaa")
    strong = strength.estimated_bits("aB3$xY9!kLmN")
    assert strong > weak


# --- self-mint rotators ---------------------------------------------------- #

def test_self_mint_rotators_present():
    for topic in ("jwt", "django", "rails", "generic"):
        rot = ROTATORS[topic]
        assert rot.mint == "self"
        assert rot.gen_spec  # has generation hints


# --- ledger ---------------------------------------------------------------- #

def test_ledger_records_fingerprints_only_by_default(tmp_path):
    import json
    from verify import ledger
    path = tmp_path / "led.jsonl"
    ledger.record(path, action="rotate", topic="jwt", old_secret="oldsecretvalue",
                  new_secret="newsecretvalue", generated=True, new_entropy_bits=256.0)
    entry = json.loads(path.read_text().splitlines()[0])
    assert entry["topic"] == "jwt" and entry["generated"] is True
    assert "new_secret" not in entry             # no plaintext by default
    assert "…" in entry["new_fingerprint"]
    assert oct(path.stat().st_mode)[-3:] == "600"


def test_ledger_record_secret_opt_in(tmp_path):
    import json
    from verify import ledger
    path = tmp_path / "led.jsonl"
    ledger.record(path, action="update", topic="generic",
                  new_secret="theNewValue", record_secret=True)
    entry = json.loads(path.read_text().splitlines()[0])
    assert entry["new_secret"] == "theNewValue"


# --- self-hosted endpoint overrides ---------------------------------------- #

def test_endpoint_override_changes_host():
    seen = {}

    def responder(method, url, headers, data, basic_auth):
        seen["url"] = url
        return Response(status=200, body='{"username":"x","id":1}')

    http = FakeHttp(responder)
    VERIFIERS["gitlab"].func("glpat-x", {"endpoint": "https://gitlab.corp"}, http)
    assert seen["url"] == "https://gitlab.corp/api/v4/user"


def test_require_endpoint_skips_without_base_url():
    res, _ = _run("artifactory", status=200)  # no endpoint
    assert res.status == SKIPPED
    assert "base-url" in res.detail


def test_self_hostable_topics_marked():
    for topic in ("github", "gitlab", "gitea", "datadog", "sentry", "artifactory",
                  "grafana", "jira", "confluence"):
        assert VERIFIERS[topic].endpoint is True


# --- offline (network-free) validators ------------------------------------- #

def _offline(topic, secret):
    # offline validators ignore the http client entirely
    return VERIFIERS[topic].func(secret, {}, FakeHttp(lambda *a: Response(status=None)))


def test_jwt_expired_is_inactive():
    # exp = 1516239022 (2018) -> expired
    tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIiwiZXhwIjoxNTE2MjM5MDIyfQ.sig"
    res = _offline("jwt", tok)
    assert res.status == INACTIVE and "expired" in res.detail


def test_jwt_without_exp_is_locally_derived():
    tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIiwiaXNzIjoiYWNtZSJ9.sig"
    res = _offline("jwt", tok)
    assert res.status == LOCALLY_DERIVED and res.identity["alg"] == "HS256"


def test_jwt_garbage_is_invalid_material():
    assert _offline("jwt", "not-a-jwt").status == INVALID_MATERIAL
    assert _offline("jwt", "aaa.bbb.ccc").status == INVALID_MATERIAL


def test_private_key_structure():
    import base64
    body = base64.b64encode(b"\x00" * 64).decode()  # valid base64, 64 bytes DER
    pem = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"
    res = _offline("private", pem)
    assert res.status == LOCALLY_DERIVED and res.identity["kind"] == "OpenSSH"

    assert _offline("private", "not a key").status == INVALID_MATERIAL


def test_jwt_not_before_is_inactive():
    import base64 as b64
    import json as _json
    future = 9999999999  # year 2286
    hdr = b64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    pl = b64.urlsafe_b64encode(_json.dumps({"nbf": future}).encode()).decode().rstrip("=")
    res = _offline("jwt", f"{hdr}.{pl}.sig")
    assert res.status == INACTIVE and "not valid before" in res.detail


def test_jwt_alg_none_flagged():
    res = _offline("jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.")
    assert res.status == LOCALLY_DERIVED and res.identity["alg"] == "none"
    assert "alg=none" in res.detail


# --- credential URIs (DB connection strings) ------------------------------- #

def test_credential_uri_with_password():
    res = _offline("postgres", "postgres://u:pw@db.corp:5432/app")
    assert res.status == LOCALLY_DERIVED
    assert res.identity["host"] == "db.corp" and res.identity["port"] == 5432


def test_credential_uri_percent_decoded():
    res = _offline("mongodb", "mongodb+srv://user:p%40ss@c0.x.mongodb.net/db")
    assert res.status == LOCALLY_DERIVED and res.identity["scheme"] == "mongodb+srv"


def test_credential_uri_jdbc_query_creds():
    res = _offline("jdbc", "jdbc:mysql://h:3306/a?user=root&password=rootpw")
    assert res.status == LOCALLY_DERIVED and res.identity["user"] == "root"


def test_credential_uri_non_uri_is_unsupported():
    from verify.core import UNSUPPORTED
    res = _offline("mongodb", "just-an-api-key-not-a-uri")
    assert res.status == UNSUPPORTED


# --- TruffleHog-sourced providers ------------------------------------------ #

def test_new_providers_registered():
    for t in ("asana", "vercel", "twitter", "doppler", "supabase", "square", "mapbox",
              "shopify", "sourcegraph", "mattermost", "databricks", "posthog", "zendesk",
              "bitbucket", "sumologic", "planetscale", "discord", "newrelic"):
        assert t in VERIFIERS


def _capture():
    seen = {}

    def responder(method, url, headers, data, basic_auth):
        seen.update(method=method, url=url, headers=headers or {},
                    data=data, basic_auth=basic_auth)
        return Response(status=seen.pop("_status", 200), body=seen.pop("_body", "{}"))
    return seen, responder


def test_bitbucket_basic_auth_and_403_active():
    seen, responder = _capture()
    seen["_status"] = 403  # valid key, insufficient scope -> still active
    res = VERIFIERS["bitbucket"].func("app-pw", {"id": "alice"}, FakeHttp(responder))
    assert res.status == ACTIVE
    assert seen["basic_auth"] == ("alice", "app-pw")


def test_square_403_active_401_inactive():
    seen, responder = _capture()
    seen["_status"] = 403
    assert VERIFIERS["square"].func("EAAA", {}, FakeHttp(responder)).status == ACTIVE
    seen2, responder2 = _capture()
    seen2["_status"] = 401
    assert VERIFIERS["square"].func("EAAA", {}, FakeHttp(responder2)).status == INACTIVE


def test_planetscale_literal_authorization_header():
    seen, responder = _capture()
    VERIFIERS["planetscale"].func("pscale_tkn_x", {"id": "tokid"}, FakeHttp(responder))
    assert seen["headers"]["Authorization"] == "tokid:pscale_tkn_x"  # not Bearer/Basic


def test_newrelic_api_key_header_post():
    seen, responder = _capture()
    VERIFIERS["newrelic"].func("NRAK-xyz", {}, FakeHttp(responder))
    assert seen["method"] == "POST" and seen["headers"]["API-Key"] == "NRAK-xyz"


def test_zendesk_email_token_basic_and_needs():
    # needs id -> _verify (not tested here) returns SKIPPED; the func needs endpoint
    res = VERIFIERS["zendesk"].func("tok", {"id": "me@x.com"},
                                    FakeHttp(lambda *a: Response(status=200)))
    assert res.status == SKIPPED  # no endpoint
    seen, responder = _capture()
    VERIFIERS["zendesk"].func("tok", {"id": "me@x.com", "endpoint": "https://acme.zendesk.com"},
                              FakeHttp(responder))
    assert seen["basic_auth"] == ("me@x.com/token", "tok")


def test_mapbox_id_in_path_and_secret_not_leaked():
    seen, responder = _capture()
    res = VERIFIERS["mapbox"].func("sk.SECRET", {"id": "acct"}, FakeHttp(responder))
    assert res.status == ACTIVE
    assert "acct" in seen["url"] and "access_token=sk.SECRET" in seen["url"]  # on the wire
    assert "SECRET" not in res.endpoint and "<redacted>" in res.endpoint      # not in report


def test_posthog_query_param():
    seen, responder = _capture()
    VERIFIERS["posthog"].func("phx_key", {}, FakeHttp(responder))
    assert "personal_api_key=phx_key" in seen["url"]


def test_require_endpoint_skips():
    for t in ("shopify", "mattermost", "databricks"):
        res = VERIFIERS[t].func("secret", {}, FakeHttp(lambda *a: Response(status=200)))
        assert res.status == SKIPPED


# --- HttpClient options ---------------------------------------------------- #

def test_httpclient_accepts_insecure_and_rps():
    c = HttpClient(insecure=True, rps=5)
    assert c._min_interval == 0.2
