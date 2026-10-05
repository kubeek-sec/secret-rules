"""Verifiers needing JSON interpretation, companion inputs, or request signing.

Still strictly read-only: identity / auth-test / caller-identity endpoints only.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import re

from ..core import (
    ACTIVE,
    INACTIVE,
    SKIPPED,
    UNKNOWN,
    HttpClient,
    Result,
    http_check,
    register,
)

# --------------------------------------------------------------------------- #
# Slack — auth.test (read-only; identifies the token's team/user)
# --------------------------------------------------------------------------- #


def _slack_json(code, j, body):
    if j is None:
        return UNKNOWN, f"non-JSON response (HTTP {code})", None
    if j.get("ok"):
        return ACTIVE, "token valid", {
            "team": j.get("team"), "user": j.get("user"), "url": j.get("url")}
    err = j.get("error", "unknown")
    # these errors mean "the token itself is not usable"
    if err in {"invalid_auth", "not_authed", "account_inactive", "token_revoked",
               "token_expired", "no_permission"}:
        return INACTIVE, f"rejected: {err}", None
    return UNKNOWN, f"inconclusive: {err}", None


register("slack", sniff=r"\bxox[baprs]-[A-Za-z0-9-]{10,}",
         doc="POST slack.com/api/auth.test")(
    http_check(
        "slack", "https://slack.com/api/auth.test",
        auth="bearer", method="POST",
        body="", content_type="application/x-www-form-urlencoded",
        json_active=_slack_json,
    )
)

# --------------------------------------------------------------------------- #
# Stripe — GET /v1/account (read-only). Key prefix tells test vs live.
# --------------------------------------------------------------------------- #


def _stripe_identity(j):
    if not j:
        return None
    return {"account_id": j.get("id"), "country": j.get("country"),
            "livemode": j.get("charges_enabled") is not None}


@register("stripe", sniff=r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}",
          doc="GET api.stripe.com/v1/account")
def stripe(secret: str, extra: dict, http: HttpClient) -> Result:
    mode = "live" if "_live_" in secret else "test" if "_test_" in secret else "?"
    fn = http_check(
        "stripe", "https://api.stripe.com/v1/account",
        auth="basic-secret", inactive=(401,),
        identity=_stripe_identity,
    )
    res = fn(secret, extra, http)
    if res.status == ACTIVE:
        res.detail = f"credential accepted ({mode} mode)"
        res.identity = (res.identity or {}) | {"mode": mode}
    return res


# --------------------------------------------------------------------------- #
# Linear — GraphQL viewer query (read-only)
# --------------------------------------------------------------------------- #


def _linear_json(code, j, body):
    if j is None:
        return UNKNOWN, f"non-JSON response (HTTP {code})", None
    viewer = (j.get("data") or {}).get("viewer")
    if viewer:
        return ACTIVE, "token valid", {"id": viewer.get("id"), "name": viewer.get("name")}
    if code in (400, 401, 403) or j.get("errors"):
        return INACTIVE, "rejected by Linear API", None
    return UNKNOWN, f"inconclusive (HTTP {code})", None


register("linear", sniff=r"\blin_(api|oauth)_[A-Za-z0-9]{40,}",
         doc="POST api.linear.app/graphql { viewer }")(
    http_check(
        "linear", "https://api.linear.app/graphql",
        auth="header", header_name="Authorization",
        method="POST", content_type="application/json",
        body='{"query":"{ viewer { id name } }"}',
        json_active=_linear_json,
    )
)

# --------------------------------------------------------------------------- #
# Cloudflare — token-verify endpoint, or global key + account email
# --------------------------------------------------------------------------- #


def _cf_token_json(code, j, body):
    if j is None:
        return UNKNOWN, f"non-JSON response (HTTP {code})", None
    if j.get("success") and (j.get("result") or {}).get("status") == "active":
        return ACTIVE, "API token active", {"id": (j.get("result") or {}).get("id")}
    if code in (401, 403) or j.get("success") is False:
        return INACTIVE, "token not active", None
    return UNKNOWN, f"inconclusive (HTTP {code})", None


@register(
    "cloudflare",
    sniff=r"\bv1\.0-[A-Za-z0-9_-]{40,}",
    companion_help={"id": "account email — only for a *global* API key (X-Auth-Key)"},
    doc="GET api.cloudflare.com user/tokens/verify (token) or user (global key)",
)
def cloudflare(secret: str, extra: dict, http: HttpClient) -> Result:
    email = extra.get("id")
    if email:
        # Global API key: authenticate against the user endpoint with the email.
        resp = http.request(
            "GET", "https://api.cloudflare.com/client/v4/user",
            headers={"X-Auth-Email": email, "X-Auth-Key": secret},
        )
        if resp.dry_run:
            return Result("cloudflare", "planned",
                          endpoint="https://api.cloudflare.com/client/v4/user")
        if resp.status is None:
            return Result("cloudflare", UNKNOWN, detail=f"transport error: {resp.error}")
        j = resp.json() or {}
        if resp.status == 200 and j.get("success"):
            res = (j.get("result") or {})
            return Result("cloudflare", ACTIVE, detail="global API key accepted",
                          identity={"email": res.get("email"), "id": res.get("id")},
                          http_status=200)
        return Result("cloudflare", INACTIVE, detail=f"rejected (HTTP {resp.status})",
                      http_status=resp.status)
    # API token: use the dedicated verify endpoint.
    fn = http_check(
        "cloudflare", "https://api.cloudflare.com/client/v4/user/tokens/verify",
        auth="bearer", json_active=_cf_token_json,
    )
    return fn(secret, extra, http)


# --------------------------------------------------------------------------- #
# Twilio — needs Account SID (companion) + Auth Token (secret)
# --------------------------------------------------------------------------- #


@register(
    "twilio",
    needs=("id",),
    companion_help={"id": "Account SID (starts with AC...)"},
    doc="GET api.twilio.com/2010-04-01/Accounts/<SID>.json",
)
def twilio(secret: str, extra: dict, http: HttpClient) -> Result:
    sid = extra.get("id", "")
    if not sid.startswith("AC"):
        return Result("twilio", SKIPPED,
                      detail="needs --id <Account SID starting with AC...>")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json"
    resp = http.request("GET", url, basic_auth=(sid, secret))
    if resp.dry_run:
        return Result("twilio", "planned", endpoint=url)
    if resp.status is None:
        return Result("twilio", UNKNOWN, detail=f"transport error: {resp.error}")
    j = resp.json() or {}
    if resp.status == 200:
        return Result("twilio", ACTIVE, detail="credential accepted",
                      identity={"friendly_name": j.get("friendly_name"),
                                "status": j.get("status")}, http_status=200, endpoint=url)
    if resp.status in (401,):
        return Result("twilio", INACTIVE, detail="rejected (HTTP 401)", http_status=401, endpoint=url)
    return Result("twilio", UNKNOWN, detail=f"unexpected response (HTTP {resp.status})",
                  http_status=resp.status, endpoint=url)


# --------------------------------------------------------------------------- #
# Mailgun — GET /v3/domains (read-only list)
# --------------------------------------------------------------------------- #


@register("mailgun", sniff=r"\bkey-[0-9a-f]{32}", doc="GET api.mailgun.net/v3/domains")
def mailgun(secret: str, extra: dict, http: HttpClient) -> Result:
    url = "https://api.mailgun.net/v3/domains?limit=1"
    resp = http.request("GET", url, basic_auth=("api", secret))
    if resp.dry_run:
        return Result("mailgun", "planned", endpoint=url)
    if resp.status is None:
        return Result("mailgun", UNKNOWN, detail=f"transport error: {resp.error}")
    if resp.status == 200:
        j = resp.json() or {}
        return Result("mailgun", ACTIVE, detail="credential accepted",
                      identity={"domains": j.get("total_count")}, http_status=200, endpoint=url)
    if resp.status in (401,):
        return Result("mailgun", INACTIVE, detail="rejected (HTTP 401)", http_status=401, endpoint=url)
    return Result("mailgun", UNKNOWN, detail=f"unexpected response (HTTP {resp.status})",
                  http_status=resp.status, endpoint=url)


# --------------------------------------------------------------------------- #
# Atlassian (Jira / Confluence) — self-hosted or Cloud
#   Cloud:      email + API token via HTTP basic  (pass --id <email>)
#   Server/DC:  personal access token as a bearer token
# Both need the site URL via --base-url.
# --------------------------------------------------------------------------- #


def _atlassian(topic: str, secret: str, cloud_path: str, server_path: str,
               extra: dict, http: HttpClient) -> Result:
    base = extra.get("endpoint")
    if not base:
        return Result(topic, SKIPPED,
                      detail="pass --base-url (Cloud: https://<you>.atlassian.net, "
                             "Server/DC: your site URL)")
    base = base.rstrip("/")
    email = extra.get("id")
    cloud = bool(email) or base.endswith(".atlassian.net")
    url = base + (cloud_path if cloud else server_path)
    if email:  # Cloud: email + API token via basic auth
        resp = http.request("GET", url, basic_auth=(email, secret))
    else:      # Server/DC: personal access token as bearer
        resp = http.request("GET", url, headers={"Authorization": f"Bearer {secret}"})
    if resp.dry_run:
        return Result(topic, "planned", endpoint=url)
    if resp.status is None:
        return Result(topic, UNKNOWN, detail=f"transport error: {resp.error}")
    if resp.status == 200:
        j = resp.json() or {}
        return Result(topic, ACTIVE, detail="credential accepted",
                      identity={"account": j.get("displayName") or j.get("name"),
                                "email": j.get("emailAddress")}, http_status=200, endpoint=url)
    if resp.status in (401, 403):
        return Result(topic, INACTIVE, detail=f"rejected (HTTP {resp.status})",
                      http_status=resp.status, endpoint=url)
    return Result(topic, UNKNOWN, detail=f"unexpected response (HTTP {resp.status})",
                  http_status=resp.status, endpoint=url)


@register("jira", companion_help={"id": "account email (Jira Cloud basic auth)"},
          endpoint=True, doc="GET <site>/rest/api/3/myself (Cloud or Server/DC)")
def jira(secret: str, extra: dict, http: HttpClient) -> Result:
    return _atlassian("jira", secret, "/rest/api/3/myself", "/rest/api/2/myself", extra, http)


@register("confluence", companion_help={"id": "account email (Confluence Cloud basic auth)"},
          endpoint=True, doc="GET <site>/wiki/rest/api/user/current (Cloud or Server/DC)")
def confluence(secret: str, extra: dict, http: HttpClient) -> Result:
    return _atlassian("confluence", secret, "/wiki/rest/api/user/current",
                      "/rest/api/user/current", extra, http)


# --------------------------------------------------------------------------- #
# AWS — STS GetCallerIdentity, signed with SigV4 (read-only, no side effects)
# --------------------------------------------------------------------------- #

_AWS_REGION = "us-east-1"
_AWS_SERVICE = "sts"
_AWS_HOST = "sts.amazonaws.com"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


@register(
    "aws",
    needs=("id",),
    sniff=r"\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
    companion_help={
        "id": "AWS Access Key ID (AKIA.../ASIA...)",
        "session_token": "session token (required for temporary ASIA... keys)",
    },
    doc="POST sts.amazonaws.com GetCallerIdentity (SigV4)",
)
def aws(secret: str, extra: dict, http: HttpClient) -> Result:
    access_key = extra.get("id", "")
    session_token = extra.get("session_token")
    if not access_key:
        return Result("aws", SKIPPED,
                      detail="needs --id <AWS Access Key ID>; --secret is the Secret Access Key")
    if access_key.startswith("ASIA") and not session_token:
        return Result("aws", SKIPPED,
                      detail="temporary ASIA... key needs --field session_token=<token>")

    now = _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload = "Action=GetCallerIdentity&Version=2011-06-15"
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()
    content_type = "application/x-www-form-urlencoded; charset=utf-8"

    headers = {
        "content-type": content_type,
        "host": _AWS_HOST,
        "x-amz-date": amz_date,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    canonical_request = "\n".join([
        "POST", "/", "", canonical_headers, signed_headers, payload_hash,
    ])

    scope = f"{date_stamp}/{_AWS_REGION}/{_AWS_SERVICE}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    k_date = _sign(("AWS4" + secret).encode(), date_stamp)
    k_region = _sign(k_date, _AWS_REGION)
    k_service = _sign(k_region, _AWS_SERVICE)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    req_headers = {
        "Content-Type": content_type,
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
        "Accept": "application/json",
    }
    if session_token:
        req_headers["X-Amz-Security-Token"] = session_token

    url = f"https://{_AWS_HOST}/"
    resp = http.request("POST", url, headers=req_headers, data=payload)
    if resp.dry_run:
        return Result("aws", "planned", endpoint=url)
    if resp.status is None:
        return Result("aws", UNKNOWN, detail=f"transport error: {resp.error}")
    if resp.status == 200:
        # The STS query API answers in XML; scrape the identity fields.
        account = re.search(r"<Account>([^<]+)</Account>", resp.body)
        arn = re.search(r"<Arn>([^<]+)</Arn>", resp.body)
        ident = {
            "account": account.group(1) if account else None,
            "arn": arn.group(1) if arn else None,
        }
        return Result("aws", ACTIVE, detail="credential accepted (GetCallerIdentity)",
                      identity=ident, http_status=200, endpoint=url)
    if resp.status in (403,):
        return Result("aws", INACTIVE, detail="rejected (HTTP 403 — invalid/expired key)",
                      http_status=403, endpoint=url)
    return Result("aws", UNKNOWN, detail=f"unexpected response (HTTP {resp.status})",
                  http_status=resp.status, endpoint=url)
