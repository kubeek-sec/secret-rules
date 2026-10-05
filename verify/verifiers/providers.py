"""Additional read-only verifiers, each grounded in TruffleHog's detector source
(github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors).

Every endpoint here is the identity / current-user / stats / scopes call that
the corresponding TruffleHog detector uses to prove a credential is live — i.e.
strictly read-only.  Self-hosted / per-instance providers accept ``--base-url``
(marked ``endpoint=True``); multi-part credentials declare ``needs``.
"""

from __future__ import annotations

import urllib.parse

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

_2XX = tuple(range(200, 300))  # several detectors treat any 2xx as "valid"


def _interpret(topic, resp, url, active, inactive):
    """Shared status interpretation for the custom verifiers below."""
    if resp.dry_run:
        return Result(topic, "planned", endpoint=url)
    if resp.status is None:
        return Result(topic, UNKNOWN, detail=f"transport error: {resp.error}", endpoint=url)
    if resp.status == 429:
        return Result(topic, UNKNOWN, detail="rate limited (HTTP 429)", http_status=429,
                      endpoint=url)
    if resp.status in active:
        return Result(topic, ACTIVE, detail="credential accepted", http_status=resp.status,
                      endpoint=url)
    if resp.status in inactive:
        return Result(topic, INACTIVE, detail=f"rejected (HTTP {resp.status})",
                      http_status=resp.status, endpoint=url)
    return Result(topic, UNKNOWN, detail=f"unexpected response (HTTP {resp.status})",
                  http_status=resp.status, endpoint=url)


# --------------------------------------------------------------------------- #
# Group A — simple single-token APIs
# --------------------------------------------------------------------------- #

register("asana", doc="GET app.asana.com/api/1.0/users/me")(http_check(
    "asana", "https://app.asana.com", "/api/1.0/users/me",
    auth="bearer", active=(200,), inactive=(401,),
))

register("vercel", doc="GET api.vercel.com/www/user")(http_check(
    "vercel", "https://api.vercel.com", "/www/user",
    auth="bearer", active=_2XX, inactive=(401, 403),
))

register("doppler", sniff=r"\bdp\.(pt|st|ct|sa|scim)\.[A-Za-z0-9]{40,}",
         doc="GET api.doppler.com/v3/me")(http_check(
    "doppler", "https://api.doppler.com", "/v3/me",
    auth="bearer", extra_headers={"Accept": "application/json"},
    active=_2XX, inactive=(401,),
))

register("twitter", doc="GET api.twitter.com/2/tweets/20 (bearer token)")(http_check(
    "twitter", "https://api.twitter.com", "/2/tweets/20",
    auth="bearer", active=(200,), inactive=(401,),
))

register("supabase", sniff=r"\bsbp_[a-f0-9]{40}",
         doc="GET api.supabase.com/v1/projects (management token)")(http_check(
    "supabase", "https://api.supabase.com", "/v1/projects",
    auth="bearer", active=_2XX, inactive=(401, 403),
))

# Square — TruffleHog hits the sandbox host; we default to production and allow
# an override. 403 = valid key missing a scope, still a live credential.
register("square", sniff=r"\bEAAA[A-Za-z0-9\-_+=]{60}", endpoint=True,
         doc="GET connect.squareup.com/v2/merchants (sandbox via --base-url)")(http_check(
    "square", "https://connect.squareup.com", "/v2/merchants",
    auth="bearer", extra_headers={"Content-Type": "application/json"},
    active=(200, 403), inactive=(401,),
))


@register("mapbox", needs=("id",),
          companion_help={"id": "Mapbox account/username"},
          doc="GET api.mapbox.com/tokens/v2/<id>?access_token=<secret>")
def mapbox(secret: str, extra: dict, http: HttpClient) -> Result:
    acct = extra["id"]
    base = f"https://api.mapbox.com/tokens/v2/{urllib.parse.quote(acct, safe='')}"
    display = f"{base}?access_token=<redacted>"
    url = f"{base}?access_token={urllib.parse.quote(secret, safe='')}"
    resp = http.request("GET", url)
    return _interpret("mapbox", resp, display, active=_2XX, inactive=(401, 403))


# --------------------------------------------------------------------------- #
# Group B — self-hosted / per-instance / multi-part
# --------------------------------------------------------------------------- #

# Shopify — GET https://<store>.myshopify.com/admin/oauth/access_scopes.json
register(
    "shopify",
    sniff=r"\bshp(at|pa|ca|ss)_[0-9A-Fa-f]{32}",
    endpoint=True,
    companion_help={"endpoint": "store URL, e.g. https://<shop>.myshopify.com"},
    doc="GET <store>/admin/oauth/access_scopes.json",
)(http_check(
    "shopify", "", "/admin/oauth/access_scopes.json",
    auth="header", header_name="X-Shopify-Access-Token",
    active=_2XX, inactive=(401, 402, 403, 404), require_endpoint=True,
))

# Sourcegraph — POST /.api/graphql { currentUser { username } }
register(
    "sourcegraph",
    sniff=r"\bsgp_(?:[0-9a-f]{16,}_)?[0-9a-f]{40}",
    endpoint=True,
    doc="POST sourcegraph.com/.api/graphql (self-hostable)",
)(http_check(
    "sourcegraph", "https://sourcegraph.com", "/.api/graphql",
    auth="header", header_name="Authorization", prefix="token ",
    method="POST", content_type="application/json",
    body='{"query":"query { currentUser { username } }"}',
    active=_2XX, inactive=(401,),
))

# Mattermost personal access token — GET <host>/api/v4/users/stats
register(
    "mattermost",
    endpoint=True,
    companion_help={"endpoint": "server URL, e.g. https://<host>.cloud.mattermost.com"},
    doc="GET <host>/api/v4/users/stats (self-hosted — needs --base-url)",
)(http_check(
    "mattermost", "", "/api/v4/users/stats",
    auth="bearer", active=_2XX, inactive=(401, 403), require_endpoint=True,
))

# Databricks token — GET <workspace>/api/2.0/preview/scim/v2/Me
register(
    "databricks",
    sniff=r"\bdapi[0-9a-f]{32}(-\d)?",
    endpoint=True,
    companion_help={"endpoint": "workspace URL, e.g. https://<x>.cloud.databricks.com"},
    doc="GET <workspace>/api/2.0/preview/scim/v2/Me (needs --base-url)",
)(http_check(
    "databricks", "", "/api/2.0/preview/scim/v2/Me",
    auth="bearer", active=(200,), inactive=(401, 403), require_endpoint=True,
))

# PostHog personal API key — GET app.posthog.com/api/event/?personal_api_key=<key>
register(
    "posthog",
    sniff=r"\bphx_[A-Za-z0-9_]{43,48}",
    endpoint=True,
    doc="GET app.posthog.com/api/event/ (EU/self-host via --base-url)",
)(http_check(
    "posthog", "https://app.posthog.com", "/api/event/",
    auth="query", query_param="personal_api_key",
    extra_headers={"Content-Type": "application/json"},
    active=_2XX, inactive=(401,),
))

# New Relic user key — POST /graphql with API-Key header (US default, EU via --base-url)
register(
    "newrelic",
    sniff=r"\bNRAK-[A-Z0-9]{27}",
    endpoint=True,
    doc="POST api.newrelic.com/graphql (EU via --base-url)",
)(http_check(
    "newrelic", "https://api.newrelic.com", "/graphql",
    auth="header", header_name="API-Key", method="POST",
    content_type="application/json",
    body='{"query":"{ requestContext { userId } }"}',
    active=(200,), inactive=(401, 403),
))


# Zendesk API token — Basic base64("<email>/token:<token>") against the site
@register(
    "zendesk",
    needs=("id",),
    endpoint=True,
    companion_help={"id": "account email", "endpoint": "https://<subdomain>.zendesk.com"},
    doc="GET <subdomain>.zendesk.com/api/v2/users.json (Basic email/token)",
)
def zendesk(secret: str, extra: dict, http: HttpClient) -> Result:
    base = extra.get("endpoint")
    if not base:
        return Result("zendesk", SKIPPED,
                      detail="pass --base-url https://<subdomain>.zendesk.com")
    url = base.rstrip("/") + "/api/v2/users.json"
    # Zendesk API-token auth: username is literally "<email>/token".
    resp = http.request("GET", url, basic_auth=(f"{extra['id']}/token", secret))
    return _interpret("zendesk", resp, url, active=(200,), inactive=(401, 404))


# Bitbucket app password — Basic base64(<username>:<app_password>)
@register(
    "bitbucket",
    needs=("id",),
    companion_help={"id": "Bitbucket username (for the app password)"},
    doc="GET api.bitbucket.org/2.0/user (Basic username:app-password)",
)
def bitbucket(secret: str, extra: dict, http: HttpClient) -> Result:
    url = "https://api.bitbucket.org/2.0/user"
    resp = http.request("GET", url, headers={"Accept": "application/json"},
                        basic_auth=(extra["id"], secret))
    # 403 = valid credential, insufficient scope — still a live secret.
    return _interpret("bitbucket", resp, url, active=(200, 403), inactive=(401,))


# Sumo Logic — Basic base64(<access_id>:<access_key>), region host overridable
@register(
    "sumologic",
    needs=("id",),
    endpoint=True,
    companion_help={"id": "access ID", "endpoint": "region host, e.g. https://api.eu.sumologic.com"},
    doc="GET api.sumologic.com/api/v1/users (Basic id:key)",
)
def sumologic(secret: str, extra: dict, http: HttpClient) -> Result:
    base = (extra.get("endpoint") or "https://api.sumologic.com").rstrip("/")
    url = base + "/api/v1/users"
    resp = http.request("GET", url, basic_auth=(extra["id"], secret))
    return _interpret("sumologic", resp, url, active=(200,), inactive=(401,))


# PlanetScale service token — Authorization: "<id>:<token>" (literal, not Bearer/Basic)
@register(
    "planetscale",
    needs=("id",),
    sniff=r"\bpscale_tkn_[A-Za-z0-9_-]{32,}",
    companion_help={"id": "service token ID"},
    doc="GET api.planetscale.com/v1/organizations (Authorization: id:token)",
)
def planetscale(secret: str, extra: dict, http: HttpClient) -> Result:
    url = "https://api.planetscale.com/v1/organizations"
    resp = http.request("GET", url, headers={
        "Authorization": f"{extra['id']}:{secret}", "accept": "application/json"})
    return _interpret("planetscale", resp, url, active=_2XX, inactive=(401,))


# Discord bot token — GET /users/<user_id> with "Authorization: Bot <token>"
@register(
    "discord",
    needs=("id",),
    companion_help={"id": "Discord user/snowflake ID to look up"},
    doc="GET discord.com/api/v8/users/<id> (Authorization: Bot <token>)",
)
def discord(secret: str, extra: dict, http: HttpClient) -> Result:
    uid = urllib.parse.quote(extra["id"], safe="")
    url = f"https://discord.com/api/v8/users/{uid}"
    resp = http.request("GET", url, headers={"Authorization": f"Bot {secret}"})
    return _interpret("discord", resp, url, active=_2XX, inactive=(401, 403))
