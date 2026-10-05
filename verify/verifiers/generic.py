"""Single-request, read-only verifiers for token-style providers.

Each entry hits one identity / ``whoami`` / ``validate`` endpoint and reports
whether the credential was accepted.  None of these endpoints mutate anything.

Providers marked ``endpoint=True`` accept a ``--base-url`` / ``--endpoint``
override for self-hosted / enterprise deployments (on-prem GitLab, GitHub
Enterprise, self-hosted Sentry/Gitea/Grafana/Artifactory, Datadog EU, …).

To add a provider: append a ``register(...)(http_check(...))`` block.  Match the
``topic`` to the value used in ``referential/rules.yaml``.
"""

from __future__ import annotations

from ..core import http_check, register

# --- version control ------------------------------------------------------- #

register(
    "github",
    sniff=r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})",
    doc="GET api.github.com/user",
    endpoint=True,  # GitHub Enterprise: --base-url https://ghe.corp/api/v3
)(http_check(
    "github", "https://api.github.com", "/user",
    auth="bearer",
    extra_headers={"X-GitHub-Api-Version": "2022-11-28"},
    inactive=(401,),  # 403 from /user is rate limiting, not a bad token
    identity=lambda j: {"login": j.get("login"), "id": j.get("id")} if j else None,
))

register(
    "gitlab",
    sniff=r"\b(glpat-|gldt-|glrt-|glcbt-|glft-|gloas-)[A-Za-z0-9._-]{20,}",
    doc="GET gitlab.com/api/v4/user",
    endpoint=True,  # self-hosted: --base-url https://gitlab.corp.example.com
)(http_check(
    "gitlab", "https://gitlab.com", "/api/v4/user",
    auth="header", header_name="PRIVATE-TOKEN",
    inactive=(401,),
    identity=lambda j: {"username": j.get("username"), "id": j.get("id")} if j else None,
))

register(
    "gitea",
    doc="GET gitea.com/api/v1/user",
    endpoint=True,  # self-hosted: --base-url https://gitea.corp.example.com
)(http_check(
    "gitea", "https://gitea.com", "/api/v1/user",
    auth="header", header_name="Authorization", prefix="token ",
    inactive=(401,),
    identity=lambda j: {"login": j.get("login"), "id": j.get("id")} if j else None,
))

# --- AI / LLM --------------------------------------------------------------- #

register(
    "openai",
    sniff=r"\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}",
    doc="GET api.openai.com/v1/models",
)(http_check(
    "openai", "https://api.openai.com", "/v1/models",
    auth="bearer", inactive=(401,),
    identity=lambda j: {"models": len(j.get("data", []))} if j else None,
))

register(
    "anthropic",
    sniff=r"\bsk-ant-[A-Za-z0-9_-]{20,}",
    doc="GET api.anthropic.com/v1/models",
)(http_check(
    "anthropic", "https://api.anthropic.com", "/v1/models",
    auth="header", header_name="x-api-key",
    extra_headers={"anthropic-version": "2023-06-01"},
    inactive=(401,),
    identity=lambda j: {"models": len(j.get("data", []))} if j else None,
))

register(
    "huggingface",
    sniff=r"\bhf_[A-Za-z0-9]{30,}",
    doc="GET huggingface.co/api/whoami-v2",
)(http_check(
    "huggingface", "https://huggingface.co", "/api/whoami-v2",
    auth="bearer", inactive=(401,),
    identity=lambda j: {"name": j.get("name"), "type": j.get("type")} if j else None,
))

# --- email / messaging ------------------------------------------------------ #

register(
    "sendgrid",
    sniff=r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    doc="GET api.sendgrid.com/v3/scopes",
)(http_check(
    "sendgrid", "https://api.sendgrid.com", "/v3/scopes",
    auth="bearer", inactive=(401,),
    identity=lambda j: {"scopes": len(j.get("scopes", []))} if j else None,
))

register(
    "postmark",
    doc="GET api.postmarkapp.com/server",
)(http_check(
    "postmark", "https://api.postmarkapp.com", "/server",
    auth="header", header_name="X-Postmark-Server-Token",
    inactive=(401, 422),
    identity=lambda j: {"name": j.get("Name")} if j else None,
))

# --- cloud / infra ---------------------------------------------------------- #

register(
    "digitalocean",
    sniff=r"\b(dop|doo|dor)_v1_[a-f0-9]{64}",
    doc="GET api.digitalocean.com/v2/account",
)(http_check(
    "digitalocean", "https://api.digitalocean.com", "/v2/account",
    auth="bearer", inactive=(401,),
    identity=lambda j: {
        "email": (j.get("account") or {}).get("email"),
        "status": (j.get("account") or {}).get("status"),
    } if j else None,
))

register(
    "heroku",
    sniff=r"\bHRKU-[A-Za-z0-9_-]{30,}",
    doc="GET api.heroku.com/account",
)(http_check(
    "heroku", "https://api.heroku.com", "/account",
    auth="bearer",
    extra_headers={"Accept": "application/vnd.heroku+json; version=3"},
    inactive=(401,),
    identity=lambda j: {"email": j.get("email"), "id": j.get("id")} if j else None,
))

register(
    "pagerdutyapikey",
    doc="GET api.pagerduty.com/users (read-only)",
)(http_check(
    "pagerdutyapikey", "https://api.pagerduty.com", "/users?limit=1",
    auth="header", header_name="Authorization", prefix="Token token=",
    extra_headers={"Accept": "application/vnd.pagerduty+json;version=2"},
    inactive=(401,),
))

register(
    "datadog",
    doc="GET api.datadoghq.com/api/v1/validate",
    endpoint=True,  # EU / other sites: --base-url https://api.datadoghq.eu
)(http_check(
    "datadog", "https://api.datadoghq.com", "/api/v1/validate",
    auth="header", header_name="DD-API-KEY",
    active=(200,), inactive=(403,),
))

register(
    "sentry",
    doc="GET sentry.io/api/0/projects/",
    endpoint=True,  # self-hosted: --base-url https://sentry.corp.example.com
)(http_check(
    "sentry", "https://sentry.io", "/api/0/projects/",
    auth="bearer", inactive=(401,),
))

register(
    "artifactory",
    doc="GET <host>/artifactory/api/system/version (self-hosted — needs --base-url)",
    endpoint=True,
)(http_check(
    "artifactory", "", "/artifactory/api/system/version",
    auth="bearer", inactive=(401, 403),
    identity=lambda j: {"version": j.get("version")} if j else None,
    require_endpoint=True,
))

register(
    "grafana",
    sniff=r"\bgl(sa|c)_[A-Za-z0-9_]{32,}",
    doc="GET <host>/api/user (needs --base-url; Grafana stacks are per-host)",
    endpoint=True,
)(http_check(
    "grafana", "", "/api/user",
    auth="bearer", inactive=(401,),
    identity=lambda j: {"login": j.get("login"), "email": j.get("email")} if j else None,
    require_endpoint=True,
))

# --- productivity / SaaS ---------------------------------------------------- #

register(
    "dropbox",
    sniff=r"\bsl\.[A-Za-z0-9_-]{100,}",
    doc="POST api.dropboxapi.com/2/users/get_current_account",
)(http_check(
    "dropbox", "https://api.dropboxapi.com", "/2/users/get_current_account",
    auth="bearer", method="POST", body="null", content_type="application/json",
    inactive=(401,),
    identity=lambda j: {"account_id": j.get("account_id"),
                        "email": (j.get("email"))} if j else None,
))

register(
    "airtable",
    sniff=r"\bpat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}",
    doc="GET api.airtable.com/v0/meta/whoami",
)(http_check(
    "airtable", "https://api.airtable.com", "/v0/meta/whoami",
    auth="bearer", inactive=(401,),
    identity=lambda j: {"id": j.get("id")} if j else None,
))

register(
    "notion",
    sniff=r"\b(secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})",
    doc="GET api.notion.com/v1/users/me",
)(http_check(
    "notion", "https://api.notion.com", "/v1/users/me",
    auth="bearer",
    extra_headers={"Notion-Version": "2022-06-28"},
    inactive=(401,),
    identity=lambda j: {"type": j.get("type"), "name": j.get("name")} if j else None,
))

register(
    "figma",
    sniff=r"\bfig[dou]_[A-Za-z0-9_-]{30,}",
    doc="GET api.figma.com/v1/me",
)(http_check(
    "figma", "https://api.figma.com", "/v1/me",
    auth="header", header_name="X-Figma-Token",
    inactive=(401, 403),
    identity=lambda j: {"email": j.get("email"), "handle": j.get("handle")} if j else None,
))

register(
    "npm",
    sniff=r"\bnpm_[A-Za-z0-9]{36}",
    doc="GET registry.npmjs.org/-/npm/v1/user",
)(http_check(
    "npm", "https://registry.npmjs.org", "/-/npm/v1/user",
    auth="bearer", inactive=(401,),
    identity=lambda j: {"name": j.get("name")} if j else None,
))
