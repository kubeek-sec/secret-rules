"""Remediation metadata and (where safe) self-revocation for leaked secrets.

Rotation is inherently a mutating, hard-to-reverse operation, so this module is
conservative:

- Every provider gets a **manual runbook** (where to revoke, where to mint a
  replacement, caveats).  This is always safe to print.
- A few providers additionally get a ``self_revoke`` function — used *only* when
  the leaked credential can revoke **itself** through one documented endpoint
  (Slack ``auth.revoke``, GitLab ``DELETE .../self``, Dropbox
  ``auth/token/revoke``).  These are destructive and never run unless the user
  passes ``--execute`` and confirms.

We deliberately do **not** attempt to mint replacement credentials: that almost
always requires account-level auth the leaked secret doesn't have, and getting
it wrong risks breaking production.  Minting the new value stays a human step;
once you have it, ``verify.py update`` installs and re-verifies it.
"""

from __future__ import annotations

from .core import HttpClient, Result, Rotator, register_rotator

# --------------------------------------------------------------------------- #
# Self-revocation endpoints (destructive — gated behind --execute)
# --------------------------------------------------------------------------- #


def _slack_revoke(secret: str, extra: dict, http: HttpClient) -> Result:
    resp = http.request(
        "POST", "https://slack.com/api/auth.revoke",
        headers={"Authorization": f"Bearer {secret}",
                 "Content-Type": "application/x-www-form-urlencoded"},
        data="",
    )
    if resp.dry_run:
        return Result("slack", "planned", endpoint="https://slack.com/api/auth.revoke")
    j = resp.json() or {}
    if resp.status == 200 and j.get("ok") and j.get("revoked"):
        return Result("slack", "revoked", detail="token revoked via auth.revoke")
    return Result("slack", "failed",
                  detail=f"revoke failed (HTTP {resp.status}; {j.get('error', resp.error)})")


def _gitlab_revoke(secret: str, extra: dict, http: HttpClient) -> Result:
    url = "https://gitlab.com/api/v4/personal_access_tokens/self"
    resp = http.request("DELETE", url, headers={"PRIVATE-TOKEN": secret})
    if resp.dry_run:
        return Result("gitlab", "planned", endpoint=url)
    if resp.status in (204, 200):
        return Result("gitlab", "revoked", detail="personal access token revoked")
    return Result("gitlab", "failed",
                  detail=f"revoke failed (HTTP {resp.status}) — needs a PAT with api scope")


def _dropbox_revoke(secret: str, extra: dict, http: HttpClient) -> Result:
    url = "https://api.dropboxapi.com/2/auth/token/revoke"
    resp = http.request("POST", url, headers={"Authorization": f"Bearer {secret}"})
    if resp.dry_run:
        return Result("dropbox", "planned", endpoint=url)
    if resp.status == 200:
        return Result("dropbox", "revoked", detail="access token revoked")
    return Result("dropbox", "failed", detail=f"revoke failed (HTTP {resp.status})")


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

_ROTATORS = [
    Rotator(
        ("github",),
        revoke_console="https://github.com/settings/tokens (classic) / "
                       "https://github.com/settings/personal-access-tokens (fine-grained)",
        create_doc="Regenerate from the same page; update org SSO authorization if required.",
        notes="No API self-revoke with only the token (needs the OAuth app's client "
              "credentials). Revoke manually, then search audit logs for use of the token.",
    ),
    Rotator(
        ("gitlab",),
        revoke_console="https://gitlab.com/-/user_settings/personal_access_tokens",
        create_doc="Create a new token with the minimum scopes you actually need.",
        notes="Self-revoke works only for personal access tokens with the 'api' scope.",
        self_revoke=_gitlab_revoke,
        self_revoke_desc="DELETE /api/v4/personal_access_tokens/self",
    ),
    Rotator(
        ("slack",),
        revoke_console="https://api.slack.com/apps (rotate app credentials; reinstall app)",
        create_doc="Reinstall the app / re-run OAuth to mint a fresh token.",
        notes="auth.revoke invalidates exactly this token. Bot vs user tokens are "
              "revoked the same way.",
        self_revoke=_slack_revoke,
        self_revoke_desc="POST slack.com/api/auth.revoke",
    ),
    Rotator(
        ("dropbox",),
        revoke_console="https://www.dropbox.com/developers/apps",
        create_doc="Generate a new access token for the app (or re-run the OAuth flow).",
        self_revoke=_dropbox_revoke,
        self_revoke_desc="POST api.dropboxapi.com/2/auth/token/revoke",
    ),
    Rotator(
        ("aws",),
        revoke_console="IAM → Users → <user> → Security credentials → Access keys",
        create_doc="Create a new access key, deploy it, then deactivate and delete the old one.",
        notes="Prefer deactivate-first so you can roll back. Delete only after confirming "
              "nothing still uses the old key (check CloudTrail LastUsed).",
    ),
    Rotator(
        ("stripe",),
        revoke_console="https://dashboard.stripe.com/apikeys",
        create_doc="Use 'Roll key' to mint a replacement with a grace period, then expire the old one.",
        notes="Rolling keeps the old key alive briefly so you can deploy the new one first.",
    ),
    Rotator(("openai",), revoke_console="https://platform.openai.com/api-keys",
            create_doc="Create a new secret key; delete the leaked one."),
    Rotator(("anthropic",), revoke_console="https://console.anthropic.com/settings/keys",
            create_doc="Create a new API key; delete the leaked one."),
    Rotator(("sendgrid",), revoke_console="https://app.sendgrid.com/settings/api_keys",
            create_doc="Delete the leaked key and create a new one with least privilege."),
    Rotator(("twilio",), revoke_console="https://console.twilio.com/",
            create_doc="Promote the secondary Auth Token, then regenerate the primary.",
            notes="Twilio supports a primary/secondary token swap for zero-downtime rotation."),
    Rotator(("mailgun",), revoke_console="https://app.mailgun.com/settings/api_security",
            create_doc="Rotate the private API key; update sending integrations."),
    Rotator(("digitalocean",), revoke_console="https://cloud.digitalocean.com/account/api/tokens",
            create_doc="Delete the token and generate a new one."),
    Rotator(("heroku",), revoke_console="https://dashboard.heroku.com/account/applications "
            "or `heroku authorizations`",
            create_doc="Revoke the authorization; create a new API token."),
    Rotator(("airtable",), revoke_console="https://airtable.com/create/tokens",
            create_doc="Delete the personal access token and create a replacement."),
    Rotator(("notion",), revoke_console="https://www.notion.so/my-integrations",
            create_doc="Rotate the integration's internal secret."),
    Rotator(("figma",), revoke_console="https://www.figma.com/settings (Personal access tokens)",
            create_doc="Revoke the token and generate a new one."),
    Rotator(("npm",), revoke_console="https://www.npmjs.com/settings/~/tokens",
            create_doc="Delete the token; create a granular replacement."),
    Rotator(("huggingface",), revoke_console="https://huggingface.co/settings/tokens",
            create_doc="Invalidate the token and create a new one."),
    Rotator(("linear",), revoke_console="https://linear.app/settings/api",
            create_doc="Revoke the personal API key; create a new one."),
    Rotator(("cloudflare",), revoke_console="https://dash.cloudflare.com/profile/api-tokens",
            create_doc="Roll the API token; for a global key use 'Change Global API Key'.",
            notes="Global API keys are account-wide — prefer scoped API tokens for the replacement."),
    Rotator(("datadog",), revoke_console="https://app.datadoghq.com/organization-settings/api-keys",
            create_doc="Revoke the API key and create a new one."),
    Rotator(("postmark",), revoke_console="Postmark server → API Tokens",
            create_doc="Regenerate the server token."),
    Rotator(("pagerdutyapikey",), revoke_console="https://<subdomain>.pagerduty.com/api_keys",
            create_doc="Remove the key and create a new one."),

    # --- self-minted secrets: you control both ends, so generate locally ----
    Rotator(
        ("django",),
        revoke_console="your deployment's config / secret store",
        create_doc="Replace SECRET_KEY with a fresh random value and redeploy.",
        notes="Rotating invalidates existing sessions and password-reset tokens.",
        mint="self", gen_spec={"bits": 256, "charset": "base64url"},
    ),
    Rotator(
        ("rails",),
        revoke_console="your deployment's credentials / secret store",
        create_doc="Regenerate secret_key_base (e.g. `rails secret`) and redeploy.",
        notes="Rotating invalidates signed/encrypted cookies and sessions.",
        mint="self", gen_spec={"length": 128, "charset": "hex"},
    ),
    Rotator(
        ("jwt",),
        revoke_console="the service that signs/verifies the tokens",
        create_doc="Replace the HS256 signing secret on every signer and verifier.",
        notes="Rotating invalidates all tokens signed with the old secret. For RS256/"
              "asymmetric keys, generate a keypair instead of a random string.",
        mint="self", gen_spec={"bits": 256, "charset": "base64url"},
    ),
    Rotator(
        ("generic",),
        revoke_console="wherever this secret is configured",
        create_doc="Generate a fresh high-entropy value and update both sides.",
        mint="self", gen_spec={"bits": 256, "charset": "base62"},
    ),
]

for _r in _ROTATORS:
    register_rotator(_r)
