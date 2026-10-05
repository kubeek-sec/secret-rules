# verify/ — live-credential verification & rotation

A companion to the [secret-rules](../README.md) referential. The scanners tell
you a string **looks like** a secret; this tool tells you whether it is
**actually live**, and helps you **remediate** it when it is.

It mirrors the "verification" feature of tools like TruffleHog: when a scan of a
repo turns up hundreds of candidate secrets, you need to know which ones are
real, active credentials that require urgent rotation — and which are false
positives, test fixtures, or already-dead keys.

## Safety model

> **`check` never triggers anything.** Every verifier calls only *read-only*
> endpoints — identity / `whoami` / `validate` / list. Nothing creates, sends,
> charges, or deletes. Verification does send the secret to its own provider
> (that is unavoidable — it's how you prove the key is accepted), and nowhere
> else.

Additional guardrails baked in:

- **No redirects are followed**, so a credential in an `Authorization` header is
  never re-sent to another host.
- **`--dry-run`** prints exactly which endpoint(s) would be contacted and sends
  nothing.
- Secrets are shown only as a **fingerprint** (`ghp_…op (len 40)`) in output.
- The only mutating actions live in the separate **`rotate`** and **`update`**
  commands. They are **plan-only by default** and require `--execute` plus a
  confirmation to do anything irreversible.

## Install / run

No new dependencies — it uses the standard library plus PyYAML (already required
by the project). Run it directly:

```sh
python verify/verify.py <command> ...
# or inside the project environment:
uv run python verify/verify.py <command> ...
```

## Commands

### `check` — is this secret live?

```sh
# Simple token providers
python verify/verify.py check --topic github --secret ghp_xxx
python verify/verify.py check --topic openai --secret sk-xxx

# Read the secret from stdin or an env var (keeps it out of shell history / ps)
echo "$TOKEN" | python verify/verify.py check --topic slack --secret-stdin
python verify/verify.py check --topic stripe --secret-env STRIPE_KEY

# Multi-part credentials (companion via --id / --field / --session-token)
python verify/verify.py check --topic aws    --id AKIA... --secret <secret-access-key>
python verify/verify.py check --topic aws    --id ASIA... --secret <key> --session-token <tok>
python verify/verify.py check --topic twilio --id AC...   --secret <auth-token>

# Let the tool guess the provider from the secret's shape
python verify/verify.py check --secret xoxb-123...   # -> slack

# Preview without sending anything
python verify/verify.py check --topic github --secret ghp_xxx --dry-run
```

Statuses (aligned with Kingfisher's `validation.outcome` taxonomy):

| status             | meaning                                                      | exit |
|--------------------|--------------------------------------------------------------|------|
| `active`           | a live validator proved the credential works — **rotate it** | 0    |
| `inactive`         | a validator authoritatively rejected it (401, expired JWT…)  | 1    |
| `locally-derived`  | an **offline** check accepted the material (well-formed key / JWT / URI) | 0 |
| `invalid-material` | an **offline** check rejected it (malformed key or JWT)      | 1    |
| `unknown`          | inconclusive (network error, rate-limited, odd response)     | 1    |
| `unsupported`      | no verifier for this topic — check the provider console      | 1    |
| `skipped`          | a required companion/dependency was missing (e.g. AWS key id)| 1    |

On `active`, non-sensitive identity metadata from the API is shown (GitHub
login, AWS account/ARN, Stripe mode, …) so you can tell *whose* key it is.

### `check --input` — batch a scanner's output

Feed newline-delimited JSON, one finding per line:

```sh
# findings.jsonl
# {"topic":"github","secret":"ghp_..."}
# {"uid":"aws-access-key-id","secret":"<sk>","id":"AKIA..."}
# {"secret":"xoxb-..."}            # topic auto-detected from shape
python verify/verify.py check --input findings.jsonl --json
```

Each object needs a `secret` plus either `topic` or `uid` (or a recognizable
shape). Extra keys (`id`, `session_token`, …) are passed through as companions.
`--only-active` keeps just the live/valid findings; `--rps N` caps the global
request rate so a large batch doesn't hammer providers.

### Self-hosted / on-prem (custom endpoints)

Many providers run on your own infrastructure. Point a verifier at your host
with `--base-url` (single topic) or `--endpoint TOPIC=URL` (batch, repeatable):

```sh
# on-prem GitLab
python verify/verify.py check --topic gitlab --secret glpat-... \
    --base-url https://gitlab.corp.example.com

# GitHub Enterprise (note the /api/v3 REST base)
python verify/verify.py check --topic github --secret ghp_... \
    --base-url https://ghe.corp.example.com/api/v3

# self-hosted Sentry / Gitea / Artifactory / Grafana, Jira Server/DC, Datadog EU …
python verify/verify.py check --topic artifactory --secret <token> \
    --base-url https://artifactory.corp.example.com
python verify/verify.py check --topic datadog --secret <key> \
    --base-url https://api.datadoghq.eu

# batch, per-topic
python verify/verify.py check --input findings.jsonl \
    --endpoint gitlab=https://gitlab.corp --endpoint sentry=https://sentry.corp
# …or from a file:  --endpoint-config endpoints.yaml   # { endpoints: {gitlab: "https://…"} }
```

Topics that accept an override are tagged `[self-hostable]` in `list`. For hosts
with a private-CA or self-signed certificate, add `--insecure` to accept it
(a deliberate TLS-trust downgrade — use only for hosts you control).

### Offline (network-free) validation

Some material can be judged **without contacting anyone** — Kingfisher calls
this `locally_derived` / `invalid_material`. These validators send zero network
traffic:

```sh
# JWT: decode, and check structure + exp/nbf expiry (and flag alg=none)
python verify/verify.py check --topic jwt --secret eyJhbGciOiJIUzI1NiJ9....
#   expired/not-yet-valid -> inactive; well-formed -> locally-derived

# Private keys: confirm a PEM block is a well-formed RSA/EC/OpenSSH/PKCS#8 key
cat id_rsa | python verify/verify.py check --topic private --secret-stdin

# DB / credential connection strings: parse and confirm embedded credentials
python verify/verify.py check --topic postgres \
    --secret 'postgres://user:pass@db.corp:5432/app'
```

Connection-string topics (`postgres`, `mysql`, `mariadb`, `mongodb`, `redis`,
`rabbitmq`, `jdbc`) are parsed offline: we confirm a usable host+credential but
do **not** open a database connection (that needs the DB driver — see
[comparison](#how-this-compares-to-kingfisher)).

### `rotate` — verify → revoke → (re)generate → install

```sh
python verify/verify.py rotate --topic slack --secret xoxb-...
```

This (1) verifies the current secret, (2) shows how to revoke it, (3) helps you
produce a replacement, and (4) installs it and records the change.

**Revoke.** Where a credential can revoke **itself** through one documented
endpoint (Slack `auth.revoke`, GitLab `DELETE …/self`, Dropbox
`auth/token/revoke`), it can be performed here — destructive, so it asks first:

```sh
python verify/verify.py rotate --topic slack --secret xoxb-... --execute        # prompts y/N
python verify/verify.py rotate --topic slack --secret xoxb-... --execute --yes  # for automation
python verify/verify.py rotate --topic slack --secret xoxb-... --execute --dry-run  # show, don't send
```

**Produce the replacement.** Two cases:

- **Provider-minted** tokens (GitHub, AWS, Slack, Stripe, …) can't be generated
  locally — the service signs them in its own format. `rotate` won't fabricate
  one; supply the value you minted in the console with `--new-secret`, or just
  read the runbook and use `update` afterwards.
- **Self-minted** secrets — ones you control both ends of: `django`
  (`SECRET_KEY`), `rails` (`secret_key_base`), `jwt` (HS256 signing secret),
  `generic` app secrets — *can* be generated. `--generate` mints a fresh
  high-entropy value with a CSPRNG and installs it:

```sh
# generate a new JWT signing secret and write it into .env, logging the change
python verify/verify.py rotate --topic jwt --generate --sink dotenv:./app.env#JWT_SECRET

# generate but just show it (no sink)
python verify/verify.py rotate --topic generic --generate --show
```

For a self-controlled secret that isn't one of those topics, add
`--force-generate` to generate anyway. If you don't ask to generate and don't
pass `--new-secret`, `rotate` keeps the value you provided (if any) and prints
the manual runbook.

Every change (generate / install / self-revoke) is recorded to the
[audit ledger](#audit-ledger).

### `update` — install a freshly minted replacement

Once you've generated a new secret in the provider console, verify it works and
write it to a destination ("sink") in one step:

```sh
python verify/verify.py update --topic github --new-secret ghp_new \
    --sink dotenv:./.env#GITHUB_TOKEN
```

It refuses to install a secret that doesn't verify as `active` (override with
`--force`). Sinks:

| sink spec            | effect                                                    |
|----------------------|-----------------------------------------------------------|
| `stdout`             | print the value (requires `--show` to confirm)            |
| `file:PATH`          | write the raw value to `PATH` (mode `0600`)               |
| `dotenv:PATH#VAR`    | upsert `VAR=value` in a `.env`-style file (mode `0600`)   |
| `exec:COMMAND`       | run `COMMAND`, piping the value on stdin                  |

`exec:` is the integration point for a real secret manager, e.g.
`--sink "exec:vault kv put secret/app token=-"` or an `aws secretsmanager
put-secret-value` wrapper.

`update` also records to the [audit ledger](#audit-ledger).

### `gen` — generate a strong random secret

Draws from a CSPRNG (`secrets`). Size it by length or by target entropy:

```sh
python verify/verify.py gen                         # ~256-bit, base62
python verify/verify.py gen --bits 128 --charset hex
python verify/verify.py gen --length 64 --charset base64url
python verify/verify.py gen --count 3 --json        # values + their strength
```

Charsets: `base62` (default), `alnum`, `hex`, `base64url`, `ascii`.

### `entropy` — evaluate a string

```sh
python verify/verify.py entropy 'correct horse battery staple'
echo -n "$CANDIDATE" | python verify/verify.py entropy --stdin --json
```

It reports the observed **Shannon entropy** (bits/char), a **pool-based
estimate** (`length × log2(charset)`), and a verdict. The pool estimate assumes
the value is *random*: for a human-chosen password with dictionary words or
patterns the real entropy is lower, so treat it as an upper bound.

## Audit ledger

Every value changed by `rotate` or `update` is appended to a JSONL ledger —
`secret-rotations.jsonl` at the repo root by default (override with `--ledger`).
It is **git-ignored** (added to `.gitignore`) and written mode `0600`, because
it can carry sensitive material.

By default each line records *fingerprints* only — enough to correlate "which
secret changed to which" without storing the secrets:

```json
{"time":"2026-01-01T12:00:00+00:00","action":"rotate","topic":"jwt",
 "operator":"alice","new_fingerprint":"S8wL…le (len 43)","generated":true,
 "new_entropy_bits":281.8,"verified":"unsupported","sink":"dotenv:./app.env#JWT_SECRET"}
```

Pass `--record-secret` to *also* store the new value in plaintext (for teams who
use the ledger as the source of the value to deploy); `--no-ledger` disables
recording for a run.

### `list` — coverage

```sh
python verify/verify.py list          # table
python verify/verify.py list --json
```

## Supported providers

`check` has verifiers for **57 topics** (and counting); **all 600+ referential
topics** are selectable, and any without a verifier simply report `unsupported`.
`verify.py list` is the source of truth — it tags `[self-hostable]` topics
(accept `--base-url`) and shows rotation support. Rotation is `self-revoke` where
the key can revoke itself, else a manual `runbook`, or `generate` for self-minted
secrets.

**Live (network) verifiers** — the identity/whoami/validate endpoint each uses:

| topic | check endpoint (read-only) | notes |
|-------|----------------------------|-------|
| airtable | `GET /v0/meta/whoami` | |
| anthropic | `GET /v1/models` | |
| artifactory | `GET /artifactory/api/system/version` | self-hosted |
| asana | `GET /api/1.0/users/me` | |
| aws | STS `GetCallerIdentity` (SigV4) | needs `--id` |
| bitbucket | `GET /2.0/user` (Basic) | needs `--id` (username); 403=valid |
| cloudflare | token verify, or global key | `--id <email>` for global key |
| confluence | `GET /…/rest/api/user/current` | Cloud `--id`/Server |
| databricks | `GET /api/2.0/preview/scim/v2/Me` | needs `--base-url` |
| datadog | `GET /api/v1/validate` | US; `--base-url` for EU |
| digitalocean | `GET /v2/account` | |
| discord | `GET /api/v8/users/<id>` (`Bot`) | needs `--id` (user id) |
| doppler | `GET /v3/me` | |
| dropbox | `POST /2/users/get_current_account` | self-revoke |
| figma | `GET /v1/me` | |
| gitea | `GET /api/v1/user` | self-hostable |
| github | `GET /user` | GHE via `--base-url` |
| gitlab | `GET /api/v4/user` | self-hostable; self-revoke |
| grafana | `GET /api/user` | self-hosted |
| heroku | `GET /account` | |
| huggingface | `GET /api/whoami-v2` | |
| jira | `GET /…/myself` | Cloud `--id <email>`/Server |
| linear | GraphQL `{ viewer }` | |
| mailgun | `GET /v3/domains` | |
| mapbox | `GET /tokens/v2/<id>?access_token=` | needs `--id` (account) |
| mattermost | `GET /api/v4/users/stats` | needs `--base-url` |
| newrelic | `POST /graphql` (`API-Key`) | US; `--base-url` for EU |
| notion | `GET /v1/users/me` | |
| npm | `GET /-/npm/v1/user` | |
| openai | `GET /v1/models` | |
| pagerdutyapikey | `GET /users` | |
| planetscale | `GET /v1/organizations` | needs `--id` (token id) |
| postmark | `GET /server` | |
| posthog | `GET /api/event/` | EU/self-host via `--base-url` |
| sendgrid | `GET /v3/scopes` | |
| sentry | `GET /api/0/projects/` | self-hostable |
| shopify | `GET /admin/oauth/access_scopes.json` | needs `--base-url` (store) |
| slack | `POST /api/auth.test` | self-revoke |
| sourcegraph | `POST /.api/graphql` | self-hostable |
| square | `GET /v2/merchants` | 403=valid |
| stripe | `GET /v1/account` | |
| sumologic | `GET /api/v1/users` (Basic) | needs `--id`; region `--base-url` |
| supabase | `GET /v1/projects` | management token |
| twilio | `GET /Accounts/<SID>.json` | needs `--id` (SID) |
| twitter | `GET /2/tweets/20` | bearer token |
| vercel | `GET /www/user` | |
| zendesk | `GET /api/v2/users.json` (Basic) | needs `--id` (email) + `--base-url` |

Providers from `asana` down are ported from
[TruffleHog detectors](https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors)
— each uses the same read-only verification endpoint TruffleHog does.

**Offline (network-free) validators** — `locally-derived` / `invalid-material`:

| topic | check |
|-------|-------|
| jwt | decode + structure + `exp`/`nbf` expiry (+ `alg=none` flag) |
| private | PEM private key well-formedness (RSA / EC / OpenSSH / PKCS#8 / PGP) |
| postgres, mysql, mariadb, mongodb, redis, rabbitmq, jdbc | connection-URI parse + embedded-credential check |

**Self-minted (generate locally):** `django`, `rails`, `jwt`, `generic` —
see [`rotate --generate`](#rotate--verify--revoke--regenerate--install).

## How this compares to Kingfisher

[Kingfisher](https://github.com/mongodb/kingfisher) is the inspiration for the
validation model here (its outcome taxonomy, `validate`/`revoke` verbs, custom
endpoints, offline checks). What this folder matches, and what it doesn't:

**Matched**

- Active vs. inactive validation via read-only endpoints; the same outcome
  vocabulary (`active`, `inactive`, `locally-derived`/`invalid-material`,
  `unknown`≈`unavailable`, `skipped`, `unsupported`).
- `check` ≈ `kingfisher validate`; `rotate --execute` self-revoke ≈
  `kingfisher revoke`.
- Custom/self-hosted endpoints (`--base-url` / `--endpoint` / `--endpoint-config`),
  TLS downgrade (`--insecure` ≈ `--tls-mode`), rate limiting (`--rps`),
  multipart credentials (`--id` / `--field` ≈ `--var` / `--arg`), `--only-active`.
- Offline validation: JWT (exp/nbf/alg-none), private keys, credential URIs.

**Intentionally out of scope** (Kingfisher has these; this stdlib-only helper
does not):

- **Live database authentication.** Kingfisher opens real MongoDB/MySQL/Postgres
  /JDBC connections; we parse the connection string offline (no DB drivers).
- **Online JWT signature verification** via JWKS fetch (`kid` → public key).
- **Blast-radius / access-map** — enumerating what a cloud credential can access.
- **Cloud breadth** — Azure/GCP signing flows, and the hundreds of provider
  validators Kingfisher/TruffleHog ship. We cover 57 high-value topics (many
  ported from TruffleHog's detectors) and make adding more a few lines (below).

## How it's organized

```
verify/
  verify.py            CLI: check / rotate / update / gen / entropy / list
  core.py              Result, HttpClient (redirect-safe, dry-run, --insecure,
                       --rps), registries, @register / http_check, referential
  verifiers/
    generic.py         declarative single-request token verifiers (+ self-hosted)
    custom.py          JSON logic, companions, SigV4 (aws), Atlassian
    providers.py       TruffleHog-sourced verifiers (asana, shopify, discord, …)
    offline.py         network-free validators: JWT, private keys, credential URIs
  rotators.py          remediation runbooks, self-revoke, self-mint generation
  sinks.py             update destinations (file / dotenv / exec / stdout)
  strength.py          entropy evaluation + CSPRNG secret generation
  ledger.py            append-only audit ledger of changes
```

## Adding a verifier

Match the `topic` to the value in `referential/rules.yaml`. For a plain
bearer-token API, one block in `verifiers/generic.py` is enough:

```python
register(
    "mytopic",
    sniff=r"\bmytok_[A-Za-z0-9]{32}",          # optional: enables auto-detect
    doc="GET api.example.com/v1/me",
)(http_check(
    "mytopic", "https://api.example.com/v1/me",
    auth="bearer",                              # bearer | header | basic-secret
    inactive=(401,),
    identity=lambda j: {"user": j.get("login")} if j else None,
))
```

For anything with multi-part credentials, custom JSON interpretation, or request
signing, write a function in `verifiers/custom.py` decorated with `@register`.
It receives `(secret, extra, http)` and must return a `Result`. Keep every call
**read-only**.

To add rotation guidance, append a `Rotator(...)` to the list in `rotators.py`
(and a `self_revoke` function only if the credential can revoke *itself* through
a single documented endpoint).

## What makes a strong password / secret

The `entropy` and `gen` commands exist because **entropy** — how unpredictable a
value is — is what actually resists guessing. A few rules of thumb, aligned with
modern guidance (e.g. NIST SP 800-63B):

- **Length beats complexity.** A long passphrase of ordinary words
  (`correct horse battery staple`) is both stronger and more memorable than a
  short string with substitutions (`P@ssw0rd!`). Each extra random element
  multiplies the search space.
- **Think in bits of entropy.** Roughly: `< 28` trivially cracked, `~60` okay
  for a rate-limited login, **`≥ 128` for anything a machine holds** (API keys,
  signing secrets). `gen` defaults to ~256 bits.
- **Randomness, not cleverness.** Human-chosen "random" passwords cluster around
  predictable patterns. Use a CSPRNG (`gen`) or diceware passphrases, not your
  own imagination. Dictionary words, names, dates, and keyboard walks
  (`qwerty`) carry far less entropy than their length suggests.
- **One secret, one place.** Never reuse a password or key across services — a
  single breach then cascades. A password manager makes uniqueness free.
- **Don't rotate on a calendar — rotate on cause.** Forced periodic changes push
  people toward weak, incremental passwords. Rotate immediately when a secret is
  exposed (which is exactly what this tool is for), not every 90 days by ritual.
- **Check against breach lists.** Reject passwords known to have leaked
  (e.g. Have I Been Pwned's k-anonymity API) rather than imposing composition
  rules like "must contain a symbol".
- **Machine secrets are not passwords.** They don't need to be memorable, so make
  them maximal: `python verify/verify.py gen --bits 256`.

## Caveats

- Verification sends the secret to its provider. Don't run it against providers
  you aren't authorized to test.
- `gitlab` and `datadog` default to `gitlab.com` / the US Datadog site. Self-hosted
  GitLab and EU/other Datadog regions need the endpoint adjusted.
- `unknown` is not `inactive`: rate limits (HTTP 429) and transient network
  errors are reported as `unknown` so you don't wrongly treat a live key as dead.
- A `403` can mean "valid credential, insufficient scope" for some APIs — still a
  *live* secret. Verifiers lean conservative, but when in doubt, treat `unknown`
  as "verify manually".
