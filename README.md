# secret-rules

Unified referential and config generator for secrets scanners.

This project ingests the native rulesets of five scanners, merges them into a
single **deduplicated referential** of secret-detection regexes, and generates
ready-to-use configuration files for **seven** scanners.

```
rules/ (5 source rulesets)          referential/ (canonical)        configs/ (generated)
  betterleaks-v1.4.1   ─┐             rules.yaml   (all regexes,  ┌─>  gitleaks.toml
  gitleaks-v8.30.1     ─┤   parse +   deduplicated, provenance)   ├─>  betterleaks.toml
  kingfisher-v1.102.0  ─┼─> dedup ──> topics.yaml  (rules indexed ├─>  kingfisher.yml
  noseyparker-v0.24.0  ─┤             by provider/topic)          ├─>  noseyparker.yml
  titus-v1.2.2         ─┘                                         ├─>  titus.yml
                                                                  ├─>  trufflehog.yml
                                                                  └─>  secret_rules.yar (YARA)
```

## Usage

```sh
uv sync

# 1. build the referential from the source rulesets in rules/
uv run secret-rules build

# 2. generate configs for every supported scanner
uv run secret-rules generate --target all --out-dir configs

# generate only some targets, restricted to specific topics
uv run secret-rules generate --target gitleaks,yara --topics aws,github,slack

# list available topics
uv run secret-rules topics
```

Command options:

| command    | option              | default                  | meaning                                           |
|------------|---------------------|--------------------------|---------------------------------------------------|
| `build`    | `--rules-dir DIR`   | `rules`                  | where the source rulesets live                    |
| `build`    | `--out DIR`         | `referential`            | where `rules.yaml` / `topics.yaml` are written    |
| `generate` | `--target LIST`     | `all`                    | comma-separated targets (`gitleaks`, `betterleaks`, `kingfisher`, `noseyparker`, `titus`, `trufflehog`, `yara`) |
| `generate` | `--topics LIST`     | all topics               | comma-separated topics to include                 |
| `generate` | `--referential FILE`| `referential/rules.yaml` | referential to generate from                      |
| `generate` | `--out-dir DIR`     | `configs`                | where configs are written                         |
| `topics`   | `--referential FILE`| `referential/rules.yaml` | referential to list topics from                   |

`generate` reports, per target, how many rules were skipped as incompatible
with that engine (see [Target-specific compatibility](#target-specific-compatibility)).

## Verifying & rotating findings (`verify/`)

The scanners tell you a string *looks like* a secret; the companion
[`verify/`](verify/README.md) tool tells you whether it is **actually live**
and helps you **remediate** it. It uses only the standard library plus PyYAML.

```sh
# is this secret live? (read-only endpoints only; --dry-run sends nothing)
uv run verify/verify.py check --topic github --secret ghp_xxx
uv run verify/verify.py check --topic aws --id AKIA... --secret <secret-access-key>

# batch a scanner's findings (JSONL: {"topic"|"uid", "secret", ...})
uv run verify/verify.py check --input findings.jsonl --json --only-active

# remediation runbook / self-revoke (plan-only unless --execute)
uv run verify/verify.py rotate --topic slack --secret xoxb-...

# verify a freshly minted replacement and install it
uv run verify/verify.py update --topic github --new-secret ghp_new --sink dotenv:./.env#GITHUB_TOKEN

# generate a strong secret / evaluate a string's entropy
uv run verify/verify.py gen --bits 256
uv run verify/verify.py entropy 'correct horse battery staple'

# coverage
uv run verify/verify.py list
```

Highlights:

- **`check`** — live verifiers for 57 topics (GitHub, AWS SigV4, Slack, Stripe,
  OpenAI, Anthropic, GitLab, …), Kingfisher-style statuses (`active`,
  `inactive`, `locally-derived`, `invalid-material`, `unknown`, `unsupported`,
  `skipped`), provider auto-detection from the secret's shape, self-hosted
  endpoints (`--base-url`, `--endpoint`, `--endpoint-config`, `--insecure`),
  rate limiting (`--rps`), and **offline** validation of JWTs, private keys and
  credential connection strings.
- **`rotate`** — verify → revoke (self-revoke for Slack/GitLab/Dropbox) →
  replace (`--generate` for self-minted secrets such as Django/Rails/JWT keys)
  → install via a sink.
- **`update`** — installs a new secret into a sink (`stdout`, `file:`,
  `dotenv:`, `exec:`) only if it verifies as active.
- **`gen` / `entropy`** — CSPRNG secret generation and Shannon / pool-based
  entropy evaluation.
- **Audit ledger** — every change is appended to `secret-rotations.jsonl`
  (git-ignored, mode `0600`, fingerprints only by default).

Secrets are never followed across redirects and are only ever printed as
fingerprints unless explicitly requested. See [verify/README.md](verify/README.md)
for the full reference, the provider table, and how to add a verifier.

## The referential

`referential/rules.yaml` holds every rule with a canonical regex and merged
metadata:

```yaml
- uid: aws-access-token            # stable, human-readable id
  name: Aws Access Token
  topic: aws                       # provider/service grouping
  pattern: \b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b
  secret_group: 1                  # capture group holding the secret (0 = whole match)
  description: ...
  keywords: [a3t, akia, asia]      # prefilter literals (gitleaks/trufflehog)
  entropy: 3.0                     # minimum Shannon entropy threshold
  confidence: medium
  references: [...]
  examples: [...]                  # positive samples, used by the tests
  negative_examples: [...]
  sources:                         # provenance: which scanners ship this pattern
    - {scanner: gitleaks, id: aws-access-token}
    - {scanner: betterleaks, id: aws-access-token}
```

`referential/topics.yaml` indexes rule uids by topic, which backs the
`--topics` filter of the generator.

### Canonicalization & dedup

Source patterns target RE2 (gitleaks/betterleaks) or the Rust regex crate
(kingfisher/noseyparker/titus). Before dedup every pattern is canonicalized
(`secret_rules/normalize.py`):

- `(?x)` verbose patterns are flattened to one line (Rust semantics:
  whitespace is insignificant inside character classes too);
- `(?#...)` comment groups are stripped;
- named capture groups `(?P<name>...)` / `(?<name>...)` become plain groups,
  with the name kept aside (`secret_group_name`) for targets that want it
  back (titus, trufflehog);
- top-level mid-pattern flags (`foo(?i)bar`) are rewritten to the portable
  scoped form (`foo(?i:bar)`);
- leading flags are merged and emitted in a fixed order.

Two rules with the same canonical pattern are merged: provenance accumulates
in `sources`, keyword/example/reference lists are unioned, the lowest entropy
threshold wins (favoring recall), the highest confidence wins.

### Target-specific compatibility

Each generator only emits what its engine supports and reports anything it
skips in the file header:

- **gitleaks / betterleaks / trufflehog** (RE2): rules using lookarounds or
  backreferences are skipped. trufflehog *requires* keywords, so rules where
  no reliable literal can be extracted are skipped too.
- **noseyparker / titus**: patterns are guaranteed at least one capture
  group; titus additionally gets `base_score` (mapped from confidence) and a
  named secret group re-inserted.
- **YARA**: no inline flags (`(?i)` becomes the `nocase` modifier), `(?:`
  becomes `(`, lazy quantifiers become greedy (same match set; YARA forbids
  mixing them), rules using scoped flags/lookarounds/POSIX classes are
  skipped. The generated file compiles cleanly with `yara` 4.5.

## Tests

```sh
uv run pytest
```

Covers the normalizer (flattening, groups, flags), parser counts and fields,
dedup invariants (unique uids/patterns, topic index consistency), validity of
every generated config (TOML/YAML parse, per-target invariants), and two
functional checks: every rule's positive examples must match its canonical
pattern, and the generated YARA ruleset must compile with the real `yara`
binary and detect a planted AWS key (skipped when `yara` is not installed).

`tests/test_verify.py` covers the `verify/` tool without any network access
(a fake HTTP client): verifier outcomes per provider, AWS SigV4 signing,
self-revoke, shape sniffing, custom endpoints, offline JWT / private-key /
connection-URI validation, sinks, secret generation and entropy, and the audit
ledger.

## Layout

```
secret_rules/
  normalize.py        # regex canonicalization (the dedup key)
  model.py            # unified Rule model
  parsers/            # gitleaks, betterleaks, kingfisher, noseyparker, titus
  referential.py      # merge + dedup + rules.yaml/topics.yaml I/O
  generators/         # the 7 output targets
  cli.py              # build / generate / topics commands
verify/               # live verification, rotation, entropy (see verify/README.md)
rules/                # vendored source rulesets, one directory per scanner version
referential/          # generated referential (committed)
configs/              # generated scanner configs
tests/
```
