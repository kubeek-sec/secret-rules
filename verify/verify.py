#!/usr/bin/env python3
"""Verify, rotate, and re-install secrets detected by the secret-rules referential.

    # Is this secret live? (read-only — never triggers anything)
    uv run verify/verify.py check --topic github --secret ghp_xxx
    echo "$TOKEN" | uv run verify/verify.py check --topic slack --secret-stdin

    # Multi-part credentials
    uv run verify/verify.py check --topic aws --id AKIA... --secret <secret-access-key>
    uv run verify/verify.py check --topic twilio --id AC... --secret <auth-token>

    # Batch a scanner's output (one JSON object per line)
    uv run verify/verify.py check --input findings.jsonl

    # Remediation: show the rotation runbook (plan-only by default)
    uv run verify/verify.py rotate --topic slack --secret xoxb-...
    #   ...and actually self-revoke the leaked token (destructive, asks first):
    uv run verify/verify.py rotate --topic slack --secret xoxb-... --execute

    # Install a freshly minted replacement and confirm it works
    uv run verify/verify.py update --topic github --new-secret ghp_new \\
        --sink dotenv:./.env#GITHUB_TOKEN

    # What's covered?
    uv run verify/verify.py list
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

# Allow running both as `python verify/verify.py` and `python -m verify.verify`.
# When run as a script, sys.path[0] is this file's own directory, which would
# make `import verify` match the sibling verify.py instead of the package — so
# drop it (and cwd) and put the repo root first.
_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _p in (str(_HERE), ""):
    while _p in sys.path:
        sys.path.remove(_p)
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import verify  # noqa: F401,E402  (registers verifiers + rotators)
from verify import ledger, strength  # noqa: E402
from verify.core import (  # noqa: E402
    ACTIVE,
    LOCALLY_DERIVED,
    PLANNED,
    ROTATORS,
    SKIPPED,
    UNSUPPORTED,
    VERIFIERS,
    HttpClient,
    Result,
    fingerprint,
    load_rules,
    resolve_topic,
    sniff_topic,
)

# statuses that count as "the secret is good" for exit codes / filtering
_GOOD = (ACTIVE, LOCALLY_DERIVED)
from verify.sinks import SinkError, write_sink  # noqa: E402


# --------------------------------------------------------------------------- #
# secret / selector resolution
# --------------------------------------------------------------------------- #

def _read_secret(args, *, new: bool = False) -> str | None:
    import os
    val = args.new_secret if new else args.secret
    env = args.new_secret_env if new else args.secret_env
    stdin = args.new_secret_stdin if new else args.secret_stdin
    if val is not None:
        return val
    if env:
        v = os.environ.get(env)
        if v is None:
            raise SystemExit(f"error: env var {env} is not set")
        return v
    if stdin:
        # read all of stdin so multi-line secrets (PEM private keys) survive;
        # strip only the trailing newline a shell/echo appends.
        return sys.stdin.read().rstrip("\n")
    return None


def _extra_from_args(args) -> dict:
    extra: dict = {}
    if getattr(args, "id", None):
        extra["id"] = args.id
    if getattr(args, "session_token", None):
        extra["session_token"] = args.session_token
    for pair in getattr(args, "field", None) or []:
        k, _, v = pair.partition("=")
        if not v:
            raise SystemExit(f"error: --field expects key=value, got {pair!r}")
        extra[k.strip()] = v
    if getattr(args, "base_url", None):
        extra["endpoint"] = args.base_url
    return extra


def _apply_topic_endpoint(extra: dict, topic: str, endpoints: dict) -> None:
    """Fill extra['endpoint'] from the per-topic map when --base-url wasn't given."""
    if not extra.get("endpoint") and endpoints.get(topic):
        extra["endpoint"] = endpoints[topic]


def _resolve_topic(args, rules, secret: str | None) -> str:
    topic, _rule = resolve_topic(rules, uid=getattr(args, "uid", None),
                                 topic=getattr(args, "topic", None))
    if topic:
        return topic
    if secret:
        hits = sniff_topic(secret)
        if len(hits) == 1:
            print(f"(auto-detected topic: {hits[0]})", file=sys.stderr)
            return hits[0]
        if len(hits) > 1:
            raise SystemExit(f"error: ambiguous — matches {', '.join(hits)}; pass --topic")
    raise SystemExit("error: specify --topic or --uid (auto-detection found no match)")


# --------------------------------------------------------------------------- #
# core verification
# --------------------------------------------------------------------------- #

def _verify(topic: str, secret: str, extra: dict, http: HttpClient) -> Result:
    spec = VERIFIERS.get(topic)
    if spec is None:
        return Result(topic, UNSUPPORTED,
                      detail="no verifier for this topic — check the provider console manually")
    missing = [f for f in spec.needs if not extra.get(f)]
    if missing:
        hints = "; ".join(spec.companion_help.get(f, f) for f in missing)
        return Result(topic, SKIPPED, detail=f"missing required input: {hints}")
    res = spec.func(secret, extra, http)
    res.topic = topic  # a verifier may serve several topics; report the one asked for
    return res


def _print_result_labeled(label: str, res: Result, secret: str | None = None) -> None:
    print(label)
    _print_result(res, secret)


def _print_result(res: Result, secret: str | None = None) -> None:
    head = f"[{res.topic}]"
    if secret:
        head += f" {fingerprint(secret)}"
    line = f"{res.label:<14} {head}"
    if res.detail:
        line += f" — {res.detail}"
    print(line)
    if res.identity:
        ident = {k: v for k, v in res.identity.items() if v is not None}
        if ident:
            print(f"               identity: {json.dumps(ident, ensure_ascii=False)}")
    if res.endpoint:
        print(f"               endpoint: {res.endpoint}")


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_check(args) -> int:
    rules = load_rules(args.referential)
    http = _client(args)

    if args.input:
        return _check_batch(args, rules, http)

    secret = _read_secret(args)
    if secret is None:
        raise SystemExit("error: provide --secret / --secret-stdin / --secret-env (or --input)")
    topic = _resolve_topic(args, rules, secret)
    extra = _extra_from_args(args)
    _apply_topic_endpoint(extra, topic, _endpoints_from_args(args))
    res = _verify(topic, secret, extra, http)

    if args.json:
        print(json.dumps(res.to_dict(), ensure_ascii=False))
    else:
        _print_result(res, secret)
    return 0 if res.status in _GOOD + (PLANNED,) else 1


def _check_batch(args, rules, http) -> int:
    endpoints = _endpoints_from_args(args)
    results = []
    worst = 0
    for lineno, raw in enumerate(pathlib.Path(args.input).read_text().splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            print(f"error: line {lineno}: not valid JSON", file=sys.stderr)
            worst = 2
            continue
        secret = obj.get("secret")
        topic = obj.get("topic")
        if not topic and obj.get("uid"):
            topic, _ = resolve_topic(rules, uid=obj["uid"], topic=None)
        if not topic and secret:
            hits = sniff_topic(secret)
            topic = hits[0] if len(hits) == 1 else None
        if not topic or secret is None:
            print(f"error: line {lineno}: need 'secret' and 'topic'/'uid'", file=sys.stderr)
            worst = 2
            continue
        extra = {k: v for k, v in obj.items() if k not in {"secret", "topic", "uid"}}
        _apply_topic_endpoint(extra, topic, endpoints)
        res = _verify(topic, secret, extra, http)
        if args.only_active and res.status not in _GOOD:
            continue
        results.append(res)
        if res.status not in _GOOD:
            worst = max(worst, 1)
    if args.json:
        print(json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2))
    else:
        for r in results:
            _print_result(r)
        good = sum(1 for r in results if r.status in _GOOD)
        print(f"\n{good}/{len(results)} verified active/valid", file=sys.stderr)
    return worst


def _new_value(args, rot) -> tuple[str | None, bool]:
    """Decide the replacement value: generate it when that's meaningful,
    otherwise fall back to a value the user provided."""
    provided = _read_secret(args, new=True)
    if not args.generate:
        return provided, False
    if rot is not None and rot.mint == "self" or args.force_generate:
        spec = (rot.gen_spec if rot else {}) or {}
        value = strength.generate(
            length=spec.get("length"), bits=spec.get("bits"),
            charset=spec.get("charset", strength.DEFAULT_CHARSET),
        )
        return value, True
    print("   note: this provider mints its own tokens — a locally generated value "
          "won't be accepted. Keeping the provided value (if any); "
          "use --force-generate only for self-controlled secrets.")
    return provided, False


def cmd_rotate(args) -> int:
    rules = load_rules(args.referential)
    http = _client(args)
    secret = _read_secret(args)
    topic = _resolve_topic(args, rules, secret)
    extra = _extra_from_args(args)
    _apply_topic_endpoint(extra, topic, _endpoints_from_args(args))

    print(f"== Rotating [{topic}] ==")
    # 1. Verify the current secret so we know what we're dealing with.
    if secret:
        _print_result_labeled("1. Current secret:", _verify(topic, secret, extra, http), secret)
    else:
        print("1. Current secret: (not provided — skipping live check)")

    rot = ROTATORS.get(topic)
    if rot is None:
        print(f"\nNo rotation runbook for '{topic}'. Rotate it in the provider console.")
        return 1

    # 2. Revoke the leaked credential.
    revoked_status = None
    print("\n2. Revoke the leaked credential:")
    print(f"   console: {rot.revoke_console}")
    if rot.self_revoke and secret:
        print(f"   self-revoke available: {rot.self_revoke_desc}")
        if args.execute and args.dry_run:
            print("   (dry-run: would self-revoke, but no request is sent)")
        elif args.execute:
            if _confirm(args, f"Revoke this {topic} credential now? This is irreversible."):
                rev = rot.self_revoke(secret, extra, http)
                _print_result(rev)
                revoked_status = rev.status
            else:
                print("   (skipped — not confirmed)")
        else:
            print("   run again with --execute to perform the self-revoke")
    elif rot.self_revoke:
        print(f"   self-revoke available ({rot.self_revoke_desc}) — provide the secret to use it")

    # 3. Determine the replacement value.
    print("\n3. Mint a replacement:")
    print(f"   {rot.create_doc}")
    if rot.notes:
        print(f"   note: {rot.notes}")
    new_value, generated = _new_value(args, rot)
    if generated:
        bits = strength.estimated_bits(new_value)
        print(f"   generated a {len(new_value)}-char value (~{bits:.0f} bits of entropy).")

    # 4. Install + record.
    verified_status, installed_sink = _place_new_value(args, topic, new_value, generated, extra, http)

    if not args.dry_run and not args.no_ledger and (
        generated or installed_sink or revoked_status or new_value is not None
    ):
        dest = args.ledger or ledger.DEFAULT_LEDGER
        ledger.record(
            dest, action="rotate", topic=topic, uid=args.uid,
            old_secret=secret, new_secret=new_value, generated=generated,
            new_entropy_bits=strength.estimated_bits(new_value) if new_value else None,
            verified=verified_status, revoked=revoked_status, sink=installed_sink,
            record_secret=args.record_secret,
        )
        print(f"\nrecorded change to ledger: {dest}")
    return 0


def _place_new_value(args, topic, new_value, generated, extra, http):
    """Show / install the replacement. Returns (verified_status, installed_sink)."""
    if new_value is None:
        print("\n4. Install the new value:")
        print(f"   uv run {_prog()} update --topic {topic} --new-secret <NEW> "
              f"--sink dotenv:./.env#VAR")
        return None, None

    verified_status = None
    if args.sink:
        res = _verify(topic, new_value, extra, http)
        verified_status = res.status
        print("\n4. Install the new value:")
        _print_result(res, new_value)
        if args.dry_run:
            print(f"   [dry-run] would write new value to sink: {args.sink}")
            return verified_status, None
        rot = ROTATORS.get(topic)
        ok = res.status in _GOOD or args.force or (rot is not None and rot.mint == "self")
        if ok:
            try:
                print(f"   {write_sink(args.sink, new_value, show=args.show)}")
                return verified_status, args.sink
            except SinkError as e:
                print(f"   error: {e}", file=sys.stderr)
        else:
            print("   not installed (did not verify as active; pass --force)", file=sys.stderr)
        return verified_status, None

    # No sink: surface the value so it can be used.
    print("\n4. New value:")
    if args.show or generated:
        print(f"   {new_value}")
    else:
        print(f"   {fingerprint(new_value)}  (pass --show to print it, or --sink to install)")
    print(f"   install with: uv run {_prog()} update --topic {topic} "
          f"--new-secret <NEW> --sink dotenv:./.env#VAR")
    return verified_status, None


def cmd_update(args) -> int:
    rules = load_rules(args.referential)
    http = _client(args)
    new_secret = _read_secret(args, new=True)
    if new_secret is None:
        raise SystemExit("error: provide --new-secret / --new-secret-stdin / --new-secret-env")
    topic = _resolve_topic(args, rules, new_secret)
    extra = _extra_from_args(args)
    _apply_topic_endpoint(extra, topic, _endpoints_from_args(args))

    # Verify the replacement actually works before installing it.
    res = _verify(topic, new_secret, extra, http)
    print("New secret check:")
    _print_result(res, new_secret)

    if args.dry_run:
        print(f"[dry-run] would write new value to sink: {args.sink}")
        return 0

    if res.status not in _GOOD and not args.force:
        if res.status in (UNSUPPORTED, SKIPPED, PLANNED):
            print(f"warning: could not verify ({res.status}); pass --force to install anyway",
                  file=sys.stderr)
        else:
            print("refusing to install a non-working secret; pass --force to override",
                  file=sys.stderr)
        return 1

    try:
        msg = write_sink(args.sink, new_secret, show=args.show)
    except SinkError as e:
        raise SystemExit(f"error: {e}")
    print(msg)
    if not args.no_ledger:
        dest = args.ledger or ledger.DEFAULT_LEDGER
        ledger.record(dest, action="update", topic=topic, uid=args.uid,
                      new_secret=new_secret,
                      new_entropy_bits=strength.estimated_bits(new_secret),
                      verified=res.status, sink=args.sink,
                      record_secret=args.record_secret)
        print(f"recorded change to ledger: {dest}")
    return 0 if res.status in _GOOD or args.force else 1


def cmd_gen(args) -> int:
    try:
        values = [strength.generate(length=args.length, bits=args.bits, charset=args.charset)
                  for _ in range(max(1, args.count))]
    except ValueError as e:
        raise SystemExit(f"error: {e}")
    for v in values:
        if args.json:
            print(json.dumps(strength.evaluate(v).to_dict() | {"value": v}))
        else:
            print(v)
    return 0


def cmd_entropy(args) -> int:
    value = args.value
    if value is None and args.stdin:
        value = sys.stdin.readline().rstrip("\n")
    if value is None:
        raise SystemExit("error: provide a string argument or --stdin")
    st = strength.evaluate(value)
    if args.json:
        print(json.dumps(st.to_dict(), indent=2))
        return 0
    print(f"length:           {st.length}")
    print(f"charset pool:     {st.pool}")
    print(f"Shannon entropy:  {st.shannon_per_char:.2f} bits/char "
          f"({st.shannon_total:.0f} bits over the observed string)")
    print(f"estimated bits:   {st.estimated_bits:.0f}  (length × log2(pool); "
          f"assumes the value is random)")
    print(f"verdict:          {st.verdict} — {st.advice}")
    return 0


def cmd_list(args) -> int:
    rows = []
    for topic in sorted(set(VERIFIERS) | set(ROTATORS)):
        spec = VERIFIERS.get(topic)
        rot = ROTATORS.get(topic)
        check = spec.doc if spec else "(no live check — can't verify remotely)"
        needs = f" needs:{','.join(spec.needs)}" if spec and spec.needs else ""
        if spec and spec.endpoint:
            needs += " [self-hostable]"
        if rot is None:
            rot_mark = "—"
        elif rot.mint == "self":
            rot_mark = "generate"
        elif rot.self_revoke:
            rot_mark = "self-revoke"
        else:
            rot_mark = "runbook"
        rows.append((topic, check, rot_mark, needs))
    if args.json:
        print(json.dumps([
            {"topic": t, "check": d, "rotate": r, "needs": n.strip()} for t, d, r, n in rows
        ], indent=2))
        return 0
    print(f"{'TOPIC':<18} {'ROTATE':<12} CHECK")
    for topic, doc, rot_mark, needs in rows:
        print(f"{topic:<18} {rot_mark:<12} {doc}{needs}")
    print(f"\n{sum(1 for t in rows if t[0] in VERIFIERS)} topics with a verifier; "
          f"{sum(1 for t in rows if t[2] == 'generate')} self-minted (generate locally); "
          f"{sum(1 for t in rows if t[2] != '—')} with rotation guidance.")
    return 0


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _confirm(args, prompt: str) -> bool:
    if args.yes:
        return True
    if not sys.stdin.isatty():
        print(f"   {prompt} (non-interactive; pass --yes to proceed) — skipping", file=sys.stderr)
        return False
    return input(f"   {prompt} [y/N] ").strip().lower() in {"y", "yes"}


def _prog() -> str:
    return "verify/verify.py"


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout seconds")
    p.add_argument("--dry-run", action="store_true",
                   help="show the request(s) that would be sent; contact nothing")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--referential", type=pathlib.Path, default=None,
                   help="path to referential/rules.yaml (default: repo copy)")
    g = p.add_argument_group("endpoints & network (self-hosted / on-prem)")
    g.add_argument("--base-url", help="override the API base for the selected topic "
                   "(e.g. on-prem GitLab: https://gitlab.corp.example.com)")
    g.add_argument("--endpoint", action="append", metavar="TOPIC=URL",
                   help="per-topic base override (repeatable; for batch mode)")
    g.add_argument("--endpoint-config", type=pathlib.Path,
                   help="YAML file with an `endpoints: {topic: url}` mapping")
    g.add_argument("--insecure", action="store_true",
                   help="accept self-signed / private-CA TLS certs (trust downgrade)")
    g.add_argument("--rps", type=float, help="global requests-per-second cap across validators")


def _endpoints_from_args(args) -> dict:
    """Collect per-topic base-URL overrides from --endpoint / --endpoint-config."""
    import yaml
    endpoints: dict = {}
    cfg = getattr(args, "endpoint_config", None)
    if cfg:
        data = yaml.safe_load(pathlib.Path(cfg).read_text()) or {}
        endpoints.update(data.get("endpoints", {}))
    for pair in getattr(args, "endpoint", None) or []:
        topic, _, url = pair.partition("=")
        if not url:
            raise SystemExit(f"error: --endpoint expects TOPIC=URL, got {pair!r}")
        endpoints[topic.strip()] = url
    return endpoints


def _client(args) -> HttpClient:
    return HttpClient(timeout=args.timeout, dry_run=args.dry_run,
                      insecure=getattr(args, "insecure", False),
                      rps=getattr(args, "rps", None))


def _add_selector(p: argparse.ArgumentParser) -> None:
    p.add_argument("--topic", help="provider topic (as in rules.yaml)")
    p.add_argument("--uid", help="rule uid (resolves to its topic)")
    p.add_argument("--id", help="companion id (AWS access key id, Twilio SID, CF email, ...)")
    p.add_argument("--session-token", help="AWS session token for temporary ASIA... keys")
    p.add_argument("--field", action="append", metavar="K=V",
                   help="extra companion field (repeatable)")


def _add_secret_src(p: argparse.ArgumentParser, *, new: bool = False) -> None:
    pre = "new-secret" if new else "secret"
    dest = "new_secret" if new else "secret"
    g = p.add_argument_group(f"{pre} input")
    g.add_argument(f"--{pre}", dest=dest, help=f"the {pre} value (beware shell history)")
    g.add_argument(f"--{pre}-stdin", dest=f"{dest}_stdin", action="store_true",
                   help=f"read the {pre} from one line of stdin")
    g.add_argument(f"--{pre}-env", dest=f"{dest}_env", metavar="VAR",
                   help=f"read the {pre} from environment variable VAR")


def _add_ledger(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("audit ledger")
    g.add_argument("--ledger", type=pathlib.Path, default=None,
                   help="ledger path (default: repo secret-rotations.jsonl, git-ignored)")
    g.add_argument("--no-ledger", action="store_true", help="do not record this change")
    g.add_argument("--record-secret", action="store_true",
                   help="also store the new value in plaintext in the ledger (sensitive)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("check", help="verify a secret is live (read-only)")
    _add_common(pc); _add_selector(pc); _add_secret_src(pc)
    pc.add_argument("--input", help="JSONL file of {topic|uid, secret, ...} to batch-check")
    pc.add_argument("--only-active", action="store_true",
                    help="(batch) report only active/valid findings")
    pc.set_defaults(func=cmd_check)

    pr = sub.add_parser("rotate", help="verify, revoke, (re)generate & install a secret")
    _add_common(pr); _add_selector(pr)
    _add_secret_src(pr)              # the CURRENT (leaked) secret
    _add_secret_src(pr, new=True)    # the replacement, if you supply one
    _add_ledger(pr)
    pr.add_argument("--execute", action="store_true",
                    help="perform the self-revoke where available (destructive)")
    pr.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    pr.add_argument("--generate", action="store_true",
                    help="generate a high-entropy replacement when the secret is self-minted")
    pr.add_argument("--force-generate", action="store_true",
                    help="generate even for provider-minted topics (you know it's self-controlled)")
    pr.add_argument("--sink", help="install the new value: file:PATH | dotenv:PATH#VAR | exec:CMD | stdout")
    pr.add_argument("--show", action="store_true", help="allow printing the new value")
    pr.add_argument("--force", action="store_true", help="install even if the new value won't verify")
    pr.set_defaults(func=cmd_rotate)

    pu = sub.add_parser("update", help="verify a new value and install it into a sink")
    _add_common(pu); _add_selector(pu); _add_secret_src(pu, new=True); _add_ledger(pu)
    pu.add_argument("--sink", required=True,
                    help="stdout | file:PATH | dotenv:PATH#VAR | exec:COMMAND")
    pu.add_argument("--show", action="store_true", help="allow printing the value (stdout sink)")
    pu.add_argument("--force", action="store_true", help="install even if verification fails")
    pu.set_defaults(func=cmd_update)

    pg = sub.add_parser("gen", help="generate a cryptographically-secure random secret")
    pg.add_argument("--length", type=int, help="number of characters")
    pg.add_argument("--bits", type=float, help="target entropy in bits (default 256)")
    pg.add_argument("--charset", default=strength.DEFAULT_CHARSET,
                    choices=list(strength.CHARSETS), help="alphabet to draw from")
    pg.add_argument("--count", type=int, default=1, help="how many to generate")
    pg.add_argument("--json", action="store_true", help="emit value + strength as JSON")
    pg.set_defaults(func=cmd_gen)

    pe = sub.add_parser("entropy", help="evaluate the entropy / strength of a string")
    pe.add_argument("value", nargs="?", help="the string to evaluate")
    pe.add_argument("--stdin", action="store_true", help="read the string from stdin")
    pe.add_argument("--json", action="store_true")
    pe.set_defaults(func=cmd_entropy)

    pl = sub.add_parser("list", help="list topics with verifiers / rotation support")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
