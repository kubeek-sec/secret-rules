"""secret-rules command line interface.

Commands:
  build      parse the source rulesets and write the referential files
  generate   produce native configs for one or more scanners
  topics     list available topics and their rule counts
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from .generators import TARGETS
from .referential import build_rules, load_referential, write_referential


def _cmd_build(args: argparse.Namespace) -> int:
    rules = build_rules(args.rules_dir)
    rules_path, topics_path = write_referential(rules, args.out)
    print(f"referential: {len(rules)} deduplicated rules")
    print(f"  {rules_path}")
    print(f"  {topics_path}")
    return 0


def _load(args: argparse.Namespace):
    path = args.referential
    if not path.exists():
        print(f"error: referential not found at {path}; run `secret-rules build` first", file=sys.stderr)
        sys.exit(2)
    return load_referential(path)


def _cmd_generate(args: argparse.Namespace) -> int:
    rules = _load(args)
    if args.topics:
        wanted = {t.strip() for t in args.topics.split(",") if t.strip()}
        unknown = wanted - {r.topic for r in rules}
        if unknown:
            print(f"error: unknown topics: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        rules = [r for r in rules if r.topic in wanted]
        if not rules:
            print("error: no rules match the requested topics", file=sys.stderr)
            return 2

    targets = list(TARGETS) if args.target == "all" else [t.strip() for t in args.target.split(",")]
    unknown = set(targets) - set(TARGETS)
    if unknown:
        print(f"error: unknown targets: {', '.join(sorted(unknown))} (known: {', '.join(TARGETS)})", file=sys.stderr)
        return 2

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for target in targets:
        module = TARGETS[target]
        content = module.generate(rules)
        out_path = args.out_dir / module.FILENAME
        out_path.write_text(content)
        note = ""
        m = re.search(r"skipped \(incompatible with \w+\): (\d+)", content)
        if m:
            note = f" ({m.group(1)} incompatible rules skipped)"
        print(f"{target}: {out_path}{note}")
    return 0


def _cmd_topics(args: argparse.Namespace) -> int:
    rules = _load(args)
    counts: dict[str, int] = {}
    for rule in rules:
        counts[rule.topic] = counts.get(rule.topic, 0) + 1
    for topic, count in sorted(counts.items()):
        print(f"{topic}\t{count}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secret-rules", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="build the deduplicated referential from rules/")
    p_build.add_argument("--rules-dir", type=Path, default=Path("rules"))
    p_build.add_argument("--out", type=Path, default=Path("referential"))
    p_build.set_defaults(func=_cmd_build)

    p_gen = sub.add_parser("generate", help="generate scanner configs from the referential")
    p_gen.add_argument("--target", default="all", help=f"comma-separated targets or 'all' ({', '.join(TARGETS)})")
    p_gen.add_argument("--topics", help="comma-separated topics to include (default: all)")
    p_gen.add_argument("--referential", type=Path, default=Path("referential/rules.yaml"))
    p_gen.add_argument("--out-dir", type=Path, default=Path("configs"))
    p_gen.set_defaults(func=_cmd_generate)

    p_topics = sub.add_parser("topics", help="list topics in the referential")
    p_topics.add_argument("--referential", type=Path, default=Path("referential/rules.yaml"))
    p_topics.set_defaults(func=_cmd_topics)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
