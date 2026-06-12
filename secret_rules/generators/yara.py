"""Generate YARA rules from the referential.

YARA's regex engine is more limited than RE2/Rust regex:

- no inline flags: a leading ``(?i)`` becomes the ``nocase`` modifier, but
  scoped flags like ``(?i:...)`` and ``(?s)``/``(?m)``/``(?U)`` patterns
  have no equivalent and those rules are skipped;
- no named or non-capturing groups: ``(?:`` is rewritten to ``(`` (capture
  vs non-capture makes no difference to YARA matching);
- greedy and lazy quantifiers cannot be mixed in one regex: lazy quantifiers
  are rewritten as greedy, which matches the same set of inputs (only the
  match extent differs, which YARA does not report anyway);
- no POSIX classes or lookarounds: those rules are skipped.

Skipped rules are listed in the file header.
"""

from __future__ import annotations

import re

from secret_rules.model import Rule

from ._common import header, split_leading_flags

FILENAME = "secret_rules.yar"

_IDENT_RE = re.compile(r"[^A-Za-z0-9_]")
# any (?...) construct other than a plain group: scoped flags, lookarounds,
# named groups, conditionals... none are supported by YARA
_UNSUPPORTED_GROUP = re.compile(r"\(\?")
_POSIX_CLASS = re.compile(r"\[\[:")
_BACKREF = re.compile(r"\\[1-9]")


def _degreedify(body: str) -> str:
    """Rewrite lazy quantifiers (``*?``, ``+?``, ``??``, ``{n,m}?``) as greedy."""
    out: list[str] = []
    i, n = 0, len(body)
    in_class = False
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            out.append(body[i : i + 2])
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            continue
        out.append(c)
        if c in "*+?}" and i + 1 < n and body[i + 1] == "?":
            i += 2
            continue
        i += 1
    return "".join(out)


def _sanitize(pattern: str) -> tuple[str | None, bool]:
    """Return (yara-safe pattern, nocase) or (None, False) if untranslatable."""
    flags, body = split_leading_flags(pattern)
    if set(flags) - {"i"}:
        return None, False
    body = body.replace("(?:", "(")
    if _UNSUPPORTED_GROUP.search(body) or _POSIX_CLASS.search(body) or _BACKREF.search(body):
        return None, False
    body = _degreedify(body)
    body = _escape_slashes(body)
    if not body or body in ("^", "$"):
        return None, False
    return body, "i" in flags


def _escape_slashes(body: str) -> str:
    """Escape regex delimiters, leaving already-escaped ``\\/`` untouched."""
    out: list[str] = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            out.append(body[i : i + 2])
            i += 2
            continue
        out.append("\\/" if c == "/" else c)
        i += 1
    return "".join(out)


def _identifier(uid: str) -> str:
    ident = _IDENT_RE.sub("_", uid)
    if ident[0].isdigit():
        ident = "sr_" + ident
    return ident


def _meta_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def generate(rules: list[Rule]) -> str:
    blocks: list[str] = []
    skipped: list[str] = []
    for rule in rules:
        pattern, nocase = _sanitize(rule.pattern)
        if pattern is None:
            skipped.append(rule.uid)
            continue
        modifiers = " nocase" if nocase else ""
        sources = ", ".join(f"{s.scanner}:{s.id}" for s in rule.sources)
        meta = [
            f'        name = "{_meta_escape(rule.name)}"',
            f'        topic = "{_meta_escape(rule.topic)}"',
            f'        sources = "{_meta_escape(sources)}"',
        ]
        if rule.confidence:
            meta.append(f'        confidence = "{rule.confidence}"')
        blocks.append(
            f"rule {_identifier(rule.uid)}\n"
            "{\n"
            "    meta:\n" + "\n".join(meta) + "\n"
            "    strings:\n"
            f"        $re = /{pattern}/{modifiers}\n"
            "    condition:\n"
            "        $re\n"
            "}\n"
        )
    # YARA comments are //-style, not #
    head = header("yara", len(blocks), skipped).replace("#", "//")
    return head + "\n".join(blocks)
