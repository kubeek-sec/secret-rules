"""Regex canonicalization across scanner flavors.

Source rulesets target RE2 (gitleaks, betterleaks, trufflehog) or the Rust
regex crate (kingfisher, noseyparker, titus).  Both engines share a common
dialect except for:

- extended/verbose mode ``(?x)``: supported by Rust, not by Go's RE2 — so
  patterns are flattened (whitespace and ``#`` comments removed) following
  Rust semantics, where whitespace is ignored *inside character classes too*.
- named groups: ``(?P<name>...)`` and ``(?<name>...)`` are converted to plain
  capture groups; names are kept aside so generators that want them (titus,
  trufflehog) can re-insert them.

The canonical form (flattened, unnamed groups, leading flags in a fixed
order) is also the deduplication key for the referential.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_WS = " \t\n\r\f\v"
_LEADING_FLAGS = re.compile(r"^\(\?([a-zA-Z-]+)\)")
_NAMED_OPEN = re.compile(r"\?P?<([A-Za-z_][A-Za-z0-9_]*)>")


@dataclass
class CanonResult:
    pattern: str  # canonical pattern, flags inlined as a single leading group
    flags: str  # canonical flag letters (subset of "imsU"), sorted
    group_names: dict[int, str] = field(default_factory=dict)  # 1-based index -> name


def _extract_leading_flags(pattern: str) -> tuple[set[str], set[str], str]:
    """Pull off leading global flag groups like ``(?xi)`` or ``(?x)(?i)``.

    Returns (enabled flags, disabled flags, remainder).
    """
    enabled: set[str] = set()
    disabled: set[str] = set()
    rest = pattern
    while True:
        m = _LEADING_FLAGS.match(rest)
        if not m:
            break
        spec = m.group(1)
        if "-" in spec:
            on, _, off = spec.partition("-")
            enabled.update(on)
            disabled.update(off)
        else:
            enabled.update(spec)
        rest = rest[m.end() :]
    return enabled, disabled, rest


def _flatten_extended(body: str) -> str:
    """Remove insignificant whitespace and ``#`` comments from an (?x) body.

    Follows Rust regex crate semantics: whitespace is ignored everywhere,
    including inside character classes; ``\\ `` is a literal space.
    """
    out: list[str] = []
    i = 0
    in_class = False
    class_start = -1
    n = len(body)
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            nxt = body[i + 1]
            if nxt == " ":
                out.append(" ")
            elif nxt == "#" and not in_class:
                out.append("#")
            else:
                out.append(body[i : i + 2])
            i += 2
            continue
        if in_class:
            if c == "]" and i > class_start + (2 if body.startswith("[^", class_start) else 1):
                in_class = False
                out.append(c)
            elif c in _WS:
                pass
            else:
                out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            class_start = i
            out.append(c)
            i += 1
            continue
        if body.startswith("(?#", i):
            # PCRE comment group: runs to the first ')', drop it entirely
            end = body.find(")", i)
            i = n if end == -1 else end + 1
            continue
        if c in _WS:
            i += 1
            continue
        if c == "#":
            while i < n and body[i] != "\n":
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _strip_comment_groups(body: str) -> str:
    """Drop PCRE ``(?#...)`` comment groups (unsupported by RE2 and Python)."""
    out: list[str] = []
    i, n = 0, len(body)
    in_class = False
    class_start = -1
    while i < n:
        c = body[i]
        if c == "\\" and i + 1 < n:
            out.append(body[i : i + 2])
            i += 2
            continue
        if in_class:
            if c == "]" and i > class_start + (2 if body.startswith("[^", class_start) else 1):
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            class_start = i
            out.append(c)
            i += 1
            continue
        if body.startswith("(?#", i):
            end = body.find(")", i)
            i = n if end == -1 else end + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


_MID_FLAGS = re.compile(r"\(\?([a-zA-Z]*-?[a-zA-Z]+)\)")


def _scope_midpattern_flags(body: str) -> str:
    """Rewrite top-level mid-pattern global flags as scoped groups.

    RE2/Rust accept ``foo(?i)bar`` (flags apply to the rest of the group);
    Python and YARA do not.  At nesting depth 0 the equivalent scoped form
    ``foo(?i:bar)`` is valid everywhere.  Innermost-last occurrences are
    rewritten first so multiple flag groups nest correctly.
    """
    for _ in range(10):
        # locate the last top-level occurrence
        depth = 0
        in_class = False
        class_start = -1
        target = None
        i, n = 0, len(body)
        while i < n:
            c = body[i]
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if in_class:
                if c == "]" and i > class_start + (2 if body.startswith("[^", class_start) else 1):
                    in_class = False
                i += 1
                continue
            if c == "[":
                in_class = True
                class_start = i
                i += 1
                continue
            if c == "(":
                m = _MID_FLAGS.match(body, i)
                if m and depth == 0 and i > 0:
                    target = m
                    i = m.end()
                    continue
                if not body.startswith("(?#", i):
                    depth += 1
                i += 1
                continue
            if c == ")":
                depth -= 1
                i += 1
                continue
            i += 1
        if target is None:
            return body
        body = f"{body[: target.start()]}(?{target.group(1)}:{body[target.end():]})"
    return body


def capture_groups(pattern: str) -> list[tuple[int, str | None]]:
    """List capture groups as (1-based index, name or None), in order.

    Understands ``(?P<name>...)`` and ``(?<name>...)``; skips non-capturing
    groups, inline-flag groups and lookarounds.
    """
    groups: list[tuple[int, str | None]] = []
    i = 0
    n = len(pattern)
    in_class = False
    class_start = -1
    idx = 0
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]" and i > class_start + (2 if pattern.startswith("[^", class_start) else 1):
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            class_start = i
            i += 1
            continue
        if c == "(":
            if pattern.startswith("(?", i):
                m = _NAMED_OPEN.match(pattern, i + 1)
                if m and not pattern.startswith(("(?<=", "(?<!"), i):
                    idx += 1
                    groups.append((idx, m.group(1)))
                    i = m.end()
                    continue
                # (?:, (?i), (?i:..., lookarounds: not capturing
                i += 2
                continue
            idx += 1
            groups.append((idx, None))
            i += 1
            continue
        i += 1
    return groups


def strip_group_names(pattern: str) -> tuple[str, dict[int, str]]:
    """Convert named capture groups to plain ones; return (pattern, names)."""
    names: dict[int, str] = {}
    out: list[str] = []
    i = 0
    n = len(pattern)
    in_class = False
    class_start = -1
    idx = 0
    while i < n:
        c = pattern[i]
        if c == "\\":
            out.append(pattern[i : i + 2])
            i += 2
            continue
        if in_class:
            if c == "]" and i > class_start + (2 if pattern.startswith("[^", class_start) else 1):
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            class_start = i
            out.append(c)
            i += 1
            continue
        if c == "(":
            if pattern.startswith("(?", i):
                m = _NAMED_OPEN.match(pattern, i + 1)
                if m and not pattern.startswith(("(?<=", "(?<!"), i):
                    idx += 1
                    names[idx] = m.group(1)
                    out.append("(")
                    i = m.end()
                    continue
                out.append(c)
                i += 1
                continue
            idx += 1
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out), names


def insert_group_name(pattern: str, group_index: int, name: str) -> str:
    """Rewrite the Nth plain capture group as ``(?P<name>...)``."""
    out: list[str] = []
    i = 0
    n = len(pattern)
    in_class = False
    class_start = -1
    idx = 0
    while i < n:
        c = pattern[i]
        if c == "\\":
            out.append(pattern[i : i + 2])
            i += 2
            continue
        if in_class:
            if c == "]" and i > class_start + (2 if pattern.startswith("[^", class_start) else 1):
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            class_start = i
            out.append(c)
            i += 1
            continue
        if c == "(" and not pattern.startswith("(?", i):
            idx += 1
            if idx == group_index:
                out.append(f"(?P<{name}>")
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def canonicalize(pattern: str) -> CanonResult:
    """Produce the canonical single-line, unnamed-group form of a pattern."""
    enabled, _disabled, body = _extract_leading_flags(pattern)
    if "x" in enabled:
        body = _flatten_extended(body)
        enabled.discard("x")
    else:
        body = _strip_comment_groups(body)
    body = _scope_midpattern_flags(body)
    body, names = strip_group_names(body)
    flags = "".join(sorted(enabled & set("imsU")))
    canonical = (f"(?{flags})" if flags else "") + body
    return CanonResult(pattern=canonical, flags=flags, group_names=names)
