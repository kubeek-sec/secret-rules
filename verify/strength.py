"""Entropy evaluation and cryptographically-secure secret generation.

Two jobs:

- ``evaluate(s)`` — describe how strong a string is: its observed Shannon
  entropy, and a pool-based bit estimate (``length × log2(charset)``) with a
  verdict.  The pool estimate assumes the string was chosen *randomly* from the
  character classes it uses; for human-chosen passwords it is an upper bound,
  because dictionary words and patterns carry far less real entropy.

- ``generate(...)`` — mint a new random secret using :mod:`secrets` (a CSPRNG),
  sized by target bits or explicit length.
"""

from __future__ import annotations

import math
import secrets
import string
from collections import Counter
from dataclasses import dataclass

# Character pools usable for generation (and for naming classes in evaluate()).
CHARSETS = {
    "base62": string.ascii_letters + string.digits,
    "alnum": string.ascii_letters + string.digits,
    "hex": "0123456789abcdef",
    "base64url": string.ascii_letters + string.digits + "-_",
    "ascii": string.ascii_letters + string.digits + string.punctuation,
}
DEFAULT_CHARSET = "base62"
DEFAULT_BITS = 256

_PUNCT = set(string.punctuation)


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #

@dataclass
class Strength:
    length: int
    shannon_per_char: float   # bits/char of the *observed* string
    shannon_total: float      # shannon_per_char × length
    pool: int                 # size of the detected character pool
    estimated_bits: float     # length × log2(pool) — assumes randomness
    verdict: str
    advice: str

    def to_dict(self) -> dict:
        return {
            "length": self.length,
            "shannon_bits_per_char": round(self.shannon_per_char, 3),
            "shannon_total_bits": round(self.shannon_total, 1),
            "charset_pool": self.pool,
            "estimated_bits": round(self.estimated_bits, 1),
            "verdict": self.verdict,
            "advice": self.advice,
        }


def shannon_per_char(s: str) -> float:
    """Shannon entropy (bits per character) of the observed string."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def charset_pool(s: str) -> int:
    """Estimate the pool a string appears to be drawn from, by character class."""
    pool = 0
    if any(c in string.ascii_lowercase for c in s):
        pool += 26
    if any(c in string.ascii_uppercase for c in s):
        pool += 26
    if any(c in string.digits for c in s):
        pool += 10
    if any(c in _PUNCT for c in s):
        pool += len(string.punctuation)  # 32
    if " " in s:
        pool += 1
    # anything else (unicode etc.): count distinct extra symbols
    extra = {c for c in s if c not in string.printable}
    pool += len(extra)
    return pool or 1


def estimated_bits(s: str) -> float:
    return len(s) * math.log2(charset_pool(s)) if s else 0.0


def classify(bits: float) -> tuple[str, str]:
    """Map an entropy estimate (bits) to a verdict and a short piece of advice."""
    if bits < 28:
        return "very weak", "trivially brute-forceable; do not use"
    if bits < 36:
        return "weak", "too short — aim for far more length"
    if bits < 60:
        return "moderate", "ok for rate-limited logins, weak for anything offline"
    if bits < 128:
        return "strong", "good for passwords; for API secrets prefer ≥128 bits"
    return "very strong", "excellent — appropriate for keys and machine secrets"


def evaluate(s: str) -> Strength:
    spc = shannon_per_char(s)
    pool = charset_pool(s)
    bits = estimated_bits(s)
    verdict, advice = classify(bits)
    return Strength(
        length=len(s),
        shannon_per_char=spc,
        shannon_total=spc * len(s),
        pool=pool,
        estimated_bits=bits,
        verdict=verdict,
        advice=advice,
    )


# --------------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------------- #

def length_for_bits(bits: float, charset: str = DEFAULT_CHARSET) -> int:
    alpha = CHARSETS[charset]
    return max(1, math.ceil(bits / math.log2(len(alpha))))


def generate(length: int | None = None, bits: float | None = None,
             charset: str = DEFAULT_CHARSET) -> str:
    """Generate a random secret from a CSPRNG.

    Provide ``length`` directly, or a target ``bits`` of entropy (default
    256-bit-equivalent when neither is given).
    """
    if charset not in CHARSETS:
        raise ValueError(f"unknown charset {charset!r}; choose from {', '.join(CHARSETS)}")
    alpha = CHARSETS[charset]
    if length is None:
        length = length_for_bits(bits if bits is not None else DEFAULT_BITS, charset)
    return "".join(secrets.choice(alpha) for _ in range(length))
