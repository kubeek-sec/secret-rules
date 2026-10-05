"""Network-free validators (Kingfisher calls these ``locally_derived`` /
``invalid_material``).

These prove things about captured material *without contacting any service*:
a JWT's structure and expiry, or whether a PEM block is a well-formed private
key.  They never verify a signature against a remote party — only what can be
decided locally.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import json
import urllib.parse

from ..core import (
    INACTIVE,
    INVALID_MATERIAL,
    LOCALLY_DERIVED,
    UNSUPPORTED,
    HttpClient,
    Result,
    register,
)


def _b64url(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


@register(
    "jwt",
    sniff=r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.?[A-Za-z0-9_-]*",
    doc="offline: decode JWT, check structure + expiry (no network)",
)
def jwt(secret: str, extra: dict, http: HttpClient) -> Result:
    parts = secret.strip().split(".")
    if len(parts) < 2:
        return Result("jwt", INVALID_MATERIAL, detail="not a JWT (need header.payload[.signature])")
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
    except (ValueError, binascii.Error):
        return Result("jwt", INVALID_MATERIAL, detail="header/payload is not valid base64url JSON")

    ident = {k: payload.get(k) for k in ("iss", "sub", "aud") if payload.get(k)}
    alg = header.get("alg")
    ident["alg"] = alg
    now = _dt.datetime.now(_dt.timezone.utc)

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        exp_dt = _dt.datetime.fromtimestamp(exp, _dt.timezone.utc)
        ident["exp"] = exp_dt.isoformat()
        if exp_dt < now:
            return Result("jwt", INACTIVE, detail=f"expired at {exp_dt.isoformat()}",
                          identity=ident)

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)):
        nbf_dt = _dt.datetime.fromtimestamp(nbf, _dt.timezone.utc)
        ident["nbf"] = nbf_dt.isoformat()
        if now < nbf_dt:
            return Result("jwt", INACTIVE, detail=f"not valid before {nbf_dt.isoformat()}",
                          identity=ident)

    note = "well-formed JWT; signature not checked (needs the signing key)"
    if isinstance(alg, str) and alg.lower() == "none":
        note = "unsigned token (alg=none) — accepted only by misconfigured verifiers"
    return Result("jwt", LOCALLY_DERIVED, detail=note, identity=ident)


_PK_KINDS = {
    "RSA PRIVATE KEY": "RSA (PKCS#1)",
    "EC PRIVATE KEY": "EC (SEC1)",
    "DSA PRIVATE KEY": "DSA",
    "OPENSSH PRIVATE KEY": "OpenSSH",
    "PRIVATE KEY": "PKCS#8",
    "ENCRYPTED PRIVATE KEY": "PKCS#8 (encrypted)",
    "PGP PRIVATE KEY BLOCK": "PGP",
}


@register(
    "private",
    sniff=r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
    doc="offline: check a PEM private key is well-formed (no network)",
)
def private_key(secret: str, extra: dict, http: HttpClient) -> Result:
    text = secret.strip()
    begin = next((k for k in _PK_KINDS if f"-----BEGIN {k}-----" in text), None)
    if begin is None:
        return Result("private", INVALID_MATERIAL, detail="no recognizable PEM private-key header")
    try:
        body = text.split(f"-----BEGIN {begin}-----", 1)[1].split("-----END", 1)[0]
        raw = base64.b64decode("".join(body.split()), validate=False)
    except (ValueError, IndexError, binascii.Error):
        return Result("private", INVALID_MATERIAL, detail="PEM body is not valid base64")
    if len(raw) < 16:
        return Result("private", INVALID_MATERIAL, detail="PEM body too short to be a key")
    return Result("private", LOCALLY_DERIVED,
                  detail=f"well-formed {_PK_KINDS[begin]} private key ({len(raw)} bytes DER)",
                  identity={"kind": _PK_KINDS[begin]})


@register(
    "postgres", "mysql", "mariadb", "mongodb", "mongo", "redis", "rabbitmq", "jdbc",
    sniff=r"\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqps?)://[^\s]+:[^\s]+@",
    doc="offline: parse a connection URI, confirm embedded credentials (no network)",
)
def credential_uri(secret: str, extra: dict, http: HttpClient) -> Result:
    """Validate a DB/credential connection string structurally.

    We parse the URI and confirm it embeds a usable credential (host + password)
    without connecting — a live auth would need the database driver, which this
    stdlib-only tool deliberately avoids. Reported as ``locally-derived``.
    """
    topic = extra.get("_topic", "credential-uri")
    s = secret.strip()
    uri = s[5:] if s.lower().startswith("jdbc:") else s
    if "://" not in uri:
        return Result(topic, UNSUPPORTED,
                      detail="not a connection URI (no live validator for this credential kind)")
    try:
        parts = urllib.parse.urlsplit(uri)
        pw = urllib.parse.unquote(parts.password) if parts.password else None
        user = urllib.parse.unquote(parts.username) if parts.username else None
        host = parts.hostname
        port = parts.port
    except ValueError:
        return Result(topic, INVALID_MATERIAL, detail="malformed connection URI")
    # credentials may also live in the query string (common for JDBC)
    q = urllib.parse.parse_qs(parts.query)
    user = user or (q.get("user") or q.get("username") or [None])[0]
    pw = pw or (q.get("password") or [None])[0]
    if not host or not pw:
        return Result(topic, INVALID_MATERIAL,
                      detail="URI parsed but has no embedded host+password credential")
    return Result(topic, LOCALLY_DERIVED,
                  detail=f"well-formed {parts.scheme} credential URI "
                         f"(not connected — needs a DB driver to prove liveness)",
                  identity={"scheme": parts.scheme, "user": user, "host": host, "port": port})
