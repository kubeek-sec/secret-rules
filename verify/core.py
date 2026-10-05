"""Core primitives for credential verification and rotation.

This module is deliberately dependency-light (standard library + PyYAML, which
the project already depends on).  It provides:

- ``Result``        — the outcome of a single verification.
- ``HttpClient``    — a tiny, redirect-safe HTTP wrapper with a ``--dry-run``
                      mode that records the requests it *would* send.
- ``VerifierSpec``  — metadata + callable for a provider verifier, plus the
                      ``register``/``http_check`` helpers used to declare them.
- ``Rotator``       — remediation metadata for a provider (see ``rotators.py``).
- referential loading helpers (``load_rules``, ``resolve_topic``).

Safety model
------------
Verification means proving a credential is *live* without side effects.  Every
verifier in this package only ever calls read-only endpoints (identity /
``whoami`` / ``validate`` / list).  Nothing here creates, sends, charges, or
deletes.  The only mutating actions live behind the separate ``rotate``/``update``
commands and are plan-only unless the user explicitly confirms execution.
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

# status values (aligned with Kingfisher's validation.outcome taxonomy)
ACTIVE = "active"          # a live validator proved the credential is usable
INACTIVE = "inactive"      # a validator authoritatively rejected it
UNKNOWN = "unknown"        # inconclusive: timeout / rate limit / server error
UNSUPPORTED = "unsupported"  # no verifier registered for this topic
SKIPPED = "skipped"        # a required dependency/input was missing
PLANNED = "planned"        # dry-run: no request was actually sent
# network-free (cryptographic / structural) validation outcomes:
LOCALLY_DERIVED = "locally-derived"   # key material parsed/accepted offline
INVALID_MATERIAL = "invalid-material"  # parsing/structure rejected the material

_STATUS_GLYPH = {
    ACTIVE: "✔ ACTIVE",
    INACTIVE: "✘ inactive",
    UNKNOWN: "? unknown",
    UNSUPPORTED: "– unsupported",
    SKIPPED: "– skipped",
    PLANNED: "· planned",
    LOCALLY_DERIVED: "✔ local-ok",
    INVALID_MATERIAL: "✘ malformed",
}


@dataclass
class Result:
    topic: str
    status: str
    detail: str = ""
    identity: dict | None = None          # non-sensitive metadata from the API
    http_status: int | None = None
    endpoint: str | None = None

    @property
    def label(self) -> str:
        return _STATUS_GLYPH.get(self.status, self.status)

    def to_dict(self) -> dict:
        d = {"topic": self.topic, "status": self.status}
        if self.detail:
            d["detail"] = self.detail
        if self.identity:
            d["identity"] = self.identity
        if self.http_status is not None:
            d["http_status"] = self.http_status
        if self.endpoint:
            d["endpoint"] = self.endpoint
        return d


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

_USER_AGENT = "secret-rules-verify/0.1 (+read-only credential verification)"
_MAX_BODY = 64 * 1024  # never read more than 64 KiB of a response


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects.

    A redirect could resend the ``Authorization`` header (the secret) to a
    different host.  We treat any 3xx as a terminal response instead.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


@dataclass
class Response:
    status: int | None           # HTTP status, or None on a transport error
    body: str = ""
    headers: dict = field(default_factory=dict)
    error: str | None = None     # transport error message, if any
    dry_run: bool = False

    def json(self):
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None


class HttpClient:
    def __init__(self, timeout: float = 10.0, dry_run: bool = False,
                 insecure: bool = False, rps: float | None = None):
        self.timeout = timeout
        self.dry_run = dry_run
        self.rps = rps                      # global requests-per-second cap
        self._min_interval = (1.0 / rps) if rps else 0.0
        self._last_request = 0.0
        self.planned: list[dict] = []
        ctx = ssl.create_default_context()
        if insecure:
            # For on-prem / self-hosted services with private-CA or self-signed
            # certs. A deliberate, documented trust downgrade (--insecure).
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ctx),
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        data: bytes | str | None = None,
        basic_auth: tuple[str, str] | None = None,
    ) -> Response:
        method = method.upper()
        headers = dict(headers or {})
        headers.setdefault("User-Agent", _USER_AGENT)
        headers.setdefault("Accept", "application/json")
        if basic_auth is not None:
            raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        if isinstance(data, str):
            data = data.encode()

        # Record for --dry-run. Never store secrets: headers aren't kept, and a
        # query string (which may carry a token, e.g. ?access_token=) is redacted.
        safe_url = url
        try:
            parsed = urllib.parse.urlsplit(url)
            if parsed.query:
                safe_url = urllib.parse.urlunsplit(parsed._replace(query="<redacted>"))
        except ValueError:
            pass
        self.planned.append({"method": method, "url": safe_url})
        if self.dry_run:
            return Response(status=None, dry_run=True)

        if self._min_interval:  # global rate limit across all validators
            wait = self._min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(_MAX_BODY).decode("utf-8", "replace")
                return Response(status=resp.status, body=body, headers=dict(resp.headers))
        except urllib.error.HTTPError as e:  # 4xx / 5xx still carry a body
            body = ""
            try:
                body = e.read(_MAX_BODY).decode("utf-8", "replace")
            except Exception:  # pragma: no cover - defensive
                pass
            return Response(status=e.code, body=body, headers=dict(e.headers or {}))
        except (urllib.error.URLError, OSError, ValueError) as e:
            return Response(status=None, error=str(getattr(e, "reason", e)))


# --------------------------------------------------------------------------- #
# Verifier registry
# --------------------------------------------------------------------------- #

VerifierFn = Callable[[str, dict, HttpClient], Result]


@dataclass
class VerifierSpec:
    topics: tuple[str, ...]
    func: VerifierFn
    needs: tuple[str, ...] = ()          # required ``extra`` fields (e.g. "id")
    companion_help: dict = field(default_factory=dict)
    sniff: re.Pattern | None = None      # for topic auto-detection
    doc: str = ""
    endpoint: bool = False               # accepts --base-url / --endpoint override


VERIFIERS: dict[str, VerifierSpec] = {}


def register(
    *topics: str,
    needs: tuple[str, ...] = (),
    sniff: str | None = None,
    companion_help: dict | None = None,
    doc: str = "",
    endpoint: bool = False,
):
    """Decorator: register a verifier function under one or more topics."""

    def deco(func: VerifierFn) -> VerifierFn:
        first_docline = ""
        if func.__doc__:
            first_docline = func.__doc__.strip().splitlines()[0]
        spec = VerifierSpec(
            topics=topics,
            func=func,
            needs=needs,
            sniff=re.compile(sniff) if sniff else None,
            companion_help=companion_help or {},
            doc=doc or first_docline,
            endpoint=endpoint,
        )
        for t in topics:
            VERIFIERS[t] = spec
        return func

    return deco


def _interpret(
    resp: Response,
    *,
    topic: str,
    endpoint: str,
    active=(200,),
    inactive=(401, 403),
    json_active=None,
    identity=None,
) -> Result:
    """Translate an HTTP response into a Result."""
    if resp.dry_run:
        return Result(topic, PLANNED, detail=f"would GET/POST {endpoint}", endpoint=endpoint)
    if resp.status is None:
        return Result(topic, UNKNOWN, detail=f"transport error: {resp.error}", endpoint=endpoint)

    code = resp.status
    if json_active is not None:
        status, detail, ident = json_active(code, resp.json(), resp.body)
        return Result(topic, status, detail=detail, identity=ident, http_status=code, endpoint=endpoint)

    if code == 429:
        return Result(topic, UNKNOWN, detail="rate limited (HTTP 429) — try again later",
                      http_status=code, endpoint=endpoint)
    if code in active:
        ident = None
        if identity is not None:
            try:
                ident = identity(resp.json())
            except Exception:
                ident = None
        return Result(topic, ACTIVE, detail="credential accepted", identity=ident,
                      http_status=code, endpoint=endpoint)
    if code in inactive:
        return Result(topic, INACTIVE, detail=f"rejected (HTTP {code})",
                      http_status=code, endpoint=endpoint)
    if 500 <= code < 600:
        return Result(topic, UNKNOWN, detail=f"server error (HTTP {code})",
                      http_status=code, endpoint=endpoint)
    return Result(topic, UNKNOWN, detail=f"unexpected response (HTTP {code})",
                  http_status=code, endpoint=endpoint)


def http_check(
    topic_label: str,
    base: str,
    path: str = "",
    *,
    auth: str = "bearer",            # bearer | basic-secret | basic-id-secret | header | query
    header_name: str | None = None,  # for auth="header"
    prefix: str = "",                # token prefix for auth="header"
    query_param: str | None = None,  # for auth="query" (?<param>=<secret>)
    method: str = "GET",
    extra_headers: dict | None = None,
    body: str | bytes | None = None,
    content_type: str | None = None,
    active=(200,),
    inactive=(401, 403),
    json_active=None,
    identity=None,
    require_endpoint: bool = False,
) -> VerifierFn:
    """Build a verifier that performs a single read-only request.

    ``base`` is the service root (scheme + host, optionally an API prefix) and
    ``path`` is appended to it. A self-hosted / enterprise deployment overrides
    the base via ``extra["endpoint"]`` (CLI: ``--base-url`` / ``--endpoint``),
    e.g. on-prem GitLab or GitHub Enterprise. Set ``require_endpoint`` for
    services with no public host (self-hosted only).

    ``topic_label`` only tags the returned Result; the real topic key comes from
    ``register``.
    """

    def _fn(secret: str, extra: dict, http: HttpClient) -> Result:
        if require_endpoint and not extra.get("endpoint"):
            return Result(topic_label, SKIPPED,
                          detail="self-hosted only — pass --base-url https://<host>")
        root = (extra.get("endpoint") or base).rstrip("/")
        url = root + path
        display_url = url  # secret-free URL used for reporting (never carries the secret)
        headers = dict(extra_headers or {})
        basic = None
        if auth == "bearer":
            headers["Authorization"] = f"Bearer {secret}"
        elif auth == "header":
            headers[header_name] = f"{prefix}{secret}"
        elif auth == "basic-secret":
            basic = (secret, "")
        elif auth == "basic-id-secret":  # Basic base64(<id>:<secret>) — e.g. Bitbucket, Zendesk
            basic = (extra.get("id", ""), secret)
        elif auth == "query":            # ?<param>=<secret> — e.g. Mapbox
            sep = "&" if "?" in url else "?"
            display_url = f"{url}{sep}{query_param}=<redacted>"
            url = f"{url}{sep}{query_param}={urllib.parse.quote(secret, safe='')}"
        else:  # pragma: no cover - misconfiguration
            raise ValueError(f"unknown auth style {auth!r}")
        if content_type:
            headers["Content-Type"] = content_type
        resp = http.request(method, url, headers=headers, data=body, basic_auth=basic)
        return _interpret(resp, topic=topic_label, endpoint=display_url, active=active,
                          inactive=inactive, json_active=json_active, identity=identity)

    return _fn


# --------------------------------------------------------------------------- #
# Rotation registry (see rotators.py)
# --------------------------------------------------------------------------- #

RevokeFn = Callable[[str, dict, HttpClient], Result]


@dataclass
class Rotator:
    """Remediation guidance for a provider.

    ``self_revoke`` is populated only when the leaked credential can revoke
    *itself* through a single documented endpoint (e.g. Slack ``auth.revoke``).
    Everything else is a manual runbook: we never guess at destructive calls.
    """

    topics: tuple[str, ...]
    revoke_console: str              # where a human revokes the leaked secret
    create_doc: str                  # where a human mints the replacement
    notes: str = ""
    self_revoke: RevokeFn | None = None
    self_revoke_desc: str = ""
    # "provider": the service mints the token (a locally generated value won't
    # be accepted).  "self": a secret you control both ends of (Django/Rails
    # SECRET_KEY, JWT HS256 signing key, generic app secret) — safe to generate
    # locally with a CSPRNG.  ``gen_spec`` hints the generation parameters.
    mint: str = "provider"
    gen_spec: dict = field(default_factory=dict)


ROTATORS: dict[str, Rotator] = {}


def register_rotator(rot: Rotator) -> Rotator:
    for t in rot.topics:
        ROTATORS[t] = rot
    return rot


# --------------------------------------------------------------------------- #
# Referential + secret helpers
# --------------------------------------------------------------------------- #

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REFERENTIAL = _REPO_ROOT / "referential" / "rules.yaml"


def load_rules(path: Path | None = None) -> list[dict]:
    path = path or DEFAULT_REFERENTIAL
    data = yaml.safe_load(path.read_text())
    return data["rules"]


def resolve_topic(rules: list[dict], *, uid: str | None, topic: str | None) -> tuple[str | None, dict | None]:
    """Resolve a (topic, rule) pair from a ``--uid`` or ``--topic`` selector."""
    if uid:
        for r in rules:
            if r["uid"] == uid:
                return r["topic"], r
        raise KeyError(f"no rule with uid {uid!r}")
    if topic:
        rule = next((r for r in rules if r["topic"] == topic), None)
        return topic, rule
    return None, None


def sniff_topic(secret: str) -> list[str]:
    """Return topics whose verifier recognizes the shape of ``secret``."""
    hits = []
    for topic, spec in VERIFIERS.items():
        if spec.sniff and spec.sniff.search(secret):
            hits.append(topic)
    return sorted(set(hits))


def fingerprint(secret: str) -> str:
    """A non-reversible preview for logs: first 4 + last 2 chars, middle masked."""
    s = secret.strip()
    if len(s) <= 8:
        return s[0] + "…" if s else "(empty)"
    return f"{s[:4]}…{s[-2:]} (len {len(s)})"
