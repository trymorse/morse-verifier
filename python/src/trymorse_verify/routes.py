# Which calls go to the enclave sealed, which the relay answers alone, and which headers ride inside
# the seal, as src/sealed_routes.ts lists them (and the backend's internal/seal/routes.go and
# worker.ContentHeaders before it), and the replies around a seal that every client of it reads the
# same way. A test holds these lists to src/testdata/protocol.json, which the TypeScript tests write.
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

import httpx

SEALED_CONTENT_TYPE = "application/morse-sealed"
MAX_KEYS = 4

# Each route the enclave serves sealed, as `METHOD /path`, where `{x}` is one path segment and
# `{x...}` is the rest of the path.
SEALED_PATTERNS = (
    "POST /v1/chat/completions",
    "POST /v1/chat/compact",
    "POST /v1/images/generations",
    "POST /v1/videos",
    "GET /v1/videos/{id}/content",
    "POST /v1/search",
    "POST /v1/fetch",
    "POST /v1/research",
    "GET /v1/research/{id}",
    "GET /v1/research/{id}/events",
    "GET /v1/lookup/{service}/{path...}",
    "POST /v1/audio/transcriptions",
    "POST /v1/plugins/call",
    "POST /v1/plugins/token",
    "POST /v1/plugins/revoke",
)

# The routes the relay answers alone, which carry no content: there is nothing in them to seal.
PLAIN_PATTERNS = (
    "GET /v1/models",
    "GET /v1/attestation",
    "GET /v1/receipts/{id}",
    "GET /v1/videos/{id}",
)

# The headers the enclave reads from inside a seal. It drops any other.
CONTENT_HEADERS = (
    "Content-Type",
    "X-E2EE-Version",
    "X-E2EE-Nonce",
    "X-E2EE-Timestamp",
    "X-E2EE-Algo",
    "X-Client-Pub-Key",
    "X-Model-Pub-Key",
    "X-Signing-Algo",
    "X-Encryption-Version",
    "X-Encrypt-All-Fields",
    "Ehbp-Encapsulated-Key",
    "X-Tinfoil-Model",
    "X-Tinfoil-Max-Output-Tokens",
)
CONTENT_HEADER_NAMES = {h.lower(): h for h in CONTENT_HEADERS}

# The headers a client drops from a request before sealing it, by their lowercase names, where a
# trailing `*` is any rest: the SDK's own, which the enclave doesn't read and beside the seal would
# name the client, and the transport's, which the sealed request sets for itself. The key moves to
# the outer request. Any other header that is not a content header refuses the request.
DROPPED_HEADERS = (
    "authorization",
    "accept",
    "user-agent",
    "x-stainless-*",
    "openai-*",
    "content-length",
    "host",
    "connection",
    "keep-alive",
    "transfer-encoding",
)

# The headers the relay sets beside a sealed reply, outside the seal, so nothing authenticates them.
# A reply's own header of the same name, from inside the seal, wins.
RELAY_REPLY_HEADERS = (
    "X-Request-Id",
    "X-Funding",
    "X-Included-Lane",
    "X-Included-Lane-Until",
    "X-Included-Until",
    "X-Output-Limited",
    "X-Turn-Remaining",
)

# The statuses whose reply has no body, though its seal still ends in a final frame.
NULL_BODY_STATUSES = frozenset({204, 205, 304})


def _routes(patterns: Sequence[str]) -> list[tuple[str, re.Pattern[str]]]:
    out = []
    for pattern in patterns:
        method, path = pattern.split(" ")
        source = "/".join(
            ".*" if s.endswith("...}") else "[^/]+" if s.startswith("{") else re.escape(s)
            for s in path.split("/")
        )
        out.append((method, re.compile(source)))
    return out


_SEALED = _routes(SEALED_PATTERNS)
_PLAIN = _routes(PLAIN_PATTERNS)


def ambiguous_path(path: str) -> bool:
    """Whether a server could read `path`, as written, as another path: it has a `.` or `..`
    segment, plainly or as `%2e`, which a WHATWG URL (so fetch, in sealed_routes.ts) resolves, or a
    backslash, which one reads as `/`. httpx sends a path as written, so neither matches."""
    return "\\" in path or any(s.lower().replace("%2e", ".") in (".", "..") for s in path.split("/"))


def _matches(table: list[tuple[str, re.Pattern[str]]], method: str, path: str) -> bool:
    path = path.split("?", 1)[0].split("#", 1)[0]
    return not ambiguous_path(path) and any(m == method.upper() and p.fullmatch(path) for m, p in table)


def seals_route(method: str, path: str) -> bool:
    """Whether the enclave serves `method` `path` sealed. A query is ignored, and an ambiguous path
    matches nothing."""
    return _matches(_SEALED, method, path)


def plain_route(method: str, path: str) -> bool:
    """Whether the relay answers `method` `path` alone, with nothing to seal."""
    return _matches(_PLAIN, method, path)


def dropped_header(name: str) -> bool:
    """Whether a client drops header `name`, lowercase, before sealing."""
    return any(name.startswith(d[:-1]) if d.endswith("*") else name == d for d in DROPPED_HEADERS)


def with_relay_headers(inner: httpx.Headers, outer: Mapping[str, str]) -> httpx.Headers:
    """A sealed reply's own headers, then each of the relay's from `outer` that it doesn't set."""
    headers = httpx.Headers(inner)
    for name in RELAY_REPLY_HEADERS:
        value = outer.get(name)
        if value is not None and name not in headers:
            headers[name] = value
    return headers
