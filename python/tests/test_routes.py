# routes.py is src/sealed_routes.ts's lists, as protocol.json (which the TypeScript tests write)
# has them, and seals exactly what the backend's worker serves sealed.
from __future__ import annotations

import json

import httpx
import pytest
from world import read

from trymorse_verify import routes
from trymorse_verify.attested import NotSent, _plain_request, _read_call


def test_holds_the_lists_protocol_json_has():
    protocol = json.loads(read("protocol.json"))
    assert protocol == {
        "sealed_content_type": routes.SEALED_CONTENT_TYPE,
        "max_keys": routes.MAX_KEYS,
        "sealed_patterns": list(routes.SEALED_PATTERNS),
        "plain_patterns": list(routes.PLAIN_PATTERNS),
        "content_headers": list(routes.CONTENT_HEADERS),
        "dropped_headers": list(routes.DROPPED_HEADERS),
        "relay_reply_headers": list(routes.RELAY_REPLY_HEADERS),
        "null_body_statuses": sorted(routes.NULL_BODY_STATUSES),
    }


def test_seals_exactly_the_routes_the_backends_worker_serves_sealed():
    vectors = json.loads(read("seal_vectors.json"))
    assert sorted(routes.SEALED_PATTERNS) == sorted(vectors["sealable_patterns"])


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/v1/models"),
        ("GET", "/v1/attestation?model=m"),
        ("GET", "/v1/receipts/rcpt-1"),
        ("GET", "/v1/videos/job_1"),
    ],
)
def test_leaves_what_carries_no_content_to_the_relay(method, path):
    assert [routes.plain_route(method, path), routes.seals_route(method, path)] == [True, False]


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/v1/embeddings"),
        ("POST", "/v1/models"),
        ("GET", "/v1/receipts"),
        ("GET", "/v1/videos/job_1/content/more"),
        ("POST", "/v1/chat/completions/"),
    ],
)
def test_names_neither_sealed_nor_plain(method, path):
    assert [routes.plain_route(method, path), routes.seals_route(method, path)] == [False, False]


# fetch resolves these before sealed_routes.ts matches them; httpx would send them as written.
@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/v1/receipts/%2e%2E"),
        ("GET", "/v1/receipts/."),
        ("GET", "/v1/research/%2E"),
        ("GET", "/v1/lookup/s/%2e%2e/models"),
        ("POST", "/v1/models/../chat/completions"),
        ("GET", "/v1\\models"),
    ],
)
def test_matches_no_path_with_a_dot_segment_or_backslash(method, path):
    assert routes.ambiguous_path(path)
    assert [routes.plain_route(method, path), routes.seals_route(method, path)] == [False, False]


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/v1/chat/completions?x=1"),
        ("GET", "/v1/lookup/svc/a/b/c"),
        ("GET", "/v1/research/r1/events"),
    ],
)
def test_seals(method, path):
    assert routes.seals_route(method, path)


@pytest.mark.parametrize(
    "name,dropped",
    [
        ("authorization", True),
        ("x-stainless-retry-count", True),
        ("openai-organization", True),
        ("x-stainless", False),
        ("accept-encoding", False),
        ("x-debug", False),
        ("content-type", False),
    ],
)
def test_drops_before_sealing(name, dropped):
    assert routes.dropped_header(name) is dropped


def test_the_relays_headers_fill_in_only_what_the_sealed_reply_doesnt_set():
    inner = httpx.Headers({"Content-Type": "application/json", "X-Funding": "credits"})
    outer = httpx.Headers({"x-request-id": "req_1", "x-funding": "plan", "set-cookie": "a=b"})
    assert dict(routes.with_relay_headers(inner, outer)) == {
        "content-type": "application/json",
        "x-funding": "credits",
        "x-request-id": "req_1",
    }


# attested.test.ts reads the same table, so the two clients can't drift on what goes out. Where
# fetch resolves a dot segment or backslash and sends the result, httpx would send the path as
# written, so the Python client refuses it.
URLS = json.loads(read("request_urls.json"))


@pytest.mark.parametrize("case", URLS["cases"], ids=lambda c: f"{c['method']} {c['url']}")
def test_sends_plain_seals_or_refuses_each_url_of_request_urls_json_as_the_table_says(case):
    want = {**case, **case.get("python", {})}
    request = httpx.Request(
        case["method"],
        case["url"],
        headers={"Authorization": "Bearer sk", "Content-Type": "application/json"},
    )
    try:
        call = _read_call(request, URLS["origin"], "attested_client()")
    except NotSent:
        assert want["sends"] == "refused"
        return
    path = _plain_request(request).url.raw_path.decode() if call.plain else call.path
    assert ("plain" if call.plain else "sealed", path) == (want["sends"], want["path"])
