# A stand-in for Morse's relay and the enclaves behind it, over real HTTP on 127.0.0.1, for the
# attested clients' tests, as src/testing/relay.ts has it. GET /v1/attestation lists documents;
# POST /v1/sealed opens a seal with one enclave's key and seals that enclave's answer, or answers
# 421; anything else gets prod's refusal of a bad key, in the clear. It records each request as it
# arrived.
from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opener import EnclaveKey, Opened, ReplySealer, key_ids_of

MAX_CALLS = 100


@dataclass
class Answer:
    """What an enclave answers to a request it opened."""

    status: int
    headers: dict[str, list[str]] | None = None
    # The body, a frame each, sent as each is ready.
    chunks: Iterable[str] = ()
    # Ends the reply before its final frame.
    truncated: bool = False


@dataclass
class Plain:
    """An answer in the clear."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


@dataclass
class Call:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    # A sealed request's key ids, hex, and what an enclave opened, if one could.
    key_ids: list[str] | None = None
    opened: Opened | None = None


def refusal(code: str, message: str) -> dict:
    return {"error": {"message": message, "type": "invalid_request_error", "param": None, "code": code}}


@dataclass
class Relay:
    # The enclaves whose keys open seals now.
    enclaves: Callable[[], list[EnclaveKey]]
    # The base64 documents GET /v1/attestation lists.
    listed: Callable[[], list[str]]
    # The documents a 421 lists. Default: what `listed` does.
    listed_on_421: Callable[[], list[str]] | None = None
    # Default: 200 with {"ok":true}.
    answer: Callable[[Opened], Answer] | None = None
    # Answers a request in the clear before anything else does, unless it returns None.
    plain: Callable[[Call], Plain | None] | None = None
    calls: list[Call] = field(default_factory=list)
    origin: str = ""

    def start(self) -> Relay:
        relay = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args) -> None:
                pass

            def _json(self, status: int, value: object) -> None:
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def _serve(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                call = Call(
                    self.command,
                    self.path,
                    {k.lower(): v for k, v in self.headers.items()},
                    self.rfile.read(length),
                )
                relay.calls.append(call)
                # A client that never stops retrying gets an answer it doesn't retry, so its test
                # fails rather than runs on.
                if len(relay.calls) > MAX_CALLS:
                    return self._json(503, refusal("stub_relay_call_limit", f"Over {MAX_CALLS} calls."))
                clear = relay.plain(call) if relay.plain else None
                if clear:
                    self.send_response(clear.status)
                    for name, value in clear.headers.items():
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(clear.body.encode())
                    return
                if call.method == "GET" and call.path == "/v1/attestation":
                    return self._json(
                        200,
                        {"object": "proxy_attestation", "environment": "prod", "instances": relay.listed()},
                    )
                if call.method != "POST" or call.path != "/v1/sealed":
                    return self._json(401, refusal("invalid_api_key", "Incorrect API key provided."))
                call.key_ids = key_ids_of(call.body)
                for enclave in relay.enclaves():
                    call.opened = enclave.open(call.body)
                    if call.opened:
                        break
                if not call.opened:
                    return self._json(
                        421,
                        {
                            **refusal("sealed_key_unknown", "No enclave holds these keys."),
                            "instances": (relay.listed_on_421 or relay.listed)(),
                        },
                    )
                answer = (
                    relay.answer(call.opened)
                    if relay.answer
                    else Answer(200, {"Content-Type": ["application/json"]}, ['{"ok":true}'])
                )
                sealer = ReplySealer(call.opened.cek)
                head = {"status": answer.status, "headers": answer.headers}
                self.send_response(200)
                self.send_header("content-type", "application/morse-sealed")
                self.send_header("cache-control", "no-store")
                self.send_header("x-request-id", "req_relay")
                self.end_headers()
                self.wfile.write(sealer.salt)
                self.wfile.write(sealer.frame(json.dumps(head).encode(), False))
                self.wfile.flush()
                for chunk in answer.chunks:
                    self.wfile.write(sealer.frame(chunk.encode(), False))
                    self.wfile.flush()
                if not answer.truncated:
                    self.wfile.write(sealer.frame(b"", True))

            def _answer(self) -> None:
                try:
                    self._serve()
                except (BrokenPipeError, ConnectionResetError):
                    pass  # The client stopped reading, as it does a reply it refuses.

            do_GET = do_POST = _answer

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, args=(0.02,), daemon=True)
        self._thread.start()
        self.origin = f"http://127.0.0.1:{self._server.server_address[1]}"
        return self

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def sealed(self) -> list[Call]:
        return [c for c in self.calls if c.path == "/v1/sealed"]

    def routes(self) -> list[str]:
        return [f"{c.method} {c.path}" for c in self.calls]

    def listings(self) -> int:
        return self.routes().count("GET /v1/attestation")
