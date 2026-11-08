# What the attested clients' tests stand on: a stub relay (relay.py) whose enclaves open seals with
# test keys, documents a forged Nitro root signs, GitHub as the captures of 2026-11-06 have it, and
# a clock the test moves. conftest.py makes `clock` and `setup` fixtures of them.
from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
from forge import forge_nitro
from opener import EnclaveKey
from relay import Call, Relay
from world import LIVE, LOG, MINUTE, NOW, STATEMENT, Fake, World, fake

from trymorse_verify.attested import Keyring, Reach, async_client, sync_client
from trymorse_verify.nitro import Pcrs, same_pcrs
from trymorse_verify.source import parse_log

# The headers the OpenAI SDK sends with each request, from openai 7.53's client.mjs, as the TS
# tests send them.
SDK = {
    "Authorization": "Bearer sk_test",
    "Accept": "application/json",
    "User-Agent": "OpenAI/Python 3.46.0",
    "X-Stainless-Lang": "python",
    "X-Stainless-Package-Version": "3.46.0",
    "X-Stainless-OS": "Linux",
    "X-Stainless-Arch": "x64",
    "X-Stainless-Runtime": "CPython",
    "X-Stainless-Runtime-Version": "3.12.16",
    "X-Stainless-Retry-Count": "0",
    "X-Stainless-Read-Timeout": "600",
    "OpenAI-Organization": "org-test",
}
CHAT = '{"model":"m","messages":[{"role":"user","content":"hi"}]}'
CHAT_HEADERS = {**SDK, "Content-Type": "application/json"}
UNLISTED = Pcrs("ab" * 48, "ab" * 48, "ab" * 48)
# An image on list 290 that no commit on main names.
UNPUBLISHED = next(
    Pcrs(i["pcr0"], i["pcr1"], i["pcr2"])
    for i in json.loads(STATEMENT)["images"]
    if not i["revoked"]
    and not any(same_pcrs(r.pcrs, Pcrs(i["pcr0"], i["pcr1"], i["pcr2"])) for r in parse_log(LOG))
)
FORGE = forge_nitro(NOW)


class Clock:
    def __init__(self) -> None:
        self.ms = NOW

    def __call__(self) -> int:
        return self.ms


class Enclave(EnclaveKey):
    """An enclave on the live image: its key, and a document of it, signed a minute ago by default."""

    def __init__(self, clock: Clock):
        super().__init__()
        self._clock = clock

    def document(self, **o) -> str:
        options = {
            "timestamp": self._clock() - MINUTE,
            "public_key": self.public_key,
            "environment": "prod",
            "pcrs": LIVE,
            **o,
        }
        return base64.b64encode(FORGE.document(**options)).decode()


class Router(httpx.BaseTransport):
    """What the checks fetch with: the relay over HTTP, and GitHub as `world` fakes it."""

    def __init__(self, origin: str, world: Fake, github: Callable[[str], None] | None):
        self._origin = origin
        self._world = world
        self._github = github
        self._real = httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(self._origin):
            return self._real.handle_request(request)
        if self._github:
            self._github(url)
        return self._world.handle(request)


class Recording(httpx.BaseTransport):
    """The transport a client sends with, which records what it was asked to send."""

    def __init__(self, sent: list[httpx.Request]):
        self.sent = sent
        self._real = httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(request)
        return self._real.handle_request(request)


class AsyncRecording(httpx.AsyncBaseTransport):
    def __init__(self, sent: list[httpx.Request]):
        self.sent = sent
        self._real = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(request)
        return await self._real.handle_async_request(request)


@dataclass
class Setup:
    relay: Relay
    ring: Keyring
    world: Fake
    live: list[Enclave]
    clock: Clock
    sent: list[httpx.Request] = field(default_factory=list)

    @property
    def at(self) -> str:
        return self.relay.origin

    def client(self, **kwargs) -> httpx.Client:
        return sync_client(self.ring, Recording(self.sent), **kwargs)

    def async_client(self, **kwargs) -> httpx.AsyncClient:
        return async_client(self.ring, AsyncRecording(self.sent), **kwargs)

    def chat(self, path: str = "/v1/chat/completions", **o) -> httpx.Response:
        with self.client() as c:
            return c.post(f"{self.at}{path}", headers=o.pop("headers", CHAT_HEADERS), content=CHAT, **o)


def make_setup(clock: Clock, relays: list[Relay]) -> Callable[..., Setup]:
    def make(
        live: list[Enclave] | None = None,
        world: World | None = None,
        exec: Callable | None = None,
        github: Callable[[str], None] | None = None,
        **o,
    ) -> Setup:
        live = [Enclave(clock)] if live is None else live
        o.setdefault("listed", lambda: [e.document() for e in live])
        relay = Relay(enclaves=lambda: live, **o).start()
        relays.append(relay)
        w = fake(world)
        ring = Keyring(
            relay.origin,
            Reach(
                httpx.Client(transport=Router(relay.origin, w, github), timeout=30),
                exec(w.exec) if exec else w.exec,
                clock,
                FORGE.root,
            ),
        )
        return Setup(relay, ring, w, live, clock)

    return make


def opened_head(call: Call) -> dict:
    assert call.opened is not None
    return call.opened.head
