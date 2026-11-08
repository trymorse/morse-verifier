# attested_client() and attested_async_client(): httpx clients for OpenAI's Python SDK that seal each
# request carrying content to the keys of enclaves that passed the checks `trymorse-verify` prints as
# Attestation, Allowed, and Source, and raise rather than send anything the relay could read, as
# src/node/attested.ts does for the TypeScript SDK's fetch:
#   OpenAI(base_url="https://api.trymorse.ai/v1", api_key=..., http_client=attested_client())
# The checks and the seal are shared; only the sending differs between the two clients.
from __future__ import annotations

import asyncio
import concurrent.futures
import math
import os
import shutil
import threading
import time
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import TypeVar

import httpx

from .io import MAX_BODY, Exec, Unfinished, default_client, get, temp_dir
from .io import exec as run_program
from .io import json as read_json
from .nitro import MAX_AGE_MS, NITRO_ROOT, AttestedDocument, Cert, Pcrs, same_pcrs
from .routes import (
    CONTENT_HEADER_NAMES,
    MAX_KEYS,
    NULL_BODY_STATUSES,
    SEALED_CONTENT_TYPE,
    ambiguous_path,
    dropped_header,
    plain_route,
    seals_route,
    with_relay_headers,
)
from .seal import HeadTooLarge, InnerHead, ReplyOpener, SealedReplyError, SealKey, seal_request
from .signed_list import SignedList, fetch_signed_list, verify_signed_list
from .source import Release, read_releases
from .verify import Refused, check_document, unpublished

ORIGIN = "https://api.trymorse.ai"
NOTHING_SENT = "Nothing was sent."
# What a VerifyError says went out when a sealed try did before the check: a 421 or sealed_stale
# refused it, and the keys for the next try didn't pass.
FIRST_TRY_SENT = "Nothing was sent but the first try, which was sealed to keys that had passed."

T = TypeVar("T")


class VerifyError(Exception):
    """A check refused every enclave, or could not finish, so nothing was sent, or nothing past a
    first try that a 421 or sealed_stale refused. `step` is the check as `trymorse-verify` names it;
    `reason` says why, without the check's name or what was sent; `retryable` is True when the
    check could not finish (the network, a rate limit, git), so a later call may pass, and False
    when it refused what it was shown."""

    def __init__(self, step: str, reason: str, retryable: bool, sent: str = NOTHING_SENT):
        super().__init__(f"{step} {'could not finish' if retryable else 'failed'}: {reason}. {sent}")
        self.step = step
        self.reason = reason
        self.retryable = retryable


class NotSent(Exception):
    """A request the client would not send: to another origin, on a route the enclave can't seal,
    with a header the enclave would drop, or too long a head. Nothing was sent."""


@dataclass(frozen=True)
class Reach:
    """What the checks reach the world with. Tests pass their own."""

    # Fetches the origin's /v1/attestation and Morse's signed list from GitHub.
    client: httpx.Client
    exec: Exec
    # This machine's clock, in ms. Documents are judged by it, never by the enclave's.
    now: Callable[[], int]
    root: Cert


@dataclass(frozen=True)
class Keys:
    keys: tuple[SealKey, ...]
    expires_at: int


def _during(step: str, run: Callable[[], T]) -> T:
    """Runs `run` as check `step`, so whatever stops it is a VerifyError naming that check."""
    try:
        return run()
    except VerifyError:
        raise
    except Exception as e:
        raise VerifyError(step, str(e), isinstance(e, Unfinished)) from e


class _Sources:
    """Step 3 by an image's PCRs: the newest release on main that names them. A release found is
    kept; PCRs none names read main again, at most once a minute."""

    def __init__(self, exec: Exec, now: Callable[[], int]):
        self._exec = exec
        self._now = now
        self._found: dict[str, Release] = {}
        self._releases: list[Release] | None = None
        self._read_at = 0
        self._lock = threading.Lock()

    def _read_main(self) -> list[Release]:
        dir = temp_dir("trymorse-attested-")
        try:
            return read_releases(self._exec, os.path.join(dir, "enclave.git"))
        finally:
            shutil.rmtree(dir, ignore_errors=True)

    def __call__(self, pcrs: Pcrs) -> Release | None:
        id = pcrs.pcr0 + pcrs.pcr1 + pcrs.pcr2
        with self._lock:
            if id in self._found:
                return self._found[id]
            if self._releases is None or self._now() - self._read_at >= 60_000:
                self._read_at = self._now()
                self._releases = None
                self._releases = self._read_main()
            release = next((r for r in self._releases if same_pcrs(r.pcrs, pcrs)), None)
            if release:
                self._found[id] = release
            return release


class _Fetch:
    """One fetch of the keys, which every caller that asks while it runs waits for: a sync one on
    its thread, an async one on its event loop."""

    def __init__(self, generation: int):
        self.generation = generation
        self.keys: concurrent.futures.Future[Keys] = concurrent.futures.Future()
        # Running, so a waiter that is cancelled can't cancel it for the others.
        self.keys.set_running_or_notify_cancel()


def _again(e: VerifyError) -> VerifyError:
    """`e` for one more caller of a fetch, with its own traceback."""
    return VerifyError(e.step, e.reason, e.retryable)


class Keyring:
    """The keys an origin's requests are sealed to, which only `_verify_keys` makes: one per origin
    in a process, shared by every client of it, sync or async. Thread-safe."""

    def __init__(self, origin: str, reach: Reach):
        self.origin = origin
        self.reach = reach
        self._source_of = _Sources(reach.exec, reach.now)
        self._verified: weakref.WeakSet[SealKey] = weakref.WeakSet()
        self._lock = threading.Lock()
        self._held: Keys | None = None
        self._fetching: _Fetch | None = None
        # A 421's replacement bumps the generation, so an older fetch still running never puts its
        # keys back.
        self._generation = 0
        # Only an enclave's offset, from a sealed sealed_stale, moves the clock `ts` is set by.
        self.offset_ms = 0.0

    def now(self) -> int:
        return self.reach.now()

    def _mark_verified(self, keys: tuple[SealKey, ...]) -> None:
        with self._lock:
            self._verified.update(keys)

    def verified(self, keys: Keys) -> bool:
        """Whether every key is one `_verify_keys` made, by identity."""
        with self._lock:
            return all(k in self._verified for k in keys.keys)

    def _listed(self) -> list[str]:
        url = f"{self.origin}/v1/attestation"
        got = get(self.reach.client, url)
        if got.status != 200:
            raise Unfinished(f"{url} answered {got.status}")
        reply = read_json(got.body)
        if not (
            isinstance(reply, dict)
            and reply.get("object") == "proxy_attestation"
            and isinstance(reply.get("instances"), list)
            and all(isinstance(i, str) for i in reply["instances"])
        ):
            raise ValueError(f"{url} is not a list of enclaves")
        return reply["instances"]

    def _verify_keys(self, instances: list[str]) -> Keys:
        """Checks 1 to 3 for each document, and the keys of those that passed, newest first. A key
        any refused document names is left out, though another document of it passed."""
        if not instances:
            raise VerifyError("Attestation", f"{self.origin} lists no enclave", False)
        at = self.now()
        files = _during("Allowed", lambda: fetch_signed_list(self.reach.client))
        try:
            signed: SignedList = verify_signed_list(files, at)
        except Exception as e:  # any error in the list refuses it, as in TS
            raise VerifyError("Allowed", f"Morse's signed list {files.tag} {e}", False) from e
        checked = [
            check_document(instance, f"document {i + 1} of {len(instances)}", signed, self.reach.root, at)
            for i, instance in enumerate(instances)
        ]
        refused = [(c.label, c.reason, c.public_key) for c in checked if isinstance(c, Refused)]
        docs: list[AttestedDocument] = []
        for doc in checked:
            if isinstance(doc, Refused):
                continue
            release = _during("Source", lambda doc=doc: self._source_of(doc.pcrs))
            if release:
                docs.append(doc)
            else:
                name = doc.module_id or doc.key_id.hex()
                refused.append(("Source", f"enclave {name}: {unpublished(doc.pcrs)}", doc.public_key.hex()))
        refused_keys = {key for _, _, key in refused}
        newest: dict[str, AttestedDocument] = {}
        for doc in docs:
            key = doc.public_key.hex()
            known = newest.get(key)
            if key not in refused_keys and (known is None or known.issued_at < doc.issued_at):
                newest[key] = doc
        kept = sorted(newest.values(), key=lambda d: d.issued_at, reverse=True)[:MAX_KEYS]
        if not kept:
            step, reason, _ = refused[0]
            raise VerifyError(step, reason, False)
        keys = tuple(SealKey(d.public_key, d.key_id) for d in kept)
        self._mark_verified(keys)
        return Keys(keys, min(d.issued_at for d in kept) + MAX_AGE_MS)

    def _claim(self) -> Keys | tuple[_Fetch, bool]:
        """The keys held, while the oldest of their documents is under 30 minutes old, or else the
        fetch to wait for, which concurrent callers share, and whether this caller runs it."""
        with self._lock:
            if self._held and self.now() <= self._held.expires_at:
                return self._held
            if self._fetching:
                return self._fetching, False
            self._fetching = _Fetch(self._generation)
            return self._fetching, True

    def _run(self, fetch: _Fetch) -> None:
        """Runs `fetch`, which is over before its callers hear, so keys it finds too old get one
        more fetch, not this one again."""
        try:
            keys = self._verify_keys(_during("Attestation", self._listed))
        except BaseException as e:
            with self._lock:
                self._fetching = None
            fetch.keys.set_exception(e)
            return
        with self._lock:
            self._fetching = None
            if self._generation == fetch.generation:
                self._held = keys
            else:
                keys = self._held or keys
        fetch.keys.set_result(keys)

    def key_set(self) -> Keys:
        """The keys to seal to, fetched on this thread if no other caller is fetching them."""
        claim = self._claim()
        if isinstance(claim, Keys):
            return claim
        fetch, mine = claim
        if mine:
            self._run(fetch)
        try:
            return fetch.keys.result()
        except VerifyError as e:
            raise _again(e) from e

    async def key_set_async(self) -> Keys:
        """key_set() for an event loop, which waits on it, not on a thread. The checks block (git,
        Sigstore), so a fetch runs on one, and runs on for the next call if this one is cancelled."""
        claim = self._claim()
        if isinstance(claim, Keys):
            return claim
        fetch, mine = claim
        if mine:
            asyncio.get_running_loop().run_in_executor(None, self._run, fetch)
        try:
            return await asyncio.wrap_future(fetch.keys)
        except VerifyError as e:
            raise _again(e) from e

    def replace_keys(self, instances: list[str]) -> Keys:
        """The keys of the documents a 421 lists, which replace those held for good."""
        with self._lock:
            self._generation += 1
            mine = self._generation
            self._held = None
        keys = self._verify_keys(instances)
        with self._lock:
            if self._generation == mine:
                self._held = keys
        return keys


# --- What both clients do the same ----------------------------------------------------------------


def _origin_of(url: httpx.URL) -> str:
    host = url.raw_host.decode("ascii")
    if ":" in host:
        host = f"[{host}]"
    return f"{url.scheme}://{host}" + (f":{url.port}" if url.port is not None else "")


@dataclass(frozen=True)
class _Call:
    route: str
    plain: bool
    authorization: str = ""
    # The content headers, by the names the enclave reads.
    headers: dict[str, str] | None = None
    # The path and query the seal's head names.
    path: str = ""


def _read_call(request: httpx.Request, origin: str, name: str) -> _Call:
    """What a request is: a plain GET to pass through, or a call to seal. Raises NotSent for one
    that is neither, or that would send what the relay could read."""
    at = _origin_of(request.url)
    if at != origin:
        raise NotSent(
            f"{name} sends only to {origin}, and this request is to {at}, where your API key would go. {NOTHING_SENT}"
        )
    if request.url.userinfo:
        raise NotSent(
            f"{name} won't send a request whose URL names a user or password, as fetch won't. {NOTHING_SENT}"
        )
    pathname, _, query = request.url.raw_path.decode("ascii").partition("?")
    route = f"{request.method} {pathname}"
    if ambiguous_path(pathname):
        raise NotSent(
            f"{name} won't send {route}: a server could read a dot segment or backslash in its path as another route. {NOTHING_SENT}"
        )
    if plain_route(request.method, pathname):
        return _Call(route, plain=True)
    if not seals_route(request.method, pathname):
        raise NotSent(
            f"{name} won't send {route}: the enclave can't seal it, so it would go out readable. {NOTHING_SENT}"
        )
    authorization = request.headers.get("authorization")
    if not authorization:
        raise NotSent(
            f"{name} won't send {route} without an Authorization header, which the relay refuses. {NOTHING_SENT}"
        )
    headers: dict[str, str] = {}
    for header, value in sorted(request.headers.items()):
        content = CONTENT_HEADER_NAMES.get(header)
        if content:
            headers[content] = value
        elif not dropped_header(header):
            raise NotSent(
                f"{name} won't send the header {header}: the enclave drops it from a seal, and beside one the relay would read it. {NOTHING_SENT}"
            )
    return _Call(route, False, authorization, headers, pathname + (f"?{query}" if query else ""))


def _extensions(request: httpx.Request) -> dict:
    """The SDK's timeout, for each request sent for this one."""
    timeout = request.extensions.get("timeout")
    return {} if timeout is None else {"timeout": timeout}


def _plain_request(request: httpx.Request) -> httpx.Request:
    """A plain GET, with only the API key and Accept."""
    headers = {n: request.headers[n] for n in ("authorization", "accept") if n in request.headers}
    return httpx.Request(request.method, request.url, headers=headers, extensions=_extensions(request))


def _check_keys(ring: Keyring, keys: Keys, tried: bool, name: str) -> None:
    if ring.now() > keys.expires_at:
        raise VerifyError(
            "Attestation",
            "the oldest document that passed was over 30 minutes old by the time its checks finished",
            True,
            FIRST_TRY_SENT if tried else NOTHING_SENT,
        )
    if not ring.verified(keys):
        raise NotSent(f"{name} was about to seal to a key it hadn't verified. {NOTHING_SENT}")


def _sealed_request(
    ring: Keyring, call: _Call, request: httpx.Request, body: bytes, keys: Keys, name: str
) -> tuple[httpx.Request, bytes]:
    """The outer request, which carries only the API key and the sealed content type, and its CEK."""
    ts = math.floor((ring.now() + ring.offset_ms) / 1000)
    assert call.headers is not None
    try:
        sealed, cek = seal_request(
            list(keys.keys), InnerHead(request.method, call.path, call.headers, ts), body
        )
    except HeadTooLarge as e:
        raise NotSent(
            f"{name} won't send {call.route}: {e}, so the enclave would refuse it as request_too_large. The head holds its method, path, query, and content headers. {NOTHING_SENT}"
        ) from None
    outer = httpx.Request(
        "POST",
        f"{ring.origin}/v1/sealed",
        headers={"Authorization": call.authorization, "Content-Type": SEALED_CONTENT_TYPE},
        content=sealed,
        extensions=_extensions(request),
    )
    return outer, cek


def _redirect(res: httpx.Response, origin: str, call: _Call, name: str) -> SealedReplyError | None:
    if 300 <= res.status_code < 400:
        return SealedReplyError(
            f"{origin} answered {call.route} with a redirect ({res.status_code}), which {name} doesn't follow"
        )
    return None


def _unsealed(res: httpx.Response, origin: str, call: _Call, name: str) -> SealedReplyError:
    return SealedReplyError(
        f"{origin} answered {call.route} {res.status_code} without sealing the reply, which only the enclave can do, so {name} refuses it"
    )


def _stale_time(body: bytes) -> float | None:
    """The enclave's clock, in seconds, if `body` is its sealed_stale refusal."""
    reply = read_json(body)
    if not isinstance(reply, dict) or not isinstance(reply.get("error"), dict):
        return None
    t = reply.get("proxy_time")
    if reply["error"].get("code") != "sealed_stale" or isinstance(t, bool) or not isinstance(t, (int, float)):
        return None
    return t


def _unknown_key_instances(body: bytes) -> list[str] | None:
    """The documents a 421's sealed_key_unknown lists."""
    reply = read_json(body)
    if not isinstance(reply, dict) or not isinstance(reply.get("error"), dict):
        return None
    instances = reply.get("instances")
    if reply["error"].get("code") != "sealed_key_unknown" or not (
        isinstance(instances, list) and all(isinstance(i, str) for i in instances)
    ):
        return None
    return instances


def _listing(raw: bytes, origin: str, call: _Call, name: str) -> bytes:
    """A 421's body, read to at most 1 MiB past which it is no list of enclaves."""
    if len(raw) > MAX_BODY:
        raise SealedReplyError(
            f"{origin} answered {call.route} 421 with over 1 MiB, which {name} doesn't read"
        )
    return raw


def _doesnt_open(call: _Call, e: Exception) -> SealedReplyError:
    return SealedReplyError(f"the enclave's sealed reply to {call.route} doesn't open: {e}")


def _first_try(e: VerifyError, tried: bool) -> VerifyError:
    return VerifyError(e.step, e.reason, e.retryable, FIRST_TRY_SENT) if tried else e


def _reply(
    opener: ReplyOpener, res: httpx.Response, stream: httpx.SyncByteStream | httpx.AsyncByteStream
) -> httpx.Response:
    assert opener.head is not None
    # Each value as the bytes fetch's would be, which httpx would otherwise encode as ASCII.
    own = httpx.Headers([(name, value.encode("latin-1")) for name, value in opener.head.headers])
    headers = with_relay_headers(own, res.headers)
    if opener.head.status in NULL_BODY_STATUSES:
        stream = httpx.ByteStream(b"")
    return httpx.Response(opener.head.status, headers=headers, stream=stream)


# --- The sync client ------------------------------------------------------------------------------


class _OpenedStream(httpx.SyncByteStream):
    """The enclave's reply body, each frame's data as it opens. It raises if the reply ends before
    its final frame."""

    def __init__(self, first: list[bytes], opener: ReplyOpener, raw: Iterator[bytes], res: httpx.Response):
        self._first = first
        self._opener = opener
        self._raw = raw
        self._res = res

    def __iter__(self) -> Iterator[bytes]:
        try:
            yield from self._first
            while not self._opener.done:
                data = next(self._raw, None)
                if data is None:
                    self._opener.finish()
                yield from self._opener.feed(data)
        finally:
            self._res.close()

    def close(self) -> None:
        self._res.close()


def _open_sync(res: httpx.Response, cek: bytes, call: _Call) -> httpx.Response:
    """The enclave's reply inside `res`: its own status and headers, then the relay's headers it
    doesn't set. A status with no body is read to its final frame first."""
    opener = ReplyOpener(cek)
    raw = iter(res.stream)
    first: list[bytes] = []
    try:
        while opener.head is None or (opener.head.status in NULL_BODY_STATUSES and not opener.done):
            data = next(raw, None)
            if data is None:
                opener.finish()
            first += opener.feed(data)
        reply = _reply(opener, res, _OpenedStream(first, opener, raw, res))
    except (SealedReplyError, ValueError) as e:
        res.close()
        raise _doesnt_open(call, e) from None
    except BaseException:
        res.close()
        raise
    if opener.done:
        res.close()
    return reply


class AttestedTransport(httpx.BaseTransport):
    def __init__(self, ring: Keyring, send: httpx.BaseTransport, name: str = "attested_client()"):
        self._ring = ring
        self._send = send
        self._name = name

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        ring, name, origin = self._ring, self._name, self._ring.origin
        call = _read_call(request, origin, name)
        if call.plain:
            res = self._send.handle_request(_plain_request(request))
            if error := _redirect(res, origin, call, name):
                res.close()
                raise error
            return res
        body = request.read()
        tried = False

        def wait_for(work: Callable[[], Keys]) -> Keys:
            try:
                return work()
            except VerifyError as e:
                raise _first_try(e, tried) from None

        keys = wait_for(ring.key_set)
        key_retried = clock_retried = False
        while True:
            # Keys checked at the start of a slow fetch can be past 30 minutes at its end. They get
            # one more fetch.
            if ring.now() > keys.expires_at:
                keys = wait_for(ring.key_set)
            _check_keys(ring, keys, tried, name)
            outer, cek = _sealed_request(ring, call, request, body, keys, name)
            res = self._send.handle_request(outer)
            if error := _redirect(res, origin, call, name):
                res.close()
                raise error
            tried = True
            if res.headers.get("content-type") == SEALED_CONTENT_TYPE:
                reply = _open_sync(res, cek, call)
                if reply.status_code == 400 and not clock_retried:
                    proxy_time = _stale_time(reply.read())
                    if proxy_time is not None:
                        clock_retried = True
                        ring.offset_ms = proxy_time * 1000 - ring.now()
                        continue
                return reply
            if res.status_code < 400:
                res.close()
                raise _unsealed(res, origin, call, name)
            if res.status_code != 421 or key_retried:
                return res
            raw = b""
            for chunk in res.stream:
                raw += chunk
                if len(raw) > MAX_BODY:
                    break
            res.close()
            instances = _unknown_key_instances(_listing(raw, origin, call, name))
            if instances is None:
                return httpx.Response(421, headers=res.headers, stream=httpx.ByteStream(raw))
            key_retried = True
            keys = wait_for(lambda instances=instances: ring.replace_keys(instances))

    def close(self) -> None:
        self._send.close()


# --- The async client -----------------------------------------------------------------------------


class _AsyncOpenedStream(httpx.AsyncByteStream):
    def __init__(
        self, first: list[bytes], opener: ReplyOpener, raw: AsyncIterator[bytes], res: httpx.Response
    ):
        self._first = first
        self._opener = opener
        self._raw = raw
        self._res = res

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            for chunk in self._first:
                yield chunk
            while not self._opener.done:
                data = await anext(self._raw, None)
                if data is None:
                    self._opener.finish()
                for chunk in self._opener.feed(data):
                    yield chunk
        finally:
            await self._res.aclose()

    async def aclose(self) -> None:
        await self._res.aclose()


async def _open_async(res: httpx.Response, cek: bytes, call: _Call) -> httpx.Response:
    opener = ReplyOpener(cek)
    raw = res.stream.__aiter__()  # type: ignore[union-attr]
    first: list[bytes] = []
    try:
        while opener.head is None or (opener.head.status in NULL_BODY_STATUSES and not opener.done):
            data = await anext(raw, None)
            if data is None:
                opener.finish()
            first += opener.feed(data)
        reply = _reply(opener, res, _AsyncOpenedStream(first, opener, raw, res))
    except (SealedReplyError, ValueError) as e:
        await res.aclose()
        raise _doesnt_open(call, e) from None
    except BaseException:
        await res.aclose()
        raise
    if opener.done:
        await res.aclose()
    return reply


class AsyncAttestedTransport(httpx.AsyncBaseTransport):
    def __init__(self, ring: Keyring, send: httpx.AsyncBaseTransport, name: str = "attested_async_client()"):
        self._ring = ring
        self._send = send
        self._name = name

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        ring, name, origin = self._ring, self._name, self._ring.origin
        call = _read_call(request, origin, name)
        if call.plain:
            res = await self._send.handle_async_request(_plain_request(request))
            if error := _redirect(res, origin, call, name):
                await res.aclose()
                raise error
            return res
        body = await request.aread()
        tried = False

        # The checks block (git, Sigstore), so they run on a thread. A caller cancelled meanwhile
        # stops waiting, and the check runs on for the next call.
        async def wait_for(work: Awaitable[Keys]) -> Keys:
            try:
                return await work
            except VerifyError as e:
                raise _first_try(e, tried) from None

        keys = await wait_for(ring.key_set_async())
        key_retried = clock_retried = False
        while True:
            if ring.now() > keys.expires_at:
                keys = await wait_for(ring.key_set_async())
            _check_keys(ring, keys, tried, name)
            outer, cek = _sealed_request(ring, call, request, body, keys, name)
            res = await self._send.handle_async_request(outer)
            if error := _redirect(res, origin, call, name):
                await res.aclose()
                raise error
            tried = True
            if res.headers.get("content-type") == SEALED_CONTENT_TYPE:
                reply = await _open_async(res, cek, call)
                if reply.status_code == 400 and not clock_retried:
                    proxy_time = _stale_time(await reply.aread())
                    if proxy_time is not None:
                        clock_retried = True
                        ring.offset_ms = proxy_time * 1000 - ring.now()
                        continue
                return reply
            if res.status_code < 400:
                await res.aclose()
                raise _unsealed(res, origin, call, name)
            if res.status_code != 421 or key_retried:
                return res
            raw = b""
            async for chunk in res.stream:  # type: ignore[union-attr]
                raw += chunk
                if len(raw) > MAX_BODY:
                    break
            await res.aclose()
            instances = _unknown_key_instances(_listing(raw, origin, call, name))
            if instances is None:
                return httpx.Response(421, headers=res.headers, stream=httpx.ByteStream(raw))
            key_retried = True
            keys = await wait_for(asyncio.to_thread(ring.replace_keys, instances))

    async def aclose(self) -> None:
        await self._send.aclose()


# --- The clients ----------------------------------------------------------------------------------

_rings: dict[str, Keyring] = {}
_rings_lock = threading.Lock()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _origin(origin: str, name: str) -> str:
    at = httpx.URL(origin)
    if at.scheme != "https":
        raise ValueError(
            f"{name} sends only over HTTPS, so not to {origin}: your API key would cross the network readable"
        )
    return _origin_of(at)


def keyring(origin: str = ORIGIN, name: str = "attested_client()") -> Keyring:
    """The keyring every client of `origin` in this process shares. `name` is the client's, for
    the error an origin not over HTTPS raises."""
    at = _origin(origin, name)
    with _rings_lock:
        if at not in _rings:
            reach = Reach(default_client(), run_program, _now_ms, NITRO_ROOT)
            _rings[at] = Keyring(at, reach)
        return _rings[at]


def _no_cookies() -> CookieJar:
    # A cookie the relay or its load balancer sets would be a header the seal can't carry.
    return CookieJar(DefaultCookiePolicy(allowed_domains=[]))


def _without_accept_encoding(client: T) -> T:
    # httpx asks for compression by default, as fetch does below its Headers; neither goes in a seal.
    del client.headers["accept-encoding"]  # type: ignore[attr-defined]
    return client


def sync_client(ring: Keyring, send: httpx.BaseTransport | None = None, **kwargs) -> httpx.Client:
    """attested_client() for `ring`, sending through `send`. Tests pass their own."""
    transport = AttestedTransport(ring, send or httpx.HTTPTransport())
    return _without_accept_encoding(httpx.Client(transport=transport, cookies=_no_cookies(), **kwargs))


def async_client(ring: Keyring, send: httpx.AsyncBaseTransport | None = None, **kwargs) -> httpx.AsyncClient:
    """attested_async_client() for `ring`, sending through `send`."""
    transport = AsyncAttestedTransport(ring, send or httpx.AsyncHTTPTransport())
    return _without_accept_encoding(httpx.AsyncClient(transport=transport, cookies=_no_cookies(), **kwargs))


def attested_client(
    origin: str = ORIGIN,
    *,
    proxy: str | httpx.Proxy | None = None,
    timeout: httpx.Timeout | float | None = None,
) -> httpx.Client:
    """An httpx.Client that seals every request carrying content to Morse's verified enclave keys,
    passes the relay's four plain GETs through, and raises for anything else. Pass it to OpenAI(...,
    http_client=attested_client()). It needs git on PATH, to check each image's source. Every
    client of an origin in this process shares its keys and lookups. `proxy` is the proxy its
    requests go through; `timeout` is the default the SDK's own overrides."""
    ring = keyring(origin)
    kwargs = {} if timeout is None else {"timeout": timeout}
    return sync_client(ring, httpx.HTTPTransport(proxy=proxy), **kwargs)


def attested_async_client(
    origin: str = ORIGIN,
    *,
    proxy: str | httpx.Proxy | None = None,
    timeout: httpx.Timeout | float | None = None,
) -> httpx.AsyncClient:
    """attested_client() for AsyncOpenAI(..., http_client=attested_async_client())."""
    ring = keyring(origin, "attested_async_client()")
    kwargs = {} if timeout is None else {"timeout": timeout}
    return async_client(ring, httpx.AsyncHTTPTransport(proxy=proxy), **kwargs)
