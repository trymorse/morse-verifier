# The real openai SDK, sync and async, through attested_client() and attested_async_client() to the
# stub relay: what a user's code does, and what it gets back.
from __future__ import annotations

import asyncio
import json
import os
import threading
from collections.abc import Callable, Iterator

import httpx
import openai
import pytest
from opener import key_ids_of
from relay import Answer, Plain
from stub import AsyncRecording, Enclave, Recording, Setup, opened_head

from trymorse_verify.attested import (
    ORIGIN,
    NotSent,
    async_client,
    attested_async_client,
    attested_client,
    keyring,
    sync_client,
)
from trymorse_verify.seal import SealedReplyError

COMPLETION = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "created": 1793961340,
    "model": "m",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello"}, "finish_reason": "stop"}],
}


def chunk(content: str | None, finish: str | None = None) -> str:
    delta = {} if content is None else {"content": content}
    body = {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 1793961340,
        "model": "m",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }
    return f"data: {json.dumps(body)}\n\n"


def answer(status: int, body: object, content_type: str = "application/json") -> Callable:
    return lambda _: Answer(status, {"Content-Type": [content_type]}, [json.dumps(body)])


class Sdk:
    """The OpenAI SDK through an attested client, sync or async, called the same way."""

    def __init__(self, s: Setup, flavor: str, base_url: str | None = None, **kwargs):
        self.flavor = flavor
        options = {"base_url": base_url or f"{s.at}/v1", "api_key": "sk_test", "max_retries": 0, **kwargs}
        if flavor == "sync":
            self.client = openai.OpenAI(**options, http_client=s.client())
        else:
            self.loop = asyncio.new_event_loop()
            self.client = openai.AsyncOpenAI(**options, http_client=s.async_client())

    def __call__(self, call: Callable):
        """call(client), awaited if the client is async."""
        result = call(self.client)
        return result if self.flavor == "sync" else self.loop.run_until_complete(result)

    def iterate(self, stream) -> Iterator:
        if self.flavor == "sync":
            yield from stream
            return
        it = stream.__aiter__()
        while True:
            try:
                yield self.loop.run_until_complete(it.__anext__())
            except StopAsyncIteration:
                return

    def close(self) -> None:
        if self.flavor == "sync":
            self.client.close()
        else:
            self.loop.run_until_complete(self.client.close())
            self.loop.close()


@pytest.fixture(params=["sync", "async"])
def sdk(request):
    made: list[Sdk] = []

    def make(s: Setup, **kwargs) -> Sdk:
        made.append(Sdk(s, request.param, **kwargs))
        return made[-1]

    yield make
    for m in made:
        m.close()


def raised(sdk: Sdk, call: Callable, kind: type[BaseException]) -> BaseException:
    """What `call` raised, which must be `kind` or be caused by it, as an older SDK wraps it."""
    with pytest.raises(Exception) as e:
        sdk(call)
    error: BaseException | None = e.value
    while error is not None and not isinstance(error, kind):
        error = error.__cause__ or error.__context__
    assert error is not None, f"{e.value!r} is no {kind.__name__}"
    return error


def chat(**kwargs) -> Callable:
    return lambda c: c.chat.completions.create(
        model="m", messages=[{"role": "user", "content": "hi"}], **kwargs
    )


def test_a_chat_is_sealed_to_the_verified_key_and_its_reply_opened(setup, sdk):
    s = setup(answer=answer(200, COMPLETION))
    client = sdk(s)
    completion = client(chat())
    assert completion.choices[0].message.content == "Hello"
    [call] = s.relay.sealed()
    assert call.key_ids == [s.live[0].key_id]
    head = opened_head(call)
    assert head["method"] == "POST" and head["path"] == "/v1/chat/completions"
    assert head["headers"] == {"Content-Type": "application/json"}
    assert json.loads(call.opened.body) == {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    # The relay sees the API key and the sealed content type, and nothing that names the SDK.
    assert sorted(call.headers) == ["authorization", "content-length", "content-type", "host"]
    assert call.headers["authorization"] == "Bearer sk_test"
    assert s.relay.routes() == ["GET /v1/attestation", "POST /v1/sealed"]


def test_a_streamed_chat_arrives_as_each_frame_opens(setup, sdk):
    released = threading.Event()

    def chunks():
        yield chunk("Hel")
        released.wait(5)
        yield chunk("lo")
        yield chunk(None, "stop")
        yield "data: [DONE]\n\n"

    s = setup(answer=lambda _: Answer(200, {"Content-Type": ["text/event-stream"]}, chunks()))
    client = sdk(s)
    stream = client(chat(stream=True))
    it = client.iterate(stream)
    assert next(it).choices[0].delta.content == "Hel"
    assert not released.is_set()
    released.set()
    rest = [c.choices[0].delta.content for c in it]
    assert rest == ["lo", None]


def test_a_streamed_chat_cut_before_its_final_frame_raises(setup, sdk):
    s = setup(
        answer=lambda _: Answer(200, {"Content-Type": ["text/event-stream"]}, [chunk("Hel")], truncated=True)
    )
    client = sdk(s)
    stream = client(chat(stream=True))
    it = client.iterate(stream)
    assert next(it).choices[0].delta.content == "Hel"
    with pytest.raises(SealedReplyError, match="^the reply ends before its final frame$"):
        next(it)


def test_a_transcription_upload_is_sealed_with_its_multipart_boundary(setup, sdk):
    s = setup(answer=answer(200, {"text": "hi there"}))
    client = sdk(s)
    got = client(
        lambda c: c.audio.transcriptions.create(model="whisper-1", file=("a.wav", b"RIFF audio", "audio/wav"))
    )
    assert got.text == "hi there"
    opened = s.relay.sealed()[0].opened
    content_type = opened.head["headers"]["Content-Type"]
    assert content_type.startswith("multipart/form-data; boundary=")
    boundary = content_type.split("boundary=")[1].encode()
    parts = opened.body.split(b"--" + boundary)
    assert any(b'name="model"' in p and p.endswith(b"whisper-1\r\n") for p in parts)
    assert any(b'filename="a.wav"' in p and b"RIFF audio" in p for p in parts)


def test_models_list_goes_to_the_relay_in_the_clear_with_only_the_key_and_accept(setup, sdk):
    s = setup()
    client = sdk(s)
    error = raised(client, lambda c: c.models.list(), openai.AuthenticationError)
    assert error.status_code == 401
    assert s.relay.routes() == ["GET /v1/models"]
    assert sorted(s.relay.calls[0].headers) == ["accept", "authorization", "host"]
    assert s.world.fetched == []


def test_embeddings_raise_and_send_nothing(setup, sdk):
    s = setup()
    client = sdk(s)
    error = raised(client, lambda c: c.embeddings.create(model="m", input="hi"), NotSent)
    assert "won't send POST /v1/embeddings: the enclave can't seal it" in str(error)
    assert s.relay.calls == [] and s.world.fetched == []


def test_another_origin_raises_and_sends_nothing(setup, sdk):
    s = setup()
    client = sdk(s, base_url="https://api.openai.com/v1")
    error = raised(client, chat(), NotSent)
    assert f"sends only to {s.at}, and this request is to https://api.openai.com" in str(error)
    assert s.relay.calls == [] and s.world.fetched == []


def test_a_421_is_retried_once_sealed_to_the_keys_its_documents_list(setup, sdk, clock):
    gone, fresh = Enclave(clock), Enclave(clock)
    s = setup(
        live=[fresh],
        listed=lambda: [gone.document()],
        listed_on_421=lambda: [fresh.document()],
        answer=answer(200, COMPLETION),
    )
    client = sdk(s)
    assert client(chat()).choices[0].message.content == "Hello"
    assert [c.key_ids for c in s.relay.sealed()] == [[gone.key_id], [fresh.key_id]]


def test_a_sealed_stale_is_retried_once_on_the_enclaves_clock(setup, sdk):
    from world import NOW

    enclave_seconds = NOW // 1000 + 600

    def stale_unless_near(opened) -> Answer:
        if abs(opened.head["ts"] - enclave_seconds) <= 120:
            return Answer(200, {"Content-Type": ["application/json"]}, [json.dumps(COMPLETION)])
        body = {"error": {"code": "sealed_stale", "message": "stale"}, "proxy_time": enclave_seconds}
        return Answer(400, {"Content-Type": ["application/json"]}, [json.dumps(body)])

    s = setup(answer=stale_unless_near)
    client = sdk(s)
    assert client(chat()).choices[0].message.content == "Hello"
    assert [opened_head(c)["ts"] for c in s.relay.sealed()] == [NOW // 1000, enclave_seconds]


def test_an_unsealed_success_is_refused(setup, sdk):
    s = setup(
        plain=lambda c: (
            Plain(200, {"content-type": "application/json"}, json.dumps(COMPLETION))
            if c.path == "/v1/sealed"
            else None
        )
    )
    client = sdk(s)
    error = raised(client, chat(), SealedReplyError)
    assert str(error).endswith(
        "answered POST /v1/chat/completions 200 without sealing the reply, which only the enclave can do, so "
        + ("attested_client()" if client.flavor == "sync" else "attested_async_client()")
        + " refuses it"
    )


def test_the_relays_refusal_in_the_clear_reaches_the_sdk_as_its_error(setup, sdk):
    body = {"error": {"message": "Top up.", "type": "insufficient_balance", "code": "insufficient_balance"}}
    s = setup(
        plain=lambda c: (
            Plain(402, {"content-type": "application/json"}, json.dumps(body))
            if c.path == "/v1/sealed"
            else None
        )
    )
    client = sdk(s)
    error = raised(client, chat(), openai.APIStatusError)
    assert (error.status_code, error.code) == (402, "insufficient_balance")


def test_a_reply_slower_than_the_sdks_timeout_raises_its_timeout_error(setup, sdk):
    released = threading.Event()

    def slow(opened) -> Answer:
        released.wait(5)
        return Answer(200, {"Content-Type": ["application/json"]}, [json.dumps(COMPLETION)])

    s = setup(answer=slow)
    client = sdk(s, timeout=0.5)
    try:
        raised(client, chat(), openai.APITimeoutError)
    finally:
        released.set()
    assert len(s.relay.sealed()) == 1


def test_one_client_serves_concurrent_calls_with_one_check(setup, sdk):
    s = setup(answer=answer(200, COMPLETION))
    client = sdk(s)
    if client.flavor == "sync":
        results: list[str] = []
        threads = [
            threading.Thread(target=lambda: results.append(client(chat()).choices[0].message.content))
            for _ in range(3)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
    else:

        async def all_three():
            got = await asyncio.gather(*(chat()(client.client) for _ in range(3)))
            return [g.choices[0].message.content for g in got]

        results = client.loop.run_until_complete(all_three())
    assert results == ["Hello"] * 3
    assert s.relay.listings() == 1
    assert len(s.relay.sealed()) == 3


def test_the_clients_are_what_openai_takes(setup):
    s = setup()
    assert openai.OpenAI(api_key="k", http_client=sync_client(s.ring))
    assert openai.AsyncOpenAI(api_key="k", http_client=async_client(s.ring))


live = pytest.mark.skipif(os.environ.get("VERIFY_LIVE") != "1", reason="VERIFY_LIVE=1 runs it against prod")


@live
@pytest.mark.parametrize("flavor", ["sync", "async"])
def test_against_prod_a_bogus_key_is_sealed_to_verified_enclaves_and_gets_the_relays_401(flavor):
    """The real checks, git, and Sigstore against api.trymorse.ai, with an API key that is no one's:
    the request goes out sealed to keys that passed, and the relay refuses the key in the clear."""
    sent: list[httpx.Request] = []
    ring = keyring()
    options = {"base_url": f"{ORIGIN}/v1", "api_key": "sk_" + "0" * 48, "max_retries": 0}
    loop = asyncio.new_event_loop()
    if flavor == "sync":
        client = openai.OpenAI(**options, http_client=sync_client(ring, Recording(sent)))

        def run(call):
            return call(client)
    else:
        client = openai.AsyncOpenAI(**options, http_client=async_client(ring, AsyncRecording(sent)))

        def run(call):
            return loop.run_until_complete(call(client))

    try:
        with pytest.raises(openai.AuthenticationError) as e:
            run(chat())
        assert e.value.status_code == 401
        assert [(r.method, str(r.url)) for r in sent] == [("POST", f"{ORIGIN}/v1/sealed")]
        assert sorted(sent[0].headers) == ["authorization", "content-length", "content-type", "host"]
        assert sent[0].headers["content-type"] == "application/morse-sealed"
        keys = ring.key_set()
        assert 1 <= len(keys.keys) <= 4 and ring.verified(keys)
        body = sent[0].content
        assert (body[0], body[1]) == (1, len(keys.keys))
        assert key_ids_of(body) == [k.key_id.hex() for k in keys.keys]
        assert len(body) % 1024 == (2 + 88 * len(keys.keys)) % 1024

        with pytest.raises(NotSent, match="won't send POST /v1/embeddings"):
            run(lambda c: c.embeddings.create(model="m", input="hi"))
        assert len(sent) == 1
    finally:
        if flavor == "async":
            loop.run_until_complete(client.close())
        loop.close()


@live
def test_against_prod_the_public_clients_get_the_relays_401_for_a_bogus_key():
    options = {"base_url": f"{ORIGIN}/v1", "api_key": "sk_" + "0" * 48, "max_retries": 0}
    with pytest.raises(openai.AuthenticationError):
        openai.OpenAI(**options, http_client=attested_client()).chat.completions.create(
            model="m", messages=[{"role": "user", "content": "hi"}]
        )

    async def main():
        async with openai.AsyncOpenAI(**options, http_client=attested_async_client()) as c:
            await c.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])

    with pytest.raises(openai.AuthenticationError):
        asyncio.run(main())
