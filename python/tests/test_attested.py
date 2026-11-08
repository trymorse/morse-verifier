# attested_client() and attested_async_client(), as src/node/attested.test.ts holds attested(): over
# real HTTP to a stub relay (relay.py) whose enclaves open seals with test keys, with documents a
# forged Nitro root signs, GitHub as the captures of 2026-11-06 have it, and a clock the test moves.
from __future__ import annotations

import asyncio
import concurrent.futures
import json
import re
import threading
from collections.abc import Callable

import pytest
from relay import Answer, Plain
from stub import CHAT, CHAT_HEADERS, SDK, UNLISTED, UNPUBLISHED, Enclave, opened_head
from world import LOG, MINUTE, NOW, World

from trymorse_verify import attested
from trymorse_verify.attested import (
    FIRST_TRY_SENT,
    Keyring,
    NotSent,
    VerifyError,
    attested_async_client,
    attested_client,
    keyring,
)
from trymorse_verify.io import TimedOut
from trymorse_verify.seal import SealedReplyError


class TestASealedCall:
    def test_seals_the_path_query_body_and_content_type_to_the_verified_key_and_sends_only_the_key_and_type(
        self, setup
    ):
        s = setup()
        res = s.chat("/v1/chat/completions?trace=1")
        assert res.status_code == 200
        assert res.json() == {"ok": True}
        assert res.headers["x-request-id"] == "req_relay"
        assert s.relay.routes() == ["GET /v1/attestation", "POST /v1/sealed"]
        [call] = s.relay.sealed()
        assert call.key_ids == [s.live[0].key_id]
        assert opened_head(call) == {
            "method": "POST",
            "path": "/v1/chat/completions?trace=1",
            "headers": {"Content-Type": "application/json"},
            "ts": NOW // 1000,
            "body_len": len(CHAT),
        }
        assert call.opened.body.decode() == CHAT
        assert dict(s.sent[-1].headers) == {
            "host": s.at.removeprefix("http://"),
            "authorization": "Bearer sk_test",
            "content-type": "application/morse-sealed",
            "content-length": str(len(call.body)),
        }
        assert sorted(call.headers) == ["authorization", "content-length", "content-type", "host"]

    # The enclave sends a 204's frames to the final one, which the client reads, and gives no body
    # though a frame held data.
    def test_gives_a_204_no_body_once_its_reply_has_ended_in_its_final_frame(self, setup):
        truncated = [False]
        s = setup(answer=lambda _: Answer(204, chunks=["data"], truncated=truncated[0]))
        res = s.chat()
        assert (res.status_code, res.content) == (204, b"")
        truncated[0] = True
        with pytest.raises(SealedReplyError) as e:
            s.chat()
        assert str(e.value) == (
            "the enclave's sealed reply to POST /v1/chat/completions doesn't open: the reply ends before its final frame"
        )

    def test_gives_the_replys_latin_1_headers_as_fetch_would_and_raises_for_one_fetch_refuses(self, setup):
        headers = [{"Content-Disposition": ["attachment; filename=café.mp4"]}]
        s = setup(answer=lambda _: Answer(200, headers[0], ["{}"]))
        assert s.chat().headers["content-disposition"] == "attachment; filename=café.mp4"
        headers[0] = {"X-Note": ["Ā"]}
        with pytest.raises(SealedReplyError) as e:
            s.chat()
        assert str(e.value) == (
            "the enclave's sealed reply to POST /v1/chat/completions doesn't open: the reply's header \"X-Note\" is not one fetch takes"
        )
        assert len(s.relay.sealed()) == 2

    def test_drops_the_content_length_and_host_the_request_carried_which_the_sealed_request_sets_itself(
        self, setup
    ):
        s = setup()
        res = s.chat(headers={**CHAT_HEADERS, "Content-Length": str(len(CHAT))})
        assert res.status_code == 200
        assert opened_head(s.relay.sealed()[0])["headers"] == {"Content-Type": "application/json"}
        assert s.relay.sealed()[0].headers["content-length"] == str(len(s.relay.sealed()[0].body))

    def test_raises_on_a_redirect_of_the_sealed_request_and_doesnt_follow_it(self, setup):
        s = setup(
            plain=lambda c: Plain(307, {"location": "/v1/elsewhere"}) if c.path == "/v1/sealed" else None
        )
        with s.client(follow_redirects=True) as c, pytest.raises(SealedReplyError) as e:
            c.post(f"{s.at}/v1/chat/completions", headers=CHAT_HEADERS, content=CHAT)
        assert str(e.value) == (
            f"{s.at} answered POST /v1/chat/completions with a redirect (307), which attested_client() doesn't follow"
        )
        assert s.relay.routes() == ["GET /v1/attestation", "POST /v1/sealed"]

    def test_passes_the_relays_refusal_in_the_clear_on_and_refuses_a_clear_success(self, setup):
        plain = [
            Plain(402, {"content-type": "application/json"}, '{"error":{"code":"insufficient_balance"}}')
        ]
        s = setup(plain=lambda c: plain[0] if c.path == "/v1/sealed" else None)
        refused = s.chat()
        assert refused.status_code == 402
        assert refused.text == plain[0].body
        plain[0] = Plain(200, {"content-type": "application/json"}, '{"choices":[]}')
        with pytest.raises(SealedReplyError) as e:
            s.chat()
        assert str(e.value) == (
            f"{s.at} answered POST /v1/chat/completions 200 without sealing the reply, which only the enclave can do, so attested_client() refuses it"
        )

    def test_raises_for_a_421_of_over_1_mib_which_is_no_list_of_enclaves(self, setup):
        s = setup(plain=lambda c: Plain(421, {}, "x" * (1 << 20) + "x") if c.path == "/v1/sealed" else None)
        with pytest.raises(SealedReplyError) as e:
            s.chat()
        assert str(e.value) == (
            f"{s.at} answered POST /v1/chat/completions 421 with over 1 MiB, which attested_client() doesn't read"
        )

    def test_keeps_no_cookie_the_relay_sets_which_would_be_a_header_the_seal_cant_carry(self, setup):
        s = setup(
            plain=lambda c: (
                Plain(401, {"set-cookie": "AWSALB=x; Path=/"}, "{}") if c.path == "/v1/models" else None
            )
        )
        with s.client() as c:
            assert c.get(f"{s.at}/v1/models", headers=SDK).status_code == 401
            assert (
                c.post(f"{s.at}/v1/chat/completions", headers=CHAT_HEADERS, content=CHAT).status_code == 200
            )


class TestWhatItWontSend:
    def test_passes_the_relays_plain_gets_through_with_only_the_key_and_accept_and_fetches_no_keys(
        self, setup
    ):
        s = setup()
        with s.client() as c:
            res = c.get(f"{s.at}/v1/models", headers=SDK)
        assert res.status_code == 401
        assert res.json() == {
            "error": {
                "message": "Incorrect API key provided.",
                "type": "invalid_request_error",
                "param": None,
                "code": "invalid_api_key",
            }
        }
        assert s.relay.routes() == ["GET /v1/models"]
        assert dict(s.sent[0].headers) == {
            "host": s.at.removeprefix("http://"),
            "authorization": "Bearer sk_test",
            "accept": "application/json",
        }

    def test_raises_for_a_route_the_enclave_cant_seal_another_origin_a_header_it_doesnt_know_or_a_redirect(
        self, setup
    ):
        s = setup(
            plain=lambda c: (
                Plain(302, {"location": "https://elsewhere.example/"})
                if c.path == "/v1/receipts/r1"
                else None
            )
        )

        def raised(url: str, **o) -> str:
            with s.client() as c, pytest.raises((NotSent, SealedReplyError)) as e:
                c.request(o.pop("method", "POST"), url, **o)
            return str(e.value)

        assert raised(f"{s.at}/v1/embeddings", headers=CHAT_HEADERS, content='{"input":"hi"}') == (
            "attested_client() won't send POST /v1/embeddings: the enclave can't seal it, so it would go out readable. Nothing was sent."
        )
        assert raised("https://api.openai.com/v1/chat/completions", headers=CHAT_HEADERS, content=CHAT) == (
            f"attested_client() sends only to {s.at}, and this request is to https://api.openai.com, where your API key would go. Nothing was sent."
        )
        assert raised(
            f"{s.at}/v1/chat/completions", headers={**CHAT_HEADERS, "X-Debug": "1"}, content=CHAT
        ).startswith("attested_client() won't send the header x-debug: ")
        assert raised(
            f"{s.at}/v1/chat/completions", headers={"Content-Type": "application/json"}, content=CHAT
        ) == (
            "attested_client() won't send POST /v1/chat/completions without an Authorization header, which the relay refuses. Nothing was sent."
        )
        assert raised(f"{s.at}/v1/receipts/%2e%2e", method="GET", headers=SDK) == (
            "attested_client() won't send GET /v1/receipts/%2e%2e: a server could read a dot segment or backslash in its path as another route. Nothing was sent."
        )
        assert s.relay.routes() == []
        assert s.world.fetched == []
        assert "answered GET /v1/receipts/r1 with a redirect (302)" in raised(
            f"{s.at}/v1/receipts/r1", method="GET", headers=SDK
        )

    def test_raises_for_a_request_whose_sealed_head_is_over_the_enclaves_8_kib(self, setup):
        s = setup()
        with s.client() as c, pytest.raises(NotSent) as e:
            c.get(f"{s.at}/v1/lookup/svc/x?q={'a' * 9000}", headers=SDK)
        assert str(e.value) == (
            "attested_client() won't send GET /v1/lookup/svc/x: the sealed head is 9087 bytes, over the proxy's 8192, so the enclave would refuse it as request_too_large. The head holds its method, path, query, and content headers. Nothing was sent."
        )
        assert s.relay.sealed() == []

    def test_only_goes_to_an_https_origin_and_shares_one_keyring_per_origin(self):
        with pytest.raises(ValueError, match=r"^attested_client\(\) sends only over HTTPS"):
            attested_client("http://api.trymorse.ai")
        with pytest.raises(ValueError, match=r"^attested_async_client\(\) sends only over HTTPS"):
            attested_async_client("http://api.trymorse.ai")
        assert keyring() is keyring("https://api.trymorse.ai/")
        assert keyring() is not keyring("https://inference.trymorse.ai")
        assert attested_client()._transport._ring is attested_async_client()._transport._ring  # type: ignore[attr-defined]

    def test_asks_for_no_compression_which_would_be_a_header_beside_the_seal(self):
        assert "accept-encoding" not in attested_client().headers
        assert "accept-encoding" not in attested_async_client().headers


class TestTheKeysItSealsTo:
    def test_are_only_those_every_document_of_which_passed_attestation_allowed_and_source(self, setup, clock):
        good, also_unlisted, also_stale, forged, unpublished = (Enclave(clock) for _ in range(5))
        s = setup(
            live=[good, also_unlisted, also_stale, forged, unpublished],
            listed=lambda: [
                good.document(),
                also_unlisted.document(),
                also_unlisted.document(pcrs=UNLISTED),
                also_stale.document(),
                also_stale.document(timestamp=clock() - 31 * MINUTE),
                forged.document(sign_with="stranger"),
                unpublished.document(pcrs=UNPUBLISHED),
            ],
        )
        assert s.chat().status_code == 200
        assert [c.key_ids for c in s.relay.sealed()] == [[good.key_id]]

    def test_are_the_newest_four_newest_first_since_a_seal_names_at_most_four(self, setup, clock):
        five = [Enclave(clock) for _ in range(5)]
        s = setup(
            live=five,
            listed=lambda: list(
                reversed([e.document(timestamp=clock() - (i + 1) * MINUTE) for i, e in enumerate(five)])
            ),
        )
        s.chat()
        assert s.relay.sealed()[0].key_ids == [e.key_id for e in five[:4]]

    def test_are_fetched_again_once_the_oldest_of_their_documents_is_30_minutes_old(self, setup, clock):
        old, young = Enclave(clock), Enclave(clock)
        s = setup(
            live=[old, young],
            listed=lambda: [old.document(timestamp=clock() - 29 * MINUTE), young.document()],
        )
        s.chat()
        clock.ms += MINUTE
        s.chat()
        assert s.relay.listings() == 1
        clock.ms += 1
        s.chat()
        assert s.relay.listings() == 2

    def test_that_turn_30_minutes_old_while_checked_get_one_more_fetch_and_are_never_sealed_to(
        self, setup, clock
    ):
        slow = Enclave(clock)

        def github(url: str) -> None:
            if url.endswith("prod.statement.json"):
                clock.ms += 2 * MINUTE

        s = setup(live=[slow], listed=lambda: [slow.document(timestamp=clock() - 29 * MINUTE)], github=github)
        with pytest.raises(VerifyError) as e:
            s.chat()
        assert (e.value.step, e.value.retryable) == ("Attestation", True)
        assert str(e.value) == (
            "Attestation could not finish: the oldest document that passed was over 30 minutes old by the time its checks finished. Nothing was sent."
        )
        assert s.relay.listings() == 2
        assert s.relay.sealed() == []

    # Only _verify_keys makes keys, so to show the check right before a seal holds, the test stops
    # the keyring from recording the keys it verified.
    def test_are_each_checked_right_before_the_seal_as_ones_it_verified(self, setup, monkeypatch):
        s = setup()
        monkeypatch.setattr(Keyring, "_mark_verified", lambda self, keys: None)
        with pytest.raises(NotSent) as e:
            s.chat()
        assert (
            str(e.value)
            == "attested_client() was about to seal to a key it hadn't verified. Nothing was sent."
        )
        assert s.relay.sealed() == []

    def test_raise_a_verify_error_naming_the_check_that_refused_when_none_passes_sending_nothing(
        self, setup, clock
    ):
        unlisted = Enclave(clock)
        s = setup(live=[unlisted], listed=lambda: [unlisted.document(pcrs=UNLISTED)])
        with pytest.raises(VerifyError) as e:
            s.chat()
        assert (e.value.step, e.value.retryable) == ("Allowed", False)
        assert str(e.value) == (
            "Allowed failed: enclave i-0123-enc0123 runs PCR0 abababababab…abababab, which is not on Morse's signed list. Nothing was sent."
        )
        assert s.relay.routes() == ["GET /v1/attestation"]

    def test_cant_be_checked_without_git_and_the_error_says_so(self, setup):
        s = setup(world=World(git="missing"))
        with pytest.raises(VerifyError) as e:
            s.chat()
        assert (e.value.step, e.value.retryable) == ("Source", True)
        assert str(e.value) == (
            "Source could not finish: the Source check runs git, which isn't on this machine's PATH. Install git (https://git-scm.com) and run again. Nothing was sent."
        )
        assert s.relay.sealed() == []

    def test_cant_be_checked_when_git_runs_past_its_60_seconds(self, setup):
        def stuck(faked):
            def run(command, args, **o):
                if command == "git" and args[0] == "clone":
                    assert o["timeout_ms"] == 60_000
                    raise TimedOut("git ran for more than 60000 ms")
                return faked(command, args, **o)

            return run

        s = setup(exec=stuck)
        with pytest.raises(VerifyError) as e:
            s.chat()
        assert (e.value.step, e.value.retryable) == ("Source", True)
        assert str(e.value) == (
            "Source could not finish: git clone of https://github.com/trymorse/morse-enclave didn't finish in 60 s. Check that this machine reaches github.com, and run again. Nothing was sent."
        )

    def test_cant_be_checked_without_a_temporary_directory_to_clone_into(self, setup, monkeypatch):
        monkeypatch.setenv("TMPDIR", "/proc/nope")
        s = setup()
        with pytest.raises(VerifyError) as e:
            s.chat()
        assert (e.value.step, e.value.retryable) == ("Source", True)
        assert str(e.value) == (
            "Source could not finish: it can't make a temporary directory in /proc/nope (ENOENT). Set TMPDIR to a directory it can write, and run again. Nothing was sent."
        )
        assert s.relay.sealed() == []

    def test_of_an_image_main_doesnt_name_read_main_again_once_a_minute_has_passed(self, setup, clock):
        world = World(log="\0".join(LOG.split("\0")[1:]))
        s = setup(world=world)
        with pytest.raises(VerifyError, match="^Source failed: "):
            s.chat()
        world.log = None
        clock.ms += MINUTE - 1
        with pytest.raises(VerifyError, match="^Source failed: "):
            s.chat()
        clock.ms += 1
        assert s.chat().status_code == 200
        assert sum(c[1] == "clone" for c in s.world.ran) == 2

    def test_are_fetched_once_for_concurrent_calls_and_again_with_the_signed_list_after_30_minutes(
        self, setup, clock, monkeypatch
    ):
        cloning, cloned, waiting = threading.Event(), threading.Event(), threading.Semaphore(0)

        def held(faked):
            def run(command, args, **o):
                if args[0] == "clone":
                    cloning.set()
                    cloned.wait(5)
                return faked(command, args, **o)

            return run

        class Keys(concurrent.futures.Future):
            def result(self, timeout=None):
                waiting.release()
                return super().result(timeout)

        class Fetch(attested._Fetch):
            def __init__(self, generation: int):
                super().__init__(generation)
                self.keys = Keys()
                self.keys.set_running_or_notify_cancel()

        monkeypatch.setattr(attested, "_Fetch", Fetch)
        s = setup(exec=held)

        def statements() -> int:
            return sum(u.endswith("prod.statement.json") for u in s.world.fetched)

        def clones() -> int:
            return sum(c[1] == "clone" for c in s.world.ran)

        results: list[int] = []
        threads = [threading.Thread(target=lambda: results.append(s.chat().status_code)) for _ in range(2)]
        threads[0].start()
        assert cloning.wait(5)
        threads[1].start()
        # The second call waits on the first one's fetch, which is cloning.
        assert waiting.acquire(timeout=5)
        cloned.set()
        for t in threads:
            t.join(5)
        assert results == [200, 200]
        assert [s.relay.listings(), statements(), clones()] == [1, 1, 1]
        clock.ms += 29 * MINUTE
        s.chat()
        assert statements() == 1
        clock.ms += MINUTE + 1
        s.chat()
        assert [s.relay.listings(), statements(), clones()] == [2, 2, 1]


class TestA421SealedKeyUnknown:
    def test_is_retried_once_sealed_to_the_keys_its_documents_list_once_they_pass_which_are_kept(
        self, setup, clock
    ):
        gone, fresh = Enclave(clock), Enclave(clock)
        s = setup(live=[fresh], listed=lambda: [gone.document()], listed_on_421=lambda: [fresh.document()])
        assert s.chat().status_code == 200
        s.chat()
        assert [(c.key_ids, bool(c.opened)) for c in s.relay.sealed()] == [
            ([gone.key_id], False),
            ([fresh.key_id], True),
            ([fresh.key_id], True),
        ]
        assert s.relay.listings() == 1

    # A deploy: the relay's listing still names the enclave that stopped, which another call's
    # fetch, under way when the 421 came, verified. Its keys must not replace the 421's, and that
    # call seals to the 421's.
    def test_replaces_the_keys_for_good_though_a_fetch_under_way_meanwhile_lists_the_old_ones(
        self, setup, clock
    ):
        gone, fresh = Enclave(clock), Enclave(clock)
        at_421, answer_421, at_get, answer_get = (threading.Event() for _ in range(4))
        gets = [0]

        def listed() -> list[str]:
            gets[0] += 1
            if gets[0] == 2:
                at_get.set()
                answer_get.wait(5)
            return [gone.document()]

        def listed_on_421() -> list[str]:
            at_421.set()
            answer_421.wait(5)
            return [fresh.document()]

        s = setup(live=[fresh], listed=listed, listed_on_421=listed_on_421)
        refused: list[int] = []
        fetching: list[int] = []
        first = threading.Thread(target=lambda: refused.append(s.chat().status_code))
        first.start()
        assert at_421.wait(5)
        clock.ms += 30 * MINUTE
        second = threading.Thread(target=lambda: fetching.append(s.chat().status_code))
        second.start()
        assert at_get.wait(5)
        answer_421.set()
        first.join(5)
        assert refused == [200]
        before = len(s.relay.sealed())
        answer_get.set()
        second.join(5)
        assert fetching == [200]
        s.chat()
        assert [c.key_ids for c in s.relay.sealed()[before:]] == [[fresh.key_id], [fresh.key_id]]

    # Two calls get a 421 each, and the first's replacement finishes last. The second's keys, the
    # newer, are kept.
    def test_keeps_the_newer_of_two_replacements_though_the_older_finishes_last(self, setup, clock):
        gone, older, newer = Enclave(clock), Enclave(clock), Enclave(clock)
        replacements = iter([older, newer])
        statements, held, release = [0], threading.Event(), threading.Event()

        def github(url: str) -> None:
            if url.endswith("prod.statement.json"):
                statements[0] += 1
                if statements[0] == 2:
                    held.set()
                    release.wait(5)

        s = setup(
            live=[older, newer],
            listed=lambda: [gone.document()],
            listed_on_421=lambda: [next(replacements).document()],
            github=github,
        )
        first: list[int] = []
        a = threading.Thread(target=lambda: first.append(s.chat().status_code))
        a.start()
        assert held.wait(5)
        assert s.chat().status_code == 200
        release.set()
        a.join(5)
        assert first == [200]
        s.chat()
        assert s.relay.sealed()[-1].key_ids == [newer.key_id]

    def test_is_passed_on_when_the_retry_gets_one_too_and_raises_when_its_documents_fail(self, setup, clock):
        gone, also_gone = Enclave(clock), Enclave(clock)
        s = setup(live=[], listed=lambda: [gone.document()], listed_on_421=lambda: [also_gone.document()])
        res = s.chat()
        assert res.status_code == 421
        assert res.json()["error"]["code"] == "sealed_key_unknown"
        assert [c.key_ids for c in s.relay.sealed()] == [[gone.key_id], [also_gone.key_id]]

        t = setup(
            live=[],
            listed=lambda: [gone.document()],
            listed_on_421=lambda: [also_gone.document(pcrs=UNLISTED)],
        )
        with pytest.raises(VerifyError) as e:
            t.chat()
        assert e.value.step == "Allowed"
        assert str(e.value) == (
            "Allowed failed: enclave i-0123-enc0123 runs PCR0 abababababab…abababab, which is not on Morse's signed list. "
            + FIRST_TRY_SENT
        )
        assert len(t.relay.sealed()) == 1


def stale_unless_near(
    seconds: Callable[[], float], proxy_time: Callable[[], float] | None = None
) -> Callable:
    """An enclave that answers sealed_stale, naming its clock as `proxy_time`, unless the seal's ts
    is within 2 minutes of `seconds`."""

    def answer(opened) -> Answer:
        if abs(opened.head["ts"] - seconds()) <= 120:
            return Answer(200, {"Content-Type": ["application/json"]}, ["{}"])
        body = {
            "error": {"code": "sealed_stale", "message": "stale"},
            "proxy_time": (proxy_time or seconds)(),
        }
        return Answer(400, {"Content-Type": ["application/json"]}, [json.dumps(body)])

    return answer


class TestASealedSealedStale:
    def test_sets_the_clock_ts_is_sealed_with_to_the_enclaves_and_seals_once_more(self, setup):
        enclave_seconds = NOW // 1000 + 600
        s = setup(answer=stale_unless_near(lambda: enclave_seconds))
        assert s.chat().status_code == 200
        s.chat()
        assert [opened_head(c)["ts"] for c in s.relay.sealed()] == [
            NOW // 1000,
            enclave_seconds,
            enclave_seconds,
        ]

    def test_never_moves_the_clock_documents_are_judged_by(self, setup, clock):
        s = setup(answer=stale_unless_near(lambda: (clock() + 40 * MINUTE) / 1000))
        assert s.chat().status_code == 200
        clock.ms += 30 * MINUTE
        assert s.chat().status_code == 200
        assert s.relay.listings() == 2
        assert len(s.relay.sealed()) == 3

    def test_is_retried_only_once(self, setup):
        s = setup(answer=stale_unless_near(lambda: 0, lambda: NOW // 1000 + 600))
        res = s.chat()
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "sealed_stale"
        assert len(s.relay.sealed()) == 2


class TestTheAsyncClient:
    def test_seals_as_the_sync_one_does_and_fetches_the_keys_once_for_concurrent_calls(self, setup):
        s = setup()

        async def main() -> list[int]:
            async with s.async_client() as c:

                async def one() -> int:
                    res = await c.post(f"{s.at}/v1/chat/completions", headers=CHAT_HEADERS, content=CHAT)
                    return res.status_code

                return list(await asyncio.gather(one(), one()))

        assert asyncio.run(main()) == [200, 200]
        assert s.relay.listings() == 1
        assert sum(c[1] == "clone" for c in s.world.ran) == 1
        assert [opened_head(c)["headers"] for c in s.relay.sealed()] == [
            {"Content-Type": "application/json"}
        ] * 2

    # A thread of the event loop's executor blocked on a fetch is one the app's own to_thread work
    # waits for, so only the fetch takes one: held keys and the wait for a fetch need none.
    def test_takes_a_thread_only_to_fetch_the_keys(self, setup):
        s = setup()
        submitted: list[str] = []

        class Executor(concurrent.futures.ThreadPoolExecutor):
            def submit(self, fn, /, *args, **kwargs):
                submitted.extend(re.findall(r"Keyring\.(\w+)", repr(fn)))
                return super().submit(fn, *args, **kwargs)

        async def main() -> list[int]:
            asyncio.get_running_loop().set_default_executor(Executor())
            async with s.async_client() as c:

                async def one() -> int:
                    res = await c.post(f"{s.at}/v1/chat/completions", headers=CHAT_HEADERS, content=CHAT)
                    return res.status_code

                return [*await asyncio.gather(one(), one(), one()), await one()]

        assert asyncio.run(main()) == [200] * 4
        assert submitted == ["_run"]

    def test_stops_waiting_for_a_caller_cancelled_while_its_check_runs_on_for_the_next_call(self, setup):
        cloning, cloned = threading.Event(), threading.Event()

        def held(faked):
            def run(command, args, **o):
                if args[0] == "clone":
                    cloning.set()
                    cloned.wait(5)
                return faked(command, args, **o)

            return run

        s = setup(exec=held)

        async def main() -> int:
            async with s.async_client() as c:
                call = asyncio.ensure_future(
                    c.post(f"{s.at}/v1/chat/completions", headers=CHAT_HEADERS, content=CHAT)
                )
                await asyncio.to_thread(cloning.wait, 5)
                call.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await call
                assert s.relay.sealed() == []
                cloned.set()
                res = await c.post(f"{s.at}/v1/chat/completions", headers=CHAT_HEADERS, content=CHAT)
                return res.status_code

        assert asyncio.run(main()) == 200
        assert sum(c[1] == "clone" for c in s.world.ran) == 1
        assert len(s.relay.sealed()) == 1

    def test_retries_a_421_and_a_sealed_stale_once_as_the_sync_one_does(self, setup, clock):
        gone, also_gone = Enclave(clock), Enclave(clock)
        unknown = setup(
            live=[], listed=lambda: [gone.document()], listed_on_421=lambda: [also_gone.document()]
        )
        stale = setup(answer=stale_unless_near(lambda: 0, lambda: NOW // 1000 + 600))

        async def main() -> list[int]:
            statuses = []
            for s in (unknown, stale):
                async with s.async_client() as c:
                    res = await c.post(f"{s.at}/v1/chat/completions", headers=CHAT_HEADERS, content=CHAT)
                    statuses.append(res.status_code)
            return statuses

        assert asyncio.run(main()) == [421, 400]
        assert [len(unknown.relay.sealed()), len(stale.relay.sealed())] == [2, 2]

    def test_raises_what_the_sync_one_does(self, setup, clock):
        unlisted = Enclave(clock)
        s = setup(live=[unlisted], listed=lambda: [unlisted.document(pcrs=UNLISTED)])

        async def main() -> None:
            async with s.async_client() as c:
                with pytest.raises(
                    NotSent, match=r"^attested_async_client\(\) won't send POST /v1/embeddings"
                ):
                    await c.post(f"{s.at}/v1/embeddings", headers=CHAT_HEADERS, content="{}")
                with pytest.raises(VerifyError, match="^Allowed failed: "):
                    await c.post(f"{s.at}/v1/chat/completions", headers=CHAT_HEADERS, content=CHAT)

        asyncio.run(main())


def test_the_module_exports_the_clients():
    import trymorse_verify

    assert trymorse_verify.attested_client is attested.attested_client
    assert trymorse_verify.attested_async_client is attested.attested_async_client
    assert trymorse_verify.VerifyError is VerifyError
