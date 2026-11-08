# seal.py against the backend's vectors (seal_vectors.json) and RFC 9180's (hpke_vector.json), as
# src/seal.test.ts and src/testing/opener.test.ts hold seal.ts to them.
from __future__ import annotations

import json
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from opener import EnclaveKey, ReplySealer, key_ids_of
from world import read

from trymorse_verify.seal import (
    Draws,
    HeadTooLarge,
    InnerHead,
    ReplyOpener,
    SealedReplyError,
    SealKey,
    frame_keys,
    frame_nonce,
    head_json,
    hpke_export,
    hpke_keys,
    hpke_nonce,
    inner_plaintext,
    key_id_of,
    seal_request,
    x25519_public,
    x25519_shared,
)

VECTORS = json.loads(read("seal_vectors.json"))
HPKE = json.loads(read("hpke_vector.json"))
h = bytes.fromhex


def test_fixes_the_suite_the_backend_seals_with():
    assert VECTORS["suite"] == {
        "kem": "DHKEM(X25519, HKDF-SHA256)",
        "kdf": "HKDF-SHA256",
        "aead": "AES-256-GCM",
        "cek_info": "morse-seal-v1 cek",
        "reply_key_info": "morse-seal-v1 reply key",
        "reply_nonce_info": "morse-seal-v1 reply nonce",
    }


def test_names_each_key_by_the_first_8_bytes_of_its_sha256():
    for r in VECTORS["recipients"]:
        assert key_id_of(h(r["public_key"])).hex() == r["key_id"]
        assert x25519_public(h(r["private_key"])).hex() == r["public_key"]


def _keys(v: dict) -> list[SealKey]:
    recipients = VECTORS["recipients"]
    return [SealKey(h(recipients[i]["public_key"]), h(recipients[i]["key_id"])) for i in v["recipients"]]


def _head(v: dict) -> InnerHead:
    head = v["head"]
    return InnerHead(head["method"], head["path"], head["headers"], head["ts"])


@pytest.mark.parametrize("v", VECTORS["requests"], ids=lambda v: v["name"])
class TestTheRequestVector:
    def test_writes_the_head_and_the_padded_inner_plaintext_byte_for_byte(self, v):
        body = h(v["body"])
        assert v["head"]["body_len"] == len(body)
        assert head_json(_head(v), len(body)).hex() == v["head_json"]
        assert inner_plaintext(h(v["head_json"]), body).hex() == v["inner"]

    def test_seals_byte_for_byte_as_the_backend_does(self, v):
        keys = _keys(v)
        draws = Draws(h(v["cek"]), [h(e) for e in v["ephemeral_private_keys"]])
        sealed, cek = seal_request(keys, _head(v), h(v["body"]), draws)
        assert sealed.hex() == v["sealed"]
        assert cek.hex() == v["cek"]
        assert len(sealed) % 1024 == (2 + 88 * len(keys)) % 1024

    def test_seals_with_fresh_draws_to_what_each_recipients_private_key_opens(self, v):
        sealed, cek = seal_request(_keys(v), _head(v), h(v["body"]))
        assert key_ids_of(sealed) == [VECTORS["recipients"][i]["key_id"] for i in v["recipients"]]
        for i in v["recipients"]:
            opened = EnclaveKey(h(VECTORS["recipients"][i]["private_key"])).open(sealed)
            assert opened is not None
            assert opened.head == v["head"]
            assert opened.body.hex() == v["body"]
            assert opened.cek == cek
        assert EnclaveKey().open(sealed) is None


def test_refuses_to_seal_to_no_key_or_more_than_four():
    head = InnerHead("POST", "/v1/chat/completions", {}, 0)
    key = SealKey(x25519_public(os.urandom(32)), b"12345678")
    with pytest.raises(ValueError, match="sealing to 0 keys, not 1 to 4"):
        seal_request([], head, b"")
    with pytest.raises(ValueError, match="sealing to 5 keys, not 1 to 4"):
        seal_request([key] * 5, head, b"")


def test_refuses_a_head_over_8_kib():
    key = SealKey(x25519_public(os.urandom(32)), b"12345678")
    with pytest.raises(HeadTooLarge, match=r"^the sealed head is 9087 bytes, over the proxy's 8192$"):
        seal_request([key], InnerHead("GET", f"/v1/lookup/svc/x?q={'a' * 9000}", {}, 1792216730), b"")


def test_escapes_the_head_as_go_does():
    head = InnerHead("GET", '/v1/lookup/a?q=<&>\u2028\u2029"\\\n\x01é', {"X-B": "1", "X-A": "2"}, 1)
    assert head_json(head, 0) == (
        b'{"method":"GET","path":"/v1/lookup/a?q=\\u003c\\u0026\\u003e\\u2028\\u2029\\"\\\\\\n\\u0001'
        + "é".encode()
        + b'","headers":{"X-A":"2","X-B":"1"},"ts":1,"body_len":0}'
    )


def test_escapes_a_lone_surrogate_as_json_stringify_does_so_the_head_is_utf_8():
    head = InnerHead("GET", "/v1/x", {"X-A": "a\ud800b\udfff"}, 1)
    assert head_json(head, 0) == (
        b'{"method":"GET","path":"/v1/x","headers":{"X-A":"a\\ud800b\\udfff"},"ts":1,"body_len":0}'
    )


def _opened(reply: bytes, cek: bytes, chunk: int) -> tuple[ReplyOpener, bytes]:
    opener = ReplyOpener(cek)
    body = b""
    for i in range(0, len(reply), chunk):
        body += b"".join(opener.feed(reply[i : i + chunk]))
    opener.finish()
    return opener, body


@pytest.mark.parametrize("v", VECTORS["replies"], ids=lambda v: v["name"])
class TestTheReplyVector:
    def test_derives_each_frames_nonce(self, v):
        keys = frame_keys(h(v["cek"]), h(v["salt"]))
        assert keys.base.hex() == v["base_nonce"]
        for i, f in enumerate(v["frames"]):
            assert frame_nonce(keys.base, i).hex() == f["nonce"]

    @pytest.mark.parametrize("chunk", [1, 7, 1 << 20])
    def test_opens_to_its_head_and_body_read_in_chunks(self, v, chunk):
        opener, body = _opened(h(v["reply"]), h(v["cek"]), chunk)
        assert opener.head is not None
        assert opener.head.status == v["head"]["status"]
        assert opener.head.headers == [(n, x) for n, values in v["head"]["headers"].items() for x in values]
        assert body.hex() == "".join(f["data"] for f in v["frames"][1:])

    @pytest.mark.parametrize("lost", ["the whole final frame", "the final frame's last byte"])
    def test_fails_without(self, v, lost):
        reply = h(v["reply"])
        final = len(h(v["frames"][-1]["frame"]))
        cut = reply[: len(reply) - (final if lost == "the whole final frame" else 1)]
        with pytest.raises(SealedReplyError, match="the reply ends before its final frame"):
            _opened(cut, h(v["cek"]), 1 << 20)

    def test_refuses_a_reply_opened_under_another_cek(self, v):
        other = bytes(b ^ 1 for b in h(v["cek"]))
        with pytest.raises(SealedReplyError, match="frame 0 does not open"):
            _opened(h(v["reply"]), other, 1 << 20)

    def test_is_what_the_test_enclave_seals_from_the_same_salt(self, v):
        sealer = ReplySealer(h(v["cek"]), h(v["salt"]))
        frames = [sealer.frame(h(f["data"]), i == len(v["frames"]) - 1) for i, f in enumerate(v["frames"])]
        assert [f.hex() for f in frames] == [f["frame"] for f in v["frames"]]
        assert (h(v["salt"]) + b"".join(frames)).hex() == v["reply"]


def test_a_reply_that_ends_before_its_salt_or_whose_frames_are_malformed():
    cek = os.urandom(32)
    with pytest.raises(SealedReplyError, match="the reply ends before its salt"):
        _opened(b"\0" * 31, cek, 64)
    salt = os.urandom(32)
    keys = frame_keys(cek, salt)

    def frame(pt: bytes, index: int = 0) -> bytes:
        ct = AESGCM(keys.key).encrypt(frame_nonce(keys.base, index), pt, None)
        return len(ct).to_bytes(4, "big") + ct

    for pt, reason in [
        (b"\0" * 1000, "frame 0 is malformed"),
        (b"\2" + bytes(1023), "frame 0 is malformed"),
        (b"\1" + (1020).to_bytes(4, "big") + bytes(1019), "frame 0 overstates its length"),
        (b"\1" + (2).to_bytes(4, "big") + b"{}" + bytes(1017), "the reply's head is not JSON"),
    ]:
        with pytest.raises(SealedReplyError, match=reason):
            _opened(salt + frame(pt), cek, 4096)
    for head in [b'{"status":99,"headers":null}', b'{"status":true,"headers":null}', b'{"status":200}']:
        pt = b"\1" + len(head).to_bytes(4, "big") + head
        with pytest.raises(SealedReplyError, match="the reply's head is not JSON"):
            _opened(salt + frame(pt + bytes(1024 - len(pt))), cek, 4096)
    head = b'{"status":204.0,"headers":null}'
    pt = b"\1" + len(head).to_bytes(4, "big") + head
    opener, body = _opened(salt + frame(pt + bytes(1024 - len(pt))), cek, 4096)
    assert (opener.head.status, opener.head.headers, body) == (204, [], b"")


def _head_frame(head: bytes) -> tuple[bytes, bytes]:
    """A reply of one final frame holding `head`, and its CEK."""
    cek, salt = os.urandom(32), os.urandom(32)
    keys = frame_keys(cek, salt)
    pt = b"\1" + len(head).to_bytes(4, "big") + head
    ct = AESGCM(keys.key).encrypt(frame_nonce(keys.base, 0), pt + bytes(1024 - len(pt)), None)
    return salt + len(ct).to_bytes(4, "big") + ct, cek


# fetch's Headers, which src/seal.ts builds the head's headers into, takes a value of bytes, so
# Latin-1, and trims it; it refuses a name that is not a token and a value with NUL, CR, or LF.
@pytest.mark.parametrize(
    "headers,taken",
    [
        (
            {"Content-Disposition": ["attachment; filename=café.mp4"]},
            [("Content-Disposition", "attachment; filename=café.mp4")],
        ),
        (
            {"X-A": [" v ", "\t w\r\n", "a\tb", ""]},
            [("X-A", "v"), ("X-A", "w"), ("X-A", "a\tb"), ("X-A", "")],
        ),
        ({"X-A": ["Ā"]}, None),
        ({"X-A": ["\ud800"]}, None),
        ({"bad name": ["v"]}, None),
        ({"": ["v"]}, None),
        ({"X-A": ["a\r\nb"]}, None),
        ({"X-A": ["a\u0000b"]}, None),
    ],
)
def test_takes_the_heads_headers_as_fetch_does(headers, taken):
    reply, cek = _head_frame(json.dumps({"status": 200, "headers": headers}).encode())
    if taken is None:
        with pytest.raises(SealedReplyError, match=r"^the reply's header .* is not one fetch takes$"):
            _opened(reply, cek, 4096)
    else:
        assert _opened(reply, cek, 4096)[0].head.headers == taken


def test_drops_a_bom_before_the_heads_json_as_text_decoder_does():
    reply, cek = _head_frame(b'\xef\xbb\xbf{"status":200,"headers":null}')
    assert _opened(reply, cek, 4096)[0].head.status == 200


# RFC 9180's test vector for base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and
# AES-256-GCM, as src/seal.test.ts reads it.
class TestRfc9180BaseModeVector:
    sender = x25519_shared(h(HPKE["skEm"]), h(HPKE["pkRm"]))
    keys = hpke_keys(sender, h(HPKE["enc"]), h(HPKE["pkRm"]), h(HPKE["info"]))

    def test_encapsulates_to_the_ephemeral_key_which_decapsulates_to_the_same_dh(self):
        assert x25519_public(h(HPKE["skEm"])).hex() == HPKE["enc"]
        assert x25519_shared(h(HPKE["skRm"]), h(HPKE["enc"])) == self.sender

    def test_derives_the_key_the_base_nonce_and_the_exporter_secret(self):
        assert self.keys.key.hex() == HPKE["key"]
        assert self.keys.nonce.hex() == HPKE["base_nonce"]
        assert self.keys.exporter_secret.hex() == HPKE["exporter_secret"]

    @pytest.mark.parametrize("e", HPKE["encryptions"], ids=lambda e: str(e["seq"]))
    def test_seals_each_message_under_its_sequence_numbers_nonce(self, e):
        nonce = hpke_nonce(self.keys.nonce, e["seq"])
        assert nonce.hex() == e["nonce"]
        assert AESGCM(self.keys.key).encrypt(nonce, h(e["pt"]), h(e["aad"])).hex() == e["ct"]

    @pytest.mark.parametrize("x", HPKE["exports"], ids=lambda x: x["exporter_context"] or "empty")
    def test_exports(self, x):
        got = hpke_export(self.keys.exporter_secret, h(x["exporter_context"]), x["L"])
        assert got.hex() == x["exported_value"]
