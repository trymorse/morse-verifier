# A request sealed to enclave keys, and the reply it gets, opened, as src/seal.ts does both and the
# backend's internal/seal reads and writes them. Nothing here does I/O: attested.py feeds it bytes.
#
# A sealed request is: version 1, the number of keys n, then n entries of
#   key id (first 8 bytes of SHA-256 of the key) | HPKE enc (32) | HPKE seal of the CEK (48)
# which together are the AAD of one AES-256-GCM seal, under the CEK and a zero nonce, of
#   head length (4, big-endian) | head JSON | body | zeros, so the seal fills whole KiB.
# HPKE is RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, with info
# "morse-seal-v1 cek" and the key id as AAD. The reply is a 32-byte salt, then frames of
#   length (4) | AES-256-GCM seal of: final flag (1) | data length (4) | data | zeros, to whole KiB
# under keys HKDF-SHA256(CEK, salt) derives, frame i's nonce the base nonce XOR i. The first frame
# holds the head, {"status": ..., "headers": {...}}, and the last has the final flag.
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .io import parse_json
from .routes import MAX_KEYS

MAX_HEAD = 8 << 10
VERSION = 1
PAD = 1024
TAG = 16
CEK_INFO = b"morse-seal-v1 cek"
REPLY_KEY_INFO = b"morse-seal-v1 reply key"
REPLY_NONCE_INFO = b"morse-seal-v1 reply nonce"
SALT = 32
FRAME_HEAD = 5
ENTRY = 8 + 32 + 48


def key_id_of(public_key: bytes) -> bytes:
    return hashlib.sha256(public_key).digest()[:8]


@dataclass(frozen=True, eq=False)
class SealKey:
    """An enclave's X25519 key, and its id. Compared by identity, so a key is the one verified,
    not one equal to it."""

    public_key: bytes
    key_id: bytes


@dataclass(frozen=True)
class InnerHead:
    method: str
    path: str
    headers: dict[str, str]
    ts: int


@dataclass(frozen=True)
class Draws:
    """The random values a seal takes, which tests fix."""

    cek: bytes
    ephemeral: list[bytes] = field(default_factory=list)


# --- RFC 9180 -------------------------------------------------------------------------------------

_HPKE_V1 = b"HPKE-v1"
_KEM_SUITE = b"KEM" + struct.pack(">H", 0x0020)
_HPKE_SUITE = b"HPKE" + struct.pack(">HHH", 0x0020, 0x0001, 0x0002)


def _labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, _HPKE_V1 + suite + label + ikm, hashlib.sha256).digest()


def _labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled = struct.pack(">H", length) + _HPKE_V1 + suite + label + info
    return HKDFExpand(hashes.SHA256(), length, labeled).derive(prk)


@dataclass(frozen=True)
class HpkeKeys:
    key: bytes
    nonce: bytes
    exporter_secret: bytes


def hpke_keys(dh: bytes, encapsulated: bytes, recipient: bytes, info: bytes) -> HpkeKeys:
    """RFC 9180's base-mode key schedule for DHKEM(X25519): the AEAD key, its base nonce, and the
    secret the context exports from."""
    eae_prk = _labeled_extract(_KEM_SUITE, b"", b"eae_prk", dh)
    shared = _labeled_expand(_KEM_SUITE, eae_prk, b"shared_secret", encapsulated + recipient, 32)
    context = (
        b"\x00"
        + _labeled_extract(_HPKE_SUITE, b"", b"psk_id_hash", b"")
        + _labeled_extract(_HPKE_SUITE, b"", b"info_hash", info)
    )
    secret = _labeled_extract(_HPKE_SUITE, shared, b"secret", b"")
    return HpkeKeys(
        key=_labeled_expand(_HPKE_SUITE, secret, b"key", context, 32),
        nonce=_labeled_expand(_HPKE_SUITE, secret, b"base_nonce", context, 12),
        exporter_secret=_labeled_expand(_HPKE_SUITE, secret, b"exp", context, 32),
    )


def hpke_export(exporter_secret: bytes, exporter_context: bytes, length: int) -> bytes:
    """RFC 9180's Export (5.3): `length` bytes for `exporter_context` from a context's secret."""
    return _labeled_expand(_HPKE_SUITE, exporter_secret, b"sec", exporter_context, length)


def hpke_nonce(base: bytes, seq: int) -> bytes:
    """The nonce of a context's `seq`th message (RFC 9180 5.2): the base nonce XOR `seq`."""
    return (int.from_bytes(base, "big") ^ seq).to_bytes(len(base), "big")


def x25519_public(secret: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def x25519_shared(secret: bytes, public: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(public))


def _hpke_seal(recipient: bytes, ephemeral: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 base-mode single-shot seal, as Go's crypto/hpke Sender.Seal makes it."""
    encapsulated = x25519_public(ephemeral)
    keys = hpke_keys(x25519_shared(ephemeral, recipient), encapsulated, recipient, CEK_INFO)
    return encapsulated, AESGCM(keys.key).encrypt(keys.nonce, plaintext, aad)


# --- The request ----------------------------------------------------------------------------------

# Go's encoding/json escapes these in a string, and the JSON the enclave reads is Go's.
_GO_ESCAPES = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "\u2028": "\\u2028", "\u2029": "\\u2029"}
_SURROGATE = re.compile("[\ud800-\udfff]")


def head_json(head: InnerHead, body_length: int) -> bytes:
    """The head, as JSON.stringify writes it in src/seal.ts, with Go's escapes."""
    text = json.dumps(
        {
            "method": head.method,
            "path": head.path,
            "headers": {name: head.headers[name] for name in sorted(head.headers)},
            "ts": head.ts,
            "body_len": body_length,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    for c, escaped in _GO_ESCAPES.items():
        text = text.replace(c, escaped)
    # A lone surrogate, which no header or path httpx sends holds, is escaped, as JSON.stringify
    # escapes one, so the head is UTF-8.
    return _SURROGATE.sub(lambda m: f"\\u{ord(m[0]):04x}", text).encode("utf-8")


def inner_plaintext(head_bytes: bytes, body: bytes) -> bytes:
    unpadded = 4 + len(head_bytes) + len(body)
    padding = (PAD - (unpadded + TAG) % PAD) % PAD
    return struct.pack(">I", len(head_bytes)) + head_bytes + body + bytes(padding)


class HeadTooLarge(ValueError):
    def __init__(self, length: int):
        super().__init__(f"the sealed head is {length} bytes, over the proxy's {MAX_HEAD}")


def seal_request(
    keys: list[SealKey], head: InnerHead, body: bytes, draws: Draws | None = None
) -> tuple[bytes, bytes]:
    """The request sealed to `keys`, and the CEK its reply opens under."""
    if not 1 <= len(keys) <= MAX_KEYS:
        raise ValueError(f"sealing to {len(keys)} keys, not 1 to {MAX_KEYS}")
    head_bytes = head_json(head, len(body))
    if len(head_bytes) > MAX_HEAD:
        raise HeadTooLarge(len(head_bytes))
    if draws is None:
        draws = Draws(os.urandom(32), [os.urandom(32) for _ in keys])
    entries = []
    for k, ephemeral in zip(keys, draws.ephemeral, strict=True):
        encapsulated, ct = _hpke_seal(k.public_key, ephemeral, k.key_id, draws.cek)
        entries.append(k.key_id + encapsulated + ct)
    aad = bytes([VERSION, len(keys)]) + b"".join(entries)
    ct = AESGCM(draws.cek).encrypt(bytes(12), inner_plaintext(head_bytes, body), aad)
    return aad + ct, draws.cek


# --- The reply ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class FrameKeys:
    key: bytes
    base: bytes


def frame_keys(cek: bytes, salt: bytes) -> FrameKeys:
    def derive(info: bytes, length: int) -> bytes:
        return HKDF(hashes.SHA256(), length, salt, info).derive(cek)

    return FrameKeys(derive(REPLY_KEY_INFO, 32), derive(REPLY_NONCE_INFO, 12))


def frame_nonce(base: bytes, index: int) -> bytes:
    """The base nonce with its last four bytes XOR the frame's index."""
    last = (int.from_bytes(base[8:], "big") ^ index) & 0xFFFFFFFF
    return base[:8] + last.to_bytes(4, "big")


class SealedReplyError(Exception):
    """A sealed reply that does not open, or ends before its final frame."""


@dataclass(frozen=True)
class ReplyHead:
    status: int
    # Each header's values, in order, each a string of code points to U+00FF, as fetch's are.
    headers: list[tuple[str, str]]


# What fetch's Headers takes as a name: an RFC 9110 token.
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def _header(name: str, value: str) -> tuple[str, str]:
    """A header as fetch's Headers.append takes it, or raises: a token name, and a value of
    code points to U+00FF, trimmed of HTTP whitespace, with no NUL, CR, or LF."""
    value = value.strip("\t\n\r ")
    if not _TOKEN.fullmatch(name) or any(c in value for c in "\0\r\n") or max(value, default="") > "\xff":
        raise SealedReplyError(f"the reply's header {json.dumps(name)} is not one fetch takes")
    return name, value


def _reply_head(data: bytes) -> ReplyHead:
    """The first frame's JSON, as src/seal.ts's zod schema reads it: status an integer 100 to 599,
    headers null or an object of string arrays, each a header fetch's Headers takes. A BOM is
    dropped, as TextDecoder drops it."""
    try:
        head = parse_json(data.decode("utf-8-sig", "replace"))
        status = head["status"]
        if isinstance(status, bool) or not isinstance(status, (int, float)):
            raise ValueError
        if isinstance(status, float):
            if not status.is_integer():
                raise ValueError
            status = int(status)
        if not 100 <= status <= 599:
            raise ValueError
        raw = head["headers"]
        if raw is not None and not isinstance(raw, dict):
            raise ValueError
        headers = []
        for name, values in (raw or {}).items():
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise ValueError
            headers += [(name, v) for v in values]
    except (ValueError, KeyError, TypeError):
        raise SealedReplyError("the reply's head is not JSON") from None
    return ReplyHead(status, [_header(name, v) for name, v in headers])


class ReplyOpener:
    """Opens a sealed reply as its bytes arrive. `feed` returns each frame's data as it opens;
    `head` is set once the first frame has. `finish` raises unless the final frame came."""

    def __init__(self, cek: bytes):
        self._cek = cek
        self._buffer = bytearray()
        self._keys: FrameKeys | None = None
        self._index = 0
        self.head: ReplyHead | None = None
        self.done = False

    def feed(self, data: bytes) -> list[bytes]:
        out: list[bytes] = []
        if self.done:
            return out
        self._buffer += data
        if self._keys is None:
            if len(self._buffer) < SALT:
                return out
            self._keys = frame_keys(self._cek, bytes(self._buffer[:SALT]))
            del self._buffer[:SALT]
        while not self.done and len(self._buffer) >= 4:
            (size,) = struct.unpack(">I", self._buffer[:4])
            if len(self._buffer) < 4 + size:
                break
            ciphertext = bytes(self._buffer[4 : 4 + size])
            del self._buffer[: 4 + size]
            chunk, final = self._open(ciphertext)
            self.done = final
            if self.head is None:
                self.head = _reply_head(chunk)
            elif chunk:
                out.append(chunk)
        return out

    def _open(self, ciphertext: bytes) -> tuple[bytes, bool]:
        assert self._keys is not None
        index = self._index
        self._index += 1
        try:
            pt = AESGCM(self._keys.key).decrypt(frame_nonce(self._keys.base, index), ciphertext, None)
        except (InvalidTag, ValueError):
            raise SealedReplyError(f"frame {index} does not open") from None
        if len(pt) < FRAME_HEAD or len(pt) % PAD != 0 or pt[0] > 1:
            raise SealedReplyError(f"frame {index} is malformed")
        (length,) = struct.unpack(">I", pt[1:5])
        if length > len(pt) - FRAME_HEAD:
            raise SealedReplyError(f"frame {index} overstates its length")
        return pt[FRAME_HEAD : FRAME_HEAD + length], pt[0] == 1

    def finish(self) -> None:
        """The reply's bytes have ended: an error unless its final frame came."""
        if self._keys is None:
            raise SealedReplyError("the reply ends before its salt")
        if not self.done:
            raise SealedReplyError("the reply ends before its final frame")
