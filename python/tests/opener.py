# The enclave's side of a seal, for tests, as src/testing/opener.ts has it: it opens a request sealed
# to its X25519 key and seals a reply frame by frame, as the backend's internal/seal does.
# test_seal.py holds both to seal_vectors.json, which the backend wrote.
from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from trymorse_verify.seal import (
    CEK_INFO,
    ENTRY,
    PAD,
    frame_keys,
    frame_nonce,
    hpke_keys,
    key_id_of,
    x25519_public,
    x25519_shared,
)


@dataclass(frozen=True)
class Opened:
    head: dict
    body: bytes
    cek: bytes


def key_ids_of(sealed: bytes) -> list[str]:
    """The key ids, hex, a sealed request names, in order."""
    return [sealed[2 + n * ENTRY : 10 + n * ENTRY].hex() for n in range(sealed[1])]


class EnclaveKey:
    """An enclave's key pair. `open` reads a request sealed to it, or is None when no entry names
    it, as the worker then answers 421."""

    def __init__(self, secret: bytes | None = None):
        self.secret = secret or os.urandom(32)
        self.public_key = x25519_public(self.secret)
        self.key_id = key_id_of(self.public_key).hex()

    def open(self, sealed: bytes) -> Opened | None:
        ids = key_ids_of(sealed)
        if sealed[0] != 1 or self.key_id not in ids:
            return None
        n = ids.index(self.key_id)
        aad = sealed[: 2 + sealed[1] * ENTRY]
        entry = aad[2 + n * ENTRY : 2 + (n + 1) * ENTRY]
        encapsulated = entry[8:40]
        keys = hpke_keys(x25519_shared(self.secret, encapsulated), encapsulated, self.public_key, CEK_INFO)
        cek = AESGCM(keys.key).decrypt(keys.nonce, entry[40:], entry[:8])
        ct = sealed[len(aad) :]
        if len(ct) % PAD != 0:
            raise ValueError("the ciphertext is not padded")
        inner = AESGCM(cek).decrypt(bytes(12), ct, aad)
        (size,) = struct.unpack(">I", inner[:4])
        head = json.loads(inner[4 : 4 + size])
        end = 4 + size + head["body_len"]
        if any(inner[end:]):
            raise ValueError("the padding is not zeros")
        return Opened(head, inner[4 + size : end], cek)


class ReplySealer:
    """A reply sealed under `cek`, written part by part: `salt`, then each frame in turn."""

    def __init__(self, cek: bytes, salt: bytes | None = None):
        self.salt = salt or os.urandom(32)
        self._keys = frame_keys(cek, self.salt)
        self._index = 0

    def frame(self, data: bytes, final: bool) -> bytes:
        size = -(-(5 + len(data)) // PAD) * PAD
        pt = bytes([1 if final else 0]) + struct.pack(">I", len(data)) + data
        pt += bytes(size - len(pt))
        ct = AESGCM(self._keys.key).encrypt(frame_nonce(self._keys.base, self._index), pt, None)
        self._index += 1
        return struct.pack(">I", len(ct)) + ct
