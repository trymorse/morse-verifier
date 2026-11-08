# DER by hand, to write the certificates no library would: a repeated extension, two signature
# algorithms that differ, and signatures in every encoding but DER.
from __future__ import annotations


def length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, *parts: bytes) -> bytes:
    body = b"".join(parts)
    return bytes([tag]) + length(len(body)) + body


def integer(n: int) -> bytes:
    """A non-negative INTEGER in minimal two's complement."""
    return tlv(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def read(der: bytes, at: int = 0) -> tuple[int, bytes, int]:
    """The tag, body, and end of the TLV at `at`."""
    tag, n, start = der[at], der[at + 1], at + 2
    if n & 0x80:
        size = n & 0x7F
        n, start = int.from_bytes(der[start : start + size], "big"), start + size
    return tag, der[start : start + n], start + n


def children(der: bytes) -> list[bytes]:
    """The raw TLVs inside the one constructed TLV `der`."""
    _, body, _ = read(der)
    out, at = [], 0
    while at < len(body):
        out.append(body[at : read(body, at)[2]])
        at = read(body, at)[2]
    return out


def with_extensions(cert: bytes, edit) -> bytes:
    """`cert` with its TBS's extensions replaced by `edit(extensions)`, and its signature kept: a
    parser must refuse it before it checks the signature."""
    tbs, alg, signature = children(cert)
    fields = children(tbs)
    extensions = children(children(fields[-1])[0])
    fields[-1] = tlv(0xA3, tlv(0x30, *edit(extensions)))
    return tlv(0x30, tlv(0x30, *fields), alg, signature)


def with_outer_algorithm(cert: bytes, algorithm: bytes) -> bytes:
    """`cert` with the algorithm outside its TBS, which no signature covers, replaced."""
    tbs, _, signature = children(cert)
    return tlv(0x30, tbs, algorithm, signature)


ECDSA_SHA256 = tlv(0x30, bytes.fromhex("06082a8648ce3d040302"))
