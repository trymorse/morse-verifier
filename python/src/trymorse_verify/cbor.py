# The CBOR an AWS Nitro document is written in, read as strictly as the TypeScript decoder
# (src/cbor.ts): a map may not repeat a key, no bytes may follow the item, integers stop at 2^53,
# and floats and simple values other than true, false, and null are refused. By hand:
#   python -c 'import cbor2,sys; print(cbor2.loads(sys.stdin.buffer.read()))' < document.cbor
from __future__ import annotations

from dataclasses import dataclass

MAX_DEPTH = 16
BREAK = 0xFF
MAX_SAFE_INTEGER = 2**53 - 1


@dataclass(frozen=True)
class Tag:
    tag: int
    value: Cbor


Cbor = int | str | bytes | bool | None | list | dict | Tag


def decode(data: bytes) -> Cbor:
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if n > len(data) - at:
            raise ValueError("the CBOR ends early")
        out = data[at : at + n]
        at += n
        return out

    def argument(info: int) -> int:
        if info < 24:
            return info
        size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
        if not size:
            raise ValueError(f"CBOR additional information {info}")
        n = int.from_bytes(take(size), "big")
        if n > MAX_SAFE_INTEGER:
            raise ValueError("a CBOR integer past 2^53")
        return n

    def text(b: bytes) -> str:
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("the CBOR text is not UTF-8") from e

    def at_break() -> bool:
        nonlocal at
        if at < len(data) and data[at] == BREAK:
            at += 1
            return True
        return False

    def map_entries(depth: int, more) -> dict:
        out: dict = {}
        i = 0
        while more(i):
            key = item(depth + 1)
            if type(key) is not int and type(key) is not str:
                raise ValueError("a CBOR map key that is neither integer nor text")
            if key in out:
                raise ValueError(f"a CBOR map repeats key {key}")
            out[key] = item(depth + 1)
            i += 1
        return out

    def chunks(major: int) -> list[bytes]:
        out = []
        while not at_break():
            (initial,) = take(1)
            if initial >> 5 != major or initial & 31 == 31:
                raise ValueError("a CBOR string chunk of another type")
            out.append(take(argument(initial & 31)))
        return out

    def indefinite(major: int, depth: int) -> Cbor:
        if major == 2:
            return b"".join(chunks(2))
        if major == 3:
            return "".join(text(c) for c in chunks(3))
        if major == 4:
            items = []
            while not at_break():
                items.append(item(depth + 1))
            return items
        if major == 5:
            return map_entries(depth, lambda _: not at_break())
        raise ValueError(f"CBOR additional information 31 on major type {major}")

    def item(depth: int) -> Cbor:
        if depth > MAX_DEPTH:
            raise ValueError("the CBOR nests too deep")
        (initial,) = take(1)
        major, info = initial >> 5, initial & 31
        if major == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            if info == 31:
                raise ValueError("a CBOR break outside an indefinite-length item")
            raise ValueError(f"CBOR simple value {info}")
        if info == 31:
            return indefinite(major, depth)
        n = argument(info)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return bytes(take(n))
        if major == 3:
            return text(take(n))
        if major == 4:
            return [item(depth + 1) for _ in range(n)]
        if major == 5:
            return map_entries(depth, lambda i: i < n)
        return Tag(n, item(depth + 1))

    out = item(0)
    if at != len(data):
        raise ValueError("bytes follow the CBOR item")
    return out


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 2**32:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def encode(v: Cbor) -> bytes:
    """Definite-length CBOR of ints, text, bytes, null, lists, and maps in their order, as
    COSE's Sig_structure and the test forge write it."""
    if v is None:
        return b"\xf6"
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, str):
        b = v.encode()
        return _head(3, len(b)) + b
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, dict):
        return _head(5, len(v)) + b"".join(encode(k) + encode(x) for k, x in v.items())
    raise TypeError(f"no CBOR for {type(v).__name__}")
