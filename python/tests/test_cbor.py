# The CBOR decoder's strictness (src/cbor.test.ts), with the TS decoder's words but for UTF-8's.
from __future__ import annotations

import pytest

from trymorse_verify.cbor import Tag, decode


def d(hex_text: str):
    return decode(bytes.fromhex(hex_text))


@pytest.mark.parametrize(
    "hex_text, value",
    [
        ("bf6161016162820203ff", {"a": 1, "b": [2, 3]}),
        ("bfff", {}),
        ("9f018202039f04ffff", [1, [2, 3], [4]]),
        ("9fff", []),
        ("5f420102410340ff", b"\x01\x02\x03"),
        ("5fff", b""),
        ("7f626869612160ff", "hi!"),
        ("bf62c2a1a10102ff", {"¡": {1: 2}}),
    ],
    ids=[
        "a map",
        "an empty map",
        "an array",
        "an empty array",
        "a byte string in chunks",
        "a byte string of no chunks",
        "a text string in chunks",
        "a definite map inside an indefinite one",
    ],
)
def test_decodes_an_indefinite_length_item(hex_text, value):
    assert d(hex_text) == value


@pytest.mark.parametrize(
    "hex_text, reason",
    [
        ("ff", "break outside an indefinite-length item"),
        ("8201ff", "break outside an indefinite-length item"),
        ("bf01ff", "break outside an indefinite-length item"),
        ("9f0102", "ends early"),
        ("bf0102", "ends early"),
        ("5f6161ff", "chunk of another type"),
        ("7f4161ff", "chunk of another type"),
        ("5f5fffff", "chunk of another type"),
        ("7f61c261a1ff", "not UTF-8"),
        ("1f", "additional information 31 on major type 0"),
        ("3f", "additional information 31 on major type 1"),
        ("df01", "additional information 31 on major type 6"),
        ("bf01020103ff", "repeats key 1"),
        ("bf410101ff", "neither integer nor text"),
        ("9fff00", "bytes follow"),
    ],
    ids=[
        "a break on its own",
        "a break inside a definite array",
        "a break where a map's value belongs",
        "an array with no break",
        "a map with no break",
        "a byte string with a text chunk",
        "a text string with a byte chunk",
        "a byte string with an indefinite chunk",
        "a text chunk that splits a character",
        "an indefinite unsigned integer",
        "an indefinite negative integer",
        "an indefinite tag",
        "a repeated key",
        "a byte string as a key",
        "bytes after the break",
    ],
)
def test_refuses_an_indefinite_length_item(hex_text, reason):
    with pytest.raises(ValueError, match=reason):
        d(hex_text)


def test_an_indefinite_item_counts_toward_the_nesting_limit():
    assert d("9f" * 16 + "01" + "ff" * 16) is not None
    with pytest.raises(ValueError, match="nests too deep"):
        d("9f" * 17 + "01" + "ff" * 17)


# What a document's CBOR may not hold, though cbor2 would read each: the rules a forged document
# would lean on to say one thing to this verifier and another to a reader that keeps the last key.
@pytest.mark.parametrize(
    "hex_text, reason",
    [
        ("a2616101616102", "repeats key a"),
        ("a201010102", "repeats key 1"),
        ("a2200120 02", "repeats key -1"),
        ("0100", "bytes follow the CBOR item"),
        ("a1616101f6", "bytes follow the CBOR item"),
        ("1b0020000000000000", "integer past 2\\^53"),
        ("3b0020000000000000", "integer past 2\\^53"),
        ("5b0020000000000000", "integer past 2\\^53"),
        ("1c", "additional information 28"),
        ("f97e00", "simple value 25"),
        ("fb3ff0000000000000", "simple value 27"),
        ("f7", "simple value 23"),
        ("a1f401", "neither integer nor text"),
        ("a1f601", "neither integer nor text"),
        ("6261", "ends early"),
        ("62c3", "ends early"),
        ("62c328", "not UTF-8"),
    ],
    ids=[
        "a repeated text key",
        "a repeated integer key",
        "a repeated negative key",
        "a byte after an integer",
        "a byte after a map",
        "an integer of 2^53",
        "a negative integer past -2^53",
        "a byte string 2^53 long",
        "a reserved additional information",
        "a half-precision float",
        "a double",
        "undefined",
        "false as a key",
        "null as a key",
        "a text string cut short",
        "a two-byte text string of one byte",
        "a text string that is not UTF-8",
    ],
)
def test_refuses(hex_text, reason):
    with pytest.raises(ValueError, match=reason):
        d(hex_text.replace(" ", ""))


def test_reads_the_largest_safe_integer_and_its_negative():
    assert d("1b001fffffffffffff") == 2**53 - 1
    assert d("3b001ffffffffffffe") == -(2**53 - 1)


def test_keeps_a_tag_and_reads_true_false_and_null():
    assert d("d84083f5f4f6") == Tag(64, [True, False, None])
