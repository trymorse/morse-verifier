# An AWS Nitro attestation document: a COSE_Sign1 (ES384) whose payload names the enclave's PCRs,
# its key in user_data, and a certificate chain that must end at AWS's pinned root. The rules are
# those of src/nitro.ts, src/x509.ts, and src/pins.ts. By hand, with AWS's guide
# (https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html):
#   curl -s https://api.trymorse.ai/v1/attestation | jq -r '.instances[0]' | base64 -d > doc.cbor
#   python -c 'import cbor2,sys; d=cbor2.loads(open("doc.cbor","rb").read()); print(cbor2.loads(d.value[2]))'
#   then check the cabundle chains to the root whose SHA-256 is 641a0321…8f79bb5b, the timestamp
#   is under 30 minutes old, and the COSE signature verifies with the leaf's key.
from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.x509.oid import ExtensionOID

from . import cbor

USER_DATA_PREFIX = "morse-proxy-hpke-v1|"
MAX_AGE_MS = 30 * 60_000
MAX_AHEAD_MS = 5 * 60_000
ES384 = -35
KEY_BYTES = 32
ZERO_PCR = "0" * 96

AWS_NITRO_ROOT_PEM = b"""-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
"""

# The critical extensions a certificate may carry, as x509.ts allows them.
HANDLED_CRITICAL = {
    ExtensionOID.BASIC_CONSTRAINTS,
    ExtensionOID.KEY_USAGE,
    ExtensionOID.EXTENDED_KEY_USAGE,
}
HASHES = {
    "1.2.840.10045.4.3.2": hashes.SHA256,
    "1.2.840.10045.4.3.3": hashes.SHA384,
    "1.2.840.10045.4.3.4": hashes.SHA512,
}
CURVE_SIZES = {"secp256r1": 32, "secp384r1": 48, "secp521r1": 66}


@dataclass(frozen=True)
class Pcrs:
    pcr0: str
    pcr1: str
    pcr2: str


def all_zero(p: Pcrs) -> bool:
    """A debug-mode enclave's PCRs."""
    return p.pcr0 == ZERO_PCR and p.pcr1 == ZERO_PCR and p.pcr2 == ZERO_PCR


def same_pcrs(a: Pcrs, b: Pcrs) -> bool:
    return a.pcr0 == b.pcr0 and a.pcr1 == b.pcr1 and a.pcr2 == b.pcr2


@dataclass(frozen=True)
class Pin:
    """An image the document's PCRs must name: one entry of Morse's signed list."""

    version: str
    environment: str
    pcrs: Pcrs
    revoked: bool


@dataclass(frozen=True)
class AttestedDocument:
    public_key: bytes
    key_id: bytes
    issued_at: int
    pcrs: Pcrs
    module_id: str | None
    tls_key: bytes | None


class UnpinnedError(ValueError):
    """An image no pin names."""


def _der_tlvs(der: bytes) -> list[bytes]:
    """The raw TLVs inside one DER SEQUENCE, which must be all of `der`."""

    def tlv(at: int) -> tuple[int, int]:
        if at + 2 > len(der):
            raise ValueError("the certificate ends early")
        length, start = der[at + 1], at + 2
        if length & 0x80:
            n = length & 0x7F
            length, start = int.from_bytes(der[start : start + n], "big"), start + n
        if start + length > len(der):
            raise ValueError("the certificate ends early")
        return start, start + length

    start, end = tlv(0)
    if der[0] != 0x30 or end != len(der):
        raise ValueError("the certificate is not one DER SEQUENCE")
    out, at = [], start
    while at < end:
        _, stop = tlv(at)
        out.append(der[at:stop])
        at = stop
    return out


@dataclass(frozen=True)
class Cert:
    der: bytes
    cert: x509.Certificate
    tbs: bytes
    issuer: bytes
    subject: bytes
    ca: bool
    path_len: int | None
    key_cert_sign: bool | None
    unhandled_critical: list[str]


def parse_cert(raw: bytes) -> Cert:
    c = x509.load_der_x509_certificate(raw)
    outer = _der_tlvs(raw)
    tbs = _der_tlvs(outer[0])
    fields = tbs[1:] if tbs[0][0] == 0xA0 else tbs
    # The outer algorithm is outside the signature, so it must be the signed one, as RFC 5280 says.
    if len(outer) != 3 or outer[1] != fields[1]:
        raise ValueError("the certificate's two signature algorithms differ")
    exts = list(c.extensions)
    basic = next((e.value for e in exts if e.oid == ExtensionOID.BASIC_CONSTRAINTS), None)
    usage = next((e.value for e in exts if e.oid == ExtensionOID.KEY_USAGE), None)
    return Cert(
        der=raw,
        cert=c,
        tbs=outer[0],
        issuer=fields[2],
        subject=fields[4],
        ca=basic is not None and basic.ca,
        path_len=basic.path_length if basic is not None else None,
        key_cert_sign=None if usage is None else usage.key_cert_sign,
        unhandled_critical=[
            e.oid.dotted_string for e in exts if e.critical and e.oid not in HANDLED_CRITICAL
        ],
    )


def parse_pem(pem: bytes) -> Cert:
    return parse_cert(x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER))


NITRO_ROOT = parse_pem(AWS_NITRO_ROOT_PEM)


def _strict_signature(der: bytes, size: int) -> bool:
    """An ECDSA-Sig-Value in DER and nothing else, its integers non-negative and of the curve's size."""
    try:
        r, s = decode_dss_signature(der)
    except ValueError:
        return False
    if r < 0 or s < 0 or encode_dss_signature(r, s) != der:
        return False
    return r.bit_length() <= 8 * size and s.bit_length() <= 8 * size


def _signed_by(child: Cert, parent: Cert) -> bool:
    if child.issuer != parent.subject:
        return False
    hash_ = HASHES.get(child.cert.signature_algorithm_oid.dotted_string)
    key = parent.cert.public_key()
    if hash_ is None or not isinstance(key, ec.EllipticCurvePublicKey):
        return False
    size = CURVE_SIZES.get(key.curve.name)
    if size is None or not _strict_signature(child.cert.signature, size):
        return False
    try:
        key.verify(child.cert.signature, child.tbs, ec.ECDSA(hash_()))
        return True
    except InvalidSignature:
        return False


def _check_issuer(issuer: Cert, below: int, name: str) -> None:
    if not issuer.ca:
        raise ValueError(f"{name} is not a CA")
    if issuer.key_cert_sign is False:
        raise ValueError(f"{name} may not sign certificates")
    if issuer.path_len is not None and below > issuer.path_len:
        raise ValueError(f"{name} allows {issuer.path_len} intermediates below it, the chain has {below}")


def iso(ms: int) -> str:
    """A time as JavaScript's toISOString writes it."""
    t = datetime.fromtimestamp(ms // 1000, tz=timezone.utc)
    return f"{t:%Y-%m-%dT%H:%M:%S}.{ms % 1000:03d}Z"


def _ms(t: datetime) -> int:
    return int(t.timestamp()) * 1000


def verify_chain(chain: Sequence[Cert], anchor: Cert, now_ms: int) -> None:
    def check(cert: Cert, name: str) -> None:
        before, after = _ms(cert.cert.not_valid_before_utc), _ms(cert.cert.not_valid_after_utc)
        if not before <= now_ms <= after:
            raise ValueError(f"{name} is valid {iso(before)} to {iso(after)}, not at {iso(now_ms)}")
        if cert.unhandled_critical:
            raise ValueError(f"{name} has unhandled critical extensions {','.join(cert.unhandled_critical)}")

    check(anchor, "the pinned anchor")
    for i, cert in enumerate(chain):
        check(cert, f"certificate {i}")
        if i > 0:
            _check_issuer(cert, i - 1, f"certificate {i}")
        if _signed_by(cert, anchor):
            _check_issuer(anchor, i, "the pinned anchor")
            return
        parent = chain[i + 1] if i + 1 < len(chain) else None
        if parent is None or not _signed_by(cert, parent):
            raise ValueError(f"certificate {i} is signed by neither the next one nor the pinned anchor")
    raise ValueError("the chain is empty")


def key_in_user_data(user_data: bytes, environment: str) -> bytes:
    prefix = f"{USER_DATA_PREFIX}{environment}|".encode()
    if len(user_data) != len(prefix) + KEY_BYTES or not user_data.startswith(prefix):
        raise ValueError(
            f"user_data does not name a {environment} key: {user_data[:40].decode('utf-8', 'replace')}"
        )
    return user_data[len(prefix) :]


def js_round(x: float) -> int:
    """Math.round: halves go up."""
    return math.floor(x + 0.5)


def check_fresh(issued_at: int, now_ms: int) -> None:
    if now_ms - issued_at > MAX_AGE_MS:
        raise ValueError(f"the document is {js_round((now_ms - issued_at) / 60_000)} minutes old")
    if issued_at - now_ms > MAX_AHEAD_MS:
        raise ValueError(
            f"the document is {js_round((issued_at - now_ms) / 60_000)} minutes ahead of this device's clock"
        )


def check_pcrs(pins: Sequence[Pin], environment: str, pcrs: Pcrs) -> Pin:
    """The pin of `environment` that names these PCRs. Refuses a debug enclave's all-zero PCRs, a
    revoked image, and, as UnpinnedError, an image no pin names."""
    if all_zero(pcrs):
        raise ValueError("the enclave reports all-zero PCRs, so it runs in debug mode")
    pinned = next((p for p in pins if p.environment == environment and same_pcrs(p.pcrs, pcrs)), None)
    if pinned is None:
        raise UnpinnedError(f"no {environment} pin names PCR0 {pcrs.pcr0[:16]}")
    if pinned.revoked:
        raise ValueError(f"the {environment} image {pinned.version} is revoked")
    return pinned


def _field(m: object, key: object) -> object:
    return m.get(key) if isinstance(m, dict) else None


def _bytes_at(m: object, key: object) -> bytes:
    value = _field(m, key)
    if not isinstance(value, bytes):
        raise ValueError(f"{key} is not bytes")
    return value


def key_id_of(public_key: bytes) -> bytes:
    return hashlib.sha256(public_key).digest()[:8]


def verify_nitro_document(
    document: bytes,
    environment: str,
    pins: Sequence[Pin],
    root: Cert,
    now_ms: int,
    report: Callable[[str], None] | None = None,
) -> AttestedDocument:
    """Checks a document as src/nitro.ts does. `report` hears each stage that passed: "signed",
    "fresh", "build", and "key", so the first stage not reported is the one that failed."""
    say = report or (lambda _: None)
    sign1 = cbor.decode(document)
    if isinstance(sign1, cbor.Tag) and sign1.tag == 18:
        sign1 = sign1.value
    if not isinstance(sign1, list) or len(sign1) != 4:
        raise ValueError("the document is not a COSE_Sign1")
    protected, _, payload_bytes, signature = sign1
    if not all(isinstance(x, bytes) for x in (protected, payload_bytes, signature)):
        raise ValueError("the COSE_Sign1 is malformed")
    if _field(cbor.decode(protected), 1) != ES384:
        raise ValueError("the document is not signed with ES384")
    payload = cbor.decode(payload_bytes)
    if _field(payload, "digest") != "SHA384":
        raise ValueError("the document's digest is not SHA384")
    issued_at = _field(payload, "timestamp")
    if type(issued_at) is not int:
        raise ValueError("the document has no timestamp")

    leaf = parse_cert(_bytes_at(payload, "certificate"))
    bundle = _field(payload, "cabundle")
    if not isinstance(bundle, list) or not bundle or not all(isinstance(c, bytes) for c in bundle):
        raise ValueError("the document's cabundle is not a list of certificates")
    key = leaf.cert.public_key()
    if leaf.ca or not (isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp384r1"):
        raise ValueError("the signing certificate is not a P-384 leaf")
    intermediates = [parse_cert(c) for c in reversed(bundle[1:])]
    verify_chain([leaf, *intermediates], root, issued_at)
    sig_structure = cbor.encode(["Signature1", protected, b"", payload_bytes])
    try:
        if len(signature) != 96:
            raise InvalidSignature
        der = encode_dss_signature(
            int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big")
        )
        key.verify(der, sig_structure, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        raise ValueError("the document's signature does not verify") from None
    say("signed")

    check_fresh(issued_at, now_ms)
    say("fresh")

    pcr_map = _field(payload, "pcrs")
    pcrs = Pcrs(*(_bytes_at(pcr_map, n).hex() for n in range(3)))
    check_pcrs(pins, environment, pcrs)
    say("build")

    public_key = key_in_user_data(_bytes_at(payload, "user_data"), environment)
    say("key")
    module_id = _field(payload, "module_id")
    tls_key = _field(payload, "public_key")
    return AttestedDocument(
        public_key=public_key,
        key_id=key_id_of(public_key),
        issued_at=issued_at,
        pcrs=pcrs,
        module_id=module_id if isinstance(module_id, str) else None,
        tls_key=tls_key if isinstance(tls_key, bytes) else None,
    )
