# An AWS Nitro document and the certificate chain under it (src/nitro.test.ts, src/x509.der.test.ts):
# a real document under AWS's root, forged ones under a test root, and each rule of the chain.
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from der import ECDSA_SHA256, children, integer, tlv, with_extensions, with_outer_algorithm
from forge import PCR, forge_nitro
from world import read

from trymorse_verify.nitro import (
    NITRO_ROOT,
    Pcrs,
    Pin,
    _strict_signature,
    parse_cert,
    verify_chain,
    verify_nitro_document,
)

MINUTE = 60_000


def test_pins_the_aws_nitro_enclaves_root_g1_by_the_fingerprint_aws_publishes():
    assert (
        hashlib.sha256(NITRO_ROOT.der).hexdigest()
        == "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
    )


class TestARealAwsNitroDocument:
    """NSM writes this document's payload as an indefinite-length map."""

    document = base64.b64decode(read("nitro_document.b64").decode().strip())
    issued_at = 1792280904626
    pcrs = Pcrs(
        "1dab5ad4c661f95a9e7e3f57bcd83efd9fced7f749ac21ea85a1853131bb5e43b41eb58615efef998d478ce485fcff53",
        "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03",
        "f9d2c68436810c46556535a583870e2913ec1f05ecca361b4e78eaa00d0b365dee6570e7699c4f34165fbf635bf35c6a",
    )

    def check(
        self, document=None, *, after=MINUTE, pins=None, environment="dev", root=NITRO_ROOT, report=None
    ):
        pins = [Pin("v1", "dev", self.pcrs, False)] if pins is None else pins
        return verify_nitro_document(
            self.document if document is None else document,
            environment,
            pins,
            root,
            self.issued_at + after,
            report,
        )

    @pytest.mark.parametrize("after", [MINUTE, 30 * MINUTE, -5 * MINUTE])
    def test_passes_every_check_and_vouches_for_the_key_its_user_data_names(self, after):
        doc = self.check(after=after)
        assert doc.public_key.hex() == "48895025406095a204ddcf391e72f6a517af868796cd3167d9ddceef13c9ae5e"
        assert doc.key_id.hex() == "d074a9212978f332"
        assert doc.issued_at == self.issued_at
        assert doc.pcrs == self.pcrs
        assert doc.module_id == "i-0a93e4d666586119b-enc01a14c4380fcd25f"
        assert doc.tls_key is None

    def test_reports_each_stage_as_it_passes_in_order(self):
        steps: list[str] = []
        self.check(report=steps.append)
        assert steps == ["signed", "fresh", "build", "key"]

    def forged(self) -> bytes:
        forged = bytearray(self.document)
        forged[-1] ^= 1
        return bytes(forged)

    @pytest.mark.parametrize(
        "make, passed",
        [
            (lambda t: {"document": t.forged()}, []),
            (lambda t: {"after": 31 * MINUTE}, ["signed"]),
            (lambda t: {"pins": []}, ["signed", "fresh"]),
        ],
        ids=["a bad signature", "an old document", "an unpinned build"],
    )
    def test_reports_only_the_stages_before_the_one_that_fails(self, make, passed):
        steps: list[str] = []
        with pytest.raises(ValueError):
            self.check(report=steps.append, **make(self))
        assert steps == passed

    @pytest.mark.parametrize(
        "o, reason",
        [
            ({"after": 31 * MINUTE}, "^the document is 31 minutes old$"),
            ({"after": -6 * MINUTE}, "^the document is 6 minutes ahead of this device's clock$"),
            ({"pins": []}, "^no dev pin names PCR0 1dab5ad4c661f95a$"),
            ({"environment": "prod"}, "^no prod pin names PCR0 1dab5ad4c661f95a$"),
        ],
    )
    def test_is_refused_late_early_or_unpinned(self, o, reason):
        with pytest.raises(ValueError, match=reason):
            self.check(**o)

    def test_is_refused_when_its_pin_is_revoked(self):
        with pytest.raises(ValueError, match="^the dev image v1 is revoked$"):
            self.check(pins=[Pin("v1", "dev", self.pcrs, True)])

    def test_is_refused_with_one_byte_of_its_signature_changed(self):
        with pytest.raises(ValueError, match="^the document's signature does not verify$"):
            self.check(self.forged())

    def test_is_refused_under_another_root(self):
        with pytest.raises(ValueError, match="signed by neither the next one nor the pinned anchor"):
            self.check(root=forge_nitro(self.issued_at).root)


FORGED_AT = 1_793_961_600_000


@pytest.fixture(scope="module")
def forge():
    return forge_nitro(FORGED_AT)


class TestAForgedDocument:
    now = FORGED_AT

    def check(self, forge, **o) -> object:
        o.setdefault("public_key", bytes(range(32)))
        pins = [Pin("v1", "dev", PCR, False), Pin("v2", "prod", Pcrs("b0" * 48, PCR.pcr1, PCR.pcr2), False)]
        return verify_nitro_document(
            forge.document(timestamp=self.now - MINUTE, **o), "dev", pins, forge.root, self.now
        )

    def test_vouches_for_the_key_its_user_data_names(self, forge):
        doc = self.check(forge)
        assert doc.public_key == bytes(range(32))
        assert doc.key_id == hashlib.sha256(bytes(range(32))).digest()[:8]
        assert doc.issued_at == self.now - MINUTE

    @pytest.mark.parametrize(
        "o, reason",
        [
            ({"environment": "prod"}, "user_data does not name a dev key"),
            ({"public_key": bytes(31)}, "user_data does not name a dev key"),
            ({"pcrs": Pcrs("00" * 48, "00" * 48, "00" * 48)}, "debug mode"),
            ({"pcrs": Pcrs("b0" * 48, PCR.pcr1, PCR.pcr2)}, "no dev pin"),
            ({"digest": "SHA256"}, "digest is not SHA384"),
            ({"digest": "\ufeffSHA384"}, "digest is not SHA384"),
            ({"alg": -7}, "not signed with ES384"),
            ({"sign_with": "stranger"}, "signature does not verify"),
        ],
        ids=[
            "a document of the other environment",
            "a key that is not 32 bytes",
            "all-zero PCRs",
            "PCRs of the prod image",
            "a SHA256 digest",
            "a digest after a byte-order mark, which TextDecoder would drop",
            "ES256",
            "a signer outside the chain",
        ],
    )
    def test_refuses(self, forge, o, reason):
        with pytest.raises(ValueError, match=reason):
            self.check(forge, **o)


# --- The chain, rule by rule ---------------------------------------------------------------

NOW = datetime(2026, 10, 1, 9, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1000)
HOUR = timedelta(hours=1)
UNSIGNED = "certificate 0 is signed by neither the next one nor the pinned anchor"
ABSENT = object()


def usage(key_cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not key_cert_sign,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


class Party:
    def __init__(self, name: str):
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        self.key = ec.generate_private_key(ec.SECP384R1())


def issue(
    subject: Party,
    issuer: Party,
    *,
    ca: bool | None,
    path_len: int | None = None,
    key_cert_sign: object = ABSENT,
    before: datetime = NOW - HOUR,
    after: datetime = NOW + 48 * HOUR,
    critical: str | None = None,
) -> bytes:
    """A certificate as src/testing/certs.ts issues one: basic constraints only when `ca` is not
    None, key usage only when `key_cert_sign` is given, both critical."""
    b = (
        x509.CertificateBuilder()
        .subject_name(subject.name)
        .issuer_name(issuer.name)
        .public_key(subject.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
    )
    if ca is not None:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True)
    if key_cert_sign is not ABSENT:
        b = b.add_extension(usage(bool(key_cert_sign)), critical=True)
    if critical:
        b = b.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(critical), b"\x05\x00"), critical=True
        )
    return b.sign(issuer.key, hashes.SHA384()).public_bytes(serialization.Encoding.DER)


def outcome(chain: list[bytes], anchor: bytes) -> str:
    try:
        verify_chain([parse_cert(c) for c in chain], parse_cert(anchor), NOW_MS)
        return "accepted"
    except ValueError as e:
        return f"refused: {e}"


@pytest.fixture(scope="module")
def parties():
    return Party("Root"), Party("Intermediate"), Party("Second"), Party("Leaf")


def test_accepts_a_leaf_under_an_intermediate_under_the_anchor(parties):
    root, mid, _, leaf = parties
    anchor = issue(root, root, ca=True, key_cert_sign=True)
    assert outcome([issue(leaf, mid, ca=False), issue(mid, root, ca=True, key_cert_sign=True)], anchor) == (
        "accepted"
    )


@pytest.mark.parametrize(
    "anchor_o, mid_o, reason",
    [
        ({}, {"ca": False}, "certificate 1 is not a CA"),
        ({}, {"ca": None}, "certificate 1 is not a CA"),
        ({}, {"key_cert_sign": False}, "certificate 1 may not sign certificates"),
        ({"ca": False}, {}, "the pinned anchor is not a CA"),
        ({"key_cert_sign": False}, {}, "the pinned anchor may not sign certificates"),
        ({"path_len": 0}, {}, "the pinned anchor allows 0 intermediates below it, the chain has 1"),
        ({}, {"after": NOW - HOUR, "before": NOW - 2 * HOUR}, "certificate 1 is valid "),
        ({"after": NOW - HOUR, "before": NOW - 2 * HOUR}, {}, "the pinned anchor is valid "),
        (
            {},
            {"critical": "1.3.6.1.4.1.99999.1"},
            "certificate 1 has unhandled critical extensions 1.3.6.1.4.1.99999.1",
        ),
    ],
    ids=[
        "an intermediate that is not a CA",
        "an intermediate with no basic constraints",
        "an intermediate whose key usage leaves out keyCertSign",
        "an anchor that is not a CA",
        "an anchor whose key usage leaves out keyCertSign",
        "an anchor that allows no intermediate",
        "an expired intermediate",
        "an expired anchor",
        "an intermediate with a critical extension nothing here reads",
    ],
)
def test_refuses_a_chain_whose_issuer_breaks_a_rule(parties, anchor_o, mid_o, reason):
    root, mid, _, leaf = parties
    anchor = issue(root, root, **{"ca": True, "key_cert_sign": True, **anchor_o})
    chain = [issue(leaf, mid, ca=False), issue(mid, root, **{"ca": True, "key_cert_sign": True, **mid_o})]
    assert outcome(chain, anchor).startswith(f"refused: {reason}")


@pytest.mark.parametrize(
    "o, reason",
    [
        ({"after": NOW - HOUR, "before": NOW - 2 * HOUR}, "certificate 0 is valid "),
        ({"before": NOW + HOUR}, "certificate 0 is valid "),
        ({"critical": "1.3.6.1.4.1.99999.1"}, "certificate 0 has unhandled critical extensions"),
    ],
    ids=["an expired leaf", "a leaf not yet valid", "a leaf with a critical extension nothing here reads"],
)
def test_refuses_a_leaf_outside_its_validity_or_with_an_unread_critical_extension(parties, o, reason):
    root, _, _, leaf = parties
    anchor = issue(root, root, ca=True, key_cert_sign=True)
    assert outcome([issue(leaf, root, ca=False, **o)], anchor).startswith(f"refused: {reason}")


def test_names_the_validity_window_and_the_time_it_was_checked_at(parties):
    root, _, _, leaf = parties
    anchor = issue(root, root, ca=True, key_cert_sign=True)
    late = issue(leaf, root, ca=False, before=NOW - 2 * HOUR, after=NOW - HOUR)
    assert outcome([late], anchor) == (
        "refused: certificate 0 is valid 2026-10-01T07:00:00.000Z to 2026-10-01T08:00:00.000Z, not at 2026-10-01T09:00:00.000Z"
    )


@pytest.mark.parametrize(
    "path_len, reason", [(1, None), (0, "certificate 2 allows 0 intermediates below it, the chain has 1")]
)
def test_holds_an_intermediate_to_its_path_length(parties, path_len, reason):
    root, mid, second, leaf = parties
    anchor = issue(root, root, ca=True, key_cert_sign=True)
    chain = [
        issue(leaf, second, ca=False),
        issue(second, mid, ca=True, key_cert_sign=True),
        issue(mid, root, ca=True, path_len=path_len, key_cert_sign=True),
    ]
    assert outcome(chain, anchor) == ("accepted" if reason is None else f"refused: {reason}")


def test_refuses_a_leaf_the_anchor_did_not_sign(parties):
    root, mid, _, leaf = parties
    anchor = issue(root, root, ca=True, key_cert_sign=True)
    assert outcome([issue(leaf, mid, ca=False)], anchor) == f"refused: {UNSIGNED}"


# --- Parsing -------------------------------------------------------------------------------


def test_refuses_a_certificate_whose_outer_algorithm_which_no_signature_covers_is_another(parties):
    root, _, _, _ = parties
    cert = issue(root, root, ca=True, key_cert_sign=True)
    assert parse_cert(cert).der == cert
    with pytest.raises(ValueError, match="^the certificate's two signature algorithms differ$"):
        parse_cert(with_outer_algorithm(cert, ECDSA_SHA256))


def test_refuses_a_certificate_that_repeats_an_extension(parties):
    root, _, _, _ = parties
    cert = issue(root, root, ca=True, key_cert_sign=True)
    with pytest.raises(Exception, match="Duplicate 2.5.29.19 extension found"):
        parse_cert(with_extensions(cert, lambda exts: [*exts, exts[0]]))


def test_refuses_a_certificate_in_ber_not_der(parties):
    root, _, _, _ = parties
    tbs, alg, signature = children(issue(root, root, ca=True, key_cert_sign=True))
    # The outer SEQUENCE's length in four bytes, where DER takes the fewest.
    body = tbs + alg + signature
    with pytest.raises(ValueError):
        parse_cert(b"\x30\x84" + len(body).to_bytes(4, "big") + body)


# --- A signature verifies only in its one DER encoding (src/x509.ts's ECDSA rules) ------------
# High-s is another signature, not another encoding, so it verifies as ECDSA allows.

N384 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973


def content(n: int) -> bytes:
    """An INTEGER's minimal content octets."""
    return integer(n)[2:]


ENCODINGS = {
    "minimal DER (control)": lambda r, s: tlv(0x30, integer(r), integer(s)),
    "trailing bytes after the SEQUENCE": lambda r, s: tlv(0x30, integer(r), integer(s)) + b"\0\0",
    "a third INTEGER inside the SEQUENCE": lambda r, s: tlv(0x30, integer(r), integer(s), integer(0)),
    "negative INTEGER r (high bit set, no 0x00 pad)": lambda r, s: tlv(
        0x30, tlv(0x02, r.to_bytes(48, "big")), integer(s)
    ),
    "leading-zero rule violated (extra 0x00 before r)": lambda r, s: tlv(
        0x30, tlv(0x02, b"\0" + content(r)), integer(s)
    ),
    "long-form length on a short INTEGER": lambda r, s: tlv(
        0x30, b"\x02\x81" + bytes([len(content(r))]) + content(r), integer(s)
    ),
    "indefinite-length SEQUENCE": lambda r, s: b"\x30\x80" + integer(r) + integer(s) + b"\0\0",
    "SET instead of SEQUENCE": lambda r, s: tlv(0x31, integer(r), integer(s)),
    "OCTET STRING instead of INTEGER r": lambda r, s: tlv(0x30, tlv(0x04, content(r)), integer(s)),
    "r and s swapped": lambda r, s: tlv(0x30, integer(s), integer(r)),
    "r = 0": lambda r, s: tlv(0x30, integer(0), integer(s)),
    "high-s twin (n - s), minimal DER": lambda r, s: tlv(0x30, integer(r), integer(N384 - s)),
    "r + n (49 bytes)": lambda r, s: tlv(0x30, integer(r + N384), integer(s)),
}


@pytest.mark.parametrize("name", ENCODINGS)
def test_verifies_a_chain_signed_in_an_encoding_only_when_it_is_minimal_der(parties, name):
    root, _, _, leaf = parties
    anchor = issue(root, root, ca=True, key_cert_sign=True)
    tbs, alg, _ = children(issue(leaf, root, ca=False))
    high_r = name.startswith("negative")
    while True:
        r, s = decode_dss_signature(root.key.sign(tbs, ec.ECDSA(hashes.SHA384())))
        if (r >> 383 == 1) == high_r:
            break
    signed = tlv(0x30, tbs, alg, tlv(0x03, b"\0" + ENCODINGS[name](r, s)))
    minimal = "control" in name or "high-s" in name
    assert outcome([signed], anchor) == ("accepted" if minimal else f"refused: {UNSIGNED}")


# OpenSSL refuses each of these too, so the test above passes without nitro.py's own DER rule;
# this one holds that rule, should a backend ever read BER.
DER = {"minimal DER (control)", "r and s swapped", "r = 0", "high-s twin (n - s), minimal DER"}


@pytest.mark.parametrize("name", ENCODINGS)
def test_reads_as_a_signature_only_minimal_der_with_scalars_of_the_curves_size(name):
    r, s = (1 << 383) | 12345, 67890
    assert _strict_signature(ENCODINGS[name](r, s), 48) == (name in DER)
