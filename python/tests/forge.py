# A test root and the documents it signs, as src/testing/forge.ts and certs.ts forge them: AWS's
# root can't sign test documents, so these chain to a P-384 root made here.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from trymorse_verify import cbor
from trymorse_verify.nitro import USER_DATA_PREFIX, Cert, Pcrs, parse_cert

PCR = Pcrs("a0" * 48, "a1" * 48, "a2" * 48)


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _usage(**on: bool) -> x509.KeyUsage:
    flags = dict.fromkeys(
        [
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ],
        False,
    )
    return x509.KeyUsage(**{**flags, **on})


def issue(
    subject: tuple[str, ec.EllipticCurvePrivateKey],
    issuer: tuple[str, ec.EllipticCurvePrivateKey],
    now: datetime,
    *,
    ca: bool,
    days: int = 30,
    critical_oid: str | None = None,
) -> bytes:
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(subject[0]))
        .issuer_name(_name(issuer[0]))
        .public_key(subject[1].public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=days))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(_usage(key_cert_sign=True) if ca else _usage(digital_signature=True), critical=True)
    )
    if critical_oid:
        b = b.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(critical_oid), b"\x05\x00"),
            critical=True,
        )
    return b.sign(issuer[1], hashes.SHA384()).public_bytes(serialization.Encoding.DER)


@dataclass
class Forge:
    root: Cert
    root_der: bytes
    intermediate_der: bytes
    leaf_der: bytes
    leaf_key: ec.EllipticCurvePrivateKey
    stranger: ec.EllipticCurvePrivateKey

    def document(
        self,
        timestamp: int,
        public_key: bytes,
        environment: str = "dev",
        user_data: bytes | None = None,
        pcrs: Pcrs = PCR,
        digest: str = "SHA384",
        alg: int = -35,
        sign_with: str = "leaf",
        tls_key: bytes | None = None,
        module_id: str = "i-0123-enc0123",
    ) -> bytes:
        payload = cbor.encode(
            {
                "module_id": module_id,
                "digest": digest,
                "timestamp": timestamp,
                "pcrs": {
                    0: bytes.fromhex(pcrs.pcr0),
                    1: bytes.fromhex(pcrs.pcr1),
                    2: bytes.fromhex(pcrs.pcr2),
                    3: bytes(48),
                },
                "certificate": self.leaf_der,
                "cabundle": [self.root_der, self.intermediate_der],
                "public_key": tls_key,
                "user_data": user_data
                if user_data is not None
                else f"{USER_DATA_PREFIX}{environment}|".encode() + public_key,
                "nonce": None,
            }
        )
        protected = cbor.encode({1: alg})
        key = self.stranger if sign_with == "stranger" else self.leaf_key
        der = key.sign(cbor.encode(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der)
        return cbor.encode([protected, {}, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")])


def forge_nitro(now_ms: int) -> Forge:
    """A test root and documents it signs, with certificates valid for 30 days either side of now."""
    now = datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc)
    root = ("aws.nitro-enclaves", _key())
    intermediate = ("zonal.aws.nitro-enclaves", _key())
    leaf = ("i-0123.enc0123.aws", _key())
    root_der = issue(root, root, now, ca=True)
    return Forge(
        root=parse_cert(root_der),
        root_der=root_der,
        intermediate_der=issue(intermediate, root, now, ca=True),
        leaf_der=issue(leaf, intermediate, now, ca=False),
        leaf_key=leaf[1],
        stranger=_key(),
    )
