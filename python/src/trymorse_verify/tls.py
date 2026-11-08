# Where TLS to the host ends: the SHA-256 of the key its certificate names, to compare with the keys
# the enclaves attest in their documents' public_key. By hand:
#   openssl s_client -connect api.trymorse.ai:443 -servername api.trymorse.ai </dev/null 2>/dev/null \
#     | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256
from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class ServedKey:
    # Hex SHA-256 of the DER SubjectPublicKeyInfo of the certificate the host served.
    spki_sha256: str
    # The common name of its issuer.
    issuer: str


def served_key(host: str) -> ServedKey:
    """A new connection to `host`:443, checked as any HTTPS client checks it (Mozilla's roots, as
    httpx and Node use), with no session reused."""
    context = ssl.create_default_context(cafile=certifi.where())
    with socket.create_connection((host, 443), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    return ServedKey(
        spki_sha256=hashlib.sha256(spki).hexdigest(),
        issuer=str(cn[-1].value) if cn else cert.issuer.rfc4514_string(),
    )
