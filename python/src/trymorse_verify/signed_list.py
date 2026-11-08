# Morse's signed list of the prod images it allows, which its private CI signs with Sigstore and
# logs in Rekor, Sigstore's public log. These are the rules of Morse's own Go verifier
# (internal/pinsig in morse-server, which is private; morse-enclave carries a public copy), on top
# of sigstore-python, as src/node/signed_list.ts has them on top of @sigstore/verify. By hand:
#   tag=$(curl -sI https://github.com/trymorse/morse-pins/releases/latest | sed -n 's|^location: .*/tag/||Ip' | tr -d '\r')
#   curl -sLO https://github.com/trymorse/morse-pins/releases/download/$tag/prod.statement.json
#   curl -sLO https://github.com/trymorse/morse-pins/releases/download/$tag/prod.sigstore.json
#   cosign verify-blob prod.statement.json --bundle prod.sigstore.json \
#     --certificate-identity https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main \
#     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
#     --certificate-github-workflow-sha "$(jq -r .pins_commit prod.statement.json)"
#   jq -r '.verificationMaterial.tlogEntries[0] | "Rekor entry \(.logIndex), logged \(.integratedTime | tonumber | todate)"' prod.sigstore.json
#   jq -e '.verificationMaterial.tlogEntries[0].integratedTime | tonumber > now - 7 * 86400' prod.sigstore.json   # true: logged in the last 7 days
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal
from importlib import resources

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .io import Unfinished, get, parse_json
from .io import json as read_json
from .nitro import Pcrs, js_round, parse_cert

RELEASES = "https://github.com/trymorse/morse-pins/releases"
TAG = re.compile(r"signed-[0-9]+-[0-9]{8}T[0-9]{6}Z")
MEDIA_TYPES = (
    "application/vnd.dev.sigstore.bundle.v0.3+json",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
)
MAX_AGE_MS = 7 * 24 * 3600_000
MAX_AHEAD_MS = 5 * 60_000

# Who may sign the list: the sign.yml workflow on main of Watermark-Labs/pins, on a GitHub-hosted
# runner, started by a push or the schedule, in the first attempt of its run. Extensions .8 and up
# hold DER UTF8Strings; .1 holds the issuer raw.
ISSUER = "https://token.actions.githubusercontent.com"
SIGNER = "https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main"
REPOSITORY = "https://github.com/Watermark-Labs/pins"
FULCIO = "1.3.6.1.4.1.57264.1."
EXPECTED = {
    8: ISSUER,
    9: SIGNER,
    11: "github-hosted",
    12: REPOSITORY,
    14: "refs/heads/main",
    15: "1405118053",
    17: "334112171",
    18: SIGNER,
}
TRIGGERS = ("push", "schedule")
RUN = re.compile(r"https://github\.com/Watermark-Labs/pins/actions/runs/[0-9]+/attempts/1")

# Sigstore's public trusted root: the same object as src/node/sigstore_root.ts (a test holds them
# equal), copied from Sigstore's root-signing repository (targets/trusted_root.json through TUF).
SIGSTORE_TRUSTED_ROOT: dict = json.loads(
    resources.files(__package__).joinpath("sigstore_root.json").read_text("utf-8")
)


@dataclass(frozen=True)
class SignedListFiles:
    tag: str
    statement: bytes
    # The bundle's JSON, parsed, or None if it held none.
    bundle: object


@dataclass(frozen=True)
class ListedImage:
    pcrs: Pcrs
    revoked: bool


@dataclass(frozen=True)
class SignedList:
    sequence: int
    time: str
    pins_commit: str
    # The Rekor entry's global index, which search.sigstore.dev and rekor-cli look up.
    log_index: str
    # When Rekor logged it, in ms, as its signed entry timestamp says.
    integrated_time: int
    images: tuple[ListedImage, ...]


def fetch_signed_list(client: httpx.Client) -> SignedListFiles:
    """The latest release of github.com/trymorse/morse-pins, resolved once so that both files
    come from it, and its prod statement and bundle."""
    latest = get(client, f"{RELEASES}/latest", "manual")
    location = latest.headers.get("location") or ""
    prefix = f"{RELEASES}/tag/"
    tag = location[len(prefix) :] if location.startswith(prefix) else ""
    if not TAG.fullmatch(tag):
        raise Unfinished(
            f"{RELEASES}/latest answered {latest.status} {location or 'with no release'}, not a signed list"
        )

    def asset(name: str) -> bytes:
        url = f"{RELEASES}/download/{tag}/{name}"
        got = get(client, url, "follow")
        if got.status != 200:
            raise Unfinished(f"{url} answered {got.status}")
        return got.body

    statement = asset("prod.statement.json")
    return SignedListFiles(tag, statement, read_json(asset("prod.sigstore.json")))


# --- The statement -------------------------------------------------------------------------

_JS_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _js_string(s: str) -> str:
    """A string as JSON.stringify writes it."""
    out = []
    for c in s:
        if c in _JS_ESCAPES:
            out.append(_JS_ESCAPES[c])
        elif c < " " or "\ud800" <= c <= "\udfff":
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def _js_number(x: float | int) -> str:
    """A number as JavaScript writes it (Number::toString), from its shortest round-trip digits."""
    if x == 0:
        return "0"
    sign, digits, exp = Decimal(repr(float(x))).normalize().as_tuple()
    d = "".join(map(str, digits))
    k, n = len(d), len(d) + exp
    out = (
        d + "0" * (n - k)
        if k <= n <= 21
        else d[:n] + "." + d[n:]
        if 0 < n <= 21
        else "0." + "0" * -n + d
        if -6 < n <= 0
        else d + f"e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"
        if k == 1
        else f"{d[0]}.{d[1:]}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"
    )
    return ("-" if sign else "") + out


def _canonical(v: object) -> str:
    """JCS: keys sorted by UTF-16 code unit, no whitespace, strings and numbers as JSON.stringify
    writes them, which writes a number too big for a double, such as 1e400, as null."""
    if isinstance(v, list):
        return "[" + ",".join(_canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(f"{_js_string(k)}:{_canonical(v[k])}" for k in keys) + "}"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, float) and not math.isfinite(v):
        return "null"
    if isinstance(v, (int, float)):
        return _js_number(v)
    return _js_string(v)


DATE = (
    r"(?:(?:[0-9][0-9][2468][048]|[0-9][0-9][13579][26]|[0-9][0-9]0[48]|[02468][048]00|[13579][26]00)-02-29"
    r"|[0-9]{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])|(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)"
    r"|(?:02)-(?:0[1-9]|1[0-9]|2[0-8])))"
)
# RFC 3339 with seconds and Z or an offset, as zod's z.iso.datetime({ offset: true }) reads it.
DATETIME = re.compile(
    DATE
    + r"T(?:(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?(?:Z|([+-](?:[01][0-9]|2[0-3]):[0-5][0-9])))"
)
PCR = re.compile(r"[0-9a-f]{96}")
COMMIT = re.compile(r"[0-9a-f]{40}")
ZERO = "0" * 96
SAFE = 2**53 - 1
STATEMENT_KEYS = ("environment", "images", "pins_commit", "sequence", "time", "type")
IMAGE_KEYS = ("pcr0", "pcr1", "pcr2", "revoked")


def _kind(v: object) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


def _received(v: dict, key: str) -> str:
    return _kind(v[key]) if key in v else "undefined"


def _object(v: object, path: str) -> dict:
    if not isinstance(v, dict):
        raise ValueError(f"{path}: Invalid input: expected object, received {_kind(v)}")
    return v


def _no_other_keys(v: dict, keys: tuple[str, ...], path: str) -> None:
    extra = [k for k in v if k not in keys]
    if extra:
        names = ", ".join(json.dumps(k, ensure_ascii=False) for k in extra)
        raise ValueError(f"{path}: Unrecognized key{'s' if len(extra) > 1 else ''}: {names}")


def _string(v: dict, key: str, path: str, pattern: re.Pattern) -> None:
    if not isinstance(v.get(key), str):
        raise ValueError(f"{path}: Invalid input: expected string, received {_received(v, key)}")
    if not pattern.fullmatch(v[key]):
        raise ValueError(f"{path}: Invalid string: must match pattern /^{pattern.pattern}$/")


def _literal(v: dict, key: str, want: str) -> None:
    if not isinstance(v.get(key), str) or v[key] != want:
        raise ValueError(f'{key}: Invalid input: expected "{want}"')


def _parse_statement(st: object) -> dict:
    """The schema of src/node/signed_list.ts, refused with the words of zod's first issue: an
    object's fields in order, then its unknown keys, then its refinement."""
    st = _object(st, "it")
    _literal(st, "environment", "prod")
    images = st.get("images")
    if not isinstance(images, list):
        raise ValueError(f"images: Invalid input: expected array, received {_received(st, 'images')}")
    for i, image in enumerate(images):
        at = f"images.{i}"
        image = _object(image, at)
        for n in ("pcr0", "pcr1", "pcr2"):
            _string(image, n, f"{at}.{n}", PCR)
        if not isinstance(image.get("revoked"), bool):
            raise ValueError(
                f"{at}.revoked: Invalid input: expected boolean, received {_received(image, 'revoked')}"
            )
        _no_other_keys(image, IMAGE_KEYS, at)
        if image["pcr0"] == image["pcr1"] == image["pcr2"] == ZERO:
            raise ValueError(f"{at}: an image has all-zero PCRs")
    if not images:
        raise ValueError("images: Too small: expected array to have >=1 items")
    _string(st, "pins_commit", "pins_commit", COMMIT)
    seq = st.get("sequence")
    if isinstance(seq, bool) or not isinstance(seq, (int, float)):
        raise ValueError(f"sequence: Invalid input: expected number, received {_received(st, 'sequence')}")
    if not float(seq).is_integer():
        raise ValueError("sequence: Invalid input: expected int, received number")
    # zod's int() is a safe integer's: one a double holds exactly.
    if seq > SAFE:
        raise ValueError(f"sequence: Too big: expected int to be <={SAFE}")
    if seq < -SAFE:
        raise ValueError(f"sequence: Too small: expected int to be >={-SAFE}")
    if seq <= 0:
        raise ValueError("sequence: Too small: expected number to be >0")
    if not isinstance(st.get("time"), str):
        raise ValueError(f"time: Invalid input: expected string, received {_received(st, 'time')}")
    if not DATETIME.fullmatch(st["time"]):
        raise ValueError("time: Invalid ISO datetime")
    _literal(st, "type", "morse-enclave-pins-v1")
    _no_other_keys(st, STATEMENT_KEYS, "it")
    return st


def read_statement(statement: bytes) -> dict:
    """The statement, if its bytes are exactly the canonical JSON (JCS) of a prod pins statement,
    as Morse signs it: no byte-order mark, sorted keys, no whitespace. Raises a ValueError that
    completes "Morse's signed list <tag> …"."""
    try:
        text = statement.decode("utf-8")
        parsed = parse_json(text)
    except ValueError:
        raise ValueError("is not JSON") from None
    if _canonical(parsed) != text:
        raise ValueError("is not in canonical form (JCS), as Morse signs it")
    try:
        return _parse_statement(parsed)
    except ValueError as e:
        raise ValueError(f"is not a prod pins statement: {e}") from None


# --- The bundle ----------------------------------------------------------------------------


def _utf8_string(der: bytes) -> str | None:
    """The DER UTF8String an extension holds, or None if it holds anything else."""
    if len(der) < 2 or der[0] != 0x0C:
        return None
    length, at = der[1], 2
    if length == 0x81 and len(der) > 2 and der[2] >= 0x80:
        length, at = der[2], 3
    elif length == 0x82 and len(der) > 3 and der[2] != 0:
        length, at = (der[2] << 8) | der[3], 4
    elif length > 0x7F:
        return None
    if at + length != len(der):
        return None
    try:
        return der[at:].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _ago(ms: int) -> str:
    if ms >= 2 * 24 * 3600_000:
        return f"{js_round(ms / (24 * 3600_000))} days"
    return f"{js_round(ms / 60_000)} min"


def _logged_certificate(body: bytes) -> bytes:
    """The one certificate a hashedrekord entry's body names, or b""."""
    try:
        entry = json.loads(body)
        pem = base64.b64decode(entry["spec"]["signature"]["publicKey"]["content"])
        if pem.count(b"-----BEGIN ") != 1:
            return b""
        return x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)
    except Exception:
        return b""


def _bundle_error(e: Exception) -> str:
    errors = getattr(e, "errors", None)
    if callable(errors):
        fields = []
        for err in errors():
            path = ""
            for part in err.get("loc", ()):
                path += f"[{part}]" if isinstance(part, int) else f".{part}" if path else str(part)
            fields.append(path)
        return f"invalid bundle ({', '.join(fields)})"
    return str(e).split("\n")[0]


def _san(cert: x509.Certificate) -> str:
    """The subjectAltName as Node's X509Certificate writes it, such as "URI:https://…"."""
    try:
        names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return "undefined"
    shown = []
    for n in names:
        if isinstance(n, x509.UniformResourceIdentifier):
            shown.append(f"URI:{n.value}")
        elif isinstance(n, x509.RFC822Name):
            shown.append(f"email:{n.value}")
        elif isinstance(n, x509.DNSName):
            shown.append(f"DNS:{n.value}")
        else:
            shown.append(f"{type(n).__name__}:{n.value}")
    return ", ".join(shown)


def _json_names(v: object) -> object:
    """The bundle as @sigstore/protobuf-specs reads it: each field by its JSON name alone, which is
    camelCase. sigstore-python's models also take a field's proto name, such as media_type, which
    TS leaves out as an unknown key, so this leaves it out too."""
    if isinstance(v, dict):
        return {k: _json_names(x) for k, x in v.items() if "_" not in k}
    if isinstance(v, list):
        return [_json_names(x) for x in v]
    return v


class _Identity:
    """sigstore-python's identity policy, which this leaves to the checks after it, as TS does."""

    def verify(self, cert: x509.Certificate) -> None:
        return None


def verify_signed_list(files: SignedListFiles, now_ms: int, trusted_root: dict | None = None) -> SignedList:
    """Checks the bundle signs the statement as Morse's pins workflow, logged once in Rekor v1 with
    both a signed entry timestamp and an inclusion proof, between 7 days before `now_ms` and 5
    minutes after it. Raises a ValueError that completes "Morse's signed list <tag> …"."""
    # Imported here, as sigstore-python is slow to import and only this check needs it.
    from sigstore.models import Bundle, TrustedRoot
    from sigstore.verify import Verifier
    from sigstore_models.bundle.v1 import Bundle as BundleModel
    from sigstore_models.common.v1 import HashAlgorithm
    from sigstore_models.trustroot import v1 as trustroot_v1

    try:
        inner = BundleModel.from_json(json.dumps(_json_names(files.bundle)))
    except Exception as e:
        raise ValueError(f"is not a Sigstore bundle: {_bundle_error(e)}") from None
    if inner.media_type not in MEDIA_TYPES:
        raise ValueError(f"is a {inner.media_type}, not a v0.3 bundle")
    if inner.message_signature is None:
        raise ValueError("signs a DSSE envelope, not the statement itself")
    material = inner.verification_material
    if material.certificate is None:
        raise ValueError("is not signed with one Fulcio certificate")
    entries = material.tlog_entries or []
    if len(entries) != 1:
        raise ValueError(f"has {len(entries)} log entries, not one")
    (entry,) = entries
    kind = f"{entry.kind_version.kind} {entry.kind_version.version}"
    if kind != "hashedrekord 0.0.1":
        raise ValueError(f"is logged as {kind}, not hashedrekord 0.0.1 (Rekor v1)")
    if (
        entry.inclusion_promise is None
        or entry.inclusion_proof is None
        or not entry.inclusion_proof.checkpoint
    ):
        raise ValueError(
            "lacks Rekor's signed entry timestamp or its inclusion proof, which it must carry both of"
        )
    # After the checkpoint's first blank line comes one signature line and nothing else, as in Go.
    envelope = entry.inclusion_proof.checkpoint.envelope
    blank = envelope.find("\n\n")
    signatures = "" if blank < 0 else envelope[blank + 2 :].removesuffix("\n")
    if not signatures or "\n" in signatures:
        raise ValueError("carries a checkpoint signed other than once")

    digest = hashlib.sha256(files.statement).digest()
    signed = inner.message_signature.message_digest
    if signed is None or signed.algorithm != HashAlgorithm.SHA2_256 or signed.digest != digest:
        raise ValueError("names a digest other than the statement's SHA-256")
    certificate = material.certificate.raw_bytes
    if _logged_certificate(entry.canonicalized_body) != certificate:
        raise ValueError("is logged with another certificate than it carries")

    # The leaf's profile, read before sigstore-python reads it (it refuses both, in its own words),
    # by x509.ts's rules, as src/node/signed_list.ts reads it: DER, one signature algorithm, and
    # each extension once.
    try:
        parsed = parse_cert(certificate)
    except Exception as e:
        raise ValueError(
            f"is signed with a certificate that {str(e).removeprefix('the certificate ')}"
        ) from None
    leaf = parsed.cert
    extensions = list(leaf.extensions)
    eku = next((x.value for x in extensions if x.oid == ExtensionOID.EXTENDED_KEY_USAGE), [])
    if ExtendedKeyUsageOID.CODE_SIGNING not in eku:
        raise ValueError("is signed with a certificate not issued for code signing")
    unread = [
        x for x in parsed.unhandled_critical if x != ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string
    ]
    if unread:
        raise ValueError(
            f"is signed with a certificate whose extension {unread[0]} is critical, which nothing here reads"
        )

    try:
        root = TrustedRoot(
            trustroot_v1.TrustedRoot.from_json(json.dumps(trusted_root or SIGSTORE_TRUSTED_ROOT))
        )
        Verifier(trusted_root=root).verify_artifact(files.statement, Bundle(inner), _Identity())
    except Exception as e:
        raise ValueError(f"doesn't verify: {e}") from None

    san = _san(leaf)
    if san != f"URI:{SIGNER}":
        raise ValueError(f"was signed as {san}, not Morse's pins workflow")
    values: dict[int, list[bytes]] = {}
    for x in extensions:
        oid = x.oid.dotted_string
        if not oid.startswith(FULCIO) or len(oid.split(".")) != 9:
            continue
        raw = x.value.value if isinstance(x.value, x509.UnrecognizedExtension) else x.value.public_bytes()
        values.setdefault(int(oid[len(FULCIO) :]), []).append(raw)

    def extension(n: int) -> str:
        found = values.get(n, [])
        text = _utf8_string(found[0]) if len(found) == 1 else None
        if text is None:
            raise ValueError(f"has a certificate with no single UTF8String {FULCIO}{n}")
        return text

    for n, want in EXPECTED.items():
        if extension(n) != want:
            raise ValueError(f"has a certificate whose {FULCIO}{n} is {extension(n)}, not {want}")
    raw_issuer = values.get(1)
    if raw_issuer is not None and (len(raw_issuer) != 1 or raw_issuer[0] != ISSUER.encode()):
        raise ValueError(f"has a certificate whose {FULCIO}1 is another issuer")
    if extension(20) not in TRIGGERS:
        raise ValueError(f"was signed by a run started by {extension(20)}")
    if not RUN.fullmatch(extension(21)):
        raise ValueError(f"was signed by {extension(21)}, not a first-attempt run of Watermark-Labs/pins")
    commit = extension(13)
    if extension(19) != commit:
        raise ValueError(f"was signed by a workflow at {extension(19)}, not the source commit {commit}")

    st = read_statement(files.statement)
    if st["pins_commit"] != commit:
        raise ValueError(
            f"names pins commit {st['pins_commit']}, but its certificate was issued for {commit}"
        )

    integrated_time = int(entry.integrated_time) * 1000
    if now_ms - integrated_time > MAX_AGE_MS:
        raise ValueError(
            f"was logged {_ago(now_ms - integrated_time)} ago, and the check refuses a list more than 7 days old"
        )
    if integrated_time - now_ms > MAX_AHEAD_MS:
        raise ValueError(f"was logged {_ago(integrated_time - now_ms)} ahead of this machine's clock")
    return SignedList(
        sequence=int(st["sequence"]),
        time=st["time"],
        pins_commit=st["pins_commit"],
        log_index=str(entry.log_index),
        integrated_time=integrated_time,
        images=tuple(ListedImage(Pcrs(i["pcr0"], i["pcr1"], i["pcr2"]), i["revoked"]) for i in st["images"]),
    )
