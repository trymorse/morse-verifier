# verify(): runs the checks the CLI prints, in order, and decides what each prints, as
# src/node/verify.ts does. The comment above each step says what it proves. A document's rules are
# in nitro.py and the list's in signed_list.py; signed_list.py, source.py, rebuild.py, and tls.py
# say how to run each by hand.
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import shutil
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

from . import cbor
from .io import Exec, Unfinished, cause_of, default_client, get, mkdtemp, temp_dir
from .io import exec as run_program
from .io import json as read_json
from .nitro import (
    NITRO_ROOT,
    AttestedDocument,
    Cert,
    Pcrs,
    Pin,
    all_zero,
    js_round,
    same_pcrs,
    verify_nitro_document,
)
from .rebuild import rebuild as rebuild_commit
from .signed_list import SignedList, fetch_signed_list, verify_signed_list
from .source import REPO, Release, find_release, read_releases
from .tls import ServedKey, served_key

ENVIRONMENT = "prod"
MODULE_ID = re.compile(r"[A-Za-z0-9-]{1,64}")
BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


@dataclass(frozen=True)
class Step:
    label: str
    # "info" informs and decides nothing: an image's PCRs, what --rebuild is about to run, and TLS.
    status: str  # "passed" | "failed" | "unfinished" | "not run" | "info"
    lines: list[str]


@dataclass(frozen=True)
class Enclave:
    # Hex of the first 8 bytes of the SHA-256 of its HPKE key, which requests are sealed to.
    key_id: str
    public_key: str
    issued_at: int
    module_id: str | None


@dataclass
class Image:
    pcrs: Pcrs
    # The enclaves whose documents attest these PCRs, by key. A key two images' documents name is
    # in both.
    enclaves: list[Enclave] = field(default_factory=list)
    # The commit on main whose message names these PCRs: the one --release pins, or else the newest.
    release: Release | None = None
    rebuilt: bool = False


@dataclass(frozen=True)
class Report:
    host: str
    # 0: every check passed. 1: a check failed; send nothing. 2: it could not finish; nothing is proven.
    exit_code: int
    steps: list[Step]
    # The closing lines: the verdict, and on a pass the --release pin to copy.
    verdict: list[str]
    images: list[Image]
    list: SignedList | None


@dataclass(frozen=True)
class Refused:
    """A document steps 1 or 2 refused, and why. `public_key` (hex) is the key it names, read
    unchecked, so a caller can refuse that key though another document of it passed."""

    label: str  # "Attestation" | "Allowed"
    reason: str
    public_key: str | None


Checked = AttestedDocument | Refused


class Failed(Exception):
    """A check refused what it was shown: exit 1."""

    def __init__(self, label: str, *lines: str):
        super().__init__(" ".join(lines))
        self.label = label
        self.lines = list(lines)


def short(h: str) -> str:
    return f"{h[:12]}…{h[-8:]}"


def pcr_lines(p: Pcrs) -> list[str]:
    return [f"PCR0 {short(p.pcr0)}", f"PCR1 {short(p.pcr1)}", f"PCR2 {short(p.pcr2)}"]


def joined(items: Sequence[str]) -> str:
    """ "a", "a and b", or "a, b, and c"."""
    if len(items) < 3:
        return " and ".join(items)
    return f"{', '.join(items[:-1])}, and {items[-1]}"


def ago(ms: int) -> str:
    minutes = js_round(ms / 60_000)
    if minutes < 0:
        return f"{-minutes} min ahead of this machine's clock"
    if minutes == 0:
        return "just now"
    if minutes < 120:
        return f"{minutes} min ago"
    hours = js_round(minutes / 60)
    return f"{hours} h ago" if hours < 48 else f"{js_round(hours / 24)} days ago"


def _date(value: str) -> float | None:
    """A date as JavaScript's Date.parse reads the ones a server sends, in seconds: an HTTP date,
    whose -0000 is UTC, or ISO 8601, whose date alone is UTC and whose time with no offset is
    this machine's. V8 reads more, such as "1.5" as a day in 2001; those are None here."""
    try:
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value, re.ASCII):
            return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T.+", value, re.ASCII):
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        t = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if t.tzinfo is None and value.rstrip().endswith("-0000"):
        t = t.replace(tzinfo=timezone.utc)
    return t.timestamp()


def retry_after(value: str | None, now_ms: int) -> float:
    """Seconds a 429's Retry-After asks for, at most 60."""
    seconds: float | None
    if value is not None and re.fullmatch(r"[0-9]+", value, re.ASCII):
        seconds = float(value)
    else:
        at = _date(value or "")
        seconds = None if at is None else at - now_ms / 1000
    return min(max(seconds, 1) if seconds is not None else 5, 60)


def from_base64(text: str) -> bytes | None:
    """Padded standard base64's bytes, or None for anything else."""
    if not BASE64.fullmatch(text):
        return None
    try:
        return base64.b64decode(text)
    except binascii.Error:
        return None


@dataclass(frozen=True)
class _Seen:
    module_id: str | None = None
    public_key: str | None = None
    pcrs: Pcrs | None = None


def peek(document: bytes | None) -> _Seen:
    """The module_id, key, and PCRs a document names, read without checking it, to name it in a
    refusal. The key is the last 32 bytes of its user_data, where a valid document's key is. A
    module_id is kept only in the letters, digits, and dashes AWS writes one in, since it is
    unsigned here; without it the refusal names the document by its place in the list."""
    try:
        sign1 = cbor.decode(document)  # type: ignore[arg-type]
        if isinstance(sign1, cbor.Tag):
            sign1 = sign1.value
        payload = cbor.decode(sign1[2])  # type: ignore[index]
        pcrs = payload["pcrs"]  # type: ignore[index]
        module_id = payload.get("module_id")  # type: ignore[union-attr]
        user_data = payload.get("user_data")  # type: ignore[union-attr]
        return _Seen(
            module_id=module_id if isinstance(module_id, str) and MODULE_ID.fullmatch(module_id) else None,
            public_key=user_data[-32:].hex()
            if isinstance(user_data, bytes) and len(user_data) >= 32
            else None,
            pcrs=Pcrs(pcrs[0].hex(), pcrs[1].hex(), pcrs[2].hex()),
        )
    except Exception:
        return _Seen()


def refused_by(signed: SignedList, pcrs: Pcrs) -> str | None:
    """Why the list does not allow these PCRs, or None if it lists them and no entry for them is
    revoked."""
    entries = [i for i in signed.images if same_pcrs(i.pcrs, pcrs)]
    if not entries:
        return "which is not on Morse's signed list"
    if any(i.revoked for i in entries):
        return "which is on Morse's signed list, but Morse revoked it"
    return None


def pins_of(signed: SignedList) -> list[Pin]:
    """The list's images as pins, revoked ones first, so a revoked entry wins over a copy."""
    pins = [Pin(f"on list {signed.sequence}", ENVIRONMENT, i.pcrs, i.revoked) for i in signed.images]
    return sorted(pins, key=lambda p: not p.revoked)


def runs(releases: list[Release], pcrs: Pcrs) -> str:
    """The release on main whose PCRs an image's are, as --release's refusal names it."""
    r = next((r for r in releases if same_pcrs(r.pcrs, pcrs)), None)
    return r.name if r else f"PCR0 {short(pcrs.pcr0)}, which no commit on main names"


def unpublished(pcrs: Pcrs) -> str:
    """Step 3's refusal of an image no release on main names."""
    return f"no commit on main of {REPO} names PCR0 {short(pcrs.pcr0)}: its source isn't published. If Morse is mid-deploy it appears within minutes; run again. Until then, don't send it anything."


def check_document(instance: str, who: str, signed: SignedList | None, root: Cert, at: int) -> Checked:
    """Steps 1 and 2 for one document, base64, at `at` by this machine's clock: AWS Nitro signed
    it under `root`, it is fresh, it names a prod key, and `signed` allows its PCRs. `who` names
    it in a refusal when it has no module_id."""
    document = from_base64(instance)
    seen = peek(document)
    name = f"enclave {seen.module_id}" if seen.module_id else who
    passed: list[str] = []
    try:
        if document is None:
            raise ValueError("the document is not base64")
        pins = pins_of(signed) if signed else []
        return verify_nitro_document(document, ENVIRONMENT, pins, root, at, passed.append)
    except Exception as e:
        reason = str(e)
        # The first step not reported is the one that failed: after "fresh", the PCR test, which is
        # step 1's for a debug enclave's all-zero PCRs and step 2's for the list's lookup.
        if (passed[-1] if passed else None) != "fresh" or (seen.pcrs and all_zero(seen.pcrs)):
            return Refused("Attestation", f"{name}: {reason}", seen.public_key)
        if signed and seen.pcrs:
            why = refused_by(signed, seen.pcrs) or reason
            return Refused("Allowed", f"{name} runs PCR0 {short(seen.pcrs.pcr0)}, {why}", seen.public_key)
        return Refused("Allowed", f"{name}: {reason}", seen.public_key)


def _now() -> int:
    return int(time.time() * 1000)


def verify(
    host: str = "api.trymorse.ai",
    *,
    release: str | None = None,
    rebuild: bool = False,
    on_step: Callable[[Step], None] | None = None,
    now: Callable[[], int] = _now,
    client: httpx.Client | None = None,
    exec: Exec = run_program,
    tls: Callable[[str], ServedKey] = served_key,
    sleep: Callable[[float], None] = time.sleep,
    root: Cert = NITRO_ROOT,
) -> Report:
    """Runs every check the CLI prints against `host` and returns what each decided. `now` is the
    clock in ms: documents and the signed list are judged by it, never by the host's. `client`,
    `exec`, `tls`, and `sleep` are what the checks reach the world with; tests replace them, and
    `root`, the root AWS Nitro documents must chain to, with forged documents."""
    steps: list[Step] = []
    images: list[Image] = []
    signed: SignedList | None = None
    passed = ""

    def emit(label: str, status: str, lines: list[str]) -> None:
        nonlocal passed
        step = Step(label, status, lines)
        steps.append(step)
        if status == "passed":
            passed = label
        if on_step:
            on_step(step)

    def report(exit_code: int, verdict: list[str]) -> Report:
        return Report(host, exit_code, steps, verdict, images, signed)

    http = client or default_client()
    dir: str | None = None
    try:
        dir = temp_dir("trymorse-verify-")
        clone = os.path.join(dir, "enclave.git")
        # 1. Attestation: AWS Nitro signed a document for each enclave the host lists, under 30
        # minutes ago by this machine's clock, naming the PCRs of the image it booted, not all zero
        # (debug mode), and the prod key it seals to. Only the PCRs' lookup is step 2's: the images
        # Morse's signed list allows.
        url = f"https://{host}/v1/attestation"
        got = get(http, url)
        if got.status == 429:
            sleep(retry_after(got.headers.get("retry-after"), now()))
            got = get(http, url)
        if got.status == 429:
            raise Unfinished(
                f"{host} is rate-limiting this address (60 requests a minute). Run again in a minute"
            )
        if got.status != 200:
            raise Unfinished(f"{url} answered {got.status}")
        reply = read_json(got.body)
        if not (
            isinstance(reply, dict)
            and reply.get("object") == "proxy_attestation"
            and isinstance(reply.get("instances"), list)
            and all(isinstance(i, str) for i in reply["instances"])
        ):
            raise Failed("Attestation", f"{url} is not a list of enclaves")
        instances: list[str] = reply["instances"]
        if not instances:
            raise Failed("Attestation", f"{host} lists no enclave")

        files = fetch_signed_list(http)
        list_error = ""
        try:
            signed = verify_signed_list(files, now())
        except Exception as e:  # any error in the list refuses it, as in TS
            list_error = str(e)

        at = now()
        checked = [
            check_document(instance, f"document {i + 1} of {len(instances)}", signed, root, at)
            for i, instance in enumerate(instances)
        ]
        for c in checked:
            if isinstance(c, Refused) and c.label == "Attestation":
                raise Failed(c.label, c.reason)
        if signed is None:
            raise Failed("Allowed", f"Morse's signed list {files.tag} {list_error}")
        for c in checked:
            if isinstance(c, Refused):
                raise Failed(c.label, c.reason)

        # Every document that passed goes through each check below at its own PCRs, in images by
        # PCRs. Keys only count and name the enclaves, each at its newest document, newest first.
        docs = sorted(
            (c for c in checked if isinstance(c, AttestedDocument)),
            key=lambda d: d.issued_at,
            reverse=True,
        )
        keys: dict[str, tuple[int, list[int]]] = {}
        for doc in docs:
            n = next((j for j, im in enumerate(images) if same_pcrs(im.pcrs, doc.pcrs)), -1)
            if n < 0:
                images.append(Image(doc.pcrs))
                n = len(images) - 1
            key_id = doc.key_id.hex()
            if not any(e.key_id == key_id for e in images[n].enclaves):
                images[n].enclaves.append(Enclave(key_id, doc.public_key.hex(), doc.issued_at, doc.module_id))
            issued_at, of = keys.setdefault(key_id, (doc.issued_at, []))
            if n + 1 not in of:
                of.append(n + 1)
        several = len(images) > 1
        root_hash = hashlib.sha256(root.der).hexdigest()

        def key_line(key_id: str, issued_at: int, of: list[int]) -> str:
            line = f"key {key_id}, signed {ago(at - issued_at)}"
            if several:
                line += f", image{'s' if len(of) > 1 else ''} {joined([str(i) for i in of])}"
            return line

        emit(
            "Attestation",
            "passed",
            [
                f"{len(keys)} enclave{'s, each' if len(keys) > 1 else ','} signed by AWS Nitro (root {root_hash[:8]}…{root_hash[-8:]})",
                *(key_line(k, issued_at, of) for k, (issued_at, of) in keys.items()),
                *([] if several else pcr_lines(images[0].pcrs)),
            ],
        )

        releases: list[Release] | None = None
        for i, image in enumerate(images):
            if several:
                emit(f"Image {i + 1}", "info", pcr_lines(image.pcrs))

            # 2. Allowed: Morse's CI signed a list of the prod images Morse allows, Rekor logged it
            # in the last 7 days, and it lists these PCRs, unrevoked. Its signer is Morse.
            emit(
                "Allowed",
                "passed",
                [
                    "on Morse's signed list of prod images, not revoked",
                    f"list {signed.sequence}, logged {ago(at - signed.integrated_time)} at Rekor entry {signed.log_index}",
                    f"https://search.sigstore.dev/?logIndex={signed.log_index}",
                ],
            )

            # 3. Source: a commit on main of the public repository names these PCRs as the release
            # it is. That Morse's CI wrote them is all this proves without --rebuild.
            if releases is None:
                releases = read_releases(exec, clone)
            named = [r for r in releases if same_pcrs(r.pcrs, image.pcrs)]
            if not named:
                raise Failed("Source", unpublished(image.pcrs))
            image.release, also = named[0], named[1:]
            emit(
                "Source",
                "passed",
                [
                    f"{image.release.name}, commit {image.release.commit[:12]} on main of {REPO}, names these PCRs",
                    *([f"and so do {joined([r.name for r in also])}"] if also else []),
                ],
            )

            # --release: every enclave runs the release named, by its PCRs.
            if release is not None and i == 0:
                wanted = find_release(releases, release)
                if wanted is None:
                    raise Unfinished(
                        f"no release {release} on main of {REPO}; see https://{REPO}/commits/main"
                    )
                if not all(same_pcrs(im.pcrs, wanted.pcrs) for im in images):
                    raise Failed(
                        "Release",
                        f"--release names {wanted.name}, commit {wanted.commit[:12]}, but not every enclave runs it:",
                        *(
                            f"key {e.key_id} runs {runs(releases, im.pcrs)}"
                            for im in images
                            for e in im.enclaves
                        ),
                        "A deploy replaces one enclave at a time, so for a few minutes after one the enclaves run two releases. Run again."
                        if several
                        else "They run another release. Read it, and pin its commit to accept it.",
                    )
                emit(
                    "Release",
                    "passed",
                    [f"every enclave runs {wanted.name}, commit {wanted.commit[:12]}, as --release asks"],
                )
                # Every enclave runs this one image, so the commit pinned is the one to build and name.
                image.release = wanted

            # 4. Rebuild: this machine builds the commit with its own build.sh and gets the
            # attested PCRs.
            if not rebuild:
                emit(
                    "Rebuild",
                    "not run",
                    [
                        "not run. These PCRs are the ones Morse's CI wrote in that commit.",
                        "Run with --rebuild to build it here and compare (Docker, ~2 min).",
                    ],
                )
                continue
            try:
                rebuilt = rebuild_commit(
                    exec,
                    clone,
                    image.release.commit,
                    mkdtemp(os.path.join(dir, f"{i + 1}-")),
                    lambda lines: emit("Rebuild", "info", lines),
                )
            except Unfinished as e:
                if e.lines:
                    emit("Rebuild", "unfinished", list(e.lines))
                raise
            if not same_pcrs(rebuilt, image.pcrs):
                raise Failed(
                    "Rebuild",
                    f"commit {image.release.commit[:12]} rebuilds here to other PCRs than the enclaves attest:",
                    *pcr_lines(rebuilt),
                )
            image.rebuilt = True
            emit("Rebuild", "passed", ["rebuilt here: PCR0, PCR1, and PCR2 match"])

        # 5. TLS, which informs and never fails: whether this machine's own connection to the host
        # ended inside an enclave, at a key a document that passed every check above attests.
        served: ServedKey | None = None
        tls_error = ""
        try:
            served = tls(host)
        except Exception as e:
            tls_error = cause_of(e)
        attested = [hashlib.sha256(d.tls_key).hexdigest() for d in docs if d.tls_key]
        if served is None:
            line = (
                f"could not connect to {host}:443 ({tls_error}), so this says nothing of where its TLS ends."
            )
        elif served.spki_sha256 in attested:
            line = (
                f"this connection to {host} ended inside an attested enclave (key {served.spki_sha256[:16]})"
            )
        else:
            line = f"{host}'s TLS key {served.spki_sha256[:16]} (issuer {served.issuer}) is in no attestation document, so TLS ends before the enclave. Morse's relay can read requests on it unless they're sealed."
        emit("TLS", "info", [line])

        names = joined([im.release.name if im.release else "" for im in images])
        how = (
            f"which {'rebuild' if several else 'rebuilds'} here to the same PCRs."
            if rebuild
            else "as published (not rebuilt here)."
        )
        verdict = [f"Passed. The enclaves {host} lists run {names} of {REPO}, {how}"]
        if not several and images[0].release:
            verdict.append(f"Pin this release in CI: --release {images[0].release.commit}")
        return report(0, verdict)
    except Failed as e:
        emit(e.label, "failed", [f"FAILED: {e.lines[0]}", *e.lines[1:]])
        return report(1, [f"Failed at {e.label}. Don't send anything to these enclaves."])
    except Exception as e:
        reason = str(e)
        checked_to = f"Nothing was checked past {passed}." if passed else "Nothing was checked."
        return report(2, [f"Could not finish: {reason}. {checked_to}"])
    finally:
        # A temporary directory left behind, such as one a build filled with root's files, fails
        # nothing.
        if dir:
            shutil.rmtree(dir, ignore_errors=True)
        if client is None:
            http.close()
