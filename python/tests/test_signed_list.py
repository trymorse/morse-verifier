# Morse's signed list: sigstore-python's verification and Morse's rules after it
# (src/node/signed_list.test.ts), on list 290 as GitHub served it and on Morse's 40 forgeries.
from __future__ import annotations

import base64
import copy
import json
import re

import pytest
from der import ECDSA_SHA256, with_extensions, with_outer_algorithm
from world import BUNDLE, NOW, STATEMENT, TAG, TESTDATA, ms

from trymorse_verify.signed_list import (
    SIGSTORE_TRUSTED_ROOT,
    SignedListFiles,
    read_statement,
    verify_signed_list,
)

MINUTE = 60_000
DAY = 24 * 60 * MINUTE
LOGGED = ms("2026-11-06T09:52:18Z")


def bundle() -> dict:
    return json.loads(BUNDLE)


def list290(statement: bytes = STATEMENT, b: object = "default") -> SignedListFiles:
    return SignedListFiles(TAG, statement, bundle() if b == "default" else b)


def entry(b: dict) -> dict:
    return b["verificationMaterial"]["tlogEntries"][0]


def edited(edit) -> SignedListFiles:
    b = bundle()
    edit(b)
    return list290(b=b)


class TestList290:
    def test_verifies_offline_under_sigstores_public_root_and_lists_45_prod_images_4_revoked(self):
        signed = verify_signed_list(list290(), NOW)
        assert (
            signed.sequence,
            signed.time,
            signed.pins_commit,
            signed.log_index,
            signed.integrated_time,
        ) == (
            290,
            "2026-11-06T09:51:52Z",
            "a772f3906ac4c0fa611522207db19083b6049ba4",
            "3714441255",
            LOGGED,
        )
        assert len(signed.images) == 45
        assert len([i for i in signed.images if i.revoked]) == 4

    @pytest.mark.parametrize("now", [LOGGED - 5 * MINUTE, LOGGED + 7 * DAY])
    def test_is_accepted_from_5_minutes_before_rekor_logged_it_to_7_days_after(self, now):
        assert verify_signed_list(list290(), now).sequence == 290

    @pytest.mark.parametrize(
        "now, reason",
        [
            (
                LOGGED + 7 * DAY + MINUTE,
                "logged 7 days ago, and the check refuses a list more than 7 days old",
            ),
            (LOGGED - 6 * MINUTE, "logged 6 min ahead of this machine's clock"),
        ],
    )
    def test_is_refused_too_old_or_ahead(self, now, reason):
        with pytest.raises(ValueError, match=re.escape(reason)):
            verify_signed_list(list290(), now)

    def test_is_refused_with_one_byte_of_the_statement_changed(self):
        statement = bytearray(STATEMENT)
        statement[statement.index(b"f")] = ord("F")
        with pytest.raises(ValueError, match="names a digest other than the statement's SHA-256"):
            verify_signed_list(list290(bytes(statement)), NOW)

    @pytest.mark.parametrize(
        "field, reason",
        [
            (
                "inclusionProof",
                r"^is not a Sigstore bundle: invalid bundle \(verificationMaterial\.tlogEntries\[0\]\.inclusionProof\)$",
            ),
            ("inclusionPromise", "^lacks Rekor's signed entry timestamp or its inclusion proof"),
        ],
    )
    def test_is_refused_when_its_log_entry_lacks_its_proof_or_promise(self, field, reason):
        with pytest.raises(ValueError, match=reason):
            verify_signed_list(edited(lambda b: entry(b).pop(field)), NOW)

    def test_is_refused_logged_twice_logged_in_rekor_v2_or_not_as_a_bundle(self):
        with pytest.raises(ValueError, match="has 2 log entries, not one"):
            verify_signed_list(
                edited(lambda b: b["verificationMaterial"]["tlogEntries"].append(entry(b))), NOW
            )
        with pytest.raises(ValueError, match="is logged as hashedrekord 0.0.2, not hashedrekord 0.0.1"):
            verify_signed_list(edited(lambda b: entry(b)["kindVersion"].update(version="0.0.2")), NOW)
        with pytest.raises(ValueError, match="^is not a Sigstore bundle"):
            verify_signed_list(list290(b=None), NOW)

    def test_is_refused_under_another_root(self):
        forged = json.loads((TESTDATA / "pinsig_forged.json").read_text("utf-8"))
        with pytest.raises(ValueError, match="^doesn't verify: "):
            verify_signed_list(list290(), NOW, forged["trusted_root"])


class TestReadStatement:
    text = STATEMENT.decode()

    def test_reads_list_290s_statement(self):
        st = read_statement(STATEMENT)
        assert (st["sequence"], st["time"]) == (290, "2026-11-06T09:51:52Z")

    def test_refuses_it_after_a_byte_order_mark_which_isnt_json(self):
        with pytest.raises(ValueError, match="^is not JSON$"):
            read_statement(b"\xef\xbb\xbf" + STATEMENT)

    @pytest.mark.parametrize(
        "time", ["2026-11-06", "2026-11-06 09:51:52Z", "2026-11-06T09:51:52", "yesterday"]
    )
    def test_refuses_a_time_that_is_not_rfc_3339(self, time):
        with pytest.raises(ValueError, match="^is not a prod pins statement: time: "):
            read_statement(self.text.replace("2026-11-06T09:51:52Z", time).encode())

    def test_accepts_a_fraction_and_an_offset_as_zod_does(self):
        read_statement(self.text.replace("09:51:52Z", "09:51:52.123+01:00").encode())

    # The words zod gives each, in the TypeScript port.
    @pytest.mark.parametrize(
        "edit, reason",
        [
            (('"sequence":290', '"sequence":0'), "sequence: Too small: expected number to be >0"),
            (
                ('"sequence":290', '"sequence":9007199254740992'),
                "sequence: Too big: expected int to be <=9007199254740991",
            ),
            (
                ('"sequence":290', '"sequence":100000000000000000000'),
                "sequence: Too big: expected int to be <=9007199254740991",
            ),
            (
                ('"sequence":290', '"sequence":-9007199254740992'),
                "sequence: Too small: expected int to be >=-9007199254740991",
            ),
            (('"sequence":290', '"sequence":2.5'), "sequence: Invalid input: expected int, received number"),
            (
                ('"sequence":290', '"sequence":"290"'),
                "sequence: Invalid input: expected number, received string",
            ),
            (('"environment":"prod"', '"environment":"dev"'), 'environment: Invalid input: expected "prod"'),
            (
                ('"type":"morse-enclave-pins-v1"}', '"type":"morse-enclave-pins-v1","zz":1,"zzz":2}'),
                'it: Unrecognized keys: "zz", "zzz"',
            ),
        ],
    )
    def test_names_the_first_thing_wrong_as_zod_does(self, edit, reason):
        with pytest.raises(ValueError, match=f"^is not a prod pins statement: {re.escape(reason)}$"):
            read_statement(self.text.replace(*edit).encode())

    def test_reads_the_largest_safe_integer(self):
        st = read_statement(self.text.replace('"sequence":290', '"sequence":9007199254740991').encode())
        assert st["sequence"] == 2**53 - 1

    # JSON.stringify writes a number past a double's range, which JSON.parse reads as Infinity, as
    # null; Python's int() refuses an integer of more than 4300 digits.
    @pytest.mark.parametrize(
        "number", ["290.0", "2.9e2", "1e300", "12345678901234567890", "1e400", "-1e400", "9" * 5000]
    )
    def test_refuses_a_number_javascript_would_write_otherwise(self, number):
        with pytest.raises(ValueError, match="^is not in canonical form"):
            read_statement(self.text.replace('"sequence":290', f'"sequence":{number}').encode())

    def test_refuses_nan_which_json_parse_does(self):
        with pytest.raises(ValueError, match="^is not JSON$"):
            read_statement(self.text.replace('"sequence":290', '"sequence":NaN').encode())


FORGED = json.loads((TESTDATA / "pinsig_forged.json").read_text("utf-8"))
AT = ms("2026-10-28T12:05:00Z")


@pytest.fixture
def no_ct_log(monkeypatch):
    """Morse's forged root has no CT log, as the TS tests' ctlogThreshold 0 says: sigstore-python
    checks a certificate's SCT against the root's CT keys unconditionally, so the forgeries skip
    that one check here. Every other check of sigstore-python's runs."""
    import sigstore.verify.verifier as verifier
    from sigstore.models import TrustedRoot

    monkeypatch.setattr(verifier, "verify_sct", lambda *a, **k: None)
    monkeypatch.setattr(TrustedRoot, "ct_keyring", lambda self, purpose: None)


def forged_check(c: dict):
    return verify_signed_list(
        SignedListFiles("forged", FORGED["statements"][c["statement"]].encode(), c["bundle"]),
        AT,
        FORGED["trusted_root"],
    )


FIELD = r"1\.3\.6\.1\.4\.1\.57264\.1\."


def ext(n: int, value: str) -> str:
    return rf"^has a certificate whose {FIELD}{n} is {value}, not "


# Why each is refused, so that one fault refusing them all, such as a clock or a trust root that
# slipped, fails here. Morse's rules give the TS words; sigstore-python's refusals carry its own.
REASONS = {
    "issuer": ext(8, r"https://accounts\.google\.com"),
    "build-signer": r"^was signed as URI:\S+/check\.yml@refs/heads/main, not Morse's pins workflow$",
    "san-only": r"^was signed as URI:\S+/check\.yml@refs/heads/main, not Morse's pins workflow$",
    "source-repository-uri": ext(12, r"https://github\.com/Watermark-Labs/pins-fork"),
    "repository-id": ext(15, "1"),
    "owner-id": ext(17, "1"),
    "ref": ext(14, "refs/heads/feature"),
    "trigger": r"^was signed by a run started by workflow_dispatch$",
    "runner": ext(11, "self-hosted"),
    "no-trigger-extension": rf"^has a certificate with no single UTF8String {FIELD}20$",
    "build-config-uri": ext(18, r"\S+/other\.yml@refs/heads/main"),
    "build-config-digest": r"^was signed by a workflow at (ab){20}, not the source commit [0-9a-f]{40}$",
    "run-attempt-2": r"^was signed by \S+/actions/runs/\d+/attempts/2, not a first-attempt run of Watermark-Labs/pins$",
    "run-other-repository": r"^was signed by https://github\.com/Watermark-Labs/pins-fork/actions/runs/1/attempts/1, not a first-attempt run of Watermark-Labs/pins$",
    # cryptography 47, the floor pyproject.toml declares, words it "certificate has expired".
    "expired": r"^doesn't verify: failed to build timestamp certificate chain: (validation failed: cert is not valid at validation time|certificate has expired)",
    "critical-extension": r"^is signed with a certificate whose extension 1\.3\.6\.1\.4\.1\.57264\.99 is critical, which nothing here reads$",
    "no-eku": r"^is signed with a certificate not issued for code signing$",
    "signature": r"^doesn't verify: Signature is invalid for input$",
    "body-digest": r"^doesn't verify: transparency log entry is inconsistent with other materials$",
    "body-signature": r"^doesn't verify: transparency log entry is inconsistent with other materials$",
    "body-certificate": r"^is logged with another certificate than it carries$",
    "set": r"^doesn't verify: invalid log entry: SET: invalid inclusion promise: keyring: invalid signature$",
    "inclusion": r"^doesn't verify: invalid log entry: inclusion proof contains invalid root hash",
    "checkpoint-other-tree": r"^doesn't verify: invalid log entry: .*Inclusion proof contains invalid root hash signature",
    "unknown-log": r"^doesn't verify: invalid log entry: checkpoint: Signature not found for log ID [0-9a-f]{64}$",
    "two-entries": r"^has 2 log entries, not one$",
    "dsse": r"^signs a DSSE envelope, not the statement itself$",
    "short-log-id": r"^doesn't verify: invalid log entry: SET: invalid inclusion promise: keyring: invalid signature$",
    "checkpoint-short-hash": r"^doesn't verify: invalid log entry: checkpoint: invalid signature: keyring: invalid signature$",
    "checkpoint-two-signatures": r"^carries a checkpoint signed other than once$",
    "deprecated-issuer": rf"^has a certificate whose {FIELD}1 is another issuer$",
    "no-promise": r"^lacks Rekor's signed entry timestamp or its inclusion proof",
    "no-proof": r"^is not a Sigstore bundle: invalid bundle \(verificationMaterial\.tlogEntries\[0\]\.inclusionProof\)$",
    "statement-non-canonical": r"^is not in canonical form \(JCS\), as Morse signs it$",
    "statement-type": r"^is not a prod pins statement: type: ",
    "statement-commit": r"^names pins commit (ab){20}, but its certificate was issued for [0-9a-f]{40}$",
    "statement-folded-key": r'^is not a prod pins statement: it: Unrecognized key: "ſequence"$',
    "statement-null-revoked": r"^is not a prod pins statement: images\.0\.revoked: ",
    "statement-no-images": r"^is not a prod pins statement: images: Too small",
}


class TestMorsesForgedBundles:
    """Morse's own forgeries, from morse-server's internal/pinsig: each changes one thing of a valid
    bundle signed under a test CA and Rekor key, and the Go verifier refuses every one but "valid".
    The statement-* cases sign a bad statement, so the bundle verifies and the statement is refused."""

    def test_has_all_40(self):
        assert len(FORGED["cases"]) == 40

    def test_accepts_the_valid_one(self, no_ct_log):
        valid = next(c for c in FORGED["cases"] if c["name"] == "valid")
        assert forged_check(valid).sequence == 101

    def test_has_a_reason_for_each_forgery(self):
        assert sorted(REASONS) == sorted(c["name"] for c in FORGED["cases"] if c["error"])

    @pytest.mark.parametrize(
        "c", [c for c in FORGED["cases"] if c["error"]], ids=lambda c: f"{c['name']} (Go: {c['error']})"
    )
    def test_refuses(self, c, no_ct_log):
        with pytest.raises(ValueError, match=REASONS[c["name"]]):
            forged_check(c)

    def test_refuses_a_checkpoint_with_two_signature_lines_a_blank_line_apart(self, no_ct_log):
        valid = next(c for c in FORGED["cases"] if c["name"] == "valid")
        b = copy.deepcopy(valid["bundle"])
        checkpoint = entry(b)["inclusionProof"]["checkpoint"]
        _, signature = checkpoint["envelope"].split("\n\n")
        checkpoint["envelope"] += "\n" + signature
        with pytest.raises(ValueError, match="^carries a checkpoint signed other than once$"):
            forged_check({**valid, "bundle": b})

    def test_reads_only_each_fields_json_name_as_typescript_does(self, no_ct_log):
        """sigstore-python's models also read a field's proto name, such as media_type; TS leaves
        it out as an unknown key, so a bundle in proto names is no bundle to either."""

        def snake(v):
            if isinstance(v, dict):
                return {re.sub("([A-Z])", lambda m: "_" + m[1].lower(), k): snake(x) for k, x in v.items()}
            return [snake(x) for x in v] if isinstance(v, list) else v

        valid = next(c for c in FORGED["cases"] if c["name"] == "valid")
        with pytest.raises(ValueError, match=r"^is not a Sigstore bundle: invalid bundle \(mediaType, "):
            forged_check({**valid, "bundle": snake(valid["bundle"])})

    def test_refuses_the_valid_one_without_the_ct_log_it_lacks(self):
        valid = next(c for c in FORGED["cases"] if c["name"] == "valid")
        with pytest.raises(ValueError, match="^doesn't verify: CTFE keys not found in trusted root$"):
            forged_check(valid)


def with_leaf(edit) -> dict:
    """List 290's bundle with its Fulcio certificate edited, in the bundle and in its log entry."""
    b = bundle()
    cert = b["verificationMaterial"]["certificate"]
    der = edit(base64.b64decode(cert["rawBytes"]))
    cert["rawBytes"] = base64.b64encode(der).decode()
    body = json.loads(base64.b64decode(entry(b)["canonicalizedBody"]))
    pem = b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"
    body["spec"]["signature"]["publicKey"]["content"] = base64.b64encode(pem).decode()
    entry(b)["canonicalizedBody"] = base64.b64encode(json.dumps(body).encode()).decode()
    return b


class TestTheFulcioCertificate:
    """Read by x509.ts's rules, as src/node/signed_list.ts reads it, before sigstore-python."""

    def test_is_refused_when_it_repeats_an_extension(self):
        b = with_leaf(lambda der: with_extensions(der, lambda exts: [*exts, exts[-1]]))
        with pytest.raises(
            ValueError,
            match=r"^is signed with a certificate that Duplicate 1\.3\.6\.1\.4\.1\.11129\.2\.4\.2 extension found$",
        ):
            verify_signed_list(list290(b=b), NOW)

    def test_is_refused_when_its_outer_algorithm_is_another(self):
        b = with_leaf(lambda der: with_outer_algorithm(der, ECDSA_SHA256))
        with pytest.raises(
            ValueError,
            match="^is signed with a certificate that the certificate's two signature algorithms differ$",
        ):
            verify_signed_list(list290(b=b), NOW)


def test_the_embedded_sigstore_root_is_the_typescript_ports():
    """src/node/sigstore_root.ts holds the root as a TypeScript object literal: quote its keys and
    drop its trailing commas, and it is JSON to compare with sigstore_root.json."""
    source = (TESTDATA.parent / "node" / "sigstore_root.ts").read_text("utf-8")
    literal = source.split("export const SIGSTORE_TRUSTED_ROOT = ", 1)[1].strip().removesuffix(";")
    literal = re.sub(r"^(\s*)([A-Za-z_]\w*):", r'\1"\2":', literal, flags=re.M)
    literal = re.sub(r",(\s*[}\]])", r"\1", literal)
    assert json.loads(literal) == SIGSTORE_TRUSTED_ROOT
    assert SIGSTORE_TRUSTED_ROOT["mediaType"] == "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
