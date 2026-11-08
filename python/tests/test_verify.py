# verify() on the captures from 2026-11-06, one part changed at a time (src/node/verify.test.ts).
from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import re
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from forge import forge_nitro
from world import (
    ATTESTATION,
    BUNDLE,
    LIVE,
    LIVE_COMMIT,
    LOG,
    MINUTE,
    NOW,
    STATEMENT,
    TAG,
    World,
    fake,
    live_instances,
    ms,
    read,
    reply,
)

from trymorse_verify.io import TimedOut
from trymorse_verify.nitro import Pcrs, same_pcrs
from trymorse_verify.source import parse_log
from trymorse_verify.tls import ServedKey
from trymorse_verify.verify import Report, verify


def check(world: World | None = None, **o) -> Report:
    return verify(**{**fake(world).options, **o})


def last(r: Report):
    return r.steps[-1]


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def x25519_public() -> bytes:
    return X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def statement_images() -> list[dict]:
    return json.loads(STATEMENT)["images"]


REVOKED = next(Pcrs(i["pcr0"], i["pcr1"], i["pcr2"]) for i in statement_images() if i["revoked"])
OLDER = parse_log(LOG)[1]


class TestCaptures:
    def test_passes_every_check_and_pins_the_commit_both_enclaves_run(self):
        r = check()
        assert r.exit_code == 0
        assert [(s.label, s.status) for s in r.steps] == [
            ("Attestation", "passed"),
            ("Allowed", "passed"),
            ("Source", "passed"),
            ("Rebuild", "not run"),
            ("TLS", "info"),
        ]
        assert len(r.images) == 1
        image = r.images[0]
        assert image.pcrs == LIVE and not image.rebuilt
        assert (image.release.name, image.release.commit) == ("v2026.11.4-pins-23c1570", LIVE_COMMIT)
        assert [e.module_id for e in image.enclaves] == [
            "i-0d45a659f78879f74-enc01a1aff4a42aa553",
            "i-015c22f85232d8af3-enc01a1aff39c639a81",
        ]
        assert (r.list.sequence, r.list.log_index) == (290, "3714441255")

    def test_could_not_finish_when_it_cant_make_its_temporary_directory(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", "/proc/nope")
        r = check()
        assert r.exit_code == 2
        assert r.verdict == [
            "Could not finish: it can't make a temporary directory in /proc/nope (ENOENT). Set TMPDIR to a directory it can write, and run again. Nothing was checked."
        ]

    def test_reaches_only_the_host_morse_pins_latest_release_and_git(self):
        world = fake()
        verify(**world.options)
        assert world.fetched == [
            "https://api.trymorse.ai/v1/attestation",
            "https://github.com/trymorse/morse-pins/releases/latest",
            "https://github.com/trymorse/morse-pins/releases/download/signed-290-20261106T095152Z/prod.statement.json",
            "https://github.com/trymorse/morse-pins/releases/download/signed-290-20261106T095152Z/prod.sigstore.json",
        ]
        assert [c[:3] for c in world.ran][0] == ["git", "clone", "--quiet"]
        assert world.ran[1][:2] == ["git", "-C"] and world.ran[1][2].endswith("enclave.git")
        assert len(world.ran) == 2


class TestAttestation:
    def test_fails_a_document_whose_signature_has_one_byte_changed_naming_its_enclave(self):
        first, second = live_instances()
        doc = bytearray(base64.b64decode(first))
        doc[-1] ^= 1
        r = check(World(attestation=[reply([b64(doc), second])]))
        assert r.exit_code == 1
        assert (last(r).label, last(r).status, last(r).lines) == (
            "Attestation",
            "failed",
            [
                "FAILED: enclave i-0d45a659f78879f74-enc01a1aff4a42aa553: the document's signature does not verify"
            ],
        )
        assert r.verdict == ["Failed at Attestation. Don't send anything to these enclaves."]

    @pytest.mark.parametrize(
        "at, reason",
        [
            (ms("2026-11-06T11:03:30Z"), "31 minutes old"),
            (ms("2026-11-06T10:27:30Z"), "6 minutes ahead of this device's clock"),
        ],
    )
    def test_fails_the_documents_on_a_clock_too_late_or_too_early(self, at, reason):
        r = check(now=lambda: at)
        assert r.exit_code == 1
        assert last(r).label == "Attestation"
        assert reason in last(r).lines[0]

    def test_fails_a_host_that_lists_no_enclave_and_one_that_answers_with_something_else(self):
        none = check(World(attestation=[reply([])]))
        assert last(none).lines == ["FAILED: api.trymorse.ai lists no enclave"]
        other = check(World(attestation=[lambda: httpx.Response(200, json={"object": "list", "data": []})]))
        assert last(other).lines == [
            "FAILED: https://api.trymorse.ai/v1/attestation is not a list of enclaves"
        ]
        assert (none.exit_code, other.exit_code) == (1, 1)

    def test_waits_once_as_a_429_asks_then_checks_the_second_reply(self):
        world = fake(
            World(
                attestation=[
                    lambda: httpx.Response(429, headers={"retry-after": "7"}, text="slow down"),
                    reply(live_instances()),
                ]
            )
        )
        r = verify(**world.options)
        assert world.slept == [7]
        assert r.exit_code == 0

    # What Date.parse makes of each, in verify.ts, under a clock 5 hours behind UTC.
    @pytest.mark.parametrize(
        "value, seconds",
        [
            ("Fri, 06 Nov 2026 10:40:30 GMT", 30),
            ("Fri, 06 Nov 2026 10:40:30 -0000", 30),
            ("Fri, 06 Nov 2026 05:40:30 EST", 30),
            ("Fri, 06 Nov 2026 05:40:30", 30),
            ("2026-11-06T10:40:30Z", 30),
            ("2026-11-06T10:40:30+00:00", 30),
            ("2026-11-06T05:40:30", 30),
            ("2026-11-06", 1),
            ("Fri, 06 Nov 2026 10:50:00 GMT", 60),
            ("600", 60),
            ("0", 1),
            ("soon", 5),
            (None, 5),
        ],
    )
    def test_reads_retry_after_as_date_parse_does(self, value, seconds, monkeypatch):
        retry_after = importlib.import_module("trymorse_verify.verify").retry_after
        monkeypatch.setenv("TZ", "EST5")
        time.tzset()
        try:
            assert retry_after(value, NOW) == seconds
        finally:
            monkeypatch.undo()
            time.tzset()

    def test_could_not_finish_when_the_host_is_still_rate_limiting_or_unreachable(self):
        limited = check(World(attestation=[lambda: httpx.Response(429, headers={"retry-after": "600"})]))
        assert limited.exit_code == 2
        assert limited.verdict == [
            "Could not finish: api.trymorse.ai is rate-limiting this address (60 requests a minute). Run again in a minute. Nothing was checked."
        ]

        def down():
            raise httpx.ConnectError("[Errno -2] Name or service not known")

        unreachable = check(World(attestation=[down]))
        assert unreachable.exit_code == 2
        assert unreachable.verdict == [
            "Could not finish: https://api.trymorse.ai/v1/attestation: [Errno -2] Name or service not known. Nothing was checked."
        ]

    def test_could_not_finish_when_the_host_redirects(self):
        r = check(
            World(
                attestation=[lambda: httpx.Response(302, headers={"location": "https://elsewhere.example/"})]
            )
        )
        assert r.verdict == [
            "Could not finish: https://api.trymorse.ai/v1/attestation: unexpected redirect. Nothing was checked."
        ]

    def test_reads_an_attestation_reply_and_a_bundle_that_open_with_a_bom_as_text_decoder_does(self):
        bom = b"\xef\xbb\xbf"
        assert (
            check(World(attestation=[lambda: httpx.Response(200, content=bom + ATTESTATION)])).exit_code == 0
        )
        assert check(World(list=(TAG, STATEMENT, bom + BUNDLE))).exit_code == 0

    def test_could_not_finish_when_the_host_sends_more_than_1_mib(self):
        r = check(World(attestation=[lambda: httpx.Response(200, content=b" " * ((1 << 20) + 1))]))
        assert r.verdict == [
            "Could not finish: https://api.trymorse.ai/v1/attestation sent more than 1 MiB. Nothing was checked."
        ]


class TestAllowed:
    def test_fails_when_one_byte_of_the_signed_list_changed(self):
        statement = bytearray(STATEMENT)
        statement[-3] ^= 1
        r = check(World(list=("signed-290-20261106T095152Z", bytes(statement), read("prod.sigstore.json"))))
        assert r.exit_code == 1
        assert last(r).lines == [
            "FAILED: Morse's signed list signed-290-20261106T095152Z names a digest other than the statement's SHA-256"
        ]

    def test_fails_an_image_the_signed_list_does_not_name_list_280(self):
        r = check(
            World(
                list=(
                    "signed-280-20261106T080407Z",
                    read("prod.statement.280.json"),
                    read("prod.sigstore.280.json"),
                )
            )
        )
        assert r.exit_code == 1
        assert (last(r).label, last(r).status, last(r).lines) == (
            "Allowed",
            "failed",
            [
                "FAILED: enclave i-0d45a659f78879f74-enc01a1aff4a42aa553 runs PCR0 4fccf46baafd…ef6e1606, which is not on Morse's signed list"
            ],
        )

    def test_fails_a_list_whose_check_raises_anything_as_src_node_verify_ts_does(self, monkeypatch):
        v = importlib.import_module("trymorse_verify.verify")

        def crash(files, now):
            raise TypeError("unsupported operand type(s) for +: 'int' and 'str'")

        monkeypatch.setattr(v, "verify_signed_list", crash)
        r = check()
        assert r.exit_code == 1
        assert (last(r).label, last(r).lines) == (
            "Allowed",
            [
                "FAILED: Morse's signed list signed-290-20261106T095152Z unsupported operand type(s) for +: 'int' and 'str'"
            ],
        )

    def test_fails_a_list_signed_with_a_certificate_that_repeats_an_extension(self):
        from der import with_extensions
        from test_signed_list import with_leaf

        b = with_leaf(lambda der: with_extensions(der, lambda exts: [*exts, exts[-1]]))
        r = check(World(list=("signed-290-20261106T095152Z", STATEMENT, json.dumps(b).encode())))
        assert r.exit_code == 1
        assert r.verdict == ["Failed at Allowed. Don't send anything to these enclaves."]
        assert (
            last(r)
            .lines[0]
            .startswith(
                "FAILED: Morse's signed list signed-290-20261106T095152Z is signed with a certificate that Duplicate"
            )
        )

    def test_could_not_finish_when_githubs_latest_release_of_morse_pins_is_not_a_signed_list(self):
        world = fake()

        def handle(request: httpx.Request) -> httpx.Response:
            if str(request.url).endswith("/releases/latest"):
                return httpx.Response(
                    302, headers={"location": "https://github.com/trymorse/morse-pins/releases/tag/v1"}
                )
            return world.handle(request)

        r = verify(**{**world.options, "client": httpx.Client(transport=httpx.MockTransport(handle))})
        assert r.exit_code == 2
        assert re.fullmatch(r"Could not finish: .*not a signed list\. Nothing was checked\.", r.verdict[0])


@pytest.fixture(scope="module")
def forge():
    return forge_nitro(NOW)


class TestForgedDocuments:
    """AWS's root can't sign test documents, so these forge documents under a test root, with
    the PCRs of images on list 290."""

    @pytest.fixture(autouse=True)
    def _forge(self, forge):
        self.forge = forge

    def instance(self, pcrs: Pcrs, minutes_ago: int = 1) -> str:
        return b64(
            self.forge.document(
                timestamp=NOW - minutes_ago * MINUTE,
                public_key=x25519_public(),
                environment="prod",
                pcrs=pcrs,
            )
        )

    def with_docs(self, pcrs: list[Pcrs], world: World | None = None, **o) -> Report:
        world = world or World()
        world.attestation = [reply([self.instance(p, i + 1) for i, p in enumerate(pcrs)])]
        return check(world, root=self.forge.root, **o)

    def test_fails_an_image_morse_revoked(self):
        r = self.with_docs([REVOKED])
        assert r.exit_code == 1
        assert last(r).lines == [
            "FAILED: enclave i-0123-enc0123 runs PCR0 21534ac29424…a564b595, which is on Morse's signed list, but Morse revoked it"
        ]

    def test_fails_a_debug_mode_enclaves_all_zero_pcrs_at_attestation_saying_so(self):
        zero = "0" * 96
        r = self.with_docs([Pcrs(zero, zero, zero)])
        assert r.exit_code == 1
        assert (last(r).label, last(r).status, last(r).lines) == (
            "Attestation",
            "failed",
            ["FAILED: enclave i-0123-enc0123: the enclave reports all-zero PCRs, so it runs in debug mode"],
        )

    def test_fails_a_document_signed_by_a_key_not_its_certificates(self):
        doc = self.forge.document(
            timestamp=NOW - MINUTE,
            public_key=x25519_public(),
            environment="prod",
            pcrs=LIVE,
            sign_with="stranger",
        )
        r = check(World(attestation=[reply([b64(doc)])]), root=self.forge.root)
        assert last(r).lines == ["FAILED: enclave i-0123-enc0123: the document's signature does not verify"]

    def test_fails_a_document_that_chains_to_another_root(self):
        doc = self.forge.document(
            timestamp=NOW - MINUTE, public_key=x25519_public(), environment="prod", pcrs=LIVE
        )
        r = check(World(attestation=[reply([b64(doc)])]))
        assert last(r).lines == [
            "FAILED: enclave i-0123-enc0123: certificate 1 is signed by neither the next one nor the pinned anchor"
        ]

    def test_prints_a_block_for_each_image_when_the_enclaves_run_two(self):
        r = self.with_docs([LIVE, OLDER.pcrs])
        assert r.exit_code == 0
        assert [s.label for s in r.steps] == [
            "Attestation",
            "Image 1",
            "Allowed",
            "Source",
            "Rebuild",
            "Image 2",
            "Allowed",
            "Source",
            "Rebuild",
            "TLS",
        ]
        assert re.fullmatch(r"key [0-9a-f]{16}, signed 1 min ago, image 1", r.steps[0].lines[1])
        assert re.fullmatch(r"key [0-9a-f]{16}, signed 2 min ago, image 2", r.steps[0].lines[2])
        assert r.steps[7].lines[0] == (
            "v2026.11.4-pins-86774b6, commit 78f8ef8f9d0e on main of github.com/trymorse/morse-enclave, names these PCRs"
        )
        assert r.verdict == [
            "Passed. The enclaves api.trymorse.ai lists run v2026.11.4-pins-23c1570 and v2026.11.4-pins-86774b6 of github.com/trymorse/morse-enclave, as published (not rebuilt here)."
        ]

    def test_names_the_newest_commit_of_an_images_pcrs_as_its_source_and_the_others_too(self):
        shared = next(r for r in parse_log(LOG) if r.name == "v2026.11.3-pins-66a50eb")
        r = self.with_docs([shared.pcrs])
        assert r.exit_code == 0
        assert next(s for s in r.steps if s.label == "Source").lines == [
            "v2026.11.3-pins-66a50eb, commit 33a690c92568 on main of github.com/trymorse/morse-enclave, names these PCRs",
            "and so do v2026.11.3-pins-c076991",
        ]

    def test_rebuilds_the_commit_release_pins_not_a_newer_one_that_names_its_pcrs_too(self):
        pinned = next(r for r in parse_log(LOG) if r.name == "v2026.11.3-pins-c076991")
        world = fake(World(attestation=[reply([self.instance(pinned.pcrs)])], build=pinned.pcrs))
        r = verify(**world.options, root=self.forge.root, release=pinned.commit, rebuild=True)
        assert r.exit_code == 0
        assert next(s for s in r.steps if s.label == "Source").lines == [
            "v2026.11.3-pins-66a50eb, commit 33a690c92568 on main of github.com/trymorse/morse-enclave, names these PCRs",
            "and so do v2026.11.3-pins-c076991",
        ]
        assert [c[-1] for c in world.ran if "archive" in c] == [pinned.commit]
        rebuild = next(s for s in r.steps if s.label == "Rebuild")
        assert f" archive --format=tar {pinned.commit} > src.tar" in rebuild.lines[1]
        assert r.verdict == [
            "Passed. The enclaves api.trymorse.ai lists run v2026.11.3-pins-c076991 of github.com/trymorse/morse-enclave, which rebuilds here to the same PCRs.",
            f"Pin this release in CI: --release {pinned.commit}",
        ]

    def test_fails_release_while_a_deploy_has_the_enclaves_on_two_releases_naming_each(self):
        r = self.with_docs([LIVE, OLDER.pcrs], release="v2026.11.4-pins-23c1570")
        assert r.exit_code == 1
        assert last(r).label == "Release"
        assert re.fullmatch(r"key [0-9a-f]{16} runs v2026\.11\.4-pins-23c1570", last(r).lines[1])
        assert re.fullmatch(r"key [0-9a-f]{16} runs v2026\.11\.4-pins-86774b6", last(r).lines[2])
        assert last(r).lines[3] == (
            "A deploy replaces one enclave at a time, so for a few minutes after one the enclaves run two releases. Run again."
        )

    def test_fails_an_enclave_whose_user_data_names_a_dev_key(self):
        doc = self.forge.document(timestamp=NOW - MINUTE, public_key=bytes(32), environment="dev", pcrs=LIVE)
        r = check(World(attestation=[reply([b64(doc)])]), root=self.forge.root)
        assert re.match(
            r"FAILED: enclave i-0123-enc0123: user_data does not name a prod key", last(r).lines[0]
        )

    def test_fails_a_document_that_is_not_base64_by_its_place_in_the_list(self):
        r = check(World(attestation=[reply(["not base64!"])]), root=self.forge.root)
        assert last(r).lines == ["FAILED: document 1 of 1: the document is not base64"]


class TestOneKeyInTwoDocuments:
    """One HPKE key in two documents at two images: each document is checked at its own PCRs, so
    an older one's image skips no check behind a newer one's."""

    KEY = x25519_public()
    KEY_ID = hashlib.sha256(KEY).hexdigest()[:16]
    TLS_KEY = bytes([7] * 91)

    @pytest.fixture(autouse=True)
    def _forge(self, forge):
        self.forge = forge

    def sharing(self, pcrs: list[Pcrs], world: World | None = None, **o) -> Report:
        world = world or World()
        world.attestation = [
            reply(
                [
                    b64(
                        self.forge.document(
                            timestamp=NOW - (i + 1) * MINUTE,
                            public_key=self.KEY,
                            environment="prod",
                            pcrs=p,
                            tls_key=self.TLS_KEY if i == 1 else None,
                        )
                    )
                    for i, p in enumerate(pcrs)
                ]
            )
        ]
        return check(world, root=self.forge.root, **o)

    def test_counts_one_enclave_and_checks_the_source_of_the_older_documents_image_too(self):
        releases = parse_log(LOG)
        unpublished = next(
            Pcrs(i["pcr0"], i["pcr1"], i["pcr2"])
            for i in statement_images()
            if not i["revoked"]
            and not any(same_pcrs(r.pcrs, Pcrs(i["pcr0"], i["pcr1"], i["pcr2"])) for r in releases)
        )
        r = self.sharing([LIVE, unpublished])
        assert r.exit_code == 1
        assert r.steps[0].lines[0].startswith("1 enclave, signed by AWS Nitro ")
        assert r.steps[0].lines[1] == f"key {self.KEY_ID}, signed 1 min ago, images 1 and 2"
        assert [(s.label, s.status) for s in r.steps] == [
            ("Attestation", "passed"),
            ("Image 1", "info"),
            ("Allowed", "passed"),
            ("Source", "passed"),
            ("Rebuild", "not run"),
            ("Image 2", "info"),
            ("Allowed", "passed"),
            ("Source", "failed"),
        ]
        assert [[e.key_id for e in im.enclaves] for im in r.images] == [[self.KEY_ID], [self.KEY_ID]]

    def test_fails_release_when_the_older_document_runs_another_release(self):
        r = self.sharing([LIVE, OLDER.pcrs], release="v2026.11.4-pins-23c1570")
        assert r.exit_code == 1
        assert last(r).label == "Release"
        assert last(r).lines[1:3] == [
            f"key {self.KEY_ID} runs v2026.11.4-pins-23c1570",
            f"key {self.KEY_ID} runs v2026.11.4-pins-86774b6",
        ]

    def test_rebuilds_the_older_documents_image_too(self):
        r = self.sharing([LIVE, OLDER.pcrs], rebuild=True)
        assert r.exit_code == 1
        assert [(s.label, s.status) for s in r.steps][-4:] == [
            ("Allowed", "passed"),
            ("Source", "passed"),
            ("Rebuild", "info"),
            ("Rebuild", "failed"),
        ]
        assert last(r).lines[0] == (
            "FAILED: commit 78f8ef8f9d0e rebuilds here to other PCRs than the enclaves attest:"
        )

    def test_names_both_releases_and_finds_the_tls_key_the_older_document_attests(self):
        r = self.sharing(
            [LIVE, OLDER.pcrs],
            World(tls=ServedKey(hashlib.sha256(self.TLS_KEY).hexdigest(), "i-0123")),
        )
        assert r.exit_code == 0
        assert (
            last(r).lines[0].startswith("this connection to api.trymorse.ai ended inside an attested enclave")
        )
        assert r.verdict[0] == (
            "Passed. The enclaves api.trymorse.ai lists run v2026.11.4-pins-23c1570 and v2026.11.4-pins-86774b6 of github.com/trymorse/morse-enclave, as published (not rebuilt here)."
        )


class TestSource:
    def test_fails_an_image_no_commit_on_main_names(self):
        r = check(World(log="\0".join(LOG.split("\0")[1:])))
        assert r.exit_code == 1
        assert last(r).lines == [
            "FAILED: no commit on main of github.com/trymorse/morse-enclave names PCR0 4fccf46baafd…ef6e1606: its source isn't published. If Morse is mid-deploy it appears within minutes; run again. Until then, don't send it anything."
        ]

    def test_runs_git_on_its_own_clone_whatever_repository_a_git_hooks_environment_names(self, monkeypatch):
        monkeypatch.setenv("GIT_DIR", "/elsewhere/.git")
        monkeypatch.setenv("GIT_WORK_TREE", "/elsewhere")
        monkeypatch.setenv("GIT_INDEX_FILE", "/elsewhere/.git/index")
        world = fake()
        r = verify(**world.options, rebuild=True)
        assert r.exit_code == 0
        git = [world.envs[i] for i, c in enumerate(world.ran) if c[0] == "git"]
        assert len(git) == 3
        for env in git:
            assert env["GIT_TERMINAL_PROMPT"] == "0"
            assert not {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"} & set(env)
        assert next(c for c in world.ran if "log" in c)[-1] == "refs/heads/main"

    def test_runs_build_sh_without_image_mirror(self, monkeypatch):
        monkeypatch.setenv("IMAGE_MIRROR", "mirror.example")
        world = fake()
        verify(**world.options, rebuild=True)
        bash = next(world.envs[i] for i, c in enumerate(world.ran) if c[0] == "bash")
        assert "IMAGE_MIRROR" not in bash and bash.get("PATH") == os.environ["PATH"]

    def test_could_not_finish_without_git_naming_the_step_that_runs_it(self):
        r = check(World(git="missing"))
        assert r.exit_code == 2
        assert re.fullmatch(
            r"Could not finish: the Source check runs git, .* Nothing was checked past Allowed\.",
            r.verdict[0],
        )

        world = fake()

        def gone(command, args, **o):
            if command == "git" and "archive" in args:
                raise FileNotFoundError("spawn git ENOENT")
            return world.exec(command, args, **o)

        r = verify(**{**world.options, "exec": gone}, rebuild=True)
        assert r.exit_code == 2
        assert re.fullmatch(
            r"Could not finish: the Rebuild check runs git, .* Nothing was checked past Source\.",
            r.verdict[0],
        )

    def test_could_not_finish_when_git_runs_out_of_time(self):
        world = fake()

        def stuck(command, args, **o):
            if command == "git" and args[0] == "clone":
                raise TimedOut("git ran for more than 60000 ms")
            return world.exec(command, args, **o)

        r = verify(**{**world.options, "exec": stuck})
        assert r.verdict == [
            "Could not finish: git clone of https://github.com/trymorse/morse-enclave didn't finish in 60 s. Check that this machine reaches github.com, and run again. Nothing was checked past Allowed."
        ]


class TestRelease:
    @pytest.mark.parametrize("release", ["v2026.11.4-pins-23c1570", LIVE_COMMIT])
    def test_passes_when_every_enclave_runs_the_release_named_by_name_or_commit(self, release):
        r = check(release=release)
        assert r.exit_code == 0
        assert next(s for s in r.steps if s.label == "Release").lines == [
            "every enclave runs v2026.11.4-pins-23c1570, commit 696ab5a852e0, as --release asks"
        ]

    def test_fails_when_the_enclaves_run_another_release(self):
        r = check(release="v2026.11.4-pins-86774b6")
        assert r.exit_code == 1
        assert last(r).lines == [
            "FAILED: --release names v2026.11.4-pins-86774b6, commit 78f8ef8f9d0e, but not every enclave runs it:",
            "key 8f6198f0b59e34cf runs v2026.11.4-pins-23c1570",
            "key 0032c6519a4b546d runs v2026.11.4-pins-23c1570",
            "They run another release. Read it, and pin its commit to accept it.",
        ]

    def test_could_not_finish_for_a_release_main_does_not_have(self):
        r = check(release="v1.8.2")
        assert r.exit_code == 2
        assert r.verdict == [
            "Could not finish: no release v1.8.2 on main of github.com/trymorse/morse-enclave; see https://github.com/trymorse/morse-enclave/commits/main. Nothing was checked past Source."
        ]

    def test_matches_40_hex_against_commits_only_though_a_newer_subject_is_that_hex(self):
        P = lambda c: c * 96  # noqa: E731
        shadow = f"{'e' * 40}\n{LIVE_COMMIT}\n\nPCR0 {P('a')}\nPCR1 {P('b')}\nPCR2 {P('c')}\n"
        r = check(World(log=shadow + "\0" + LOG), release=LIVE_COMMIT)
        assert r.exit_code == 0
        assert next(s for s in r.steps if s.label == "Release").lines == [
            "every enclave runs v2026.11.4-pins-23c1570, commit 696ab5a852e0, as --release asks"
        ]


class TestRebuild:
    def test_passes_when_the_commit_rebuilds_to_the_attested_pcrs_after_saying_what_it_runs(self):
        world = fake()
        r = verify(**world.options, rebuild=True)
        assert r.exit_code == 0
        rebuild = [s for s in r.steps if s.label == "Rebuild"]
        assert [s.status for s in rebuild] == ["info", "passed"]
        lines = rebuild[0].lines
        assert re.fullmatch(r"\$ cd \S+trymorse-verify-\w+/1-\w+", lines[0])
        assert re.fullmatch(
            rf"\$ git -C \S+trymorse-verify-\w+/enclave\.git archive --format=tar {LIVE_COMMIT} > src\.tar",
            lines[1],
        )
        assert lines[2:] == [
            "$ mkdir src && tar -xf src.tar -C src",
            "$ bash src/deploy/enclave/build.sh eif src.tar rebuild prod out",
            "build.sh sha256 b875f928546aee7855cb1db9afc8ab3f1a8a34d43de5bbd62f7076d7ba9f3917",
            "This runs that commit's own build.sh, with access to the Docker daemon, which is root on this machine: run it on one you don't mind that on. Its log goes to stderr.",
        ]
        assert rebuild[1].lines == ["rebuilt here: PCR0, PCR1, and PCR2 match"]
        assert r.verdict[0] == (
            "Passed. The enclaves api.trymorse.ai lists run v2026.11.4-pins-23c1570 of github.com/trymorse/morse-enclave, which rebuilds here to the same PCRs."
        )
        assert [c[0] for c in world.ran] == ["git", "git", "docker", "git", "tar", "bash"]
        archive = world.ran[3]
        assert archive[:2] == ["git", "-C"] and archive[2].endswith("enclave.git")
        assert archive[3:6] == ["archive", "--format=tar", "-o"]
        assert archive[6].endswith("src.tar") and archive[7] == LIVE_COMMIT

    def test_fails_when_the_commit_rebuilds_to_other_pcrs(self):
        r = check(World(build=Pcrs(LIVE.pcr0, LIVE.pcr1, "0" * 96)), rebuild=True)
        assert r.exit_code == 1
        assert last(r).lines == [
            "FAILED: commit 696ab5a852e0 rebuilds here to other PCRs than the enclaves attest:",
            "PCR0 4fccf46baafd…ef6e1606",
            "PCR1 3b4a7e1b5f13…a0974d03",
            "PCR2 000000000000…00000000",
        ]

    @pytest.mark.parametrize(
        "docker, reason",
        [
            ("missing", r"Could not finish: --rebuild needs Docker, and docker isn't on this machine's PATH"),
            (
                "down",
                r"Could not finish: docker can't reach its daemon \(Cannot connect to the Docker daemon",
            ),
        ],
    )
    def test_could_not_finish_without_docker_or_its_daemon(self, docker, reason):
        r = check(World(docker=docker), rebuild=True)
        assert r.exit_code == 2
        assert re.match(reason, r.verdict[0])
        assert r.verdict[0].endswith("Nothing was checked past Source.")

    def test_could_not_finish_when_build_sh_fails_with_the_end_of_its_log_and_how_to_build_on_x86_64(self):
        r = check(World(docker="amd64", build="fails"), rebuild=True)
        assert r.exit_code == 2
        assert (last(r).label, last(r).status, last(r).lines) == (
            "Rebuild",
            "unfinished",
            [
                "build.sh exited 1 on amd64 Docker. Its log ended:",
                "rootfs sha256 7ca659b2",
                "exec /usr/bin/bash: exec format error",
                "A commit's build.sh builds the EIF on arm64 Linux, and newer ones on x86_64 Linux too.",
                "For an older commit on x86_64, enable arm64 emulation first: docker run --privileged --rm tonistiigi/binfmt --install arm64",
                "Docker Desktop on Apple silicon runs arm64 (untested).",
            ],
        )
        assert r.verdict == ["Could not finish: build.sh exited 1. Nothing was checked past Source."]

    def test_removes_its_temporary_directory(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        assert check(rebuild=True).exit_code == 0
        assert list(tmp_path.iterdir()) == []


class TestTls:
    def test_says_the_connection_ended_inside_an_enclave_when_its_key_is_one_a_document_attests(self):
        r = check(
            World(
                tls=ServedKey(
                    "b0474adfce42421fb12c43ebee26901a97ebbf11f32d4a225ffa5767c534b679", "i-0d45a659f78879f74"
                )
            )
        )
        assert r.exit_code == 0
        assert last(r).lines == [
            "this connection to api.trymorse.ai ended inside an attested enclave (key b0474adfce42421f)"
        ]

    def test_never_fails_even_when_it_cant_connect(self):
        r = check(World(tls=ConnectionRefusedError("connect ECONNREFUSED")))
        assert r.exit_code == 0
        assert last(r).lines == [
            "could not connect to api.trymorse.ai:443 (connect ECONNREFUSED), so this says nothing of where its TLS ends."
        ]


@pytest.mark.skipif(os.environ.get("VERIFY_LIVE") != "1", reason="VERIFY_LIVE=1 runs it against prod")
def test_against_prod_passes():
    r = verify()
    detail = "\n".join(line for s in r.steps for line in s.lines)
    assert r.verdict[0].startswith("Passed."), f"{r.verdict}\n{detail}"
    assert r.exit_code == 0
