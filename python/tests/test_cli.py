# The command line (src/node/main.test.ts): what it prints, in what width, and its exit codes.
from __future__ import annotations

import base64
import re
import subprocess
import sys

import httpx
import pytest
from forge import forge_nitro
from world import LIVE, LOG, NOW, World, fake, reply

from trymorse_verify.cli import USAGE, format_step, main, shown, wrap
from trymorse_verify.nitro import Pcrs
from trymorse_verify.verify import Step


def run(argv: list[str], world: World | None = None, **options):
    out: list[str] = []
    err: list[str] = []
    code = main(argv, out=out.append, err=err.append, **{**fake(world).options, **options})
    return code, "".join(out), "".join(err)


# What `trymorse-verify` printed for api.trymorse.ai on 2026-11-06 at 10:40 UTC, from the captures.
PASSED = """trymorse-verify 0.0.0
Checking the enclaves api.trymorse.ai lists

Attestation  2 enclaves, each signed by AWS Nitro (root 641a0321…8f79bb5b)
             key 8f6198f0b59e34cf, signed 6 min ago
             key 0032c6519a4b546d, signed 8 min ago
             PCR0 4fccf46baafd…ef6e1606
             PCR1 3b4a7e1b5f13…a0974d03
             PCR2 de079dd37c0b…1c4d4f35
Allowed      on Morse's signed list of prod images, not revoked
             list 290, logged 48 min ago at Rekor entry 3714441255
             https://search.sigstore.dev/?logIndex=3714441255
Source       v2026.11.4-pins-23c1570, commit 696ab5a852e0 on main of
             github.com/trymorse/morse-enclave, names these PCRs
Rebuild      not run. These PCRs are the ones Morse's CI wrote in that commit.
             Run with --rebuild to build it here and compare (Docker, ~2 min).
TLS          api.trymorse.ai's TLS key 7589dd8f4f792416 (issuer Amazon RSA 2048
             M04) is in no attestation document, so TLS ends before the enclave.
             Morse's relay can read requests on it unless they're sealed.

Passed. The enclaves api.trymorse.ai lists run v2026.11.4-pins-23c1570 of
github.com/trymorse/morse-enclave, as published (not rebuilt here).
Pin this release in CI: --release 696ab5a852e09f3ab11e49156f3892e02796db5a
"""


def test_prints_each_check_it_passed_and_exits_0():
    assert run([]) == (0, PASSED, "")


@pytest.mark.parametrize("argv", [[], ["--rebuild"], ["--release", "v2026.11.4-pins-23c1570"]])
def test_keeps_every_line_to_80_characters_and_prints_no_claim_it_cant_back(argv):
    _, out, _ = run(argv)
    for line in out.split("\n"):
        assert len(line) <= 80, line
    assert not re.search(
        r"·|append-only|every build is logged|your connection ends inside|no one can be served a different one",
        out,
    )


def test_names_the_step_that_failed_and_exits_1():
    code, out, _ = run([], World(attestation=[reply([])]))
    assert out == (
        "trymorse-verify 0.0.0\nChecking the enclaves api.trymorse.ai lists\n\n"
        "Attestation  FAILED: api.trymorse.ai lists no enclave\n\n"
        "Failed at Attestation. Don't send anything to these enclaves.\n"
    )
    assert code == 1


def test_says_what_it_could_not_finish_and_what_it_checked_before_and_exits_2():
    code, out, _ = run([], World(git="missing"))
    assert (
        "\nCould not finish: the Source check runs git, which isn't on this machine's PATH.\n"
        "Install git (https://git-scm.com) and run again. Nothing was checked past\nAllowed.\n"
    ) in out
    assert code == 2


def test_labels_a_failure_that_follows_a_step_of_the_same_label():
    code, out, _ = run(["--rebuild"], World(build=Pcrs(LIVE.pcr0, LIVE.pcr1, "0" * 96)))
    assert "\nRebuild      FAILED: commit 696ab5a852e0 rebuilds here to other PCRs than the\n" in out
    assert code == 1


def test_leaves_one_blank_line_before_the_verdict_when_no_step_printed():
    code, out, _ = run([], World(attestation=[lambda: httpx.Response(503, text="x")]))
    assert out == (
        "trymorse-verify 0.0.0\nChecking the enclaves api.trymorse.ai lists\n\n"
        "Could not finish: https://api.trymorse.ai/v1/attestation answered 503. Nothing\nwas checked.\n"
    )
    assert code == 2


def test_prints_no_control_character_a_documents_module_id_or_a_commits_subject_carries():
    hide = "\x1b[1A\x1b[2KPassed.\x1b[8m"
    forge = forge_nitro(NOW)
    doc = forge.document(
        timestamp=NOW - 60_000, public_key=bytes(32), environment="dev", pcrs=LIVE, module_id=f"i-0123{hide}"
    )
    code, out, _ = run([], World(attestation=[reply([base64.b64encode(doc).decode()])]), root=forge.root)
    assert code == 1
    assert "\x1b" not in out
    assert "\nAttestation  FAILED: document 1 of 1: user_data does not name a prod key" in out

    code, out, _ = run([], World(log=LOG.replace("v2026.11.4-pins-23c1570", f"v2026.11.4{hide}\u202e")))
    assert code == 0
    assert "\x1b" not in out and "\u202e" not in out
    assert "v2026.11.4\\u{1b}[1A\\u{1b}[2KPassed.\\u{1b}[8m\\u{202e}" in out


def test_prints_its_usage_for_help_and_its_version_for_version():
    assert run(["--help"]) == (0, f"{USAGE}\n", "")
    assert run(["-h"]) == (0, f"{USAGE}\n", "")
    assert run(["--version"]) == (0, "0.0.0\n", "")
    for line in USAGE.split("\n"):
        assert len(line) <= 80


@pytest.mark.parametrize(
    "argv",
    [
        ["--json"],
        ["--release"],
        ["api.trymorse.ai", "other.example"],
        ["https://api.trymorse.ai"],
        ["--rel", "x"],
    ],
)
def test_refuses_bad_arguments_with_its_usage_and_exits_2(argv):
    code, out, err = run(argv)
    assert code == 2
    assert out == ""
    assert USAGE in err


def test_takes_the_host_and_flags_in_any_order():
    world = fake()
    out: list[str] = []
    code = main(
        ["--release", "v2026.11.4-pins-23c1570", "api.trymorse.ai", "--release=v2026.11.4-pins-23c1570"],
        out=out.append,
        **world.options,
    )
    assert code == 0
    assert "Release      every enclave runs v2026.11.4-pins-23c1570" in "".join(out)


def test_runs_as_python_m():
    ran = subprocess.run([sys.executable, "-m", "trymorse_verify", "--help"], capture_output=True, text=True)
    assert (ran.returncode, ran.stdout) == (0, f"{USAGE}\n")


class TestFormatStep:
    def test_prints_a_label_once_in_a_13_character_column_and_wraps_the_text_to_80(self):
        text = " ".join(["word"] * 20)
        assert format_step(Step("Rebuild", "info", [text, "two"])) == [
            "Rebuild      " + " ".join(["word"] * 13),
            "             " + " ".join(["word"] * 7),
            "             two",
        ]
        assert format_step(Step("Rebuild", "passed", ["rebuilt"]), "Rebuild") == ["             rebuilt"]
        for status in ("failed", "unfinished"):
            assert format_step(Step("Rebuild", status, ["FAILED: no"]), "Rebuild") == [
                "Rebuild      FAILED: no"
            ]


def test_shown_writes_each_control_character_but_a_newline_and_each_bidi_control_as_its_code():
    assert (
        shown("a\x1b[8m\tb\x7f\x9b\u202a\u2069\nc…")
        == "a\\u{1b}[8m\\u{9}b\\u{7f}\\u{9b}\\u{202a}\\u{2069}\nc…"
    )


def test_wrap_breaks_at_spaces_to_fit_and_leaves_a_word_longer_than_the_width_whole():
    assert wrap("one two three four", 9) == ["one two", "three", "four"]
    assert wrap("a 0123456789abcdef b", 8) == ["a", "0123456789abcdef", "b"]


def test_wrap_counts_as_javascript_does_an_emoji_as_two():
    assert wrap("ab \U0001f600\U0001f600 c", 6) == ["ab", "\U0001f600\U0001f600 c"]
    assert wrap("ab \U0001f600\U0001f600\U0001f600 c", 6) == ["ab", "\U0001f600\U0001f600\U0001f600", "c"]
