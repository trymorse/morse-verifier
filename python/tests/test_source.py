# Releases on morse-enclave's main (src/node/source.test.ts).
from __future__ import annotations

import pytest
from world import LIVE, LIVE_COMMIT, LOG

from trymorse_verify.io import Ran, TimedOut, Unfinished
from trymorse_verify.source import find_release, parse_log, read_releases


def P(c: str) -> str:
    return c * 96


def commit(c: str) -> str:
    return c * 40


def message(name: str, rootfs: bool = True) -> str:
    tail = f"rootfs sha256 {'d' * 64}\n" if rootfs else ""
    return f"{name}\n\nPCR0 {P('a')}\nPCR1 {P('b')}\nPCR2 {P('c')}\n{tail}"


class TestParseLog:
    def test_reads_every_release_on_morse_enclaves_main_newest_first(self):
        releases = parse_log(LOG)
        assert len(releases) == 32
        assert releases[0].name == "v2026.11.4-pins-23c1570"
        assert releases[0].commit == LIVE_COMMIT and releases[0].pcrs == LIVE
        assert releases[0].rootfs == "7ca659b21f66d3875cddbc4f884d6aa72417813b75fdcbd7c6b7d2a47659e99a"
        assert releases[-1].name == "v2026.10.2"

    def test_reads_a_message_without_a_rootfs_line_or_without_its_last_newline(self):
        log = "\0".join(
            [
                f"{commit('1')}\n{message('v1')}",
                f"{commit('2')}\n{message('v2', False)}",
                f"{commit('3')}\n{message('v3').rstrip()}",
            ]
        )
        assert [(r.name, r.rootfs) for r in parse_log(log)] == [
            ("v1", "d" * 64),
            ("v2", None),
            ("v3", "d" * 64),
        ]

    def test_leaves_out_a_commit_whose_message_is_not_a_releases(self):
        log = "\0".join(
            [
                f"{commit('1')}\nFix the README\n",
                f"{commit('2')}\n{message('v2')}\n",
                f"{commit('3')}\n{message('v3').replace('PCR1', 'PCR9')}",
                f"{commit('4')}\n{message('v4').upper()}",
                f"{commit('5')}\n{message('two words')}",
                f"not a commit\n{message('v6')}",
                f"{commit('7')}\n{message('v7')}\n\n",
            ]
        )
        assert parse_log(log) == []

    def test_reads_a_name_as_javascripts_regexp_does_not_as_pythons(self):
        # U+FEFF is space to JavaScript and not to Python; U+001C and U+0085 are the other way round.
        log = "\0".join(
            f"{commit(c)}\n{message(f'v{c}{x}')}" for c, x in zip("123", "\ufeff\x1c\x85", strict=True)
        )
        assert [r.name for r in parse_log(log)] == ["v2\x1c", "v3\x85"]


class TestFindRelease:
    releases = parse_log(LOG)

    def test_finds_a_release_by_its_name_or_its_commit(self):
        assert find_release(self.releases, "v2026.11.4-pins-23c1570").commit == LIVE_COMMIT
        assert find_release(self.releases, LIVE_COMMIT).name == "v2026.11.4-pins-23c1570"
        assert find_release(self.releases, LIVE_COMMIT[:12]) is None
        assert find_release(self.releases, "v1.8.2") is None

    def test_finds_a_40_hex_pin_by_its_commit_alone_though_a_newer_commits_subject_is_that_hex(self):
        shadowed = parse_log(
            "\0".join(
                [f"{commit('e')}\n{message(LIVE_COMMIT)}", f"{commit('d')}\n{message(commit('9'))}", LOG]
            )
        )
        assert (shadowed[0].name, shadowed[0].commit) == (LIVE_COMMIT, commit("e"))
        found = find_release(shadowed, LIVE_COMMIT)
        assert (found.name, found.commit, found.pcrs) == ("v2026.11.4-pins-23c1570", LIVE_COMMIT, LIVE)
        assert find_release(shadowed, commit("9")) is None


def test_read_releases_gives_each_git_command_60_s_and_says_which_one_ran_out():
    bounds = []

    def stuck(command, args, *, timeout_ms=None, **_):
        bounds.append(timeout_ms)
        if args[0] == "clone":
            return Ran(0, "", "")
        raise TimedOut("ran too long")

    with pytest.raises(Unfinished) as e:
        read_releases(stuck, "/nowhere/enclave.git")
    assert str(e.value) == (
        "git log of https://github.com/trymorse/morse-enclave didn't finish in 60 s. Check that this machine reaches github.com, and run again"
    )
    assert bounds == [60_000, 60_000]


def test_read_releases_says_what_git_printed_last_when_it_fails():
    def failing(command, args, **_):
        return Ran(
            128,
            "",
            "Cloning into bare repository...\nfatal: unable to access 'https://github.com/trymorse/morse-enclave/'",
        )

    with pytest.raises(
        Unfinished,
        match="^git clone of https://github.com/trymorse/morse-enclave failed: fatal: unable to access",
    ):
        read_releases(failing, "/nowhere/enclave.git")
