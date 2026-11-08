# Where each image's source is published: every release of the enclave is a commit on main of
# github.com/trymorse/morse-enclave (which a ruleset Morse set, and could change, keeps GitHub from
# rewriting or deleting), whose message is the release's name and the PCRs Morse's CI measured when
# it built it. By hand:
#   git clone --bare --filter=tree:0 --single-branch --branch main https://github.com/trymorse/morse-enclave enclave.git
#   git -C enclave.git log --format='%H %s' main            # each release, newest first
#   git -C enclave.git show -s --format=%B <commit>          # the PCRs its message names
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from .io import Exec, Unfinished, git_env, is_missing, no_git, timed_out
from .nitro import Pcrs

REPO = "github.com/trymorse/morse-enclave"

# How long each git command may run. The clone is a few hundred KB, so a git still running then
# is stuck, and would hold every check waiting on it.
GIT_TIMEOUT_MS = 60_000

# JavaScript's \S, which src/node/source.ts names a release with. Python's \S differs: it takes
# U+FEFF as a name's character and U+001C-U+001F and U+0085 as space.
_NAME = r"[^\t\n\x0b\x0c\r \xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+"

# The message Morse's CI writes on each release commit.
MESSAGE = re.compile(
    f"({_NAME})"
    r"\n\nPCR0 ([0-9a-f]{96})\nPCR1 ([0-9a-f]{96})\nPCR2 ([0-9a-f]{96})\n"
    r"(?:rootfs sha256 ([0-9a-f]{64})\n)?"
)
COMMIT = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class Release:
    name: str
    commit: str
    pcrs: Pcrs
    rootfs: str | None


def parse_log(log: str) -> list[Release]:
    """The releases in the output of `git log -z --format=%H%n%B`, newest first. A commit whose
    message is not a release's is left out."""
    releases = []
    for entry in log.split("\0"):
        newline = entry.find("\n")
        commit = entry[:newline] if newline >= 0 else entry[:-1]
        message = entry[newline + 1 :]
        m = MESSAGE.fullmatch(message if message.endswith("\n") else message + "\n")
        if not COMMIT.fullmatch(commit) or not m:
            continue
        releases.append(Release(m[1], commit, Pcrs(m[2], m[3], m[4]), m[5]))
    return releases


def read_releases(exec: Exec, clone: str) -> list[Release]:
    """Clones main's commits (no files, a few hundred KB) into `clone` and reads its releases."""

    def git(args: list[str]) -> str:
        verb = args[2] if args[0] == "-C" else args[0]
        try:
            ran = exec("git", args, env=git_env(), timeout_ms=GIT_TIMEOUT_MS)
        except Exception as e:
            if is_missing(e):
                raise Unfinished(no_git("Source")) from e
            if timed_out(e):
                raise Unfinished(
                    f"git {verb} of https://{REPO} didn't finish in {GIT_TIMEOUT_MS // 1000} s. Check that this machine reaches github.com, and run again"
                ) from e
            raise
        if ran.code != 0:
            raise Unfinished(f"git {verb} of https://{REPO} failed: {ran.tail.split(chr(10))[-1]}")
        return ran.stdout

    git(
        [
            "clone",
            "--quiet",
            "--bare",
            "--filter=tree:0",
            "--single-branch",
            "--branch",
            "main",
            f"https://{REPO}",
            clone,
        ]
    )
    return parse_log(git(["-C", clone, "log", "-z", "--format=%H%n%B", "refs/heads/main"]))


def find_release(releases: Sequence[Release], x: str) -> Release | None:
    """The release `x` names, if main has it: 40 hex by its commit alone, so no commit's subject
    can stand in for a pinned commit, and anything else by its name, newest first."""
    by_commit = COMMIT.fullmatch(x) is not None
    return next((r for r in releases if (r.commit if by_commit else r.name) == x), None)
