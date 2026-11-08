# The command line: reads the arguments, prints each step verify() decides as it decides it, in
# plain text, and returns the exit code, as src/node/main.ts does. Only the first line differs: it
# names this package.
from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Sequence
from importlib import metadata

from .verify import Step, verify

LABEL = 13
WIDTH = 80
HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
NAME = "trymorse-verify"

USAGE = f"""Usage: {NAME} [host] [--release <name|commit>] [--rebuild]

Checks that the enclaves <host> lists (default api.trymorse.ai) run an image
AWS Nitro signed for, that Morse's signed list allows, and whose source is a
commit on main of github.com/trymorse/morse-enclave.

  --release <x>  every enclave must run this release: a commit's subject, such
                 as v2026.11.4-pins-23c1570, or its 40-hex commit
  --rebuild      build each image here from its commit with Docker, and
                 compare its PCRs with the attested ones
  --version      print this verifier's version
  --help         print this

Exit 0: every check passed. 1: a check failed; don't send anything.
2: it could not finish, so nothing is proven."""


def version() -> str:
    """This package's version: 0.0.0 in its source, the release's in what PyPI ships."""
    try:
        return metadata.version(NAME)
    except metadata.PackageNotFoundError:
        return "0.0.0"


def _length(text: str) -> int:
    """`text`'s length as JavaScript counts it, in UTF-16 code units: an emoji is two."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def wrap(text: str, width: int) -> list[str]:
    """`text` in lines of at most `width` UTF-16 code units, as src/node/main.ts counts them, where
    its words allow, broken at spaces."""
    lines: list[str] = []
    line = ""
    for word in text.split(" "):
        if line and _length(line) + 1 + _length(word) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    return [*lines, line]


# Each control character (Unicode's Cc) and each bidi control.
_HIDDEN = re.compile("[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def shown(text: str) -> str:
    """`text` with each control character but a newline, and each bidi control, written as
    `\\u{1b}`, so nothing a document, a commit, or a program's log carries can move the cursor,
    hide a line, or reorder one."""
    return _HIDDEN.sub(lambda m: m[0] if m[0] == "\n" else f"\\u{{{ord(m[0]):x}}}", text)


def format_step(step: Step, previous: str = "") -> list[str]:
    """A step as printed: its label in a 13-character column unless the step before had the same
    one and this one neither failed nor stopped, and its text shown and wrapped to 80 characters."""
    show_label = step.label != previous or step.status in ("failed", "unfinished")
    return [
        (step.label if show_label and i == 0 and j == 0 else "").ljust(LABEL) + part
        for i, line in enumerate(step.lines)
        for j, part in enumerate(wrap(shown(line), WIDTH - LABEL))
    ]


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # type: ignore[override]
        raise ValueError(message)


def _parse(argv: Sequence[str]) -> argparse.Namespace:
    p = _Parser(add_help=False, allow_abbrev=False)
    p.add_argument("hosts", nargs="*")
    p.add_argument("--release")
    p.add_argument("--rebuild", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--version", action="store_true")
    return p.parse_intermixed_args(list(argv))


def main(
    argv: Sequence[str],
    out: Callable[[str], object] | None = None,
    err: Callable[[str], object] | None = None,
    **options,
) -> int:
    """Runs the command line on `argv` and returns its exit code. `options` go to verify()."""
    write_out = out or (lambda t: (sys.stdout.write(t), sys.stdout.flush()))
    write_err = err or (lambda t: (sys.stderr.write(t), sys.stderr.flush()))
    try:
        args = _parse(argv)
    except ValueError as e:
        write_err(f"{e}\n\n{USAGE}\n")
        return 2
    if args.help:
        write_out(f"{USAGE}\n")
        return 0
    if args.version:
        write_out(f"{version()}\n")
        return 0
    host, *extra = args.hosts or ["api.trymorse.ai"]
    if extra or not HOST.fullmatch(host):
        write_err(f"Name one host, such as api.trymorse.ai.\n\n{USAGE}\n")
        return 2

    write_out(f"{NAME} {version()}\nChecking the enclaves {host} lists\n\n")
    previous = ""

    def on_step(step: Step) -> None:
        nonlocal previous
        write_out("\n".join(format_step(step, previous)) + "\n")
        previous = step.label

    report = verify(host, release=args.release, rebuild=args.rebuild, on_step=on_step, **options)
    verdict = [part for line in report.verdict for part in wrap(shown(line), WIDTH)]
    write_out(("\n" if previous else "") + "\n".join(verdict) + "\n")
    return report.exit_code


def run() -> None:
    """The console script: `trymorse-verify`, `uvx trymorse-verify`, or `python -m trymorse_verify`."""
    try:
        code = main(sys.argv[1:])
    except Exception as e:
        sys.stdout.write(f"\nCould not finish: {e}. Nothing is proven.\n")
        code = 2
    sys.exit(code)
