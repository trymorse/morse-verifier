# How the checks reach the network and run programs. Nothing here decides anything.
from __future__ import annotations

import codecs
import errno
import json as _json
import os
import secrets
import string
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

import httpx

MAX_BODY = 1 << 20
# How long a GET may take in all, as AbortSignal.timeout(30_000) gives each of TS's. httpx's own
# timeout is per read, so a server sending a byte a read could hold a GET open for good.
GET_SECONDS = 30.0


class Unfinished(Exception):
    """A check that could not run, so nothing past the last check that passed is proven (exit 2).
    `lines` are details to print first, such as the end of a build's log."""

    def __init__(self, reason: str, lines: Sequence[str] = ()):
        super().__init__(reason)
        self.lines = list(lines)


@dataclass(frozen=True)
class Got:
    status: int
    headers: httpx.Headers
    body: bytes


def cause_of(e: BaseException) -> str:
    cause = e.__cause__ or e.__context__
    if isinstance(e, httpx.HTTPError) and cause is not None and str(cause):
        return str(cause)
    return str(e) or type(e).__name__


def get(client: httpx.Client, url: str, redirect: str = "error") -> Got:
    """GETs `url` and reads at most 1 MiB of its body. A network error, a longer body, or a GET
    still reading after GET_SECONDS is Unfinished. `redirect` is "error" (a redirect is
    Unfinished), "manual", or "follow"."""
    deadline = time.monotonic() + GET_SECONDS
    try:
        with client.stream("GET", url, follow_redirects=redirect == "follow") as reply:
            if redirect == "error" and reply.is_redirect:
                raise Unfinished(f"{url}: unexpected redirect")
            body = bytearray()
            for chunk in reply.iter_bytes():
                if time.monotonic() > deadline:
                    raise Unfinished(f"{url} took more than {GET_SECONDS:g} s")
                body += chunk
                if len(body) > MAX_BODY:
                    raise Unfinished(f"{url} sent more than 1 MiB")
            return Got(reply.status_code, reply.headers, bytes(body))
    except httpx.HTTPError as e:
        raise Unfinished(f"{url}: {cause_of(e)}") from e


def default_client() -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(30.0))


def _reject_constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def _js_int(text: str) -> float | int:
    """An integer as JSON.parse reads it: a double past 2^53, which has 16 digits. Read as a double
    from its digits, a long one is no int() past Python's 4300-digit limit, but infinity."""
    if len(text.lstrip("-")) > 16:
        return float(text)
    n = int(text)
    return n if abs(n) <= 2**53 else float(text)


def parse_json(text: str) -> object:
    """`text` as JSON.parse reads it: no NaN or Infinity, and an integer of any length. Raises
    ValueError for what JSON.parse refuses, and for nesting deeper than Python's recursion limit,
    which JSON.parse would read."""
    try:
        return _json.loads(text, parse_int=_js_int, parse_constant=_reject_constant)
    except RecursionError:
        raise ValueError("it nests too deep") from None


def json(data: bytes) -> object:
    """The JSON in `data`, or None if it holds none. A BOM is dropped, as TextDecoder drops it."""
    try:
        return parse_json(data.decode("utf-8-sig", "replace"))
    except ValueError:
        return None


def tmpdir() -> str:
    """The system's temporary directory, as Node's os.tmpdir() finds it."""
    if os.name == "nt":
        import tempfile

        return tempfile.gettempdir()
    path = os.environ.get("TMPDIR") or os.environ.get("TMP") or os.environ.get("TEMP") or "/tmp"
    return path[:-1] if len(path) > 1 and path.endswith("/") else path


_SUFFIX = string.ascii_letters + string.digits


def mkdtemp(prefix: str) -> str:
    """A new directory `prefix` and six random letters or digits, as Node's mkdtemp names one."""
    for _ in range(100):
        path = prefix + "".join(secrets.choice(_SUFFIX) for _ in range(6))
        try:
            os.mkdir(path, 0o700)
            return path
        except FileExistsError:
            continue
    raise FileExistsError(path)


def temp_dir(prefix: str) -> str:
    """A new directory in the system's temporary one. When it can't be made, the check can't run."""
    base = tmpdir()
    try:
        return mkdtemp(os.path.join(base, prefix))
    except OSError as e:
        code = errno.errorcode.get(e.errno or 0, str(e))
        raise Unfinished(
            f"it can't make a temporary directory in {base} ({code}). Set TMPDIR to a directory it can write, and run again"
        ) from e


@dataclass(frozen=True)
class Ran:
    code: int
    stdout: str
    # The last 20 lines of what the program printed.
    tail: str


class TimedOut(Exception):
    pass


Exec = Callable[..., Ran]


def exec(
    command: str,
    args: Sequence[str],
    *,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    log: bool = False,
    timeout_ms: int | None = None,
) -> Ran:
    """Runs a program with no shell. Raises FileNotFoundError when it is not on PATH. With `log`,
    copies everything it prints to stderr as it runs; without, keeps its stdout. With
    `timeout_ms`, kills it once that long has passed and raises TimedOut."""
    child = subprocess.Popen(
        [command, *args],
        cwd=cwd,
        env=dict(env) if env is not None else None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout: list[str] = []
    tail = [""]
    lock = threading.Lock()

    def keep(text: str) -> None:
        with lock:
            tail[0] = "\n".join((tail[0] + text).split("\n")[-21:])
            if log:
                sys.stderr.write(text)
                sys.stderr.flush()

    def pump(stream, into_stdout: bool) -> None:
        put = stdout.append if into_stdout and not log else keep
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        with stream:
            for chunk in iter(lambda: stream.read1(65536), b""):
                put(decoder.decode(chunk))
        put(decoder.decode(b"", final=True))

    readers = [
        threading.Thread(target=pump, args=(child.stdout, True), daemon=True),
        threading.Thread(target=pump, args=(child.stderr, False), daemon=True),
    ]
    for r in readers:
        r.start()
    deadline = None if timeout_ms is None else time.monotonic() + timeout_ms / 1000
    try:
        child.wait(None if deadline is None else max(deadline - time.monotonic(), 0))
        for r in readers:
            r.join(None if deadline is None else max(deadline - time.monotonic(), 0))
            if r.is_alive():
                raise subprocess.TimeoutExpired(command, timeout_ms)
    except subprocess.TimeoutExpired:
        # A program it started can hold the pipes open after it is killed, so this raises at once.
        child.kill()
        child.wait()
        raise TimedOut(f"{command} ran for more than {timeout_ms} ms") from None
    return Ran(child.returncode, "".join(stdout), tail[0].rstrip())


# What `git rev-parse --local-env-vars` lists, and the rest that point git at another repository
# than the one named. Git sets some for its hooks, so a check run from a hook would read that one.
ELSEWHERE = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
    "GIT_QUARANTINE_PATH",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
}


def git_env() -> dict[str, str]:
    """This process's environment, without what points git at another repository, and never
    prompting for a password."""
    env = {k: v for k, v in os.environ.items() if k not in ELSEWHERE}
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def is_missing(e: BaseException) -> bool:
    return isinstance(e, FileNotFoundError)


def no_git(step: str) -> str:
    """Why `step` could not finish when git isn't on PATH."""
    return f"the {step} check runs git, which isn't on this machine's PATH. Install git (https://git-scm.com) and run again"


def timed_out(e: BaseException) -> bool:
    return isinstance(e, TimedOut)
