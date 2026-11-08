# How the checks run programs (src/node/io.test.ts).
from __future__ import annotations

import math
import sys
import time

import httpx
import pytest

from trymorse_verify import io
from trymorse_verify.io import TimedOut, Unfinished, exec, get, git_env, json, temp_dir

python = sys.executable


def test_exec_returns_what_a_program_printed_and_its_exit_code():
    ran = exec(
        python, ["-c", "import sys; sys.stdout.write('out'); print('err', file=sys.stderr); sys.exit(3)"]
    )
    assert (ran.code, ran.stdout, ran.tail) == (3, "out", "err")


def test_exec_keeps_the_last_20_lines_and_with_log_copies_all_to_stderr(capsys):
    ran = exec(python, ["-c", "for i in range(30): print(i)"], log=True)
    assert ran.stdout == ""
    assert ran.tail.split("\n") == [str(i) for i in range(10, 30)]
    assert capsys.readouterr().err.split() == [str(i) for i in range(30)]


def test_exec_kills_a_program_still_running_after_timeout_though_a_program_it_started_holds_its_output_open():
    started = time.monotonic()
    script = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3)']); time.sleep(3)"
    )
    with pytest.raises(TimedOut):
        exec(python, ["-c", script], timeout_ms=200)
    assert time.monotonic() - started < 2


def test_exec_raises_file_not_found_for_a_program_not_on_path():
    with pytest.raises(FileNotFoundError):
        exec("trymorse-verify-no-such-program", [])


def test_git_env_never_prompts_and_names_no_other_repository(monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/elsewhere/.git")
    monkeypatch.setenv("GIT_AUTHOR_NAME", "kept")
    env = git_env()
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert "GIT_DIR" not in env and env["GIT_AUTHOR_NAME"] == "kept"


def test_temp_dir_is_named_as_nodes_mkdtemp_names_one(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", f"{tmp_path}/")
    made = temp_dir("trymorse-verify-")
    assert (
        made.startswith(f"{tmp_path}/trymorse-verify-")
        and len(made) == len(f"{tmp_path}/trymorse-verify-") + 6
    )


def test_json_reads_what_json_parse_reads_and_nothing_else():
    assert json(b'\xef\xbb\xbf{"a":1}') == {"a": 1}
    assert json(b'{"a":' + b"9" * 5000 + b"}") == {"a": math.inf}
    assert json(b'{"a":' + b"9" * 17 + b"}") == {"a": 1e17}
    assert json(b"[" * 100_000 + b"]" * 100_000) is None
    assert json(b'{"a":NaN}') is None
    assert json(b"\xef\xbb\xbf\xef\xbb\xbf{}") is None


def test_get_is_unfinished_once_a_server_sending_a_byte_at_a_time_has_taken_its_time(monkeypatch):
    monkeypatch.setattr(io, "GET_SECONDS", 0.2)

    def drip():
        for _ in range(10):
            time.sleep(0.05)
            yield b"x"

    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=drip())))
    started = time.monotonic()
    with pytest.raises(Unfinished, match=r"^https://h\.example/ took more than 0\.2 s$"):
        get(client, "https://h.example/")
    assert time.monotonic() - started < 0.4
