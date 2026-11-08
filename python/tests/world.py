# What verify() reaches, faked from the captures in src/testdata, as src/testing/world.ts fakes
# it: api.trymorse.ai's attestation reply, the morse-pins release that was latest, morse-enclave's
# main, and api.trymorse.ai's TLS key, all as they were on 2026-11-06 at 10:35 UTC. Tests change
# one part at a time.
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import httpx

from trymorse_verify.io import Ran
from trymorse_verify.nitro import Pcrs
from trymorse_verify.tls import ServedKey

TESTDATA = Path(__file__).resolve().parents[2] / "src" / "testdata"


def read(name: str) -> bytes:
    return (TESTDATA / name).read_bytes()


def ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


NOW = ms("2026-11-06T10:40:00Z")
MINUTE = 60_000
ATTESTATION = read("live_attestation.json")
STATEMENT = read("prod.statement.json")
BUNDLE = read("prod.sigstore.json")
TAG = "signed-290-20261106T095152Z"
LOG = read("morse_enclave_main.txt").decode()
API_SPKI = read("api_tls_spki_sha256.txt").decode().strip()

# The image both enclaves ran, which v2026.11.4-pins-23c1570 (commit 696ab5a8) names.
LIVE = Pcrs(
    "4fccf46baafdf7362402ef287d332e49db794e98d0a6fff6337c05915835160cd9b619c47d063d7b19e9e03eef6e1606",
    "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03",
    "de079dd37c0b9e8250e9529abd281d3f6cfb0a900ab9fc22e7c02d180c3f3f30bf56fc5ea17376be06faf6301c4d4f35",
)
LIVE_COMMIT = "696ab5a852e09f3ab11e49156f3892e02796db5a"
RELEASES = "https://github.com/trymorse/morse-pins/releases"

Reply = Callable[[], httpx.Response]


@dataclass
class World:
    # The attestation replies, in order; the last one repeats.
    attestation: list[Reply] | None = None
    list: tuple[str, bytes, bytes] | None = None
    log: str | None = None
    git: str | None = None  # "missing"
    docker: str | None = None  # "missing", "down", or the daemon's arch
    # What build.sh measures, or "fails".
    build: Pcrs | str | None = None
    tls: ServedKey | Exception | None = None


def live_instances() -> list[str]:
    return json.loads(ATTESTATION)["instances"]


def reply(instances: list[str]) -> Reply:
    """The capture's attestation reply with its instances replaced."""
    return lambda: httpx.Response(
        200,
        json={
            "object": "proxy_attestation",
            "environment": "prod",
            "instances": instances,
            "proxy_time": 1793961340,
        },
    )


class Missing(FileNotFoundError):
    pass


@dataclass
class Fake:
    """verify()'s options for a world, and every request and program it makes, with each
    program's environment."""

    world: World
    fetched: list[str] = field(default_factory=list)
    ran: list[list[str]] = field(default_factory=list)
    envs: list[dict | None] = field(default_factory=list)
    slept: list[float] = field(default_factory=list)
    attestations: int = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.fetched.append(url)
        tag, statement, bundle = self.world.list or (TAG, STATEMENT, BUNDLE)
        if url == "https://api.trymorse.ai/v1/attestation":
            replies = self.world.attestation or [lambda: httpx.Response(200, content=ATTESTATION)]
            r = replies[min(self.attestations, len(replies) - 1)]
            self.attestations += 1
            return r()
        if url == f"{RELEASES}/latest":
            return httpx.Response(302, headers={"location": f"{RELEASES}/tag/{tag}"})
        if url == f"{RELEASES}/download/{tag}/prod.statement.json":
            return httpx.Response(200, content=statement)
        if url == f"{RELEASES}/download/{tag}/prod.sigstore.json":
            return httpx.Response(200, content=bundle)
        return httpx.Response(404, text="not found")

    def exec(self, command, args, *, cwd=None, env=None, log=False, timeout_ms=None) -> Ran:
        args = list(args)
        self.ran.append([command, *args])
        self.envs.append(env)
        w = self.world
        if command == "git":
            if w.git == "missing":
                raise Missing(f"spawn {command} ENOENT")
            if args[0] == "clone":
                return Ran(0, "", "")
            if "log" in args:
                return Ran(0, w.log if w.log is not None else LOG, "")
            if "archive" in args:
                Path(args[args.index("-o") + 1]).write_text("a tar")
                return Ran(0, "", "")
        if command == "docker":
            if w.docker == "missing":
                raise Missing(f"spawn {command} ENOENT")
            if w.docker == "down":
                return Ran(
                    1,
                    "",
                    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
                )
            return Ran(0, f"{w.docker or 'arm64'}\n", "")
        if command == "tar":
            script = Path(args[args.index("-C") + 1]) / "deploy/enclave"
            script.mkdir(parents=True, exist_ok=True)
            (script / "build.sh").write_text("#!/bin/bash\n")
            return Ran(0, "", "")
        if command == "bash":
            if w.build == "fails":
                return Ran(1, "", "rootfs sha256 7ca659b2\nexec /usr/bin/bash: exec format error")
            pcrs = w.build if isinstance(w.build, Pcrs) else LIVE
            out = Path(cwd) / args[5]
            out.mkdir(parents=True, exist_ok=True)
            (out / "measurements.json").write_text(
                json.dumps(
                    {
                        "Measurements": {
                            "HashAlgorithm": "Sha384 { ... }",
                            "PCR0": pcrs.pcr0,
                            "PCR1": pcrs.pcr1,
                            "PCR2": pcrs.pcr2,
                        }
                    }
                )
            )
            return Ran(0, "", "")
        raise AssertionError(f"the test runs no {command}")

    def tls(self, host: str) -> ServedKey:
        if isinstance(self.world.tls, Exception):
            raise self.world.tls
        return self.world.tls or ServedKey(API_SPKI, "Amazon RSA 2048 M04")

    @property
    def options(self) -> dict:
        return {
            "client": httpx.Client(transport=httpx.MockTransport(self.handle)),
            "exec": self.exec,
            "now": lambda: NOW,
            "sleep": self.slept.append,
            "tls": self.tls,
        }


def fake(world: World | None = None) -> Fake:
    return Fake(world or World())
