# What the CLI prints for each scenario of src/testdata/golden_scenarios.json must be
# src/testdata/golden/<name>.txt byte for byte, but the first line, which names this package. The
# TypeScript CLI's src/node/golden.test.ts writes and holds the same files, so the two can't drift.
from __future__ import annotations

import base64
import json
import re

import httpx
import pytest
from world import LOG, STATEMENT, TAG, TESTDATA, World, fake, live_instances, ms, read, reply

from trymorse_verify.cli import main
from trymorse_verify.nitro import Pcrs, parse_cert
from trymorse_verify.tls import ServedKey

SCENARIOS = json.loads((TESTDATA / "golden_scenarios.json").read_text("utf-8"))
FORGED = json.loads((TESTDATA / "golden_forged.json").read_text("utf-8"))


def instance(ref: str) -> str:
    if ref.startswith("forged:"):
        return FORGED["documents"][ref[len("forged:") :]]
    n, flipped = re.fullmatch(r"live(\d)(-flipped)?", ref).groups()
    live = live_instances()[int(n)]
    if not flipped:
        return live
    doc = bytearray(base64.b64decode(live))
    doc[-1] ^= 1
    return base64.b64encode(doc).decode()


def response(spec: dict):
    if "instances" in spec:
        return reply([instance(i) for i in spec["instances"]])
    if "json" in spec:
        return lambda: httpx.Response(200, json=spec["json"])
    return lambda: httpx.Response(spec["status"], headers=spec.get("headers"), text=spec.get("body", ""))


def world_of(s: dict) -> World:
    statement = bytearray(STATEMENT)
    if s.get("list") == "290-changed":
        statement[-3] ^= 1
    log = LOG
    if "drop" in s.get("log", {}):
        log = "\0".join(LOG.split("\0")[s["log"]["drop"] :])
    if "replace" in s.get("log", {}):
        log = LOG.replace(*s["log"]["replace"], 1)
    tls = s.get("tls")
    build = s.get("build")
    return World(
        attestation=[response(r) for r in s["attestation"]] if "attestation" in s else None,
        list=(
            ("signed-280-20261106T080407Z", read("prod.statement.280.json"), read("prod.sigstore.280.json"))
            if s.get("list") == "280"
            else (TAG, bytes(statement), read("prod.sigstore.json"))
        ),
        log=log,
        git=s.get("git"),
        docker=s.get("docker"),
        build=Pcrs(build["pcr0"], build["pcr1"], build["pcr2"]) if isinstance(build, dict) else build,
        tls=None
        if tls is None
        else ConnectionError(tls["error"])
        if "error" in tls
        else ServedKey(tls["spkiSha256"], tls["issuer"]),
    )


def normalized(out: str) -> str:
    """The output with the temporary directories' random names written as XXXXXX."""
    return re.sub(r"(trymorse-verify-|/\d+-)[A-Za-z0-9]{6}", r"\g<1>XXXXXX", out)


@pytest.mark.parametrize("s", SCENARIOS["scenarios"], ids=lambda s: s["name"])
def test_prints_what_the_typescript_cli_prints(s, monkeypatch):
    monkeypatch.setenv("TMPDIR", SCENARIOS["tmpdir"])
    out: list[str] = []
    now = ms(s["world"].get("now", SCENARIOS["now"]))
    options = {**fake(world_of(s["world"])).options, "now": lambda: now}
    if s["world"].get("root") == "forged":
        options["root"] = parse_cert(base64.b64decode(FORGED["root"]))
    main(s["argv"], out=out.append, err=lambda _: None, **options)
    golden = (TESTDATA / "golden" / f"{s['name']}.txt").read_text("utf-8")
    header, rest = golden.split("\n", 1)
    assert header == "@askmorse/verify 0.0.0"
    assert normalized("".join(out)) == f"trymorse-verify 0.0.0\n{rest}"
