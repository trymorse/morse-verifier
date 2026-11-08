# --rebuild: builds the release's enclave image (EIF) from its commit with that commit's own
# deploy/enclave/build.sh, and reads the PCRs nitro-cli measured. By hand:
#   git -C enclave.git archive --format=tar <commit> > src.tar
#   mkdir src && tar -xf src.tar -C src
#   bash src/deploy/enclave/build.sh eif src.tar rebuild prod out
#   jq .Measurements out/measurements.json
from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable

from .io import Exec, Unfinished, git_env, is_missing, no_git
from .nitro import Pcrs

HINT = [
    "A commit's build.sh builds the EIF on arm64 Linux, and newer ones on x86_64 Linux too.",
    "For an older commit on x86_64, enable arm64 emulation first: docker run --privileged --rm tonistiigi/binfmt --install arm64",
    "Docker Desktop on Apple silicon runs arm64 (untested).",
]
PCR = re.compile(r"[0-9a-f]{96}")


def _pcr(value: object) -> str:
    if not isinstance(value, str) or not PCR.fullmatch(value):
        raise Unfinished("build.sh wrote no PCRs to measurements.json")
    return value


def rebuild(exec: Exec, clone: str, commit: str, dir: str, notice: Callable[[list[str]], None]) -> Pcrs:
    """Builds `commit` of the bare clone `clone` in `dir` and returns the PCRs of the EIF it
    built. `notice` hears the commands that export and build it, before build.sh runs."""
    try:
        docker = exec("docker", ["version", "--format", "{{.Server.Arch}}"])
    except Exception as e:
        if is_missing(e):
            raise Unfinished(
                "--rebuild needs Docker, and docker isn't on this machine's PATH. Install Docker, or run without --rebuild"
            ) from e
        raise
    if docker.code != 0:
        raise Unfinished(
            f"docker can't reach its daemon ({docker.tail.split(chr(10))[-1]}). Start Docker and run again"
        )

    tar = os.path.join(dir, "src.tar")
    src = os.path.join(dir, "src")
    out = os.path.join(dir, "out")
    try:
        archived = exec("git", ["-C", clone, "archive", "--format=tar", "-o", tar, commit], env=git_env())
    except Exception as e:
        if is_missing(e):
            raise Unfinished(no_git("Rebuild")) from e
        raise
    if archived.code != 0:
        raise Unfinished(f"git archive {commit} failed: {archived.tail}")
    os.mkdir(src)
    extracted = exec("tar", ["-xf", tar, "-C", src])
    if extracted.code != 0:
        raise Unfinished(f"tar could not extract {tar}: {extracted.tail}")
    with open(os.path.join(src, "deploy/enclave/build.sh"), "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    args = ["src/deploy/enclave/build.sh", "eif", "src.tar", "rebuild", "prod", "out"]
    notice(
        [
            f"$ cd {dir}",
            f"$ git -C {clone} archive --format=tar {commit} > src.tar",
            "$ mkdir src && tar -xf src.tar -C src",
            f"$ bash {' '.join(args)}",
            f"build.sh sha256 {digest}",
            "This runs that commit's own build.sh, with access to the Docker daemon, which is root on this machine: run it on one you don't mind that on. Its log goes to stderr.",
        ]
    )

    env = {k: v for k, v in os.environ.items() if k != "IMAGE_MIRROR"}
    built = exec("bash", args, cwd=dir, env=env, log=True)
    if built.code != 0:
        raise Unfinished(
            f"build.sh exited {built.code}",
            [
                f"build.sh exited {built.code} on {docker.stdout.strip() or 'this'} Docker. Its log ended:",
                *built.tail.split("\n")[-6:],
                *HINT,
            ],
        )
    try:
        with open(os.path.join(out, "measurements.json"), encoding="utf-8") as f:
            measured = json.load(f)
    except (OSError, ValueError):
        raise Unfinished("build.sh wrote no measurements.json") from None
    m = measured.get("Measurements") if isinstance(measured, dict) else None
    m = m if isinstance(m, dict) else {}
    return Pcrs(_pcr(m.get("PCR0")), _pcr(m.get("PCR1")), _pcr(m.get("PCR2")))
