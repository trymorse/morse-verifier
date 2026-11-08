// --rebuild: builds the release's enclave image (EIF) from its commit with that commit's own
// deploy/enclave/build.sh, and reads the PCRs nitro-cli measured. By hand:
//   git -C enclave.git archive --format=tar <commit> > src.tar
//   mkdir src && tar -xf src.tar -C src
//   bash src/deploy/enclave/build.sh eif src.tar rebuild prod out
//   jq .Measurements out/measurements.json
import { createHash } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Pcrs } from "../pins.ts";
import { type Exec, gitEnv, isMissing, noGit, Unfinished } from "./io.ts";

const HINT = [
	"A commit's build.sh builds the EIF on arm64 Linux, and newer ones on x86_64 Linux too.",
	"For an older commit on x86_64, enable arm64 emulation first: docker run --privileged --rm tonistiigi/binfmt --install arm64",
	"Docker Desktop on Apple silicon runs arm64 (untested).",
];

const pcr = (value: unknown) => {
	if (typeof value !== "string" || !/^[0-9a-f]{96}$/.test(value))
		throw new Unfinished("build.sh wrote no PCRs to measurements.json");
	return value;
};

/** Builds `commit` of the bare clone `clone` in `dir` and returns the PCRs of the EIF it built.
 * `notice` hears the commands that export and build it, before build.sh runs. */
export async function rebuild(
	exec: Exec,
	clone: string,
	commit: string,
	dir: string,
	notice: (lines: string[]) => void,
): Promise<Pcrs> {
	const docker = await exec("docker", [
		"version",
		"--format",
		"{{.Server.Arch}}",
	]).catch((e) => {
		throw isMissing(e)
			? new Unfinished(
					"--rebuild needs Docker, and docker isn't on this machine's PATH. Install Docker, or run without --rebuild",
				)
			: e;
	});
	if (docker.code !== 0)
		throw new Unfinished(
			`docker can't reach its daemon (${docker.tail.split("\n").at(-1)}). Start Docker and run again`,
		);

	const tar = join(dir, "src.tar");
	const src = join(dir, "src");
	const out = join(dir, "out");
	const archived = await exec(
		"git",
		["-C", clone, "archive", "--format=tar", "-o", tar, commit],
		{ env: gitEnv() },
	).catch((e) => {
		throw isMissing(e) ? new Unfinished(noGit("Rebuild")) : e;
	});
	if (archived.code !== 0)
		throw new Unfinished(`git archive ${commit} failed: ${archived.tail}`);
	await mkdir(src);
	const extracted = await exec("tar", ["-xf", tar, "-C", src]);
	if (extracted.code !== 0)
		throw new Unfinished(`tar could not extract ${tar}: ${extracted.tail}`);
	const script = join(src, "deploy/enclave/build.sh");
	const hash = createHash("sha256")
		.update(await readFile(script))
		.digest("hex");
	const args = [
		"src/deploy/enclave/build.sh",
		"eif",
		"src.tar",
		"rebuild",
		"prod",
		"out",
	];
	notice([
		`$ cd ${dir}`,
		`$ git -C ${clone} archive --format=tar ${commit} > src.tar`,
		"$ mkdir src && tar -xf src.tar -C src",
		`$ bash ${args.join(" ")}`,
		`build.sh sha256 ${hash}`,
		"This runs that commit's own build.sh, with access to the Docker daemon, which is root on this machine: run it on one you don't mind that on. Its log goes to stderr.",
	]);

	const { IMAGE_MIRROR: _, ...env } = process.env;
	const built = await exec("bash", args, { cwd: dir, env, log: true });
	if (built.code !== 0)
		throw new Unfinished(`build.sh exited ${built.code}`, [
			`build.sh exited ${built.code} on ${docker.stdout.trim() || "this"} Docker. Its log ended:`,
			...built.tail.split("\n").slice(-6),
			...HINT,
		]);
	let measured: { Measurements?: Record<string, unknown> };
	try {
		measured = JSON.parse(
			await readFile(join(out, "measurements.json"), "utf8"),
		) as typeof measured;
	} catch {
		throw new Unfinished("build.sh wrote no measurements.json");
	}
	const m = measured.Measurements ?? {};
	return { pcr0: pcr(m.PCR0), pcr1: pcr(m.PCR1), pcr2: pcr(m.PCR2) };
}
