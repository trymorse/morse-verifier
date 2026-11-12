// Where each image's source is published: every release of the enclave is a commit on main of
// github.com/trymorse/morse-enclave (which a ruleset Morse set, and could change, keeps GitHub from
// rewriting or deleting), whose message is the release's name and the PCRs Morse's CI measured when
// it built it. By hand:
//   git clone --bare --filter=tree:0 --single-branch --branch main https://github.com/trymorse/morse-enclave enclave.git
//   git -C enclave.git log --format='%H %s' main            # each release, newest first
//   git -C enclave.git show -s --format=%B <commit>          # the PCRs its message names
import type { Pcrs } from "../pins.ts";
import {
	type Exec,
	gitEnv,
	isMissing,
	noGit,
	timedOut,
	Unfinished,
} from "./io.ts";

export const REPO = "github.com/trymorse/morse-enclave";

/** How long each git command may run. The clone is a few hundred KB, so a git still running then
 * is stuck, and would hold every check waiting on it. */
const GIT_TIMEOUT_MS = 60_000;

/** The message Morse's CI writes on each release commit, which Morse's sealing sidecar reads
 * too. */
const MESSAGE =
	/^(\S+)\n\nPCR0 ([0-9a-f]{96})\nPCR1 ([0-9a-f]{96})\nPCR2 ([0-9a-f]{96})\n(?:rootfs sha256 ([0-9a-f]{64})\n)?$/;

export interface Release {
	readonly name: string;
	readonly commit: string;
	readonly pcrs: Pcrs;
	readonly rootfs: string | null;
}

export const samePcrs = (a: Pcrs, b: Pcrs) =>
	a.pcr0 === b.pcr0 && a.pcr1 === b.pcr1 && a.pcr2 === b.pcr2;

/** The releases in the output of `git log -z --format=%H%n%B`, newest first. A commit whose message
 * is not a release's is left out. */
export function parseLog(log: string): Release[] {
	const releases: Release[] = [];
	for (const entry of log.split("\0")) {
		const newline = entry.indexOf("\n");
		const commit = entry.slice(0, newline);
		const message = entry.slice(newline + 1);
		const m = MESSAGE.exec(message.endsWith("\n") ? message : `${message}\n`);
		if (!/^[0-9a-f]{40}$/.test(commit) || !m) continue;
		releases.push({
			name: m[1],
			commit,
			pcrs: { pcr0: m[2], pcr1: m[3], pcr2: m[4] },
			rootfs: m[5] ?? null,
		});
	}
	return releases;
}

/** Clones main's commits (no files, a few hundred KB) into `clone` and reads its releases. */
export async function readReleases(
	exec: Exec,
	clone: string,
): Promise<Release[]> {
	const git = async (args: string[]) => {
		const verb = args[0] === "-C" ? args[2] : args[0];
		const ran = await exec("git", args, {
			env: gitEnv(),
			timeoutMs: GIT_TIMEOUT_MS,
		}).catch((e) => {
			if (isMissing(e)) throw new Unfinished(noGit("Source"));
			if (timedOut(e))
				throw new Unfinished(
					`git ${verb} of https://${REPO} didn't finish in ${GIT_TIMEOUT_MS / 1000} s. Check that this machine reaches github.com, and run again`,
				);
			throw e;
		});
		if (ran.code !== 0)
			throw new Unfinished(
				`git ${verb} of https://${REPO} failed: ${ran.tail.split("\n").at(-1)}`,
			);
		return ran.stdout;
	};
	await git([
		"clone",
		"--quiet",
		"--bare",
		"--filter=tree:0",
		"--single-branch",
		"--branch",
		"main",
		`https://${REPO}`,
		clone,
	]);
	return parseLog(
		await git(["-C", clone, "log", "-z", "--format=%H%n%B", "refs/heads/main"]),
	);
}

/** The release `x` names, if main has it: 40 hex by its commit alone, so no commit's subject can
 * stand in for a pinned commit, and anything else by its name (a commit's subject), newest first. */
export const findRelease = (releases: readonly Release[], x: string) =>
	releases.find((r) =>
		/^[0-9a-f]{40}$/.test(x) ? r.commit === x : r.name === x,
	);
