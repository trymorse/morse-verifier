// How the checks reach the network and run programs. Nothing here decides anything.
import { spawn } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { concat } from "../bytes.ts";

/** A check that could not run, so nothing past the last check that passed is proven (exit 2).
 * `lines` are details to print first, such as the end of a build's log. */
export class Unfinished extends Error {
	override name = "Unfinished";
	readonly lines: readonly string[];
	constructor(reason: string, lines: readonly string[] = []) {
		super(reason);
		this.lines = lines;
	}
}

const MAX_BODY = 1 << 20;

export interface Got {
	readonly status: number;
	readonly headers: Headers;
	readonly body: Uint8Array;
}

/** GETs `url` and reads at most 1 MiB of its body. A network error or a longer body is Unfinished. */
export async function get(
	fetchFn: typeof fetch,
	url: string,
	redirect: RequestRedirect = "error",
): Promise<Got> {
	let reply: Response;
	try {
		reply = await fetchFn(url, { redirect });
	} catch (e) {
		throw new Unfinished(`${url}: ${causeOf(e)}`);
	}
	const chunks: Uint8Array[] = [];
	let size = 0;
	const reader = reply.body?.getReader();
	for (;;) {
		const read = reader ? await reader.read() : { done: true as const };
		if (read.done) break;
		size += read.value.length;
		if (size > MAX_BODY) {
			await reader?.cancel();
			throw new Unfinished(`${url} sent more than 1 MiB`);
		}
		chunks.push(read.value);
	}
	return { status: reply.status, headers: reply.headers, body: concat(chunks) };
}

/** The JSON in `bytes`, or undefined if they hold none. */
export function json(bytes: Uint8Array): unknown {
	try {
		return JSON.parse(new TextDecoder().decode(bytes));
	} catch {
		return undefined;
	}
}

/** A new directory in the system's temporary one, named from `prefix`. When it can't be made, the
 * check can't run: Unfinished. */
export const tempDir = (prefix: string): Promise<string> =>
	mkdtemp(join(tmpdir(), prefix)).catch((e) => {
		throw new Unfinished(
			`it can't make a temporary directory in ${tmpdir()} (${(e as NodeJS.ErrnoException).code ?? causeOf(e)}). Set TMPDIR to a directory it can write, and run again`,
		);
	});

export const causeOf = (e: unknown): string => {
	const cause = e instanceof Error ? e.cause : undefined;
	if (cause instanceof Error) return cause.message;
	return e instanceof Error ? e.message : String(e);
};

export interface Ran {
	readonly code: number;
	readonly stdout: string;
	/** The last 20 lines of what the program printed. */
	readonly tail: string;
}

/** Runs a program with no shell. Rejects with `code: "ENOENT"` when it is not on PATH. With `log`,
 * copies everything it prints to stderr as it runs; without, keeps its stdout. With `timeoutMs`,
 * kills it once that long has passed and rejects with `code: "ETIMEDOUT"`. */
export type Exec = (
	command: string,
	args: readonly string[],
	options?: {
		readonly cwd?: string;
		readonly env?: NodeJS.ProcessEnv;
		readonly log?: boolean;
		readonly timeoutMs?: number;
	},
) => Promise<Ran>;

export const exec: Exec = (
	command,
	args,
	{ cwd, env, log = false, timeoutMs } = {},
) =>
	new Promise((resolve, reject) => {
		const child = spawn(command, args, {
			cwd,
			env,
			stdio: ["ignore", "pipe", "pipe"],
		});
		// A program it started can hold the pipes open after it is killed, so this rejects at once.
		const timer =
			timeoutMs === undefined
				? undefined
				: setTimeout(() => {
						child.kill("SIGKILL");
						child.stdout.destroy();
						child.stderr.destroy();
						reject(
							Object.assign(
								new Error(`${command} ran for more than ${timeoutMs} ms`),
								{ code: "ETIMEDOUT" },
							),
						);
					}, timeoutMs);
		let stdout = "";
		let tail = "";
		const keep = (text: string) => {
			tail = (tail + text).split("\n").slice(-21).join("\n");
			if (log) process.stderr.write(text);
		};
		child.stdout.setEncoding("utf8");
		child.stderr.setEncoding("utf8");
		child.stdout.on("data", (text: string) => {
			if (log) keep(text);
			else stdout += text;
		});
		child.stderr.on("data", keep);
		child.on("error", (e) => {
			clearTimeout(timer);
			reject(e);
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			resolve({ code: code ?? 1, stdout, tail: tail.trimEnd() });
		});
	});

// What `git rev-parse --local-env-vars` lists, and the rest that point git at another repository
// than the one named. Git sets some for its hooks, so a check run from a hook would read that one.
const ELSEWHERE = new Set([
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
]);

/** The environment every git command here runs in: this process's, without what points git at
 * another repository, and never prompting for a password. */
export const gitEnv = (): NodeJS.ProcessEnv => ({
	...Object.fromEntries(
		Object.entries(process.env).filter(([name]) => !ELSEWHERE.has(name)),
	),
	GIT_TERMINAL_PROMPT: "0",
});

export const isMissing = (e: unknown) =>
	(e as { code?: unknown } | null)?.code === "ENOENT";

/** Why `step` could not finish when git isn't on PATH. */
export const noGit = (step: string) =>
	`the ${step} check runs git, which isn't on this machine's PATH. Install git (https://git-scm.com) and run again`;

export const timedOut = (e: unknown) =>
	(e as { code?: unknown } | null)?.code === "ETIMEDOUT";
