// The command line: reads the arguments, prints each step verify() decides as it decides it, in
// plain text, and returns the exit code.
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import {
	DEFAULT_HOST,
	type Step,
	type VerifyOptions,
	verify,
} from "./verify.ts";

const LABEL = 13;
const WIDTH = 80;
const HOST = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;

export const USAGE = `Usage: npx @askmorse/verify [host] [--release <name|commit>] [--rebuild]

Checks that the enclaves <host> lists (default ${DEFAULT_HOST}) run an
image AWS Nitro signed for, that Morse's signed list allows, and whose source
is a commit on main of github.com/trymorse/morse-enclave.

  --release <x>  every enclave must run this release: a commit's subject, such
                 as v2026.11.4-pins-23c1570, or its 40-hex commit
  --rebuild      build each image here from its commit with Docker, and
                 compare its PCRs with the attested ones
  --version      print this verifier's version
  --help         print this

Exit 0: every check passed. 1: a check failed; don't send anything.
2: it could not finish, so nothing is proven.`;

/** This package's version: 0.0.0 in its source, the release's in what npm ships. */
const version = (): string =>
	(
		JSON.parse(
			readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
		) as { version: string }
	).version;

/** `text` in lines of at most `width` characters where its words allow, broken at spaces. */
export function wrap(text: string, width: number): string[] {
	const lines: string[] = [];
	let line = "";
	for (const word of text.split(" ")) {
		if (line && line.length + 1 + word.length > width) {
			lines.push(line);
			line = word;
		} else line = line ? `${line} ${word}` : word;
	}
	return [...lines, line];
}

/** `text` with each control character but a newline, and each bidi control, written as `\u{1b}`,
 * so nothing a document, a commit, or a program's log carries can move the cursor, hide a line, or
 * reorder one. */
export const shown = (text: string) =>
	text.replace(/[\p{Cc}\u202A-\u202E\u2066-\u2069]/gu, (c) =>
		c === "\n" ? c : `\\u{${c.charCodeAt(0).toString(16)}}`,
	);

/** A step as printed: its label in a 13-character column unless the step before had the same one
 * and this one neither failed nor stopped, and its text shown and wrapped to 80 characters. */
export function formatStep(step: Step, previous = ""): string[] {
	const showLabel =
		step.label !== previous ||
		step.status === "failed" ||
		step.status === "unfinished";
	return step.lines.flatMap((line, i) =>
		wrap(shown(line), WIDTH - LABEL).map(
			(part, j) =>
				(showLabel && i === 0 && j === 0 ? step.label : "").padEnd(LABEL) +
				part,
		),
	);
}

export interface Io {
	readonly out?: (text: string) => void;
	readonly err?: (text: string) => void;
}

export async function main(
	argv: readonly string[],
	options: Omit<VerifyOptions, "release" | "rebuild" | "onStep"> & Io = {},
): Promise<number> {
	const out = options.out ?? ((t: string) => process.stdout.write(t));
	const err = options.err ?? ((t: string) => process.stderr.write(t));
	let args: ReturnType<typeof parse>;
	try {
		args = parse(argv);
	} catch (e) {
		err(`${(e as Error).message}\n\n${USAGE}\n`);
		return 2;
	}
	if (args.values.help) {
		out(`${USAGE}\n`);
		return 0;
	}
	if (args.values.version) {
		out(`${version()}\n`);
		return 0;
	}
	const [host = options.host ?? DEFAULT_HOST, ...extra] = args.positionals;
	if (extra.length > 0 || !HOST.test(host)) {
		err(`Name one host, such as ${DEFAULT_HOST}.\n\n${USAGE}\n`);
		return 2;
	}

	out(`@askmorse/verify ${version()}\nChecking the enclaves ${host} lists\n\n`);
	let previous = "";
	const report = await verify({
		...options,
		host,
		release: args.values.release,
		rebuild: args.values.rebuild,
		onStep: (step) => {
			out(`${formatStep(step, previous).join("\n")}\n`);
			previous = step.label;
		},
	});
	out(
		`${previous ? "\n" : ""}${report.verdict.flatMap((line) => wrap(shown(line), WIDTH)).join("\n")}\n`,
	);
	return report.exitCode;
}

const parse = (argv: readonly string[]) =>
	parseArgs({
		args: [...argv],
		allowPositionals: true,
		options: {
			release: { type: "string" },
			rebuild: { type: "boolean", default: false },
			help: { type: "boolean", short: "h", default: false },
			version: { type: "boolean", default: false },
		},
	});
