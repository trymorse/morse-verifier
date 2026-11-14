// What verify() reaches, faked from the captures in testdata: api.trymorse.ai's attestation reply,
// the newest prod list on morse-pins' statements/images branch, morse-enclave's main, and
// api.trymorse.ai's TLS key, all as they were on 2026-11-11 at 21:04 UTC. Tests change one part at
// a time.
import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Exec, Ran } from "../node/io.ts";
import { parseLog } from "../node/source.ts";
import type { VerifyOptions } from "../node/verify.ts";
import type { Pcrs } from "../pins.ts";

const read = (name: string) =>
	readFileSync(new URL(`../testdata/${name}`, import.meta.url));

export const NOW = Date.parse("2026-11-11T21:05:00Z");
const ATTESTATION = read("live_attestation.json");
export const STATEMENT = read("prod.statement.json");
export const BUNDLE = read("prod.sigstore.json");
export const LIST = "prod/288-20261111T143126Z";
export const STATEMENTS_COMMIT = "8ca79af1e6714d8705b61aec5503f96508f53873";
export const LOG = read("morse_enclave_main.txt").toString("utf8");
// List 254, signed before the live image was, which leaves images unrevoked that list 288 revokes.
export const LIST_254 = {
	name: "prod/254-20261110T101835Z",
	statement: read("prod.statement.254.json"),
	bundle: read("prod.sigstore.254.json"),
};
const API_SPKI = read("api_tls_spki_sha256.txt").toString().trim();

// Every image list 288 leaves unrevoked has a release on main, so a test of an allowed image
// whose source isn't published takes v2026.11.14's commit off main.
const withoutUnpublished = LOG.split("\0").filter(
	(entry) => parseLog(entry)[0]?.name !== "v2026.11.14",
);
export const UNPUBLISHED = (
	parseLog(LOG).find((r) => r.name === "v2026.11.14") as { pcrs: Pcrs }
).pcrs;
export const LOG_WITHOUT_UNPUBLISHED = withoutUnpublished.join("\0");

// The image both enclaves ran, which v2026.11.15 (commit e6cdc422) names.
export const LIVE: Pcrs = {
	pcr0: "75b4ee3b48971c27c2e00b9466a1d7e36b8db72d119c8e4cd0c95840b9b9c07cca87bf7e4ab27cff2c796fedd0619cbf",
	pcr1: "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03",
	pcr2: "7a04e791a60c5f103767b90b83ac5f8d8e40caa0869b15c9dcd466913ac43c8a9110749976ee1de08e54ba66645dee72",
};
export const LIVE_COMMIT = "e6cdc422958266cedd937171bc7a3ba35618b225";

export interface World {
	/** The attestation replies, in order; the last one repeats. */
	attestation?: (() => Response)[];
	list?: { name: string; statement: Uint8Array; bundle: Uint8Array };
	log?: string;
	git?: "missing";
	docker?: "missing" | "down" | string;
	/** What build.sh measures, or "fails". */
	build?: Pcrs | "fails";
	tls?: { spkiSha256: string; issuer: string } | Error;
}

export const REFS =
	"https://github.com/trymorse/morse-pins.git/info/refs?service=git-upload-pack";

const pkt = (line: string | null) =>
	line === null
		? "0000"
		: (line.length + 4).toString(16).padStart(4, "0") + line;

// GitHub's ref advertisement of morse-pins, its branches at the capture's commits.
export const advertisement = (
	statements = STATEMENTS_COMMIT,
	branch = "refs/heads/statements/images",
) =>
	[
		pkt("# service=git-upload-pack\n"),
		pkt(null),
		pkt(
			"fabdad92a921967d8f05058ed9baf747ca4e4685 HEAD\0multi_ack thin-pack side-band side-band-64k ofs-delta symref=HEAD:refs/heads/main\n",
		),
		pkt("fabdad92a921967d8f05058ed9baf747ca4e4685 refs/heads/main\n"),
		pkt(`${statements} ${branch}\n`),
		pkt(null),
	].join("");

// prod/index.json with the one list `name`, as sign.yml writes an entry.
const indexOf = (name: string) => {
	const [, sequence, d, t] = /^prod\/(\d+)-(\d{8})T(\d{6})Z$/.exec(name) ?? [];
	const time = `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6)}T${t.slice(0, 2)}:${t.slice(2, 4)}:${t.slice(4)}Z`;
	return [
		{
			sequence: Number(sequence),
			time,
			statement: `${name}.statement.json`,
			bundle: `${name}.sigstore.json`,
		},
	];
};

const ran = (stdout = "", code = 0, tail = ""): Ran => ({ code, stdout, tail });
const missing = (command: string) =>
	Object.assign(new Error(`spawn ${command} ENOENT`), { code: "ENOENT" });

/** verify()'s options for `world`, and every request and program it makes, with each program's
 * environment. */
export function fake(world: World = {}) {
	const fetched: string[] = [];
	const ranCommands: string[][] = [];
	const envs: (NodeJS.ProcessEnv | undefined)[] = [];
	const slept: number[] = [];
	let attestations = 0;
	const list = world.list ?? {
		name: LIST,
		statement: STATEMENT,
		bundle: BUNDLE,
	};
	const raw = `https://raw.githubusercontent.com/trymorse/morse-pins/${STATEMENTS_COMMIT}`;

	const fetchFn = (async (input: string | URL | Request) => {
		const url = String(input);
		fetched.push(url);
		if (url === "https://api.trymorse.ai/v1/attestation") {
			const replies = world.attestation ?? [
				() => new Response(ATTESTATION, { status: 200 }),
			];
			return replies[Math.min(attestations++, replies.length - 1)]();
		}
		if (url === REFS) return new Response(advertisement(), { status: 200 });
		if (url === `${raw}/prod/index.json`)
			return Response.json(indexOf(list.name));
		if (url === `${raw}/${list.name}.statement.json`)
			return new Response(new Uint8Array(list.statement), { status: 200 });
		if (url === `${raw}/${list.name}.sigstore.json`)
			return new Response(new Uint8Array(list.bundle), { status: 200 });
		return new Response("not found", { status: 404 });
	}) as typeof fetch;

	const exec: Exec = async (command, args, { cwd = "", env } = {}) => {
		ranCommands.push([command, ...args]);
		envs.push(env);
		if (command === "git") {
			if (world.git === "missing") throw missing("git");
			if (args[0] === "clone") return ran();
			if (args.includes("log")) return ran(world.log ?? LOG);
			if (args.includes("archive")) {
				await writeFile(args[args.indexOf("-o") + 1], "a tar");
				return ran();
			}
		}
		if (command === "docker") {
			if (world.docker === "missing") throw missing("docker");
			if (world.docker === "down")
				return ran(
					"",
					1,
					"Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
				);
			return ran(`${world.docker ?? "arm64"}\n`);
		}
		if (command === "tar") {
			const script = join(args[args.indexOf("-C") + 1], "deploy/enclave");
			await mkdir(script, { recursive: true });
			await writeFile(join(script, "build.sh"), "#!/bin/bash\n");
			return ran();
		}
		if (command === "bash") {
			if (world.build === "fails")
				return ran(
					"",
					1,
					"rootfs sha256 7ca659b2\nexec /usr/bin/bash: exec format error",
				);
			const pcrs = world.build ?? LIVE;
			await mkdir(join(cwd, args[5]), { recursive: true });
			await writeFile(
				join(cwd, args[5], "measurements.json"),
				JSON.stringify({
					Measurements: {
						HashAlgorithm: "Sha384 { ... }",
						PCR0: pcrs.pcr0,
						PCR1: pcrs.pcr1,
						PCR2: pcrs.pcr2,
					},
				}),
			);
			return ran();
		}
		throw new Error(`the test runs no ${command}`);
	};

	const options = {
		// The captures are api.trymorse.ai's, so the world is that host's, not the default one.
		host: "api.trymorse.ai",
		fetch: fetchFn,
		exec,
		now: () => NOW,
		sleep: async (ms: number) => {
			slept.push(ms);
		},
		tls: async () => {
			if (world.tls instanceof Error) throw world.tls;
			return (
				world.tls ?? { spkiSha256: API_SPKI, issuer: "Amazon RSA 2048 M04" }
			);
		},
	} satisfies VerifyOptions;
	return { options, fetched, ran: ranCommands, envs, slept };
}

/** The capture's attestation reply with its instances replaced. */
export const reply = (instances: string[]) => () =>
	Response.json({
		object: "proxy_attestation",
		environment: "prod",
		instances,
		proxy_time: 1793961340,
	});

export const liveInstances = (): string[] =>
	(JSON.parse(ATTESTATION.toString("utf8")) as { instances: string[] })
		.instances;
