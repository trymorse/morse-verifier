// What verify() reaches, faked from the captures in testdata: api.trymorse.ai's attestation reply,
// the morse-pins release that was latest, morse-enclave's main, and api.trymorse.ai's TLS key, all
// as they were on 2026-11-06 at 10:35 UTC. Tests change one part at a time.
import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Exec, Ran } from "../node/io.ts";
import type { VerifyOptions } from "../node/verify.ts";
import type { Pcrs } from "../pins.ts";

const read = (name: string) =>
	readFileSync(new URL(`../testdata/${name}`, import.meta.url));

export const NOW = Date.parse("2026-11-06T10:40:00Z");
const ATTESTATION = read("live_attestation.json");
export const STATEMENT = read("prod.statement.json");
export const BUNDLE = read("prod.sigstore.json");
export const TAG = "signed-290-20261106T095152Z";
export const LOG = read("morse_enclave_main.txt").toString("utf8");
const API_SPKI = read("api_tls_spki_sha256.txt").toString().trim();

/** The image both enclaves ran, which v2026.11.4-pins-23c1570 (commit 696ab5a8) names. */
export const LIVE: Pcrs = {
	pcr0: "4fccf46baafdf7362402ef287d332e49db794e98d0a6fff6337c05915835160cd9b619c47d063d7b19e9e03eef6e1606",
	pcr1: "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03",
	pcr2: "de079dd37c0b9e8250e9529abd281d3f6cfb0a900ab9fc22e7c02d180c3f3f30bf56fc5ea17376be06faf6301c4d4f35",
};
export const LIVE_COMMIT = "696ab5a852e09f3ab11e49156f3892e02796db5a";

export interface World {
	/** The attestation replies, in order; the last one repeats. */
	attestation?: (() => Response)[];
	list?: { tag: string; statement: Uint8Array; bundle: Uint8Array };
	log?: string;
	git?: "missing";
	docker?: "missing" | "down" | string;
	/** What build.sh measures, or "fails". */
	build?: Pcrs | "fails";
	tls?: { spkiSha256: string; issuer: string } | Error;
}

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
	const list = world.list ?? { tag: TAG, statement: STATEMENT, bundle: BUNDLE };
	const releases = "https://github.com/trymorse/morse-pins/releases";

	const fetchFn = (async (input: string | URL | Request) => {
		const url = String(input);
		fetched.push(url);
		if (url === "https://api.trymorse.ai/v1/attestation") {
			const replies = world.attestation ?? [
				() => new Response(ATTESTATION, { status: 200 }),
			];
			return replies[Math.min(attestations++, replies.length - 1)]();
		}
		if (url === `${releases}/latest`)
			return new Response(null, {
				status: 302,
				headers: { location: `${releases}/tag/${list.tag}` },
			});
		if (url === `${releases}/download/${list.tag}/prod.statement.json`)
			return new Response(new Uint8Array(list.statement), { status: 200 });
		if (url === `${releases}/download/${list.tag}/prod.sigstore.json`)
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
