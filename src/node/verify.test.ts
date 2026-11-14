import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { x25519 } from "@noble/curves/ed25519.js";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { type Bytes, fromBase64, toBase64 } from "../bytes.ts";
import type { Pcrs } from "../pins.ts";
import { forgeNitro } from "../testing/forge.ts";
import {
	advertisement,
	fake,
	LIST,
	LIST_254,
	LIVE,
	LIVE_COMMIT,
	LOG,
	LOG_WITHOUT_UNPUBLISHED,
	liveInstances,
	NOW,
	REFS,
	reply,
	STATEMENT,
	STATEMENTS_COMMIT,
	UNPUBLISHED,
	type World,
} from "../testing/world.ts";
import { parseLog, type Release } from "./source.ts";
import { type Report, verify } from "./verify.ts";

const MINUTE = 60_000;
const read = (name: string) =>
	new Uint8Array(readFileSync(new URL(`../testdata/${name}`, import.meta.url)));
const check = (world: World = {}, o: Parameters<typeof verify>[0] = {}) =>
	verify({ ...fake(world).options, ...o });
/** The step a report stopped at, and the lines it printed there. */
const last = (r: Report) => r.steps.at(-1);

describe("verify(), on the captures from 2026-11-11", () => {
	it("passes every check, and pins the commit both enclaves run", async () => {
		const r = await check();
		expect(r.exitCode).toBe(0);
		expect(r.steps.map((s) => [s.label, s.status])).toEqual([
			["Attestation", "passed"],
			["Allowed", "passed"],
			["Source", "passed"],
			["Rebuild", "not run"],
			["TLS", "info"],
		]);
		expect(r.images).toHaveLength(1);
		expect(r.images[0]).toMatchObject({
			pcrs: LIVE,
			release: { name: "v2026.11.15", commit: LIVE_COMMIT },
			rebuilt: false,
		});
		expect(r.images[0].enclaves.map((e) => e.moduleId)).toEqual([
			"i-015c22f85232d8af3-enc01a1ca0de87771e5",
			"i-0d45a659f78879f74-enc01a1ca0eee2be5d3",
		]);
		expect(r.list).toMatchObject({
			sequence: 288,
			logIndex: "194111814",
			signedAt: Date.parse("2026-11-11T14:31:53Z"),
			witnesses: 4,
		});
	});

	it("could not finish when it can't make its temporary directory", async () => {
		vi.stubEnv("TMPDIR", "/proc/nope");
		try {
			const r = await check();
			expect(r.exitCode).toBe(2);
			expect(r.verdict).toEqual([
				expect.stringMatching(
					/^Could not finish: it can't make a temporary directory in \/proc\/nope \(ENOENT\)\. Set TMPDIR to a directory it can write, and run again\. Nothing was checked\.$/,
				),
			]);
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("reaches only the host, morse-pins' statements branch, and git", async () => {
		const world = fake();
		await verify(world.options);
		const raw = `https://raw.githubusercontent.com/trymorse/morse-pins/${STATEMENTS_COMMIT}`;
		expect(world.fetched).toEqual([
			"https://api.trymorse.ai/v1/attestation",
			REFS,
			`${raw}/prod/index.json`,
			`${raw}/${LIST}.statement.json`,
			`${raw}/${LIST}.sigstore.json`,
		]);
		expect(world.ran.map((c) => c.slice(0, 3))).toEqual([
			["git", "clone", "--quiet"],
			["git", "-C", expect.stringMatching(/enclave\.git$/)],
		]);
	});

	it("checks the API key door unless it's named another host", async () => {
		const world = fake();
		await verify({ ...world.options, host: undefined });
		expect(world.fetched[0]).toBe(
			"https://inference.trymorse.ai/v1/attestation",
		);
	});
});

describe("Attestation", () => {
	it("fails a document whose signature has one byte changed, naming its enclave", async () => {
		const [first, second] = liveInstances();
		const doc = fromBase64(first) as Bytes;
		doc[doc.length - 1] ^= 1;
		const r = await check({ attestation: [reply([toBase64(doc), second])] });
		expect(r.exitCode).toBe(1);
		expect(last(r)).toEqual({
			label: "Attestation",
			status: "failed",
			lines: [
				"FAILED: enclave i-015c22f85232d8af3-enc01a1ca0de87771e5: the document's signature does not verify",
			],
		});
		expect(r.verdict).toEqual([
			"Failed at Attestation. Don't send anything to these enclaves.",
		]);
	});

	it.each([
		[
			"31 minutes after the older one",
			Date.parse("2026-11-11T21:23:30Z"),
			/31 minutes old/,
		],
		[
			"6 minutes before the newer one",
			Date.parse("2026-11-11T20:55:00Z"),
			/6 minutes ahead of this device's clock/,
		],
	])("fails the documents on a clock %s", async (_, at, reason) => {
		const r = await check({}, { now: () => at });
		expect(r.exitCode).toBe(1);
		expect(last(r)?.label).toBe("Attestation");
		expect(last(r)?.lines[0]).toMatch(reason);
	});

	it("fails a host that lists no enclave, and one that answers with something else", async () => {
		const none = await check({ attestation: [reply([])] });
		expect(last(none)?.lines).toEqual([
			"FAILED: api.trymorse.ai lists no enclave",
		]);
		const other = await check({
			attestation: [() => Response.json({ object: "list", data: [] })],
		});
		expect(last(other)?.lines).toEqual([
			"FAILED: https://api.trymorse.ai/v1/attestation is not a list of enclaves",
		]);
		expect([none.exitCode, other.exitCode]).toEqual([1, 1]);
	});

	it("waits once as a 429 asks, then checks the second reply", async () => {
		const world = fake({
			attestation: [
				() =>
					new Response("slow down", {
						status: 429,
						headers: { "retry-after": "7" },
					}),
				reply(liveInstances()),
			],
		});
		const r = await verify(world.options);
		expect(world.slept).toEqual([7000]);
		expect(r.exitCode).toBe(0);
	});

	it("could not finish when the host is still rate-limiting, or unreachable", async () => {
		const limited = await check({
			attestation: [
				() =>
					new Response("", { status: 429, headers: { "retry-after": "600" } }),
			],
		});
		expect(limited.exitCode).toBe(2);
		expect(limited.verdict).toEqual([
			"Could not finish: api.trymorse.ai is rate-limiting this address (60 requests a minute). Run again in a minute. Nothing was checked.",
		]);
		const down = await check({
			attestation: [
				() => {
					throw new TypeError("fetch failed", {
						cause: new Error("getaddrinfo ENOTFOUND api.trymorse.ai"),
					});
				},
			],
		});
		expect(down.exitCode).toBe(2);
		expect(down.verdict[0]).toBe(
			"Could not finish: https://api.trymorse.ai/v1/attestation: getaddrinfo ENOTFOUND api.trymorse.ai. Nothing was checked.",
		);
	});
});

describe("Allowed", () => {
	it("fails when one byte of the signed list changed", async () => {
		const statement = Uint8Array.from(STATEMENT);
		statement[statement.length - 3] ^= 1;
		const r = await check({
			list: { name: LIST, statement, bundle: read("prod.sigstore.json") },
		});
		expect(r.exitCode).toBe(1);
		expect(last(r)?.lines).toEqual([
			"FAILED: Morse's signed list prod/288-20261111T143126Z names a digest other than the statement's SHA-256",
		]);
	});

	it("fails the list Morse's private signer signed, which it no longer trusts", async () => {
		const r = await check({
			list: {
				name: LIST,
				statement: read("private.statement.290.json"),
				bundle: read("private.sigstore.290.json"),
			},
		});
		expect(r.exitCode).toBe(1);
		expect(last(r)?.lines).toEqual([
			"FAILED: Morse's signed list prod/288-20261111T143126Z was signed as URI:https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main, not Morse's pins workflow",
		]);
	});

	it("fails an image the signed list does not name: list 254, signed before the live image was", async () => {
		const r = await check({ list: LIST_254 });
		expect(r.exitCode).toBe(1);
		expect(last(r)).toEqual({
			label: "Allowed",
			status: "failed",
			lines: [
				"FAILED: enclave i-015c22f85232d8af3-enc01a1ca0de87771e5 runs PCR0 75b4ee3b4897…d0619cbf, which is not on Morse's signed list",
			],
		});
	});

	it("could not finish when morse-pins advertises no statements branch", async () => {
		const world = fake();
		const r = await verify({
			...world.options,
			fetch: (async (url: string) =>
				String(url) === REFS
					? new Response(advertisement(STATEMENTS_COMMIT, "refs/heads/other"))
					: world.options.fetch(url)) as typeof fetch,
		});
		expect(r.exitCode).toBe(2);
		expect(r.verdict[0]).toMatch(
			/^Could not finish: .*advertises no refs\/heads\/statements\/images, so no signed list\. Nothing was checked\.$/,
		);
	});
});

// AWS's root can't sign test documents, so these forge documents under a test root, with the PCRs
// of images on list 288.
describe("forged documents of other images", () => {
	let forge: Awaited<ReturnType<typeof forgeNitro>>;
	beforeAll(async () => {
		forge = await forgeNitro(new Date(NOW));
	});
	const instance = async (pcrs: Pcrs, minutesAgo = 1) =>
		toBase64(
			await forge.document({
				timestamp: NOW - minutesAgo * MINUTE,
				publicKey: x25519.getPublicKey(x25519.utils.randomSecretKey()) as Bytes,
				environment: "prod",
				pcrs,
			}),
		);
	const withDocs = async (pcrs: Pcrs[], world: World = {}, o = {}) =>
		check(
			{
				...world,
				attestation: [
					reply(await Promise.all(pcrs.map((p, i) => instance(p, i + 1)))),
				],
			},
			{ root: forge.root, ...o },
		);
	const [, older] = parseLog(LOG);
	const revoked = (
		JSON.parse(STATEMENT.toString()) as {
			images: (Pcrs & { revoked: boolean })[];
		}
	).images.find((i) => i.revoked) as Pcrs;

	it("fails an image Morse revoked", async () => {
		const r = await withDocs([revoked]);
		expect(r.exitCode).toBe(1);
		expect(last(r)?.lines).toEqual([
			"FAILED: enclave i-0123-enc0123 runs PCR0 044207f79a70…c5c342d8, which is on Morse's signed list, but Morse revoked it",
		]);
	});

	it("fails a debug-mode enclave's all-zero PCRs at Attestation, saying so", async () => {
		const zero = "0".repeat(96);
		const r = await withDocs([{ pcr0: zero, pcr1: zero, pcr2: zero }]);
		expect(r.exitCode).toBe(1);
		expect(last(r)).toEqual({
			label: "Attestation",
			status: "failed",
			lines: [
				"FAILED: enclave i-0123-enc0123: the enclave reports all-zero PCRs, so it runs in debug mode",
			],
		});
	});

	it("prints a block for each image when the enclaves run two", async () => {
		const r = await withDocs([LIVE, older.pcrs]);
		expect(r.exitCode).toBe(0);
		expect(r.steps.map((s) => s.label)).toEqual([
			"Attestation",
			"Image 1",
			"Allowed",
			"Source",
			"Rebuild",
			"Image 2",
			"Allowed",
			"Source",
			"Rebuild",
			"TLS",
		]);
		expect(r.steps[0].lines.slice(1)).toEqual([
			expect.stringMatching(/^key [0-9a-f]{16}, signed 1 min ago, image 1$/),
			expect.stringMatching(/^key [0-9a-f]{16}, signed 2 min ago, image 2$/),
		]);
		expect(r.steps[7].lines[0]).toBe(
			"v2026.11.14-pins-a6556e9, commit 2e667dcb138a on main of github.com/trymorse/morse-enclave, names these PCRs",
		);
		expect(r.verdict).toEqual([
			"Passed. The enclaves api.trymorse.ai lists run v2026.11.15 and v2026.11.14-pins-a6556e9 of github.com/trymorse/morse-enclave, as published (not rebuilt here).",
		]);
	});

	it("names the newest commit of an image's PCRs as its source, and the others too", async () => {
		const shared = parseLog(LOG).find(
			(r) => r.name === "v2026.11.3-pins-66a50eb",
		) as Release;
		const r = await withDocs([shared.pcrs], { list: LIST_254 });
		expect(r.exitCode).toBe(0);
		expect(r.steps.find((s) => s.label === "Source")?.lines).toEqual([
			"v2026.11.3-pins-66a50eb, commit 33a690c92568 on main of github.com/trymorse/morse-enclave, names these PCRs",
			"and so do v2026.11.3-pins-c076991",
		]);
	});

	it("rebuilds the commit --release pins, not a newer one that names its PCRs too, and names it", async () => {
		const pinned = parseLog(LOG).find(
			(r) => r.name === "v2026.11.3-pins-c076991",
		) as Release;
		const world = fake({
			attestation: [reply([await instance(pinned.pcrs)])],
			build: pinned.pcrs,
			list: LIST_254,
		});
		const r = await verify({
			...world.options,
			root: forge.root,
			release: pinned.commit,
			rebuild: true,
		});
		expect(r.exitCode).toBe(0);
		expect(r.steps.find((s) => s.label === "Source")?.lines).toEqual([
			"v2026.11.3-pins-66a50eb, commit 33a690c92568 on main of github.com/trymorse/morse-enclave, names these PCRs",
			"and so do v2026.11.3-pins-c076991",
		]);
		expect(
			world.ran.filter((c) => c.includes("archive")).map((c) => c.at(-1)),
		).toEqual([pinned.commit]);
		expect(r.steps.find((s) => s.label === "Rebuild")?.lines[1]).toContain(
			` archive --format=tar ${pinned.commit} > src.tar`,
		);
		expect(r.verdict).toEqual([
			"Passed. The enclaves api.trymorse.ai lists run v2026.11.3-pins-c076991 of github.com/trymorse/morse-enclave, which rebuilds here to the same PCRs.",
			`Pin this release in CI: --release ${pinned.commit}`,
		]);
	});

	it("fails --release while a deploy has the enclaves on two releases, naming each", async () => {
		const r = await withDocs(
			[LIVE, older.pcrs],
			{},
			{ release: "v2026.11.15" },
		);
		expect(r.exitCode).toBe(1);
		expect(last(r)?.label).toBe("Release");
		expect(last(r)?.lines.slice(1, 3)).toEqual([
			expect.stringMatching(/^key [0-9a-f]{16} runs v2026\.11\.15$/),
			expect.stringMatching(
				/^key [0-9a-f]{16} runs v2026\.11\.14-pins-a6556e9$/,
			),
		]);
		expect(last(r)?.lines[3]).toBe(
			"A deploy replaces one enclave at a time, so for a few minutes after one the enclaves run two releases. Run again.",
		);
	});

	// One HPKE key in two documents at two images: each document is checked at its own PCRs, so
	// an older one's image skips no check behind a newer one's.
	describe("of one key", () => {
		const key = x25519.getPublicKey(x25519.utils.randomSecretKey()) as Bytes;
		const keyId = createHash("sha256").update(key).digest("hex").slice(0, 16);
		const tlsKey = new Uint8Array(91).fill(7) as Bytes;
		const sharing = async (
			pcrs: Pcrs[],
			world: World = {},
			o: Parameters<typeof verify>[0] = {},
		) =>
			check(
				{
					...world,
					attestation: [
						reply(
							await Promise.all(
								pcrs.map(async (p, i) =>
									toBase64(
										await forge.document({
											timestamp: NOW - (i + 1) * MINUTE,
											publicKey: key,
											environment: "prod",
											pcrs: p,
											tlsKey: i === 1 ? tlsKey : undefined,
										}),
									),
								),
							),
						),
					],
				},
				{ root: forge.root, ...o },
			);
		it("counts one enclave, and checks the source of the older document's image too", async () => {
			const r = await sharing([LIVE, UNPUBLISHED], {
				log: LOG_WITHOUT_UNPUBLISHED,
			});
			expect(r.exitCode).toBe(1);
			expect(r.steps[0].lines.slice(0, 2)).toEqual([
				expect.stringMatching(/^1 enclave, signed by AWS Nitro /),
				`key ${keyId}, signed 1 min ago, images 1 and 2`,
			]);
			expect(r.steps.map((s) => [s.label, s.status])).toEqual([
				["Attestation", "passed"],
				["Image 1", "info"],
				["Allowed", "passed"],
				["Source", "passed"],
				["Rebuild", "not run"],
				["Image 2", "info"],
				["Allowed", "passed"],
				["Source", "failed"],
			]);
			expect(r.images.map((im) => im.enclaves.map((e) => e.keyId))).toEqual([
				[keyId],
				[keyId],
			]);
		});

		it("fails --release when the older document runs another release", async () => {
			const r = await sharing(
				[LIVE, older.pcrs],
				{},
				{
					release: "v2026.11.15",
				},
			);
			expect(r.exitCode).toBe(1);
			expect(last(r)?.label).toBe("Release");
			expect(last(r)?.lines.slice(1, 3)).toEqual([
				`key ${keyId} runs v2026.11.15`,
				`key ${keyId} runs v2026.11.14-pins-a6556e9`,
			]);
		});

		it("rebuilds the older document's image too", async () => {
			const r = await sharing([LIVE, older.pcrs], {}, { rebuild: true });
			expect(r.exitCode).toBe(1);
			expect(r.steps.map((s) => [s.label, s.status]).slice(-4)).toEqual([
				["Allowed", "passed"],
				["Source", "passed"],
				["Rebuild", "info"],
				["Rebuild", "failed"],
			]);
			expect(last(r)?.lines[0]).toBe(
				"FAILED: commit 2e667dcb138a rebuilds here to other PCRs than the enclaves attest:",
			);
		});

		it("names both releases, and finds the TLS key the older document attests", async () => {
			const r = await sharing([LIVE, older.pcrs], {
				tls: {
					spkiSha256: createHash("sha256").update(tlsKey).digest("hex"),
					issuer: "i-0123",
				},
			});
			expect(r.exitCode).toBe(0);
			expect(last(r)?.lines[0]).toMatch(
				/^this connection to api\.trymorse\.ai ended inside an attested enclave/,
			);
			expect(r.verdict[0]).toBe(
				"Passed. The enclaves api.trymorse.ai lists run v2026.11.15 and v2026.11.14-pins-a6556e9 of github.com/trymorse/morse-enclave, as published (not rebuilt here).",
			);
		});
	});

	it("fails an enclave whose user_data names a dev key", async () => {
		const doc = await forge.document({
			timestamp: NOW - MINUTE,
			publicKey: new Uint8Array(32) as Bytes,
			environment: "dev",
			pcrs: LIVE,
		});
		const r = await check(
			{ attestation: [reply([toBase64(doc)])] },
			{ root: forge.root },
		);
		expect(last(r)?.lines).toEqual([
			expect.stringMatching(
				/^FAILED: enclave i-0123-enc0123: user_data does not name a prod key/,
			),
		]);
	});
});

describe("Source", () => {
	it("fails an image no commit on main names", async () => {
		const log = LOG.split("\0").slice(1).join("\0");
		const r = await check({ log });
		expect(r.exitCode).toBe(1);
		expect(last(r)?.lines).toEqual([
			"FAILED: no commit on main of github.com/trymorse/morse-enclave names PCR0 75b4ee3b4897…d0619cbf: its source isn't published. If Morse is mid-deploy it appears within minutes; run again. Until then, don't send it anything.",
		]);
	});

	it("runs git on its own clone, whatever repository a git hook's environment names", async () => {
		vi.stubEnv("GIT_DIR", "/elsewhere/.git");
		vi.stubEnv("GIT_WORK_TREE", "/elsewhere");
		vi.stubEnv("GIT_INDEX_FILE", "/elsewhere/.git/index");
		try {
			const world = fake();
			const r = await verify({ ...world.options, rebuild: true });
			expect(r.exitCode).toBe(0);
			const git = world.ran.flatMap(([c], i) =>
				c === "git" ? [world.envs[i]] : [],
			);
			expect(git).toHaveLength(3);
			for (const env of git) {
				expect(env?.GIT_TERMINAL_PROMPT).toBe("0");
				expect(env).not.toHaveProperty("GIT_DIR");
				expect(env).not.toHaveProperty("GIT_WORK_TREE");
				expect(env).not.toHaveProperty("GIT_INDEX_FILE");
			}
			expect(world.ran.find((c) => c.includes("log"))?.at(-1)).toBe(
				"refs/heads/main",
			);
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("could not finish without git, naming the step that runs it", async () => {
		const r = await check({ git: "missing" });
		expect(r.exitCode).toBe(2);
		expect(r.verdict[0]).toMatch(
			/^Could not finish: the Source check runs git, .* Nothing was checked past Allowed\.$/,
		);

		const world = fake();
		const gone = await verify({
			...world.options,
			rebuild: true,
			exec: (command, args, options) =>
				command === "git" && args.includes("archive")
					? Promise.reject(
							Object.assign(new Error("spawn git ENOENT"), { code: "ENOENT" }),
						)
					: world.options.exec(command, args, options),
		});
		expect(gone.exitCode).toBe(2);
		expect(gone.verdict[0]).toMatch(
			/^Could not finish: the Rebuild check runs git, .* Nothing was checked past Source\.$/,
		);
	});
});

describe("--release", () => {
	it.each([
		["its name", "v2026.11.15"],
		["its commit", LIVE_COMMIT],
	])("passes when every enclave runs the release, named by %s", async (_, release) => {
		const r = await check({}, { release });
		expect(r.exitCode).toBe(0);
		expect(r.steps.find((s) => s.label === "Release")?.lines).toEqual([
			"every enclave runs v2026.11.15, commit e6cdc4229582, as --release asks",
		]);
	});

	it("fails when the enclaves run another release", async () => {
		const r = await check({}, { release: "v2026.11.14-pins-a6556e9" });
		expect(r.exitCode).toBe(1);
		expect(last(r)?.lines).toEqual([
			"FAILED: --release names v2026.11.14-pins-a6556e9, commit 2e667dcb138a, but not every enclave runs it:",
			"key b7b56034a2a03576 runs v2026.11.15",
			"key f6bad5f9a3f183f6 runs v2026.11.15",
			"They run another release. Read it, and pin its commit to accept it.",
		]);
	});

	it("could not finish for a release main does not have", async () => {
		const r = await check({}, { release: "v1.8.2" });
		expect(r.exitCode).toBe(2);
		expect(r.verdict).toEqual([
			"Could not finish: no release v1.8.2 on main of github.com/trymorse/morse-enclave; see https://github.com/trymorse/morse-enclave/commits/main. Nothing was checked past Source.",
		]);
	});
});

describe("--rebuild", () => {
	it("passes when the commit rebuilds to the attested PCRs, after saying what it runs", async () => {
		const world = fake();
		const r = await verify({ ...world.options, rebuild: true });
		expect(r.exitCode).toBe(0);
		const rebuild = r.steps.filter((s) => s.label === "Rebuild");
		expect(rebuild.map((s) => s.status)).toEqual(["info", "passed"]);
		expect(rebuild[0].lines).toEqual([
			expect.stringMatching(/^\$ cd \S+trymorse-verify-\w+\/1-\w+$/),
			expect.stringMatching(
				new RegExp(
					`^\\$ git -C \\S+trymorse-verify-\\w+/enclave\\.git archive --format=tar ${LIVE_COMMIT} > src\\.tar$`,
				),
			),
			"$ mkdir src && tar -xf src.tar -C src",
			"$ bash src/deploy/enclave/build.sh eif src.tar rebuild prod out",
			"build.sh sha256 b875f928546aee7855cb1db9afc8ab3f1a8a34d43de5bbd62f7076d7ba9f3917",
			"This runs that commit's own build.sh, with access to the Docker daemon, which is root on this machine: run it on one you don't mind that on. Its log goes to stderr.",
		]);
		expect(rebuild[1].lines).toEqual([
			"rebuilt here: PCR0, PCR1, and PCR2 match",
		]);
		expect(r.verdict[0]).toBe(
			"Passed. The enclaves api.trymorse.ai lists run v2026.11.15 of github.com/trymorse/morse-enclave, which rebuilds here to the same PCRs.",
		);
		expect(world.ran.map((c) => c[0])).toEqual([
			"git",
			"git",
			"docker",
			"git",
			"tar",
			"bash",
		]);
		expect(world.ran[3]).toEqual([
			"git",
			"-C",
			expect.stringMatching(/enclave\.git$/),
			"archive",
			"--format=tar",
			"-o",
			expect.stringMatching(/src\.tar$/),
			LIVE_COMMIT,
		]);
	});

	it("fails when the commit rebuilds to other PCRs", async () => {
		const r = await check(
			{ build: { ...LIVE, pcr2: "0".repeat(96) } },
			{ rebuild: true },
		);
		expect(r.exitCode).toBe(1);
		expect(last(r)?.lines).toEqual([
			"FAILED: commit e6cdc4229582 rebuilds here to other PCRs than the enclaves attest:",
			"PCR0 75b4ee3b4897…d0619cbf",
			"PCR1 3b4a7e1b5f13…a0974d03",
			"PCR2 000000000000…00000000",
		]);
	});

	it.each([
		[
			"without Docker",
			{ docker: "missing" },
			/^Could not finish: --rebuild needs Docker, and docker isn't on this machine's PATH/,
		],
		[
			"when Docker's daemon is down",
			{ docker: "down" },
			/^Could not finish: docker can't reach its daemon \(Cannot connect to the Docker daemon/,
		],
	] as const)("could not finish %s", async (_, world, reason) => {
		const r = await check(world, { rebuild: true });
		expect(r.exitCode).toBe(2);
		expect(r.verdict[0]).toMatch(reason);
		expect(r.verdict[0]).toMatch(/Nothing was checked past Source\.$/);
	});

	it("could not finish when build.sh fails, with the end of its log and how to build on x86_64", async () => {
		const r = await check(
			{ docker: "amd64", build: "fails" },
			{ rebuild: true },
		);
		expect(r.exitCode).toBe(2);
		expect(last(r)).toEqual({
			label: "Rebuild",
			status: "unfinished",
			lines: [
				"build.sh exited 1 on amd64 Docker. Its log ended:",
				"rootfs sha256 7ca659b2",
				"exec /usr/bin/bash: exec format error",
				"A commit's build.sh builds the EIF on arm64 Linux, and newer ones on x86_64 Linux too.",
				"For an older commit on x86_64, enable arm64 emulation first: docker run --privileged --rm tonistiigi/binfmt --install arm64",
				"Docker Desktop on Apple silicon runs arm64 (untested).",
			],
		});
		expect(r.verdict).toEqual([
			"Could not finish: build.sh exited 1. Nothing was checked past Source.",
		]);
	});
});

describe("TLS", () => {
	it("says the connection ended inside an enclave when its key is one a document attests", async () => {
		const r = await check({
			tls: {
				spkiSha256:
					"9ca2e4167101e6282d70320e4e72981afbc950d98e15389faf2540e77dca4ea1",
				issuer: "i-0d45a659f78879f74",
			},
		});
		expect(r.exitCode).toBe(0);
		expect(last(r)?.lines).toEqual([
			"this connection to api.trymorse.ai ended inside an attested enclave (key 9ca2e4167101e628)",
		]);
	});

	it("never fails, even when it can't connect", async () => {
		const r = await check({ tls: new Error("connect ECONNREFUSED") });
		expect(r.exitCode).toBe(0);
		expect(last(r)?.lines).toEqual([
			"could not connect to api.trymorse.ai:443 (connect ECONNREFUSED), so this says nothing of where its TLS ends.",
		]);
	});
});

describe.runIf(process.env.VERIFY_LIVE === "1")(
	"against prod (VERIFY_LIVE=1)",
	() => {
		it("passes", { timeout: 120_000 }, async () => {
			const r = await verify();
			expect(
				r.verdict.join("\n"),
				r.steps.map((s) => s.lines.join("\n")).join("\n"),
			).toMatch(/^Passed\./);
			expect(r.exitCode).toBe(0);
		});
	},
);
