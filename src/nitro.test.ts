import { readFileSync } from "node:fs";
import { x25519 } from "@noble/curves/ed25519.js";
import { beforeAll, describe, expect, it } from "vitest";
import { type Bytes, fromBase64, hex, sha256Bytes } from "./bytes.ts";
import { type NitroStep, verifyNitroDocument } from "./nitro.ts";
import { NITRO_ROOT } from "./nitro_root.ts";
import { type PinnedImage, parseEnclavePins } from "./pins.ts";
import { forgeNitro, PCR, pinOf } from "./testing/forge.ts";

const MINUTE = 60_000;

it("pins the AWS Nitro Enclaves root G1 by the fingerprint AWS publishes", async () => {
	expect(hex(await sha256Bytes(NITRO_ROOT.der))).toBe(
		"641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b",
	);
});

it("refuses a pins file with an all-zero entry", () => {
	const zero = "0".repeat(96);
	expect(() =>
		parseEnclavePins([pinOf({ pcr0: zero, pcr1: zero, pcr2: zero })]),
	).toThrow(/all-zero/);
});

it("reads the public morse-pins entries, which name the image by its morse-enclave tag", () => {
	const {
		commit: _,
		version: __,
		...measured
	} = pinOf({ environment: "prod" });
	const [pin] = parseEnclavePins([{ tag: "v2026.11.0", ...measured }]);
	expect(pin).toEqual({ version: "v2026.11.0", ...measured });
});

// NSM encodes this document's payload as an indefinite-length map.
describe("a real AWS Nitro document", () => {
	const document = fromBase64(
		readFileSync(
			new URL("./testdata/nitro_document.b64", import.meta.url),
			"utf8",
		).trim(),
	) as Bytes;
	const issuedAt = 1792280904626;
	const pins: PinnedImage[] = [
		pinOf({
			pcr0: "1dab5ad4c661f95a9e7e3f57bcd83efd9fced7f749ac21ea85a1853131bb5e43b41eb58615efef998d478ce485fcff53",
			pcr1: "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03",
			pcr2: "f9d2c68436810c46556535a583870e2913ec1f05ecca361b4e78eaa00d0b365dee6570e7699c4f34165fbf635bf35c6a",
		}),
	];
	const expect_ = (o: { now?: number; pins?: PinnedImage[] } = {}) => ({
		environment: "dev" as const,
		pins: o.pins ?? pins,
		root: NITRO_ROOT,
		now: o.now ?? issuedAt + MINUTE,
	});

	it.each([
		["a minute after its timestamp", MINUTE],
		["30 minutes after its timestamp", 30 * MINUTE],
		["5 minutes before its timestamp", -5 * MINUTE],
	])("passes every check %s, and vouches for the key its user_data names", async (_, after) => {
		const key = await verifyNitroDocument(
			document,
			expect_({ now: issuedAt + after }),
		);
		expect(hex(key.publicKey)).toBe(
			"48895025406095a204ddcf391e72f6a517af868796cd3167d9ddceef13c9ae5e",
		);
		expect(hex(key.keyId)).toBe("d074a9212978f332");
		expect(key.issuedAt).toBe(issuedAt);
	});

	// What the proof page shows: each stage as it passes, and on a failure the stages before it.
	it("reports each stage as it passes, in order", async () => {
		const steps: NitroStep[] = [];
		const key = await verifyNitroDocument(
			document,
			expect_({ now: issuedAt + 41_000 }),
			(step) => steps.push(step),
		);
		expect(steps.map((s) => s.step)).toEqual([
			"signed",
			"fresh",
			"build",
			"key",
		]);
		expect(steps[0]).toMatchObject({ step: "signed", issuedAt });
		expect(steps[0]).toHaveProperty("chainLength", expect.any(Number));
		expect(steps[1]).toEqual({ step: "fresh", ageMs: 41_000 });
		expect(steps[2]).toMatchObject({
			step: "build",
			pin: pins[0],
			pcrs: { pcr0: pins[0].pcr0, pcr1: pins[0].pcr1, pcr2: pins[0].pcr2 },
		});
		expect(steps[3]).toEqual({ step: "key", publicKey: key.publicKey });
	});

	it.each([
		[
			"a bad signature",
			() => {
				const forged = document.slice();
				forged[forged.length - 1] ^= 1;
				return { document: forged, expect: expect_() };
			},
			[],
		],
		[
			"an old document",
			() => ({
				document,
				expect: expect_({ now: issuedAt + 31 * MINUTE }),
			}),
			["signed"],
		],
		[
			"an unpinned build",
			() => ({
				document,
				expect: expect_({ pins: [] }),
			}),
			["signed", "fresh"],
		],
	])("reports only the stages before the one that fails: %s", async (_, make, passed) => {
		const { document: doc, expect: want } = make();
		const steps: string[] = [];
		await expect(
			verifyNitroDocument(doc, want, (step) => steps.push(step.step)),
		).rejects.toThrow();
		expect(steps).toEqual(passed);
	});

	it("returns the PCRs and module_id it attests, and its public_key, which is null", async () => {
		const attested = await verifyNitroDocument(document, expect_());
		expect(attested.pcrs).toEqual({
			pcr0: pins[0].pcr0,
			pcr1: pins[0].pcr1,
			pcr2: pins[0].pcr2,
		});
		expect(attested.moduleId).toBe("i-0a93e4d666586119b-enc01a14c4380fcd25f");
		expect(attested.tlsKey).toBeNull();
	});

	it("is refused 31 minutes after its timestamp, and 6 minutes before it", async () => {
		await expect(
			verifyNitroDocument(document, expect_({ now: issuedAt + 31 * MINUTE })),
		).rejects.toThrow(/31 minutes old/);
		await expect(
			verifyNitroDocument(document, expect_({ now: issuedAt - 6 * MINUTE })),
		).rejects.toThrow(/ahead of this device's clock/);
	});

	it("is refused when no pin names its PCRs, or the pin is revoked", async () => {
		await expect(
			verifyNitroDocument(document, expect_({ pins: [] })),
		).rejects.toThrow(/no dev pin/);
		await expect(
			verifyNitroDocument(
				document,
				expect_({ pins: pins.map((p) => ({ ...p, revoked: true })) }),
			),
		).rejects.toThrow(/revoked/);
		await expect(
			verifyNitroDocument(document, {
				...expect_(),
				environment: "prod",
			}),
		).rejects.toThrow(/no prod pin/);
	});

	it("is refused with one byte of its signature changed", async () => {
		const forged = document.slice();
		forged[forged.length - 1] ^= 1;
		await expect(verifyNitroDocument(forged, expect_())).rejects.toThrow(
			/signature does not verify/,
		);
	});

	it("is refused under another root", async () => {
		const { root } = await forgeNitro();
		await expect(
			verifyNitroDocument(document, { ...expect_(), root }),
		).rejects.toThrow(/pinned anchor|signed by neither/);
	});
});

describe("a forged document under a test root", () => {
	const publicKey = x25519.getPublicKey(
		x25519.utils.randomSecretKey(),
	) as Bytes;
	const now = Date.now();
	let forge: Awaited<ReturnType<typeof forgeNitro>>;
	beforeAll(async () => {
		forge = await forgeNitro();
	});
	const check = (doc: Bytes, environment: "dev" | "prod" = "dev") =>
		verifyNitroDocument(doc, {
			environment,
			pins: [pinOf(), pinOf({ environment: "prod", pcr0: "b0".repeat(48) })],
			root: forge.root,
			now,
		});

	it("vouches for the key its user_data names", async () => {
		const key = await check(
			await forge.document({ timestamp: now - MINUTE, publicKey }),
		);
		expect(hex(key.publicKey)).toBe(hex(publicKey));
		expect(hex(key.keyId)).toBe(
			hex((await sha256Bytes(publicKey)).slice(0, 8)),
		);
		expect(key.issuedAt).toBe(now - MINUTE);
	});

	it.each([
		[
			"a document of the other environment",
			{ environment: "prod" },
			/user_data does not name a dev key/,
		],
		[
			"a key that is not 32 bytes",
			{ publicKey: new Uint8Array(31) },
			/user_data does not name a dev key/,
		],
		[
			"all-zero PCRs",
			{
				pcrs: {
					pcr0: "00".repeat(48),
					pcr1: "00".repeat(48),
					pcr2: "00".repeat(48),
				},
			},
			/debug mode/,
		],
		[
			"PCRs of the prod image",
			{ pcrs: { ...PCR, pcr0: "b0".repeat(48) } },
			/no dev pin/,
		],
		["a SHA256 digest", { digest: "SHA256" }, /digest is not SHA384/],
		["ES256", { alg: -7 }, /not signed with ES384/],
		[
			"a signer outside the chain",
			{ signWith: "stranger" as const },
			/signature does not verify/,
		],
	])("refuses %s", async (_, o, reason) => {
		await expect(
			check(await forge.document({ timestamp: now - MINUTE, publicKey, ...o })),
		).rejects.toThrow(reason);
	});
});
