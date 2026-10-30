import { x25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import {
	type ProxyTrustAnchors,
	UnattestedError,
	verifyInstances,
} from "./attestation.ts";
import { type Bytes, hex, toBase64 } from "./bytes.ts";
import { NITRO_ROOT } from "./nitro_root.ts";
import { forgeNitro, pinOf, standIn } from "./testing/forge.ts";

const MINUTE = 60_000;
const newKey = () =>
	x25519.getPublicKey(x25519.utils.randomSecretKey()) as Bytes;
const now = Date.now();
const dev: ProxyTrustAnchors = {
	environment: "dev",
	pins: [pinOf()],
	root: NITRO_ROOT,
	standIns: true,
};

describe("verifyInstances", () => {
	it("keeps every instance that passes, newest first, and expires with the oldest", async () => {
		const [a, b] = [newKey(), newKey()];
		const proxyKeys = await verifyInstances(
			[
				standIn({ publicKey: a, timestamp: now - 9 * MINUTE }),
				standIn({ publicKey: b, timestamp: now - MINUTE }),
				"not base64!",
				standIn({ environment: "prod", publicKey: newKey(), timestamp: now }),
			],
			dev,
			now,
		);
		expect(proxyKeys.keys.map((k) => hex(k.publicKey))).toEqual([
			hex(b),
			hex(a),
		]);
		expect(proxyKeys.expiresAt).toBe(now - 9 * MINUTE + 30 * MINUTE);
	});

	it("seals to at most four keys, and to one key once", async () => {
		const repeated = newKey();
		const instances = [
			standIn({ publicKey: repeated, timestamp: now - 2 * MINUTE }),
			standIn({ publicKey: repeated, timestamp: now - MINUTE }),
			...Array.from({ length: 5 }, (_, i) =>
				standIn({ publicKey: newKey(), timestamp: now - (3 + i) * MINUTE }),
			),
		];
		const { keys } = await verifyInstances(instances, dev, now);
		expect(keys).toHaveLength(4);
		expect(hex(keys[0].publicKey)).toBe(hex(repeated));
		expect(keys[0].issuedAt).toBe(now - MINUTE);
	});

	it("names why each instance was refused when none passes", async () => {
		const refused = await verifyInstances(
			[
				standIn({ publicKey: newKey(), timestamp: now }),
				toBase64(new Uint8Array([0x84, 0x40])),
			],
			{ ...dev, standIns: false },
			now,
		).catch((e: unknown) => e);
		expect(refused).toBeInstanceOf(UnattestedError);
		expect((refused as UnattestedError).reasons).toEqual([
			expect.stringMatching(/stand-in document, which this build refuses/),
			expect.stringMatching(/CBOR ends early/),
		]);
		await expect(verifyInstances([], dev, now)).rejects.toThrow(
			/lists no attested instance/,
		);
	});

	it("accepts a Nitro document that chains to the root and whose PCRs are pinned", async () => {
		const forge = await forgeNitro();
		const publicKey = newKey();
		const { keys } = await verifyInstances(
			[toBase64(await forge.document({ timestamp: now - MINUTE, publicKey }))],
			{ ...dev, standIns: false, root: forge.root, pins: [pinOf()] },
			now,
		);
		expect(keys.map((k) => hex(k.publicKey))).toEqual([hex(publicKey)]);
	});
});
