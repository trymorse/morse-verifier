// The enclave's side of a seal, for tests: it opens a request sealed to its X25519 key and seals a
// reply frame by frame, as the backend's internal/seal does. opener.test.ts holds both to
// seal_vectors.json, which the backend wrote.
import { x25519 } from "@noble/curves/ed25519.js";
import { type Bytes, concat, dec, hex } from "../bytes.ts";
import { CEK_INFO, frameKeys, frameNonce, hpkeKeys, keyIdOf } from "../seal.ts";

const ENTRY = 8 + 32 + 48;
const PAD = 1024;

export interface Opened {
	readonly head: {
		readonly method: string;
		readonly path: string;
		readonly headers: Record<string, string>;
		readonly ts: number;
		readonly body_len: number;
	};
	readonly body: Bytes;
	readonly cek: Bytes;
}

/** The key ids, hex, a sealed request names, in order. */
export const keyIdsOf = (sealed: Bytes): string[] =>
	Array.from({ length: sealed[1] }, (_, n) =>
		hex(sealed.subarray(2 + n * ENTRY, 10 + n * ENTRY)),
	);

const decrypt = async (
	key: Uint8Array,
	iv: Uint8Array,
	data: Bytes,
	additionalData: Bytes,
) =>
	new Uint8Array(
		await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: new Uint8Array(iv), additionalData },
			await crypto.subtle.importKey(
				"raw",
				new Uint8Array(key),
				"AES-GCM",
				false,
				["decrypt"],
			),
			data,
		),
	) as Bytes;

/** An enclave's key pair. `open` reads a request sealed to it, or is undefined when no entry
 * names it, as the worker then answers 421. */
export function enclaveKey(
	secret: Bytes = x25519.utils.randomSecretKey() as Bytes,
) {
	const publicKey = x25519.getPublicKey(secret) as Bytes;
	const open = async (sealed: Bytes): Promise<Opened | undefined> => {
		const n = keyIdsOf(sealed).indexOf(hex(await keyIdOf(publicKey)));
		if (sealed[0] !== 1 || n < 0) return undefined;
		const aad = sealed.slice(0, 2 + sealed[1] * ENTRY);
		const entry = aad.subarray(2 + n * ENTRY, 2 + (n + 1) * ENTRY);
		const encapsulated = entry.slice(8, 40);
		const { key, nonce } = hpkeKeys(
			x25519.getSharedSecret(secret, encapsulated),
			encapsulated,
			publicKey,
			CEK_INFO,
		);
		const cek = await decrypt(key, nonce, entry.slice(40), entry.slice(0, 8));
		const ct = sealed.slice(aad.length);
		if (ct.length % PAD !== 0) throw new Error("the ciphertext is not padded");
		const inner = await decrypt(cek, new Uint8Array(12), ct, aad);
		const size = new DataView(inner.buffer).getUint32(0);
		const head = JSON.parse(
			dec.decode(inner.subarray(4, 4 + size)),
		) as Opened["head"];
		const end = 4 + size + head.body_len;
		if (inner.subarray(end).some((b) => b !== 0))
			throw new Error("the padding is not zeros");
		return { head, body: inner.slice(4 + size, end), cek };
	};
	return { publicKey, open };
}

/** A reply sealed under `cek`, written part by part: `salt`, then each frame in turn. */
export async function replySealer(
	cek: Bytes,
	salt: Bytes = crypto.getRandomValues(new Uint8Array(32)),
) {
	const keys = await frameKeys(cek, salt);
	let index = 0;
	const frame = async (data: Bytes, final: boolean): Promise<Bytes> => {
		const pt = new Uint8Array(Math.ceil((5 + data.length) / PAD) * PAD);
		pt[0] = final ? 1 : 0;
		new DataView(pt.buffer).setUint32(1, data.length);
		pt.set(data, 5);
		const ct = new Uint8Array(
			await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: frameNonce(keys.base, index++) },
				keys.key,
				pt,
			),
		);
		const size = new Uint8Array(4);
		new DataView(size.buffer).setUint32(0, ct.length);
		return concat([size, ct]);
	};
	return { salt, frame };
}
