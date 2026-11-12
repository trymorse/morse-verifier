import { x25519 } from "@noble/curves/ed25519.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import {
	type Bytes,
	concat,
	enc,
	hkdfAes,
	hkdfBytes,
	hkdfInput,
} from "./bytes.ts";

export const SEALED_CONTENT_TYPE = "application/morse-sealed";
export const MAX_KEYS = 4;
const MAX_HEAD = 8 << 10;
const VERSION = 1;
const PAD = 1024;
const TAG = 16;
export const CEK_INFO = enc.encode("morse-seal-v1 cek");
const REPLY_KEY_INFO = enc.encode("morse-seal-v1 reply key");
const REPLY_NONCE_INFO = enc.encode("morse-seal-v1 reply nonce");
const SALT = 32;
const FRAME_HEAD = 5;

export async function keyIdOf(publicKey: Bytes): Promise<Bytes> {
	const digest = new Uint8Array(
		await crypto.subtle.digest("SHA-256", publicKey),
	);
	return digest.slice(0, 8);
}

export interface SealKey {
	readonly publicKey: Bytes;
	readonly keyId: Bytes;
}

/** A JSON value as the head carries it. */
type HeadJson =
	| boolean
	| number
	| string
	| null
	| readonly HeadJson[]
	| { readonly [key: string]: HeadJson };

export interface InnerHead {
	readonly method: string;
	readonly path: string;
	readonly headers: Readonly<Record<string, string>>;
	readonly ts: number;
	/** A chat's ask for the Privacy Veil, `true` or an object, carried inside the seal so the relay
	 * can't drop it. A proxy from before the Veil refuses a head that has it. Left out when unset. */
	readonly privacy_veil?: HeadJson;
	/** The chat's cache partition for the Veil: at least 16 random bytes in unpadded base64url,
	 * the same for every call of one chat. Left out when unset or empty. */
	readonly privacy_veil_partition?: string;
}

export interface Draws {
	readonly cek: Bytes;
	readonly ephemeral: readonly Bytes[];
}

const i2osp2 = (n: number) => Uint8Array.of(n >> 8, n & 0xff);
const HPKE_V1 = enc.encode("HPKE-v1");
const KEM_SUITE = concat([enc.encode("KEM"), i2osp2(0x0020)]);
const HPKE_SUITE = concat([
	enc.encode("HPKE"),
	i2osp2(0x0020),
	i2osp2(0x0001),
	i2osp2(0x0002),
]);

const labeledExtract = (suite: Bytes, salt: Bytes, label: string, ikm: Bytes) =>
	extract(sha256, concat([HPKE_V1, suite, enc.encode(label), ikm]), salt);

const labeledExpand = (
	suite: Bytes,
	prk: Uint8Array,
	label: string,
	info: Bytes,
	length: number,
) =>
	expand(
		sha256,
		prk,
		concat([i2osp2(length), HPKE_V1, suite, enc.encode(label), info]),
		length,
	);

const aes = (key: Uint8Array, usage: KeyUsage) =>
	crypto.subtle.importKey("raw", new Uint8Array(key), "AES-GCM", false, [
		usage,
	]);

/** RFC 9180's base-mode key schedule for DHKEM(X25519): the AEAD key, its base nonce, and the
 * secret the context exports from. */
export function hpkeKeys(
	dh: Uint8Array,
	encapsulated: Bytes,
	recipient: Bytes,
	info: Bytes,
): { key: Uint8Array; nonce: Uint8Array; exporterSecret: Uint8Array } {
	const empty = new Uint8Array();
	const eaePrk = labeledExtract(
		KEM_SUITE,
		empty,
		"eae_prk",
		new Uint8Array(dh),
	);
	const shared = labeledExpand(
		KEM_SUITE,
		eaePrk,
		"shared_secret",
		concat([encapsulated, recipient]),
		32,
	);
	const context = concat([
		Uint8Array.of(0),
		labeledExtract(HPKE_SUITE, empty, "psk_id_hash", empty),
		labeledExtract(HPKE_SUITE, empty, "info_hash", info),
	]);
	const secret = labeledExtract(
		HPKE_SUITE,
		new Uint8Array(shared),
		"secret",
		empty,
	);
	return {
		key: labeledExpand(HPKE_SUITE, secret, "key", context, 32),
		nonce: labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12),
		exporterSecret: labeledExpand(HPKE_SUITE, secret, "exp", context, 32),
	};
}

/** RFC 9180's Export (5.3): `length` bytes for `exporterContext` from a context's secret. */
export const hpkeExport = (
	exporterSecret: Uint8Array,
	exporterContext: Bytes,
	length: number,
): Uint8Array =>
	labeledExpand(HPKE_SUITE, exporterSecret, "sec", exporterContext, length);

/** The nonce of a context's `seq`th message (RFC 9180 5.2): the base nonce XOR `seq` as a
 * big-endian integer. `seq` is a safe integer, so only the last eight bytes can change. */
export function hpkeNonce(base: Uint8Array, seq: number): Bytes {
	const nonce = new Uint8Array(base);
	const view = new DataView(nonce.buffer);
	view.setBigUint64(4, view.getBigUint64(4) ^ BigInt(seq));
	return nonce;
}

/** RFC 9180 base-mode single-shot seal, as Go's crypto/hpke Sender.Seal makes it. */
async function hpkeSeal(
	recipient: Bytes,
	ephemeral: Bytes,
	aad: Bytes,
	plaintext: Bytes,
): Promise<{ enc: Bytes; ct: Bytes }> {
	const encapsulated = new Uint8Array(x25519.getPublicKey(ephemeral));
	const { key, nonce } = hpkeKeys(
		x25519.getSharedSecret(ephemeral, recipient),
		encapsulated,
		recipient,
		CEK_INFO,
	);
	const ct = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: new Uint8Array(nonce), additionalData: aad },
		await aes(key, "encrypt"),
		plaintext,
	);
	return { enc: encapsulated, ct: new Uint8Array(ct) };
}

const GO_ESCAPES: Record<string, string> = {
	"<": "\\u003c",
	">": "\\u003e",
	"&": "\\u0026",
	"\u2028": "\\u2028",
	"\u2029": "\\u2029",
};

/** The head as Go's encoding/json writes the backend's `seal.Head`: its fields in the struct's
 * order, the headers by name, the Veil's two only when set, and `<`, `>`, `&`, U+2028, and U+2029
 * escaped, inside the ask's JSON too, which Go compacts as this does. */
export function headJson(head: InnerHead, bodyLength: number): Bytes {
	const headers = Object.fromEntries(
		Object.keys(head.headers)
			.sort()
			.map((name) => [name, head.headers[name]]),
	);
	return enc.encode(
		JSON.stringify({
			method: head.method,
			path: head.path,
			headers,
			ts: head.ts,
			...(head.privacy_veil !== undefined && {
				privacy_veil: head.privacy_veil,
			}),
			...(head.privacy_veil_partition && {
				privacy_veil_partition: head.privacy_veil_partition,
			}),
			body_len: bodyLength,
		}).replace(/[<>&\u2028\u2029]/g, (c) => GO_ESCAPES[c]),
	);
}

export function innerPlaintext(headBytes: Bytes, body: Bytes): Bytes {
	const unpadded = 4 + headBytes.length + body.length;
	const inner = new Uint8Array(
		unpadded + ((PAD - ((unpadded + TAG) % PAD)) % PAD),
	);
	new DataView(inner.buffer).setUint32(0, headBytes.length);
	inner.set(headBytes, 4);
	inner.set(body, 4 + headBytes.length);
	return inner;
}

const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

export async function sealRequest(
	keys: readonly SealKey[],
	head: InnerHead,
	body: Bytes,
	draws: Draws = {
		cek: random(32),
		ephemeral: keys.map(() => x25519.utils.randomSecretKey() as Bytes),
	},
): Promise<{ sealed: Bytes; cek: Bytes }> {
	if (keys.length < 1 || keys.length > MAX_KEYS)
		throw new Error(`sealing to ${keys.length} keys, not 1 to ${MAX_KEYS}`);
	const headBytes = headJson(head, body.length);
	if (headBytes.length > MAX_HEAD) throw new HeadTooLarge(headBytes.length);
	const entries = await Promise.all(
		keys.map(async (k, i) => {
			const { enc: encapsulated, ct } = await hpkeSeal(
				k.publicKey,
				draws.ephemeral[i],
				k.keyId,
				draws.cek,
			);
			return concat([k.keyId, encapsulated, ct]);
		}),
	);
	const aad = concat([Uint8Array.of(VERSION, keys.length), ...entries]);
	const ct = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: new Uint8Array(12), additionalData: aad },
		await aes(draws.cek, "encrypt"),
		innerPlaintext(headBytes, body),
	);
	return { sealed: concat([aad, new Uint8Array(ct)]), cek: draws.cek };
}

export interface FrameKeys {
	readonly key: CryptoKey;
	readonly base: Bytes;
}

export async function frameKeys(cek: Bytes, salt: Bytes): Promise<FrameKeys> {
	const ikm = await hkdfInput(cek);
	return {
		key: await hkdfAes(ikm, salt, REPLY_KEY_INFO),
		base: await hkdfBytes(ikm, salt, REPLY_NONCE_INFO, 12),
	};
}

export function frameNonce(base: Bytes, index: number): Bytes {
	const nonce = base.slice();
	const view = new DataView(nonce.buffer);
	view.setUint32(8, (view.getUint32(8) ^ index) >>> 0);
	return nonce;
}

async function openFrame(
	keys: FrameKeys,
	index: number,
	ciphertext: Bytes,
): Promise<{ data: Bytes; final: boolean }> {
	let pt: Bytes;
	try {
		pt = new Uint8Array(
			await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: frameNonce(keys.base, index) },
				keys.key,
				ciphertext,
			),
		);
	} catch {
		throw new SealedReplyError(`frame ${index} does not open`);
	}
	if (pt.length < FRAME_HEAD || pt.length % PAD !== 0 || pt[0] > 1)
		throw new SealedReplyError(`frame ${index} is malformed`);
	const length = new DataView(pt.buffer).getUint32(1);
	if (length > pt.length - FRAME_HEAD)
		throw new SealedReplyError(`frame ${index} overstates its length`);
	return {
		data: pt.slice(FRAME_HEAD, FRAME_HEAD + length),
		final: pt[0] === 1,
	};
}

export class HeadTooLarge extends Error {
	override name = "HeadTooLarge";
	constructor(length: number) {
		super(`the sealed head is ${length} bytes, over the proxy's ${MAX_HEAD}`);
	}
}

export class SealedReplyError extends Error {
	override name = "SealedReplyError";
}

function byteReader(stream: ReadableStream<Uint8Array>) {
	const reader = stream.getReader();
	let buffered = new Uint8Array(0) as Bytes;
	return {
		async read(n: number): Promise<Bytes | undefined> {
			while (buffered.length < n) {
				const { done, value } = await reader.read();
				if (done) return undefined;
				buffered = concat([buffered, value]);
			}
			const out = buffered.slice(0, n);
			buffered = buffered.slice(n);
			return out;
		},
		cancel: (reason?: unknown) => reader.cancel(reason),
	};
}

const replyHead = z.object({
	status: z.number().int().min(100).max(599),
	headers: z.record(z.string(), z.array(z.string())).nullable(),
});

export interface OpenedReply {
	readonly status: number;
	readonly headers: Headers;
	readonly body: ReadableStream<Uint8Array<ArrayBuffer>>;
}

export async function openReply(
	body: ReadableStream<Uint8Array>,
	cek: Bytes,
): Promise<OpenedReply> {
	const reader = byteReader(body);
	const salt = await reader.read(SALT);
	if (!salt) throw new SealedReplyError("the reply ends before its salt");
	const keys = await frameKeys(cek, salt);
	let index = 0;
	const next = async () => {
		const size = await reader.read(4);
		const ciphertext =
			size && (await reader.read(new DataView(size.buffer).getUint32(0)));
		if (!ciphertext)
			throw new SealedReplyError("the reply ends before its final frame");
		return openFrame(keys, index++, ciphertext);
	};
	const first = await next();
	let head: z.infer<typeof replyHead>;
	try {
		head = replyHead.parse(JSON.parse(new TextDecoder().decode(first.data)));
	} catch {
		throw new SealedReplyError("the reply's head is not JSON");
	}
	const headers = new Headers();
	for (const [name, values] of Object.entries(head.headers ?? {}))
		for (const value of values) headers.append(name, value);
	let done = first.final;
	return {
		status: head.status,
		headers,
		body: new ReadableStream<Uint8Array<ArrayBuffer>>({
			async pull(controller) {
				while (!done) {
					const frame = await next();
					done = frame.final;
					if (frame.data.length > 0) {
						controller.enqueue(frame.data);
						if (!done) return;
					}
				}
				controller.close();
			},
			cancel: (reason) => reader.cancel(reason),
		}),
	};
}
