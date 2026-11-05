import { readFileSync } from "node:fs";
import { x25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { type Bytes, concat, hex, unhex } from "./bytes.ts";
import {
	frameKeys,
	frameNonce,
	headJson,
	hpkeExport,
	hpkeKeys,
	hpkeNonce,
	innerPlaintext,
	keyIdOf,
	openReply,
	SealedReplyError,
	sealRequest,
} from "./seal.ts";

const vectors = JSON.parse(
	readFileSync(
		new URL("./testdata/seal_vectors.json", import.meta.url),
		"utf8",
	),
) as {
	suite: Record<string, string>;
	recipients: { public_key: string; key_id: string }[];
	requests: {
		name: string;
		recipients: number[];
		ephemeral_private_keys: string[];
		cek: string;
		head: {
			method: string;
			path: string;
			headers: Record<string, string>;
			ts: number;
			body_len: number;
		};
		head_json: string;
		body: string;
		inner: string;
		sealed: string;
	}[];
	replies: {
		name: string;
		cek: string;
		salt: string;
		base_nonce: string;
		head: { status: number; headers: Record<string, string[]> };
		frames: { data: string; nonce: string; frame: string }[];
		reply: string;
	}[];
};

const streamOf = (bytes: Bytes, chunk = bytes.length) =>
	new ReadableStream<Uint8Array>({
		start(controller) {
			for (let i = 0; i < bytes.length; i += chunk)
				controller.enqueue(bytes.slice(i, i + chunk));
			controller.close();
		},
	});

const readAll = async (stream: ReadableStream<Uint8Array>) => {
	const parts: Uint8Array[] = [];
	for await (const part of stream) parts.push(part);
	return concat(parts);
};

it("fixes the suite the backend seals with", () => {
	expect(vectors.suite).toMatchObject({
		kem: "DHKEM(X25519, HKDF-SHA256)",
		kdf: "HKDF-SHA256",
		aead: "AES-256-GCM",
		cek_info: "morse-seal-v1 cek",
		reply_key_info: "morse-seal-v1 reply key",
		reply_nonce_info: "morse-seal-v1 reply nonce",
	});
});

it("names each key by the first 8 bytes of its SHA-256", async () => {
	for (const r of vectors.recipients)
		expect(hex(await keyIdOf(unhex(r.public_key)))).toBe(r.key_id);
});

describe.each(vectors.requests)("the request vector $name", (v) => {
	const { body_len, ...head } = v.head;
	const body = unhex(v.body);

	it("writes the head and the padded inner plaintext byte for byte", () => {
		expect(body_len).toBe(body.length);
		expect(hex(headJson(head, body.length))).toBe(v.head_json);
		expect(hex(innerPlaintext(unhex(v.head_json), body))).toBe(v.inner);
	});

	it("seals byte for byte as the backend does", async () => {
		const keys = v.recipients.map((i) => ({
			publicKey: unhex(vectors.recipients[i].public_key),
			keyId: unhex(vectors.recipients[i].key_id),
		}));
		const { sealed, cek } = await sealRequest(keys, head, body, {
			cek: unhex(v.cek),
			ephemeral: v.ephemeral_private_keys.map(unhex),
		});
		expect(hex(sealed)).toBe(v.sealed);
		expect(hex(cek)).toBe(v.cek);
		expect(sealed.length % 1024).toBe((2 + 88 * keys.length) % 1024);
	});
});

describe.each(vectors.replies)("the reply vector $name", (v) => {
	it("derives each frame's nonce", async () => {
		const keys = await frameKeys(unhex(v.cek), unhex(v.salt));
		expect(hex(keys.base)).toBe(v.base_nonce);
		v.frames.forEach((f, i) => {
			expect(hex(frameNonce(keys.base, i))).toBe(f.nonce);
		});
	});

	it.each([
		1,
		7,
		1 << 20,
	])("opens to its head and body read in chunks of %i bytes", async (chunk) => {
		const reply = await openReply(
			streamOf(unhex(v.reply), chunk),
			unhex(v.cek),
		);
		expect(reply.status).toBe(v.head.status);
		for (const [name, values] of Object.entries(v.head.headers))
			expect(reply.headers.get(name)).toBe(values.join(", "));
		expect(hex(await readAll(reply.body))).toBe(
			v.frames
				.slice(1)
				.map((f) => f.data)
				.join(""),
		);
	});

	it.each([
		"the whole final frame",
		"the final frame's last byte",
	])("fails the stream without %s", async (lost) => {
		const reply = unhex(v.reply);
		const finalFrame = unhex(v.frames.at(-1)?.frame ?? "").length;
		const cut = reply.slice(
			0,
			reply.length - (lost === "the whole final frame" ? finalFrame : 1),
		);
		const read = openReply(streamOf(cut), unhex(v.cek)).then((r) =>
			readAll(r.body),
		);
		await expect(read).rejects.toBeInstanceOf(SealedReplyError);
	});

	it("refuses a reply opened under another CEK", async () => {
		const other = unhex(v.cek).map((b) => b ^ 1);
		await expect(
			openReply(streamOf(unhex(v.reply)), new Uint8Array(other)),
		).rejects.toBeInstanceOf(SealedReplyError);
	});
});

// RFC 9180's test vector for base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and
// AES-256-GCM, from the CFRG's test-vectors.json (cfrg/draft-irtf-cfrg-hpke at b1f7cb0). It keeps
// the encryptions RFC 9180's appendix prints for each suite, numbered by `seq`: 0, 1, 2, 4, 255,
// and 256.
const hpke = JSON.parse(
	readFileSync(new URL("./testdata/hpke_vector.json", import.meta.url), "utf8"),
) as {
	info: string;
	skRm: string;
	skEm: string;
	pkRm: string;
	enc: string;
	shared_secret: string;
	key: string;
	base_nonce: string;
	exporter_secret: string;
	encryptions: {
		seq: number;
		aad: string;
		ct: string;
		nonce: string;
		pt: string;
	}[];
	exports: { exporter_context: string; L: number; exported_value: string }[];
};

describe("RFC 9180's base-mode vector for X25519, HKDF-SHA256, and AES-256-GCM", () => {
	const sender = x25519.getSharedSecret(unhex(hpke.skEm), unhex(hpke.pkRm));
	const keys = hpkeKeys(
		sender,
		unhex(hpke.enc),
		unhex(hpke.pkRm),
		unhex(hpke.info),
	);

	it("encapsulates to the ephemeral key, which the recipient's key decapsulates to the same DH", () => {
		expect(hex(x25519.getPublicKey(unhex(hpke.skEm)))).toBe(hpke.enc);
		expect(x25519.getSharedSecret(unhex(hpke.skRm), unhex(hpke.enc))).toEqual(
			sender,
		);
	});

	it("derives the key, the base nonce, and the exporter secret", () => {
		expect(hex(keys.key)).toBe(hpke.key);
		expect(hex(keys.nonce)).toBe(hpke.base_nonce);
		expect(hex(keys.exporterSecret)).toBe(hpke.exporter_secret);
	});

	it.each(
		hpke.encryptions,
	)("seals message $seq under its sequence number's nonce", async (e) => {
		const nonce = hpkeNonce(keys.nonce, e.seq);
		expect(hex(nonce)).toBe(e.nonce);
		const key = await crypto.subtle.importKey(
			"raw",
			new Uint8Array(keys.key),
			"AES-GCM",
			false,
			["encrypt"],
		);
		const ct = await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: nonce, additionalData: unhex(e.aad) },
			key,
			unhex(e.pt),
		);
		expect(hex(ct)).toBe(e.ct);
	});

	it.each(
		hpke.exports,
	)("exports $L bytes for the context '$exporter_context'", (x) => {
		expect(
			hex(hpkeExport(keys.exporterSecret, unhex(x.exporter_context), x.L)),
		).toBe(x.exported_value);
	});
});
