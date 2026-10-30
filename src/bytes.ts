/** Bytes WebCrypto accepts as-is (a SharedArrayBuffer-backed view would not be). */
export type Bytes = Uint8Array<ArrayBuffer>;

export const enc = new TextEncoder();
export const dec = new TextDecoder();

const HEX_DIGITS = enc.encode("0123456789abcdef");

/** Byte by byte into one buffer, since a sealed image is megabytes. */
export function hex(bytes: ArrayBuffer | Uint8Array): string {
	const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
	const out = new Uint8Array(input.length * 2);
	for (let i = 0; i < input.length; i++) {
		out[2 * i] = HEX_DIGITS[input[i] >> 4];
		out[2 * i + 1] = HEX_DIGITS[input[i] & 15];
	}
	return dec.decode(out);
}

const HEX = /^([0-9a-fA-F]{2})*$/;

export function unhex(text: string): Bytes {
	const digits = text.startsWith("0x") ? text.slice(2) : text;
	if (!HEX.test(digits)) throw new TypeError(`not hex: ${text.slice(0, 16)}`);
	const out = new Uint8Array(digits.length / 2);
	for (let i = 0; i < out.length; i++)
		out[i] = Number.parseInt(digits.slice(2 * i, 2 * i + 2), 16);
	return out;
}

const bytesOf = (input: Bytes | string): Bytes =>
	typeof input === "string" ? enc.encode(input) : input;

export const sha256Bytes = async (input: Bytes | string): Promise<Bytes> =>
	new Uint8Array(await crypto.subtle.digest("SHA-256", bytesOf(input)));

/** HKDF-SHA-256 keying material, to derive one key or several from. */
export const hkdfInput = (ikm: Bytes) =>
	crypto.subtle.importKey("raw", ikm, "HKDF", false, [
		"deriveBits",
		"deriveKey",
	]);

const hkdf = (salt: Bytes, info: Bytes) => ({
	name: "HKDF",
	hash: "SHA-256",
	salt,
	info,
});

/** `length` bytes of HKDF-SHA-256. */
export const hkdfBytes = async (
	ikm: CryptoKey,
	salt: Bytes,
	info: Bytes,
	length: number,
): Promise<Bytes> =>
	new Uint8Array(
		await crypto.subtle.deriveBits(hkdf(salt, info), ikm, 8 * length),
	);

/** An AES-256-GCM key by HKDF-SHA-256, non-extractable, to encrypt and decrypt. */
export const hkdfAes = async (
	ikm: CryptoKey | Bytes,
	salt: Bytes,
	info: Bytes,
): Promise<CryptoKey> =>
	crypto.subtle.deriveKey(
		hkdf(salt, info),
		ikm instanceof Uint8Array ? await hkdfInput(ikm) : ikm,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);

export function concat(chunks: readonly Uint8Array[]): Bytes {
	const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
	let offset = 0;
	for (const chunk of chunks) {
		out.set(chunk, offset);
		offset += chunk.length;
	}
	return out;
}

export const equalBytes = (a: Uint8Array, b: Uint8Array) =>
	a.length === b.length && a.every((x, i) => x === b[i]);

const BASE64_DIGIT = new Uint8Array(128);
for (const c of "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
	BASE64_DIGIT[c.charCodeAt(0)] = 1;

/** Whole groups of four digits, the last one padded with at most two `=`. A scan and not a
 * regex: a repeated group overflows the regex engine's stack on a photo's length. */
function isBase64(text: string): boolean {
	if (text.length % 4 !== 0) return false;
	const padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
	const digits = text.length - padding;
	// A code unit past the table reads undefined, which is not a digit either.
	for (let i = 0; i < digits; i++)
		if (!BASE64_DIGIT[text.charCodeAt(i)]) return false;
	return true;
}

/** Padded standard base64's bytes, or undefined for anything else. */
export function fromBase64(text: string): Bytes | undefined {
	if (!isBase64(text)) return undefined;
	const binary = atob(text);
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < out.length; i++) out[i] = binary.charCodeAt(i);
	return out;
}

/** Padded standard base64, in slices small enough for fromCharCode's argument list. */
export function toBase64(bytes: Uint8Array): string {
	let text = "";
	for (let i = 0; i < bytes.length; i += 0x8000)
		text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
	return btoa(text);
}
