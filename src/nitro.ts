import { type Bytes, enc, equalBytes, hex } from "./bytes.ts";
import { type Cbor, decodeCbor, encodeCborArray } from "./cbor.ts";
import { type Pcrs, type PinnedImage, pinNamed, refusePcrs } from "./pins.ts";
import { keyIdOf } from "./seal.ts";
import { type Cert, importKey, P384, parseCert, verifyChain } from "./x509.ts";

export const USER_DATA_PREFIX = "morse-proxy-hpke-v1|";
export const MAX_AGE_MS = 30 * 60_000;
const MAX_AHEAD_MS = 5 * 60_000;
const ES384 = -35;
const KEY_BYTES = 32;

export interface AttestedKey {
	readonly publicKey: Bytes;
	readonly keyId: Bytes;
	readonly issuedAt: number;
}

export interface Expectation {
	readonly environment: string;
	readonly pins: readonly PinnedImage[];
	readonly root: Cert;
	readonly now: number;
}

/** A stage of `verifyNitroDocument` that passed, reported as it does so: the signature and its chain
 * (`chainLength` counts the leaf and its intermediates, not the root it ends at), the document's
 * age, the pinned image its PCRs name, and the key its user_data binds. A document that fails
 * reports the stages before the one that threw, so the first stage not reported is the one that
 * failed. */
export type NitroStep =
	| { step: "signed"; issuedAt: number; chainLength: number }
	| { step: "fresh"; ageMs: number }
	| { step: "build"; pin: PinnedImage; pcrs: Pcrs }
	| { step: "key"; publicKey: Bytes };

const field = (map: Cbor, key: string | number): Cbor | undefined =>
	map instanceof Map ? map.get(key) : undefined;

function bytesAt(map: Cbor, key: string | number): Bytes {
	const value = field(map, key);
	if (!(value instanceof Uint8Array)) throw new Error(`${key} is not bytes`);
	return value;
}

export function keyInUserData(userData: Bytes, environment: string): Bytes {
	const prefix = enc.encode(`${USER_DATA_PREFIX}${environment}|`);
	if (
		userData.length !== prefix.length + KEY_BYTES ||
		!equalBytes(userData.subarray(0, prefix.length), prefix)
	)
		throw new Error(
			`user_data does not name a ${environment} key: ${new TextDecoder().decode(userData.subarray(0, 40))}`,
		);
	return userData.slice(prefix.length);
}

export function checkFresh(issuedAt: number, now: number) {
	if (now - issuedAt > MAX_AGE_MS)
		throw new Error(
			`the document is ${Math.round((now - issuedAt) / 60_000)} minutes old`,
		);
	if (issuedAt - now > MAX_AHEAD_MS)
		throw new Error(
			`the document is ${Math.round((issuedAt - now) / 60_000)} minutes ahead of this device's clock`,
		);
}

export async function verifyNitroDocument(
	document: Bytes,
	expect: Expectation,
	report?: (step: NitroStep) => void,
): Promise<AttestedKey> {
	let sign1 = decodeCbor(document);
	if (
		!Array.isArray(sign1) &&
		sign1 !== null &&
		typeof sign1 === "object" &&
		"tag" in sign1 &&
		sign1.tag === 18
	)
		sign1 = sign1.value;
	if (!Array.isArray(sign1) || sign1.length !== 4)
		throw new Error("the document is not a COSE_Sign1");
	const [protectedHeader, , payloadBytes, signature] = sign1 as Cbor[];
	if (
		!(protectedHeader instanceof Uint8Array) ||
		!(payloadBytes instanceof Uint8Array) ||
		!(signature instanceof Uint8Array)
	)
		throw new Error("the COSE_Sign1 is malformed");
	if (field(decodeCbor(protectedHeader), 1) !== ES384)
		throw new Error("the document is not signed with ES384");
	const payload = decodeCbor(payloadBytes);
	if (field(payload, "digest") !== "SHA384")
		throw new Error("the document's digest is not SHA384");
	const issuedAt = field(payload, "timestamp");
	if (typeof issuedAt !== "number")
		throw new Error("the document has no timestamp");

	const leaf = parseCert(bytesAt(payload, "certificate"));
	const bundle = field(payload, "cabundle");
	if (
		!Array.isArray(bundle) ||
		bundle.length === 0 ||
		!bundle.every((c) => c instanceof Uint8Array)
	)
		throw new Error("the document's cabundle is not a list of certificates");
	if (leaf.ca || leaf.curve !== P384)
		throw new Error("the signing certificate is not a P-384 leaf");
	const intermediates = (bundle as Bytes[]).slice(1).reverse().map(parseCert);
	await verifyChain([leaf, ...intermediates], expect.root, new Date(issuedAt));
	const signed = await crypto.subtle.verify(
		{ name: "ECDSA", hash: "SHA-384" },
		await importKey(leaf, "SHA-384"),
		signature,
		encodeCborArray([
			"Signature1",
			protectedHeader,
			new Uint8Array(),
			payloadBytes,
		]),
	);
	if (!signed) throw new Error("the document's signature does not verify");
	report?.({ step: "signed", issuedAt, chainLength: intermediates.length + 1 });

	checkFresh(issuedAt, expect.now);
	report?.({ step: "fresh", ageMs: expect.now - issuedAt });

	const pcrs = field(payload, "pcrs");
	const pcr = (n: number) => hex(bytesAt(pcrs ?? null, n));
	const pcrsOf = { pcr0: pcr(0), pcr1: pcr(1), pcr2: pcr(2) };
	const refused = refusePcrs(expect.pins, expect.environment, pcrsOf);
	if (refused) throw refused;
	const pin = pinNamed(expect.pins, expect.environment, pcrsOf);
	if (!pin) throw new Error("no pin names the document's PCRs");
	report?.({ step: "build", pin, pcrs: pcrsOf });

	const publicKey = keyInUserData(
		bytesAt(payload, "user_data"),
		expect.environment,
	);
	report?.({ step: "key", publicKey });
	return { publicKey, keyId: await keyIdOf(publicKey), issuedAt };
}
