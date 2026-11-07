import {
	AsnConvert,
	AsnIntegerArrayBufferConverter,
	AsnProp,
	AsnPropTypes,
} from "@peculiar/asn1-schema";
import {
	AlgorithmIdentifier,
	BasicConstraints,
	Certificate,
	id_ce_basicConstraints,
	id_ce_extKeyUsage,
	id_ce_keyUsage,
	KeyUsage,
	KeyUsageFlags,
} from "@peculiar/asn1-x509";
import { type Bytes, concat, equalBytes, fromBase64, hex } from "./bytes.ts";

export const EC_KEY = "1.2.840.10045.2.1";
export const P384 = "1.3.132.0.34";
const RSA_KEY = "1.2.840.113549.1.1.1";
const RSA_PSS = "1.2.840.113549.1.1.10";
const MGF1 = "1.2.840.113549.1.1.8";
const SHA384 = "2.16.840.1.101.3.4.2.2";
const PSS_SALT = 48;

/** The named curves a key may use, by OID, each with its parameters' DER. */
const CURVES: Record<string, { name: string; size: number; der: string }> = {
	"1.2.840.10045.3.1.7": {
		name: "P-256",
		size: 32,
		der: "06082a8648ce3d030107",
	},
	[P384]: { name: "P-384", size: 48, der: "06052b81040022" },
	"1.3.132.0.35": { name: "P-521", size: 66, der: "06052b81040023" },
};

/** ECDSA-Sig-Value (RFC 3279), declared here so the chunk skips the rest of asn1-ecc. */
class EcdsaSignature {
	r = new ArrayBuffer(0);
	s = new ArrayBuffer(0);
	constructor(params: Partial<EcdsaSignature> = {}) {
		Object.assign(this, params);
	}
}
for (const field of ["r", "s"])
	AsnProp({
		type: AsnPropTypes.Integer,
		converter: AsnIntegerArrayBufferConverter,
	})(EcdsaSignature.prototype, field);

/** RSASSA-PSS-params (RFC 4055), declared like EcdsaSignature. A field left out takes its
 * default (SHA-1, MGF1 with SHA-1, a 20-byte salt, trailer 1), which only the trailer may. */
class PssParams {
	hashAlgorithm?: AlgorithmIdentifier;
	maskGenAlgorithm?: AlgorithmIdentifier;
	saltLength?: number;
	trailerField?: number;
}
for (const [context, field, type] of [
	[0, "hashAlgorithm", AlgorithmIdentifier],
	[1, "maskGenAlgorithm", AlgorithmIdentifier],
	[2, "saltLength", AsnPropTypes.Integer],
	[3, "trailerField", AsnPropTypes.Integer],
] as const)
	AsnProp({ type, context, optional: true })(PssParams.prototype, field);

/** RSASSA-PSS takes its hash from its parameters, which sha384Pss holds to SHA-384. */
const SIGNATURES: Record<string, { key: string; hash: string; pss?: true }> = {
	"1.2.840.113549.1.1.11": { key: RSA_KEY, hash: "SHA-256" },
	"1.2.840.113549.1.1.12": { key: RSA_KEY, hash: "SHA-384" },
	"1.2.840.113549.1.1.13": { key: RSA_KEY, hash: "SHA-512" },
	[RSA_PSS]: { key: RSA_KEY, hash: "SHA-384", pss: true },
	"1.2.840.10045.4.3.2": { key: EC_KEY, hash: "SHA-256" },
	"1.2.840.10045.4.3.3": { key: EC_KEY, hash: "SHA-384" },
	"1.2.840.10045.4.3.4": { key: EC_KEY, hash: "SHA-512" },
};

/** The critical extensions a certificate may carry. Extended key usage is allowed and never
 * checked: NVIDIA's leaves list the TLS purposes, and no purpose names signing a JWS, so a check
 * would refuse the real leaves for a purpose they could never list. */
const HANDLED_CRITICAL = new Set([
	id_ce_basicConstraints,
	id_ce_keyUsage,
	id_ce_extKeyUsage,
]);

export interface Cert {
	readonly der: Bytes;
	readonly tbs: Bytes;
	readonly serial: Bytes;
	readonly spki: Bytes;
	readonly issuer: Bytes;
	readonly subject: Bytes;
	readonly signatureAlgorithm: string;
	readonly signatureParameters: Bytes | undefined;
	readonly signature: Bytes;
	readonly keyAlgorithm: string;
	readonly curve: string | undefined;
	readonly notBefore: Date;
	readonly notAfter: Date;
	readonly ca: { pathLen: number | undefined } | undefined;
	readonly keyUsage: number | undefined;
	readonly unhandledCritical: readonly string[];
}

const bytes = (b: BufferSource): Bytes =>
	ArrayBuffer.isView(b)
		? new Uint8Array(b.buffer, b.byteOffset, b.byteLength).slice()
		: new Uint8Array(b.slice(0));
const der = (value: unknown): Bytes => bytes(AsnConvert.serialize(value));

function curveOf(parameters: ArrayBuffer | undefined): string | undefined {
	if (!parameters) return undefined;
	const der = hex(bytes(parameters));
	return (
		Object.keys(CURVES).find((oid) => CURVES[oid].der === der) ??
		`parameters ${der}`
	);
}

export function parseCert(raw: Bytes): Cert {
	const c = AsnConvert.parse(raw, Certificate);
	if (!equalBytes(der(c), raw))
		throw new Error("the certificate is not distinguished-encoded");
	const t = c.tbsCertificate;
	// The outer algorithm is outside the signature, so it must be the signed one, as RFC 5280 says.
	if (!equalBytes(der(c.signatureAlgorithm), der(t.signature)))
		throw new Error("the certificate's two signature algorithms differ");
	const parameters = c.signatureAlgorithm.parameters;
	const extensions = t.extensions ?? [];
	const extension = (id: string) =>
		extensions.find((e) => e.extnID === id)?.extnValue.buffer;
	const constraints = extension(id_ce_basicConstraints);
	const basic = constraints
		? AsnConvert.parse(constraints, BasicConstraints)
		: undefined;
	const usage = extension(id_ce_keyUsage);
	return {
		der: raw,
		tbs: der(t),
		serial: bytes(t.serialNumber),
		spki: der(t.subjectPublicKeyInfo),
		issuer: der(t.issuer),
		subject: der(t.subject),
		signatureAlgorithm: c.signatureAlgorithm.algorithm,
		signatureParameters: parameters ? bytes(parameters) : undefined,
		signature: bytes(c.signatureValue),
		keyAlgorithm: t.subjectPublicKeyInfo.algorithm.algorithm,
		curve:
			t.subjectPublicKeyInfo.algorithm.algorithm === EC_KEY
				? curveOf(t.subjectPublicKeyInfo.algorithm.parameters ?? undefined)
				: undefined,
		notBefore: t.validity.notBefore.getTime(),
		notAfter: t.validity.notAfter.getTime(),
		ca: basic?.cA ? { pathLen: basic.pathLenConstraint } : undefined,
		keyUsage: usage ? AsnConvert.parse(usage, KeyUsage).toNumber() : undefined,
		unhandledCritical: extensions
			.filter((e) => e.critical && !HANDLED_CRITICAL.has(e.extnID))
			.map((e) => e.extnID),
	};
}

export function parsePem(pem: string): Cert {
	const body = pem.replace(/-----[^-]+-----|\s/g, "");
	const der = fromBase64(body);
	if (!der) throw new Error("the PEM body is not base64");
	return parseCert(der);
}

function scalar(b: Bytes, size: number): Bytes | undefined {
	let start = 0;
	while (start < b.length && b[start] === 0) start++;
	if (b.length - start > size) return undefined;
	const out = new Uint8Array(size);
	out.set(b.subarray(start), size - (b.length - start));
	return out;
}

export async function importKey(
	cert: Cert,
	hash: string,
	rsa: "RSASSA-PKCS1-v1_5" | "RSA-PSS" = "RSASSA-PKCS1-v1_5",
): Promise<CryptoKey> {
	if (cert.keyAlgorithm === RSA_KEY)
		return crypto.subtle.importKey(
			"spki",
			cert.spki,
			{ name: rsa, hash },
			false,
			["verify"],
		);
	const curve = cert.curve && CURVES[cert.curve];
	if (cert.keyAlgorithm === EC_KEY && curve)
		return crypto.subtle.importKey(
			"spki",
			cert.spki,
			{ name: "ECDSA", namedCurve: curve.name },
			false,
			["verify"],
		);
	throw new Error(`unsupported key ${cert.keyAlgorithm} ${cert.curve ?? ""}`);
}

/** A positive DER INTEGER's content: no sign bit, and a leading zero only where one is due. */
const minimalUnsigned = (v: Bytes) =>
	v.length > 0 &&
	!(v[0] & 0x80) &&
	!(v[0] === 0 && v.length > 1 && !(v[1] & 0x80));

/** An ECDSA-Sig-Value in DER and nothing else: it re-encodes to the same bytes, and neither
 * integer is negative or padded. Anything looser would let one signature have many encodings. */
function strictSignature(der: Bytes): { r: Bytes; s: Bytes } | undefined {
	let sig: EcdsaSignature;
	try {
		sig = AsnConvert.parse(der, EcdsaSignature);
	} catch {
		return undefined;
	}
	if (!equalBytes(bytes(AsnConvert.serialize(sig)), der)) return undefined;
	const [r, s] = [bytes(sig.r), bytes(sig.s)];
	return minimalUnsigned(r) && minimalUnsigned(s) ? { r, s } : undefined;
}

/** SHA-384 with its parameters absent or NULL, which RFC 4055 has mean the same. */
const isSha384 = (a: AlgorithmIdentifier | undefined) =>
	a?.algorithm === SHA384 &&
	(!a.parameters || hex(bytes(a.parameters)) === "0500");

/** Whether RSASSA-PSS parameters name SHA-384, MGF1 with SHA-384, a 48-byte salt, and trailer
 * 1, the only set verified (AMD signs its SEV certificates with it). WebCrypto takes the salt
 * length alone and uses the key's hash for MGF1 and the trailer 0xBC, so a set it can't express
 * is refused here rather than verified as something else. The parameters must re-encode to
 * their own bytes; AMD's ARK and ASK write the default trailer out, and that re-encodes too. */
function sha384Pss(parameters: Bytes | undefined): boolean {
	if (!parameters) return false;
	try {
		const p = AsnConvert.parse(parameters, PssParams);
		const mgf = p.maskGenAlgorithm;
		return (
			equalBytes(der(p), parameters) &&
			isSha384(p.hashAlgorithm) &&
			mgf?.algorithm === MGF1 &&
			!!mgf.parameters &&
			isSha384(AsnConvert.parse(mgf.parameters, AlgorithmIdentifier)) &&
			p.saltLength === PSS_SALT &&
			(p.trailerField ?? 1) === 1
		);
	} catch {
		return false;
	}
}

async function signedBy(child: Cert, parent: Cert): Promise<boolean> {
	if (!equalBytes(child.issuer, parent.subject)) return false;
	const alg = SIGNATURES[child.signatureAlgorithm];
	if (!alg || alg.key !== parent.keyAlgorithm) return false;
	if (alg.pss)
		return (
			sha384Pss(child.signatureParameters) &&
			crypto.subtle.verify(
				{ name: "RSA-PSS", saltLength: PSS_SALT },
				await importKey(parent, alg.hash, "RSA-PSS"),
				child.signature,
				child.tbs,
			)
		);
	const key = await importKey(parent, alg.hash);
	if (alg.key === RSA_KEY)
		return crypto.subtle.verify(
			"RSASSA-PKCS1-v1_5",
			key,
			child.signature,
			child.tbs,
		);
	const raw = rawEcdsaSignature(
		child.signature,
		CURVES[parent.curve ?? ""].size,
	);
	if (!raw) return false;
	return crypto.subtle.verify(
		{ name: "ECDSA", hash: alg.hash },
		key,
		raw,
		child.tbs,
	);
}

/** A DER ECDSA-Sig-Value as the `size`-byte r ‖ s WebCrypto verifies, or undefined when it is
 * not strict DER or either integer exceeds the curve. */
export function rawEcdsaSignature(der: Bytes, size: number): Bytes | undefined {
	const sig = strictSignature(der);
	if (!sig) return undefined;
	const r = scalar(sig.r, size);
	const s = scalar(sig.s, size);
	return r && s ? concat([r, s]) : undefined;
}

function checkIssuer(issuer: Cert, below: number, name: string) {
	if (!issuer.ca) throw new Error(`${name} is not a CA`);
	if (
		issuer.keyUsage !== undefined &&
		(issuer.keyUsage & KeyUsageFlags.keyCertSign) === 0
	)
		throw new Error(`${name} may not sign certificates`);
	if (issuer.ca.pathLen !== undefined && below > issuer.ca.pathLen)
		throw new Error(
			`${name} allows ${issuer.ca.pathLen} intermediates below it, the chain has ${below}`,
		);
}

export interface Path {
	readonly leaf: Cert;
	readonly notAfter: Date;
}

export async function verifyChain(
	chain: readonly Cert[],
	anchor: Cert,
	now: Date,
): Promise<Path> {
	const t = now.getTime();
	const check = (cert: Cert, name: string) => {
		if (!(cert.notBefore.getTime() <= t && t <= cert.notAfter.getTime()))
			throw new Error(
				`${name} is valid ${cert.notBefore.toISOString()} to ${cert.notAfter.toISOString()}, not at ${now.toISOString()}`,
			);
		if (cert.unhandledCritical.length > 0)
			throw new Error(
				`${name} has unhandled critical extensions ${cert.unhandledCritical.join(",")}`,
			);
	};
	check(anchor, "the pinned anchor");
	for (const [i, cert] of chain.entries()) {
		check(cert, `certificate ${i}`);
		if (i > 0) checkIssuer(cert, i - 1, `certificate ${i}`);
		if (await signedBy(cert, anchor)) {
			checkIssuer(anchor, i, "the pinned anchor");
			const path = [anchor, ...chain.slice(0, i + 1)];
			return {
				leaf: chain[0],
				notAfter: new Date(Math.min(...path.map((c) => c.notAfter.getTime()))),
			};
		}
		const parent = chain[i + 1];
		if (!parent || !(await signedBy(cert, parent)))
			throw new Error(
				`certificate ${i} is signed by neither the next one nor the pinned anchor`,
			);
	}
	throw new Error("the chain is empty");
}
