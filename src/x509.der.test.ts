import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
	AlgorithmIdentifier,
	AttributeTypeAndValue,
	AttributeValue,
	BasicConstraints,
	Certificate,
	Extension,
	Extensions,
	id_ce_basicConstraints,
	id_ce_keyUsage,
	KeyUsage,
	KeyUsageFlags,
	Name,
	RelativeDistinguishedName,
	SubjectPublicKeyInfo,
	TBSCertificate,
	Validity,
	Version,
} from "@peculiar/asn1-x509";
import { expect, it } from "vitest";
import { parseCert, verifyChain } from "./x509.ts";

const ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const EC_KEY = "1.2.840.10045.2.1";
const NOW = new Date("2026-10-01T09:00:00Z");
const HOUR = 3600_000;
const hexb = (h: string) =>
	Uint8Array.from(Buffer.from(h.replace(/\s/g, ""), "hex"));
const cat = (...parts: Uint8Array[]) =>
	Uint8Array.from(parts.flatMap((p) => [...p]));

const nameOf = (cn: string) =>
	new Name([
		new RelativeDistinguishedName([
			new AttributeTypeAndValue({
				type: "2.5.4.3",
				value: new AttributeValue({ utf8String: cn }),
			}),
		]),
	]);

const keypair = () =>
	crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, [
		"sign",
		"verify",
	]);

async function spkiOf(key: CryptoKey, params?: string | null) {
	const spki = AsnConvert.parse(
		await crypto.subtle.exportKey("spki", key),
		SubjectPublicKeyInfo,
	);
	if (params !== undefined)
		spki.algorithm = new AlgorithmIdentifier({
			algorithm: EC_KEY,
			parameters: params === null ? undefined : hexb(params).buffer,
		});
	return spki;
}

function tbsFor(
	subject: string,
	issuer: string,
	spki: SubjectPublicKeyInfo,
	ca: boolean,
) {
	const ext = ca
		? [
				new Extension({
					extnID: id_ce_basicConstraints,
					critical: true,
					extnValue: new OctetString(
						AsnConvert.serialize(new BasicConstraints({ cA: true })),
					),
				}),
				new Extension({
					extnID: id_ce_keyUsage,
					critical: true,
					extnValue: new OctetString(
						AsnConvert.serialize(
							new KeyUsage(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign),
						),
					),
				}),
			]
		: [
				new Extension({
					extnID: id_ce_keyUsage,
					critical: true,
					extnValue: new OctetString(
						AsnConvert.serialize(new KeyUsage(KeyUsageFlags.digitalSignature)),
					),
				}),
			];
	return new TBSCertificate({
		version: Version.v3,
		serialNumber: new Uint8Array([1, 2, 3, 4]).buffer,
		signature: new AlgorithmIdentifier({ algorithm: ECDSA_SHA384 }),
		issuer: nameOf(issuer),
		validity: new Validity({
			notBefore: new Date(NOW.getTime() - HOUR),
			notAfter: new Date(NOW.getTime() + HOUR),
		}),
		subject: nameOf(subject),
		subjectPublicKeyInfo: spki,
		extensions: new Extensions(ext),
	});
}

const rawSign = async (key: CryptoKey, data: Uint8Array<ArrayBuffer>) =>
	new Uint8Array(
		await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-384" }, key, data),
	);

const certBytes = (tbs: TBSCertificate, sigValue: Uint8Array) =>
	new Uint8Array(
		AsnConvert.serialize(
			new Certificate({
				tbsCertificate: tbs,
				signatureAlgorithm: new AlgorithmIdentifier({
					algorithm: ECDSA_SHA384,
				}),
				signatureValue: sigValue.buffer as ArrayBuffer,
			}),
		),
	);

const len = (n: number) => (n < 0x80 ? [n] : [0x81, n]);
const tlv = (tag: number, body: Uint8Array) =>
	cat(new Uint8Array([tag, ...len(body.length)]), body);
const strip = (b: Uint8Array) => {
	let i = 0;
	while (i < b.length - 1 && b[i] === 0) i++;
	return b.subarray(i);
};
const minimalInt = (raw: Uint8Array) => {
	const v = strip(raw);
	return tlv(0x02, v[0] & 0x80 ? cat(new Uint8Array([0]), v) : v);
};

interface Signed {
	r: Uint8Array;
	s: Uint8Array;
}

type Encoding = (sig: Signed) => Uint8Array;
const N384 = BigInt(
	"0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
);
const toBig = (b: Uint8Array) =>
	BigInt(`0x${Buffer.from(b).toString("hex") || "0"}`);
const toBytes = (n: bigint, size = 48) =>
	hexb(n.toString(16).padStart(size * 2, "0"));

const ENCODINGS: Record<string, Encoding> = {
	"minimal DER (control)": ({ r, s }) =>
		tlv(0x30, cat(minimalInt(r), minimalInt(s))),
	"trailing bytes after the SEQUENCE": ({ r, s }) =>
		cat(tlv(0x30, cat(minimalInt(r), minimalInt(s))), hexb("0000")),
	"a third INTEGER inside the SEQUENCE": ({ r, s }) =>
		tlv(0x30, cat(minimalInt(r), minimalInt(s), hexb("020100"))),
	"negative INTEGER r (high bit set, no 0x00 pad)": ({ r, s }) =>
		tlv(0x30, cat(tlv(0x02, strip(r)), minimalInt(s))),
	"leading-zero rule violated (extra 0x00 before r)": ({ r, s }) =>
		tlv(
			0x30,
			cat(tlv(0x02, cat(new Uint8Array([0, 0]), strip(r))), minimalInt(s)),
		),
	"long-form length on a short INTEGER": ({ r, s }) => {
		const v = minimalInt(r).subarray(2);
		return tlv(
			0x30,
			cat(new Uint8Array([0x02, 0x81, v.length]), v, minimalInt(s)),
		);
	},
	"indefinite-length SEQUENCE": ({ r, s }) =>
		cat(hexb("3080"), minimalInt(r), minimalInt(s), hexb("0000")),
	"SET instead of SEQUENCE": ({ r, s }) =>
		tlv(0x31, cat(minimalInt(r), minimalInt(s))),
	"OCTET STRING instead of INTEGER r": ({ r, s }) =>
		tlv(0x30, cat(tlv(0x04, strip(r)), minimalInt(s))),
	"r and s swapped": ({ r, s }) => tlv(0x30, cat(minimalInt(s), minimalInt(r))),
	"r = 0": ({ s }) => tlv(0x30, cat(hexb("020100"), minimalInt(s))),
	"high-s twin (n - s), minimal DER": ({ r, s }) =>
		tlv(0x30, cat(minimalInt(r), minimalInt(toBytes(N384 - toBig(s))))),
	"r + n (49 bytes)": ({ r, s }) =>
		tlv(0x30, cat(minimalInt(toBytes(toBig(r) + N384, 49)), minimalInt(s))),
};

async function chainWith(encode: Encoding, needHighR = false) {
	const anchorKeys = await keypair();
	const anchorTbs = tbsFor(
		"Anchor",
		"Anchor",
		await spkiOf(anchorKeys.publicKey),
		true,
	);
	const anchorRaw = await rawSign(
		anchorKeys.privateKey,
		new Uint8Array(AsnConvert.serialize(anchorTbs)),
	);
	const anchor = parseCert(
		certBytes(
			anchorTbs,
			new Uint8Array(
				AsnConvert.serialize(
					new ECDSASigValue({
						r: anchorRaw.slice(0, 48).buffer,
						s: anchorRaw.slice(48).buffer,
					}),
				),
			),
		),
	);
	const leafKeys = await keypair();
	const leafTbs = tbsFor(
		"Leaf",
		"Anchor",
		await spkiOf(leafKeys.publicKey),
		false,
	);
	for (;;) {
		const raw = await rawSign(
			anchorKeys.privateKey,
			new Uint8Array(AsnConvert.serialize(leafTbs)),
		);
		const sig = { r: raw.slice(0, 48), s: raw.slice(48) };
		if (needHighR && (sig.r[0] & 0x80) === 0) continue;
		if (!needHighR && strip(sig.r)[0] & 0x80) continue;
		return {
			anchor,
			leafDer: certBytes(leafTbs, encode(sig)),
			sigDer: encode(sig),
		};
	}
}

const outcome = async (
	anchor: ReturnType<typeof parseCert>,
	leafDer: Uint8Array<ArrayBuffer>,
) => {
	try {
		await verifyChain([parseCert(leafDer)], anchor, NOW);
		return "accepted";
	} catch (e) {
		return `refused: ${e instanceof Error ? e.message : e}`;
	}
};

// A signature verifies only in its one DER encoding. High-s is a different signature, not a
// different encoding, so it verifies as ECDSA allows.
for (const [name, encode] of Object.entries(ENCODINGS))
	it(`verifies a chain signed as: ${name} only when that is minimal DER`, async () => {
		const { anchor, leafDer } = await chainWith(
			encode,
			name.startsWith("negative"),
		);
		const minimal = name.includes("control") || name.includes("high-s");
		expect(await outcome(anchor, leafDer)).toBe(
			minimal
				? "accepted"
				: "refused: certificate 0 is signed by neither the next one nor the pinned anchor",
		);
	});
