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
	Name,
	RelativeDistinguishedName,
	SubjectPublicKeyInfo,
	TBSCertificate,
	Validity,
	Version,
} from "@peculiar/asn1-x509";
import type { Bytes } from "../bytes.ts";

const ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const HOUR = 3600_000;

export interface CertOptions {
	ca?: boolean;
	pathLen?: number;
	keyUsage?: number;
	notBefore?: Date;
	notAfter?: Date;
	critical?: string;
	oversizedR?: boolean;
}

export interface Party {
	name: string;
	keys: CryptoKeyPair;
}

export const party = async (name: string): Promise<Party> => ({
	name,
	keys: await crypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-384" },
		true,
		["sign", "verify"],
	),
});

const nameOf = (cn: string) =>
	new Name([
		new RelativeDistinguishedName([
			new AttributeTypeAndValue({
				type: "2.5.4.3",
				value: new AttributeValue({ utf8String: cn }),
			}),
		]),
	]);

const extension = (id: string, critical: boolean, value: Uint8Array) =>
	new Extension({ extnID: id, critical, extnValue: new OctetString(value) });

export async function sign(key: CryptoKey, data: Uint8Array): Promise<Bytes> {
	return new Uint8Array(
		await crypto.subtle.sign(
			{ name: "ECDSA", hash: "SHA-384" },
			key,
			new Uint8Array(data),
		),
	);
}

export async function issue(
	subject: Party,
	issuer: Party,
	now: Date,
	o: CertOptions,
): Promise<Bytes> {
	const extensions = [];
	if (o.ca !== undefined)
		extensions.push(
			extension(
				id_ce_basicConstraints,
				true,
				new Uint8Array(
					AsnConvert.serialize(
						new BasicConstraints({ cA: o.ca, pathLenConstraint: o.pathLen }),
					),
				),
			),
		);
	if (o.keyUsage !== undefined)
		extensions.push(
			extension(
				id_ce_keyUsage,
				true,
				new Uint8Array(AsnConvert.serialize(new KeyUsage(o.keyUsage))),
			),
		);
	if (o.critical)
		extensions.push(extension(o.critical, true, new Uint8Array([5, 0])));
	const tbs = new TBSCertificate({
		version: Version.v3,
		serialNumber: crypto.getRandomValues(new Uint8Array(8)).buffer,
		signature: new AlgorithmIdentifier({ algorithm: ECDSA_SHA384 }),
		issuer: nameOf(issuer.name),
		validity: new Validity({
			notBefore: o.notBefore ?? new Date(now.getTime() - HOUR),
			notAfter: o.notAfter ?? new Date(now.getTime() + 48 * HOUR),
		}),
		subject: nameOf(subject.name),
		subjectPublicKeyInfo: AsnConvert.parse(
			await crypto.subtle.exportKey("spki", subject.keys.publicKey),
			SubjectPublicKeyInfo,
		),
		extensions: extensions.length > 0 ? new Extensions(extensions) : undefined,
	});
	const raw = await sign(
		issuer.keys.privateKey,
		new Uint8Array(AsnConvert.serialize(tbs)),
	);
	const r = o.oversizedR
		? new Uint8Array([1, ...raw.slice(0, 48)])
		: raw.slice(0, 48);
	const signature = new ECDSASigValue({
		r: derInteger(r).buffer,
		s: derInteger(raw.slice(48)).buffer,
	});
	return new Uint8Array(
		AsnConvert.serialize(
			new Certificate({
				tbsCertificate: tbs,
				signatureAlgorithm: new AlgorithmIdentifier({
					algorithm: ECDSA_SHA384,
				}),
				signatureValue: AsnConvert.serialize(signature),
			}),
		),
	);
}

/** An unsigned integer as DER's minimal two's complement: no leading zeros, and a 0x00 pad
 * when the top bit is set. */
function derInteger(raw: Uint8Array): Uint8Array<ArrayBuffer> {
	let at = 0;
	while (at < raw.length - 1 && raw[at] === 0) at++;
	const v = raw.slice(at);
	return v[0] & 0x80 ? Uint8Array.from([0, ...v]) : v;
}
