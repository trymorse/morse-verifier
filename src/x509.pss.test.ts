import { readFileSync } from "node:fs";
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
	Name,
	RelativeDistinguishedName,
	SubjectPublicKeyInfo,
	TBSCertificate,
	Validity,
	Version,
} from "@peculiar/asn1-x509";
import { describe, expect, it } from "vitest";
import { type Cert, parseCert, parsePem, verifyChain } from "./x509.ts";

// AMD's Genoa ARK and ASK as KDS serves them (/vcek/v1/Genoa/cert_chain, the ASK first), and the
// VCEK KDS issued on 2026-11-03 for the chip and TCB of Tinfoil's router, valid from the day
// before. All three are signed with RSASSA-PSS, SHA-384, and a 48-byte salt.

const NOW = new Date("2026-11-03T04:12:00Z");
const HOUR = 3600_000;
const RSA_PSS = "1.2.840.113549.1.1.10";
const UNSIGNED =
	"refused: certificate 0 is signed by neither the next one nor the pinned anchor";

const testdata = (name: string) =>
	readFileSync(new URL(`./testdata/${name}`, import.meta.url));
const [ask, ark] = (
	testdata("amd_genoa_chain.pem")
		.toString()
		.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []
).map(parsePem);
const vcek = parseCert(new Uint8Array(testdata("amd_genoa_vcek.der")));

const outcome = (chain: readonly Cert[], anchor: Cert) =>
	verifyChain(chain, anchor, NOW).then(
		() => "accepted",
		(e: Error) => `refused: ${e.message}`,
	);

const hexb = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const cat = (...parts: Uint8Array[]) =>
	Uint8Array.from(parts.flatMap((p) => [...p]));
const len = (n: number) => (n < 0x80 ? [n] : [0x81, n]);
const tlv = (tag: number, ...parts: Uint8Array[]) => {
	const body = cat(...parts);
	return cat(Uint8Array.of(tag, ...len(body.length)), body);
};

// RSASSA-PSS-params in DER by hand, field by field: [0] the hash, [1] MGF1 and its hash, [2] the
// salt length, [3] the trailer field, each left out when undefined.
const OIDS = {
	"SHA-1": "06052b0e03021a",
	"SHA-256": "0609608648016503040201",
	"SHA-384": "0609608648016503040202",
	MGF1: "06092a864886f70d010108",
};
type Hash = Exclude<keyof typeof OIDS, "MGF1">;
const NULL = hexb("0500");
const ABSENT = new Uint8Array();
const sha = (hash: Hash, parameters = NULL) =>
	tlv(0x30, hexb(OIDS[hash]), parameters);
const mgf1 = (hash: Hash, parameters = NULL) =>
	tlv(0x30, hexb(OIDS.MGF1), sha(hash, parameters));
const integer = (n: number) => tlv(0x02, Uint8Array.of(n));
const params = (...fields: (Uint8Array | undefined)[]) =>
	tlv(0x30, ...fields.flatMap((f, i) => (f ? [tlv(0xa0 + i, f)] : [])));

describe("AMD's Genoa certificates", () => {
	it("are what the hand-made parameters below write, the trailer field out on the ARK and ASK only", () => {
		const amd = params(
			sha("SHA-384"),
			mgf1("SHA-384"),
			integer(48),
			integer(1),
		);
		expect(ark.signatureParameters).toEqual(amd);
		expect(ask.signatureParameters).toEqual(amd);
		expect(vcek.signatureParameters).toEqual(
			params(sha("SHA-384"), mgf1("SHA-384"), integer(48)),
		);
	});

	it("verify the ARK's signature over itself", async () => {
		expect(await outcome([ark], ark)).toBe("accepted");
	});

	it("verify the ASK under the ARK", async () => {
		expect(await outcome([ask], ark)).toBe("accepted");
	});

	it("verify the VCEK under the ASK, and through it to the ARK", async () => {
		expect(await outcome([vcek], ask)).toBe("accepted");
		expect(await outcome([vcek, ask], ark)).toBe("accepted");
	});

	it("refuse the VCEK under the ARK alone, which did not sign it", async () => {
		expect(await outcome([vcek], ark)).toBe(UNSIGNED);
	});

	it("refuse a VCEK whose outer algorithm, which no signature covers, names another salt", () => {
		const der = vcek.der.slice();
		// The outer copy follows the TBS, so its salt length, INTEGER 48, is the last one.
		der[Buffer.from(der).lastIndexOf(hexb("a203020130")) + 4] = 32;
		expect(() => parseCert(der)).toThrow(
			"the certificate's two signature algorithms differ",
		);
	});

	it("refuse an ASK whose TBS changed by one byte", async () => {
		const der = ask.der.slice();
		// The last digit of its notBefore, 221031133348Z, so the certificate still parses.
		der[Buffer.from(der).indexOf("221031133348Z") + 11] ^= 1;
		const tampered = parseCert(der);
		expect(tampered.notBefore.getTime() - ask.notBefore.getTime()).toBe(1000);
		expect(await outcome([tampered], ark)).toBe(UNSIGNED);
	});
});

const keys = crypto.subtle.generateKey(
	{
		name: "RSA-PSS",
		modulusLength: 2048,
		publicExponent: Uint8Array.of(1, 0, 1),
		hash: "SHA-384",
	},
	true,
	["sign", "verify"],
);

interface Signing {
	hash: string;
	salt: number;
}

const nameOf = (cn: string) =>
	new Name([
		new RelativeDistinguishedName([
			new AttributeTypeAndValue({
				type: "2.5.4.3",
				value: new AttributeValue({ utf8String: cn }),
			}),
		]),
	]);

/** A self-signed CA naming RSASSA-PSS with `parameters`, signed with `signing`'s hash, as
 * MGF1's too, and salt length. */
async function selfSigned(
	parameters: Uint8Array | undefined,
	signing: Signing,
) {
	const { publicKey, privateKey } = await keys;
	const algorithm = () =>
		new AlgorithmIdentifier({
			algorithm: RSA_PSS,
			parameters: parameters?.slice().buffer,
		});
	const tbs = new TBSCertificate({
		version: Version.v3,
		serialNumber: Uint8Array.of(1).buffer,
		signature: algorithm(),
		issuer: nameOf("PSS"),
		validity: new Validity({
			notBefore: new Date(NOW.getTime() - HOUR),
			notAfter: new Date(NOW.getTime() + HOUR),
		}),
		subject: nameOf("PSS"),
		subjectPublicKeyInfo: AsnConvert.parse(
			await crypto.subtle.exportKey("spki", publicKey),
			SubjectPublicKeyInfo,
		),
		extensions: new Extensions([
			new Extension({
				extnID: id_ce_basicConstraints,
				critical: true,
				extnValue: new OctetString(
					AsnConvert.serialize(new BasicConstraints({ cA: true })),
				),
			}),
		]),
	});
	const signer = await crypto.subtle.importKey(
		"pkcs8",
		await crypto.subtle.exportKey("pkcs8", privateKey),
		{ name: "RSA-PSS", hash: signing.hash },
		false,
		["sign"],
	);
	const signature = await crypto.subtle.sign(
		{ name: "RSA-PSS", saltLength: signing.salt },
		signer,
		new Uint8Array(AsnConvert.serialize(tbs)),
	);
	return parseCert(
		new Uint8Array(
			AsnConvert.serialize(
				new Certificate({
					tbsCertificate: tbs,
					signatureAlgorithm: algorithm(),
					signatureValue: signature,
				}),
			),
		),
	);
}

/** Whether WebCrypto verifies `cert`'s signature as it was made, whatever its parameters say. */
async function signatureHolds(cert: Cert, signing: Signing) {
	const key = await crypto.subtle.importKey(
		"spki",
		cert.spki,
		{ name: "RSA-PSS", hash: signing.hash },
		false,
		["verify"],
	);
	return crypto.subtle.verify(
		{ name: "RSA-PSS", saltLength: signing.salt },
		key,
		cert.signature,
		cert.tbs,
	);
}

const AMD_SIGNING = { hash: "SHA-384", salt: 48 };
type Verdict = "accepted" | "refused";

// Each certificate is signed so that a verifier taking its parameters at their word, or ignoring
// the ones WebCrypto can't express, would accept it. Only SHA-384, MGF1 with SHA-384, a 48-byte
// salt, and the trailer 0xBC pass, in DER, with the trailer written out or not.
const PARAMETERS: [string, Verdict, Uint8Array | undefined, Signing][] = [
	[
		"AMD's set, as the ARK and ASK write it",
		"accepted",
		params(sha("SHA-384"), mgf1("SHA-384"), integer(48), integer(1)),
		AMD_SIGNING,
	],
	[
		"AMD's set, as the VCEK writes it",
		"accepted",
		params(sha("SHA-384"), mgf1("SHA-384"), integer(48)),
		AMD_SIGNING,
	],
	[
		"AMD's set with the hashes' parameters absent, not NULL",
		"accepted",
		params(sha("SHA-384", ABSENT), mgf1("SHA-384", ABSENT), integer(48)),
		AMD_SIGNING,
	],
	[
		"a 32-byte salt",
		"refused",
		params(sha("SHA-384"), mgf1("SHA-384"), integer(32)),
		{ hash: "SHA-384", salt: 32 },
	],
	[
		"SHA-256 throughout",
		"refused",
		params(sha("SHA-256"), mgf1("SHA-256"), integer(32)),
		{ hash: "SHA-256", salt: 32 },
	],
	[
		"MGF1 with SHA-256",
		"refused",
		params(sha("SHA-384"), mgf1("SHA-256"), integer(48)),
		AMD_SIGNING,
	],
	[
		"trailer field 2",
		"refused",
		params(sha("SHA-384"), mgf1("SHA-384"), integer(48), integer(2)),
		AMD_SIGNING,
	],
	[
		"no parameters, so SHA-1 and a 20-byte salt",
		"refused",
		undefined,
		{ hash: "SHA-1", salt: 20 },
	],
	["NULL parameters", "refused", NULL, AMD_SIGNING],
	[
		"SHA-384 with parameters other than NULL",
		"refused",
		params(sha("SHA-384", integer(0)), mgf1("SHA-384"), integer(48)),
		AMD_SIGNING,
	],
	[
		"the salt length in a long-form length",
		"refused",
		params(sha("SHA-384"), mgf1("SHA-384"), hexb("02810130")),
		AMD_SIGNING,
	],
	[
		"a fifth field",
		"refused",
		params(
			sha("SHA-384"),
			mgf1("SHA-384"),
			integer(48),
			integer(1),
			integer(0),
		),
		AMD_SIGNING,
	],
];

it.each(
	PARAMETERS,
)("RSASSA-PSS with %s is %s", async (_, verdict, parameters, signing) => {
	const cert = await selfSigned(parameters, signing);
	expect(await signatureHolds(cert, signing)).toBe(true);
	expect(await outcome([cert], cert)).toBe(
		verdict === "accepted" ? verdict : UNSIGNED,
	);
});
