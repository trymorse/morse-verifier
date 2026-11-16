// why: src/testing is outside tsconfig.build.json, so this test root and its hook never ship.
import {
	createHash,
	createPublicKey,
	generateKeyPairSync,
	type KeyObject,
	sign,
} from "node:crypto";
import {
	type ListTrust,
	MORSE_TRUST,
	parseWitness,
} from "../node/signed_list.ts";
import { SIGSTORE_TRUSTED_ROOT } from "../node/sigstore_root.ts";

type Der = Buffer;
const tlv = (tag: number, ...contents: Uint8Array[]): Der => {
	const body = Buffer.concat(contents);
	const n = body.length;
	const length =
		n < 0x80
			? [n]
			: n < 0x100
				? [0x81, n]
				: n < 0x10000
					? [0x82, n >> 8, n & 0xff]
					: [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff];
	return Buffer.concat([Buffer.from([tag, ...length]), body]);
};
const seq = (...c: Uint8Array[]) => tlv(0x30, ...c);
const set = (...c: Uint8Array[]) => tlv(0x31, ...c);
const explicit = (n: number, ...c: Uint8Array[]) => tlv(0xa0 + n, ...c);
const octets = (b: Uint8Array) => tlv(0x04, b);
const utf8 = (s: string) => tlv(0x0c, Buffer.from(s, "utf8"));
const bool = (b: boolean) => tlv(0x01, Buffer.from([b ? 0xff : 0]));
const uint = (b: Uint8Array): Der => {
	let at = 0;
	while (at < b.length - 1 && b[at] === 0) at++;
	const v = b.subarray(at);
	return tlv(0x02, v[0] & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : v);
};
const small = (n: number) => uint(Buffer.from([n]));
const oid = (dotted: string): Der => {
	const [a, b, ...rest] = dotted.split(".").map(Number);
	const out = [40 * a + b];
	for (const n of rest) {
		const septets = [n & 0x7f];
		for (let v = n >>> 7; v > 0; v >>>= 7) septets.unshift((v & 0x7f) | 0x80);
		out.push(...septets);
	}
	return tlv(0x06, Buffer.from(out));
};
const utcTime = (t: number) =>
	tlv(
		0x17,
		Buffer.from(
			`${new Date(t).toISOString().slice(2, 19).replace(/[-:T]/g, "")}Z`,
		),
	);
const generalizedTime = (t: number) =>
	tlv(
		0x18,
		Buffer.from(
			`${new Date(t).toISOString().slice(0, 19).replace(/[-:T]/g, "")}Z`,
		),
	);

const ECDSA_SHA256 = "1.2.840.10045.4.3.2";
export const ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const SHA256 = "2.16.840.1.101.3.4.2.1";
const algorithm = (id: string) => seq(oid(id));
const nameOf = (organization: string, commonName: string) =>
	seq(
		set(seq(oid("2.5.4.10"), utf8(organization))),
		set(seq(oid("2.5.4.3"), utf8(commonName))),
	);
const spki = (key: KeyObject) =>
	(key.type === "private" ? createPublicKey(key) : key).export({
		type: "spki",
		format: "der",
	}) as Buffer;
const ecKeys = () => generateKeyPairSync("ec", { namedCurve: "P-256" });
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const sha256 = (...b: Uint8Array[]) => {
	const h = createHash("sha256");
	for (const x of b) h.update(x);
	return h.digest();
};

export interface Ext {
	readonly id: string;
	readonly critical: boolean;
	readonly value: Uint8Array;
	readonly der?: Uint8Array;
}
const extensionDer = (e: Ext) =>
	e.der ?? seq(oid(e.id), ...(e.critical ? [bool(true)] : []), octets(e.value));

interface CertSpec {
	readonly serial: Uint8Array;
	readonly issuer: Der;
	readonly subject: Der;
	readonly notBefore: number;
	readonly notAfter: number;
	readonly key: KeyObject;
	readonly extensions: readonly Ext[];
	readonly innerAlgorithm?: string;
}
const tbsOf = (c: CertSpec) =>
	seq(
		explicit(0, small(2)),
		uint(c.serial),
		algorithm(c.innerAlgorithm ?? ECDSA_SHA256),
		c.issuer,
		seq(utcTime(c.notBefore), utcTime(c.notAfter)),
		c.subject,
		spki(c.key),
		...(c.extensions.length > 0
			? [explicit(3, seq(...c.extensions.map(extensionDer)))]
			: []),
	);
const signed = (tbs: Der, by: KeyObject) =>
	seq(
		tbs,
		algorithm(ECDSA_SHA256),
		tlv(0x03, Buffer.from([0]), sign("sha256", tbs, by)),
	);

const serial = () => {
	const b = createHash("sha256").update(String(Math.random())).digest();
	b[0] = (b[0] & 0x7f) | 0x10;
	return b.subarray(0, 16);
};

const KEY_USAGE = "2.5.29.15";
const BASIC_CONSTRAINTS = "2.5.29.19";
const EXT_KEY_USAGE = "2.5.29.37";
const SUBJECT_ALT_NAME = "2.5.29.17";
const SCT_LIST = "1.3.6.1.4.1.11129.2.4.2";
const CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
export const FULCIO = "1.3.6.1.4.1.57264.1.";

interface Authority {
	readonly name: Der;
	readonly key: KeyObject;
	readonly cert: Der;
}
function authority(
	organization: string,
	commonName: string,
	from: number,
): Authority {
	const { publicKey, privateKey } = ecKeys();
	const name = nameOf(organization, commonName);
	const cert = signed(
		tbsOf({
			serial: serial(),
			issuer: name,
			subject: name,
			notBefore: from,
			notAfter: from + 3650 * 86400_000,
			key: publicKey,
			extensions: [
				{
					id: KEY_USAGE,
					critical: true,
					value: tlv(0x03, Buffer.from([1, 6])),
				},
				{ id: BASIC_CONSTRAINTS, critical: true, value: seq(bool(true)) },
			],
		}),
		privateKey,
	);
	return { name, key: privateKey, cert };
}

export const SIGNED = Date.parse("2026-11-10T10:00:00Z");
export const EXPIRED = SIGNED + 10 * 60_000;
export const AT = SIGNED + 40 * 60_000;
const SINCE = Date.parse("2026-01-01T00:00:00Z");

const FULCIO_CA = authority("fulcio.test.example", "test fulcio", SINCE);
const OTHER_CA = authority("fulcio.test.example", "test fulcio", SINCE);
const TSA_ROOT = authority("tsa.test.example", "test tsa root", SINCE);
const TSA_KEYS = ecKeys();
const TSA_SERIAL = serial();
const TSA_NAME = nameOf("tsa.test.example", "test tsa");
const TSA_LEAF = signed(
	tbsOf({
		serial: TSA_SERIAL,
		issuer: TSA_ROOT.name,
		subject: TSA_NAME,
		notBefore: SINCE,
		notAfter: SINCE + 3650 * 86400_000,
		key: TSA_KEYS.publicKey,
		extensions: [
			{
				id: EXT_KEY_USAGE,
				critical: true,
				value: seq(oid("1.3.6.1.5.5.7.3.8")),
			},
		],
	}),
	TSA_ROOT.key,
);
const CT = ecKeys();
const CT_ID = sha256(spki(CT.publicKey));
const OTHER_CT = ecKeys();
const LOG = generateKeyPairSync("ed25519");
const LOG_ORIGIN = "rekor.test.example";
const LOG_ID = sha256(spki(LOG.publicKey));

export const TEST_TRUSTED_ROOT = {
	mediaType: SIGSTORE_TRUSTED_ROOT.mediaType,
	tlogs: [
		{
			baseUrl: `https://${LOG_ORIGIN}`,
			hashAlgorithm: "SHA2_256",
			publicKey: {
				rawBytes: b64(spki(LOG.publicKey)),
				keyDetails: "PKIX_ED25519",
				validFor: { start: new Date(SINCE).toISOString() },
			},
			logId: { keyId: b64(LOG_ID) },
		},
	],
	certificateAuthorities: [
		{
			subject: {
				organization: "fulcio.test.example",
				commonName: "test fulcio",
			},
			uri: "https://fulcio.test.example",
			certChain: { certificates: [{ rawBytes: b64(FULCIO_CA.cert) }] },
			validFor: { start: new Date(SINCE).toISOString() },
		},
	],
	ctlogs: [
		{
			baseUrl: "https://ct.test.example",
			hashAlgorithm: "SHA2_256",
			publicKey: {
				rawBytes: b64(spki(CT.publicKey)),
				keyDetails: "PKIX_ECDSA_P256_SHA_256",
				validFor: { start: new Date(SINCE).toISOString() },
			},
			logId: { keyId: b64(CT_ID) },
		},
	],
	timestampAuthorities: [
		{
			subject: { organization: "tsa.test.example", commonName: "test tsa" },
			uri: "https://tsa.test.example",
			certChain: {
				certificates: [
					{ rawBytes: b64(TSA_LEAF) },
					{ rawBytes: b64(TSA_ROOT.cert) },
				],
			},
			validFor: { start: new Date(SINCE).toISOString() },
		},
	],
};

// why: verifySignedList is synchronous and reads SIGSTORE_TRUSTED_ROOT on each call, so the swap
// is seen by `fn` alone, and the finally restores it even when `fn` throws.
export function underTestRoot<T>(fn: () => T): T {
	const root = SIGSTORE_TRUSTED_ROOT as Record<string, unknown>;
	const saved = { ...root };
	Object.assign(root, TEST_TRUSTED_ROOT);
	try {
		return fn();
	} finally {
		for (const key of Object.keys(root)) delete root[key];
		Object.assign(root, saved);
	}
}

const WITNESSES = ["a", "b", "c"].map((n) => {
	const name = `witness-${n}.test.example`;
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const key = Buffer.from(
		publicKey.export({ format: "jwk" }).x ?? "",
		"base64url",
	);
	const hash = sha256(Buffer.from(`${name}\n\x04`, "latin1"), key).subarray(
		0,
		4,
	);
	const vkey = `${name}+${hash.toString("hex")}+${b64(Buffer.concat([Buffer.from([4]), key]))}`;
	const cosign = (text: string, at: number) => {
		const time = Buffer.alloc(8);
		time.writeBigUInt64BE(BigInt(Math.floor(at / 1000)));
		const signature = sign(
			null,
			Buffer.from(`cosignature/v1\ntime ${Math.floor(at / 1000)}\n${text}`),
			privateKey,
		);
		return `— ${name} ${b64(Buffer.concat([hash, time, signature]))}`;
	};
	return { witness: parseWitness(vkey, `test operator ${n}`), cosign };
});

export const TEST_TRUST: ListTrust = {
	...MORSE_TRUST,
	witnesses: WITNESSES.map((w) => w.witness),
};

export const WORKFLOW_URI =
	"https://github.com/trymorse/morse-pins/.github/workflows/sign.yml@refs/heads/main";
export const COMMIT = "c0ffee".padEnd(40, "0");
const ISSUER = "https://token.actions.githubusercontent.com";

export const FULCIO_VALUES: Readonly<Record<number, string>> = {
	8: ISSUER,
	9: WORKFLOW_URI,
	10: COMMIT,
	11: "github-hosted",
	12: "https://github.com/trymorse/morse-pins",
	13: COMMIT,
	14: "refs/heads/main",
	15: "1437511167",
	16: "https://github.com/trymorse",
	17: "345029672",
	18: WORKFLOW_URI,
	19: COMMIT,
	20: "schedule",
	21: "https://github.com/trymorse/morse-pins/actions/runs/19000000001/attempts/1",
	22: "public",
};

export const fulcio = (n: number, value: string): Ext => ({
	id: `${FULCIO}${n}`,
	critical: false,
	value: utf8(value),
});

const LEAF_EXTENSIONS: readonly Ext[] = [
	{ id: KEY_USAGE, critical: true, value: tlv(0x03, Buffer.from([7, 0x80])) },
	{ id: EXT_KEY_USAGE, critical: false, value: seq(oid(CODE_SIGNING)) },
	subjectAltName(WORKFLOW_URI),
	{ id: `${FULCIO}1`, critical: false, value: Buffer.from(ISSUER) },
	...Object.entries(FULCIO_VALUES).map(([n, v]) => fulcio(Number(n), v)),
];

export const extKeyUsage = (...ids: string[]): Ext => ({
	id: EXT_KEY_USAGE,
	critical: false,
	value: seq(...ids.map(oid)),
});

export function subjectAltName(uri: string): Ext {
	return {
		id: SUBJECT_ALT_NAME,
		critical: true,
		value: seq(tlv(0x86, Buffer.from(uri))),
	};
}

export const spelledOutFalse = (e: Ext): Ext => ({
	...e,
	der: seq(oid(e.id), bool(false), octets(e.value)),
});

export const EXTENSION = { KEY_USAGE, EXT_KEY_USAGE, SUBJECT_ALT_NAME };

export const replacing =
	(id: string, ...by: Ext[]) =>
	(es: readonly Ext[]): readonly Ext[] =>
		es.flatMap((e) => (e.id === id ? by : [e]));

export interface Forgery {
	readonly extensions?: (e: readonly Ext[]) => readonly Ext[];
	readonly untrustedCa?: boolean;
	readonly sct?: "none" | "untrusted";
	readonly innerAlgorithm?: string;
	readonly timestampAt?: number;
	readonly cosignedAt?: readonly number[];
	readonly pinsCommit?: string;
}

const canonical = (v: unknown): string =>
	Array.isArray(v)
		? `[${v.map(canonical).join(",")}]`
		: v !== null && typeof v === "object"
			? `{${Object.keys(v)
					.sort()
					.map(
						(k) =>
							`${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`,
					)
					.join(",")}}`
			: JSON.stringify(v);

const leafHash = (b: Uint8Array) => sha256(Buffer.from([0]), b);
const split = (n: number) => 2 ** Math.floor(Math.log2(n - 1));
const treeHash = (leaves: Buffer[]): Buffer =>
	leaves.length === 1
		? leaves[0]
		: sha256(
				Buffer.from([1]),
				treeHash(leaves.slice(0, split(leaves.length))),
				treeHash(leaves.slice(split(leaves.length))),
			);
const auditPath = (m: number, leaves: Buffer[]): Buffer[] => {
	if (leaves.length === 1) return [];
	const k = split(leaves.length);
	return m < k
		? [...auditPath(m, leaves.slice(0, k)), treeHash(leaves.slice(k))]
		: [...auditPath(m - k, leaves.slice(k)), treeHash(leaves.slice(0, k))];
};

function sctList(
	precertTbs: Der,
	issuerSpki: Buffer,
	key: KeyObject,
	at: number,
) {
	const time = Buffer.alloc(8);
	time.writeBigUInt64BE(BigInt(at));
	const length = (n: number, bytes: number) => {
		const b = Buffer.alloc(bytes);
		b.writeUIntBE(n, 0, bytes);
		return b;
	};
	const signature = sign(
		"sha256",
		Buffer.concat([
			Buffer.from([0, 0]),
			time,
			length(1, 2),
			sha256(issuerSpki),
			length(precertTbs.length, 3),
			precertTbs,
			length(0, 2),
		]),
		key,
	);
	const sct = Buffer.concat([
		Buffer.from([0]),
		CT_ID,
		time,
		length(0, 2),
		Buffer.from([4, 3]),
		length(signature.length, 2),
		signature,
	]);
	const list = Buffer.concat([length(sct.length, 2), sct]);
	return octets(Buffer.concat([length(list.length, 2), list]));
}

function timestamp(signature: Buffer, at: number): Buffer {
	const info = seq(
		small(1),
		oid("1.3.6.1.4.1.57264.2"),
		seq(algorithm(SHA256), octets(sha256(signature))),
		uint(serial()),
		generalizedTime(at),
	);
	const attributes = [
		seq(oid("1.2.840.113549.1.9.3"), set(oid("1.2.840.113549.1.9.16.1.4"))),
		seq(oid("1.2.840.113549.1.9.4"), set(octets(sha256(info)))),
	];
	const signerInfo = seq(
		small(1),
		// why: RFC 5652's IssuerAndSerialNumber names the issuer of the TSA's certificate.
		seq(TSA_ROOT.name, uint(TSA_SERIAL)),
		algorithm(SHA256),
		tlv(0xa0, ...attributes),
		algorithm(ECDSA_SHA256),
		octets(sign("sha256", set(...attributes), TSA_KEYS.privateKey)),
	);
	const signedData = seq(
		small(3),
		set(algorithm(SHA256)),
		seq(oid("1.2.840.113549.1.9.16.1.4"), explicit(0, octets(info))),
		set(signerInfo),
	);
	return seq(
		seq(small(0)),
		seq(oid("1.2.840.113549.1.7.2"), explicit(0, signedData)),
	);
}

export function forgeList(f: Forgery = {}) {
	const statement = Buffer.from(
		canonical({
			environment: "prod",
			images: [
				{
					pcr0: "a0".repeat(48),
					pcr1: "a1".repeat(48),
					pcr2: "a2".repeat(48),
					revoked: false,
				},
			],
			pins_commit: f.pinsCommit ?? COMMIT,
			sequence: 9,
			time: "2026-11-10T09:59:30Z",
			type: "morse-enclave-pins-v1",
		}),
	);
	const leafKeys = ecKeys();
	const ca = f.untrustedCa ? OTHER_CA : FULCIO_CA;
	const leaf: CertSpec = {
		serial: serial(),
		issuer: ca.name,
		subject: seq(),
		notBefore: SIGNED,
		notAfter: EXPIRED,
		key: leafKeys.publicKey,
		extensions: f.extensions?.(LEAF_EXTENSIONS) ?? LEAF_EXTENSIONS,
		innerAlgorithm: f.innerAlgorithm,
	};
	const sct =
		f.sct === "none"
			? []
			: [
					{
						id: SCT_LIST,
						critical: false,
						// why: RFC 6962 signs the precertificate's TBS, which has no SCT list.
						value: sctList(
							tbsOf(leaf),
							spki(ca.key),
							f.sct === "untrusted" ? OTHER_CT.privateKey : CT.privateKey,
							SIGNED,
						),
					},
				];
	const certificate = signed(
		tbsOf({ ...leaf, extensions: [...leaf.extensions, ...sct] }),
		ca.key,
	);

	const digest = sha256(statement);
	const signature = sign("sha256", statement, leafKeys.privateKey);
	const body = Buffer.from(
		JSON.stringify({
			apiVersion: "0.0.2",
			kind: "hashedrekord",
			spec: {
				hashedRekordV002: {
					data: { algorithm: "SHA2_256", digest: b64(digest) },
					signature: {
						content: b64(signature),
						verifier: {
							x509Certificate: { rawBytes: b64(certificate) },
							keyDetails: "PKIX_ECDSA_P256_SHA_256",
						},
					},
				},
			},
		}),
	);
	// why: an entry inside a tree of 7 makes the audit path mix left and right siblings.
	const leaves = [0, 1, 2, 3, 4].map((i) =>
		leafHash(Buffer.from(`entry ${i}`)),
	);
	leaves.push(leafHash(body), leafHash(Buffer.from("entry 6")));
	const root = treeHash(leaves);
	const text = `${LOG_ORIGIN}\n${leaves.length}\n${b64(root)}\n`;
	const logLine = `— ${LOG_ORIGIN} ${b64(Buffer.concat([LOG_ID.subarray(0, 4), sign(null, Buffer.from(text), LOG.privateKey)]))}`;
	const cosignedAt = f.cosignedAt ?? WITNESSES.map(() => SIGNED + 2 * 60_000);
	const envelope = `${text}\n${[logLine, ...WITNESSES.map((w, i) => w.cosign(text, cosignedAt[i]))].join("\n")}\n`;

	return {
		name: "prod/9-20261110T095930Z",
		commit: "5".repeat(40),
		statement,
		bundle: {
			mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
			verificationMaterial: {
				certificate: { rawBytes: b64(certificate) },
				tlogEntries: [
					{
						logIndex: "5",
						logId: { keyId: b64(LOG_ID) },
						kindVersion: { kind: "hashedrekord", version: "0.0.2" },
						canonicalizedBody: b64(body),
						inclusionProof: {
							logIndex: "5",
							rootHash: b64(root),
							treeSize: String(leaves.length),
							hashes: auditPath(5, leaves).map(b64),
							checkpoint: { envelope },
						},
					},
				],
				timestampVerificationData: {
					rfc3161Timestamps: [
						{
							signedTimestamp: b64(
								timestamp(signature, f.timestampAt ?? SIGNED + 60_000),
							),
						},
					],
				},
			},
			messageSignature: {
				messageDigest: { algorithm: "SHA2_256", digest: b64(digest) },
				signature: b64(signature),
			},
		},
	};
}
