import { KeyUsageFlags } from "@peculiar/asn1-x509";
import { type Bytes, concat, enc, toBase64, unhex } from "../bytes.ts";
import { encodeCborArray } from "../cbor.ts";
import { USER_DATA_PREFIX } from "../nitro.ts";
import type { PinnedImage } from "../pins.ts";
import { parseCert } from "../x509.ts";
import { issue, party } from "./certs.ts";

type Value =
	| number
	| string
	| Bytes
	| null
	| Value[]
	| Map<number | string, Value>;

function head(major: number, n: number): Bytes {
	if (n < 24) return Uint8Array.of((major << 5) | n);
	if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
	if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
	if (n < 2 ** 32) {
		const out = new Uint8Array(5);
		out[0] = (major << 5) | 26;
		new DataView(out.buffer).setUint32(1, n);
		return out;
	}
	const out = new Uint8Array(9);
	out[0] = (major << 5) | 27;
	new DataView(out.buffer).setBigUint64(1, BigInt(n));
	return out;
}

function cbor(v: Value): Bytes {
	if (v === null) return Uint8Array.of(0xf6);
	if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
	if (typeof v === "string") {
		const bytes = enc.encode(v);
		return concat([head(3, bytes.length), bytes]);
	}
	if (v instanceof Uint8Array) return concat([head(2, v.length), v]);
	if (Array.isArray(v)) return concat([head(4, v.length), ...v.map(cbor)]);
	return concat([
		head(5, v.size),
		...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)]),
	]);
}

export const PCR = {
	pcr0: "a0".repeat(48),
	pcr1: "a1".repeat(48),
	pcr2: "a2".repeat(48),
};

export const pinOf = (o: Partial<PinnedImage> = {}): PinnedImage => ({
	commit: "c0ffee",
	version: "v1.2.3",
	environment: "dev",
	...PCR,
	built_at: "2026-10-01T00:00:00Z",
	revoked: false,
	...o,
});

export interface DocumentOptions {
	timestamp: number;
	publicKey: Bytes;
	environment?: string;
	userData?: Bytes;
	pcrs?: { pcr0: string; pcr1: string; pcr2: string };
	digest?: string;
	alg?: number;
	signWith?: "leaf" | "stranger";
	/** The document's public_key, the SPKI the enclave's TLS ends with. */
	tlsKey?: Bytes;
	moduleId?: string;
}

/** A test root and documents it signs, with certificates valid for 30 days either side of `now`. */
export async function forgeNitro(now = new Date()) {
	const rootParty = await party("aws.nitro-enclaves");
	const intermediate = await party("zonal.aws.nitro-enclaves");
	const leafParty = await party("i-0123.enc0123.aws");
	const stranger = await party("stranger");
	const ca = { ca: true, keyUsage: KeyUsageFlags.keyCertSign };
	const window = {
		notBefore: new Date(now.getTime() - 30 * 86_400_000),
		notAfter: new Date(now.getTime() + 30 * 86_400_000),
	};
	const rootDer = await issue(rootParty, rootParty, now, { ...ca, ...window });
	const intermediateDer = await issue(intermediate, rootParty, now, {
		...ca,
		...window,
	});
	const leafDer = await issue(leafParty, intermediate, now, {
		ca: false,
		keyUsage: KeyUsageFlags.digitalSignature,
		...window,
	});
	const document = async (o: DocumentOptions): Promise<Bytes> => {
		const pcrs = o.pcrs ?? PCR;
		const payload = cbor(
			new Map<string, Value>([
				["module_id", o.moduleId ?? "i-0123-enc0123"],
				["digest", o.digest ?? "SHA384"],
				["timestamp", o.timestamp],
				[
					"pcrs",
					new Map<number, Value>([
						[0, unhex(pcrs.pcr0)],
						[1, unhex(pcrs.pcr1)],
						[2, unhex(pcrs.pcr2)],
						[3, new Uint8Array(48)],
					]),
				],
				["certificate", leafDer],
				["cabundle", [rootDer, intermediateDer]],
				["public_key", o.tlsKey ?? null],
				[
					"user_data",
					o.userData ??
						concat([
							enc.encode(`${USER_DATA_PREFIX}${o.environment ?? "dev"}|`),
							o.publicKey,
						]),
				],
				["nonce", null],
			]),
		);
		const protectedHeader = cbor(new Map([[1, o.alg ?? -35]]));
		const signer = o.signWith === "stranger" ? stranger : leafParty;
		const signature = new Uint8Array(
			await crypto.subtle.sign(
				{ name: "ECDSA", hash: "SHA-384" },
				signer.keys.privateKey,
				encodeCborArray([
					"Signature1",
					protectedHeader,
					new Uint8Array(),
					payload,
				]),
			),
		);
		return cbor([protectedHeader, new Map(), payload, signature]);
	};
	return { root: parseCert(rootDer), document };
}

export const standIn = (o: {
	environment?: string;
	publicKey: Bytes;
	timestamp: number;
}) =>
	toBase64(
		enc.encode(
			JSON.stringify({
				object: "proxy_attestation_stand_in",
				warning:
					"not an AWS Nitro attestation: this proxy runs outside an enclave",
				environment: o.environment ?? "dev",
				user_data: toBase64(
					concat([
						enc.encode(`${USER_DATA_PREFIX}${o.environment ?? "dev"}|`),
						o.publicKey,
					]),
				),
				timestamp: o.timestamp,
			}),
		),
	);
