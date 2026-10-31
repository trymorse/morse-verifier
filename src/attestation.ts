import { z } from "zod";
import { type Bytes, dec, fromBase64 } from "./bytes.ts";
import {
	type AttestedKey,
	checkFresh,
	type Expectation,
	keyInUserData,
	MAX_AGE_MS,
	type NitroStep,
	verifyNitroDocument,
} from "./nitro.ts";
import { UnpinnedError } from "./pins.ts";
import { keyIdOf, MAX_KEYS } from "./seal.ts";

export interface ProxyTrustAnchors extends Omit<Expectation, "now"> {
	readonly standIns: boolean;
}

export interface ProxyKeys {
	readonly keys: readonly AttestedKey[];
	readonly expiresAt: number;
}

export class UnattestedError extends Error {
	override name = "UnattestedError";
	/** Whether an instance's document verified but names an image no pin does, which pins of a later
	 * release may. No pins lift any other refusal. */
	readonly unpinned: boolean;
	/** `refusals` is why each instance was refused, in the proxy's order. */
	constructor(readonly refusals: readonly Error[]) {
		super(
			refusals.length === 0
				? "the proxy lists no attested instance"
				: `no proxy instance is attested: ${refusals.map((r) => r.message).join("; ")}`,
		);
		this.unpinned = refusals.some((r) => r instanceof UnpinnedError);
	}
}

const STAND_IN = "proxy_attestation_stand_in";

const standIn = z.object({
	object: z.literal(STAND_IN),
	environment: z.string(),
	user_data: z.string(),
	timestamp: z.number().int(),
});

async function verifyStandIn(
	document: Bytes,
	trust: ProxyTrustAnchors,
	now: number,
): Promise<AttestedKey> {
	const read = standIn.safeParse(JSON.parse(dec.decode(document)) as unknown);
	if (!read.success)
		throw new Error("the document is neither Nitro nor a stand-in");
	if (!trust.standIns)
		throw new Error(
			"the proxy runs outside an enclave: a stand-in document, which this build refuses",
		);
	if (read.data.environment !== trust.environment)
		throw new Error(`the stand-in is for ${read.data.environment}`);
	const userData = fromBase64(read.data.user_data);
	if (!userData) throw new Error("the stand-in's user_data is not base64");
	checkFresh(read.data.timestamp, now);
	const publicKey = keyInUserData(userData, trust.environment);
	return {
		publicKey,
		keyId: await keyIdOf(publicKey),
		issuedAt: read.data.timestamp,
	};
}

const isJson = (document: Bytes) => document[0] === 0x7b;

/** One instance's document, base64, checked against `trust`. `report` hears each stage of a Nitro
 * document as it passes (see NitroStep); a development stand-in has none, so it reports nothing and
 * says `standIn`. */
export async function proveInstance(
	instance: string,
	trust: ProxyTrustAnchors,
	now: number,
	report?: (step: NitroStep) => void,
): Promise<{ key: AttestedKey; standIn: boolean }> {
	const document = fromBase64(instance);
	if (!document) throw new Error("the document is not base64");
	return isJson(document)
		? { key: await verifyStandIn(document, trust, now), standIn: true }
		: {
				key: await verifyNitroDocument(document, { ...trust, now }, report),
				standIn: false,
			};
}

export async function verifyInstances(
	instances: readonly string[],
	trust: ProxyTrustAnchors,
	now = Date.now(),
): Promise<ProxyKeys> {
	const results = await Promise.allSettled(
		instances.map(async (i) => (await proveInstance(i, trust, now)).key),
	);
	const refusals: Error[] = [];
	const byId = new Map<string, AttestedKey>();
	for (const r of results) {
		if (r.status === "rejected") {
			refusals.push(
				r.reason instanceof Error ? r.reason : new Error(String(r.reason)),
			);
			continue;
		}
		const id = r.value.keyId.join(",");
		const known = byId.get(id);
		if (!known || known.issuedAt < r.value.issuedAt) byId.set(id, r.value);
	}
	const keys = [...byId.values()]
		.sort((a, b) => b.issuedAt - a.issuedAt)
		.slice(0, MAX_KEYS);
	if (keys.length === 0) throw new UnattestedError(refusals);
	return {
		keys,
		expiresAt: Math.min(...keys.map((k) => k.issuedAt)) + MAX_AGE_MS,
	};
}
