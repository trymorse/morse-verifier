import { z } from "zod";

const pcr = z.string().regex(/^[0-9a-f]{96}$/);
const ZERO_PCR = "0".repeat(96);

const measured = {
	environment: z.string().min(1),
	pcr0: pcr,
	pcr1: pcr,
	pcr2: pcr,
	built_at: z.iso.datetime(),
	revoked: z.boolean(),
};

/** An entry of Morse's private pins names the backend commit and describe it was built from. An
 * entry of the public morse-pins names only the morse-enclave tag of its source. */
const fromCommit = {
	commit: z.string().min(1),
	version: z.string().min(1),
	...measured,
};
const fromTag = { tag: z.string().min(1), ...measured };
const named = <T extends { tag: string }>({ tag, ...rest }: T) => ({
	version: tag,
	...rest,
});
const image = z.union([
	z.strictObject(fromCommit),
	z.strictObject(fromTag).transform(named),
]);
export type PinnedImage = {
	readonly commit?: string;
	readonly version: string;
	readonly environment: string;
	readonly pcr0: string;
	readonly pcr1: string;
	readonly pcr2: string;
	readonly built_at: string;
	readonly revoked: boolean;
};

const allZero = (p: Pcrs) =>
	p.pcr0 === ZERO_PCR && p.pcr1 === ZERO_PCR && p.pcr2 === ZERO_PCR;

const pinsSchema = z
	.array(image)
	.refine(
		(all) => !all.some(allZero),
		"an entry pins all-zero PCRs, which only a debug enclave reports",
	);

/** Parses the app's own pins or the public morse-pins `enclave_pins.json`. */
export const parseEnclavePins = (input: unknown): readonly PinnedImage[] =>
	pinsSchema.parse(input);

const liveImage = z.union([
	z.object(fromCommit),
	z.object(fromTag).transform(named),
]);
const liveImageNamed = z.object({
	environment: measured.environment,
	pcr0: pcr,
	pcr1: pcr,
	pcr2: pcr,
	revoked: z.unknown().optional(),
});

/** Reads the live list a tab may be older than: it ignores a field it doesn't know, and a malformed
 * entry costs only itself. An entry that names an image and doesn't say `revoked: false` revokes
 * that image, however else it is damaged, since dropping it could lose a revocation. Throws for
 * anything but a list. Publishing still goes through parseEnclavePins. */
export function parseLivePins(input: unknown): {
	readonly pins: readonly PinnedImage[];
	readonly dropped: number;
} {
	const pins: PinnedImage[] = [];
	let dropped = 0;
	for (const entry of z.array(z.unknown()).parse(input)) {
		const read = liveImage.safeParse(entry);
		if (read.success && !allZero(read.data)) {
			pins.push(read.data);
			continue;
		}
		dropped++;
		const damaged = liveImageNamed.safeParse(entry);
		if (damaged.success && damaged.data.revoked !== false)
			pins.push({
				...damaged.data,
				version: "unreadable",
				built_at: new Date(0).toISOString(),
				revoked: true,
			});
	}
	return { pins, dropped };
}

export type Pcrs = {
	readonly pcr0: string;
	readonly pcr1: string;
	readonly pcr2: string;
};

/** The pin of `environment` that names exactly these PCRs, revoked or not. */
export const pinNamed = (
	pins: readonly PinnedImage[],
	environment: string,
	pcrs: Pcrs,
): PinnedImage | undefined =>
	pins.find(
		(p) =>
			p.environment === environment &&
			p.pcr0 === pcrs.pcr0 &&
			p.pcr1 === pcrs.pcr1 &&
			p.pcr2 === pcrs.pcr2,
	);

/** Refuses an image no pin names: one built after these pins were read, which newer pins may
 * name, or one never pinned. */
export class UnpinnedError extends Error {
	override name = "UnpinnedError";
}

/** The pin of `environment` that names these PCRs. Throws for a debug enclave's all-zero PCRs, a
 * revoked image, or, as UnpinnedError, an image no pin names. */
export function checkPcrs(
	pins: readonly PinnedImage[],
	environment: string,
	pcrs: Pcrs,
): PinnedImage {
	if (allZero(pcrs))
		throw new Error(
			"the enclave reports all-zero PCRs, so it runs in debug mode",
		);
	const pinned = pinNamed(pins, environment, pcrs);
	if (!pinned)
		throw new UnpinnedError(
			`no ${environment} pin names PCR0 ${pcrs.pcr0.slice(0, 16)}`,
		);
	if (pinned.revoked)
		throw new Error(`the ${environment} image ${pinned.version} is revoked`);
	return pinned;
}
