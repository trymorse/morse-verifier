import { z } from "zod";

const pcr = z.string().regex(/^[0-9a-f]{96}$/);
const ZERO_PCR = "0".repeat(96);

const image = z.strictObject({
	commit: z.string().min(1),
	version: z.string().min(1),
	environment: z.string().min(1),
	pcr0: pcr,
	pcr1: pcr,
	pcr2: pcr,
	built_at: z.iso.datetime(),
	revoked: z.boolean(),
});
export type PinnedImage = z.infer<typeof image>;

const pinsSchema = z
	.array(image)
	.refine(
		(all) =>
			!all.some(
				(p) =>
					p.pcr0 === ZERO_PCR && p.pcr1 === ZERO_PCR && p.pcr2 === ZERO_PCR,
			),
		"an entry pins all-zero PCRs, which only a debug enclave reports",
	);

export const parseEnclavePins = (input: unknown): readonly PinnedImage[] =>
	pinsSchema.parse(input);

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
	if (
		pcrs.pcr0 === ZERO_PCR &&
		pcrs.pcr1 === ZERO_PCR &&
		pcrs.pcr2 === ZERO_PCR
	)
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
