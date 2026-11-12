// verify(): runs the checks the CLI prints, in order, and decides what each prints. The comment above
// each step says what it proves. A document's rules are in ../nitro.ts, ../x509.ts, and ../pins.ts,
// and the list's in signed_list.ts; signed_list.ts, source.ts, rebuild.ts, and tls.ts say how to run
// each by hand.
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { type Bytes, fromBase64, hex, sha256Bytes } from "../bytes.ts";
import { type Cbor, decodeCbor } from "../cbor.ts";
import {
	type AttestedDocument,
	type NitroStep,
	verifyNitroDocument,
} from "../nitro.ts";
import { NITRO_ROOT } from "../nitro_root.ts";
import { allZero, type Pcrs, type PinnedImage } from "../pins.ts";
import { attestationReply } from "../sealed_routes.ts";
import type { Cert } from "../x509.ts";
import {
	causeOf,
	type Exec,
	exec,
	get,
	json,
	tempDir,
	Unfinished,
} from "./io.ts";
import { rebuild } from "./rebuild.ts";
import {
	fetchSignedList,
	type SignedList,
	verifySignedList,
} from "./signed_list.ts";
import {
	findRelease,
	REPO,
	type Release,
	readReleases,
	samePcrs,
} from "./source.ts";
import { type ServedKey, servedKey } from "./tls.ts";

export interface VerifyOptions {
	/** The host whose /v1/attestation lists the enclaves. Default api.trymorse.ai. */
	readonly host?: string;
	/** A release name (its commit's subject) or 40-hex commit on main that every enclave must run. */
	readonly release?: string;
	/** Rebuild each image from its commit with Docker and compare its PCRs. */
	readonly rebuild?: boolean;
	/** Hears each step as it is decided, in order. */
	readonly onStep?: (step: Step) => void;
	/** The clock, in ms. Documents and the signed list are judged by it, never by the host's. */
	readonly now?: () => number;
	// What the checks reach the world with. Tests replace them; the CLI never does.
	readonly fetch?: typeof fetch;
	readonly exec?: Exec;
	readonly tls?: (host: string) => Promise<ServedKey>;
	readonly sleep?: (ms: number) => Promise<void>;
	/** The root AWS Nitro documents must chain to. Only tests pass another, with forged documents. */
	readonly root?: Cert;
}

export interface Step {
	readonly label: string;
	/** "info" informs and decides nothing: an image's PCRs, what --rebuild is about to run, and TLS. */
	readonly status: "passed" | "failed" | "unfinished" | "not run" | "info";
	readonly lines: readonly string[];
}

export interface Enclave {
	/** Hex of the first 8 bytes of the SHA-256 of its HPKE key, which requests are sealed to. */
	readonly keyId: string;
	readonly publicKey: string;
	readonly issuedAt: number;
	readonly moduleId: string | null;
}

export interface Image {
	readonly pcrs: Pcrs;
	/** The enclaves whose documents attest these PCRs, by key. A key two images' documents name is in both. */
	readonly enclaves: Enclave[];
	/** The commit on main whose message names these PCRs: the one --release pins, or else the newest. */
	release?: Release;
	rebuilt: boolean;
}

export interface Report {
	readonly host: string;
	/** 0: every check passed. 1: a check failed; send nothing. 2: it could not finish; nothing is proven. */
	readonly exitCode: 0 | 1 | 2;
	readonly steps: readonly Step[];
	/** The closing lines: the verdict, and on a pass the --release pin to copy. */
	readonly verdict: readonly string[];
	readonly images: readonly Image[];
	readonly list?: SignedList;
}

/** One listed document, as steps 1 and 2 found it: verified, or refused by one of them and why.
 * A refused document's `publicKey` (hex) is the key it names, read unchecked, so a caller can
 * refuse that key though another document of it passed. */
export type Checked =
	| { readonly doc: AttestedDocument }
	| {
			readonly doc?: undefined;
			readonly label: "Attestation" | "Allowed";
			readonly reason: string;
			readonly publicKey?: string;
	  };

/** A check refused what it was shown: exit 1. */
class Failed extends Error {
	readonly label: string;
	readonly lines: readonly string[];
	constructor(label: string, ...lines: string[]) {
		super(lines.join(" "));
		this.label = label;
		this.lines = lines;
	}
}

const ENVIRONMENT = "prod";
const short = (h: string) => `${h.slice(0, 12)}…${h.slice(-8)}`;
const pcrLines = (p: Pcrs) => [
	`PCR0 ${short(p.pcr0)}`,
	`PCR1 ${short(p.pcr1)}`,
	`PCR2 ${short(p.pcr2)}`,
];
const sha256 = async (b: Bytes) => hex(await sha256Bytes(b));
/** "a", "a and b", or "a, b, and c". */
const joined = (items: readonly string[]) =>
	items.length < 3
		? items.join(" and ")
		: `${items.slice(0, -1).join(", ")}, and ${items.at(-1)}`;
const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function ago(ms: number): string {
	const minutes = Math.round(ms / 60_000);
	if (minutes < 0) return `${-minutes} min ahead of this machine's clock`;
	if (minutes === 0) return "just now";
	if (minutes < 120) return `${minutes} min ago`;
	const hours = Math.round(minutes / 60);
	return hours < 48 ? `${hours} h ago` : `${Math.round(hours / 24)} days ago`;
}

/** Seconds a 429's Retry-After asks for, at most 60. */
function retryAfter(value: string | null, now: number): number {
	const seconds = /^\d+$/.test(value ?? "")
		? Number(value)
		: (Date.parse(value ?? "") - now) / 1000;
	return Math.min(Number.isFinite(seconds) ? Math.max(seconds, 1) : 5, 60);
}

const MODULE_ID = /^[A-Za-z0-9-]{1,64}$/;

/** The module_id, key, and PCRs a document names, read without checking it, to name it in a
 * refusal. The key is the last 32 bytes of its user_data, where a valid document's key is. A
 * module_id is kept only in the letters, digits, and dashes AWS writes one in, since it is unsigned
 * here; without it the refusal names the document by its place in the list. */
function peek(document: Bytes | undefined): {
	moduleId?: string;
	publicKey?: string;
	pcrs?: Pcrs;
} {
	try {
		let sign1 = decodeCbor(document as Bytes);
		if (sign1 !== null && typeof sign1 === "object" && "tag" in sign1)
			sign1 = sign1.value;
		const payload = decodeCbor((sign1 as Cbor[])[2] as Bytes) as Map<
			string,
			Cbor
		>;
		const pcrs = payload.get("pcrs") as Map<number, Bytes>;
		const moduleId = payload.get("module_id");
		const userData = payload.get("user_data");
		return {
			moduleId:
				typeof moduleId === "string" && MODULE_ID.test(moduleId)
					? moduleId
					: undefined,
			publicKey:
				userData instanceof Uint8Array && userData.length >= 32
					? hex(userData.slice(-32))
					: undefined,
			pcrs: {
				pcr0: hex(pcrs.get(0) as Bytes),
				pcr1: hex(pcrs.get(1) as Bytes),
				pcr2: hex(pcrs.get(2) as Bytes),
			},
		};
	} catch {
		return {};
	}
}

/** Why the list does not allow these PCRs, or undefined if it lists them and no entry for them
 * is revoked. */
function refusedBy(list: SignedList, pcrs: Pcrs) {
	const entries = list.images.filter((i) => samePcrs(i, pcrs));
	if (entries.length === 0) return "which is not on Morse's signed list";
	if (entries.some((i) => i.revoked))
		return "which is on Morse's signed list, but Morse revoked it";
	return undefined;
}

/** The list's images as the core's pins, revoked ones first, so a revoked entry wins over a copy. */
const pinsOf = (list: SignedList): PinnedImage[] =>
	list.images
		.map((image) => ({
			...image,
			version: `on list ${list.sequence}`,
			environment: ENVIRONMENT,
			built_at: list.time,
		}))
		.sort((a, b) => Number(b.revoked) - Number(a.revoked));

/** Step 3's refusal of an image no release on main names. */
export const unpublished = (pcrs: Pcrs) =>
	`no commit on main of ${REPO} names PCR0 ${short(pcrs.pcr0)}: its source isn't published. If Morse is mid-deploy it appears within minutes; run again. Until then, don't send it anything.`;

/** Steps 1 and 2 for one document, base64, at `at` by this machine's clock: AWS Nitro signed it
 * under `root`, it is fresh, it names a prod key, and `list` allows its PCRs. `who` names it in a
 * refusal when it has no module_id. */
export async function checkDocument(
	instance: string,
	who: string,
	list: SignedList | undefined,
	root: Cert,
	at: number,
): Promise<Checked> {
	const document = fromBase64(instance);
	const seen = peek(document);
	const name = seen.moduleId ? `enclave ${seen.moduleId}` : who;
	const passed: NitroStep["step"][] = [];
	try {
		if (!document) throw new Error("the document is not base64");
		const pins = list ? pinsOf(list) : [];
		const doc = await verifyNitroDocument(
			document,
			{ environment: ENVIRONMENT, pins, root, now: at },
			(s) => passed.push(s.step),
		);
		return { doc };
	} catch (e) {
		const reason = (e as Error).message;
		const { publicKey, pcrs } = seen;
		// The first step not reported is the one that failed: after "fresh", the PCR test, which is
		// step 1's for a debug enclave's all-zero PCRs and step 2's for the list's lookup.
		if (passed.at(-1) !== "fresh" || (pcrs && allZero(pcrs)))
			return { label: "Attestation", reason: `${name}: ${reason}`, publicKey };
		return {
			label: "Allowed",
			reason:
				list && pcrs
					? `${name} runs PCR0 ${short(pcrs.pcr0)}, ${refusedBy(list, pcrs) ?? reason}`
					: `${name}: ${reason}`,
			publicKey,
		};
	}
}

export async function verify(options: VerifyOptions = {}): Promise<Report> {
	const host = options.host ?? "api.trymorse.ai";
	const now = options.now ?? Date.now;
	const fetchFn = options.fetch ?? fetch;
	const run = options.exec ?? exec;
	const steps: Step[] = [];
	const images: Image[] = [];
	let list: SignedList | undefined;
	let passed = "";
	const emit = (label: string, status: Step["status"], lines: string[]) => {
		const step = { label, status, lines };
		steps.push(step);
		if (status === "passed") passed = label;
		options.onStep?.(step);
	};
	const report = (exitCode: 0 | 1 | 2, verdict: string[]): Report => ({
		host,
		exitCode,
		steps,
		verdict,
		images,
		list,
	});

	let dir: string | undefined;
	try {
		dir = await tempDir("trymorse-verify-");
		const clone = join(dir, "enclave.git");
		// 1. Attestation: AWS Nitro signed a document for each enclave the host lists, under 30 minutes
		// ago by this machine's clock, naming the PCRs of the image it booted, not all zero (debug
		// mode), and the prod key it seals to. Only the PCRs' lookup is step 2's: the images Morse's
		// signed list allows.
		const url = `https://${host}/v1/attestation`;
		let got = await get(fetchFn, url);
		if (got.status === 429) {
			const seconds = retryAfter(got.headers.get("retry-after"), now());
			await (options.sleep ?? wait)(seconds * 1000);
			got = await get(fetchFn, url);
		}
		if (got.status === 429)
			throw new Unfinished(
				`${host} is rate-limiting this address (60 requests a minute). Run again in a minute`,
			);
		if (got.status !== 200)
			throw new Unfinished(`${url} answered ${got.status}`);
		const read = attestationReply.safeParse(json(got.body));
		if (!read.success)
			throw new Failed("Attestation", `${url} is not a list of enclaves`);
		const instances = read.data.instances;
		if (instances.length === 0)
			throw new Failed("Attestation", `${host} lists no enclave`);

		const files = await fetchSignedList(fetchFn);
		let listError = "";
		try {
			list = verifySignedList(files, now());
		} catch (e) {
			listError = (e as Error).message;
		}

		const at = now();
		const root = options.root ?? NITRO_ROOT;
		const checked = await Promise.all(
			instances.map((instance, i) =>
				checkDocument(
					instance,
					`document ${i + 1} of ${instances.length}`,
					list,
					root,
					at,
				),
			),
		);
		for (const c of checked)
			if (!c.doc && c.label === "Attestation")
				throw new Failed(c.label, c.reason);
		if (!list)
			throw new Failed(
				"Allowed",
				`Morse's signed list ${files.name} ${listError}`,
			);
		for (const c of checked) if (!c.doc) throw new Failed(c.label, c.reason);

		// Every document that passed goes through each check below at its own PCRs, in images by
		// PCRs. Keys only count and name the enclaves, each at its newest document, newest first.
		const docs = checked
			.flatMap((c) => (c.doc ? [c.doc] : []))
			.sort((a, b) => b.issuedAt - a.issuedAt);
		const keys = new Map<string, { issuedAt: number; images: number[] }>();
		for (const doc of docs) {
			let n = images.findIndex((i) => samePcrs(i.pcrs, doc.pcrs));
			if (n < 0)
				n = images.push({ pcrs: doc.pcrs, enclaves: [], rebuilt: false }) - 1;
			const keyId = hex(doc.keyId);
			if (!images[n].enclaves.some((e) => e.keyId === keyId))
				images[n].enclaves.push({
					keyId,
					publicKey: hex(doc.publicKey),
					issuedAt: doc.issuedAt,
					moduleId: doc.moduleId,
				});
			const key = keys.get(keyId) ?? { issuedAt: doc.issuedAt, images: [] };
			if (!key.images.includes(n + 1)) key.images.push(n + 1);
			keys.set(keyId, key);
		}
		const several = images.length > 1;
		const rootHash = await sha256(root.der);
		emit("Attestation", "passed", [
			`${keys.size} enclave${keys.size > 1 ? "s, each" : ","} signed by AWS Nitro (root ${rootHash.slice(0, 8)}…${rootHash.slice(-8)})`,
			...[...keys].map(
				([id, key]) =>
					`key ${id}, signed ${ago(at - key.issuedAt)}${several ? `, image${key.images.length > 1 ? "s" : ""} ${joined(key.images.map(String))}` : ""}`,
			),
			...(several ? [] : pcrLines(images[0].pcrs)),
		]);

		let releases: readonly Release[] | undefined;
		for (const [i, image] of images.entries()) {
			if (several) emit(`Image ${i + 1}`, "info", pcrLines(image.pcrs));

			// 2. Allowed: the public sign.yml of trymorse/morse-pins signed a list of the prod images
			// Morse allows in the last 7 days, Rekor v2 logged it, at least 3 witnesses cosigned the
			// log's checkpoint, and it lists these PCRs, unrevoked. Its signer is Morse.
			emit("Allowed", "passed", [
				"on Morse's signed list of prod images, not revoked",
				`list ${list.sequence}, signed ${ago(at - list.signedAt)}, Rekor v2 entry ${list.logIndex}, ${list.witnesses} witnesses`,
				"https://github.com/trymorse/morse-pins/tree/statements/images/prod",
			]);

			// 3. Source: a commit on main of the public repository names these PCRs as the release it
			// is. That Morse's CI wrote them is all this proves without --rebuild.
			releases ??= await readReleases(run, clone);
			const known = releases;
			const named = known.filter((r) => samePcrs(r.pcrs, image.pcrs));
			const [release, ...also] = named;
			if (!release) throw new Failed("Source", unpublished(image.pcrs));
			image.release = release;
			emit("Source", "passed", [
				`${release.name}, commit ${release.commit.slice(0, 12)} on main of ${REPO}, names these PCRs`,
				...(also.length
					? [`and so do ${joined(also.map((r) => r.name))}`]
					: []),
			]);

			// --release: every enclave runs the release named, by its PCRs.
			if (options.release !== undefined && i === 0) {
				const wanted = findRelease(known, options.release);
				if (!wanted)
					throw new Unfinished(
						`no release ${options.release} on main of ${REPO}; see https://${REPO}/commits/main`,
					);
				const runs = (pcrs: Pcrs) =>
					known.find((r) => samePcrs(r.pcrs, pcrs))?.name ??
					`PCR0 ${short(pcrs.pcr0)}, which no commit on main names`;
				if (!images.every((im) => samePcrs(im.pcrs, wanted.pcrs)))
					throw new Failed(
						"Release",
						`--release names ${wanted.name}, commit ${wanted.commit.slice(0, 12)}, but not every enclave runs it:`,
						...images.flatMap((im) =>
							im.enclaves.map((e) => `key ${e.keyId} runs ${runs(im.pcrs)}`),
						),
						several
							? "A deploy replaces one enclave at a time, so for a few minutes after one the enclaves run two releases. Run again."
							: "They run another release. Read it, and pin its commit to accept it.",
					);
				emit("Release", "passed", [
					`every enclave runs ${wanted.name}, commit ${wanted.commit.slice(0, 12)}, as --release asks`,
				]);
				// Every enclave runs this one image, so the commit pinned is the one to build and name.
				image.release = wanted;
			}

			// 4. Rebuild: this machine builds the commit with its own build.sh and gets the attested PCRs.
			if (!options.rebuild) {
				emit("Rebuild", "not run", [
					"not run. These PCRs are the ones Morse's CI wrote in that commit.",
					"Run with --rebuild to build it here and compare (Docker, ~2 min).",
				]);
				continue;
			}
			const rebuilt = await rebuild(
				run,
				clone,
				image.release.commit,
				await mkdtemp(join(dir, `${i + 1}-`)),
				(lines) => emit("Rebuild", "info", lines),
			).catch((e) => {
				if (e instanceof Unfinished && e.lines.length)
					emit("Rebuild", "unfinished", [...e.lines]);
				throw e;
			});
			if (!samePcrs(rebuilt, image.pcrs))
				throw new Failed(
					"Rebuild",
					`commit ${image.release.commit.slice(0, 12)} rebuilds here to other PCRs than the enclaves attest:`,
					...pcrLines(rebuilt),
				);
			image.rebuilt = true;
			emit("Rebuild", "passed", ["rebuilt here: PCR0, PCR1, and PCR2 match"]);
		}

		// 5. TLS, which informs and never fails: whether this machine's own connection to the host
		// ended inside an enclave, at a key a document that passed every check above attests.
		let served: ServedKey | undefined;
		let tlsError = "";
		try {
			served = await (options.tls ?? servedKey)(host);
		} catch (e) {
			tlsError = causeOf(e);
		}
		const attested = await Promise.all(
			docs.flatMap((d) => (d.tlsKey ? [sha256(d.tlsKey)] : [])),
		);
		emit("TLS", "info", [
			!served
				? `could not connect to ${host}:443 (${tlsError}), so this says nothing of where its TLS ends.`
				: attested.includes(served.spkiSha256)
					? `this connection to ${host} ended inside an attested enclave (key ${served.spkiSha256.slice(0, 16)})`
					: `${host}'s TLS key ${served.spkiSha256.slice(0, 16)} (issuer ${served.issuer}) is in no attestation document, so TLS ends before the enclave. Morse's relay can read requests on it unless they're sealed.`,
		]);

		const names = joined(images.map((im) => im.release?.name ?? ""));
		const verdict = [
			`Passed. The enclaves ${host} lists run ${names} of ${REPO}, ${
				options.rebuild
					? `which ${several ? "rebuild" : "rebuilds"} here to the same PCRs.`
					: "as published (not rebuilt here)."
			}`,
		];
		if (!several && images[0].release)
			verdict.push(
				`Pin this release in CI: --release ${images[0].release.commit}`,
			);
		return report(0, verdict);
	} catch (e) {
		if (e instanceof Failed) {
			emit(e.label, "failed", [`FAILED: ${e.lines[0]}`, ...e.lines.slice(1)]);
			return report(1, [
				`Failed at ${e.label}. Don't send anything to these enclaves.`,
			]);
		}
		const reason = e instanceof Error ? e.message : String(e);
		return report(2, [
			`Could not finish: ${reason}. ${passed ? `Nothing was checked past ${passed}.` : "Nothing was checked."}`,
		]);
	} finally {
		// A temporary directory left behind, such as one a build filled with root's files, fails nothing.
		if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
	}
}
