// Morse's signed list of the prod images it allows, which its private CI signs with Sigstore and
// logs in Rekor, Sigstore's public log. These are the rules of Morse's own Go verifier
// (internal/pinsig in morse-server, which is private; morse-enclave carries a public copy), on top
// of @sigstore/verify. By hand:
//   tag=$(curl -sI https://github.com/trymorse/morse-pins/releases/latest | sed -n 's|^location: .*/tag/||Ip' | tr -d '\r')
//   curl -sLO https://github.com/trymorse/morse-pins/releases/download/$tag/prod.statement.json
//   curl -sLO https://github.com/trymorse/morse-pins/releases/download/$tag/prod.sigstore.json
//   cosign verify-blob prod.statement.json --bundle prod.sigstore.json \
//     --certificate-identity https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main \
//     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
//     --certificate-github-workflow-sha "$(jq -r .pins_commit prod.statement.json)"
//   jq -r '.verificationMaterial.tlogEntries[0] | "Rekor entry \(.logIndex), logged \(.integratedTime | tonumber | todate)"' prod.sigstore.json
//   jq -e '.verificationMaterial.tlogEntries[0].integratedTime | tonumber > now - 7 * 86400' prod.sigstore.json   # true: logged in the last 7 days
import { createHash, X509Certificate } from "node:crypto";
import { bundleFromJSON, ValidationError } from "@sigstore/bundle";
import { HashAlgorithm, TrustedRoot } from "@sigstore/protobuf-specs";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { z } from "zod";
import { parseCert } from "../x509.ts";
import { get, json, Unfinished } from "./io.ts";
import { SIGSTORE_TRUSTED_ROOT } from "./sigstore_root.ts";

const RELEASES = "https://github.com/trymorse/morse-pins/releases";
const TAG = /^signed-\d+-\d{8}T\d{6}Z$/;
const MEDIA_TYPES = [
	"application/vnd.dev.sigstore.bundle.v0.3+json",
	"application/vnd.dev.sigstore.bundle+json;version=0.3",
];
const MAX_AGE_MS = 7 * 24 * 3600_000;
const MAX_AHEAD_MS = 5 * 60_000;

// Who may sign the list: the sign.yml workflow on main of Watermark-Labs/pins, on a GitHub-hosted
// runner, started by a push or the schedule, in the first attempt of its run. Extensions .8 and up
// hold DER UTF8Strings; .1 holds the issuer raw.
const ISSUER = "https://token.actions.githubusercontent.com";
const SIGNER =
	"https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main";
const REPOSITORY = "https://github.com/Watermark-Labs/pins";
const FULCIO = "1.3.6.1.4.1.57264.1.";
const EXPECTED: Record<number, string> = {
	8: ISSUER,
	9: SIGNER,
	11: "github-hosted",
	12: REPOSITORY,
	14: "refs/heads/main",
	15: "1405118053",
	17: "334112171",
	18: SIGNER,
};
const TRIGGERS = ["push", "schedule"];
const CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
const SUBJECT_ALT_NAME = "2.5.29.17";
const RUN =
	/^https:\/\/github\.com\/Watermark-Labs\/pins\/actions\/runs\/\d+\/attempts\/1$/;

export interface SignedListFiles {
	readonly tag: string;
	readonly statement: Uint8Array;
	readonly bundle: unknown;
}

/** The latest release of github.com/trymorse/morse-pins, resolved once so that both files come from
 * it, and its prod statement and bundle. */
export async function fetchSignedList(
	fetchFn: typeof fetch,
): Promise<SignedListFiles> {
	const latest = await get(fetchFn, `${RELEASES}/latest`, "manual");
	const location = latest.headers.get("location") ?? "";
	const tag = location.startsWith(`${RELEASES}/tag/`)
		? location.slice(`${RELEASES}/tag/`.length)
		: "";
	if (!TAG.test(tag))
		throw new Unfinished(
			`${RELEASES}/latest answered ${latest.status} ${location || "with no release"}, not a signed list`,
		);
	const asset = async (name: string) => {
		const url = `${RELEASES}/download/${tag}/${name}`;
		const got = await get(fetchFn, url, "follow");
		if (got.status !== 200)
			throw new Unfinished(`${url} answered ${got.status}`);
		return got.body;
	};
	const statement = await asset("prod.statement.json");
	return { tag, statement, bundle: json(await asset("prod.sigstore.json")) };
}

const pcr = z.string().regex(/^[0-9a-f]{96}$/);
const ZERO = "0".repeat(96);
const statementSchema = z.strictObject({
	environment: z.literal("prod"),
	images: z
		.array(
			z
				.strictObject({ pcr0: pcr, pcr1: pcr, pcr2: pcr, revoked: z.boolean() })
				.refine(
					(i) => !(i.pcr0 === ZERO && i.pcr1 === ZERO && i.pcr2 === ZERO),
					"an image has all-zero PCRs",
				),
		)
		.min(1),
	pins_commit: z.string().regex(/^[0-9a-f]{40}$/),
	sequence: z.number().int().positive(),
	time: z.iso.datetime({ offset: true }),
	type: z.literal("morse-enclave-pins-v1"),
});

export interface ListedImage {
	readonly pcr0: string;
	readonly pcr1: string;
	readonly pcr2: string;
	readonly revoked: boolean;
}

export interface SignedList {
	readonly sequence: number;
	readonly time: string;
	readonly pinsCommit: string;
	/** The Rekor entry's global index, which search.sigstore.dev and rekor-cli look up. */
	readonly logIndex: string;
	/** When Rekor logged it, in ms, as its signed entry timestamp says. */
	readonly integratedTime: number;
	readonly images: readonly ListedImage[];
}

/** The trust a bundle is checked against. Tests pass Morse's forged test root, which has no CT log. */
export interface SigstoreTrust {
	readonly root: unknown;
	readonly ctlogThreshold: number;
}

const PUBLIC_GOOD: SigstoreTrust = {
	root: SIGSTORE_TRUSTED_ROOT,
	ctlogThreshold: 1,
};

/** JCS: keys sorted by UTF-16 code unit, no whitespace, strings and numbers as JSON.stringify writes. */
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

/** The DER UTF8String an extension holds, or undefined if it holds anything else. */
function utf8String(der: Uint8Array): string | undefined {
	if (der[0] !== 0x0c) return undefined;
	let length = der[1];
	let at = 2;
	if (length === 0x81 && der[2] >= 0x80) [length, at] = [der[2], 3];
	else if (length === 0x82 && der[2] !== 0)
		[length, at] = [(der[2] << 8) | der[3], 4];
	else if (length > 0x7f) return undefined;
	if (at + length !== der.length) return undefined;
	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(der.subarray(at));
	} catch {
		return undefined;
	}
}

const ago = (ms: number) =>
	ms >= 2 * 24 * 3600_000
		? `${Math.round(ms / (24 * 3600_000))} days`
		: `${Math.round(ms / 60_000)} min`;

/** The one certificate a hashedrekord entry's body names, or an empty buffer. */
function loggedCertificate(body: Buffer): Buffer {
	try {
		const entry = JSON.parse(body.toString("utf8")) as {
			spec: { signature: { publicKey: { content: string } } };
		};
		const pem = Buffer.from(
			entry.spec.signature.publicKey.content,
			"base64",
		).toString("utf8");
		if (pem.split("-----BEGIN ").length !== 2) return Buffer.alloc(0);
		return new X509Certificate(pem).raw;
	} catch {
		return Buffer.alloc(0);
	}
}

/** The statement, if its bytes are exactly the canonical JSON (JCS) of a prod pins statement, as
 * Morse signs it: no byte-order mark, sorted keys, no whitespace. Throws an Error that completes
 * "Morse's signed list <tag> …". */
export function readStatement(
	statement: Uint8Array,
): z.infer<typeof statementSchema> {
	let text: string;
	let parsed: unknown;
	try {
		text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
			statement,
		);
		parsed = JSON.parse(text);
	} catch {
		throw new Error("is not JSON");
	}
	if (canonical(parsed) !== text)
		throw new Error("is not in canonical form (JCS), as Morse signs it");
	const read = statementSchema.safeParse(parsed);
	if (!read.success) {
		const issue = read.error.issues[0];
		throw new Error(
			`is not a prod pins statement: ${issue.path.join(".") || "it"}: ${issue.message}`,
		);
	}
	return read.data;
}

/** Checks the bundle signs the statement as Morse's pins workflow, logged once in Rekor v1 with both a
 * signed entry timestamp and an inclusion proof, between 7 days before `now` and 5 minutes after it.
 * Throws an Error that completes "Morse's signed list <tag> …". */
export function verifySignedList(
	{ statement, bundle: json }: SignedListFiles,
	now: number,
	trust: SigstoreTrust = PUBLIC_GOOD,
): SignedList {
	let bundle: ReturnType<typeof bundleFromJSON>;
	try {
		bundle = bundleFromJSON(json);
	} catch (e) {
		const fields =
			e instanceof ValidationError && e.fields?.length
				? ` (${e.fields.join(", ")})`
				: "";
		throw new Error(
			`is not a Sigstore bundle: ${(e as Error).message}${fields}`,
		);
	}
	if (!MEDIA_TYPES.includes(bundle.mediaType))
		throw new Error(`is a ${bundle.mediaType}, not a v0.3 bundle`);
	if (bundle.content.$case !== "messageSignature")
		throw new Error("signs a DSSE envelope, not the statement itself");
	const material = bundle.verificationMaterial.content;
	if (material?.$case !== "certificate")
		throw new Error("is not signed with one Fulcio certificate");
	const entries = bundle.verificationMaterial.tlogEntries;
	if (entries.length !== 1)
		throw new Error(`has ${entries.length} log entries, not one`);
	const [entry] = entries;
	const kind = `${entry.kindVersion?.kind} ${entry.kindVersion?.version}`;
	if (kind !== "hashedrekord 0.0.1")
		throw new Error(`is logged as ${kind}, not hashedrekord 0.0.1 (Rekor v1)`);
	if (!entry.inclusionPromise || !entry.inclusionProof?.checkpoint)
		throw new Error(
			"lacks Rekor's signed entry timestamp or its inclusion proof, which it must carry both of",
		);
	// After the checkpoint's first blank line comes one signature line and nothing else, as in Go.
	const { envelope } = entry.inclusionProof.checkpoint;
	const blank = envelope.indexOf("\n\n");
	const signatures =
		blank < 0 ? "" : envelope.slice(blank + 2).replace(/\n$/, "");
	if (!signatures || signatures.includes("\n"))
		throw new Error("carries a checkpoint signed other than once");

	const digest = createHash("sha256").update(statement).digest();
	const signed = bundle.content.messageSignature.messageDigest;
	if (
		signed?.algorithm !== HashAlgorithm.SHA2_256 ||
		!digest.equals(signed.digest)
	)
		throw new Error("names a digest other than the statement's SHA-256");
	const certificate = Buffer.from(material.certificate.rawBytes);
	if (!loggedCertificate(entry.canonicalizedBody).equals(certificate))
		throw new Error("is logged with another certificate than it carries");

	let signer: ReturnType<Verifier["verify"]>;
	try {
		signer = new Verifier(toTrustMaterial(TrustedRoot.fromJSON(trust.root)), {
			tlogThreshold: 1,
			ctlogThreshold: trust.ctlogThreshold,
		}).verify(toSignedEntity(bundle, Buffer.from(statement)));
	} catch (e) {
		throw new Error(`doesn't verify: ${(e as Error).message}`);
	}

	const leaf = new X509Certificate(certificate);
	if (!leaf.keyUsage?.includes(CODE_SIGNING))
		throw new Error("is signed with a certificate not issued for code signing");
	let critical: readonly string[];
	try {
		critical = parseCert(new Uint8Array(certificate)).unhandledCritical;
	} catch (e) {
		throw new Error(
			`is signed with a certificate that ${(e as Error).message.replace(/^the certificate /, "")}`,
		);
	}
	const unread = critical.filter((id) => id !== SUBJECT_ALT_NAME);
	if (unread.length > 0)
		throw new Error(
			`is signed with a certificate whose extension ${unread[0]} is critical, which nothing here reads`,
		);
	const san = leaf.subjectAltName;
	if (san !== `URI:${SIGNER}`)
		throw new Error(`was signed as ${san}, not Morse's pins workflow`);
	const values = new Map<number, Buffer[]>();
	for (const { oid, value } of signer.identity?.oids ?? []) {
		const id = oid?.id.join(".") ?? "";
		if (!id.startsWith(FULCIO) || id.split(".").length !== 9) continue;
		const n = Number(id.slice(FULCIO.length));
		values.set(n, [...(values.get(n) ?? []), value]);
	}
	const extension = (n: number) => {
		const found = values.get(n) ?? [];
		const text = found.length === 1 ? utf8String(found[0]) : undefined;
		if (text === undefined)
			throw new Error(
				`has a certificate with no single UTF8String ${FULCIO}${n}`,
			);
		return text;
	};
	for (const [n, want] of Object.entries(EXPECTED))
		if (extension(Number(n)) !== want)
			throw new Error(
				`has a certificate whose ${FULCIO}${n} is ${extension(Number(n))}, not ${want}`,
			);
	const rawIssuer = values.get(1);
	if (
		rawIssuer &&
		(rawIssuer.length !== 1 || rawIssuer[0].toString() !== ISSUER)
	)
		throw new Error(`has a certificate whose ${FULCIO}1 is another issuer`);
	if (!TRIGGERS.includes(extension(20)))
		throw new Error(`was signed by a run started by ${extension(20)}`);
	if (!RUN.test(extension(21)))
		throw new Error(
			`was signed by ${extension(21)}, not a first-attempt run of Watermark-Labs/pins`,
		);
	const commit = extension(13);
	if (extension(19) !== commit)
		throw new Error(
			`was signed by a workflow at ${extension(19)}, not the source commit ${commit}`,
		);

	const st = readStatement(statement);
	if (st.pins_commit !== commit)
		throw new Error(
			`names pins commit ${st.pins_commit}, but its certificate was issued for ${commit}`,
		);

	const integratedTime = Number(entry.integratedTime) * 1000;
	if (now - integratedTime > MAX_AGE_MS)
		throw new Error(
			`was logged ${ago(now - integratedTime)} ago, and the check refuses a list more than 7 days old`,
		);
	if (integratedTime - now > MAX_AHEAD_MS)
		throw new Error(
			`was logged ${ago(integratedTime - now)} ahead of this machine's clock`,
		);
	return {
		sequence: st.sequence,
		time: st.time,
		pinsCommit: st.pins_commit,
		logIndex: entry.logIndex,
		integratedTime,
		images: st.images,
	};
}
