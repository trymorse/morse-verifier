// Morse's signed list of the prod images it allows, which the public sign.yml of trymorse/morse-pins
// signs with Sigstore, logs in Rekor v2, Sigstore's public log, and commits to the statements/images
// branch. These are the rules of the enclave's own Go verifier (internal/pinsig with the trust of
// internal/door/trust.go, which morse-enclave carries a copy of), on top of @sigstore/verify. By hand:
//   commit=$(git ls-remote https://github.com/trymorse/morse-pins refs/heads/statements/images | cut -f1)
//   raw=https://raw.githubusercontent.com/trymorse/morse-pins/$commit
//   list=$(curl -s $raw/prod/index.json | jq -r '.[0].statement | rtrimstr(".statement.json")')
//   curl -so prod.statement.json $raw/$list.statement.json
//   curl -so prod.sigstore.json $raw/$list.sigstore.json
//   cosign verify-blob prod.statement.json --bundle prod.sigstore.json \
//     --certificate-identity https://github.com/trymorse/morse-pins/.github/workflows/sign.yml@refs/heads/main \
//     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
//     --certificate-github-workflow-sha "$(jq -r .pins_commit prod.statement.json)"
//   jq -r '.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope' prod.sigstore.json   # the log's line, then the witnesses'
//   jq -r .verificationMaterial.certificate.rawBytes prod.sigstore.json | base64 -d | openssl x509 -inform der -noout -startdate   # signed in the last 7 days
import {
	createHash,
	createPublicKey,
	verify as cryptoVerify,
	type KeyObject,
	X509Certificate,
} from "node:crypto";
import { bundleFromJSON, ValidationError } from "@sigstore/bundle";
import { HashAlgorithm, TrustedRoot } from "@sigstore/protobuf-specs";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { z } from "zod";
import { parseCert } from "../x509.ts";
import { get, json, Unfinished } from "./io.ts";
import { SIGSTORE_TRUSTED_ROOT } from "./sigstore_root.ts";

// The branch's tip comes from git's ref advertisement, and every file from raw.githubusercontent.com
// at that commit, so one read sees one snapshot that a later push can't change under it. Neither is
// GitHub's rate-limited API.
const REFS =
	"https://github.com/trymorse/morse-pins.git/info/refs?service=git-upload-pack";
const RAW = "https://raw.githubusercontent.com/trymorse/morse-pins";
const BRANCH = "refs/heads/statements/images";
const MEDIA_TYPES = [
	"application/vnd.dev.sigstore.bundle.v0.3+json",
	"application/vnd.dev.sigstore.bundle+json;version=0.3",
];
const MAX_AGE_MS = 7 * 24 * 3600_000;
const MAX_AHEAD_MS = 5 * 60_000;

interface Signer {
	readonly repository: string;
	readonly repositoryId: string;
	readonly ownerId: string;
}

// Who may sign the list: the sign.yml workflow on main of trymorse/morse-pins, on a GitHub-hosted
// runner, started by a push or the schedule, in the first attempt of its run. The repository's and
// its owner's ids, from gh api repos/trymorse/morse-pins, make a renamed or recreated repository
// fail. Extensions .8 and up hold DER UTF8Strings; .1 holds the issuer raw.
const MORSE_PINS: Signer = {
	repository: "trymorse/morse-pins",
	repositoryId: "1437511167",
	ownerId: "345029672",
};
const ISSUER = "https://token.actions.githubusercontent.com";
const FULCIO = "1.3.6.1.4.1.57264.1.";
const TRIGGERS = ["push", "schedule"];
const CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
const SUBJECT_ALT_NAME = "2.5.29.17";
const workflowOf = (s: Signer) =>
	`https://github.com/${s.repository}/.github/workflows/sign.yml@refs/heads/main`;

export interface Witness {
	readonly name: string;
	readonly operator: string;
	readonly hash: Buffer;
	readonly key: KeyObject;
}

export function parseWitness(vkey: string, operator: string): Witness {
	const [, name, hash, key] =
		/^([^+\s]+)\+([0-9a-f]{8})\+(\S+)$/.exec(vkey) ?? [];
	const raw = Buffer.from(key ?? "", "base64");
	if (!name || raw.length !== 33 || raw[0] !== 0x04)
		throw new Error(`${vkey} is not a cosignature/v1 Ed25519 verifier key`);
	const keyHash = createHash("sha256")
		.update(
			Buffer.concat([Buffer.from(`${name}\n\x04`, "latin1"), raw.subarray(1)]),
		)
		.digest()
		.subarray(0, 4);
	if (keyHash.toString("hex") !== hash)
		throw new Error(`the key hash of ${name} is not its key's`);
	return {
		name,
		operator,
		hash: keyHash,
		key: createPublicKey({
			key: {
				kty: "OKP",
				crv: "Ed25519",
				x: raw.subarray(1).toString("base64url"),
			},
			format: "jwk",
		}),
	};
}

// The enclave's witnesses and k (internal/door/trust.go), all four staging or test tier: each one's
// published verifier key, "name+hash+base64(0x04 || Ed25519 key)", and who runs it.
const WITNESSES = [
	[
		"krabbel.ct.ipng.ch+4b10dbd8+BO4sLOtnhktlqMCejDx9C5LDd+/xZxbmBb6BP9ZD2Def",
		"IPng Networks",
	],
	[
		"staging.witness.transparency.goog/ring-any-bells+2e1a8dc9+BG5JTpLc3FJtwzgh1Uv+Qelz9qeOH2bfWjS1s0s+y4rL",
		"TrustFabric",
	],
	[
		"witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv",
		"Mullvad VPN",
	],
	[
		"witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G",
		"Geomys",
	],
].map(([vkey, operator]) => parseWitness(vkey, operator));

export interface ListTrust {
	readonly signer: Signer;
	readonly witnesses: readonly Witness[];
	readonly k: number;
}

export const MORSE_TRUST: ListTrust = {
	signer: MORSE_PINS,
	witnesses: WITNESSES,
	k: 3,
};

export interface SignedListFiles {
	readonly name: string;
	readonly commit: string;
	readonly statement: Uint8Array;
	readonly bundle: unknown;
}

// The pkt-lines of git's smart-HTTP ref advertisement, null for each flush, or undefined if it
// isn't one.
function pktLines(body: Uint8Array): (string | null)[] | undefined {
	const b = Buffer.from(body);
	const lines: (string | null)[] = [];
	for (let at = 0; at < b.length; ) {
		const size = b.toString("latin1", at, at + 4);
		const n = /^[0-9a-f]{4}$/.test(size) ? Number.parseInt(size, 16) : -1;
		if (n < 0 || (n > 0 && n < 4) || at + Math.max(n, 4) > b.length)
			return undefined;
		lines.push(n === 0 ? null : b.toString("latin1", at + 4, at + n));
		at += Math.max(n, 4);
	}
	return lines;
}

function tipOf(body: Uint8Array): string | undefined {
	const lines = pktLines(body);
	if (lines?.[0] !== "# service=git-upload-pack\n" || lines[1] !== null)
		return undefined;
	for (const line of lines.slice(2)) {
		if (line === null) return undefined;
		const [sha, name] = line.replace(/\n$/, "").split("\0")[0].split(" ");
		if (name === BRANCH && /^[0-9a-f]{40}$/.test(sha)) return sha;
	}
	return undefined;
}

// The index sign.yml writes: the newest lists first, each named by its sequence and UTC time.
const indexSchema = z
	.array(
		z.strictObject({
			sequence: z.number().int().positive(),
			time: z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/),
			statement: z.string(),
			bundle: z.string(),
		}),
	)
	.min(1)
	.refine((entries) =>
		entries.every(({ sequence, time, statement, bundle }) => {
			const stem = `prod/${sequence}-${time.replace(/[-:]/g, "")}`;
			return (
				statement === `${stem}.statement.json` &&
				bundle === `${stem}.sigstore.json`
			);
		}),
	);

export async function fetchSignedList(
	fetchFn: typeof fetch,
): Promise<SignedListFiles> {
	const refs = await get(fetchFn, REFS);
	if (refs.status !== 200)
		throw new Unfinished(`${REFS} answered ${refs.status}`);
	const commit = tipOf(refs.body);
	if (!commit)
		throw new Unfinished(`${REFS} advertises no ${BRANCH}, so no signed list`);
	const file = async (path: string) => {
		const url = `${RAW}/${commit}/${path}`;
		const got = await get(fetchFn, url);
		if (got.status !== 200)
			throw new Unfinished(`${url} answered ${got.status}`);
		return got.body;
	};
	const index = indexSchema.safeParse(json(await file("prod/index.json")));
	if (!index.success)
		throw new Unfinished(
			`${RAW}/${commit}/prod/index.json is not an index of signed lists`,
		);
	const [newest] = index.data;
	return {
		name: newest.statement.replace(/\.statement\.json$/, ""),
		commit,
		statement: await file(newest.statement),
		bundle: json(await file(newest.bundle)),
	};
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
	readonly logIndex: string;
	readonly signedAt: number;
	readonly witnesses: number;
	readonly images: readonly ListedImage[];
}

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

// The one certificate a hashedrekord 0.0.2 entry's body names, or an empty buffer.
function loggedCertificate(body: Buffer): Buffer {
	try {
		const entry = JSON.parse(body.toString("utf8")) as {
			spec: {
				hashedRekordV002: {
					signature: { verifier: { x509Certificate: { rawBytes: string } } };
				};
			};
		};
		const der =
			entry.spec.hashedRekordV002.signature.verifier.x509Certificate.rawBytes;
		return typeof der === "string"
			? Buffer.from(der, "base64")
			: Buffer.alloc(0);
	} catch {
		return Buffer.alloc(0);
	}
}

const SIGNATURE_LINE =
	/^— (\S+) ((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$/;

// A checkpoint as a C2SP signed note: its text, one blank line, then only signature lines, so that
// @sigstore/verify, which checks the log's line, and the count below read the same text.
function readNote(envelope: string) {
	const blank = envelope.indexOf("\n\n");
	if (blank < 0 || !envelope.endsWith("\n") || /[\r\0]/.test(envelope))
		return undefined;
	const lines = envelope.slice(blank + 2, -1).split("\n");
	const signatures = lines.map((line) => SIGNATURE_LINE.exec(line));
	if (lines.length > 100 || signatures.some((m) => !m)) return undefined;
	return {
		text: Buffer.from(envelope.slice(0, blank + 1), "utf8"),
		signatures: signatures.map((m) => ({
			name: m?.[1] ?? "",
			raw: Buffer.from(m?.[2] ?? "", "base64"),
		})),
	};
}

// The time in ms of each counted cosignature, earliest first: a cosignature/v1 signature, by a
// witness of the trust, over the checkpoint's text. Each operator counts once, at its earliest.
function cosignatures(
	note: NonNullable<ReturnType<typeof readNote>>,
	witnesses: readonly Witness[],
): number[] {
	const earliest = new Map<string, number>();
	for (const { name, raw } of note.signatures) {
		if (raw.length !== 4 + 8 + 64) continue;
		const seconds = raw.readBigUInt64BE(4);
		if (seconds > 1n << 62n) continue;
		const signed = Buffer.concat([
			Buffer.from(`cosignature/v1\ntime ${seconds}\n`),
			note.text,
		]);
		for (const w of witnesses) {
			if (w.name !== name || !w.hash.equals(raw.subarray(0, 4))) continue;
			if (!cryptoVerify(null, signed, w.key, raw.subarray(12))) continue;
			const at = Number(seconds) * 1000;
			if (at < (earliest.get(w.operator) ?? Number.POSITIVE_INFINITY))
				earliest.set(w.operator, at);
		}
	}
	return [...earliest.values()].sort((a, b) => a - b);
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

// The identity is read first, as the Go verifier reads it, so a list another signer signed says so
// whichever log it names. A Rekor v2 entry carries no integrated time, so the certificate bounds the
// time: k witnesses must have cosigned the checkpoint by its NotAfter, and its NotBefore, which the
// signature is never earlier than, must be between 7 days before `now` and 5 minutes after it.
// Throws an Error that completes "Morse's signed list <name> …".
export function verifySignedList(
	{ statement, bundle: json }: SignedListFiles,
	now: number,
	trust: ListTrust = MORSE_TRUST,
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
	const certificate = Buffer.from(material.certificate.rawBytes);
	let leaf: X509Certificate;
	try {
		leaf = new X509Certificate(certificate);
	} catch {
		throw new Error("is signed with a certificate that isn't X.509");
	}
	const workflow = workflowOf(trust.signer);
	const san = leaf.subjectAltName;
	if (san !== `URI:${workflow}`)
		throw new Error(`was signed as ${san}, not Morse's pins workflow`);

	const kind = `${entry.kindVersion?.kind} ${entry.kindVersion?.version}`;
	if (kind !== "hashedrekord 0.0.2")
		throw new Error(`is logged as ${kind}, not hashedrekord 0.0.2 (Rekor v2)`);
	const note = readNote(entry.inclusionProof?.checkpoint?.envelope ?? "");
	if (!note)
		throw new Error(
			"carries a checkpoint that isn't one signed note of text and signature lines",
		);

	const digest = createHash("sha256").update(statement).digest();
	const signed = bundle.content.messageSignature.messageDigest;
	if (
		signed?.algorithm !== HashAlgorithm.SHA2_256 ||
		!digest.equals(signed.digest)
	)
		throw new Error("names a digest other than the statement's SHA-256");
	if (!loggedCertificate(entry.canonicalizedBody).equals(certificate))
		throw new Error("is logged with another certificate than it carries");

	let signer: ReturnType<Verifier["verify"]>;
	try {
		signer = new Verifier(
			toTrustMaterial(TrustedRoot.fromJSON(SIGSTORE_TRUSTED_ROOT)),
			{ tlogThreshold: 1, ctlogThreshold: 1 },
		).verify(toSignedEntity(bundle, Buffer.from(statement)));
	} catch (e) {
		throw new Error(`doesn't verify: ${(e as Error).message}`);
	}

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
	const expected: Record<number, string> = {
		8: ISSUER,
		9: workflow,
		11: "github-hosted",
		12: `https://github.com/${trust.signer.repository}`,
		14: "refs/heads/main",
		15: trust.signer.repositoryId,
		17: trust.signer.ownerId,
		18: workflow,
	};
	for (const [n, want] of Object.entries(expected))
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
	const run = `https://github.com/${trust.signer.repository}/actions/runs/`;
	const attempt = extension(21);
	if (
		!attempt.startsWith(run) ||
		!/^\d+\/attempts\/1$/.test(attempt.slice(run.length))
	)
		throw new Error(
			`was signed by ${extension(21)}, not a first-attempt run of ${trust.signer.repository}`,
		);
	const commit = extension(13);
	if (extension(19) !== commit)
		throw new Error(
			`was signed by a workflow at ${extension(19)}, not the source commit ${commit}`,
		);

	const counted = cosignatures(note, trust.witnesses);
	if (counted.length < trust.k)
		throw new Error(
			`is cosigned by ${counted.length} of the ${trust.k} witnesses it needs`,
		);
	if (counted[trust.k - 1] > leaf.validToDate.getTime())
		throw new Error(
			`is cosigned by fewer than ${trust.k} witnesses before its certificate expired`,
		);

	const st = readStatement(statement);
	if (st.pins_commit !== commit)
		throw new Error(
			`names pins commit ${st.pins_commit}, but its certificate was issued for ${commit}`,
		);

	const signedAt = leaf.validFromDate.getTime();
	if (now - signedAt > MAX_AGE_MS)
		throw new Error(
			`was signed ${ago(now - signedAt)} ago, and the check refuses a list more than 7 days old`,
		);
	if (signedAt - now > MAX_AHEAD_MS)
		throw new Error(
			`was signed ${ago(signedAt - now)} ahead of this machine's clock`,
		);
	return {
		sequence: st.sequence,
		time: st.time,
		pinsCommit: st.pins_commit,
		logIndex: entry.logIndex,
		signedAt,
		witnesses: counted.length,
		images: st.images,
	};
}
