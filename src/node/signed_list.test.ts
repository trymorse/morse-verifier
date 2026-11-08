import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BUNDLE, NOW, STATEMENT, TAG } from "../testing/world.ts";
import { readStatement, verifySignedList } from "./signed_list.ts";

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const LOGGED = Date.parse("2026-11-06T09:52:18Z");
interface Bundle {
	verificationMaterial: { tlogEntries: Record<string, unknown>[] };
}
const bundle = () => JSON.parse(BUNDLE.toString("utf8")) as Bundle;
const list290 = (o: { statement?: Uint8Array; bundle?: unknown } = {}) => ({
	tag: TAG,
	statement: STATEMENT,
	bundle: bundle(),
	...o,
});
const entry = (b: Bundle) => b.verificationMaterial.tlogEntries[0];
const edited = (edit: (b: Bundle) => void) => {
	const b = bundle();
	edit(b);
	return list290({ bundle: b });
};

describe("Morse's signed list 290, as GitHub served it", () => {
	it("verifies offline under Sigstore's public root, and lists 45 prod images, 4 revoked", () => {
		const list = verifySignedList(list290(), NOW);
		expect(list).toMatchObject({
			sequence: 290,
			time: "2026-11-06T09:51:52Z",
			pinsCommit: "a772f3906ac4c0fa611522207db19083b6049ba4",
			logIndex: "3714441255",
			integratedTime: LOGGED,
		});
		expect(list.images).toHaveLength(45);
		expect(list.images.filter((i) => i.revoked)).toHaveLength(4);
	});

	it("is accepted from 5 minutes before Rekor logged it to 7 days after", () => {
		for (const now of [LOGGED - 5 * MINUTE, LOGGED + 7 * DAY])
			expect(verifySignedList(list290(), now).sequence).toBe(290);
	});

	it.each([
		[
			"7 days and a minute after Rekor logged it",
			LOGGED + 7 * DAY + MINUTE,
			/logged 7 days ago, and the check refuses a list more than 7 days old/,
		],
		[
			"6 minutes before Rekor logged it",
			LOGGED - 6 * MINUTE,
			/logged 6 min ahead of this machine's clock/,
		],
	])("is refused %s", (_, now, reason) => {
		expect(() => verifySignedList(list290(), now)).toThrow(reason);
	});

	it("is refused with one byte of the statement changed", () => {
		const statement = Uint8Array.from(STATEMENT);
		statement[statement.indexOf("false".charCodeAt(0))] = "F".charCodeAt(0);
		expect(() => verifySignedList(list290({ statement }), NOW)).toThrow(
			/names a digest other than the statement's SHA-256/,
		);
	});

	it.each([
		[
			"its inclusion proof, which @sigstore/bundle refuses first",
			(b: Bundle) => delete entry(b).inclusionProof,
			/^is not a Sigstore bundle: invalid bundle \(verificationMaterial\.tlogEntries\[0\]\.inclusionProof\)$/,
		],
		[
			"Rekor's signed entry timestamp",
			(b: Bundle) => delete entry(b).inclusionPromise,
			/lacks Rekor's signed entry timestamp or its inclusion proof/,
		],
	])("is refused when its log entry lacks %s", (_, edit, reason) => {
		expect(() => verifySignedList(edited(edit), NOW)).toThrow(reason);
	});

	it("is refused logged twice, logged in Rekor v2, or not as a bundle", () => {
		expect(() =>
			verifySignedList(
				edited((b) => b.verificationMaterial.tlogEntries.push(entry(b))),
				NOW,
			),
		).toThrow(/has 2 log entries, not one/);
		expect(() =>
			verifySignedList(
				edited((b) => {
					(entry(b).kindVersion as { version: string }).version = "0.0.2";
				}),
				NOW,
			),
		).toThrow(/is logged as hashedrekord 0.0.2, not hashedrekord 0.0.1/);
		expect(() => verifySignedList(list290({ bundle: undefined }), NOW)).toThrow(
			/is not a Sigstore bundle/,
		);
	});
});

describe("readStatement", () => {
	const text = STATEMENT.toString("utf8");
	const bytes = (t: string) => new TextEncoder().encode(t);

	it("reads list 290's statement", () => {
		expect(readStatement(STATEMENT)).toMatchObject({
			sequence: 290,
			time: "2026-11-06T09:51:52Z",
		});
	});

	it("refuses it after a byte-order mark, which isn't JSON", () => {
		expect(() =>
			readStatement(Uint8Array.from([0xef, 0xbb, 0xbf, ...STATEMENT])),
		).toThrow(/^is not JSON$/);
	});

	it.each([
		"2026-11-06",
		"2026-11-06 09:51:52Z",
		"2026-11-06T09:51:52",
		"yesterday",
	])("refuses a time that is not RFC 3339: %s", (time) => {
		expect(() =>
			readStatement(bytes(text.replace("2026-11-06T09:51:52Z", time))),
		).toThrow(/^is not a prod pins statement: time: /);
	});
});

// Morse's own forgeries, from morse-server's internal/pinsig: each changes one thing of a valid
// bundle signed under a test CA and Rekor key, and the Go verifier refuses every one but "valid".
// The statement-* cases sign a bad statement, so the bundle verifies and the statement is refused.
describe("Morse's forged pins bundles", () => {
	const forged = JSON.parse(
		readFileSync(
			new URL("../testdata/pinsig_forged.json", import.meta.url),
			"utf8",
		),
	) as {
		trusted_root: unknown;
		statements: Record<string, string>;
		cases: {
			name: string;
			error: string;
			statement: string;
			bundle: unknown;
		}[];
	};
	const trust = { root: forged.trusted_root, ctlogThreshold: 0 };
	const at = Date.parse("2026-10-28T12:05:00Z");
	const check = (c: (typeof forged.cases)[number]) =>
		verifySignedList(
			{
				tag: "forged",
				statement: new TextEncoder().encode(forged.statements[c.statement]),
				bundle: c.bundle,
			},
			at,
			trust,
		);

	it("has all 40", () => {
		expect(forged.cases).toHaveLength(40);
	});

	it("accepts the valid one", () => {
		const valid = forged.cases.find((c) => c.name === "valid");
		expect(valid && check(valid)).toMatchObject({ sequence: 101 });
	});

	// Why each is refused, so that one fault refusing them all, such as a clock or a trust root
	// that slipped, fails here.
	const FIELD = "1\\.3\\.6\\.1\\.4\\.1\\.57264\\.1\\.";
	const ext = (n: number, value: string) =>
		new RegExp(`^has a certificate whose ${FIELD}${n} is ${value}, not `);
	const REASONS: Record<string, RegExp> = {
		issuer: ext(8, "https://accounts\\.google\\.com"),
		"build-signer":
			/^was signed as URI:\S+\/check\.yml@refs\/heads\/main, not Morse's pins workflow$/,
		"san-only":
			/^was signed as URI:\S+\/check\.yml@refs\/heads\/main, not Morse's pins workflow$/,
		"source-repository-uri": ext(
			12,
			"https://github\\.com/Watermark-Labs/pins-fork",
		),
		"repository-id": ext(15, "1"),
		"owner-id": ext(17, "1"),
		ref: ext(14, "refs/heads/feature"),
		trigger: /^was signed by a run started by workflow_dispatch$/,
		runner: ext(11, "self-hosted"),
		"no-trigger-extension": new RegExp(
			`^has a certificate with no single UTF8String ${FIELD}20$`,
		),
		"build-config-uri": ext(18, "\\S+/other\\.yml@refs/heads/main"),
		"build-config-digest":
			/^was signed by a workflow at (ab){20}, not the source commit [0-9a-f]{40}$/,
		"run-attempt-2":
			/^was signed by \S+\/actions\/runs\/\d+\/attempts\/2, not a first-attempt run of Watermark-Labs\/pins$/,
		"run-other-repository":
			/^was signed by https:\/\/github\.com\/Watermark-Labs\/pins-fork\/actions\/runs\/1\/attempts\/1, not a first-attempt run of Watermark-Labs\/pins$/,
		expired: /^doesn't verify: Failed to verify certificate chain$/,
		"critical-extension":
			/^is signed with a certificate whose extension 1\.3\.6\.1\.4\.1\.57264\.99 is critical, which nothing here reads$/,
		"no-eku": /^is signed with a certificate not issued for code signing$/,
		signature: /^doesn't verify: signature verification failed$/,
		"body-digest": /^doesn't verify: digest mismatch$/,
		"body-signature": /^doesn't verify: signature mismatch$/,
		"body-certificate": /^is logged with another certificate than it carries$/,
		set: /^doesn't verify: inclusion promise could not be verified$/,
		inclusion:
			/^doesn't verify: calculated root hash does not match inclusion proof$/,
		"checkpoint-other-tree":
			/^doesn't verify: calculated root hash does not match inclusion proof$/,
		"unknown-log": /^doesn't verify: inclusion promise could not be verified$/,
		"two-entries": /^has 2 log entries, not one$/,
		dsse: /^signs a DSSE envelope, not the statement itself$/,
		"short-log-id": /^doesn't verify: inclusion promise could not be verified$/,
		"checkpoint-short-hash": /^doesn't verify: invalid checkpoint signature$/,
		"checkpoint-two-signatures":
			/^carries a checkpoint signed other than once$/,
		"deprecated-issuer": new RegExp(
			`^has a certificate whose ${FIELD}1 is another issuer$`,
		),
		"no-promise":
			/^lacks Rekor's signed entry timestamp or its inclusion proof/,
		"no-proof":
			/^is not a Sigstore bundle: invalid bundle \(verificationMaterial\.tlogEntries\[0\]\.inclusionProof\)$/,
		"statement-non-canonical":
			/^is not in canonical form \(JCS\), as Morse signs it$/,
		"statement-type": /^is not a prod pins statement: type: /,
		"statement-commit":
			/^names pins commit (ab){20}, but its certificate was issued for [0-9a-f]{40}$/,
		"statement-folded-key":
			/^is not a prod pins statement: it: Unrecognized key: "ſequence"$/,
		"statement-null-revoked":
			/^is not a prod pins statement: images\.0\.revoked: /,
		"statement-no-images": /^is not a prod pins statement: images: Too small/,
	};

	it("has a reason for each forgery, and each names one", () => {
		expect(Object.keys(REASONS).sort()).toEqual(
			forged.cases
				.filter((c) => c.error !== "")
				.map((c) => c.name)
				.sort(),
		);
	});

	it.each(
		forged.cases.filter((c) => c.error !== "").map((c) => [c.name, c.error, c]),
	)("refuses %s (Go: %s)", (name, _, c) => {
		expect(() => check(c)).toThrow(REASONS[name]);
	});

	it("refuses a checkpoint with two signature lines a blank line apart", () => {
		const valid = forged.cases.find((c) => c.name === "valid");
		const b = structuredClone(valid?.bundle) as Bundle;
		const proof = entry(b).inclusionProof as {
			checkpoint: { envelope: string };
		};
		const [, signature] = proof.checkpoint.envelope.split("\n\n");
		proof.checkpoint.envelope += `\n${signature}`;
		expect(() =>
			check({
				name: "",
				error: "",
				statement: valid?.statement ?? "",
				bundle: b,
			}),
		).toThrow(/^carries a checkpoint signed other than once$/);
	});
});
