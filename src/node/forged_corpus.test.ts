import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	AT,
	COMMIT,
	ECDSA_SHA384,
	EXPIRED,
	EXTENSION,
	type Ext,
	extKeyUsage,
	type Forgery,
	FULCIO,
	FULCIO_VALUES,
	forgeList,
	fulcio,
	replacing,
	SIGNED,
	spelledOutFalse,
	subjectAltName,
	TEST_TRUST,
	TEST_TRUSTED_ROOT,
	underTestRoot,
	WORKFLOW_URI,
} from "../testing/rekor_v2.ts";
import { LIST_254 } from "../testing/world.ts";
import { verifySignedList } from "./signed_list.ts";
import { SIGSTORE_TRUSTED_ROOT } from "./sigstore_root.ts";

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const OTHER_COMMIT = "badbad".padEnd(40, "0");
const RUN = "https://github.com/trymorse/morse-pins/actions/runs/19000000001";
const OTHER_REPO_RUN_OF_EQUAL_LENGTH = RUN.replace("morse-pins", "morse-pinz");

const verify = (f: Forgery = {}, now = AT) =>
	underTestRoot(() => verifySignedList(forgeList(f), now, TEST_TRUST));
const refusal = (f: Forgery, now = AT) => {
	try {
		verify(f, now);
	} catch (e) {
		return (e as Error).message;
	}
	return "accepted";
};
const setting = (n: number, ...values: string[]) =>
	replacing(`${FULCIO}${n}`, ...values.map((v) => fulcio(n, v)));
const raw = (n: number, value: string): Ext => ({
	id: `${FULCIO}${n}`,
	critical: false,
	value: Buffer.from(value),
});

describe("a Rekor v2 list forged under the test trusted root", () => {
	it("is accepted as it is, with all three test witnesses", () => {
		expect(verify()).toMatchObject({
			sequence: 9,
			pinsCommit: COMMIT,
			logIndex: "5",
			signedAt: SIGNED,
			witnesses: 3,
		});
	});

	it.each<[string, Forgery]>([
		[
			"without the raw issuer of .1, which is optional",
			{ extensions: replacing(`${FULCIO}1`) },
		],
		["started by a push", { extensions: setting(20, "push") }],
		[
			"cosigned by the last witness at the certificate's NotAfter",
			{ cosignedAt: [SIGNED, SIGNED, EXPIRED] },
		],
		[
			"with a code-signing usage among others",
			{
				extensions: replacing(
					EXTENSION.EXT_KEY_USAGE,
					extKeyUsage("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.3"),
				),
			},
		],
	])("is accepted %s", (_, f) => {
		expect(verify(f).sequence).toBe(9);
	});
});

const CORPUS: [string, Forgery, string][] = [
	[
		"the code-signing extended key usage: issued for TLS servers only",
		{
			extensions: replacing(
				EXTENSION.EXT_KEY_USAGE,
				extKeyUsage("1.3.6.1.5.5.7.3.1"),
			),
		},
		"is signed with a certificate not issued for code signing",
	],
	[
		"the code-signing extended key usage: no extended key usage at all",
		{ extensions: replacing(EXTENSION.EXT_KEY_USAGE) },
		"is signed with a certificate not issued for code signing",
	],
	[
		"a critical extension nothing reads: one of no known kind",
		{
			extensions: (es) => [
				...es,
				{ id: "1.2.3.4", critical: true, value: Buffer.from([5, 0]) },
			],
		},
		"is signed with a certificate whose extension 1.2.3.4 is critical, which nothing here reads",
	],
	[
		"a critical extension nothing reads: the build signer URI marked critical",
		{
			extensions: replacing(`${FULCIO}9`, {
				...fulcio(9, WORKFLOW_URI),
				critical: true,
			}),
		},
		`is signed with a certificate whose extension ${FULCIO}9 is critical, which nothing here reads`,
	],
	[
		"distinguished encoding: a critical flag of FALSE written out",
		{
			extensions: (es) =>
				es.map((e) =>
					e.id === EXTENSION.EXT_KEY_USAGE ? spelledOutFalse(e) : e,
				),
		},
		"is signed with a certificate that is not distinguished-encoded",
	],
	[
		"one signature algorithm: the TBS names ECDSA with SHA-384, the certificate SHA-256",
		{ innerAlgorithm: ECDSA_SHA384 },
		"is signed with a certificate whose two signature algorithms differ",
	],

	[
		"the SAN: sign.yml on another branch",
		{
			extensions: replacing(
				EXTENSION.SUBJECT_ALT_NAME,
				subjectAltName(WORKFLOW_URI.replace("heads/main", "heads/dev")),
			),
		},
		`was signed as URI:${WORKFLOW_URI.replace("heads/main", "heads/dev")}, not Morse's pins workflow`,
	],
	...(
		[
			[8, "the issuer", "https://accounts.google.com"],
			[
				9,
				"the build signer URI",
				WORKFLOW_URI.replace("sign.yml", "release.yml"),
			],
			[11, "the GitHub-hosted runner", "self-hosted"],
			[
				12,
				"the source repository URI",
				"https://github.com/trymorse/morse-pins-fork",
			],
			[14, "the source ref", "refs/heads/dev"],
			[15, "the repository id", "1"],
			[17, "the owner id", "1"],
			[
				18,
				"the build config URI",
				WORKFLOW_URI.replace("heads/main", "tags/v1"),
			],
		] as const
	).map(([n, rule, value]): [string, Forgery, string] => [
		`${rule} (.${n}): ${value}`,
		{ extensions: setting(n, value) },
		`has a certificate whose ${FULCIO}${n} is ${value}, not ${FULCIO_VALUES[n]}`,
	]),
	[
		"one UTF8String per extension: no build signer URI (.9)",
		{ extensions: replacing(`${FULCIO}9`) },
		`has a certificate with no single UTF8String ${FULCIO}9`,
	],
	[
		"one UTF8String per extension: the source ref (.14) twice",
		{ extensions: setting(14, "refs/heads/main", "refs/heads/main") },
		`has a certificate with no single UTF8String ${FULCIO}14`,
	],
	[
		"one UTF8String per extension: the runner (.11) as raw bytes",
		{ extensions: replacing(`${FULCIO}11`, raw(11, "github-hosted")) },
		`has a certificate with no single UTF8String ${FULCIO}11`,
	],
	[
		"one UTF8String per extension: no source commit (.13)",
		{ extensions: replacing(`${FULCIO}13`) },
		`has a certificate with no single UTF8String ${FULCIO}13`,
	],
	[
		"the raw issuer (.1): another issuer",
		{
			extensions: replacing(
				`${FULCIO}1`,
				raw(1, "https://accounts.google.com"),
			),
		},
		`has a certificate whose ${FULCIO}1 is another issuer`,
	],
	[
		"the raw issuer (.1): GitHub's, twice",
		{
			extensions: replacing(
				`${FULCIO}1`,
				raw(1, FULCIO_VALUES[8]),
				raw(1, FULCIO_VALUES[8]),
			),
		},
		`has a certificate whose ${FULCIO}1 is another issuer`,
	],
	[
		"the trigger (.20), push or schedule only: a manual dispatch",
		{ extensions: setting(20, "workflow_dispatch") },
		"was signed by a run started by workflow_dispatch",
	],
	[
		"the trigger (.20), push or schedule only: a pull request",
		{ extensions: setting(20, "pull_request_target") },
		"was signed by a run started by pull_request_target",
	],
	[
		"the first attempt of the run (.21): a rerun",
		{ extensions: setting(21, `${RUN}/attempts/2`) },
		`was signed by ${RUN}/attempts/2, not a first-attempt run of trymorse/morse-pins`,
	],
	[
		"the first attempt of the run (.21): a run of another repository",
		{ extensions: setting(21, `${OTHER_REPO_RUN_OF_EQUAL_LENGTH}/attempts/1`) },
		`was signed by ${OTHER_REPO_RUN_OF_EQUAL_LENGTH}/attempts/1, not a first-attempt run of trymorse/morse-pins`,
	],
	[
		"the first attempt of the run (.21): more after the attempt",
		{ extensions: setting(21, `${RUN}/attempts/1/jobs/2`) },
		`was signed by ${RUN}/attempts/1/jobs/2, not a first-attempt run of trymorse/morse-pins`,
	],
	[
		"the workflow sha (.19) equal to the source commit (.13)",
		{ extensions: setting(19, OTHER_COMMIT) },
		`was signed by a workflow at ${OTHER_COMMIT}, not the source commit ${COMMIT}`,
	],
	[
		"the statement's pins commit equal to the source commit (.13)",
		{ pinsCommit: OTHER_COMMIT },
		`names pins commit ${OTHER_COMMIT}, but its certificate was issued for ${COMMIT}`,
	],

	[
		"the Fulcio CA: issued by a CA no trusted root names",
		{ untrustedCa: true },
		"doesn't verify: Failed to verify certificate chain",
	],
	[
		"the certificate's validity: timestamped after its NotAfter",
		{ timestampAt: EXPIRED + MINUTE },
		"doesn't verify: Failed to verify certificate chain",
	],
	["the SCT: none", { sct: "none" }, "doesn't verify: expected 1 SCTs, got 0"],
	[
		"the SCT: signed by a CT log no trusted root names",
		{ sct: "untrusted" },
		"doesn't verify: SCT verification failed",
	],

	[
		"3 cosignatures by the certificate's NotAfter: the third a second late",
		{ cosignedAt: [SIGNED, SIGNED, EXPIRED + 1000] },
		"is cosigned by fewer than 3 witnesses before its certificate expired",
	],
];

describe("the forged corpus", () => {
	it.each(CORPUS)("refuses a certificate that breaks %s", (_, f, reason) => {
		expect(refusal(f)).toBe(reason);
	});

	it.each([
		[
			"7 days and a minute after its certificate's NotBefore",
			SIGNED + 7 * DAY + MINUTE,
			"was signed 7 days ago, and the check refuses a list more than 7 days old",
		],
		[
			"6 minutes before its certificate's NotBefore",
			SIGNED - 6 * MINUTE,
			"was signed 6 min ahead of this machine's clock",
		],
	])("refuses the valid list %s", (_, now, reason) => {
		expect(refusal({}, now)).toBe(reason);
	});

	it("refuses a certificate that isn't X.509", () => {
		const list = forgeList();
		list.bundle.verificationMaterial.certificate.rawBytes =
			Buffer.from("not a certificate").toString("base64");
		expect(() =>
			underTestRoot(() => verifySignedList(list, AT, TEST_TRUST)),
		).toThrow(/^is signed with a certificate that isn't X\.509$/);
	});
});

describe("the test trust-root hook", () => {
	it("is the only way the test root verifies: under Sigstore's root the valid forged list is refused", () => {
		expect(() => verifySignedList(forgeList(), AT, TEST_TRUST)).toThrow(
			/^doesn't verify: /,
		);
	});

	it("puts Sigstore's root back after a call, and after one that throws", () => {
		const before = structuredClone(SIGSTORE_TRUSTED_ROOT);
		underTestRoot(() =>
			expect(SIGSTORE_TRUSTED_ROOT).toEqual(TEST_TRUSTED_ROOT),
		);
		expect(SIGSTORE_TRUSTED_ROOT).toEqual(before);
		expect(() =>
			underTestRoot(() => {
				throw new Error("inside");
			}),
		).toThrow("inside");
		expect(SIGSTORE_TRUSTED_ROOT).toEqual(before);
		expect(
			verifySignedList(
				{
					commit: "0".repeat(40),
					...LIST_254,
					bundle: JSON.parse(LIST_254.bundle.toString("utf8")),
				},
				Date.parse("2026-11-10T11:00:00Z"),
			).sequence,
		).toBe(254);
	});

	it("is in no file of the package's build", () => {
		const pkg = fileURLToPath(new URL("../..", import.meta.url));
		const out = mkdtempSync(join(tmpdir(), "verifier-build-"));
		try {
			execFileSync(
				process.execPath,
				[
					createRequire(import.meta.url).resolve("typescript/bin/tsc"),
					"-p",
					join(pkg, "tsconfig.build.json"),
					"--outDir",
					out,
				],
				{ cwd: pkg, stdio: "pipe" },
			);
			const files = readdirSync(out, { recursive: true, encoding: "utf8" });
			expect(files).toContain(join("node", "signed_list.js"));
			expect(files.filter((f) => /testing|rekor_v2|\.test\./.test(f))).toEqual(
				[],
			);
			const shipped = files
				.filter((f) => f.endsWith(".js") || f.endsWith(".d.ts"))
				.map((f) => [f, readFileSync(join(out, f), "utf8")] as const);
			expect(
				shipped
					.filter(([, text]) =>
						/underTestRoot|TEST_TRUSTED_ROOT|rekor_v2|testing\/|test\.example/.test(
							text,
						),
					)
					.map(([f]) => f),
			).toEqual([]);
		} finally {
			rmSync(out, { recursive: true, force: true });
		}
	}, 60_000);
});
