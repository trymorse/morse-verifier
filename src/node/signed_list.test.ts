import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
	advertisement,
	BUNDLE,
	fake,
	LIST,
	LIST_254,
	REFS,
	STATEMENT,
	STATEMENTS_COMMIT,
} from "../testing/world.ts";
import {
	fetchSignedList,
	type ListTrust,
	MORSE_TRUST,
	parseWitness,
	readStatement,
	verifySignedList,
} from "./signed_list.ts";

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const read = (name: string) =>
	readFileSync(new URL(`../testdata/${name}`, import.meta.url));

// List 254 of the public signer, as the statements/images branch holds it: signed under a
// certificate valid from 10:18:58 to 10:28:58, and cosigned by all four witnesses.
const SIGNED = Date.parse("2026-11-10T10:18:58Z");
const EXPIRED = Date.parse("2026-11-10T10:28:58Z");
const AT = SIGNED + 40 * MINUTE;
const STATEMENT_254 = LIST_254.statement;
const BUNDLE_254 = LIST_254.bundle;

interface Bundle {
	verificationMaterial: {
		certificate: { rawBytes: string };
		tlogEntries: {
			kindVersion: { version: string };
			canonicalizedBody: string;
			inclusionProof: { hashes: string[]; checkpoint: { envelope: string } };
		}[];
	};
}
const bundle = () => JSON.parse(BUNDLE_254.toString("utf8")) as Bundle;
const entry = (b: Bundle) => b.verificationMaterial.tlogEntries[0];
const list254 = (o: { statement?: Uint8Array; bundle?: unknown } = {}) => ({
	name: "prod/254-20261110T101835Z",
	commit: STATEMENTS_COMMIT,
	statement: STATEMENT_254,
	bundle: bundle(),
	...o,
});
const edited = (edit: (b: Bundle) => void) => {
	const b = bundle();
	edit(b);
	return list254({ bundle: b });
};

// The checkpoint's text, the log's signature line, and the witnesses' lines.
const noteOf = (b: Bundle) => {
	const envelope = entry(b).inclusionProof.checkpoint.envelope;
	const blank = envelope.indexOf("\n\n");
	const [log, ...witnesses] = envelope.slice(blank + 2, -1).split("\n");
	return { text: envelope.slice(0, blank + 1), log, witnesses };
};
const withLines = (b: Bundle, lines: string[]) => {
	entry(b).inclusionProof.checkpoint.envelope =
		`${noteOf(b).text}\n${lines.join("\n")}\n`;
};

describe("Morse's signed list 254, from the public signer's statements branch", () => {
	it("verifies offline under Sigstore's public root and the enclave's witnesses, and lists 69 prod images, 15 revoked", () => {
		const list = verifySignedList(list254(), AT);
		expect(list).toMatchObject({
			sequence: 254,
			time: "2026-11-10T10:18:35Z",
			pinsCommit: "59db95d5f383ed9beadaeb08f2b765a0a54891df",
			logIndex: "192273049",
			signedAt: SIGNED,
			witnesses: 4,
		});
		expect(list.images).toHaveLength(69);
		expect(list.images.filter((i) => i.revoked)).toHaveLength(15);
	});

	it("is accepted from 5 minutes before its certificate's NotBefore to 7 days after", () => {
		for (const now of [SIGNED - 5 * MINUTE, SIGNED + 7 * DAY])
			expect(verifySignedList(list254(), now).sequence).toBe(254);
	});

	it.each([
		[
			"7 days and a minute after its certificate's NotBefore",
			SIGNED + 7 * DAY + MINUTE,
			/^was signed 7 days ago, and the check refuses a list more than 7 days old$/,
		],
		[
			"6 minutes before its certificate's NotBefore",
			SIGNED - 6 * MINUTE,
			/^was signed 6 min ahead of this machine's clock$/,
		],
	])("is refused %s", (_, now, reason) => {
		expect(() => verifySignedList(list254(), now)).toThrow(reason);
	});

	it("is refused with one byte of the statement changed", () => {
		const statement = Uint8Array.from(STATEMENT_254);
		statement[statement.indexOf("false".charCodeAt(0))] = "F".charCodeAt(0);
		expect(() => verifySignedList(list254({ statement }), AT)).toThrow(
			/^names a digest other than the statement's SHA-256$/,
		);
	});

	it("is refused when the log's entry names another certificate than it carries", () => {
		const other = JSON.parse(
			read("private.sigstore.290.json").toString("utf8"),
		) as Bundle;
		const list = edited((b) => {
			const body = JSON.parse(
				Buffer.from(entry(b).canonicalizedBody, "base64").toString("utf8"),
			) as {
				spec: {
					hashedRekordV002: {
						signature: { verifier: { x509Certificate: { rawBytes: string } } };
					};
				};
			};
			body.spec.hashedRekordV002.signature.verifier.x509Certificate.rawBytes =
				other.verificationMaterial.certificate.rawBytes;
			entry(b).canonicalizedBody = Buffer.from(JSON.stringify(body)).toString(
				"base64",
			);
		});
		expect(() => verifySignedList(list, AT)).toThrow(
			/^is logged with another certificate than it carries$/,
		);
	});

	it.each([
		[
			"a changed inclusion proof",
			(b: Bundle) => {
				const [first, ...rest] = entry(b).inclusionProof.hashes;
				entry(b).inclusionProof.hashes = [
					Buffer.from(first, "base64").reverse().toString("base64"),
					...rest,
				];
			},
			/^doesn't verify: calculated root hash does not match inclusion proof$/,
		],
		[
			"the log's checkpoint signature changed",
			(b: Bundle) => {
				const { log, witnesses } = noteOf(b);
				const [name, sig] = log.slice(2).split(" ");
				const raw = Buffer.from(sig, "base64");
				raw[raw.length - 1] ^= 1;
				withLines(b, [`— ${name} ${raw.toString("base64")}`, ...witnesses]);
			},
			/^doesn't verify: invalid checkpoint signature$/,
		],
		[
			"a checkpoint with a blank line among its signatures",
			(b: Bundle) => {
				const { log, witnesses } = noteOf(b);
				withLines(b, [log, "", ...witnesses]);
			},
			/^carries a checkpoint that isn't one signed note of text and signature lines$/,
		],
	])("is refused with %s", (_, edit, reason) => {
		expect(() => verifySignedList(edited(edit), AT)).toThrow(reason);
	});

	it("is refused logged twice, or not as a bundle", () => {
		expect(() =>
			verifySignedList(
				edited((b) => b.verificationMaterial.tlogEntries.push(entry(b))),
				AT,
			),
		).toThrow(/^has 2 log entries, not one$/);
		expect(() => verifySignedList(list254({ bundle: undefined }), AT)).toThrow(
			/^is not a Sigstore bundle/,
		);
	});
});

describe("the witnesses' cosignatures", () => {
	it.each([
		["two of the four lines dropped", (w: string[]) => w.slice(0, 2)],
		[
			"two dropped and one repeated, which counts once",
			(w: string[]) => [w[0], w[1], w[1]],
		],
		[
			"one of three with a changed signature",
			(w: string[]) => {
				const [name, sig] = w[2].slice(2).split(" ");
				const raw = Buffer.from(sig, "base64");
				raw[raw.length - 1] ^= 1;
				return [w[0], w[1], `— ${name} ${raw.toString("base64")}`];
			},
		],
		[
			"one of three under another name",
			(w: string[]) => [w[0], w[1], w[2].replace(/^— \S+/, "— other.example")],
		],
	])("refuse a checkpoint with 2 counted cosignatures: %s", (_, keep) => {
		const list = edited((b) => {
			const { log, witnesses } = noteOf(b);
			withLines(b, [log, ...keep(witnesses)]);
		});
		expect(() => verifySignedList(list, AT)).toThrow(
			/^is cosigned by 2 of the 3 witnesses it needs$/,
		);
	});

	it("count 3 of the 4 as enough", () => {
		const list = edited((b) => {
			const { log, witnesses } = noteOf(b);
			withLines(b, [log, ...witnesses.slice(1)]);
		});
		expect(verifySignedList(list, AT).witnesses).toBe(3);
	});

	// Three witnesses made here, whose cosignatures this test signs at the times it picks.
	const made = ["a", "b", "c"].map((n) => {
		const name = `witness-${n}.example`;
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const key = Buffer.from(
			publicKey.export({ format: "jwk" }).x ?? "",
			"base64url",
		);
		const hash = createHash("sha256")
			.update(Buffer.concat([Buffer.from(`${name}\n\x04`, "latin1"), key]))
			.digest()
			.subarray(0, 4);
		const vkey = `${name}+${hash.toString("hex")}+${Buffer.concat([Buffer.from([4]), key]).toString("base64")}`;
		const cosign = (text: string, at: number) => {
			const time = Buffer.alloc(8);
			time.writeBigUInt64BE(BigInt(at / 1000));
			const signature = sign(
				null,
				Buffer.from(`cosignature/v1\ntime ${at / 1000}\n${text}`),
				privateKey,
			);
			return `— ${name} ${Buffer.concat([hash, time, signature]).toString("base64")}`;
		};
		return { witness: parseWitness(vkey, `operator ${n}`), cosign };
	});
	const trust: ListTrust = {
		...MORSE_TRUST,
		witnesses: made.map((m) => m.witness),
	};
	const cosignedAt = (times: number[]) =>
		edited((b) => {
			const { text, log } = noteOf(b);
			withLines(b, [log, ...made.map((m, i) => m.cosign(text, times[i]))]);
		});

	it("count when all 3 are at or before the certificate's NotAfter", () => {
		const list = cosignedAt([SIGNED, SIGNED + MINUTE, EXPIRED]);
		expect(verifySignedList(list, AT, trust).witnesses).toBe(3);
	});

	it("refuse a checkpoint whose third cosignature is after the certificate's NotAfter", () => {
		const list = cosignedAt([SIGNED, SIGNED + MINUTE, EXPIRED + 1000]);
		expect(() => verifySignedList(list, AT, trust)).toThrow(
			/^is cosigned by fewer than 3 witnesses before its certificate expired$/,
		);
	});

	it("count two witnesses of one operator once", () => {
		const oneOperator: ListTrust = {
			...trust,
			witnesses: made.map((m, i) => ({
				...m.witness,
				operator: i < 2 ? "operator a" : "operator c",
			})),
		};
		const list = cosignedAt([SIGNED, SIGNED + MINUTE, SIGNED + 2 * MINUTE]);
		expect(() => verifySignedList(list, AT, oneOperator)).toThrow(
			/^is cosigned by 2 of the 3 witnesses it needs$/,
		);
	});

	it("count no witness the trust doesn't list", () => {
		expect(() => verifySignedList(list254(), AT, trust)).toThrow(
			/^is cosigned by 0 of the 3 witnesses it needs$/,
		);
	});
});

describe("the signer", () => {
	const PRIVATE = {
		repository: "Watermark-Labs/pins",
		repositoryId: "1405118053",
		ownerId: "334112171",
	};
	const list290 = {
		name: "signed-290-20261106T095152Z",
		commit: STATEMENTS_COMMIT,
		statement: read("private.statement.290.json"),
		bundle: JSON.parse(read("private.sigstore.290.json").toString("utf8")),
	};
	const at290 = Date.parse("2026-11-06T10:40:00Z");

	it("refuses list 290 of Morse's private signer, which it no longer trusts", () => {
		expect(() => verifySignedList(list290, at290)).toThrow(
			/^was signed as URI:https:\/\/github\.com\/Watermark-Labs\/pins\/\.github\/workflows\/sign\.yml@refs\/heads\/main, not Morse's pins workflow$/,
		);
	});

	it("refuses a Rekor v1 bundle, even under the identity that signed it", () => {
		expect(() =>
			verifySignedList(list290, at290, { ...MORSE_TRUST, signer: PRIVATE }),
		).toThrow(
			/^is logged as hashedrekord 0\.0\.1, not hashedrekord 0\.0\.2 \(Rekor v2\)$/,
		);
		const v1 = edited((b) => {
			entry(b).kindVersion.version = "0.0.1";
		});
		expect(() => verifySignedList(v1, AT)).toThrow(
			/^is logged as hashedrekord 0\.0\.1, not hashedrekord 0\.0\.2/,
		);
	});

	const FIELD = "1\\.3\\.6\\.1\\.4\\.1\\.57264\\.1\\.";
	it.each([
		[
			"repository id",
			{ repositoryId: "1" },
			new RegExp(`^has a certificate whose ${FIELD}15 is 1437511167, not 1$`),
		],
		[
			"owner id",
			{ ownerId: "1" },
			new RegExp(`^has a certificate whose ${FIELD}17 is 345029672, not 1$`),
		],
		[
			"repository",
			{ repository: "trymorse/morse-pins-fork" },
			/^was signed as URI:https:\/\/github\.com\/trymorse\/morse-pins\/\.github\/workflows\/sign\.yml@refs\/heads\/main, not Morse's pins workflow$/,
		],
	])("refuses list 254 under another %s", (_, changed, reason) => {
		expect(() =>
			verifySignedList(list254(), AT, {
				...MORSE_TRUST,
				signer: { ...MORSE_TRUST.signer, ...changed },
			}),
		).toThrow(reason);
	});
});

describe("parseWitness", () => {
	it("reads each of the enclave's four witness keys", () => {
		expect(MORSE_TRUST.witnesses.map((w) => [w.name, w.operator])).toEqual([
			["krabbel.ct.ipng.ch", "IPng Networks"],
			["staging.witness.transparency.goog/ring-any-bells", "TrustFabric"],
			["witness.stagemole.eu", "Mullvad VPN"],
			["witness.navigli.sunlight.geomys.org", "Geomys"],
		]);
	});

	it("refuses a key hash that is not the key's", () => {
		expect(() =>
			parseWitness(
				"witness.stagemole.eu+67f7aea1+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv",
				"Mullvad VPN",
			),
		).toThrow(/^the key hash of witness\.stagemole\.eu is not its key's$/);
	});
});

describe("fetchSignedList", () => {
	it("reads the newest prod list at the tip of statements/images, every file at that commit", async () => {
		const world = fake();
		const files = await fetchSignedList(world.options.fetch);
		expect(files).toMatchObject({ name: LIST, commit: STATEMENTS_COMMIT });
		expect(Buffer.from(files.statement)).toEqual(STATEMENT);
		expect(files.bundle).toEqual(JSON.parse(BUNDLE.toString("utf8")));
		const raw = `https://raw.githubusercontent.com/trymorse/morse-pins/${STATEMENTS_COMMIT}`;
		expect(world.fetched).toEqual([
			REFS,
			`${raw}/prod/index.json`,
			`${raw}/${LIST}.statement.json`,
			`${raw}/${LIST}.sigstore.json`,
		]);
	});

	const answering = (url: string, reply: () => Response) => {
		const world = fake();
		return (async (input: string) =>
			String(input) === url
				? reply()
				: world.options.fetch(input)) as typeof fetch;
	};

	it("could not finish when morse-pins advertises no statements/images", async () => {
		const fetchFn = answering(
			REFS,
			() => new Response(advertisement(STATEMENTS_COMMIT, "refs/heads/other")),
		);
		await expect(fetchSignedList(fetchFn)).rejects.toThrow(
			/advertises no refs\/heads\/statements\/images, so no signed list$/,
		);
	});

	it("could not finish when the index names a file outside the list's own name", async () => {
		const index = `https://raw.githubusercontent.com/trymorse/morse-pins/${STATEMENTS_COMMIT}/prod/index.json`;
		const fetchFn = answering(index, () =>
			Response.json([
				{
					sequence: 288,
					time: "2026-11-11T14:31:26Z",
					statement: "dev/288-20261111T143126Z.statement.json",
					bundle: "prod/288-20261111T143126Z.sigstore.json",
				},
			]),
		);
		await expect(fetchSignedList(fetchFn)).rejects.toThrow(
			/prod\/index\.json is not an index of signed lists$/,
		);
	});
});

describe("readStatement", () => {
	const text = STATEMENT_254.toString("utf8");
	const bytes = (t: string) => new TextEncoder().encode(t);

	it("reads list 254's statement", () => {
		expect(readStatement(STATEMENT_254)).toMatchObject({
			sequence: 254,
			time: "2026-11-10T10:18:35Z",
		});
	});

	it("refuses it after a byte-order mark, which isn't JSON", () => {
		expect(() =>
			readStatement(Uint8Array.from([0xef, 0xbb, 0xbf, ...STATEMENT_254])),
		).toThrow(/^is not JSON$/);
	});

	it.each([
		"2026-11-10",
		"2026-11-10 10:18:35Z",
		"2026-11-10T10:18:35",
		"yesterday",
	])("refuses a time that is not RFC 3339: %s", (time) => {
		expect(() =>
			readStatement(bytes(text.replace("2026-11-10T10:18:35Z", time))),
		).toThrow(/^is not a prod pins statement: time: /);
	});
});
