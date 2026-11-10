// What the CLI prints for each scenario of testdata/golden_scenarios.json, held to
// testdata/golden/<name>.txt.
// UPDATE_GOLDEN=1 writes the files, and golden_forged.json's documents if it has none.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { type Bytes, fromBase64, toBase64 } from "../bytes.ts";
import { type Cbor, decodeCbor } from "../cbor.ts";
import type { Pcrs } from "../pins.ts";
import { forgeNitro } from "../testing/forge.ts";
import {
	fake,
	LIVE,
	LOG,
	liveInstances,
	reply,
	STATEMENT,
	type World,
} from "../testing/world.ts";
import { parseCert } from "../x509.ts";
import { main } from "./main.ts";
import { parseLog } from "./source.ts";

const testdata = (name: string) =>
	new URL(`../testdata/${name}`, import.meta.url);
const read = (name: string) => new Uint8Array(readFileSync(testdata(name)));
const UPDATE = process.env.UPDATE_GOLDEN === "1";

interface ReplySpec {
	instances?: string[];
	json?: unknown;
	status?: number;
	headers?: Record<string, string>;
	body?: string;
}
interface Scenario {
	name: string;
	argv: string[];
	world: {
		now?: string;
		root?: "forged";
		attestation?: ReplySpec[];
		list?: "290" | "290-changed" | "280";
		log?: { drop?: number; replace?: [string, string] };
		git?: "missing";
		docker?: string;
		build?: Pcrs | "fails";
		tls?: { spkiSha256: string; issuer: string } | { error: string };
	};
}
const SCENARIOS = JSON.parse(
	readFileSync(testdata("golden_scenarios.json"), "utf8"),
) as { now: string; tmpdir: string; scenarios: Scenario[] };

const FORGED = testdata("golden_forged.json");

/** Documents of five images under one forged root, written once, so their keys and the root's
 * hash are the same in every run. */
/** A forged root whose three certificates have positive serials, as RFC 5280 requires: certs.ts draws eight random bytes, which half the time read negative. */
async function positiveForge(now: number) {
	for (;;) {
		const forge = await forgeNitro(new Date(now));
		const probe = decodeCbor(
			(
				decodeCbor(
					await forge.document({
						timestamp: now,
						publicKey: new Uint8Array(32) as Bytes,
					}),
				) as Cbor[]
			)[2] as Bytes,
		) as ReadonlyMap<string, Cbor>;
		const ders = [
			probe.get("certificate"),
			...(probe.get("cabundle") as Bytes[]),
		] as Bytes[];
		if (ders.every((der) => (parseCert(der).serial[0] & 0x80) === 0))
			return forge;
	}
}

async function forgeOnce() {
	const now = Date.parse(SCENARIOS.now);
	const forge = await positiveForge(now);
	const zero = "0".repeat(96);
	const revoked = (
		JSON.parse(new TextDecoder().decode(STATEMENT)) as {
			images: (Pcrs & { revoked: boolean })[];
		}
	).images.find((i) => i.revoked) as Pcrs;
	const [, older] = parseLog(LOG);
	const doc = async (
		key: number,
		minutesAgo: number,
		pcrs: Pcrs,
		o: { environment?: string; moduleId?: string } = {},
	) =>
		toBase64(
			await forge.document({
				timestamp: now - minutesAgo * 60_000,
				publicKey: new Uint8Array(32).fill(key) as Bytes,
				environment: o.environment ?? "prod",
				pcrs: { pcr0: pcrs.pcr0, pcr1: pcrs.pcr1, pcr2: pcrs.pcr2 },
				moduleId: o.moduleId,
			}),
		);
	const documents = {
		debug: await doc(1, 1, { pcr0: zero, pcr1: zero, pcr2: zero }),
		"dev-hidden": await doc(0, 1, LIVE, {
			environment: "dev",
			moduleId: "i-0123\x1b[1A\x1b[2KPassed.\x1b[8m",
		}),
		revoked: await doc(2, 1, revoked),
		live: await doc(3, 1, LIVE),
		older: await doc(4, 2, older.pcrs),
	};
	writeFileSync(
		FORGED,
		`${JSON.stringify({ root: toBase64(forge.root.der), documents }, null, 2)}\n`,
	);
}

const forged = () =>
	JSON.parse(readFileSync(FORGED, "utf8")) as {
		root: string;
		documents: Record<string, string>;
	};

function instance(ref: string): string {
	if (ref.startsWith("forged:")) return forged().documents[ref.slice(7)];
	const [, n, flipped] = /^live(\d)(-flipped)?$/.exec(ref) ?? [];
	const live = liveInstances()[Number(n)];
	if (!flipped) return live;
	const doc = fromBase64(live) as Bytes;
	doc[doc.length - 1] ^= 1;
	return toBase64(doc);
}

const response = (r: ReplySpec) => () =>
	r.instances
		? reply(r.instances.map(instance))()
		: r.json !== undefined
			? Response.json(r.json)
			: new Response(r.body ?? "", {
					status: r.status,
					headers: r.headers,
				});

function worldOf(s: Scenario["world"]): World {
	const statement = Uint8Array.from(STATEMENT);
	if (s.list === "290-changed") statement[statement.length - 3] ^= 1;
	let log = LOG;
	if (s.log?.drop) log = LOG.split("\0").slice(s.log.drop).join("\0");
	if (s.log?.replace) log = LOG.replace(...s.log.replace);
	return {
		attestation: s.attestation?.map(response),
		list:
			s.list === "280"
				? {
						tag: "signed-280-20261106T080407Z",
						statement: read("prod.statement.280.json"),
						bundle: read("prod.sigstore.280.json"),
					}
				: {
						tag: "signed-290-20261106T095152Z",
						statement,
						bundle: read("prod.sigstore.json"),
					},
		log,
		git: s.git,
		docker: s.docker,
		build: s.build,
		tls:
			s.tls && "error" in s.tls
				? new Error(s.tls.error)
				: (s.tls as World["tls"]),
	};
}

/** The output with the temporary directories' random names written as XXXXXX. Node's mkdtemp
 * adds six letters or digits. */
const normalized = (out: string) =>
	out.replace(/(trymorse-verify-|\/\d+-)[A-Za-z0-9]{6}/g, "$1XXXXXX");

describe("the CLI's output, held to testdata/golden", () => {
	beforeAll(async () => {
		if (UPDATE && !existsSync(FORGED)) await forgeOnce();
	});

	it.each(
		SCENARIOS.scenarios.map((s) => [s.name, s]),
	)("%s", async (name, s) => {
		vi.stubEnv("TMPDIR", SCENARIOS.tmpdir);
		let out = "";
		const now = Date.parse(s.world.now ?? SCENARIOS.now);
		await main(s.argv, {
			...fake(worldOf(s.world)).options,
			now: () => now,
			...(s.world.root === "forged"
				? { root: parseCert(fromBase64(forged().root) as Bytes) }
				: {}),
			out: (t) => {
				out += t;
			},
			err: () => {},
		});
		const file = testdata(`golden/${name}.txt`);
		if (UPDATE) {
			mkdirSync(testdata("golden"), { recursive: true });
			writeFileSync(file, normalized(out));
		}
		expect(normalized(out)).toBe(readFileSync(file, "utf8"));
	});
});
