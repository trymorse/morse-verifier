import { describe, expect, it } from "vitest";
import { type Bytes, toBase64 } from "../bytes.ts";
import { forgeNitro } from "../testing/forge.ts";
import { fake, LIVE, LOG, NOW, reply } from "../testing/world.ts";
import { formatStep, main, shown, USAGE, wrap } from "./main.ts";

async function run(
	argv: string[],
	world: Parameters<typeof fake>[0] = {},
	options: Parameters<typeof main>[1] = {},
) {
	let out = "";
	let err = "";
	const code = await main(argv, {
		...fake(world).options,
		...options,
		out: (t) => {
			out += t;
		},
		err: (t) => {
			err += t;
		},
	});
	return { code, out, err };
}

// What `npx @askmorse/verify` printed for api.trymorse.ai on 2026-11-11 at 21:05 UTC, from the
// captures in testdata. The verify page shows these lines.
const PASSED = `@askmorse/verify 0.0.0
Checking the enclaves api.trymorse.ai lists

Attestation  2 enclaves, each signed by AWS Nitro (root 641a0321…8f79bb5b)
             key b7b56034a2a03576, signed 4 min ago
             key f6bad5f9a3f183f6, signed 13 min ago
             PCR0 75b4ee3b4897…d0619cbf
             PCR1 3b4a7e1b5f13…a0974d03
             PCR2 7a04e791a60c…645dee72
Allowed      on Morse's signed list of prod images, not revoked
             list 288, signed 7 h ago, Rekor v2 entry 194111814, 4 witnesses
             https://github.com/trymorse/morse-pins/tree/statements/images/prod
Source       v2026.11.15, commit e6cdc4229582 on main of
             github.com/trymorse/morse-enclave, names these PCRs
Rebuild      not run. These PCRs are the ones Morse's CI wrote in that commit.
             Run with --rebuild to build it here and compare (Docker, ~2 min).
TLS          api.trymorse.ai's TLS key 7589dd8f4f792416 (issuer Amazon RSA 2048
             M04) is in no attestation document, so TLS ends before the enclave.
             Morse's relay can read requests on it unless they're sealed.

Passed. The enclaves api.trymorse.ai lists run v2026.11.15 of
github.com/trymorse/morse-enclave, as published (not rebuilt here).
Pin this release in CI: --release e6cdc422958266cedd937171bc7a3ba35618b225
`;

describe("npx @askmorse/verify", () => {
	it("prints each check it passed, and exits 0", async () => {
		const { code, out, err } = await run([]);
		expect(out).toBe(PASSED);
		expect(err).toBe("");
		expect(code).toBe(0);
	});

	it("keeps every line to 80 characters, and prints no middle dot and none of four claims it can't back", async () => {
		for (const argv of [[], ["--rebuild"], ["--release", "v2026.11.15"]]) {
			const { out } = await run(argv);
			for (const line of out.split("\n"))
				expect(line.length, line).toBeLessThanOrEqual(80);
			// The log being append-only, every build being logged, the connection ending inside the
			// enclave, and no one being served another image: claims an earlier draft made.
			expect(out).not.toMatch(
				/·|append-only|every build is logged|your connection ends inside|no one can be served a different one/,
			);
		}
	});

	it("names the step that failed, and exits 1", async () => {
		const { code, out } = await run([], { attestation: [reply([])] });
		expect(out).toBe(`@askmorse/verify 0.0.0
Checking the enclaves api.trymorse.ai lists

Attestation  FAILED: api.trymorse.ai lists no enclave

Failed at Attestation. Don't send anything to these enclaves.
`);
		expect(code).toBe(1);
	});

	it("says what it could not finish and what it checked before, and exits 2", async () => {
		const { code, out } = await run([], { git: "missing" });
		expect(out).toContain(
			"\nCould not finish: the Source check runs git, which isn't on this machine's PATH.\nInstall git (https://git-scm.com) and run again. Nothing was checked past\nAllowed.\n",
		);
		expect(code).toBe(2);
	});

	it("labels a failure that follows a step of the same label", async () => {
		const { code, out } = await run(["--rebuild"], {
			build: { ...LIVE, pcr2: "0".repeat(96) },
		});
		expect(out).toContain(
			"\nRebuild      FAILED: commit e6cdc4229582 rebuilds here to other PCRs than the\n",
		);
		expect(code).toBe(1);
	});

	it("leaves one blank line before the verdict when no step printed", async () => {
		const { code, out } = await run([], {
			attestation: [() => new Response("x", { status: 503 })],
		});
		expect(out).toBe(`@askmorse/verify 0.0.0
Checking the enclaves api.trymorse.ai lists

Could not finish: https://api.trymorse.ai/v1/attestation answered 503. Nothing
was checked.
`);
		expect(code).toBe(2);
	});

	it("prints no control character a document's module_id or a commit's subject carries", async () => {
		const hide = "\x1b[1A\x1b[2KPassed.\x1b[8m";
		const forge = await forgeNitro(new Date(NOW));
		const doc = await forge.document({
			timestamp: NOW - 60_000,
			publicKey: new Uint8Array(32) as Bytes,
			environment: "dev",
			pcrs: LIVE,
			moduleId: `i-0123${hide}`,
		});
		const forged = await run(
			[],
			{ attestation: [reply([toBase64(doc)])] },
			{ root: forge.root },
		);
		expect(forged.code).toBe(1);
		expect(forged.out).not.toContain("\x1b");
		expect(forged.out).toContain(
			"\nAttestation  FAILED: document 1 of 1: user_data does not name a prod key",
		);

		const named = await run([], {
			log: LOG.replace("v2026.11.15", `v2026.11.4${hide}\u202e`),
		});
		expect(named.code).toBe(0);
		for (const c of ["\x1b", "\u202e"]) expect(named.out).not.toContain(c);
		expect(named.out).toContain(
			"v2026.11.4\\u{1b}[1A\\u{1b}[2KPassed.\\u{1b}[8m\\u{202e}",
		);
	});

	it("prints its usage for --help, and its version for --version", async () => {
		expect(await run(["--help"])).toEqual({
			code: 0,
			out: `${USAGE}\n`,
			err: "",
		});
		expect(await run(["--version"])).toEqual({
			code: 0,
			out: "0.0.0\n",
			err: "",
		});
		for (const line of USAGE.split("\n"))
			expect(line.length).toBeLessThanOrEqual(80);
	});

	it.each([
		[["--json"]],
		[["--release"]],
		[["api.trymorse.ai", "other.example"]],
		[["https://api.trymorse.ai"]],
	])("refuses %j with its usage, and exits 2", async (argv) => {
		const { code, out, err } = await run(argv);
		expect(code).toBe(2);
		expect(out).toBe("");
		expect(err).toContain(USAGE);
	});
});

describe("formatStep", () => {
	it("prints a label once, in a 13-character column, and wraps the text to 80", () => {
		const text = "word ".repeat(20).trim();
		expect(
			formatStep({ label: "Rebuild", status: "info", lines: [text, "two"] }),
		).toEqual([
			`Rebuild      ${"word ".repeat(13).trim()}`,
			`             ${"word ".repeat(7).trim()}`,
			"             two",
		]);
		expect(
			formatStep(
				{ label: "Rebuild", status: "passed", lines: ["rebuilt"] },
				"Rebuild",
			),
		).toEqual(["             rebuilt"]);
		for (const status of ["failed", "unfinished"] as const)
			expect(
				formatStep(
					{ label: "Rebuild", status, lines: ["FAILED: no"] },
					"Rebuild",
				),
			).toEqual(["Rebuild      FAILED: no"]);
	});
});

describe("shown", () => {
	it("writes each control character but a newline, and each bidi control, as its code", () => {
		expect(shown("a\x1b[8m\tb\x7f\x9b\u202a\u2069\nc…")).toBe(
			"a\\u{1b}[8m\\u{9}b\\u{7f}\\u{9b}\\u{202a}\\u{2069}\nc…",
		);
	});
});

describe("wrap", () => {
	it("breaks at spaces to fit, and leaves a word longer than the width whole", () => {
		expect(wrap("one two three four", 9)).toEqual(["one two", "three", "four"]);
		expect(wrap("a 0123456789abcdef b", 8)).toEqual([
			"a",
			"0123456789abcdef",
			"b",
		]);
	});
});
