import { describe, expect, it } from "vitest";
import { LIVE, LIVE_COMMIT, LOG } from "../testing/world.ts";
import { type Exec, Unfinished } from "./io.ts";
import { findRelease, parseLog, readReleases } from "./source.ts";

const P = (c: string) => c.repeat(96);
const commit = (c: string) => c.repeat(40);
const message = (name: string, rootfs = true) =>
	`${name}\n\nPCR0 ${P("a")}\nPCR1 ${P("b")}\nPCR2 ${P("c")}\n${rootfs ? `rootfs sha256 ${"d".repeat(64)}\n` : ""}`;

describe("parseLog", () => {
	it("reads every release on morse-enclave's main, newest first", () => {
		const releases = parseLog(LOG);
		expect(releases).toHaveLength(32);
		expect(releases[0]).toEqual({
			name: "v2026.11.4-pins-23c1570",
			commit: LIVE_COMMIT,
			pcrs: LIVE,
			rootfs:
				"7ca659b21f66d3875cddbc4f884d6aa72417813b75fdcbd7c6b7d2a47659e99a",
		});
		expect(releases.at(-1)?.name).toBe("v2026.10.2");
	});

	it("reads a message without a rootfs line, or without its last newline", () => {
		const log = [
			`${commit("1")}\n${message("v1")}`,
			`${commit("2")}\n${message("v2", false)}`,
			`${commit("3")}\n${message("v3").trimEnd()}`,
		].join("\0");
		expect(parseLog(log).map((r) => [r.name, r.rootfs])).toEqual([
			["v1", "d".repeat(64)],
			["v2", null],
			["v3", "d".repeat(64)],
		]);
	});

	it("leaves out a commit whose message is not a release's", () => {
		const log = [
			`${commit("1")}\nFix the README\n`,
			`${commit("2")}\n${message("v2")}\n`,
			`${commit("3")}\n${message("v3").replace("PCR1", "PCR9")}`,
			`${commit("4")}\n${message("v4").toUpperCase()}`,
			`${commit("5")}\n${message("two words")}`,
			`not a commit\n${message("v6")}`,
		].join("\0");
		expect(parseLog(log)).toEqual([]);
	});
});

describe("findRelease", () => {
	const releases = parseLog(LOG);
	it("finds a release by its name or its commit", () => {
		expect(findRelease(releases, "v2026.11.4-pins-23c1570")?.commit).toBe(
			LIVE_COMMIT,
		);
		expect(findRelease(releases, LIVE_COMMIT)?.name).toBe(
			"v2026.11.4-pins-23c1570",
		);
		expect(findRelease(releases, LIVE_COMMIT.slice(0, 12))).toBeUndefined();
		expect(findRelease(releases, "v1.8.2")).toBeUndefined();
	});

	it("finds a 40-hex pin by its commit alone, though a newer commit's subject is that hex", () => {
		const shadowed = parseLog(
			[
				`${commit("e")}\n${message(LIVE_COMMIT)}`,
				`${commit("d")}\n${message(commit("9"))}`,
				LOG,
			].join("\0"),
		);
		expect(shadowed[0]).toMatchObject({
			name: LIVE_COMMIT,
			commit: commit("e"),
		});
		expect(findRelease(shadowed, LIVE_COMMIT)).toMatchObject({
			name: "v2026.11.4-pins-23c1570",
			commit: LIVE_COMMIT,
			pcrs: LIVE,
		});
		expect(findRelease(shadowed, commit("9"))).toBeUndefined();
	});
});

describe("readReleases", () => {
	it("gives each git command 60 s, and says which one ran out", async () => {
		const bounds: (number | undefined)[] = [];
		const stuck: Exec = async (_command, args, options) => {
			bounds.push(options?.timeoutMs);
			if (args[0] === "clone") return { code: 0, stdout: "", tail: "" };
			throw Object.assign(new Error("ran too long"), { code: "ETIMEDOUT" });
		};
		const e = await readReleases(stuck, "/nowhere/enclave.git").catch(
			(e: unknown) => e,
		);
		expect(e).toBeInstanceOf(Unfinished);
		expect((e as Error).message).toBe(
			"git log of https://github.com/trymorse/morse-enclave didn't finish in 60 s. Check that this machine reaches github.com, and run again",
		);
		expect(bounds).toEqual([60_000, 60_000]);
	});
});
