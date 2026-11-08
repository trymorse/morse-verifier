import { describe, expect, it } from "vitest";
import { exec, timedOut } from "./io.ts";

const node = (script: string) => [process.execPath, ["-e", script]] as const;

describe("exec", () => {
	it("returns what a program printed and its exit code", async () => {
		const ran = await exec(
			...node(
				"process.stdout.write('out'); console.error('err'); process.exit(3)",
			),
		);
		expect(ran).toEqual({ code: 3, stdout: "out", tail: "err" });
	});

	it("kills a program still running after timeoutMs, though a program it started holds its output open", async () => {
		const started = Date.now();
		const e = await exec(
			...node(
				"require('node:child_process').spawn(process.execPath, ['-e', 'setTimeout(() => {}, 3000)'], { stdio: 'inherit' }); setTimeout(() => {}, 3000)",
			),
			{ timeoutMs: 200 },
		).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(timedOut(e)).toBe(true);
		expect(Date.now() - started).toBeLessThan(2000);
	});
});
