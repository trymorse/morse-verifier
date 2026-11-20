import { describe, expect, it } from "vitest";
import { toBase64 } from "./bytes.ts";
import { readCheckpoint } from "./note.ts";

const ROOT = toBase64(new Uint8Array(32).fill(7));
const SIG = toBase64(new Uint8Array(4 + 64).fill(9));
const TEXT = `log.test\n5\n${ROOT}\n`;
const LINE = `— log.test ${SIG}`;

describe("readCheckpoint", () => {
	it("reads the text, the origin, the size, the root, and each signature line", () => {
		const read = readCheckpoint(`${TEXT}\n${LINE}\n${LINE}\n`);
		if ("malformed" in read) throw new Error(read.malformed);
		expect(read.text).toBe(TEXT);
		expect([read.origin, read.size]).toEqual(["log.test", 5n]);
		expect(toBase64(read.root)).toBe(ROOT);
		expect(read.signatures).toHaveLength(2);
		expect(read.signatures[0].hash).toEqual(new Uint8Array(4).fill(9));
		expect(read.signatures[0].sig).toHaveLength(64);
	});

	it.each([
		["a carriage return", `${TEXT}\n${LINE}\r\n`],
		["a NUL", `log.test\0\n5\n${ROOT}\n\n${LINE}\n`],
		["no signature block", TEXT],
		["no final newline", `${TEXT}\n${LINE}`],
		["a blank line among the signatures", `${TEXT}\n${LINE}\n\n${LINE}\n`],
		["a blank extension line", `log.test\n5\n${ROOT}\next\n\n\n${LINE}\n`],
		["a line without the dash", `${TEXT}\n${LINE.slice(2)}\n`],
		["text before the dash", `${TEXT}\nx ${LINE}\n`],
		["a name with a plus", `${TEXT}\n— log+test ${SIG}\n`],
		["unpadded base64", `${TEXT}\n— log.test ${SIG.replace(/=+$/, "")}\n`],
		[
			"a signature of four bytes",
			`${TEXT}\n— log.test ${toBase64(new Uint8Array(4))}\n`,
		],
		["two lines of text", `log.test\n5\n\n${LINE}\n`],
		["a size with a leading zero", `log.test\n05\n${ROOT}\n\n${LINE}\n`],
		["a size of 2^64", `log.test\n18446744073709551616\n${ROOT}\n\n${LINE}\n`],
		[
			"a root of 31 bytes",
			`log.test\n5\n${toBase64(new Uint8Array(31))}\n\n${LINE}\n`,
		],
		["101 signature lines", `${TEXT}\n${`${LINE}\n`.repeat(101)}`],
	])("refuses a note with %s", (_, note) => {
		expect(readCheckpoint(note)).toHaveProperty("malformed");
	});
});
