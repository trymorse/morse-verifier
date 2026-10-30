import { describe, expect, it } from "vitest";
import { unhex } from "./bytes.ts";
import { decodeCbor } from "./cbor.ts";

const decode = (hexText: string) => decodeCbor(unhex(hexText));

describe("an indefinite-length item", () => {
	it.each([
		[
			"a map",
			"bf6161016162820203ff",
			new Map<string, unknown>([
				["a", 1],
				["b", [2, 3]],
			]),
		],
		["an empty map", "bfff", new Map()],
		["an array", "9f018202039f04ffff", [1, [2, 3], [4]]],
		["an empty array", "9fff", []],
		["a byte string in chunks", "5f420102410340ff", Uint8Array.of(1, 2, 3)],
		["a byte string of no chunks", "5fff", new Uint8Array()],
		["a text string in chunks", "7f626869612160ff", "hi!"],
		[
			"a definite map inside an indefinite one",
			"bf62c2a1a10102ff",
			new Map<string, unknown>([["¡", new Map([[1, 2]])]]),
		],
	])("decodes %s", (_, input, value) => {
		expect(decode(input)).toEqual(value);
	});

	it.each([
		["a break on its own", "ff", /break outside an indefinite-length item/],
		[
			"a break inside a definite array",
			"8201ff",
			/break outside an indefinite-length item/,
		],
		[
			"a break where a map's value belongs",
			"bf01ff",
			/break outside an indefinite-length item/,
		],
		["an array with no break", "9f0102", /ends early/],
		["a map with no break", "bf0102", /ends early/],
		["a byte string with a text chunk", "5f6161ff", /chunk of another type/],
		["a text string with a byte chunk", "7f4161ff", /chunk of another type/],
		[
			"a byte string with an indefinite chunk",
			"5f5fffff",
			/chunk of another type/,
		],
		[
			"a text chunk that splits a character",
			"7f61c261a1ff",
			/not valid for encoding utf-8/,
		],
		[
			"an indefinite unsigned integer",
			"1f",
			/additional information 31 on major type 0/,
		],
		[
			"an indefinite negative integer",
			"3f",
			/additional information 31 on major type 1/,
		],
		["an indefinite tag", "df01", /additional information 31 on major type 6/],
		["a repeated key", "bf01020103ff", /repeats key 1/],
		["a byte string as a key", "bf410101ff", /neither integer nor text/],
		["bytes after the break", "9fff00", /bytes follow/],
	])("refuses %s", (_, input, reason) => {
		expect(() => decode(input)).toThrow(reason);
	});

	it("counts toward the nesting limit", () => {
		expect(() =>
			decode(`${"9f".repeat(16)}01${"ff".repeat(16)}`),
		).not.toThrow();
		expect(() => decode(`${"9f".repeat(17)}01${"ff".repeat(17)}`)).toThrow(
			/nests too deep/,
		);
	});
});
