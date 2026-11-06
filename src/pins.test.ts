import { describe, expect, it } from "vitest";
import { checkPcrs, parseEnclavePins, parseLivePins } from "./pins.ts";
import { pinOf } from "./testing/forge.ts";

const pin = pinOf();
const other = pinOf({ pcr0: "c0".repeat(48) });

describe("the live list a tab reads", () => {
	it("keeps an entry with a field this tab doesn't know", () => {
		const { pins, dropped } = parseLivePins([{ ...pin, signed_by: "someone" }]);
		expect(pins).toEqual([pin]);
		expect(dropped).toBe(0);
	});

	it.each([
		["not an entry", null],
		["no PCRs", { revoked: true }],
		[
			"a PCR it can't read, though it says revoked",
			{ ...pin, pcr0: "zz", revoked: true },
		],
		[
			"no environment, though it says revoked",
			{ ...pin, environment: undefined, revoked: true },
		],
		["revoked: false and a bad date", { ...pin, built_at: "soon" }],
		["revoked: false and no version", { ...pin, version: undefined }],
		[
			"all-zero PCRs",
			pinOf({
				pcr0: "0".repeat(96),
				pcr1: "0".repeat(96),
				pcr2: "0".repeat(96),
			}),
		],
	])("drops only an entry with %s", (_, entry) => {
		const { pins, dropped } = parseLivePins([other, entry]);
		expect(pins).toEqual([other]);
		expect(dropped).toBe(1);
	});

	it.each([
		["true and a bad date", { ...pin, revoked: true, built_at: "soon" }],
		["true and no version", { ...pin, revoked: true, version: undefined }],
		["a string", { ...pin, revoked: "yes" }],
		["the string false", { ...pin, revoked: "false" }],
		["a number", { ...pin, revoked: 0 }],
		["null", { ...pin, revoked: null }],
		["undefined", { ...pin, revoked: undefined }],
		["missing", (({ revoked: _, ...rest }) => rest)(pin)],
	])("refuses an image whose entry names it with revoked %s", (_, entry) => {
		const { pins, dropped } = parseLivePins([entry]);
		expect(dropped).toBe(1);
		expect(() => checkPcrs(pins, pin.environment, pin)).toThrow(/is revoked/);
	});

	it("names no image from a list that isn't a list", () => {
		expect(() => parseLivePins({ pins: [pin] })).toThrow();
	});

	it("leaves the list the app ships and publishes strict", () => {
		expect(() =>
			parseEnclavePins([{ ...pin, signed_by: "someone" }]),
		).toThrow();
		expect(() => parseEnclavePins([pin, { revoked: true }])).toThrow();
	});
});
