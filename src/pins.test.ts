import { describe, expect, it } from "vitest";
import { parseEnclavePins } from "./pins.ts";
import { pinOf } from "./testing/forge.ts";

const pin = pinOf();

describe("the list the app ships and publishes", () => {
	it("is read strictly", () => {
		expect(() =>
			parseEnclavePins([{ ...pin, signed_by: "someone" }]),
		).toThrow();
		expect(() => parseEnclavePins([pin, { revoked: true }])).toThrow();
	});
});
