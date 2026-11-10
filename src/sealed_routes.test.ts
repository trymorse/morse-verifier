import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import {
	droppedHeader,
	plainRoute,
	SEALED_PATTERNS,
	sealsRoute,
} from "./sealed_routes.ts";

it("seals exactly the routes the backend's worker serves sealed", () => {
	const vectors = JSON.parse(
		readFileSync(
			new URL("./testdata/seal_vectors.json", import.meta.url),
			"utf8",
		),
	) as { sealable_patterns: string[] };
	expect([...SEALED_PATTERNS].sort()).toEqual(
		[...vectors.sealable_patterns].sort(),
	);
});

it.each([
	["GET", "/v1/models"],
	["GET", "/v1/attestation?model=m"],
	["GET", "/v1/receipts/rcpt-1"],
	["GET", "/v1/videos/job_1"],
])("leaves %s %s, which carries no content, to the relay", (method, path) => {
	expect([plainRoute(method, path), sealsRoute(method, path)]).toEqual([
		true,
		false,
	]);
});

it.each([
	["POST", "/v1/embeddings"],
	["POST", "/v1/models"],
	["GET", "/v1/receipts"],
	["GET", "/v1/videos/job_1/content/more"],
	["POST", "/v1/chat/completions/"],
])("names %s %s neither sealed nor plain", (method, path) => {
	expect([plainRoute(method, path), sealsRoute(method, path)]).toEqual([
		false,
		false,
	]);
});

it.each([
	["authorization", true],
	["x-stainless-retry-count", true],
	["openai-organization", true],
	["x-stainless", false],
	["accept-encoding", false],
	["x-debug", false],
	["content-type", false],
])("drops the header %s before sealing: %s", (name, dropped) => {
	expect(droppedHeader(name)).toBe(dropped);
});
