import { readFileSync, writeFileSync } from "node:fs";
import { expect, it } from "vitest";
import { MAX_KEYS, SEALED_CONTENT_TYPE } from "./seal.ts";
import {
	CONTENT_HEADERS,
	DROPPED_HEADERS,
	droppedHeader,
	NULL_BODY_STATUSES,
	PLAIN_PATTERNS,
	plainRoute,
	RELAY_REPLY_HEADERS,
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

// The Python package's routes.py holds these same lists, and its tests compare them with this file,
// which UPDATE_GOLDEN=1 writes.
it("writes the protocol's lists to protocol.json, which the Python package holds itself to", () => {
	const file = new URL("./testdata/protocol.json", import.meta.url);
	const protocol = `${JSON.stringify(
		{
			sealed_content_type: SEALED_CONTENT_TYPE,
			max_keys: MAX_KEYS,
			sealed_patterns: SEALED_PATTERNS,
			plain_patterns: PLAIN_PATTERNS,
			content_headers: [...CONTENT_HEADERS.values()],
			dropped_headers: DROPPED_HEADERS,
			relay_reply_headers: RELAY_REPLY_HEADERS,
			null_body_statuses: [...NULL_BODY_STATUSES],
		},
		null,
		2,
	)}\n`;
	if (process.env.UPDATE_GOLDEN === "1") writeFileSync(file, protocol);
	expect(readFileSync(file, "utf8")).toBe(protocol);
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
