import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { concat, hex, unhex } from "../bytes.ts";
import { enclaveKey, replySealer } from "./opener.ts";

const vectors = JSON.parse(
	readFileSync(
		new URL("../testdata/seal_vectors.json", import.meta.url),
		"utf8",
	),
) as {
	recipients: { private_key: string }[];
	requests: {
		name: string;
		recipients: number[];
		cek: string;
		head: Record<string, unknown>;
		body: string;
		sealed: string;
	}[];
	replies: {
		name: string;
		cek: string;
		salt: string;
		frames: { data: string; final: boolean }[];
		reply: string;
	}[];
};

describe.each(vectors.requests)("the request vector $name", (v) => {
	it("opens to its head, body, and CEK with each key it names, and not with another", async () => {
		for (const [i, r] of vectors.recipients.entries()) {
			const opened = await enclaveKey(unhex(r.private_key)).open(
				unhex(v.sealed),
			);
			if (!v.recipients.includes(i)) {
				expect(opened).toBeUndefined();
				continue;
			}
			expect(opened?.head).toEqual(v.head);
			expect(hex(opened?.body ?? new Uint8Array())).toBe(v.body);
			expect(hex(opened?.cek ?? new Uint8Array())).toBe(v.cek);
		}
	});
});

describe.each(vectors.replies)("the reply vector $name", (v) => {
	it("seals byte for byte as the backend does", async () => {
		const sealer = await replySealer(unhex(v.cek), unhex(v.salt));
		const parts = [sealer.salt];
		for (const f of v.frames)
			parts.push(await sealer.frame(unhex(f.data), f.final));
		expect(hex(concat(parts))).toBe(v.reply);
	});
});
