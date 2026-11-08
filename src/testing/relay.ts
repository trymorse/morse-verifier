// A stand-in for Morse's relay and the enclaves behind it, over real HTTP on 127.0.0.1, for
// attested()'s tests. GET /v1/attestation lists documents; POST /v1/sealed opens a seal with one
// enclave's key and seals that enclave's answer, or answers 421; anything else gets prod's refusal
// of a bad key, in the clear. It records each request as it arrived.
import {
	createServer,
	type IncomingHttpHeaders,
	type IncomingMessage,
	type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { type Bytes, enc } from "../bytes.ts";
import {
	type enclaveKey,
	keyIdsOf,
	type Opened,
	replySealer,
} from "./opener.ts";

/** What an enclave answers to a request it opened. */
interface Answer {
	readonly status: number;
	readonly headers?: Record<string, string[]>;
	/** The body, a frame each, sent as each is ready. */
	readonly chunks?: Iterable<string> | AsyncIterable<string>;
	/** Ends the reply before its final frame. */
	readonly truncated?: boolean;
}

/** An answer in the clear. */
interface Plain {
	readonly status: number;
	readonly headers?: Record<string, string>;
	readonly body?: string;
}

interface Call {
	readonly method: string;
	readonly path: string;
	readonly headers: IncomingHttpHeaders;
	readonly body: Bytes;
	/** A sealed request's key ids, hex, and what an enclave opened, if one could. */
	keyIds?: string[];
	opened?: Opened;
}

export interface RelayOptions {
	/** The enclaves whose keys open seals now. */
	readonly enclaves: () => readonly ReturnType<typeof enclaveKey>[];
	/** The base64 documents GET /v1/attestation lists. */
	readonly listed: () => Promise<string[]>;
	/** The documents a 421 lists. Default: what `listed` does. */
	readonly listedOn421?: () => Promise<string[]>;
	/** Default: 200 with {"ok":true}. */
	readonly answer?: (opened: Opened) => Answer;
	/** Answers a request in the clear before anything else does, unless it returns undefined. */
	readonly plain?: (call: Call) => Plain | undefined;
}

const refusal = (code: string, message: string) => ({
	error: { message, type: "invalid_request_error", param: null, code },
});

export async function startRelay(o: RelayOptions) {
	const calls: Call[] = [];
	const serve = async (req: IncomingMessage, res: ServerResponse) => {
		const parts: Buffer[] = [];
		for await (const part of req) parts.push(part as Buffer);
		const call: Call = {
			method: req.method ?? "",
			path: req.url ?? "",
			headers: req.headers,
			body: new Uint8Array(Buffer.concat(parts)) as Bytes,
		};
		calls.push(call);
		const json = (status: number, value: unknown) => {
			res.writeHead(status, { "content-type": "application/json" });
			res.end(JSON.stringify(value));
		};
		const clear = o.plain?.(call);
		if (clear) {
			res.writeHead(clear.status, clear.headers);
			res.end(clear.body);
			return;
		}
		if (call.method === "GET" && call.path === "/v1/attestation")
			return json(200, {
				object: "proxy_attestation",
				environment: "prod",
				instances: await o.listed(),
			});
		if (call.method !== "POST" || call.path !== "/v1/sealed")
			return json(
				401,
				refusal("invalid_api_key", "Incorrect API key provided."),
			);
		call.keyIds = keyIdsOf(call.body);
		for (const enclave of o.enclaves()) {
			call.opened = await enclave.open(call.body);
			if (call.opened) break;
		}
		if (!call.opened)
			return json(421, {
				...refusal("sealed_key_unknown", "No enclave holds these keys."),
				instances: await (o.listedOn421 ?? o.listed)(),
			});
		const answer = o.answer?.(call.opened) ?? {
			status: 200,
			headers: { "Content-Type": ["application/json"] },
			chunks: ['{"ok":true}'],
		};
		const sealer = await replySealer(call.opened.cek);
		const head = { status: answer.status, headers: answer.headers ?? null };
		res.writeHead(200, {
			"content-type": "application/morse-sealed",
			"cache-control": "no-store",
			"x-request-id": "req_relay",
		});
		res.write(sealer.salt);
		res.write(await sealer.frame(enc.encode(JSON.stringify(head)), false));
		for await (const chunk of answer.chunks ?? [])
			res.write(await sealer.frame(enc.encode(chunk), false));
		if (!answer.truncated)
			res.write(await sealer.frame(new Uint8Array(), true));
		res.end();
	};
	const server = createServer((req, res) => {
		serve(req, res).catch(() => res.destroy());
	});
	await new Promise<void>((resolve) =>
		server.listen(0, "127.0.0.1", () => resolve()),
	);
	const { port } = server.address() as AddressInfo;
	return {
		origin: `http://127.0.0.1:${port}`,
		calls,
		close: () =>
			new Promise<void>((resolve) => {
				server.closeAllConnections();
				server.close(() => resolve());
			}),
	};
}
