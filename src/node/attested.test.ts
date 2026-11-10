import { readFileSync } from "node:fs";
import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import { dec, hex, toBase64 } from "../bytes.ts";
import type { Pcrs } from "../pins.ts";
import { keyIdOf } from "../seal.ts";
import { type DocumentOptions, forgeNitro } from "../testing/forge.ts";
import { enclaveKey, type Opened } from "../testing/opener.ts";
import { type RelayOptions, startRelay } from "../testing/relay.ts";
import {
	fake,
	LIVE,
	LOG,
	NOW,
	STATEMENT,
	type World,
} from "../testing/world.ts";
import { attested, sealedFetch, VerifyError } from "./attested.ts";
import type { Exec } from "./io.ts";
import { parseLog, samePcrs } from "./source.ts";

const MINUTE = 60_000;
/** The headers the OpenAI SDK sends with each request, from openai 7.53's client.mjs. */
const SDK = {
	Authorization: "Bearer sk_test",
	Accept: "application/json",
	"User-Agent": "OpenAI/JS 7.53.0",
	"X-Stainless-Lang": "js",
	"X-Stainless-Package-Version": "7.53.0",
	"X-Stainless-OS": "Linux",
	"X-Stainless-Arch": "x64",
	"X-Stainless-Runtime": "node",
	"X-Stainless-Runtime-Version": "v24.11.0",
	"X-Stainless-Retry-Count": "0",
	"X-Stainless-Timeout": "600",
	"OpenAI-Organization": "org-test",
};
const CHAT = '{"model":"m","messages":[{"role":"user","content":"hi"}]}';
const chat = {
	method: "POST",
	headers: { ...SDK, "Content-Type": "application/json" },
	body: CHAT,
};
const UNLISTED: Pcrs = {
	pcr0: "ab".repeat(48),
	pcr1: "ab".repeat(48),
	pcr2: "ab".repeat(48),
};
/** An image on list 290 that no commit on main names. */
const UNPUBLISHED = (
	JSON.parse(STATEMENT.toString()) as {
		images: (Pcrs & { revoked: boolean })[];
	}
).images.find(
	(i) => !i.revoked && !parseLog(LOG).some((r) => samePcrs(r.pcrs, i)),
) as Pcrs;

let forge: Awaited<ReturnType<typeof forgeNitro>>;
beforeAll(async () => {
	forge = await forgeNitro(new Date(NOW));
});
let clock = NOW;
const relays: { close: () => Promise<void> }[] = [];
beforeEach(() => {
	clock = NOW;
});
afterEach(async () => {
	await Promise.all(relays.splice(0).map((r) => r.close()));
});

/** An enclave on the live image: its key, and a document of it, signed a minute ago by default. */
function enclave() {
	const key = enclaveKey();
	return {
		...key,
		document: async (o: Partial<DocumentOptions> = {}) =>
			toBase64(
				await forge.document({
					timestamp: clock - MINUTE,
					publicKey: key.publicKey,
					environment: "prod",
					pcrs: LIVE,
					...o,
				}),
			),
		keyId: async () => hex(await keyIdOf(key.publicKey)),
	};
}
type Enclave = ReturnType<typeof enclave>;

/** attested() for a relay whose enclaves are `live`, listing their documents, with GitHub as the
 * captures of 2026-11-06 have it, and git as `exec` wraps the fake of it. `github` hears each URL
 * fetched from GitHub. `sent` is what attested() asked fetch to send to the relay. `origin` is the
 * one attested() is for, which reaches the relay; default the relay's own. */
async function setup(
	o: Partial<RelayOptions> & {
		live?: Enclave[];
		world?: World;
		exec?: (faked: Exec) => Exec;
		github?: (url: string) => void;
		origin?: string;
	} = {},
) {
	const live = o.live ?? [enclave()];
	const relay = await startRelay({
		enclaves: () => live,
		listed: () => Promise.all(live.map((e) => e.document())),
		...o,
	});
	relays.push(relay);
	const world = fake(o.world);
	const sent: { url: string; headers: Headers; dispatcher?: unknown }[] = [];
	const origin = o.origin ?? relay.origin;
	const send = sealedFetch(origin, {
		fetch: async (input, init) => {
			const url = String(input).replace(origin, relay.origin);
			if (!url.startsWith(relay.origin)) {
				o.github?.(url);
				return world.options.fetch(input, init);
			}
			const { dispatcher, ...rest } = (init ?? {}) as RequestInit & {
				dispatcher?: unknown;
			};
			sent.push({ url, headers: new Headers(init?.headers), dispatcher });
			return fetch(url, rest);
		},
		exec: o.exec?.(world.options.exec) ?? world.options.exec,
		now: () => clock,
		root: forge.root,
	});
	const routes = () => relay.calls.map((c) => `${c.method} ${c.path}`);
	const sealed = () => relay.calls.filter((c) => c.path === "/v1/sealed");
	const listings = () =>
		routes().filter((r) => r === "GET /v1/attestation").length;
	return {
		at: relay.origin,
		send,
		relay,
		world,
		sent,
		routes,
		sealed,
		listings,
		live,
	};
}

function deferred() {
	let resolve = () => {};
	const promise = new Promise<void>((r) => {
		resolve = r;
	});
	return { promise, resolve };
}

const failure = (p: Promise<unknown>) =>
	p.then(
		() => {
			throw new Error("expected it to throw");
		},
		(e: Error) => e,
	);

describe("a sealed call", () => {
	it("seals the path, query, body, and content type to the verified key, and hands fetch only the API key and the sealed content type", async () => {
		const s = await setup();
		const res = await s.send(`${s.at}/v1/chat/completions?trace=1`, chat);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true });
		expect(res.headers.get("x-request-id")).toBe("req_relay");
		expect(s.routes()).toEqual(["GET /v1/attestation", "POST /v1/sealed"]);
		const [call] = s.sealed();
		expect(call.keyIds).toEqual([await s.live[0].keyId()]);
		expect(call.opened?.head).toEqual({
			method: "POST",
			path: "/v1/chat/completions?trace=1",
			headers: { "Content-Type": "application/json" },
			ts: NOW / 1000,
			body_len: CHAT.length,
		});
		expect(dec.decode(call.opened?.body)).toBe(CHAT);
		expect(Object.fromEntries(s.sent.at(-1)?.headers ?? [])).toEqual({
			authorization: "Bearer sk_test",
			"content-type": "application/morse-sealed",
		});
		expect(
			Object.keys(call.headers).filter((h) => /^(x-stainless|openai-)/.test(h)),
		).toEqual([]);
		expect(call.headers["user-agent"]).not.toMatch(/OpenAI/);
	});

	it("streams an SSE reply as each frame opens", async () => {
		let release = () => {};
		const held = new Promise<void>((resolve) => {
			release = resolve;
		});
		const s = await setup({
			answer: () => ({
				status: 200,
				headers: { "Content-Type": ["text/event-stream"] },
				chunks: (async function* () {
					yield 'data: {"delta":"Hel"}\n\n';
					await held;
					yield 'data: {"delta":"lo"}\n\n';
					yield "data: [DONE]\n\n";
				})(),
			}),
		});
		const res = await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(res.headers.get("content-type")).toBe("text/event-stream");
		const reader = (res.body as ReadableStream<Uint8Array>).getReader();
		expect(dec.decode((await reader.read()).value)).toBe(
			'data: {"delta":"Hel"}\n\n',
		);
		release();
		let rest = "";
		for (let r = await reader.read(); !r.done; r = await reader.read())
			rest += dec.decode(r.value);
		expect(rest).toBe('data: {"delta":"lo"}\n\ndata: [DONE]\n\n');
	});

	it("errors a reply that ends before its final frame", async () => {
		const s = await setup({
			answer: () => ({
				status: 200,
				headers: { "Content-Type": ["text/event-stream"] },
				chunks: ['data: {"delta":"Hel"}\n\n'],
				truncated: true,
			}),
		});
		const res = await s.send(`${s.at}/v1/chat/completions`, chat);
		await expect(res.text()).rejects.toThrow(
			"the reply ends before its final frame",
		);
	});

	it("gives a 204 from the enclave no body, once its reply has ended in its final frame", async () => {
		let truncated = false;
		const s = await setup({ answer: () => ({ status: 204, truncated }) });
		const res = await s.send(`${s.at}/v1/chat/completions`, chat);
		expect([res.status, res.body]).toEqual([204, null]);
		truncated = true;
		expect(
			(await failure(s.send(`${s.at}/v1/chat/completions`, chat))).message,
		).toBe(
			"the enclave's sealed reply to POST /v1/chat/completions doesn't open: the reply ends before its final frame",
		);
	});

	it("drops the Content-Length openai 4 sets, which the sealed request sets for itself", async () => {
		const s = await setup();
		const res = await s.send(`${s.at}/v1/chat/completions`, {
			...chat,
			headers: {
				...chat.headers,
				"User-Agent": "OpenAI/JS 4.104.0",
				"Content-Length": String(CHAT.length),
			},
		});
		expect(res.status).toBe(200);
		expect(s.sealed()[0].opened?.head.headers).toEqual({
			"Content-Type": "application/json",
		});
		expect(s.sealed()[0].headers["content-length"]).toBe(
			String(s.sealed()[0].body.length),
		);
	});

	it("seals a FormData upload with its multipart boundary", async () => {
		const s = await setup();
		const form = new FormData();
		form.append("model", "whisper-1");
		form.append(
			"file",
			new Blob(["RIFF audio"], { type: "audio/wav" }),
			"a.wav",
		);
		const res = await s.send(`${s.at}/v1/audio/transcriptions`, {
			method: "POST",
			headers: SDK,
			body: form,
		});
		expect(res.status).toBe(200);
		const opened = s.sealed()[0].opened as Opened;
		const type = opened.head.headers["Content-Type"];
		expect(type).toMatch(/^multipart\/form-data; boundary=/);
		const read = await new Response(opened.body, {
			headers: { "content-type": type },
		}).formData();
		expect(read.get("model")).toBe("whisper-1");
		expect(await (read.get("file") as File).text()).toBe("RIFF audio");
	});

	it("throws on a redirect of the sealed request, and doesn't follow it", async () => {
		const s = await setup({
			plain: (call) =>
				call.path === "/v1/sealed"
					? { status: 307, headers: { location: "/v1/elsewhere" } }
					: undefined,
		});
		expect(
			(await failure(s.send(`${s.at}/v1/chat/completions`, chat))).message,
		).toBe(
			`${s.at} answered POST /v1/chat/completions with a redirect (307), which attested() doesn't follow`,
		);
		expect(s.routes()).toEqual(["GET /v1/attestation", "POST /v1/sealed"]);
	});

	it("passes the relay's refusal in the clear on as it is, and refuses a clear success", async () => {
		let plain = {
			status: 402,
			body: '{"error":{"code":"insufficient_balance"}}',
		};
		const s = await setup({
			plain: (call) =>
				call.path === "/v1/sealed"
					? { ...plain, headers: { "content-type": "application/json" } }
					: undefined,
		});
		const refused = await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(refused.status).toBe(402);
		expect(await refused.text()).toBe(plain.body);
		plain = { status: 200, body: '{"choices":[]}' };
		expect(
			(await failure(s.send(`${s.at}/v1/chat/completions`, chat))).message,
		).toBe(
			`${s.at} answered POST /v1/chat/completions 200 without sealing the reply, which only the enclave can do, so attested() refuses it`,
		);
	});
});

describe("what attested() won't send", () => {
	it("passes the relay's plain GETs through with only the API key and Accept, and fetches no keys for them", async () => {
		const s = await setup();
		const res = await s.send(`${s.at}/v1/models`, { headers: SDK });
		expect(res.status).toBe(401);
		expect(await res.json()).toEqual({
			error: {
				message: "Incorrect API key provided.",
				type: "invalid_request_error",
				param: null,
				code: "invalid_api_key",
			},
		});
		expect(s.routes()).toEqual(["GET /v1/models"]);
		expect(Object.fromEntries(s.sent[0].headers)).toEqual({
			authorization: "Bearer sk_test",
			accept: "application/json",
		});
	});

	it("sends the request through the dispatcher it was given, such as a proxy's", async () => {
		const s = await setup();
		const proxy = { through: "a proxy" };
		await s.send(`${s.at}/v1/models`, {
			headers: SDK,
			dispatcher: proxy,
		} as RequestInit);
		await s.send(`${s.at}/v1/chat/completions`, {
			...chat,
			dispatcher: proxy,
		} as RequestInit);
		expect(s.sent.map((c) => [new URL(c.url).pathname, c.dispatcher])).toEqual([
			["/v1/models", proxy],
			["/v1/attestation", undefined],
			["/v1/sealed", proxy],
		]);
	});

	it("throws for a route the enclave can't seal, another origin, a header it doesn't know, or a redirect", async () => {
		const s = await setup({
			plain: (call) =>
				call.path === "/v1/receipts/r1"
					? { status: 302, headers: { location: "https://elsewhere.example/" } }
					: undefined,
		});
		const thrown = async (url: string, init: RequestInit) =>
			(await failure(s.send(url, init))).message;
		expect(
			await thrown(`${s.at}/v1/embeddings`, {
				...chat,
				body: '{"input":"hi"}',
			}),
		).toBe(
			"attested() won't send POST /v1/embeddings: the enclave can't seal it, so it would go out readable. Nothing was sent.",
		);
		expect(
			await thrown("https://api.openai.com/v1/chat/completions", chat),
		).toBe(
			`attested() sends only to ${s.at}, and this request is to https://api.openai.com, where your API key would go. Nothing was sent.`,
		);
		expect(
			await thrown(`${s.at}/v1/chat/completions`, {
				...chat,
				headers: { ...chat.headers, "X-Debug": "1" },
			}),
		).toMatch(/^attested\(\) won't send the header x-debug: /);
		expect(s.routes()).toEqual([]);
		expect(s.world.fetched).toEqual([]);
		expect(await thrown(`${s.at}/v1/receipts/r1`, { headers: SDK })).toMatch(
			/answered GET \/v1\/receipts\/r1 with a redirect \(302\)/,
		);
	});

	it("throws for a request whose sealed head is over the enclave's 8 KiB", async () => {
		const s = await setup();
		expect(
			(
				await failure(
					s.send(`${s.at}/v1/lookup/svc/x?q=${"a".repeat(9000)}`, {
						headers: SDK,
					}),
				)
			).message,
		).toBe(
			"attested() won't send GET /v1/lookup/svc/x: the sealed head is 9087 bytes, over the proxy's 8192, so the enclave would refuse it as request_too_large. The head holds its method, path, query, and content headers. Nothing was sent.",
		);
		expect(s.sealed()).toEqual([]);
	});

	it("only goes to an HTTPS origin, and shares one fetch per origin", () => {
		expect(() => attested({ origin: "http://api.trymorse.ai" })).toThrow(
			/^attested\(\) sends only over HTTPS/,
		);
		expect(attested()).toBe(attested({ origin: "https://api.trymorse.ai/" }));
		expect(attested()).not.toBe(
			attested({ origin: "https://inference.trymorse.ai" }),
		);
	});

	it("sends plain, seals, or refuses each URL of request_urls.json as the table says", async () => {
		const table = JSON.parse(
			readFileSync(
				new URL("../testdata/request_urls.json", import.meta.url),
				"utf8",
			),
		) as {
			origin: string;
			cases: { method: string; url: string; sends: string; path?: string }[];
		};
		const s = await setup({ origin: table.origin });
		const got = [];
		for (const { method, url } of table.cases) {
			const before = s.relay.calls.length;
			const sends = await s
				.send(url, {
					method,
					headers: chat.headers,
					...(method === "GET" ? {} : { body: "{}" }),
				})
				.then(
					() => "sent",
					() => "refused",
				);
			const [call] = s.relay.calls
				.slice(before)
				.filter((c) => c.path !== "/v1/attestation");
			got.push({
				method,
				url,
				...(sends === "refused"
					? { sends, sent: call }
					: call.path === "/v1/sealed"
						? { sends: "sealed", path: call.opened?.head.path }
						: { sends: "plain", path: call.path }),
			});
		}
		expect(got).toEqual(
			table.cases.map(({ method, url, sends, path }) =>
				sends === "refused"
					? { method, url, sends, sent: undefined }
					: { method, url, sends, path },
			),
		);
	});
});

describe("the keys it seals to", () => {
	it("are only those every document of which passed Attestation, Allowed, and Source", async () => {
		const [good, alsoUnlisted, alsoStale, forged, unpublished] = [
			enclave(),
			enclave(),
			enclave(),
			enclave(),
			enclave(),
		];
		const s = await setup({
			live: [good, alsoUnlisted, alsoStale, forged, unpublished],
			listed: async () => [
				await good.document(),
				await alsoUnlisted.document(),
				await alsoUnlisted.document({ pcrs: UNLISTED }),
				await alsoStale.document(),
				await alsoStale.document({ timestamp: clock - 31 * MINUTE }),
				await forged.document({ signWith: "stranger" }),
				await unpublished.document({ pcrs: UNPUBLISHED }),
			],
		});
		expect((await s.send(`${s.at}/v1/chat/completions`, chat)).status).toBe(
			200,
		);
		expect(s.sealed().map((c) => c.keyIds)).toEqual([[await good.keyId()]]);
	});

	it("are the newest four, newest first, since a seal names at most four", async () => {
		const five = [enclave(), enclave(), enclave(), enclave(), enclave()];
		const s = await setup({
			live: five,
			listed: () =>
				Promise.all(
					five
						.map((e, i) => e.document({ timestamp: clock - (i + 1) * MINUTE }))
						.reverse(),
				),
		});
		await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(s.sealed()[0].keyIds).toEqual(
			await Promise.all(five.slice(0, 4).map((e) => e.keyId())),
		);
	});

	it("are fetched again once the oldest of their documents is 30 minutes old, though a newer one isn't", async () => {
		const [old, young] = [enclave(), enclave()];
		const s = await setup({
			live: [old, young],
			listed: async () => [
				await old.document({ timestamp: clock - 29 * MINUTE }),
				await young.document(),
			],
		});
		await s.send(`${s.at}/v1/chat/completions`, chat);
		clock += MINUTE;
		await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(s.listings()).toBe(1);
		clock += 1;
		await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(s.listings()).toBe(2);
	});

	it("that turn 30 minutes old while they're checked get one more fetch, and are never sealed to", async () => {
		const slow = enclave();
		const s = await setup({
			live: [slow],
			listed: async () => [
				await slow.document({ timestamp: clock - 29 * MINUTE }),
			],
			github: (url) => {
				if (url.endsWith("prod.statement.json")) clock += 2 * MINUTE;
			},
		});
		const e = await failure(s.send(`${s.at}/v1/chat/completions`, chat));
		expect(e).toMatchObject({ step: "Attestation", retryable: true });
		expect(e.message).toBe(
			"Attestation could not finish: the oldest document that passed was over 30 minutes old by the time its checks finished. Nothing was sent.",
		);
		expect(s.listings()).toBe(2);
		expect(s.sealed()).toEqual([]);
	});

	// Only verifyKeys makes keys, so to show the check right before a seal holds, the test stops
	// WeakSet from recording the keys it verified.
	it("are each checked right before the seal as ones attested() verified", async () => {
		const add = WeakSet.prototype.add;
		const forget = vi
			.spyOn(WeakSet.prototype, "add")
			.mockImplementation(function (this: WeakSet<WeakKey>, value: WeakKey) {
				return "keyId" in value ? this : add.call(this, value);
			});
		try {
			const s = await setup();
			expect(
				(await failure(s.send(`${s.at}/v1/chat/completions`, chat))).message,
			).toBe(
				"attested() was about to seal to a key it hadn't verified. Nothing was sent.",
			);
			expect(s.sealed()).toEqual([]);
		} finally {
			forget.mockRestore();
		}
	});

	it("throw a VerifyError naming the check that refused when none passes, sending nothing", async () => {
		const unlisted = enclave();
		const s = await setup({
			live: [unlisted],
			listed: async () => [await unlisted.document({ pcrs: UNLISTED })],
		});
		const e = await failure(s.send(`${s.at}/v1/chat/completions`, chat));
		expect(e).toBeInstanceOf(VerifyError);
		expect(e).toMatchObject({ step: "Allowed", retryable: false });
		expect(e.message).toBe(
			"Allowed failed: enclave i-0123-enc0123 runs PCR0 abababababab…abababab, which is not on Morse's signed list. Nothing was sent.",
		);
		expect(s.routes()).toEqual(["GET /v1/attestation"]);
	});

	it("can't be checked without git, and the error says so", async () => {
		const s = await setup({ world: { git: "missing" } });
		const e = await failure(s.send(`${s.at}/v1/chat/completions`, chat));
		expect(e).toMatchObject({ step: "Source", retryable: true });
		expect(e.message).toBe(
			"Source could not finish: the Source check runs git, which isn't on this machine's PATH. Install git (https://git-scm.com) and run again. Nothing was sent.",
		);
		expect(s.sealed()).toEqual([]);
	});

	it("can't be checked without a temporary directory to clone into, which a later call may have", async () => {
		vi.stubEnv("TMPDIR", "/proc/nope");
		try {
			const s = await setup();
			const e = await failure(s.send(`${s.at}/v1/chat/completions`, chat));
			expect(e).toMatchObject({ step: "Source", retryable: true });
			expect(e.message).toBe(
				"Source could not finish: it can't make a temporary directory in /proc/nope (ENOENT). Set TMPDIR to a directory it can write, and run again. Nothing was sent.",
			);
			expect(s.sealed()).toEqual([]);
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("are waited for until the caller aborts, while their check runs on for the next call", async () => {
		const [cloning, cloned] = [deferred(), deferred()];
		const s = await setup({
			exec: (faked) => async (command, args, options) => {
				if (args[0] === "clone") {
					cloning.resolve();
					await cloned.promise;
				}
				return faked(command, args, options);
			},
		});
		const caller = new AbortController();
		const aborted = failure(
			s.send(`${s.at}/v1/chat/completions`, { ...chat, signal: caller.signal }),
		);
		await cloning.promise;
		const next = s.send(`${s.at}/v1/chat/completions`, chat);
		caller.abort();
		expect((await aborted).name).toBe("AbortError");
		cloned.resolve();
		expect((await next).status).toBe(200);
		expect(s.world.ran.filter((c) => c[1] === "clone")).toHaveLength(1);
		expect(s.sealed()).toHaveLength(1);
		const before = s.routes().length;
		expect(
			(
				await failure(
					s.send(`${s.at}/v1/chat/completions`, {
						...chat,
						signal: AbortSignal.abort(),
					}),
				)
			).name,
		).toBe("AbortError");
		expect(s.routes()).toHaveLength(before);
	});

	it("aren't fetched for a call already aborted, which leaves no rejection unheard", async () => {
		const s = await setup({ world: { git: "missing" } });
		const unheard: unknown[] = [];
		const hear = (e: unknown) => unheard.push(e);
		process.on("unhandledRejection", hear);
		try {
			const e = await failure(
				s.send(`${s.at}/v1/chat/completions`, {
					...chat,
					signal: AbortSignal.abort(),
				}),
			);
			expect(e.name).toBe("AbortError");
			await new Promise((r) => setTimeout(r, 50));
			expect([s.routes(), unheard]).toEqual([[], []]);
		} finally {
			process.off("unhandledRejection", hear);
		}
	});

	it("are fetched once for concurrent calls, and again, with the signed list, once the oldest is 30 minutes old", async () => {
		const s = await setup();
		const statements = () =>
			s.world.fetched.filter((u) => u.endsWith("prod.statement.json")).length;
		const clones = () => s.world.ran.filter((c) => c[1] === "clone").length;
		await Promise.all([
			s.send(`${s.at}/v1/chat/completions`, chat),
			s.send(`${s.at}/v1/chat/completions`, chat),
		]);
		expect([
			s.routes().filter((r) => r === "GET /v1/attestation").length,
			statements(),
			clones(),
		]).toEqual([1, 1, 1]);
		clock += 29 * MINUTE;
		await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(statements()).toBe(1);
		clock += MINUTE + 1;
		await s.send(`${s.at}/v1/chat/completions`, chat);
		expect([
			s.routes().filter((r) => r === "GET /v1/attestation").length,
			statements(),
			clones(),
		]).toEqual([2, 2, 1]);
	});
});

// fetch itself sends a request a 421 refused once more, on a new connection (the Fetch standard's
// HTTP-network-or-cache fetch), which a load balancer may give to an enclave that has the key. So
// each 421 here is two POSTs of the same seal.
describe("a 421 sealed_key_unknown", () => {
	it("is retried once, sealed to the keys its documents list once they pass, which are kept", async () => {
		const [gone, fresh] = [enclave(), enclave()];
		const s = await setup({
			live: [fresh],
			listed: async () => [await gone.document()],
			listedOn421: async () => [await fresh.document()],
		});
		expect((await s.send(`${s.at}/v1/chat/completions`, chat)).status).toBe(
			200,
		);
		await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(s.sealed().map((c) => [c.keyIds, Boolean(c.opened)])).toEqual([
			[[await gone.keyId()], false],
			[[await gone.keyId()], false],
			[[await fresh.keyId()], true],
			[[await fresh.keyId()], true],
		]);
		expect(s.routes().filter((r) => r === "GET /v1/attestation")).toHaveLength(
			1,
		);
	});

	// A deploy: the relay's listing still names the enclave that stopped, which another call's
	// fetch, under way when the 421 came, verified. Its keys must not replace the 421's, and that
	// call seals to the 421's.
	it("replaces the keys for good, though a fetch under way meanwhile lists the old ones", async () => {
		const [gone, fresh] = [enclave(), enclave()];
		const live = [fresh];
		const [at421, answer421, atGet, answerGet] = [
			deferred(),
			deferred(),
			deferred(),
			deferred(),
		];
		let gets = 0;
		const s = await setup({
			live,
			listed: async () => {
				if (++gets === 2) {
					atGet.resolve();
					await answerGet.promise;
				}
				return [await gone.document()];
			},
			listedOn421: async () => {
				at421.resolve();
				await answer421.promise;
				return [await fresh.document()];
			},
		});
		const refused = s.send(`${s.at}/v1/chat/completions`, chat);
		await at421.promise;
		clock += 30 * MINUTE;
		const fetching = s.send(`${s.at}/v1/chat/completions`, chat);
		await atGet.promise;
		answer421.resolve();
		expect((await refused).status).toBe(200);
		const before = s.sealed().length;
		answerGet.resolve();
		expect((await fetching).status).toBe(200);
		await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(
			s
				.sealed()
				.slice(before)
				.map((c) => c.keyIds),
		).toEqual([[await fresh.keyId()], [await fresh.keyId()]]);
	});

	it("is passed on when the retry gets one too, and throws when its documents fail", async () => {
		const [gone, alsoGone] = [enclave(), enclave()];
		const s = await setup({
			live: [],
			listed: async () => [await gone.document()],
			listedOn421: async () => [await alsoGone.document()],
		});
		expect((await s.send(`${s.at}/v1/chat/completions`, chat)).status).toBe(
			421,
		);
		expect(s.sealed().map((c) => c.keyIds)).toEqual([
			[await gone.keyId()],
			[await gone.keyId()],
			[await alsoGone.keyId()],
			[await alsoGone.keyId()],
		]);

		const t = await setup({
			live: [],
			listed: async () => [await gone.document()],
			listedOn421: async () => [await alsoGone.document({ pcrs: UNLISTED })],
		});
		const e = await failure(t.send(`${t.at}/v1/chat/completions`, chat));
		expect(e).toMatchObject({ step: "Allowed" });
		expect(e.message).toBe(
			"Allowed failed: enclave i-0123-enc0123 runs PCR0 abababababab…abababab, which is not on Morse's signed list. Nothing was sent but the first try, which was sealed to keys that had passed.",
		);
		expect(t.sealed()).toHaveLength(2);
	});
});

describe("a sealed sealed_stale", () => {
	const enclaveSeconds = NOW / 1000 + 600;
	const staleUnlessNear = (ts: number) => (opened: Opened) =>
		Math.abs(opened.head.ts - ts) <= 120
			? {
					status: 200,
					headers: { "Content-Type": ["application/json"] },
					chunks: ["{}"],
				}
			: {
					status: 400,
					headers: { "Content-Type": ["application/json"] },
					chunks: [
						JSON.stringify({
							error: { code: "sealed_stale", message: "stale" },
							proxy_time: enclaveSeconds,
						}),
					],
				};

	it("sets the clock ts is sealed with to the enclave's, and seals once more", async () => {
		const s = await setup({ answer: staleUnlessNear(enclaveSeconds) });
		expect((await s.send(`${s.at}/v1/chat/completions`, chat)).status).toBe(
			200,
		);
		await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(s.sealed().map((c) => c.opened?.head.ts)).toEqual([
			NOW / 1000,
			enclaveSeconds,
			enclaveSeconds,
		]);
	});

	it("never moves the clock documents are judged by", async () => {
		const enclaveSecondsNow = () => (clock + 40 * MINUTE) / 1000;
		const s = await setup({
			answer: (opened) =>
				Math.abs(opened.head.ts - enclaveSecondsNow()) <= 120
					? { status: 200, chunks: ["{}"] }
					: {
							status: 400,
							headers: { "Content-Type": ["application/json"] },
							chunks: [
								JSON.stringify({
									error: { code: "sealed_stale", message: "stale" },
									proxy_time: enclaveSecondsNow(),
								}),
							],
						},
		});
		expect((await s.send(`${s.at}/v1/chat/completions`, chat)).status).toBe(
			200,
		);
		clock += 30 * MINUTE;
		expect((await s.send(`${s.at}/v1/chat/completions`, chat)).status).toBe(
			200,
		);
		expect(s.listings()).toBe(2);
		expect(s.sealed()).toHaveLength(3);
	});

	it("is retried only once", async () => {
		const s = await setup({ answer: staleUnlessNear(0) });
		const res = await s.send(`${s.at}/v1/chat/completions`, chat);
		expect(res.status).toBe(400);
		expect(await res.json()).toMatchObject({ error: { code: "sealed_stale" } });
		expect(s.sealed()).toHaveLength(2);
	});
});
