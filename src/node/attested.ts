// attested(): a fetch for the OpenAI SDK that seals each request carrying content to the keys of
// enclaves that passed the checks `npx @askmorse/verify` prints as Attestation, Allowed, and Source,
// and throws rather than send anything the relay could read:
//   new OpenAI({ baseURL: "https://api.trymorse.ai/v1", apiKey, fetch: attested() })
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { type Bytes, hex } from "../bytes.ts";
import { type AttestedDocument, MAX_AGE_MS } from "../nitro.ts";
import { NITRO_ROOT } from "../nitro_root.ts";
import type { Pcrs } from "../pins.ts";
import {
	HeadTooLarge,
	MAX_KEYS,
	openReply,
	SEALED_CONTENT_TYPE,
	type SealKey,
	sealRequest,
} from "../seal.ts";
import {
	attestationReply,
	CONTENT_HEADERS,
	droppedHeader,
	NULL_BODY_STATUSES,
	plainRoute,
	sealedKeyUnknown,
	sealedStale,
	sealsRoute,
	withRelayHeaders,
} from "../sealed_routes.ts";
import type { Cert } from "../x509.ts";
import { type Exec, exec, get, json, tempDir, Unfinished } from "./io.ts";
import {
	fetchSignedList,
	type SignedList,
	verifySignedList,
} from "./signed_list.ts";
import { type Release, readReleases, samePcrs } from "./source.ts";
import { checkDocument, unpublished } from "./verify.ts";

type Fetch = (
	input: string | URL | Request,
	init?: RequestInit,
) => Promise<Response>;

export interface AttestedOptions {
	/** Where Morse's API is, over HTTPS. Default https://api.trymorse.ai. A request to any other
	 * origin throws, so your API key goes nowhere else. */
	readonly origin?: string;
}

type Check = "Attestation" | "Allowed" | "Source";

const NOTHING_SENT = "Nothing was sent.";
/** What a VerifyError says went out when a sealed try did before the check: a 421 or sealed_stale
 * refused it, and the keys for the next try didn't pass. */
const FIRST_TRY_SENT =
	"Nothing was sent but the first try, which was sealed to keys that had passed.";

/** A check refused every enclave, or could not finish, so attested() sent nothing, or nothing
 * past a first try that a 421 or sealed_stale refused. */
export class VerifyError extends Error {
	override name = "VerifyError";
	/** The check, as `npx @askmorse/verify` names it. */
	readonly step: Check;
	/** Why, without the check's name or what was sent. */
	readonly reason: string;
	/** True when the check could not finish (the network, a rate limit, git), so a later call may
	 * pass. False when it refused what it was shown. */
	readonly retryable: boolean;
	constructor(
		step: Check,
		reason: string,
		retryable: boolean,
		sent = NOTHING_SENT,
	) {
		super(
			`${step} ${retryable ? "could not finish" : "failed"}: ${reason}. ${sent}`,
		);
		this.step = step;
		this.reason = reason;
		this.retryable = retryable;
	}
}

/** What attested() reaches the world with. Tests pass their own. */
export interface Reach {
	readonly fetch: Fetch;
	readonly exec: Exec;
	readonly now: () => number;
	readonly root: Cert;
}

interface Keys {
	readonly keys: readonly SealKey[];
	readonly expiresAt: number;
}

/** Runs `run` as check `step`, so whatever stops it is a VerifyError naming that check. */
async function during<T>(step: Check, run: () => Promise<T>): Promise<T> {
	try {
		return await run();
	} catch (e) {
		if (e instanceof VerifyError) throw e;
		throw new VerifyError(
			step,
			e instanceof Error ? e.message : String(e),
			e instanceof Unfinished,
		);
	}
}

/** `work`'s result, unless `signal` aborts first, which rejects with its reason. `work` runs on
 * either way, for the other calls that share it. */
function unlessAborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
	return new Promise((resolve, reject) => {
		const abort = () => reject(signal.reason);
		if (signal.aborted) abort();
		else signal.addEventListener("abort", abort, { once: true });
		work
			.then(resolve, reject)
			.finally(() => signal.removeEventListener("abort", abort));
	});
}

/** Step 3 by an image's PCRs: the newest release on main that names them. A release found is kept;
 * PCRs none names read main again, at most once a minute. */
function sources(run: Exec, now: () => number) {
	const found = new Map<string, Release>();
	let releases: Promise<readonly Release[]> | undefined;
	let readAt = 0;
	const readMain = async () => {
		const dir = await tempDir("trymorse-attested-");
		try {
			return await readReleases(run, join(dir, "enclave.git"));
		} finally {
			await rm(dir, { recursive: true, force: true }).catch(() => {});
		}
	};
	return async (pcrs: Pcrs): Promise<Release | undefined> => {
		const id = `${pcrs.pcr0}${pcrs.pcr1}${pcrs.pcr2}`;
		if (found.has(id)) return found.get(id);
		if (!releases || now() - readAt >= 60_000) {
			readAt = now();
			releases = readMain().catch((e: unknown) => {
				releases = undefined;
				throw e;
			});
		}
		const release = (await releases).find((r) => samePcrs(r.pcrs, pcrs));
		if (release) found.set(id, release);
		return release;
	};
}

/** attested() for `origin`, reaching the world through `reach`. */
export function sealedFetch(origin: string, reach: Reach): Fetch {
	const { now } = reach;
	const sourceOf = sources(reach.exec, now);
	// Each fetch the checks make gets 30 s. A sealed reply streams for as long as it takes.
	const quick: typeof fetch = (input, init) =>
		reach.fetch(input, { ...init, signal: AbortSignal.timeout(30_000) });
	const verified = new WeakSet<SealKey>();

	/** Checks 1 to 3 for each document, and the keys of those that passed, newest first. A key any
	 * refused document names is left out, though another document of it passed. */
	const verifyKeys = async (instances: readonly string[]): Promise<Keys> => {
		if (instances.length === 0)
			throw new VerifyError("Attestation", `${origin} lists no enclave`, false);
		const at = now();
		const files = await during("Allowed", () => fetchSignedList(quick));
		let list: SignedList;
		try {
			list = verifySignedList(files, at);
		} catch (e) {
			throw new VerifyError(
				"Allowed",
				`Morse's signed list ${files.name} ${(e as Error).message}`,
				false,
			);
		}
		const checked = await Promise.all(
			instances.map((instance, i) =>
				checkDocument(
					instance,
					`document ${i + 1} of ${instances.length}`,
					list,
					reach.root,
					at,
				),
			),
		);
		const refused: { step: Check; reason: string; key?: string }[] =
			checked.flatMap((c) =>
				c.doc ? [] : [{ step: c.label, reason: c.reason, key: c.publicKey }],
			);
		const docs: AttestedDocument[] = [];
		for (const { doc } of checked) {
			if (!doc) continue;
			const release = await during("Source", () => sourceOf(doc.pcrs));
			if (release) docs.push(doc);
			else
				refused.push({
					step: "Source",
					reason: `enclave ${doc.moduleId ?? hex(doc.keyId)}: ${unpublished(doc.pcrs)}`,
					key: hex(doc.publicKey),
				});
		}
		const refusedKeys = new Set(refused.map((r) => r.key));
		const newest = new Map<string, AttestedDocument>();
		for (const doc of docs) {
			const key = hex(doc.publicKey);
			const known = newest.get(key);
			if (!refusedKeys.has(key) && (!known || known.issuedAt < doc.issuedAt))
				newest.set(key, doc);
		}
		const kept = [...newest.values()]
			.sort((a, b) => b.issuedAt - a.issuedAt)
			.slice(0, MAX_KEYS);
		if (kept.length === 0) {
			const [first] = refused;
			throw new VerifyError(first.step, first.reason, false);
		}
		const keys = kept.map((d) => ({ publicKey: d.publicKey, keyId: d.keyId }));
		for (const k of keys) verified.add(k);
		return {
			keys,
			expiresAt: Math.min(...kept.map((d) => d.issuedAt)) + MAX_AGE_MS,
		};
	};

	const listed = async () => {
		const url = `${origin}/v1/attestation`;
		const got = await get(quick, url);
		if (got.status !== 200)
			throw new Unfinished(`${url} answered ${got.status}`);
		const read = attestationReply.safeParse(json(got.body));
		if (!read.success) throw new Error(`${url} is not a list of enclaves`);
		return read.data.instances;
	};

	// The keys sealed to, which only verifyKeys makes. A 421's replacement bumps the generation, so
	// an older fetch still running never puts its keys back.
	let held: Keys | undefined;
	let fetching: Promise<Keys> | undefined;
	let generation = 0;
	const keySet = (): Promise<Keys> => {
		if (held && now() <= held.expiresAt) return Promise.resolve(held);
		fetching ??= (async () => {
			const mine = generation;
			const keys = await verifyKeys(await during("Attestation", listed));
			if (generation !== mine) return held ?? keys;
			held = keys;
			return keys;
		})().finally(() => {
			fetching = undefined;
		});
		return fetching;
	};
	const replaceKeys = async (instances: readonly string[]) => {
		const mine = ++generation;
		held = undefined;
		const keys = await verifyKeys(instances);
		if (generation === mine) held = keys;
		return keys;
	};

	/** Only an enclave's offset, from a sealed sealed_stale, moves the clock `ts` is set by. */
	let offsetMs = 0;

	return async (input, init) => {
		const request = new Request(input, {
			...init,
			duplex: "half",
		} as RequestInit);
		const url = new URL(request.url);
		const route = `${request.method} ${url.pathname}`;
		if (url.origin !== origin)
			throw new Error(
				`attested() sends only to ${origin}, and this request is to ${url.origin}, where your API key would go. Nothing was sent.`,
			);
		// A Request drops the dispatcher undici takes, such as a proxy's, which the SDK passes from its
		// fetchOptions, so it goes on to the requests made for this call by hand.
		const dispatcher = (init as { dispatcher?: unknown } | undefined)
			?.dispatcher;
		const via = dispatcher === undefined ? {} : { dispatcher };
		const answered = (res: Response) => {
			if (res.status >= 300 && res.status < 400)
				throw new Error(
					`${origin} answered ${route} with a redirect (${res.status}), which attested() doesn't follow`,
				);
			return res;
		};

		if (plainRoute(request.method, url.pathname)) {
			const headers = new Headers();
			for (const name of ["authorization", "accept"]) {
				const value = request.headers.get(name);
				if (value !== null) headers.set(name, value);
			}
			return answered(
				await reach.fetch(url, {
					method: request.method,
					headers,
					signal: request.signal,
					redirect: "manual",
					...via,
				}),
			);
		}
		if (!sealsRoute(request.method, url.pathname))
			throw new Error(
				`attested() won't send ${route}: the enclave can't seal it, so it would go out readable. Nothing was sent.`,
			);
		const authorization = request.headers.get("authorization");
		if (!authorization)
			throw new Error(
				`attested() won't send ${route} without an Authorization header, which the relay refuses. Nothing was sent.`,
			);
		const headers: Record<string, string> = {};
		for (const [name, value] of request.headers) {
			const content = CONTENT_HEADERS.get(name);
			if (content) headers[content] = value;
			else if (!droppedHeader(name))
				throw new Error(
					`attested() won't send the header ${name}: the enclave drops it from a seal, and beside one the relay would read it. Nothing was sent.`,
				);
		}
		const body = new Uint8Array(await request.arrayBuffer()) as Bytes;
		const path = url.pathname + url.search;

		// The keys may take a git clone to check, which the caller's abort, or the SDK's timeout, stops
		// waiting for.
		const { signal } = request;
		signal.throwIfAborted();
		let tried = false;
		const waitFor = async (work: Promise<Keys>) => {
			try {
				return await unlessAborted(work, signal);
			} catch (e) {
				if (!tried || !(e instanceof VerifyError)) throw e;
				throw new VerifyError(e.step, e.reason, e.retryable, FIRST_TRY_SENT);
			}
		};
		let keys = await waitFor(keySet());
		let keyRetried = false;
		let clockRetried = false;
		for (;;) {
			// Keys checked at the start of a slow fetch can be past 30 minutes at its end. They get one
			// more fetch.
			if (now() > keys.expiresAt) keys = await waitFor(keySet());
			if (now() > keys.expiresAt)
				throw new VerifyError(
					"Attestation",
					"the oldest document that passed was over 30 minutes old by the time its checks finished",
					true,
					tried ? FIRST_TRY_SENT : NOTHING_SENT,
				);
			if (!keys.keys.every((k) => verified.has(k)))
				throw new Error(
					"attested() was about to seal to a key it hadn't verified. Nothing was sent.",
				);
			const ts = Math.floor((now() + offsetMs) / 1000);
			const { sealed, cek } = await sealRequest(
				keys.keys,
				{ method: request.method, path, headers, ts },
				body,
			).catch((e: unknown) => {
				throw e instanceof HeadTooLarge
					? new Error(
							`attested() won't send ${route}: ${e.message}, so the enclave would refuse it as request_too_large. The head holds its method, path, query, and content headers. Nothing was sent.`,
						)
					: e;
			});
			const res = answered(
				await reach.fetch(`${origin}/v1/sealed`, {
					method: "POST",
					headers: {
						Authorization: authorization,
						"Content-Type": SEALED_CONTENT_TYPE,
					},
					body: sealed,
					signal,
					redirect: "manual",
					...via,
				}),
			);
			tried = true;
			if (res.headers.get("content-type") === SEALED_CONTENT_TYPE) {
				const reply = await opened(res, cek, route, signal);
				if (reply.status === 400 && !clockRetried) {
					const refusal = sealedStale.safeParse(
						await reply
							.clone()
							.json()
							.catch(() => null),
					);
					if (refusal.success) {
						clockRetried = true;
						offsetMs = refusal.data.proxy_time * 1000 - now();
						await reply.body?.cancel();
						continue;
					}
				}
				return reply;
			}
			if (res.status < 400)
				throw new Error(
					`${origin} answered ${route} ${res.status} without sealing the reply, which only the enclave can do, so attested() refuses it`,
				);
			if (res.status === 421 && !keyRetried) {
				const refusal = sealedKeyUnknown.safeParse(
					await res
						.clone()
						.json()
						.catch(() => null),
				);
				if (refusal.success) {
					keyRetried = true;
					await res.body?.cancel();
					keys = await waitFor(replaceKeys(refusal.data.instances));
					continue;
				}
			}
			return res;
		}
	};
}

/** The enclave's reply inside `res`, as a Response: its own status and headers, then the relay's
 * headers it doesn't set, and a body that errors if the reply ends before its final frame. A status
 * with no body is read to that frame first. */
async function opened(
	res: Response,
	cek: Bytes,
	route: string,
	signal: AbortSignal,
): Promise<Response> {
	let reply: Awaited<ReturnType<typeof openReply>>;
	try {
		if (!res.body) throw new Error("it has no body");
		reply = await openReply(res.body, cek);
		if (NULL_BODY_STATUSES.has(reply.status))
			await new Response(reply.body).arrayBuffer();
	} catch (e) {
		if (signal.aborted) throw signal.reason;
		throw new Error(
			`the enclave's sealed reply to ${route} doesn't open: ${(e as Error).message}`,
		);
	}
	return new Response(
		NULL_BODY_STATUSES.has(reply.status) ? null : reply.body,
		{
			status: reply.status,
			headers: withRelayHeaders(reply.headers, res.headers),
		},
	);
}

const ORIGIN = "https://api.trymorse.ai";
const perProcess = new Map<string, Fetch>();

/** A fetch that seals every request carrying content to Morse's verified enclave keys, passes the
 * relay's four plain GETs through, and throws for anything else. It needs git on PATH, to check
 * each image's source. Every call for an origin shares one fetch, with its keys and lookups. */
export function attested({ origin = ORIGIN }: AttestedOptions = {}): Fetch {
	const at = new URL(origin);
	if (at.protocol !== "https:")
		throw new TypeError(
			`attested() sends only over HTTPS, so not to ${origin}: your API key would cross the network readable`,
		);
	const known = perProcess.get(at.origin);
	if (known) return known;
	const send = sealedFetch(at.origin, {
		fetch,
		exec,
		now: Date.now,
		root: NITRO_ROOT,
	});
	perProcess.set(at.origin, send);
	return send;
}
