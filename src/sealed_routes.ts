// Which calls go to the enclave sealed, which the relay answers alone, and which headers ride inside
// the seal, as the backend's internal/seal/routes.go and worker.ContentHeaders list them, and the
// replies around a seal that every client of it reads the same way.
import { z } from "zod";

/** Each route the enclave serves sealed, as `METHOD /path`, where `{x}` is one path segment and
 * `{x...}` is the rest of the path. */
export const SEALED_PATTERNS = [
	"POST /v1/chat/completions",
	"POST /v1/chat/compact",
	"POST /v1/images/generations",
	"POST /v1/videos",
	"GET /v1/videos/{id}/content",
	"POST /v1/search",
	"POST /v1/fetch",
	"POST /v1/research",
	"GET /v1/research/{id}",
	"GET /v1/research/{id}/events",
	"GET /v1/lookup/{service}/{path...}",
	"POST /v1/audio/transcriptions",
	"POST /v1/plugins/call",
	"POST /v1/plugins/token",
	"POST /v1/plugins/revoke",
	"POST /v1/tasks",
	"POST /v1/tasks/{id}/bundle",
] as const;

/** The routes the relay answers alone, which carry no content: there is nothing in them to seal. */
const PLAIN_PATTERNS = [
	"GET /v1/models",
	"GET /v1/attestation",
	"GET /v1/receipts/{id}",
	"GET /v1/videos/{id}",
] as const;

const routes = (patterns: readonly string[]) =>
	patterns.map((pattern) => {
		const [method, path] = pattern.split(" ");
		const source = path
			.split("/")
			.map((segment) =>
				segment.endsWith("...}")
					? ".*"
					: segment.startsWith("{")
						? "[^/]+"
						: segment,
			)
			.join("/");
		return { method, path: new RegExp(`^${source}$`) };
	});
const SEALED_ROUTES = routes(SEALED_PATTERNS);
const PLAIN_ROUTES = routes(PLAIN_PATTERNS);

const matches = (
	table: ReturnType<typeof routes>,
	method: string,
	pathAndQuery: string,
) => {
	const { pathname } = new URL(pathAndQuery, "http://proxy.invalid");
	return table.some(
		(route) =>
			route.method === method.toUpperCase() && route.path.test(pathname),
	);
};

/** Whether the enclave serves `method` `pathAndQuery` sealed. The query is ignored. */
export const sealsRoute = (method: string, pathAndQuery: string) =>
	matches(SEALED_ROUTES, method, pathAndQuery);

/** Whether the relay answers `method` `pathAndQuery` alone, with nothing to seal. */
export const plainRoute = (method: string, pathAndQuery: string) =>
	matches(PLAIN_ROUTES, method, pathAndQuery);

/** The headers the enclave reads from inside a seal, by their lowercase names. It drops any other. */
export const CONTENT_HEADERS = new Map(
	[
		"Content-Type",
		"X-E2EE-Version",
		"X-E2EE-Nonce",
		"X-E2EE-Timestamp",
		"X-E2EE-Algo",
		"X-Client-Pub-Key",
		"X-Model-Pub-Key",
		"X-Signing-Algo",
		"X-Encryption-Version",
		"X-Encrypt-All-Fields",
		"Ehbp-Encapsulated-Key",
		"X-Tinfoil-Model",
		"X-Tinfoil-Max-Output-Tokens",
	].map((h) => [h.toLowerCase(), h]),
);

/** The headers a client drops from a request before sealing it, by their lowercase names, where a
 * trailing `*` is any rest: the SDK's own, which the enclave doesn't read and beside the seal would
 * name the client, and the transport's, which the sealed request sets for itself (openai 4 sets
 * Content-Length). The key moves to the outer request. Any other header that is not a content
 * header refuses the request. */
const DROPPED_HEADERS = [
	"authorization",
	"accept",
	"user-agent",
	"x-stainless-*",
	"openai-*",
	"content-length",
	"host",
	"connection",
	"keep-alive",
	"transfer-encoding",
] as const;

/** Whether a client drops header `name`, lowercase, before sealing. */
export const droppedHeader = (name: string) =>
	DROPPED_HEADERS.some((d) =>
		d.endsWith("*") ? name.startsWith(d.slice(0, -1)) : name === d,
	);

/** The headers the relay sets beside a sealed reply, outside the seal, so nothing authenticates
 * them. A reply's own header of the same name, from inside the seal, wins. */
const RELAY_REPLY_HEADERS = [
	"X-Request-Id",
	"X-Funding",
	"X-Included-Lane",
	"X-Included-Lane-Until",
	"X-Included-Until",
	"X-Output-Limited",
	"X-Turn-Remaining",
] as const;

/** A sealed reply's own headers, then each of the relay's from `outer` that it doesn't set. */
export function withRelayHeaders(inner: Headers, outer: Headers): Headers {
	const headers = new Headers(inner);
	for (const name of RELAY_REPLY_HEADERS) {
		const value = outer.get(name);
		if (value !== null && !headers.has(name)) headers.set(name, value);
	}
	return headers;
}

/** The statuses whose reply has no body, though its seal still ends in a final frame. */
export const NULL_BODY_STATUSES: ReadonlySet<number> = new Set([204, 205, 304]);

/** What GET /v1/attestation answers: each enclave's attestation document, base64. Its other fields
 * are the relay's, which nothing signs. */
export const attestationReply = z.object({
	object: z.literal("proxy_attestation"),
	instances: z.array(z.string()),
});

/** The 421, in the clear, when no enclave behind the relay holds a key the seal names. It lists the
 * documents of the enclaves there are now. */
export const sealedKeyUnknown = z.object({
	error: z.object({ code: z.literal("sealed_key_unknown") }),
	instances: z.array(z.string()),
});

/** The enclave's sealed 400 when the seal's ts is over 2 minutes off its clock, which it names. */
export const sealedStale = z.object({
	error: z.object({ code: z.literal("sealed_stale") }),
	proxy_time: z.number(),
});
