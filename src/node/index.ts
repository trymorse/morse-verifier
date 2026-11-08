// @askmorse/verify for Node: verify() runs every check the CLI prints and returns what each decided,
// and attested() is a fetch that seals each request carrying content to keys whose documents passed
// Attestation, Allowed, and Source (not Rebuild or TLS). The browser-safe core is
// "@askmorse/verify/browser".

export {
	type AttestedOptions,
	attested,
	VerifyError,
} from "./attested.ts";
export type { ListedImage, SignedList } from "./signed_list.ts";
export type { Release } from "./source.ts";
export type { ServedKey } from "./tls.ts";
export {
	type Enclave,
	type Image,
	type Report,
	type Step,
	type VerifyOptions,
	verify,
} from "./verify.ts";
