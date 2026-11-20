import { type Bytes, fromBase64 } from "./bytes.ts";

// why: c2sp.org/signed-note and c2sp.org/tlog-checkpoint: text with no blank line, one blank line,
// then only "— <name> <base64 of key hash and signature>" lines; the text is origin, size, root.

const MAX_SIGNATURES = 100;

export const validName = (name: string) =>
	name.length > 0 && !/[ +\n\t]/.test(name);

interface NoteSignature {
	readonly name: string;
	readonly hash: Bytes;
	readonly sig: Bytes;
}

export interface Checkpoint {
	readonly text: string;
	readonly origin: string;
	readonly size: bigint;
	readonly root: Bytes;
	readonly signatures: readonly NoteSignature[];
}

export function readCheckpoint(
	note: string,
): Checkpoint | { readonly malformed: string } {
	if (/[\r\0]/.test(note))
		return { malformed: "the note is not plain UTF-8 text" };
	const split = note.indexOf("\n\n");
	if (split < 0 || !note.endsWith("\n"))
		return { malformed: "the note has no signature block" };
	const text = note.slice(0, split + 1);
	const lines = note.slice(split + 2, -1).split("\n");
	if (lines.length > MAX_SIGNATURES)
		return { malformed: `the note has ${lines.length} signature lines` };
	const signatures: NoteSignature[] = [];
	for (const line of lines) {
		const rest = line.startsWith("— ") ? line.slice(2) : "";
		const space = rest.indexOf(" ");
		const name = rest.slice(0, Math.max(space, 0));
		const raw = space < 0 ? undefined : fromBase64(rest.slice(space + 1));
		if (!validName(name) || !raw || raw.length < 5)
			return {
				malformed: `the signature line ${JSON.stringify(line)} is malformed`,
			};
		signatures.push({ name, hash: raw.slice(0, 4), sig: raw.slice(4) });
	}
	const body = text.slice(0, -1).split("\n");
	if (body.length < 3 || body[0] === "")
		return { malformed: "the checkpoint has fewer than three lines" };
	const sizeText = body[1];
	if (!/^(0|[1-9]\d*)$/.test(sizeText) || BigInt(sizeText) >= 1n << 64n)
		return {
			malformed: `the checkpoint's size ${JSON.stringify(sizeText)} is not a decimal number`,
		};
	const root = fromBase64(body[2]);
	if (!root || root.length !== 32)
		return {
			malformed: "the checkpoint's root hash is not 32 bytes of base64",
		};
	return {
		text,
		origin: body[0],
		size: BigInt(sizeText),
		root,
		signatures,
	};
}
