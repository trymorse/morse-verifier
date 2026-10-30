import { type Bytes, concat, enc } from "./bytes.ts";

export type Cbor =
	| number
	| string
	| Bytes
	| boolean
	| null
	| readonly Cbor[]
	| ReadonlyMap<number | string, Cbor>
	| { readonly tag: number; readonly value: Cbor };

const MAX_DEPTH = 16;
const BREAK = 0xff;

export function decodeCbor(input: Bytes): Cbor {
	const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
	let at = 0;
	const take = (n: number) => {
		if (n > input.length - at) throw new Error("the CBOR ends early");
		const out = input.subarray(at, at + n);
		at += n;
		return out;
	};
	const argument = (info: number): number => {
		if (info < 24) return info;
		const size = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
		if (!size) throw new Error(`CBOR additional information ${info}`);
		const start = at;
		take(size);
		if (size === 1) return view.getUint8(start);
		if (size === 2) return view.getUint16(start);
		if (size === 4) return view.getUint32(start);
		const big = view.getBigUint64(start);
		if (big > BigInt(Number.MAX_SAFE_INTEGER))
			throw new Error("a CBOR integer past 2^53");
		return Number(big);
	};
	const text = (bytes: Bytes) =>
		new TextDecoder("utf-8", { fatal: true }).decode(bytes);
	const atBreak = () => {
		if (input[at] !== BREAK) return false;
		at++;
		return true;
	};
	const mapEntries = (
		depth: number,
		more: (i: number) => boolean,
	): ReadonlyMap<number | string, Cbor> => {
		const map = new Map<number | string, Cbor>();
		for (let i = 0; more(i); i++) {
			const key = item(depth + 1);
			if (typeof key !== "number" && typeof key !== "string")
				throw new Error("a CBOR map key that is neither integer nor text");
			if (map.has(key)) throw new Error(`a CBOR map repeats key ${key}`);
			map.set(key, item(depth + 1));
		}
		return map;
	};
	const chunks = (major: 2 | 3): Bytes[] => {
		const out: Bytes[] = [];
		while (!atBreak()) {
			const [initial] = take(1);
			if (initial >> 5 !== major || (initial & 31) === 31)
				throw new Error("a CBOR string chunk of another type");
			out.push(take(argument(initial & 31)));
		}
		return out;
	};
	const indefinite = (major: number, depth: number): Cbor => {
		switch (major) {
			case 2:
				return concat(chunks(2));
			case 3:
				return chunks(3).map(text).join("");
			case 4: {
				const out: Cbor[] = [];
				while (!atBreak()) out.push(item(depth + 1));
				return out;
			}
			case 5:
				return mapEntries(depth, () => !atBreak());
			default:
				throw new Error(
					`CBOR additional information 31 on major type ${major}`,
				);
		}
	};
	const item = (depth: number): Cbor => {
		if (depth > MAX_DEPTH) throw new Error("the CBOR nests too deep");
		const [initial] = take(1);
		const major = initial >> 5;
		const info = initial & 31;
		if (major === 7) {
			if (info === 20) return false;
			if (info === 21) return true;
			if (info === 22) return null;
			if (info === 31)
				throw new Error("a CBOR break outside an indefinite-length item");
			throw new Error(`CBOR simple value ${info}`);
		}
		if (info === 31) return indefinite(major, depth);
		const n = argument(info);
		switch (major) {
			case 0:
				return n;
			case 1:
				return -1 - n;
			case 2:
				return take(n).slice();
			case 3:
				return text(take(n));
			case 4:
				return Array.from({ length: n }, () => item(depth + 1));
			case 5:
				return mapEntries(depth, (i) => i < n);
			default:
				return { tag: n, value: item(depth + 1) };
		}
	};
	const out = item(0);
	if (at !== input.length) throw new Error("bytes follow the CBOR item");
	return out;
}

function head(major: number, n: number): Bytes {
	if (n < 24) return Uint8Array.of((major << 5) | n);
	if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
	if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
	const out = new Uint8Array(5);
	out[0] = (major << 5) | 26;
	new DataView(out.buffer).setUint32(1, n);
	return out;
}

export function encodeCborArray(items: readonly (string | Bytes)[]): Bytes {
	return concat([
		head(4, items.length),
		...items.flatMap((x) => {
			const bytes = typeof x === "string" ? enc.encode(x) : x;
			return [head(typeof x === "string" ? 3 : 2, bytes.length), bytes];
		}),
	]);
}
