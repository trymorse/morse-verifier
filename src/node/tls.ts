// Where TLS to the host ends: the SHA-256 of the key its certificate names, to compare with the keys
// the enclaves attest in their documents' public_key. By hand:
//   openssl s_client -connect api.trymorse.ai:443 -servername api.trymorse.ai </dev/null 2>/dev/null \
//     | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256
import { createHash, X509Certificate } from "node:crypto";
import { connect } from "node:tls";

export interface ServedKey {
	/** Hex SHA-256 of the DER SubjectPublicKeyInfo of the certificate the host served. */
	readonly spkiSha256: string;
	/** The common name of its issuer. */
	readonly issuer: string;
}

/** A new connection to `host`:443, checked as any HTTPS client checks it, with no session reused. */
export const servedKey = (host: string): Promise<ServedKey> =>
	new Promise((resolve, reject) => {
		const socket = connect(
			{ host, port: 443, servername: host, timeout: 15_000 },
			() => {
				const cert = new X509Certificate(socket.getPeerCertificate().raw);
				socket.destroy();
				const spki = cert.publicKey.export({ type: "spki", format: "der" });
				resolve({
					spkiSha256: createHash("sha256").update(spki).digest("hex"),
					issuer: /^CN=(.*)$/m.exec(cert.issuer)?.[1] ?? cert.issuer,
				});
			},
		);
		socket.on("timeout", () => socket.destroy(new Error("timed out")));
		socket.on("error", reject);
	});
