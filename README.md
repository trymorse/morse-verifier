# @morse/verifier

The browser code that checks Morse's AWS Nitro enclave without trusting Morse's app. `verifyInstances(documents, trust, now)` takes the proxy's base64 attestation documents and a `trust` object you supply (`environment`, `pins`, `root`, and `standIns`). It checks each document's COSE signature and certificate chain up to the AWS Nitro root (`NITRO_ROOT`), that the document is under 30 minutes old, that PCR0, PCR1, and PCR2 match a pin that is not revoked, and that `user_data` names the key to seal to. It returns the attested HPKE keys, or throws `UnattestedError`, whose `refusals` are the errors each document was refused with and whose `unpinned` is true when a document verified but no pin names its image, which newer pins may. `sealRequest` and `openReply` then speak the sealed wire format to those keys. The package holds no pins of its own, so you pass them in, parsed with `parseEnclavePins`. `checkPcrs(pins, environment, pcrs)` is the pin check on its own: it returns the pin that names the PCRs, and throws for a debug enclave's all-zero PCRs, a revoked image, or, as `UnpinnedError`, an image no pin names.

## How this repository is published

Morse's web app builds this code from its private monorepo. A bot publishes it here on each production release of the app and tags it with that release, such as `v2026.10.2`. A release that changes nothing here still gets a tag, on the commit it shipped. Morse does not publish its day-to-day commits.

The pins the app passes in come from [morse-pins](https://github.com/trymorse/morse-pins). The enclave they describe is built from [morse-enclave](https://github.com/trymorse/morse-enclave).

This repository does not take pull requests. To report a bug, open an issue. To report a security problem, follow `SECURITY.md`.

## Run the tests

You need Node 24 or later:

```sh
npm ci
npm test
```

## License

MIT. See `LICENSE`.
