# @askmorse/verify

[![npm](https://img.shields.io/npm/v/@askmorse/verify)](https://www.npmjs.com/package/@askmorse/verify)
[![CodeQL](https://github.com/trymorse/morse-verifier/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/trymorse/morse-verifier/actions/workflows/github-code-scanning/codeql)
[![License: MIT](https://img.shields.io/github/license/trymorse/morse-verifier)](LICENSE)

This command checks that the enclaves serving Morse's API run code you can read. It needs no account, only Node 24 or later and `git`.

```sh
npx @askmorse/verify                        # api.trymorse.ai, the web app's host
npx @askmorse/verify inference.trymorse.ai  # the API key door
npx @askmorse/verify [host] [--release <name|commit>] [--rebuild] [--help] [--version]
```

Pin a version from [npm's version list](https://www.npmjs.com/package/@askmorse/verify?activeTab=versions) to make the check reproducible.

| Exit | Means |
|---|---|
| 0 | Every check passed. |
| 1 | A check failed at the step it names. Send nothing to these enclaves. |
| 2 | It couldn't finish because of the network, a rate limit, missing `git` or Docker, or bad arguments. Nothing past that step is proven. Run it again. |

## What it checks

It checks prod only, judges times by your clock, and ignores the unsigned `environment` and `proxy_time` fields. [verify.ts](src/node/verify.ts) runs the checks in order. [signed_list.ts](src/node/signed_list.ts), [source.ts](src/node/source.ts), [rebuild.ts](src/node/rebuild.ts), and [tls.ts](src/node/tls.ts) open with the commands they stand for. The rules for a document are in [nitro.ts](src/nitro.ts), [x509.ts](src/x509.ts), and [pins.ts](src/pins.ts).

**Attestation.** Each document from `GET https://<host>/v1/attestation` must chain to the AWS Nitro root (SHA-256 `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`, [published by AWS](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)), be at most 30 minutes old and 5 minutes ahead, have PCRs that aren't all zero, which would mean debug mode, and carry `user_data` of `morse-proxy-hpke-v1|prod|` plus the 32-byte X25519 key that requests are sealed to. The verifier checks every document at its own PCRs. A host that lists no enclave fails.

```sh
curl -s https://api.trymorse.ai/v1/attestation | jq -r '.instances[0]' | base64 -d > doc.cbor
```

Check `doc.cbor` with any COSE and X.509 library, or with [`check-enclave.py`](https://github.com/trymorse/morse-enclave/blob/main/check-enclave.py), a separate Python check that reads the unsigned `enclave_pins.json`.

**Allowed.** The PCRs must be on Morse's signed list of prod images and not revoked. The list is the newest prod statement on the `statements/images` branch of [trymorse/morse-pins](https://github.com/trymorse/morse-pins/tree/statements/images/prod), the first that `prod/index.json` names. That repository's own `sign.yml` signs it on each change and at least daily, logs it in Rekor v2, and commits it with its Sigstore bundle. The verifier takes the branch tip from git's ref advertisement, reads the files at that commit from `raw.githubusercontent.com`, and checks the bundle offline against Sigstore's public root in [sigstore_root.ts](src/node/sigstore_root.ts), under the rules of [internal/pinsig](https://github.com/trymorse/morse-enclave/tree/main/internal/pinsig):

- one Rekor v2 `hashedrekord` 0.0.2 entry with its inclusion proof; a v1 entry is refused
- a checkpoint cosigned by at least 3 of the enclave's 4 witnesses (IPng Networks, TrustFabric, Mullvad VPN, and Geomys) before the certificate expired, one per operator
- a certificate for `https://github.com/trymorse/morse-pins/.github/workflows/sign.yml@refs/heads/main`, repository id `1437511167` and owner id `345029672`, from the first attempt of a push or scheduled run on a GitHub-hosted runner, so a list from Morse's private signer (`Watermark-Labs/pins`) or a renamed or recreated repository is refused
- canonical JSON whose `pins_commit` matches the commit the certificate names
- a certificate start (`NotBefore`) in the last 7 days, since a Rekor v2 entry carries no log time

By hand, with `cosign` 3 or later, which checks the log's signature on the checkpoint but not the witnesses':

```sh
commit=$(git ls-remote https://github.com/trymorse/morse-pins refs/heads/statements/images | cut -f1)
raw=https://raw.githubusercontent.com/trymorse/morse-pins/$commit
list=$(curl -s $raw/prod/index.json | jq -r '.[0].statement | rtrimstr(".statement.json")')
curl -so prod.statement.json $raw/$list.statement.json
curl -so prod.sigstore.json $raw/$list.sigstore.json
cosign verify-blob prod.statement.json --bundle prod.sigstore.json \
  --certificate-identity https://github.com/trymorse/morse-pins/.github/workflows/sign.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-sha "$(jq -r .pins_commit prod.statement.json)"
jq -r '.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope' prod.sigstore.json   # the log's signature line, then each witness's
jq -r .verificationMaterial.certificate.rawBytes prod.sigstore.json | base64 -d | openssl x509 -inform der -noout -startdate   # in the last 7 days
jq '.images[] | select(.pcr0 == "<PCR0>")' prod.statement.json
```

To compare the bundled root with Sigstore's, run this after `npm ci && npm run build`, or in `node_modules/@askmorse/verify`. It prints nothing when they match.

```sh
diff <(node -e 'import("./dist/node/sigstore_root.js").then((m) => console.log(JSON.stringify(m.SIGSTORE_TRUSTED_ROOT)))' | jq -S .) \
  <(curl -s https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json | jq -S .)
```

**Source.** A commit on `main` of [trymorse/morse-enclave](https://github.com/trymorse/morse-enclave/commits/main) must name the exact PCRs. The newest match is the source. Only a ruleset that Morse controls protects `main`, but a rewrite would break `--release` pins. Just after a deploy, the commit can take a few minutes to appear, so run again.

```sh
git clone --bare --filter=tree:0 --single-branch --branch main https://github.com/trymorse/morse-enclave enclave.git
git -C enclave.git log --format='%H %s' main
git -C enclave.git show -s --format=%B <commit>
```

**Release** (`--release <x>`). Every enclave must run `x`, which is a release name such as `v2026.11.4-pins-23c1570` or a 40-character commit hash. Pin the commit, because a name is only text in a commit message. A pin fails for a few minutes after each deploy.

**Rebuild** (`--rebuild`). It runs the commit's own `deploy/enclave/build.sh eif <tar> rebuild prod <out>` on a `git archive` export, with `IMAGE_MIRROR` unset, and compares `out/measurements.json` with the attested PCRs. The script drives Docker, which is root on your machine. It needs Docker, `bash`, `tar`, `jq`, and about 1 GB of images. Older commits build on arm64 only, so on x86_64 run `docker run --privileged --rm tonistiigi/binfmt --install arm64` first. Docker Desktop on Apple silicon is untested. A failed build exits 2.

```sh
git -C enclave.git archive --format=tar <commit> > src.tar
mkdir src && tar -xf src.tar -C src
bash src/deploy/enclave/build.sh eif src.tar rebuild prod out
jq .Measurements out/measurements.json
```

**TLS** reports and never fails. It says whether your connection to `<host>:443` ended at a key a passing document names. On `api.trymorse.ai` it ends at AWS's load balancer. On `inference.trymorse.ai` it ends inside the enclave.

```sh
openssl s_client -connect api.trymorse.ai:443 -servername api.trymorse.ai </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256
```

## What it doesn't prove

- **That every connection to the door ends in an enclave.** The TLS check covers only yours. Morse controls `trymorse.ai`'s DNS and could get another certificate for `inference.trymorse.ai`. That would show in Certificate Transparency logs, which morse-enclave's `check-door.py` watches, but plain OpenAI SDKs check neither CT nor attestation. Such a certificate can be detected, not prevented.
- **That a request to `api.trymorse.ai` is private unless sealed.** TLS ends before the enclave there.
- **That the relay's reply headers or clear refusals are the enclave's.** Headers the relay sets beside a seal, such as `X-Funding` and `X-Turn-Remaining`, and its clear-text refusals (bad key, no balance, or rate limit) aren't authenticated.
- **That metadata is private.** The relay sees who calls, when, and how big, and the enclave tells it the route and model so it can bill.
- **That a document is fresh.** Documents carry no nonce, so a relay can replay one up to 30 minutes old, or from a stopped enclave.
- **That the source builds these PCRs, without `--rebuild`.** Source only finds a commit message, which Morse's CI wrote.
- **That Morse allowed no other images.** Morse signs the list, so it can list any image. The log makes that public, not impossible.
- **That everyone sees the same list.** Nothing here watches Rekor for split views.
- **That the Morse web app checked anything.** Its check runs in JavaScript Morse serves, and in the browser the pins come from that calling code. Run the command line yourself.
- **That it runs in a given AWS account or instance.** The verifier doesn't check PCR3 or PCR4, because the claim is about code, not where it runs.

## verify()

```ts
import { verify } from "@askmorse/verify";

const report = await verify({ host: "api.trymorse.ai", release: undefined, rebuild: false, onStep: (step) => console.log(step) });
report.exitCode; // 0, 1, or 2, as the command exits
report.steps; // [{ label: "Attestation", status: "passed", lines: [...] }, ...]
report.images; // each image's PCRs, its enclaves' keys, and its release on main
```

`now`, `fetch`, `exec`, `tls`, `sleep`, and `root` are for tests. `@askmorse/verify/browser` is the browser-safe core the web app runs, in [src/index.ts](src/index.ts). It verifies with WebCrypto, seals to attested keys, and fetches nothing itself.

## attested()

`attested()` is a `fetch` for the OpenAI SDK. It seals each content request to enclaves that passed Attestation, Allowed, and Source, and throws rather than send anything the relay could read.

```ts
import OpenAI from "openai";
import { attested } from "@askmorse/verify";

const origin = "https://inference.trymorse.ai";
const client = new OpenAI({ baseURL: `${origin}/v1`, apiKey: process.env.MORSE_API_KEY, fetch: attested({ origin }) });
```

Without `origin` it uses `https://api.trymorse.ai`, which can refuse API keys with 403 `use_inference_door`.

- It runs on Node 24 or later with `git`, so not in browsers, edge runtimes, or `node:24-slim`.
- It works with openai 4 to 7. On openai 4, write `fetch: attested() as never`.
- It seals the routes in [sealed_routes.ts](src/sealed_routes.ts), with their method, path, query, body, and content headers. Any other request header throws, by name. The relay sees your API key, size, timing, and Node's default headers, and the enclave tells it the route and model so it can bill.
- It sends `/v1/models`, `/v1/attestation`, `/v1/receipts/{id}`, and `/v1/videos/{id}` unsealed, since they carry no content.
- It refuses every other route, every other origin, and every redirect, and sends nothing.
- A `dispatcher` from the SDK's `fetchOptions` carries the request. The checks' fetches use Node's global dispatcher, and `git` its own proxy settings.
- It accepts a key only when every listed document naming it passed. It refreshes keys when the oldest document is 30 minutes old, so a revocation takes effect within 30 minutes. One failing enclave doesn't block the others. It has no `--release` or `--rebuild`.
- It retries once on a 421 `sealed_key_unknown`, and once on `sealed_stale`, which means your clock is more than 2 minutes off.
- It throws a `VerifyError` with `step`, `reason`, and `retryable`, whose message ends `Nothing was sent.`, or after a retry `Nothing was sent but the first try, which was sealed to keys that had passed.` The OpenAI SDK wraps it in an `APIConnectionError`.

It proves no more than the command line does. What it adds is that your content opens only in an enclave that passed.

## Versions and pinning

The first npm release is `2026.11.14`. Each version is a release tag, `vYYYY.M.N`, without the `v`. Later versions carry npm provenance from `release.yml`. The first has none, so compare its tarball with the tag. Each tag has a [GitHub Release](https://github.com/trymorse/morse-verifier/releases). Enclave releases, such as `v2026.11.4-pins-23c1570`, are a separate series.

Whoever publishes a verifier decides what it prints, so pin the version you read and check where it came from.

```sh
npx -y @askmorse/verify@<version>
npm install @askmorse/verify@<version> && npm audit signatures
npm view @askmorse/verify@<version> dist.attestations
```

To read exactly what runs, compare `npm pack @askmorse/verify@<version>` with `npm ci && npm run build` at the tag.

```yaml
- uses: actions/setup-node@v7
  with:
    node-version: 24
- run: npx -y @askmorse/verify@<version>
```

This repository doesn't take pull requests. Open an issue for a bug, and follow `SECURITY.md` for a security problem.

## Run the tests

```sh
npm ci
npm test
VERIFY_LIVE=1 npm test   # also runs verify() against api.trymorse.ai
npm run build            # dist/, which npm publishes
```

Tests use prod captures from 2026-11-11 in [src/testdata](src/testdata).

## License

MIT. See `LICENSE`.
