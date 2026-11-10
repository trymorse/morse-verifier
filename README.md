# @askmorse/verify

Checks that the enclaves serving Morse's API run code you can read. One command, with no account.

```sh
npx @askmorse/verify@2026.11.14
```

It needs Node 24 or later and `git`. It asks `api.trymorse.ai` (or the host you name) for the AWS Nitro attestation document of each enclave it lists, and checks each one against three public records: AWS's Nitro root, Morse's signed list of images in Sigstore's public log, and the source on GitHub. With `--rebuild`, it also builds that source on your machine and compares the result.

```
@askmorse/verify <version>
Checking the enclaves api.trymorse.ai lists

Attestation  2 enclaves, each signed by AWS Nitro (root 641a0321…8f79bb5b)
             key 8f6198f0b59e34cf, signed 6 min ago
             key 0032c6519a4b546d, signed 8 min ago
             PCR0 4fccf46baafd…ef6e1606
             PCR1 3b4a7e1b5f13…a0974d03
             PCR2 de079dd37c0b…1c4d4f35
Allowed      on Morse's signed list of prod images, not revoked
             list 290, logged 48 min ago at Rekor entry 3714441255
             https://search.sigstore.dev/?logIndex=3714441255
Source       v2026.11.4-pins-23c1570, commit 696ab5a852e0 on main of
             github.com/trymorse/morse-enclave, names these PCRs
Rebuild      not run. These PCRs are the ones Morse's CI wrote in that commit.
             Run with --rebuild to build it here and compare (Docker, ~2 min).
TLS          api.trymorse.ai's TLS key 7589dd8f4f792416 (issuer Amazon RSA 2048
             M04) is in no attestation document, so TLS ends before the enclave.
             Morse's relay can read requests on it unless they're sealed.

Passed. The enclaves api.trymorse.ai lists run v2026.11.4-pins-23c1570 of
github.com/trymorse/morse-enclave, as published (not rebuilt here).
Pin this release in CI: --release 696ab5a852e09f3ab11e49156f3892e02796db5a
```

```
npx @askmorse/verify [host] [--release <name|commit>] [--rebuild] [--help] [--version]
```

| Exit | Means |
|---|---|
| 0 | Every check passed. |
| 1 | A check failed. It names the step, `Failed at <step>`. Don't send anything to these enclaves. |
| 2 | It could not finish: no network, a rate limit, no `git` or Docker, or bad arguments. Nothing past the step it names is proven. Run it again. |

The checks fix the environment to prod. The reply's own `environment` field and its `proxy_time` aren't signed, so it reads neither: documents and the list are judged by your machine's clock.

## The checks, and how to run each by hand

In [src/node](src/node), [signed_list.ts](src/node/signed_list.ts), [source.ts](src/node/source.ts), [rebuild.ts](src/node/rebuild.ts), and [tls.ts](src/node/tls.ts) each open with the commands they stand for, and [verify.ts](src/node/verify.ts) runs the checks in order and decides what each prints. A document's own rules are in the browser-safe core, which the Morse app runs too: [nitro.ts](src/nitro.ts) (its signature, age, and key), [x509.ts](src/x509.ts) (the chain to AWS's root), and [pins.ts](src/pins.ts) (its PCRs).

**Attestation.** `GET https://<host>/v1/attestation` lists base64 COSE_Sign1 documents. Each must be signed by a certificate chain that ends at the AWS Nitro Enclaves root (SHA-256 `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`, as [AWS publishes it](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)), be at most 30 minutes old and at most 5 minutes ahead by your clock, report PCRs that aren't all zero (debug mode), and carry `user_data` of `morse-proxy-hpke-v1|prod|` and a 32-byte X25519 key, the key requests are sealed to. A key's id is the first 8 bytes of its SHA-256. Enclaves are counted by key, but every document goes through each check below at its own PCRs, even one whose key a newer document names too. A host that lists no enclave fails. By hand:

```sh
curl -s https://api.trymorse.ai/v1/attestation | jq -r '.instances[0]' | base64 -d > doc.cbor
```

then check `doc.cbor` with any COSE and X.509 library, or run [`check-enclave.py`](https://github.com/trymorse/morse-enclave/blob/main/check-enclave.py) in morse-enclave, a separate implementation in Python (which looks the PCRs up in the unsigned `enclave_pins.json` instead of the signed list below).

**Allowed.** The PCRs must be on Morse's signed list of prod images and not revoked. The list is the latest release of [trymorse/morse-pins](https://github.com/trymorse/morse-pins/releases): `prod.statement.json`, signed by `prod.sigstore.json`, a Sigstore bundle that Morse's CI signs on each change and at least daily, and Sigstore's public log, Rekor, records. It is checked offline with `@sigstore/verify` against Sigstore's public trusted root ([sigstore_root.ts](src/node/sigstore_root.ts)), with the rules of Morse's own Go verifier on top (it is `internal/pinsig` in Morse's backend, morse-server, which is private, and morse-enclave carries a public copy in [internal/pinsig](https://github.com/trymorse/morse-enclave/tree/main/internal/pinsig)): one Rekor v1 `hashedrekord` entry carrying both its signed entry timestamp and its inclusion proof; a certificate issued to `https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main` on a GitHub-hosted runner, in the first attempt of a run that a push or the schedule started; a statement in canonical JSON whose `pins_commit` is the commit the certificate names; and logged no more than 7 days ago. Watermark-Labs is the GitHub organization of the company behind Morse, and its `pins` repository, where the list is written and signed, is private: the certificate names the workflow that signed, not code you can read. By hand:

```sh
tag=$(curl -sI https://github.com/trymorse/morse-pins/releases/latest | sed -n 's|^location: .*/tag/||Ip' | tr -d '\r')
curl -sLO https://github.com/trymorse/morse-pins/releases/download/$tag/prod.statement.json
curl -sLO https://github.com/trymorse/morse-pins/releases/download/$tag/prod.sigstore.json
cosign verify-blob prod.statement.json --bundle prod.sigstore.json \
  --certificate-identity https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-sha "$(jq -r .pins_commit prod.statement.json)"
jq -r '.verificationMaterial.tlogEntries[0] | "Rekor entry \(.logIndex), logged \(.integratedTime | tonumber | todate)"' prod.sigstore.json
jq -e '.verificationMaterial.tlogEntries[0].integratedTime | tonumber > now - 7 * 86400' prod.sigstore.json   # true: logged in the last 7 days
jq '.images[] | select(.pcr0 == "<PCR0>")' prod.statement.json
```

The Sigstore root in [sigstore_root.ts](src/node/sigstore_root.ts) is a copy of the `trusted_root.json` that Sigstore's root-signing repository publishes. To compare the two, run this in this repository after `npm ci && npm run build`, or in `node_modules/@askmorse/verify` where npm installed it. It prints nothing when they match, and a difference after Sigstore changes its root means this version carries the older one:

```sh
diff <(node -e 'import("./dist/node/sigstore_root.js").then((m) => console.log(JSON.stringify(m.SIGSTORE_TRUSTED_ROOT)))' | jq -S .) \
  <(curl -s https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json | jq -S .)
```

**Source.** A commit on `main` of [trymorse/morse-enclave](https://github.com/trymorse/morse-enclave/commits/main) must name the exact PCRs. GitHub refuses to rewrite or delete that branch only because of a ruleset Morse set on the repository, which Morse could change. A rewrite would show: `main`'s history would no longer contain the commits users pinned, so a `--release` pin of one would stop finding it. Morse's CI writes one commit per release, whose message is the release's name and the PCRs it measured. Morse's Go sidecar for sealing API calls, morse-seal, reads the same messages, but it isn't published yet. The newest such commit is the image's source; others with the same PCRs are printed too. During a deploy, an image can serve a few minutes before its commit is published: run again. By hand:

```sh
git clone --bare --filter=tree:0 --single-branch --branch main https://github.com/trymorse/morse-enclave enclave.git
git -C enclave.git log --format='%H %s' main
git -C enclave.git show -s --format=%B <commit>
```

**Release** (`--release <x>`). Every enclave must run the release `x` names: a commit's subject, such as `v2026.11.4-pins-23c1570`, or its 40-hex commit on `main`. Pin the commit, since a name is only text in a message. With `--rebuild`, the commit `x` names is the one it builds. A deploy replaces one enclave at a time, so for a few minutes after each deploy the enclaves run two releases and a pin fails. Morse releases several times a day.

**Rebuild** (`--rebuild`). It exports the commit with `git archive`, runs that commit's own `deploy/enclave/build.sh eif <tar> rebuild prod <out>` with `IMAGE_MIRROR` unset, and compares the PCRs `nitro-cli` measured, in `out/measurements.json`, with the attested ones. Before it runs, it prints the commands and the script's SHA-256. The script runs Docker containers with access to the Docker daemon, which is root on your machine, so use a machine you don't mind that on. It needs Docker, `bash`, `tar`, `jq`, and about 1 GB of images. A commit's `build.sh` builds the EIF on arm64 Linux, and newer ones also on x86_64 Linux. For an older commit on x86_64, enable arm64 emulation first (`docker run --privileged --rm tonistiigi/binfmt --install arm64`); it then takes about 6 minutes. Docker Desktop on Apple silicon runs arm64, which is untested. A build that fails exits 2; nothing weaker is tried instead. By hand:

```sh
git -C enclave.git archive --format=tar <commit> > src.tar
mkdir src && tar -xf src.tar -C src
bash src/deploy/enclave/build.sh eif src.tar rebuild prod out
jq .Measurements out/measurements.json
```

**TLS** informs and never fails. It opens a new TLS connection to `<host>:443`, checked as any HTTPS client checks it, and compares the SHA-256 of the served certificate's key with the keys the passing documents name in `public_key`. On `api.trymorse.ai` TLS ends at AWS's load balancer, before the enclave. By hand:

```sh
openssl s_client -connect api.trymorse.ai:443 -servername api.trymorse.ai </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256
```

## What it doesn't prove

- **That a plain API call is private.** Morse's relay, which isn't published, sits in front of the enclaves. It reads every request that isn't sealed to an enclave's key, and the metadata of every request: who, when, how big. The Morse app seals its requests; a plain `sk_` call to the API doesn't.
- **That a document is new.** Documents carry no nonce. A relay can show you one up to 30 minutes old, or one of an enclave that has since stopped. The claims are about keys and images, not about which machine answers you.
- **That the source builds these PCRs, without `--rebuild`.** The Source step only finds a commit whose message names them. Morse's CI wrote that message.
- **That Morse didn't allow other images.** Morse's own CI signs the list, so Morse can list any image it builds. The log makes each list public and undeniable later; it doesn't stop one.
- **That everyone sees the same list.** Nothing here watches Rekor for a list shown to only some people.
- **PCR3 and PCR4**, the AWS account and instance, aren't checked: the claim is about the code, not where it runs.

## verify()

The command line prints what `verify()` decides:

```ts
import { verify } from "@askmorse/verify";

const report = await verify({ host: "api.trymorse.ai", release: undefined, rebuild: false, onStep: (step) => console.log(step) });
report.exitCode; // 0, 1, or 2, as the command exits
report.steps; // [{ label: "Attestation", status: "passed", lines: [...] }, ...]
report.images; // each image's PCRs, its enclaves' keys, and its release on main
```

The other options (`now`, `fetch`, `exec`, `tls`, `sleep`, `root`) are for tests.

The browser-safe core, which the Morse web app runs, is `@askmorse/verify/browser`: `verifyInstances`, `proveInstance`, `verifyNitroDocument`, `sealRequest`, `openReply`, and the rest of [src/index.ts](src/index.ts). It verifies Nitro documents with WebCrypto and seals requests to their keys; it fetches nothing itself.

## attested()

`attested()` is a `fetch` for the OpenAI SDK, or anything else that takes one. It seals each request that carries content to the keys of enclaves that passed Attestation, Allowed, and Source, and throws rather than send anything Morse's relay could read:

```ts
import OpenAI from "openai";
import { attested } from "@askmorse/verify";

const client = new OpenAI({ baseURL: "https://api.trymorse.ai/v1", apiKey: process.env.MORSE_API_KEY, fetch: attested() });
```

It needs Node 24 or later and `git` on `PATH`: the Source check clones the commits of morse-enclave's `main` (a few hundred KB) into the temporary directory. Without `git`, every sealed request throws `Source could not finish: the Source check runs git, which isn't on this machine's PATH…`, so it doesn't run in a browser, on an edge runtime, or in an image without `git`, such as `node:24-slim`.

It works with the OpenAI SDK's majors 4 to 7 (tested with 4.104, 5.23, 6.49, and 7.53). openai 4 types its `fetch` option as node-fetch's, so TypeScript wants `fetch: attested() as never` there.

**What it sends.**

- A route the enclave serves sealed, listed in [sealed_routes.ts](src/sealed_routes.ts) (chat completions, images, videos, search, fetch, research, lookups, and transcriptions), goes inside a seal that only the verified enclaves can open: its method, path, query, body, and content headers. The relay sees your API key, `Content-Type: application/morse-sealed`, the seal's size, when you sent it, and the headers Node's `fetch` adds to every request: `User-Agent: node`, `Accept: */*`, `Accept-Language: *`, `Sec-Fetch-Mode: cors`, and `Accept-Encoding: gzip, deflate`. The SDK's `Accept`, `User-Agent`, `X-Stainless-*`, and `OpenAI-*` headers are dropped, and so is the `Content-Length` openai 4 sets, since the sealed request carries its own. Any other header throws, by name.
- The relay's four plain GETs (`/v1/models`, `/v1/attestation`, `/v1/receipts/{id}`, and `/v1/videos/{id}`) carry no content and go as they are, with only `Authorization` and `Accept`, and the headers Node's `fetch` adds.
- A `dispatcher` the SDK passes from its `fetchOptions`, such as a proxy's, carries the request: the plain GET, or the sealed `POST /v1/sealed`. The checks' own fetches use Node's global dispatcher, and `git` its own proxy settings (`http.proxy` or `HTTPS_PROXY`).
- Anything else throws: `attested() won't send POST /v1/embeddings: the enclave can't seal it, so it would go out readable. Nothing was sent.` So does a request to any origin but its own, which is `https://api.trymorse.ai` unless `attested({ origin })` names another HTTPS one, and any redirect.

**The keys.** Before its first sealed request, and again once the oldest key's document is 30 minutes old by your clock, it reads `/v1/attestation`, Morse's signed list, and morse-enclave's `main`, and runs each document through the command line's own code for the first three checks. A key goes in only when every listed document that names it passed. It keeps up to four, newest first, and seals each request to all of them, since the load balancer can hand it to any enclave. Concurrent requests share one fetch. A request stops waiting for it when its signal aborts or the SDK's timeout passes, and the fetch runs on for the next request; `git` is stopped after 60 s. The signed list is read again at every fetch, so a revocation reaches a running process within 30 minutes. A release found for an image's PCRs is kept for the life of the process. Every `attested()` for one origin shares the same keys.

Unlike the command line, an enclave that fails doesn't stop requests to the ones that passed, and nothing stands for `--release` or `--rebuild`. Morse releases several times a day, so a release pinned in production code would stop sending at the next deploy.

**Replies.** A sealed reply comes back as the enclave wrote it, with its own status and headers, and its body opens frame by frame, so a stream (`stream: true`) arrives as it is written. A reply that ends before its final frame errors its stream. The relay's `X-Request-Id`, and the other headers it sets beside the seal, are added where the enclave set none; nothing authenticates them. A refusal the relay makes in the clear, such as a bad key, no balance, or a rate limit, is returned as it is. A success in the clear throws, since only an enclave can seal a reply.

**Retries.** On a 421 `sealed_key_unknown`, when an enclave has restarted with a new key, it checks the documents the 421 lists the same way, takes their keys, and seals once more. On the enclave's sealed `sealed_stale`, when your clock is more than 2 minutes off the enclave's, it takes the enclave's time for the request's timestamp alone and seals once more. Documents are always judged by your clock.

**Errors.** When no key passes, or a check can't finish, it throws a `VerifyError` and sends nothing. Its `step` is `"Attestation"`, `"Allowed"`, or `"Source"`, and its `reason` says why. Its `retryable` is true when the check could not finish, from the network, a rate limit, or `git`, and false when the check refused what it was shown. Its message names the step and ends `Nothing was sent.` After a retry it ends `Nothing was sent but the first try, which was sealed to keys that had passed.`: a 421 or a `sealed_stale` turned that first try away, and the keys for the second didn't pass. The OpenAI SDK throws it as an `APIConnectionError` whose `cause` is the `VerifyError`, after retrying twice by default. Every other refusal is an `Error` that says what it didn't send.

`attested()` proves no more than the command line does: see [What it doesn't prove](#what-it-doesnt-prove). What it adds is that your requests' content opens only inside an enclave that passed. Your API key, the size and timing of each request, the headers Node's `fetch` adds, and the plain GETs are still in the clear to the relay.

## Versions, provenance, and pinning

The first release of `@askmorse/verify` on npm is `2026.11.14`. Each version is a release's tag with the leading `v` dropped. The sample above and the commands below say `<version>` for the version you pin: pin the version you reviewed. The command is `trymorse-verify`.

This repository is published from Morse's private monorepo on each production release of the app, tagged with that release (`vYYYY.M.N`). From the second version on, the tag publishes the same version to npm from this repository's `release.yml`, through npm's trusted publishing, so each version CI publishes carries a provenance statement naming the commit and workflow it was built from. The first version is published by a maintainer from the exported tag, because npm's trusted publishing cannot create a package, and that version has no provenance statement. A release that changes nothing here gets a tag on the commit it shipped, and npm gets no new version if it already has that commit's code under an earlier tag's version. The tree keeps version `0.0.0`; only the published package carries the release's. The app's version and the enclave's releases (`v2026.11.4-pins-23c1570`) are separate series.

Whoever publishes a verifier decides what it prints, so pin the version you read, and check it came from this repository:

```sh
npx -y @askmorse/verify@<version>
npm install @askmorse/verify@<version> && npm audit signatures
npm view @askmorse/verify@<version> dist.attestations
```

`npm audit signatures` checks the registry's signature and the provenance of each installed package. The first version has no provenance, so check its tarball against the tag. To read exactly what runs, compare the tarball (`npm pack @askmorse/verify@<version>`) with `npm ci && npm run build` at the tag.

In GitHub Actions:

```yaml
- uses: actions/setup-node@v7
  with:
    node-version: 24
- run: npx -y @askmorse/verify@<version>
```

This repository does not take pull requests. To report a bug, open an issue. To report a security problem, follow `SECURITY.md`.

## Run the tests

```sh
npm ci
npm test
VERIFY_LIVE=1 npm test   # also runs verify() against api.trymorse.ai
npm run build            # dist/, which npm publishes
```

The tests run on captures of prod from 2026-11-06 ([src/testdata](src/testdata)): an attestation reply, signed lists 280 and 290, the `git log` of morse-enclave's `main`, and Morse's own 40 forged pins bundles.

## License

MIT. See `LICENSE`.
