# trymorse-verify

Checks that the enclaves serving Morse's API run code you can read. One command, with no account.

Not yet published on PyPI. To run it today:

```sh
git clone https://github.com/trymorse/morse-verifier && cd morse-verifier/python && uv run trymorse-verify
```

Once released: `uvx trymorse-verify==<version>`, or `pipx run trymorse-verify==<version>`, or `pip install trymorse-verify==<version> && trymorse-verify`, or `python -m trymorse_verify`. It needs Python 3.10 or later and `git`.

This is the Python port of [`@askmorse/verify`](https://www.npmjs.com/package/@askmorse/verify), with [`attested_client()`](#attested_client) for OpenAI's Python SDK. It makes the same checks, prints the same lines (but the first, which names this package), and exits with the same codes: the tests of both render the same scenarios and compare them with the same files. It asks `api.trymorse.ai` (or the host you name) for the AWS Nitro attestation document of each enclave it lists, and checks each one against three public records: AWS's Nitro root, Morse's signed list of images in Sigstore's public log, and the source on GitHub. With `--rebuild`, it also builds that source on your machine with Docker and compares the result.

```
trymorse-verify [host] [--release <name|commit>] [--rebuild] [--help] [--version]
```

| Exit | Means |
|---|---|
| 0 | Every check passed. |
| 1 | A check failed. It names the step, `Failed at <step>`. Don't send anything to these enclaves. |
| 2 | It could not finish: no network, a rate limit, no `git` or Docker, or bad arguments. Nothing past the step it names is proven. Run it again. |

What each check proves, how to run each by hand, and what none of them proves are in the [package README](https://github.com/trymorse/morse-verifier#readme). The Sigstore bundle is verified offline with [sigstore-python](https://github.com/sigstore/sigstore-python) against the trusted root in `sigstore_root.json`, the same one the TypeScript package embeds, and then held to Morse's own rules for who may sign the list.

## verify()

The command line prints what `verify()` decides:

```python
from trymorse_verify import verify

report = verify("api.trymorse.ai", release=None, rebuild=False, on_step=print)
report.exit_code  # 0, 1, or 2, as the command exits
report.steps      # [Step(label="Attestation", status="passed", lines=[...]), ...]
report.images     # each image's PCRs, its enclaves' keys, and its release on main
```

The other arguments (`now`, `client`, `exec`, `tls`, `sleep`, `root`) are for tests.

## attested_client()

`attested_client()` is an `httpx.Client` for OpenAI's Python SDK, and `attested_async_client()` an `httpx.AsyncClient` for `AsyncOpenAI`. Each seals every request that carries content to the keys of enclaves that passed Attestation, Allowed, and Source, and raises rather than send anything Morse's relay could read:

```python
import os
from openai import AsyncOpenAI, OpenAI
from trymorse_verify import attested_async_client, attested_client

client = OpenAI(
    base_url="https://api.trymorse.ai/v1",
    api_key=os.environ["MORSE_API_KEY"],
    http_client=attested_client(),
)
aclient = AsyncOpenAI(
    base_url="https://api.trymorse.ai/v1",
    api_key=os.environ["MORSE_API_KEY"],
    http_client=attested_async_client(),
)
```

They do what `attested()` does for the TypeScript SDK, which the [package README](https://github.com/trymorse/morse-verifier#attested) describes in full; the tests of both send the same requests to a stand-in relay. They need `git` on `PATH`, for the Source check. They are tested with openai 1.109, 2.8, and 3.46.

- A route the enclave serves sealed (chat completions, images, videos, search, fetch, research, lookups, and transcriptions) goes inside a seal only the verified enclaves can open: its method, path, query, body, and content headers. The relay sees `POST /v1/sealed` with your API key, `Content-Type: application/morse-sealed`, `Content-Length`, and `Host`, and nothing else: the SDK's `Accept`, `User-Agent`, `X-Stainless-*`, and `OpenAI-*` headers are dropped, and the clients ask for no compression and keep no cookies. Any other header raises, by name.
- The relay's four plain GETs (`/v1/models`, `/v1/attestation`, `/v1/receipts/{id}`, and `/v1/videos/{id}`) go with only `Authorization` and `Accept`.
- Anything else raises `NotSent`: `attested_client() won't send POST /v1/embeddings: the enclave can't seal it, so it would go out readable. Nothing was sent.` So does a request to any origin but its own, `https://api.trymorse.ai` unless `attested_client("https://…")` names another HTTPS one, a URL with a user or password, and a path with a `.` or `..` segment (plain or as `%2e`) or a backslash: `fetch` resolves those before `attested()` matches the route, and httpx would send them as written. [src/testdata/request_urls.json](https://github.com/trymorse/morse-verifier/blob/main/src/testdata/request_urls.json) is the table both clients' tests hold them to. A redirect, or a success the relay sends unsealed, raises `SealedReplyError`.
- `proxy=` is the proxy the requests go through. The checks' own requests read the usual `HTTPS_PROXY`, and `git` its own settings.

**The keys.** Before the first sealed request, and again once the oldest key's document is 30 minutes old by your clock, it reads `/v1/attestation`, Morse's signed list, and morse-enclave's `main`, and runs each document through the command line's own code for the first three checks. A key goes in only when every listed document that names it passed. It keeps up to four, newest first. Concurrent requests share one fetch, and every client of an origin in a process shares its keys. Each of the checks' requests is stopped once it has run 30 s and a piece of its reply arrives, or once it has waited 30 s for one, so none runs a minute; `git` gets 60 s. The async client runs a fetch of them on a thread and waits for it, and checks the keys it holds, on its event loop: a task cancelled while the checks run stops waiting, and they run on for the next request.

**Replies.** A sealed reply comes back with the enclave's status and headers, and a stream (`stream=True`) arrives as each frame opens. Its headers are taken as `fetch` takes them, so a Latin-1 value such as `filename=café.mp4` comes through, and a header `fetch` refuses raises `SealedReplyError`, as does a reply that ends before its final frame. A refusal the relay makes in the clear, such as a bad key, is returned as it is, so the SDK raises its own error for it. One 421 `sealed_key_unknown` and one sealed `sealed_stale` are retried, as the TypeScript client retries them. The SDK's timeout covers the sealed request.

**Errors.** When no key passes, or a check can't finish, it raises `VerifyError(step, reason, retryable)` and sends nothing. `step` is `"Attestation"`, `"Allowed"`, or `"Source"`; `retryable` is true when the check could not finish (the network, a rate limit, `git`). Its message ends `Nothing was sent.`, or after a retry `Nothing was sent but the first try, which was sealed to keys that had passed.` openai 3 raises these errors as they are. openai 1 and 2 retry the request twice by default and then raise `APIConnectionError`, whose `__cause__` is the error.

## Run the tests

```sh
uv run --locked pytest
VERIFY_LIVE=1 uv run --locked pytest   # also runs verify(), and attested_client() with a bogus key, against api.trymorse.ai
```

The tests read the TypeScript package's captures of prod from 2026-11-06 (`../src/testdata`), its golden outputs, the backend's seal vectors, the protocol's routes and headers as `protocol.json` lists them, and Morse's 40 forged pins bundles.

## License

MIT. See `LICENSE`.
