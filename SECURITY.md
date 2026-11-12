# Security

If `npx @askmorse/verify`, `verify()`, `attested()`, or the browser core passes what it should refuse, report it privately. Examples are an attestation document that AWS did not sign, an image Morse's signed list doesn't allow or has revoked, a Sigstore bundle signed by anyone but Morse's pins workflow, a release whose commit on `main` names other PCRs, a rebuild that passes with PCRs other than the attested ones, a revoked pin that still passes `verifyInstances`, a reply that opens under the wrong key, or a request `attested()` seals to a key that didn't pass every check, or sends readable. A verifier that prints a claim it didn't check counts too. Do not open a public issue.

Report it through this repository's **Security** tab, under **Report a vulnerability**, or by email to hello@trymorse.ai. Say which version or tag you looked at and how to reproduce the problem.

We aim to acknowledge reports within 3 business days. We tell you what we found, and when a fix ships we credit you in its release unless you ask us not to.
