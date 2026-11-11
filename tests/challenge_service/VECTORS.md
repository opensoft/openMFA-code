# Candidate challenge and receipt compatibility vectors

`vectors.json` is a fixed known-answer corpus generated independently by
`generate_vectors.cjs` using Node crypto/OpenSSL. It imports neither Python
nor the candidate runtime/canonicalizer. Its restricted canonicalizer handles
only the fixture's strings, nonnegative safe integers, arrays, objects and
null. This is not a general RFC 8785 implementation. Cases cover null versus
bound request digests, Unicode UTF-8 and the maximum safe binding revision.

All seeds are deliberately public test material and must never be used in
real custody. The corpus exposes exact challenge canonical bytes and SHA-256
digests, receipt canonical preimages, domain-separated messages, public keys
and deterministic Ed25519 signatures.

From this code leg:

```sh
node tests/challenge_service/generate_vectors.cjs
python -m pytest tests/challenge_service/test_vectors.py -q
```

The Node command checks complete reproduction and refuses drift. Regeneration
requires the explicit `--write` option. Initial generation used Node 24.21.0;
the normal Python gate reads the static corpus without requiring Node.

Tests verify independently produced receipts, compare real service challenge
hashes and issuer signatures with fixed answers, and refuse signed wrong-domain
or changed-byte preimages, caller mismatch, expiry and issuer revocation.
Service issuance uses an explicitly named fixture factor and deterministic
test-only nonce/ID replacements. Those replacements never touch production
code. No real wallet backend, custody, MFA, human approval, online one-use
qualification or external domain effect is established by these vectors.
