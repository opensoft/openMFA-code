# Candidate challenge and receipt core

Status: draft implementation; no accepted runtime release or live MFA claim.

`openmfa_runtime` implements caller-bound challenges, real Ed25519 issuer receipts and file-backed SQLite state. CallerContext is supplied by an authenticated adapter, never copied from untrusted claims. The operator owns and protects a persistent file dedicated to one issuer. FactorVerifier is a trusted server extension and is absent by default. Without it, verification refuses. Only the possession method is implemented; MFA and human assurance requests refuse.

The canonical candidate challenge and receipt schemas belong to `opensoft/openMFA-spec` under `contracts/`. The implementation contains strict protocol checks, not a copied schema or a sibling checkout read. Governance and the sole task list belong to feature `001-challenge-receipt-core` in that spec leg.

## Local checks

Use an isolated environment in the declared development bench, from this code leg:

```sh
pip install -e . pytest
python -m pytest tests/ -q
```

State tests deliberately use a named synthetic factor verifier; issuer receipt signatures are real. This is state-machine qualification, not real factor acceptance. Tests cover rollback, concurrent/restarted use, conflicts, cancellation, expiry and revocation. Private issuer keys stay behind the supplied signing interface; test keys are ephemeral.

## Trust and limits

Verification retries return the original receipt unchanged, even after expiry; online consumption is the current-validity and one-use gate. A consumed retry reads its existing acknowledgement rather than making another decision. Fresh use checks current binding and expiry again after a potentially slow backend call. Local revocation is a persistent tombstone. Remote introspection is point-in-time and cannot by itself fence a domain effect. The SQLite acknowledgement is not atomic with an external domain transaction. Network authentication, rate limits, audit retention, custody and real provider adapters remain future work.

A proof or receipt confers no permission, human presence, MFA assurance, exact-request consent or composition attestation. Real custody, provider/discovery and human adapters, compatibility vectors, accepted assembly pins and attended QA remain separate gates. Development package version `0.0.0.dev0` allocates no release. Consumers pin the assembly root after reviewed leg merges; no leg is tagged.
