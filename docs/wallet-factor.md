# Wallet factor and isolated compatibility

`WalletFactorVerifier` requires an explicit trusted registry and the owning
openWallet `verify_proof` callable. It has no default verified backend. The
adapter resolves by the challenge's trusted subject, checks the actual wallet
signature through the owning package and compares all returned facts with the
current binding and expected challenge digest. Factor validity is capped by
binding/challenge validity. Fresh use resolves the binding again and refuses
missing, expired, revoked or rotated records and unavailable dependencies.

The adapter does not copy wallet signature math or import a sibling checkout.
Server composition supplies its owning implementation. The code-leg unit gate
uses explicitly named bridge doubles only; it is not real-factor qualification.
The separately invoked `qualification/run_isolated.py` tool supplies actual
owning packages from explicitly validated complete assembly sources.

The assembly gate checks exact repository/root commit/tree, clean leg
checkouts, gitlink/pin agreement and tree digests, shape-copy hashes, ratified
contract hashes and canonical root validators. Installed runtime modules must
match all selected source module bytes and declared crypto dependencies.
Missing dependencies fail. Nothing auto-discovers a sibling or silently skips.

The reference qualification uses distinct custody, verifier and agent
containers. Wallet keys remain in custody state; issuer keys and registry-only
credentials remain with the verifier. The agent has only its subject-scoped
client credential. The trusted driver transports public challenge/proof/receipt
JSON and performs test administration. It is not a product identity broker.
Actual signatures, authenticated transport, refusals, durable retry/restart
and resource absence after cleanup are recorded as source conformance.

This does not qualify live custody, workload composition, a human broker,
MFA, exact-request human approval or a domain effect. Remote revocation
remains point-in-time and receipt consumption is not an atomic external effect.
Unmerged source-conformance inputs do not become accepted product pins.
