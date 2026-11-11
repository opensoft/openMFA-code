"""Required-config bridge to the owning wallet verifier; no default factor."""
from .core import METHOD, MFAError, VerifiedFactor, _digest, _integer, _ref


class WalletFactorVerifier:
    def __init__(self, *, registry, verify_proof):
        if not callable(getattr(registry, "resolve", None)) or not callable(verify_proof):
            raise MFAError("wallet-backend-unavailable")
        self.registry, self.verify_proof = registry, verify_proof

    def _binding(self, subject_ref, now):
        if not _ref(subject_ref) or not _integer(now):
            raise MFAError("invalid-factor")
        try:
            binding = self.registry.resolve(subject_ref, now=now)
            valid = (binding.subject_ref == subject_ref
                     and all(_ref(getattr(binding, name)) for name in
                             ("binding_ref", "wallet_ref", "key_ref", "custody_ref"))
                     and type(binding.public_key) is bytes and len(binding.public_key) == 32
                     and _integer(binding.revision) and type(binding.revoked) is bool
                     and not binding.revoked and _integer(binding.not_before)
                     and _integer(binding.expires_at) and binding.not_before <= now < binding.expires_at)
        except Exception:
            raise MFAError("wallet-registry-unavailable") from None
        if not valid:
            raise MFAError("invalid-factor")
        return binding

    def verify(self, challenge, response, now):
        if (challenge.method != METHOD or not _integer(now)
                or not challenge.issued_at <= now < challenge.expires_at or type(response) is not dict):
            raise MFAError("invalid-factor")
        binding = self._binding(challenge.subject_ref, now)
        try:
            facts = self.verify_proof(response, expected_digest=challenge.digest, binding=binding, now=now)
            refs = ("binding_ref", "wallet_ref", "key_ref", "subject_ref", "custody_ref")
            if (any(getattr(facts, field) != getattr(binding, field) for field in refs)
                    or not _integer(facts.binding_revision) or facts.binding_revision != binding.revision
                    or facts.challenge_digest != challenge.digest):
                raise ValueError("facts")
        except Exception:
            raise MFAError("wallet-proof-refused") from None
        return VerifiedFactor(binding.subject_ref, binding.binding_ref, binding.revision,
                              challenge.digest, min(binding.expires_at, challenge.expires_at))

    def current(self, factor, now):
        if (not isinstance(factor, VerifiedFactor) or not _integer(factor.binding_revision)
                or not _ref(factor.binding_ref) or not _digest(factor.challenge_digest)
                or not _integer(factor.valid_until) or not _integer(now) or now >= factor.valid_until):
            return False
        binding = self._binding(factor.subject_ref, now)
        return binding.binding_ref == factor.binding_ref and binding.revision == factor.binding_revision
