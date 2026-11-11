"""Bridge unit tests use explicit trusted doubles; isolated qualification uses real wallet crypto."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from openmfa_runtime import CallerContext, Challenge, MFAError, VerifiedFactor
from openmfa_runtime.core import METHOD
from openmfa_runtime.wallet_factor import WalletFactorVerifier


@pytest.fixture
def configured():
    challenge = Challenge("challenge:1", "issuer:1", "caller:1", "tenant:1", "audience:1",
                          "subject:a", "a" * 43, METHOD, 1000, 1120, "sha256:" + "a" * 64)
    binding = SimpleNamespace(subject_ref="subject:a", binding_ref="binding:a",
                              wallet_ref="wallet:a", key_ref="key:a", custody_ref="custody:a",
                              public_key=b"k" * 32, revision=3, not_before=900, expires_at=1100, revoked=False)

    class Registry:
        active = binding

        def resolve(self, subject_ref, *, now):
            assert subject_ref == challenge.subject_ref
            return self.active

    def verify(proof, *, expected_digest, binding, now):
        assert proof == {"explicit": "unit-fixture-only"}
        assert expected_digest == challenge.digest
        return SimpleNamespace(**{name: getattr(binding, name) for name in
                                  ("binding_ref", "wallet_ref", "key_ref", "subject_ref", "custody_ref")},
                               binding_revision=binding.revision, challenge_digest=expected_digest)

    registry = Registry()
    return challenge, binding, registry, verify


def test_required_backend_and_valid_mapping(configured):
    challenge, binding, registry, verify = configured
    adapter = WalletFactorVerifier(registry=registry, verify_proof=verify)
    factor = adapter.verify(challenge, {"explicit": "unit-fixture-only"}, 1000)
    assert factor == VerifiedFactor("subject:a", "binding:a", 3, challenge.digest, 1100)
    assert adapter.current(factor, 1000)
    with pytest.raises(MFAError, match="wallet-backend-unavailable"):
        WalletFactorVerifier(registry=registry, verify_proof=None)


@pytest.mark.parametrize("change", [
    {"revoked": True}, {"revision": True}, {"expires_at": 1000}, {"not_before": 1001},
    {"subject_ref": "other"}, {"binding_ref": ""}, {"public_key": b"bad"},
])
def test_invalid_registry_facts_cannot_mint_factor(configured, change):
    challenge, binding, registry, verify = configured
    registry.active = SimpleNamespace(**{**vars(binding), **change})
    with pytest.raises(MFAError):
        WalletFactorVerifier(registry=registry, verify_proof=verify).verify(challenge, {}, 1000)


@pytest.mark.parametrize("change", [
    {"subject_ref": "other"}, {"custody_ref": "other"}, {"key_ref": "other"},
    {"wallet_ref": "other"}, {"binding_ref": "other"}, {"binding_revision": True},
    {"binding_revision": 4}, {"challenge_digest": "sha256:" + "0" * 64},
])
def test_mismatched_verified_facts_refuse(configured, change):
    challenge, binding, registry, verify = configured

    def wrong(*args, **kwargs):
        facts = verify(*args, **kwargs)
        return SimpleNamespace(**{**vars(facts), **change})

    with pytest.raises(MFAError, match="wallet-proof-refused"):
        WalletFactorVerifier(registry=registry, verify_proof=wrong).verify(
            challenge, {"explicit": "unit-fixture-only"}, 1000)


def test_unavailable_registry_and_crypto_errors_are_sanitized(configured):
    challenge, _, registry, verify = configured

    def unavailable(*args, **kwargs):
        raise RuntimeError("private backend details")

    registry.resolve = unavailable
    with pytest.raises(MFAError) as result:
        WalletFactorVerifier(registry=registry, verify_proof=verify).verify(challenge, {}, 1000)
    assert str(result.value) == "wallet-registry-unavailable"
    _, _, registry, _ = configured
    registry.resolve = lambda *args, **kwargs: configured[1]
    with pytest.raises(MFAError) as result:
        WalletFactorVerifier(registry=registry, verify_proof=unavailable).verify(challenge, {}, 1000)
    assert str(result.value) == "wallet-proof-refused"


def test_rotation_revocation_and_expiry_fail_current_check(configured):
    challenge, binding, registry, verify = configured
    adapter = WalletFactorVerifier(registry=registry, verify_proof=verify)
    factor = adapter.verify(challenge, {"explicit": "unit-fixture-only"}, 1000)
    registry.active = SimpleNamespace(**{**vars(binding), "revision": 4})
    assert adapter.current(factor, 1000) is False
    registry.active = binding
    assert adapter.current(factor, 1100) is False
    registry.active = SimpleNamespace(**{**vars(binding), "revoked": True})
    with pytest.raises(MFAError):
        adapter.current(factor, 1000)


def test_unrelated_method_and_expired_challenge_refuse(configured):
    challenge, _, registry, verify = configured
    adapter = WalletFactorVerifier(registry=registry, verify_proof=verify)
    for value in (replace(challenge, method="human"), replace(challenge, expires_at=1000)):
        with pytest.raises(MFAError, match="invalid-factor"):
            adapter.verify(value, {}, 1000)
