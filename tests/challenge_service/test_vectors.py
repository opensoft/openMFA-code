"""Independent digest/signature answers; fixture factors do not qualify MFA."""
import base64
from dataclasses import replace
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from openmfa_runtime import (
    CallerContext, ChallengeService, IssuerKey, MFAError, VerifiedFactor, verify_receipt,
)
from openmfa_runtime.core import Challenge

VECTORS = json.loads(Path(__file__).with_name("vectors.json").read_text(encoding="utf-8"))


@pytest.fixture(params=VECTORS, ids=lambda vector: vector["name"])
def vector(request):
    return request.param


def context_for(vector):
    challenge = Challenge(**{k: v for k, v in vector["challenge"].items() if k != "profile"})
    caller = CallerContext(**vector["caller"])
    issuer = IssuerKey(challenge.issuer, vector["receipt"]["key_ref"],
                       bytes.fromhex(vector["public_key_hex"]), 900, 2000)
    return challenge, caller, issuer


def test_independent_digest_and_receipt_verify(vector):
    challenge, caller, issuer = context_for(vector)
    assert challenge.record() == vector["challenge"]
    assert challenge.digest == vector["challenge_digest"]
    result = verify_receipt(vector["receipt"], issuer_key=issuer, challenge=challenge, caller=caller, now=1005)
    assert result.binding_revision == vector["receipt"]["binding_revision"]
    assert result.valid_until == 1065


def test_actual_service_matches_independent_challenge_and_receipt(vector, tmp_path, monkeypatch):
    expected_challenge, caller, issuer = context_for(vector)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["public_test_seed_hex"]))
    assert key.public_key().public_bytes_raw().hex() == vector["public_key_hex"]
    ids = iter((expected_challenge.id, vector["receipt"]["id"]))
    monkeypatch.setattr("openmfa_runtime.core.uuid.uuid4", lambda: next(ids))
    monkeypatch.setattr("openmfa_runtime.core.secrets.token_urlsafe", lambda _n: expected_challenge.nonce)
    clock = [1000]

    class CheckedSigner:
        def sign(self, message):
            assert message.hex() == vector["message_hex"]
            assert message == b"openMFA.receipt.v0\0" + vector["unsigned_canonical_utf8"].encode()
            return key.sign(message)

    class ExplicitFixtureFactor:
        def verify(self, challenge, response, now):
            assert response == {"fixture": "independent-vector-only"}
            return VerifiedFactor(challenge.subject_ref, vector["receipt"]["binding_ref"],
                                  vector["receipt"]["binding_revision"], challenge.digest, 2000)

        def current(self, factor, now):
            return factor.binding_ref == vector["receipt"]["binding_ref"]

    service = ChallengeService(tmp_path / "state.sqlite", issuer_key=issuer,
                               signer=CheckedSigner(), verifier=ExplicitFixtureFactor(), clock=lambda: clock[0])
    challenge = service.create(caller, expected_challenge.subject_ref, request_digest=expected_challenge.request_digest)
    assert challenge.record() == vector["challenge"]
    clock[0] = 1005
    receipt = service.verify(caller, challenge.id, {"fixture": "independent-vector-only"}, idempotency_key="verify:vector")
    assert receipt == vector["receipt"]
    assert service.verify(caller, challenge.id, {"fixture": "independent-vector-only"}, idempotency_key="verify:vector") == receipt


@pytest.mark.parametrize("message_change", ["wrong-domain", "changed-byte"])
def test_independently_signed_wrong_receipt_preimages_refuse(vector, message_change):
    challenge, caller, issuer = context_for(vector)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["public_test_seed_hex"]))
    message = bytes.fromhex(vector["message_hex"])
    changed = (b"other-protocol\0" + vector["unsigned_canonical_utf8"].encode()
               if message_change == "wrong-domain" else message[:-1] + b" ")
    receipt = {**vector["receipt"], "signature": base64.urlsafe_b64encode(key.sign(changed)).rstrip(b"=").decode()}
    with pytest.raises(MFAError, match="invalid-receipt"):
        verify_receipt(receipt, issuer_key=issuer, challenge=challenge, caller=caller, now=1005)


def test_fixed_receipt_does_not_bypass_context_expiry_or_key_revocation(vector):
    challenge, caller, issuer = context_for(vector)
    with pytest.raises(MFAError, match="invalid-receipt"):
        verify_receipt(vector["receipt"], issuer_key=issuer, challenge=challenge,
                       caller=replace(caller, tenant="tenant:other"), now=1005)
    with pytest.raises(MFAError, match="invalid-receipt"):
        verify_receipt(vector["receipt"], issuer_key=issuer, challenge=challenge, caller=caller, now=1065)
    with pytest.raises(MFAError, match="issuer-key-unavailable"):
        verify_receipt(vector["receipt"], issuer_key=replace(issuer, revoked=True),
                       challenge=challenge, caller=caller, now=1005)
