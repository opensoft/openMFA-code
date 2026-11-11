"""State-machine tests use an explicit test double; receipt crypto is real.

These tests are not wallet-factor qualification or attended MFA acceptance.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import base64
import json
import rfc8785
import sqlite3
from threading import Lock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from openmfa_runtime import (
    CallerContext, ChallengeService, IssuerKey, MFAError, VerifiedFactor, verify_receipt,
)

OP = "sha256:" + "a"*64
RESPONSE = {"fixture":"not-a-real-factor:fixture-only"}


class Clock:
    now = 1000
    def __call__(self):
        return self.now


class StateTestVerifier:
    """Synthetic state-test fixture only, never a production factor verifier."""
    active = True
    def verify(self, challenge, response, now):
        if response != RESPONSE:
            raise ValueError("invalid fixture")
        return VerifiedFactor(challenge.subject_ref,"binding:fixture",3,challenge.digest,2000)
    def current(self, factor, now):
        return self.active and factor.binding_revision==3


class CountingSigner:
    def __init__(self, key):
        self.key=key
        self.calls=0
        self.lock=Lock()
    def sign(self, message):
        with self.lock:
            self.calls+=1
        return self.key.sign(message)


@pytest.fixture
def setup(tmp_path):
    private=Ed25519PrivateKey.generate()
    key=IssuerKey("issuer:fixture","issuer-key:fixture",
                  private.public_key().public_bytes_raw(),900,2000)
    clock=Clock()
    verifier=StateTestVerifier()
    signer=CountingSigner(private)
    path=tmp_path/"state.sqlite"
    service=ChallengeService(path,issuer_key=key,signer=signer,verifier=verifier,clock=clock)
    caller=CallerContext("caller:fixture","tenant:fixture","audience:fixture")
    return service,caller,key,clock,verifier,signer,path


def issued(setup, **kwargs):
    service,caller,*_=setup
    return service.create(caller,"subject:fixture",request_digest=OP,**kwargs)


def verified(setup):
    service,caller,*_=setup
    challenge=issued(setup)
    receipt=service.verify(caller,challenge.id,RESPONSE,idempotency_key="verify:1")
    return challenge,receipt


def test_bound_challenge_and_real_signed_receipt(setup):
    service,caller,key,clock,*_=setup
    challenge,receipt=verified(setup)
    result=verify_receipt(receipt,issuer_key=key,challenge=challenge,caller=caller,now=clock.now)
    assert result.subject_ref=="subject:fixture"
    assert receipt["verified_methods"]==["wallet-ed25519-possession.v0"]
    assert receipt["expires_at"]==1060
    assert len(challenge.nonce)>=43
    assert receipt["request_digest"]==OP


def test_no_backend_or_self_asserted_verification_can_mint_a_receipt(setup):
    service,caller,key,clock,_,signer,path=setup
    no_backend=ChallengeService(path,issuer_key=key,signer=signer,clock=clock)
    challenge=issued(setup)
    with pytest.raises(MFAError,match="verifier-unavailable"):
        no_backend.verify(caller,challenge.id,{"verified":True},idempotency_key="verify:1")
    assert signer.calls==0
    assert service.outcome(caller,challenge.id)["state"]=="issued"


@pytest.mark.parametrize("change", [
    {"caller_ref":"other"},{"tenant":"other"},{"audience":"other"},
])
def test_other_caller_context_cannot_verify_inspect_or_consume(setup,change):
    service,caller,*_=setup
    challenge,receipt=verified(setup)
    other=replace(caller,**change)
    for call in [
        lambda:service.verify(other,challenge.id,RESPONSE,idempotency_key="verify:1"),
        lambda:service.outcome(other,challenge.id),
        lambda:service.consume(other,receipt["id"],operation_digest=OP,idempotency_key="consume:1"),
    ]:
        with pytest.raises(MFAError,match="not-found"):
            call()


@pytest.mark.parametrize("kwargs", [
    {"required_assurance":"mfa"},{"required_assurance":"human"},
    {"method":"webauthn"},{"ttl":121},{"ttl":True},{"ttl":0},
])
def test_unsupported_assurance_and_invalid_bounds_refuse(setup,kwargs):
    service,caller,*_=setup
    with pytest.raises(MFAError):
        service.create(caller,"subject:fixture",**kwargs)


def test_nonce_and_digest_change_for_each_challenge(setup):
    service,caller,*_=setup
    first=issued(setup)
    second=issued(setup)
    assert first.nonce!=second.nonce and first.digest!=second.digest
    assert first.id!=second.id


def test_verification_retry_is_stable_and_conflicts_do_not_remint(setup):
    service,caller,_,clock,_,signer,_=setup
    challenge,receipt=verified(setup)
    clock.now=1201
    assert service.verify(caller,challenge.id,RESPONSE,idempotency_key="verify:1")==receipt
    assert signer.calls==1
    for response,key in [({"different":True},"verify:1"),(RESPONSE,"verify:2")]:
        with pytest.raises(MFAError,match="idempotency-conflict"):
            service.verify(caller,challenge.id,response,idempotency_key=key)


def test_idempotency_key_is_scoped_and_cannot_move_to_another_challenge(setup):
    service,caller,*_=setup
    verified(setup)
    second=issued(setup)
    with pytest.raises(MFAError,match="idempotency-conflict"):
        service.verify(caller,second.id,RESPONSE,idempotency_key="verify:1")


def test_one_consumption_stable_retry_and_changed_operation_refuses(setup):
    service,caller,_,clock,*_=setup
    challenge,receipt=verified(setup)
    outcome=service.consume(caller,receipt["id"],operation_digest=OP,idempotency_key="consume:1")
    clock.now=1300
    assert service.consume(caller,receipt["id"],operation_digest=OP,idempotency_key="consume:1")==outcome
    assert service.outcome(caller,challenge.id)["state"]=="consumed"
    with pytest.raises(MFAError,match="idempotency-conflict"):
        service.consume(caller,receipt["id"],operation_digest="sha256:"+"b"*64,idempotency_key="consume:1")


def test_expired_evidence_cannot_authorize_a_new_consumption(setup):
    service,caller,key,clock,*_=setup
    challenge,receipt=verified(setup)
    clock.now=1060
    with pytest.raises(MFAError):
        verify_receipt(receipt,issuer_key=key,challenge=challenge,caller=caller,now=clock.now)
    with pytest.raises(MFAError):
        service.consume(caller,receipt["id"],operation_digest=OP,idempotency_key="consume:1")


def test_unbound_authentication_receipt_cannot_be_used_as_operation_evidence(setup):
    service,caller,*_=setup
    challenge=service.create(caller,"subject:fixture")
    receipt=service.verify(caller,challenge.id,RESPONSE,idempotency_key="verify:1")
    with pytest.raises(MFAError,match="request-binding-mismatch"):
        service.consume(caller,receipt["id"],operation_digest=OP,idempotency_key="consume:1")


def test_local_or_backend_revocation_prevents_fresh_use(setup):
    service,caller,_,_,verifier,*_=setup
    _,receipt=verified(setup)
    verifier.active=False
    with pytest.raises(MFAError,match="revoked-binding"):
        service.consume(caller,receipt["id"],operation_digest=OP,idempotency_key="consume:1")
    verifier.active=True
    service.revoke_binding("binding:fixture")
    with pytest.raises(MFAError,match="invalid-factor"):
        service.consume(caller,receipt["id"],operation_digest=OP,idempotency_key="consume:1")


def test_cancel_and_expiry_prevent_new_verification(setup):
    service,caller,_,clock,_,signer,_=setup
    first=issued(setup)
    service.cancel(caller,first.id)
    with pytest.raises(MFAError,match="cancelled"):
        service.verify(caller,first.id,RESPONSE,idempotency_key="verify:1")
    second=issued(setup)
    clock.now=second.expires_at
    with pytest.raises(MFAError,match="expired"):
        service.verify(caller,second.id,RESPONSE,idempotency_key="verify:2")
    assert service.outcome(caller,second.id)["state"]=="expired"
    assert signer.calls==0


def test_concurrent_verification_has_one_signed_receipt(setup):
    service,caller,_,_,_,signer,path=setup
    challenge=issued(setup)
    def run(_):
        return service.verify(caller,challenge.id,RESPONSE,idempotency_key="verify:1")
    with ThreadPoolExecutor(max_workers=2) as workers:
        receipts=list(workers.map(run,range(2)))
    assert receipts[0]==receipts[1] and signer.calls==1
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM challenges WHERE receipt_id IS NOT NULL").fetchone()[0]==1


def test_concurrent_consumption_and_restart_return_one_durable_outcome(setup):
    service,caller,key,clock,verifier,signer,path=setup
    _,receipt=verified(setup)
    other=ChallengeService(path,issuer_key=key,signer=signer,verifier=verifier,clock=clock)
    def run(engine):
        return engine.consume(caller,receipt["id"],operation_digest=OP,idempotency_key="consume:1")
    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes=list(workers.map(run,[service,other]))
    assert outcomes[0]==outcomes[1]
    assert run(other)==outcomes[0]


@pytest.mark.parametrize("field", [
    "issuer","key_ref","subject_ref","caller_ref","tenant","audience",
    "challenge_digest","request_digest","binding_ref","id",
])
def test_receipt_tampering_refuses(setup,field):
    _,caller,key,clock,*_=setup
    challenge,receipt=verified(setup)
    receipt[field]="tampered"
    with pytest.raises(MFAError):
        verify_receipt(receipt,issuer_key=key,challenge=challenge,caller=caller,now=clock.now)


def test_unrecognized_claims_and_method_upgrade_refuse(setup):
    _,caller,key,clock,*_=setup
    challenge,receipt=verified(setup)
    for altered in [{**receipt,"mfa":True},{**receipt,"verified_methods":["mfa"]}]:
        with pytest.raises(MFAError):
            verify_receipt(altered,issuer_key=key,challenge=challenge,caller=caller,now=clock.now)


def test_failed_signing_rolls_back_verification_state(setup):
    service,caller,key,clock,verifier,_,path=setup
    class BadSigner:
        def sign(self,_message):
            raise RuntimeError("sensitive backend detail")
    bad=ChallengeService(path,issuer_key=key,signer=BadSigner(),verifier=verifier,clock=clock)
    challenge=issued(setup)
    with pytest.raises(MFAError,match="signer-unavailable"):
        bad.verify(caller,challenge.id,RESPONSE,idempotency_key="verify:1")
    assert service.outcome(caller,challenge.id)=={"id":challenge.id,"state":"issued","receipt_id":None}


def test_raw_factor_response_is_not_persisted(setup):
    *_,path=setup
    verified(setup)
    with sqlite3.connect(path) as db:
        values=db.execute("SELECT data,receipt,response_digest FROM challenges").fetchone()
    assert RESPONSE["fixture"] not in json.dumps(values)


def test_persistent_store_and_clock_are_required(setup):
    service,caller,key,clock,verifier,signer,_=setup
    with pytest.raises(MFAError,match="persistent-store-required"):
        ChallengeService(":memory:",issuer_key=key,signer=signer)
    clock.now=True
    with pytest.raises(MFAError,match="clock-unavailable"):
        service.create(caller,"subject:fixture")


def test_binding_check_latency_cannot_extend_receipt_lifetime(setup):
    service,caller,_,clock,verifier,*_=setup
    challenge,receipt=verified(setup)
    def slow_current(factor,now):
        clock.now=receipt["expires_at"]
        return True
    verifier.current=slow_current
    with pytest.raises(MFAError):
        service.consume(caller,receipt["id"],operation_digest=OP,idempotency_key="consume:1")
    assert service.outcome(caller,challenge.id)["state"]=="verified"


def test_valid_signature_does_not_override_receipt_lifetime_policy(setup):
    _,caller,key,clock,_,signer,_=setup
    challenge,receipt=verified(setup)
    receipt["expires_at"]=challenge.expires_at
    unsigned={k:v for k,v in receipt.items() if k!="signature"}
    receipt["signature"]=base64.urlsafe_b64encode(
        signer.key.sign(b"openMFA.receipt.v0\x00"+rfc8785.dumps(unsigned))
    ).rstrip(b"=").decode()
    with pytest.raises(MFAError,match="invalid-receipt"):
        verify_receipt(receipt,issuer_key=key,challenge=challenge,caller=caller,now=clock.now)


def test_receipt_issued_before_key_activation_refuses(setup):
    _,caller,key,clock,*_=setup
    challenge,receipt=verified(setup)
    with pytest.raises(MFAError,match="invalid-receipt"):
        verify_receipt(receipt,issuer_key=replace(key,not_before=1001),
                       challenge=challenge,caller=caller,now=1010)
