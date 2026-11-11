"""Caller-bound state and signed authentication evidence.

No factor backend is enabled by default. Configured verifiers are trusted
server components, not request data. This candidate implements no HTTP
authentication, custody broker, WebAuthn/OIDC adapter or domain permission.
Stateless signature verification does not prove one-use; use online consume.
"""
from __future__ import annotations
import base64
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Protocol
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import rfc8785

CHALLENGE_PROFILE = "openmfa.challenge.v0"
RECEIPT_PROFILE = "openmfa.verification-receipt.v0"
METHOD = "wallet-ed25519-possession.v0"
_CONTEXT = b"openMFA.receipt.v0\x00"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SIG = re.compile(r"[A-Za-z0-9_-]{86}\Z")
_MAX_INT = 2**53 - 1


class MFAError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _ref(value):
    return (
        type(value) is str and 0 < len(value) <= 256 and value == value.strip()
        and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    )


def _integer(value):
    return type(value) is int and 0 <= value <= _MAX_INT


def _digest(value):
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _canonical(value):
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, TypeError, ValueError, RecursionError):
        raise MFAError("invalid-data") from None


@dataclass(frozen=True, slots=True)
class CallerContext:
    """Construct only after authenticating the relying party at its adapter."""
    caller_ref: str
    tenant: str
    audience: str

    def namespace(self):
        if not all(_ref(v) for v in asdict(self).values()):
            raise MFAError("invalid-caller")
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True, slots=True)
class Challenge:
    id: str
    issuer: str
    caller_ref: str
    tenant: str
    audience: str
    subject_ref: str
    nonce: str
    method: str
    issued_at: int
    expires_at: int
    request_digest: str | None

    def record(self):
        return {"profile": CHALLENGE_PROFILE, **asdict(self)}

    @property
    def digest(self):
        return "sha256:" + hashlib.sha256(_canonical(self.record())).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifiedFactor:
    """Returned by a trusted verifier after checking real factor evidence."""
    subject_ref: str
    binding_ref: str
    binding_revision: int
    challenge_digest: str
    valid_until: int


class FactorVerifier(Protocol):
    def verify(self, challenge: Challenge, response: dict, now: int) -> VerifiedFactor: ...
    def current(self, factor: VerifiedFactor, now: int) -> bool: ...


@dataclass(frozen=True, slots=True)
class IssuerKey:
    issuer: str
    key_ref: str
    public_key: bytes
    not_before: int
    expires_at: int
    revoked: bool = False


def _issuer_key(key, now):
    if (
        not isinstance(key, IssuerKey) or not _integer(now)
        or not _ref(key.issuer) or not _ref(key.key_ref)
        or type(key.public_key) is not bytes or len(key.public_key) != 32
        or not _integer(key.not_before) or not _integer(key.expires_at)
        or type(key.revoked) is not bool or key.revoked
        or not key.not_before <= now < key.expires_at
    ):
        raise MFAError("issuer-key-unavailable")


_RECEIPT_FIELDS = frozenset((
    "profile", "alg", "id", "issuer", "key_ref", "subject_ref", "caller_ref",
    "tenant", "audience", "challenge_digest", "request_digest",
    "verified_methods", "verified_at", "expires_at", "binding_ref",
    "binding_revision", "signature",
))


def verify_receipt(receipt, *, issuer_key, challenge, caller, now):
    """Verify crypto, freshness and expected bindings, not online consumption."""
    _issuer_key(issuer_key, now)
    caller.namespace()
    if type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS:
        raise MFAError("invalid-receipt")
    if (
        receipt["profile"] != RECEIPT_PROFILE or receipt["alg"] != "Ed25519"
        or receipt["issuer"] != issuer_key.issuer or receipt["key_ref"] != issuer_key.key_ref
        or challenge.issuer != issuer_key.issuer
        or receipt["verified_methods"] != [METHOD]
        or receipt["challenge_digest"] != challenge.digest
        or receipt["subject_ref"] != challenge.subject_ref
        or receipt["request_digest"] != challenge.request_digest
        or any(receipt[k] != getattr(caller,k) or getattr(challenge,k) != getattr(caller,k)
               for k in ("caller_ref","tenant","audience"))
        or not all(_ref(receipt[k]) for k in ("id","subject_ref","binding_ref"))
        or not _integer(receipt["binding_revision"])
        or not _integer(receipt["verified_at"]) or not _integer(receipt["expires_at"])
        or not challenge.issued_at <= receipt["verified_at"] <= now < receipt["expires_at"]
        or receipt["verified_at"] < issuer_key.not_before
        or receipt["expires_at"] > receipt["verified_at"] + 60
        or receipt["expires_at"] > min(challenge.expires_at, issuer_key.expires_at)
        or type(receipt["signature"]) is not str or _SIG.fullmatch(receipt["signature"]) is None
    ):
        raise MFAError("invalid-receipt")
    try:
        signature = base64.b64decode(receipt["signature"]+"==",altchars=b"-_",validate=True)
        if len(signature)!=64 or base64.urlsafe_b64encode(signature).rstrip(b"=").decode()!=receipt["signature"]:
            raise MFAError("invalid-receipt")
        unsigned = {k:v for k,v in receipt.items() if k!="signature"}
        Ed25519PublicKey.from_public_bytes(issuer_key.public_key).verify(
            signature, _CONTEXT+_canonical(unsigned))
    except (InvalidSignature, ValueError, TypeError):
        raise MFAError("invalid-receipt") from None
    return VerifiedFactor(
        receipt["subject_ref"], receipt["binding_ref"], receipt["binding_revision"],
        receipt["challenge_digest"], receipt["expires_at"],
    )


class ChallengeService:
    """File-backed candidate engine; caller and backend authentication are external."""

    def __init__(self, path, *, issuer_key, signer, verifier=None, clock=None):
        if str(path)==":memory:" or str(path).startswith("file:"):
            raise MFAError("persistent-store-required")
        self.path = str(Path(path))
        self.issuer_key = issuer_key
        self.signer = signer
        self.verifier = verifier
        self.clock = clock if clock is not None else (lambda: int(time.time()))
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS challenges(
                  id TEXT PRIMARY KEY, namespace TEXT NOT NULL, data TEXT NOT NULL,
                  state TEXT NOT NULL, verify_key TEXT, response_digest TEXT,
                  receipt_id TEXT UNIQUE, receipt TEXT, consume_key TEXT,
                  operation_digest TEXT, outcome TEXT);
                CREATE UNIQUE INDEX IF NOT EXISTS verification_keys
                  ON challenges(namespace,verify_key) WHERE verify_key IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS consumption_keys
                  ON challenges(namespace,consume_key) WHERE consume_key IS NOT NULL;
                CREATE TABLE IF NOT EXISTS revoked_bindings(binding_ref TEXT PRIMARY KEY);
            """)

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _now(self):
        now = self.clock()
        if not _integer(now):
            raise MFAError("clock-unavailable")
        return now

    @staticmethod
    def _challenge(row):
        data = json.loads(row["data"])
        if data.pop("profile",None)!=CHALLENGE_PROFILE:
            raise MFAError("unsupported-profile")
        return Challenge(**data)

    def _bound(self, db, caller, challenge_id):
        namespace = caller.namespace()
        row = db.execute("SELECT * FROM challenges WHERE id=? AND namespace=?",
                         (challenge_id,namespace)).fetchone()
        if row is None:
            raise MFAError("not-found")
        return row, self._challenge(row)

    def _active(self, row, challenge, now):
        if row["state"]=="cancelled":
            raise MFAError("cancelled")
        if not challenge.issued_at <= now < challenge.expires_at:
            raise MFAError("expired")

    def create(self, caller, subject_ref, *, method=METHOD, required_assurance="possession",
               request_digest=None, ttl=120):
        namespace = caller.namespace()
        now = self._now()
        _issuer_key(self.issuer_key,now)
        if method!=METHOD or required_assurance!="possession":
            raise MFAError("unsupported-assurance")
        if not _ref(subject_ref) or type(ttl) is not int or not 1<=ttl<=120:
            raise MFAError("invalid-challenge")
        if request_digest is not None and not _digest(request_digest):
            raise MFAError("invalid-request-digest")
        expires = min(now+ttl,self.issuer_key.expires_at)
        challenge = Challenge(
            str(uuid.uuid4()), self.issuer_key.issuer, caller.caller_ref,caller.tenant,
            caller.audience,subject_ref,secrets.token_urlsafe(32),method,now,expires,request_digest)
        with self._transaction() as db:
            db.execute("INSERT INTO challenges(id,namespace,data,state) VALUES(?,?,?,?)",
                       (challenge.id,namespace,_canonical(challenge.record()).decode(),"issued"))
        return challenge

    def _current(self, db, factor, challenge, now):
        if (
            not isinstance(factor,VerifiedFactor)
            or factor.subject_ref!=challenge.subject_ref
            or factor.challenge_digest!=challenge.digest
            or not _ref(factor.binding_ref) or not _integer(factor.binding_revision)
            or not _integer(factor.valid_until) or factor.valid_until<=now
            or db.execute("SELECT 1 FROM revoked_bindings WHERE binding_ref=?",
                          (factor.binding_ref,)).fetchone()
        ):
            raise MFAError("invalid-factor")
        if self.verifier is None:
            raise MFAError("verifier-unavailable")
        try:
            current = self.verifier.current(factor,now)
        except Exception:
            raise MFAError("verifier-unavailable") from None
        if current is not True:
            raise MFAError("revoked-binding")

    def verify(self, caller, challenge_id, response, *, idempotency_key):
        if not _ref(idempotency_key) or type(response) is not dict:
            raise MFAError("invalid-request")
        encoded = _canonical(response)
        if len(encoded)>8192:
            raise MFAError("invalid-request")
        response_digest = hashlib.sha256(encoded).hexdigest()
        with self._transaction() as db:
            row,challenge = self._bound(db,caller,challenge_id)
            if row["state"]=="cancelled":
                raise MFAError("cancelled")
            if row["state"] not in ("issued","verified","consumed"):
                raise MFAError("invalid-state")
            if row["verify_key"] is not None:
                if row["verify_key"]!=idempotency_key or row["response_digest"]!=response_digest:
                    raise MFAError("idempotency-conflict")
                # Historical retrieval, never re-sign or refresh its time.
                # Online consume still enforces current validity and one-use.
                return json.loads(row["receipt"])
            now = self._now()
            self._active(row,challenge,now)
            _issuer_key(self.issuer_key,now)
            if db.execute("SELECT 1 FROM challenges WHERE namespace=? AND verify_key=?",
                          (row["namespace"],idempotency_key)).fetchone():
                raise MFAError("idempotency-conflict")
            if self.verifier is None:
                raise MFAError("verifier-unavailable")
            try:
                factor = self.verifier.verify(challenge,response,now)
            except Exception:
                raise MFAError("factor-verification-failed") from None
            now = self._now()
            self._active(row,challenge,now)
            self._current(db,factor,challenge,now)
            _issuer_key(self.issuer_key,now)
            payload={
                "profile":RECEIPT_PROFILE,"alg":"Ed25519","id":str(uuid.uuid4()),
                "issuer":self.issuer_key.issuer,"key_ref":self.issuer_key.key_ref,
                "subject_ref":factor.subject_ref,"caller_ref":caller.caller_ref,
                "tenant":caller.tenant,"audience":caller.audience,
                "challenge_digest":challenge.digest,"request_digest":challenge.request_digest,
                "verified_methods":[METHOD],"verified_at":now,
                "expires_at":min(now+60,challenge.expires_at,factor.valid_until,self.issuer_key.expires_at),
                "binding_ref":factor.binding_ref,"binding_revision":factor.binding_revision,
            }
            try:
                signature = self.signer.sign(_CONTEXT+_canonical(payload))
            except Exception:
                raise MFAError("signer-unavailable") from None
            if type(signature) is not bytes or len(signature)!=64:
                raise MFAError("invalid-signer-result")
            receipt={**payload,"signature":base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}
            verify_receipt(receipt,issuer_key=self.issuer_key,challenge=challenge,caller=caller,now=self._now())
            db.execute("""UPDATE challenges SET state='verified',verify_key=?,response_digest=?,
                       receipt_id=?,receipt=? WHERE id=?""",
                       (idempotency_key,response_digest,receipt["id"],_canonical(receipt).decode(),challenge.id))
            return receipt

    def consume(self, caller, receipt_id, *, operation_digest, idempotency_key):
        if not _digest(operation_digest) or not _ref(idempotency_key):
            raise MFAError("invalid-request")
        with self._transaction() as db:
            row=db.execute("SELECT * FROM challenges WHERE receipt_id=? AND namespace=?",
                           (receipt_id,caller.namespace())).fetchone()
            if row is None:
                raise MFAError("not-found")
            challenge=self._challenge(row)
            if row["consume_key"] is not None:
                if row["consume_key"]!=idempotency_key or row["operation_digest"]!=operation_digest:
                    raise MFAError("idempotency-conflict")
                # Authorized caller reads its prior acknowledgement; no new
                # authentication evidence or domain effect is created.
                return json.loads(row["outcome"])
            if row["state"]!="verified":
                raise MFAError("invalid-state")
            now=self._now()
            self._active(row,challenge,now)
            receipt=json.loads(row["receipt"])
            factor=verify_receipt(receipt,issuer_key=self.issuer_key,challenge=challenge,caller=caller,now=now)
            self._current(db,factor,challenge,now)
            # A remote current-binding check can take time. Fence the local
            # receipt lifetime again after it returns, before recording use.
            now=self._now()
            self._active(row,challenge,now)
            verify_receipt(receipt,issuer_key=self.issuer_key,challenge=challenge,caller=caller,now=now)
            if challenge.request_digest is None or challenge.request_digest!=operation_digest:
                raise MFAError("request-binding-mismatch")
            if db.execute("SELECT 1 FROM challenges WHERE namespace=? AND consume_key=?",
                          (row["namespace"],idempotency_key)).fetchone():
                raise MFAError("idempotency-conflict")
            outcome={"receipt_id":receipt_id,"operation_digest":operation_digest,"state":"consumed"}
            db.execute("""UPDATE challenges SET state='consumed',consume_key=?,operation_digest=?,
                       outcome=? WHERE id=?""",
                       (idempotency_key,operation_digest,_canonical(outcome).decode(),challenge.id))
            return outcome

    def cancel(self, caller, challenge_id):
        with self._transaction() as db:
            row,_=self._bound(db,caller,challenge_id)
            if row["state"]=="consumed":
                raise MFAError("already-consumed")
            db.execute("UPDATE challenges SET state='cancelled' WHERE id=?",(challenge_id,))

    def revoke_binding(self, binding_ref):
        """Trusted local administration only; no unauthenticated network endpoint."""
        if not _ref(binding_ref):
            raise MFAError("invalid-binding")
        with self._transaction() as db:
            db.execute("INSERT OR IGNORE INTO revoked_bindings VALUES(?)",(binding_ref,))

    def outcome(self, caller, challenge_id):
        with self._transaction() as db:
            row,challenge=self._bound(db,caller,challenge_id)
            state=row["state"]
            if state not in ("cancelled","consumed") and self._now()>=challenge.expires_at:
                state="expired"
            return {"id":challenge_id,"state":state,"receipt_id":row["receipt_id"]}
