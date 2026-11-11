"""Container entrypoints for actual isolated service integration."""
import json
import hashlib
import os
from pathlib import Path
import sys
import time

from openwallet_runtime import ProofError, TrustedKeyBinding, create_proof, verify_proof
from openwallet_runtime.custody import RemoteRegistry, RemoteSigner, TLSClient
from openwallet_runtime.reference_service import CustodyApplication, ReferenceServer, load_key, provision_key, server_context
from openwallet_runtime.registry import BindingRegistry
from openmfa_runtime import CallerContext, Challenge, ChallengeService, IssuerKey, MFAError, verify_receipt
from openmfa_runtime.wallet_factor import WalletFactorVerifier

STATE = Path(os.environ.get("QUAL_STATE_DIR", "/state"))
CREDENTIALS = Path(os.environ.get("QUAL_CREDENTIALS_DIR", "/credentials"))
SUBJECT = "subject:qualification-machine"
KEY = "key:qualification-machine:1"
BINDING = "binding:qualification-machine:1"
OPERATION = "sha256:" + "a" * 64
CALLER = CallerContext("caller:qualification", "tenant:disposable", "audience:codeXfactory-pilot")


def client():
    return TLSClient("https://custody:8443", ca_file=CREDENTIALS / "ca.pem",
                     certificate=CREDENTIALS / "certificate.pem", private_key=CREDENTIALS / "client.key")


def custody():
    registry = BindingRegistry(STATE / "registry")
    keys = STATE / "keys"
    if not keys.exists():
        public = provision_key(keys, KEY)
        now = int(time.time())
        binding = TrustedKeyBinding(BINDING, "wallet:qualification", KEY, SUBJECT,
                                    "custody:isolated-reference", public, 1, now - 60, now + 900)
        registry.register(binding, expected_revision=None)
    policies = json.loads((CREDENTIALS / "policies.json").read_text())
    app = CustodyApplication(registry, key_directory=keys, policies=policies)
    context = server_context(ca_file=CREDENTIALS / "ca.pem", certificate=CREDENTIALS / "certificate.pem",
                             private_key=CREDENTIALS / "client.key")
    with ReferenceServer(("0.0.0.0", 8443), context=context, application=app) as server:
        server.serve_forever()


def issuer():
    keys = STATE / "issuer-keys"
    if not keys.exists():
        provision_key(keys, "issuer-key:qualification")
        path = STATE / "issuer.json"
        path.write_text(json.dumps({"not_before": int(time.time()) - 60, "expires_at": int(time.time()) + 900}))
        path.chmod(0o600)
    metadata = json.loads((STATE / "issuer.json").read_text())
    private = load_key(keys, "issuer-key:qualification")
    return IssuerKey("issuer:qualification", "issuer-key:qualification",
                     private.public_key().public_bytes_raw(), **metadata), private


def verifier(request):
    trusted, private = issuer()
    registry = RemoteRegistry(client())
    adapter = WalletFactorVerifier(registry=registry, verify_proof=verify_proof)
    service = ChallengeService(STATE / "challenges.sqlite", issuer_key=trusted, signer=private, verifier=adapter)
    caller = CallerContext(**request["caller"]) if "caller" in request else CALLER
    action = request["action"]
    if action == "create":
        return service.create(caller, SUBJECT, request_digest=OPERATION, ttl=request.get("ttl", 120)).record()
    if action == "verify":
        receipt = service.verify(caller, request["challenge"]["id"], request["proof"], idempotency_key=request["key"])
        challenge = Challenge(**{k: v for k, v in request["challenge"].items() if k != "profile"})
        verify_receipt(receipt, issuer_key=trusted, challenge=challenge, caller=caller, now=int(time.time()))
        return receipt
    if action == "consume":
        return service.consume(caller, request["receipt_id"], operation_digest=request.get("operation_digest", OPERATION),
                               idempotency_key=request["key"])
    if action == "attempt-sign":
        # An otherwise valid proof must fail solely because this peer lacks sign.
        now = int(time.time())
        binding = registry.resolve(SUBJECT, now=now)
        return create_proof(OPERATION, binding, RemoteSigner(client(), subject_ref=SUBJECT), now=now)
    if action == "health":
        try:
            registry.resolve(SUBJECT, now=int(time.time()))
            return {"reachable": True, "lookup_refused": False}
        except ProofError as error:
            if error.code != "service-refused":
                raise
            return {"reachable": True, "lookup_refused": True}
    raise ValueError("unknown-action")


def agent(request):
    if request["action"] == "inspect":
        forbidden = [STATE / "keys", STATE / "registry", STATE / "issuer-keys",
                     CREDENTIALS / "policies.json", Path("/var/run/docker.sock")]
        if any(path.exists() for path in forbidden):
            raise ValueError("custody-leak")
        return {"custody_key_absent": True, "issuer_key_absent": True, "docker_socket_absent": True}
    remote = client()
    if request["action"] == "export":
        return remote._post("/v0/export", {"subject_ref": SUBJECT})
    challenge_data = request["challenge"]
    challenge = Challenge(**{k: v for k, v in challenge_data.items() if k != "profile"})
    now = int(time.time())
    if (challenge.record() != challenge_data or challenge.issuer != "issuer:qualification"
            or any(getattr(challenge, field) != getattr(CALLER, field) for field in ("caller_ref", "tenant", "audience"))
            or not challenge.issued_at <= now < challenge.expires_at):
        raise ValueError("untrusted-test-handoff")
    binding = RemoteRegistry(remote).resolve(challenge.subject_ref, now=now)
    return create_proof(challenge.digest, binding, RemoteSigner(remote, subject_ref=challenge.subject_ref), now=now)


def main():
    mode = sys.argv[1]
    if mode == "source-files":
        import openwallet_runtime
        import openmfa_runtime
        result = {}
        for name, package in (("wallet", openwallet_runtime), ("mfa", openmfa_runtime)):
            directory = Path(package.__file__).parent
            result[name] = {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in directory.rglob("*.py") if "__pycache__" not in path.parts}
        print(json.dumps(result))
        return
    if mode == "init-volume":
        os.chmod(STATE, 0o777)
        return
    if mode == "custody":
        custody()
        return
    if mode == "idle":
        while True:
            time.sleep(60)
    if mode == "revoke":
        registry = BindingRegistry(STATE / "registry")
        registry.revoke(registry.resolve(SUBJECT, now=int(time.time())).binding_ref)
        print(json.dumps({"ok": True, "result": "revoked"}))
        return
    if mode == "rotate":
        registry = BindingRegistry(STATE / "registry")
        previous = registry.resolve(SUBJECT, now=int(time.time()))
        public = provision_key(STATE / "keys", "key:qualification-machine:2")
        now = int(time.time())
        replacement = TrustedKeyBinding("binding:qualification-machine:2", previous.wallet_ref,
            "key:qualification-machine:2", SUBJECT, previous.custody_ref, public,
            previous.revision + 1, now - 60, now + 900)
        registry.register(replacement, expected_revision=previous.revision)
        print(json.dumps({"ok": True, "result": "rotated"}))
        return
    request = json.load(sys.stdin)
    try:
        result = agent(request) if mode == "agent" else verifier(request)
        print(json.dumps({"ok": True, "result": result}))
    except Exception as error:
        code = error.code if isinstance(error, (ProofError, MFAError)) else "qualification-refused"
        print(json.dumps({"ok": False, "error": code}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
