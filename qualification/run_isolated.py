"""Actual isolated source qualification; no live identity/provider calls."""
import argparse
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

from openmfa_runtime.assembly_gate import check_assembly, check_installed_package
from pki import generate
from cleanup import finalize

DEPENDENCIES = ["cryptography==50.0.1", "rfc8785==0.1.4", "PyYAML==6.0.3",
                "cffi==2.1.1", "pycparser==3.0"]
BASE = "python@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258"
LABEL = "opensoft.wallet-mfa-qualification"
CONTRACTS = {
    "wallet": {"spec/contracts/challenge-proof-v0.schema.json":
               "ec2770110b8afcddf34deb56754f79b01d2877a0bb414ea1ce59d9ace32362ed"},
    "mfa": {"spec/contracts/challenge-v0.schema.json":
            "764adda761fe34205f371dd6210313423e02607dcf970e992c5138be1f23d0d6",
            "spec/contracts/verification-receipt-v0.schema.json":
            "10ceaaf660c5cda9cdadc862cfb055f590e8c0ecef0170b93ede85934d3fb091"},
}


def run(*args, input=None, timeout=120, check=True):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        # Command output stays outside the redacted evidence object.
        print(result.stderr[-4000:], file=sys.stderr)
        raise RuntimeError("command-refused:" + str(result.returncode))
    return result


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs)


def package_preflight(wallet_root, mfa_root, expected):
    report = {}
    for name, root, repo, package in (
        ("wallet", wallet_root, "opensoft/openWallet", "openwallet_runtime"),
        ("mfa", mfa_root, "opensoft/openMFA", "openmfa_runtime"),
    ):
        identity = expected[name]
        report[name] = check_assembly(root, repository=repo, commit=identity["commit"],
                                      tree=identity["tree"], contracts=CONTRACTS[name])
        report[name]["package"] = check_installed_package(root / "code", package)
    # The invoked driver and runtime script must also belong to this selected source.
    for filename in ("run_isolated.py", "role.py", "pki.py", "cleanup.py", "check_cleanup.py", "Dockerfile"):
        if Path(__file__).with_name(filename).read_bytes() != (mfa_root / "code/qualification" / filename).read_bytes():
            raise RuntimeError("qualification-driver-source-mismatch")
    return report


def build_image(directory, wallet_root, mfa_root, image, case):
    build = directory / "build"
    build.mkdir()
    wheels = build / "wheels"
    wheels.mkdir()
    docker("image", "inspect", BASE)
    run(sys.executable, "-m", "pip", "--isolated", "download", "--index-url", "https://pypi.org/simple",
        "--only-binary=:all:", "--no-deps", "--dest", str(wheels), *DEPENDENCIES, timeout=180)
    for index, root in enumerate((wallet_root, mfa_root)):
        source = directory / ("wheel-source-" + str(index))
        source.mkdir()
        archive = subprocess.run(["git", "-C", str(root / "code"), "archive", "--format=tar", "HEAD"],
                                 capture_output=True, check=True, timeout=30).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            stream.extractall(source, filter="data")
        run(sys.executable, "-m", "pip", "--isolated", "wheel", "--no-deps", "--no-build-isolation",
            "--wheel-dir", str(wheels), str(source), timeout=120)
    from packaging.utils import parse_wheel_filename
    requirements, digests = [], {}
    for wheel in sorted(wheels.glob("*.whl")):
        name, version, _, _ = parse_wheel_filename(wheel.name)
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        requirements.append(str(name) + "==" + str(version) + " --hash=sha256:" + digest)
        digests[wheel.name] = digest
    (build / "requirements.txt").write_text("\n".join(requirements) + "\n")
    for name in ("Dockerfile", "role.py"):
        shutil.copyfile(Path(__file__).with_name(name), build / name)
    docker("build", "--network=none", "--build-arg", "BASE_IMAGE=" + BASE,
           "--label", LABEL + "=" + case, "-t", image, str(build), timeout=240)
    return digests


def invoke(container, role, request, *, accepted=True, error=None):
    result = docker("exec", "-i", container, "python", "/opt/role.py", role,
                    input=json.dumps(request), check=False)
    try:
        body = json.loads(result.stdout)
    except ValueError:
        raise RuntimeError("invalid-role-result") from None
    if accepted:
        if result.returncode or body.get("ok") is not True:
            raise RuntimeError("role-refused:" + str(body.get("error")))
        return body["result"]
    if not result.returncode or body.get("ok") is not False:
        raise RuntimeError("negative-case-was-accepted")
    if error is None or body.get("error") != error:
        raise RuntimeError("unexpected-negative-refusal:" + str(body.get("error")))
    return body["error"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet-root", type=Path, required=True)
    parser.add_argument("--mfa-root", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True, help="Trusted expected root commit/tree JSON")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--fail-after-start", action="store_true", help="Exercise finalization of an injected failure")
    parser.add_argument("--subnet", help="Operator-checked unused RFC2544 /28 internal subnet; no daemon pool change")
    args = parser.parse_args()

    def cancel(_signal, _frame):
        raise InterruptedError("qualification-cancelled")

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    wallet_root, mfa_root = args.wallet_root.resolve(strict=True), args.mfa_root.resolve(strict=True)
    expected = json.loads(args.expected.read_text())
    # Resolve and bind all sources before creating any Docker resource.
    sources = package_preflight(wallet_root, mfa_root, expected)
    if args.subnet:
        selected = ipaddress.ip_network(args.subnet, strict=True)
        if selected.version != 4 or selected.prefixlen != 28 or not selected.subnet_of(ipaddress.ip_network("198.18.0.0/15")):
            raise RuntimeError("invalid-isolated-test-subnet")
        identifiers = docker("network", "ls", "-q").stdout.split()
        networks = json.loads(docker("network", "inspect", *identifiers).stdout) if identifiers else []
        for item in networks:
            for config in (item.get("IPAM") or {}).get("Config") or []:
                if not config.get("Subnet"):
                    continue
                existing = ipaddress.ip_network(config["Subnet"])
                if existing.version == selected.version and existing.overlaps(selected):
                    raise RuntimeError("isolated-test-subnet-overlap")
    case = "wmq-" + uuid.uuid4().hex[:16]
    image, network = "wallet-mfa-qualification:" + case, case
    names = []
    report = {"schema": 1, "stage": "isolated-source-conformance", "case": case,
              "operational_acceptance": False, "sources": sources, "base_image": BASE,
              "custody_model": "isolated_invocable", "gates": {}, "passed": False}
    label = LABEL + "=" + case
    temporary = tempfile.TemporaryDirectory(prefix=case + "-")
    try:
        directory = Path(temporary.name)
        report["wheels"] = build_image(directory, wallet_root, mfa_root, image, case)
        fingerprints = generate(directory / "credentials")
        policies = {
            fingerprints["agent"]: {"actions": ["resolve", "sign"], "subjects": ["subject:qualification-machine"]},
            fingerprints["verifier"]: {"actions": ["resolve"], "subjects": ["subject:qualification-machine"]},
        }
        (directory / "credentials/custody/policies.json").write_text(json.dumps(policies))
        (directory / "credentials/custody/policies.json").chmod(0o644)
        network_options = ["--subnet", str(selected)] if args.subnet else []
        docker("network", "create", "--internal", "--label", label, *network_options, network)
        for role in ("custody", "verifier", "agent"):
            credential_volume, state_volume = case + "-" + role + "-credentials", case + "-" + role + "-state"
            for volume in (credential_volume, state_volume):
                docker("volume", "create", "--label", label, volume)
            helper = case + "-init-" + role
            docker("create", "--name", helper, "--label", label, "--network=none", "--read-only",
                   "--cap-drop=ALL", "--security-opt=no-new-privileges",
                   "--mount", "type=volume,src=" + credential_volume + ",dst=/credentials",
                   "--mount", "type=volume,src=" + state_volume + ",dst=/state", image, "init-volume")
            names.append(helper)
            docker("cp", str(directory / "credentials" / role) + "/.", helper + ":/credentials")
            docker("start", "--attach", helper)
            docker("rm", helper)
            names.remove(helper)
            name = case + "-" + role
            command = ["run", "-d", "--name", name, "--label", label, "--network", network,
                       "--read-only", "--user=10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                       "--pids-limit=64", "--memory=192m", "--cpus=0.5",
                       "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                       "--mount", "type=volume,src=" + credential_volume + ",dst=/credentials,readonly",
                       "--mount", "type=volume,src=" + state_volume + ",dst=/state"]
            if role == "custody":
                command += ["--network-alias", "custody"]
            docker(*command, image, "custody" if role == "custody" else "idle")
            names.append(name)
        report["gates"]["resource_creation"] = True
        print(json.dumps({"event": "services_started", "case": case}), flush=True)
        if args.fail_after_start:
            raise RuntimeError("injected-failure-after-start")
        custody_name, verifier_name, agent_name = (case + "-" + role for role in ("custody", "verifier", "agent"))
        for _ in range(20):
            try:
                invoke(verifier_name, "verifier", {"action": "health"})
                break
            except RuntimeError:
                time.sleep(0.25)
        else:
            raise RuntimeError("custody-start-timeout")
        isolation = {}
        for name in names:
            info = json.loads(docker("inspect", name).stdout)[0]
            host = info["HostConfig"]
            role = name.removeprefix(case + "-")
            if (host["Privileged"] or not host["ReadonlyRootfs"] or host["PortBindings"]
                    or "ALL" not in host["CapDrop"] or info["Config"]["User"] != "10001:10001"
                    or not any("no-new-privileges" in item for item in host["SecurityOpt"])
                    or set(info["NetworkSettings"]["Networks"]) != {network}
                    or any(mount["Type"] != "volume" for mount in info["Mounts"])):
                raise RuntimeError("container-isolation-refused")
            if {mount["Name"] for mount in info["Mounts"]} != {case + "-" + role + "-credentials", case + "-" + role + "-state"}:
                raise RuntimeError("foreign-volume-refused")
            isolation[role] = True
        if not json.loads(docker("network", "inspect", network).stdout)[0]["Internal"]:
            raise RuntimeError("network-isolation-refused")
        report["gates"]["container_boundaries"] = isolation
        installed = json.loads(docker("exec", agent_name, "python", "/opt/role.py", "source-files").stdout)
        for name in ("wallet", "mfa"):
            if installed[name] != sources[name]["package"]["files"]:
                raise RuntimeError("container-package-source-mismatch")
        report["gates"]["container_package_provenance"] = True
        report["gates"]["worker_private_key_absence"] = invoke(agent_name, "agent", {"action": "inspect"})
        invoke(agent_name, "agent", {"action": "export"}, accepted=False, error="service-refused")
        invoke(verifier_name, "verifier", {"action": "attempt-sign"}, accepted=False, error="service-refused")
        report["gates"]["no_export_and_role_separation"] = True

        challenge = invoke(verifier_name, "verifier", {"action": "create"})
        proof = invoke(agent_name, "agent", {"action": "prove", "challenge": challenge})
        tampered = {**proof, "signature": ("A" if proof["signature"][0] != "A" else "B") + proof["signature"][1:]}
        invoke(verifier_name, "verifier", {"action": "verify", "challenge": challenge, "proof": tampered, "key": "verify:tampered"}, accepted=False, error="factor-verification-failed")
        another = invoke(verifier_name, "verifier", {"action": "create"})
        invoke(verifier_name, "verifier", {"action": "verify", "challenge": another, "proof": proof, "key": "verify:cross"}, accepted=False, error="factor-verification-failed")
        invoke(verifier_name, "verifier", {"action": "verify", "challenge": challenge, "proof": proof, "key": "verify:wrong-caller",
               "caller": {"caller_ref": "other", "tenant": "tenant:disposable", "audience": "audience:codeXfactory-pilot"}}, accepted=False, error="not-found")
        receipt = invoke(verifier_name, "verifier", {"action": "verify", "challenge": challenge, "proof": proof, "key": "verify:1"})
        repeated = invoke(verifier_name, "verifier", {"action": "verify", "challenge": challenge, "proof": proof, "key": "verify:1"})
        if receipt != repeated or receipt["verified_methods"] != ["wallet-ed25519-possession.v0"]:
            raise RuntimeError("receipt-compatibility-refused")
        report["gates"]["actual_proof_receipt_and_refusals"] = True
        consume = {"action": "consume", "receipt_id": receipt["id"], "key": "consume:1"}
        outcome = invoke(verifier_name, "verifier", consume)
        if invoke(verifier_name, "verifier", consume) != outcome:
            raise RuntimeError("unstable-retry")
        invoke(verifier_name, "verifier", {**consume, "operation_digest": "sha256:" + "b" * 64}, accepted=False, error="idempotency-conflict")
        docker("restart", verifier_name)
        if invoke(verifier_name, "verifier", consume) != outcome:
            raise RuntimeError("restart-outcome-lost")
        report["gates"]["durable_one_use_retry_and_restart"] = True

        expired = invoke(verifier_name, "verifier", {"action": "create", "ttl": 1})
        # No fixture clock: let the actual service's half-open lifetime close.
        time.sleep(1.1)
        invoke(verifier_name, "verifier", {"action": "verify", "challenge": expired,
               "proof": proof, "key": "verify:expired"}, accepted=False, error="expired")
        report["gates"]["actual_clock_expiry"] = True

        pending = invoke(verifier_name, "verifier", {"action": "create"})
        pending_proof = invoke(agent_name, "agent", {"action": "prove", "challenge": pending})
        docker("stop", custody_name)
        invoke(verifier_name, "verifier", {"action": "verify", "challenge": pending,
               "proof": pending_proof, "key": "verify:availability"}, accepted=False, error="factor-verification-failed")
        docker("start", custody_name)
        for _ in range(20):
            try:
                invoke(verifier_name, "verifier", {"action": "health"})
                break
            except RuntimeError:
                time.sleep(0.25)
        else:
            raise RuntimeError("custody-recovery-timeout")
        invoke(verifier_name, "verifier", {"action": "verify", "challenge": pending,
               "proof": pending_proof, "key": "verify:availability"})
        report["gates"]["unavailable_registry_rollback_and_recovery"] = True

        old_challenge = invoke(verifier_name, "verifier", {"action": "create"})
        old_proof = invoke(agent_name, "agent", {"action": "prove", "challenge": old_challenge})
        old_receipt = invoke(verifier_name, "verifier", {"action": "verify", "challenge": old_challenge,
                             "proof": old_proof, "key": "verify:old-binding"})
        pending_rotation = invoke(verifier_name, "verifier", {"action": "create"})
        pending_rotation_proof = invoke(agent_name, "agent", {"action": "prove", "challenge": pending_rotation})
        docker("exec", custody_name, "python", "/opt/role.py", "rotate")
        invoke(verifier_name, "verifier", {"action": "consume", "receipt_id": old_receipt["id"],
               "key": "consume:old-binding"}, accepted=False, error="revoked-binding")
        invoke(verifier_name, "verifier", {"action": "verify", "challenge": pending_rotation,
               "proof": pending_rotation_proof, "key": "verify:rotated-replay"}, accepted=False, error="factor-verification-failed")
        report["gates"]["remote_key_rotation_refuses_old_evidence"] = True

        challenge = invoke(verifier_name, "verifier", {"action": "create"})
        proof = invoke(agent_name, "agent", {"action": "prove", "challenge": challenge})
        receipt = invoke(verifier_name, "verifier", {"action": "verify", "challenge": challenge, "proof": proof, "key": "verify:revoke"})
        docker("exec", custody_name, "python", "/opt/role.py", "revoke")
        invoke(verifier_name, "verifier", {"action": "consume", "receipt_id": receipt["id"], "key": "consume:revoke"}, accepted=False, error="verifier-unavailable")
        docker("restart", custody_name)
        for _ in range(20):
            try:
                health = invoke(verifier_name, "verifier", {"action": "health"})
                if health["lookup_refused"]:
                    break
            except RuntimeError:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("persistent-revocation-lost")
        fresh = invoke(verifier_name, "verifier", {"action": "create"})
        invoke(agent_name, "agent", {"action": "prove", "challenge": fresh}, accepted=False, error="service-refused")
        report["gates"]["remote_revocation_and_service_restart"] = True
        report["passed"] = True
    except BaseException as error:
        report["error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print("Qualification failed: " + type(error).__name__ + ": " + str(error), file=sys.stderr)
    finally:
        # Once finalization begins, finish the bounded run-owned cleanup even
        # if a second cancellation arrives.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        report["cleanup"] = finalize(docker, label, temporary)
        report["passed"] = report["passed"] and report["cleanup"]["absence_verified"]
        args.evidence.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"event": "complete", "passed": report["passed"], "cleanup": report["cleanup"]}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
