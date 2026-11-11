"""Break only disposable clones to exercise exact assembly refusal gates."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

import yaml
from openmfa_runtime.assembly_gate import CompatibilityError, check_assembly, check_installed_package
from run_isolated import CONTRACTS


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL).strip()


def identity(root):
    return {"commit": git(root, "rev-parse", "HEAD"), "tree": git(root, "show", "-s", "--format=%T", "HEAD")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet-root", required=True, type=Path)
    parser.add_argument("--mfa-root", required=True, type=Path)
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    expected = json.loads(args.expected.read_text())
    check_installed_package(args.wallet_root / "code", "openwallet_runtime")
    check_installed_package(args.mfa_root / "code", "openmfa_runtime")
    if Path(__file__).read_bytes() != (args.mfa_root / "code/qualification/check_negative_inputs.py").read_bytes():
        raise RuntimeError("negative-driver-source-mismatch")
    results = {}
    for product, source, repository in (("wallet", args.wallet_root, "opensoft/openWallet"),
                                        ("mfa", args.mfa_root, "opensoft/openMFA")):
        check_assembly(source, repository=repository, contracts=CONTRACTS[product], **expected[product])
        with tempfile.TemporaryDirectory(prefix="wallet-mfa-gate-negative-") as temporary:
            root = Path(temporary) / "root"
            subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(source), str(root)], check=True)
            git(root, "remote", "set-url", "origin", "https://github.com/" + repository + ".git")
            git(root, "config", "user.name", "Negative gate fixture")
            git(root, "config", "user.email", "qualification@example.invalid")
            for leg in ("spec", "code"):
                subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(source / leg), str(root / leg)],
                               check=True, stderr=subprocess.DEVNULL)
            original = git(root, "rev-parse", "HEAD")

            def refuse(name, expected_error, **changes):
                configuration = dict(repository=repository, contracts=CONTRACTS[product], **identity(root))
                configuration.update(changes)
                try:
                    check_assembly(root, **configuration)
                except CompatibilityError as error:
                    if str(error) != expected_error:
                        raise AssertionError((name, str(error), expected_error)) from error
                    results[product + ":" + name] = True
                else:
                    raise AssertionError(name + " incorrectly passed")

            def commit():
                git(root, "add", ".")
                git(root, "commit", "-qm", "Deliberately broken disposable conformance fixture")

            refuse("wrong-expected-commit", "wrong-assembly-commit", commit="0" * 40)
            refuse("wrong-expected-tree", "wrong-assembly-tree", tree="0" * 40)
            (root / "untracked-probe").write_text("dirty")
            refuse("dirty-root", "dirty-assembly")
            (root / "untracked-probe").unlink()
            pin_file = root / "contracts/code-pin.yaml"
            pin = yaml.safe_load(pin_file.read_text())
            pin["commit"] = "0" * 40
            pin_file.write_text(yaml.safe_dump(pin))
            commit()
            refuse("wrong-gitlink-pin", "gitlink-pin-mismatch")
            git(root, "checkout", "--quiet", "--detach", original)
            pin = yaml.safe_load(pin_file.read_text())
            pin["digests"]["tree_sha256"] = "0" * 64
            pin_file.write_text(yaml.safe_dump(pin))
            commit()
            refuse("wrong-leg-digest", "leg-digest-mismatch")
            git(root, "checkout", "--quiet", "--detach", original)
            shape_file = root / "contracts/shape-pin.yaml"
            shape = yaml.safe_load(shape_file.read_text())
            shape["files"] = []
            shape_file.write_text(yaml.safe_dump(shape))
            commit()
            refuse("empty-shape-pin", "incomplete-shape-pin")
            git(root, "checkout", "--quiet", "--detach", original)
            validator = root / "scripts/validate-pins.py"
            validator.write_bytes(validator.read_bytes() + b"\n# deliberate fixture drift\n")
            commit()
            refuse("shape-copy-drift", "shape-copy-drift")
            git(root, "checkout", "--quiet", "--detach", original)
            workflow = root / ".github/workflows/deliberately-wrong-fixture.yml"
            workflow.write_text("jobs:\n  wrong:\n    uses: " + repository + "-code/.github/workflows/pytest-suite.yml@" + "0" * 40 + "\n")
            commit()
            refuse("wrong-workflow-reference", "canonical-assembly-gate-refused")
    try:
        check_installed_package(args.mfa_root / "code", "openwallet_runtime")
    except CompatibilityError as error:
        assert str(error) == "runtime-package-source-mismatch"
        results["wrong-installed-runtime-source"] = True
    else:
        raise AssertionError("wrong installed source passed")
    args.evidence.write_text(json.dumps({"schema": 1, "stage": "negative-source-conformance", "passed": True,
                                        "gates": results, "operational_acceptance": False}, indent=2) + "\n")
    print(json.dumps({"passed": True, "negative_gates": len(results)}))


if __name__ == "__main__":
    main()
