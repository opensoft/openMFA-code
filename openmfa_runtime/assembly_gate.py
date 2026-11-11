"""Offline source compatibility, never approval, release or deployment authority."""
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys


class CompatibilityError(ValueError):
    pass


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=30)
    if result.returncode:
        raise CompatibilityError("source-unavailable")
    return result.stdout


def _sha(value, size=40):
    if type(value) is not str or re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is None:
        raise CompatibilityError("invalid-source-binding")
    return value


def _yaml(path):
    try:
        import yaml
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (ImportError, OSError, ValueError) as error:
        raise CompatibilityError("qualification-metadata-unavailable") from error
    if type(value) is not dict:
        raise CompatibilityError("invalid-assembly-metadata")
    return value


def check_assembly(root, *, repository, commit, tree, contracts):
    """Caller supplies trusted expected identity; this function grants nothing."""
    root = Path(root).resolve(strict=True)
    _sha(commit)
    _sha(tree)
    if repository not in ("opensoft/openWallet", "opensoft/openMFA"):
        raise CompatibilityError("wrong-assembly-repository")
    remote = git(root, "remote", "get-url", "origin").decode().strip()
    normalized = remote.replace("git@github.com:", "https://github.com/").removesuffix(".git").rstrip("/")
    if normalized != "https://github.com/" + repository:
        raise CompatibilityError("wrong-assembly-repository")
    if git(root, "rev-parse", "HEAD").decode().strip() != commit:
        raise CompatibilityError("wrong-assembly-commit")
    if git(root, "show", "-s", "--format=%T", "HEAD").decode().strip() != tree:
        raise CompatibilityError("wrong-assembly-tree")
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        raise CompatibilityError("dirty-assembly")
    manifest = _yaml(root / "project.yaml")
    expected_id = "openwallet" if repository.endswith("openWallet") else "openmfa"
    if manifest.get("id") != expected_id:
        raise CompatibilityError("wrong-project-manifest")
    legs = {leg.get("role"): leg for leg in manifest.get("legs", []) if type(leg) is dict}
    if set(legs) != {"assembly", "spec", "code"}:
        raise CompatibilityError("incomplete-assembly")
    shape = _yaml(root / "contracts/shape-pin.yaml")
    for item in shape.get("files", []):
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise CompatibilityError("invalid-shape-path")
        path = root / relative
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise CompatibilityError("shape-copy-drift")
    sources = {}
    for role in ("spec", "code"):
        leg = legs[role]
        if leg.get("path") != role or leg.get("repository") != repository + "-" + role:
            raise CompatibilityError("wrong-leg-manifest")
        pin = _yaml(root / f"contracts/{role}-pin.yaml")
        expected = _sha(pin.get("commit"))
        if pin.get("source_repository") != leg["repository"] or pin.get("submodule_path") != role:
            raise CompatibilityError("wrong-leg-pin")
        entry = git(root, "ls-tree", "HEAD", "--", role).decode().strip().split()
        if len(entry) != 4 or entry[:3] != ["160000", "commit", expected]:
            raise CompatibilityError("gitlink-pin-mismatch")
        directory = root / role
        if (not (directory / ".git").exists() or directory.is_symlink()
                or git(directory, "rev-parse", "HEAD").decode().strip() != expected
                or git(directory, "status", "--porcelain", "--untracked-files=all")):
            raise CompatibilityError("leg-checkout-mismatch")
        records = [item for item in git(directory, "ls-tree", "-r", "-z", expected).split(b"\0") if item]
        digest = hashlib.sha256(b"".join(item + b"\n" for item in sorted(records))).hexdigest()
        if (pin.get("digest_definition") != "sorted-ls-tree-r-v1"
                or pin.get("digests", {}).get("tree_sha256") != digest):
            raise CompatibilityError("leg-digest-mismatch")
        # The declared root gate remains the owner of workflow/shape semantics.
        sources[role] = {"commit": expected, "tree_sha256": digest}
    for relative, digest in contracts.items():
        _sha(digest, 64)
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise CompatibilityError("invalid-contract-path")
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != digest:
            raise CompatibilityError("contract-digest-mismatch")
    for validator in ("validate-repository-naming.py", "validate-manifest.py", "validate-pins.py"):
        arguments = [sys.executable, str(root / "scripts" / validator)]
        if validator == "validate-repository-naming.py":
            arguments += ["--project", "project.yaml"]
        result = subprocess.run(arguments,
                                cwd=root, capture_output=True, timeout=60)
        if result.returncode:
            raise CompatibilityError("canonical-assembly-gate-refused")
    return {"repository": repository, "commit": commit, "tree": tree, "legs": sources}


def check_installed_package(source_directory, package):
    source = Path(source_directory).resolve(strict=True) / package
    spec = importlib.util.find_spec(package)
    if spec is None or spec.origin is None:
        raise CompatibilityError("runtime-package-unavailable")
    installed = Path(spec.origin).resolve(strict=True).parent

    def files(directory):
        result = {}
        for path in directory.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            if path.is_symlink():
                raise CompatibilityError("runtime-package-link")
            result[str(path.relative_to(directory))] = hashlib.sha256(path.read_bytes()).hexdigest()
        return result

    expected, actual = files(source), files(installed)
    if not expected or actual != expected:
        raise CompatibilityError("runtime-package-source-mismatch")
    for dependency, version in (("cryptography", "50.0.1"), ("rfc8785", "0.1.4")):
        try:
            actual_version = importlib.metadata.version(dependency)
        except importlib.metadata.PackageNotFoundError:
            raise CompatibilityError("runtime-dependency-unavailable") from None
        if actual_version != version:
            raise CompatibilityError("runtime-dependency-mismatch")
    return {"package": package, "files": expected}
