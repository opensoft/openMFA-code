import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import subprocess

import pytest

from openmfa_runtime.assembly_gate import CompatibilityError, check_assembly, check_installed_package


def command(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


@pytest.fixture
def minimal_root(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    command(tmp_path, "config", "user.email", "fixture@example.invalid")
    command(tmp_path, "config", "user.name", "Fixture")
    command(tmp_path, "remote", "add", "origin", "https://github.com/opensoft/openMFA.git")
    (tmp_path / "project.yaml").write_text('{"id":"openmfa","legs":[]}')
    command(tmp_path, "add", "project.yaml")
    command(tmp_path, "commit", "-qm", "fixture")
    return tmp_path, command(tmp_path, "rev-parse", "HEAD"), command(tmp_path, "show", "-s", "--format=%T", "HEAD")


@pytest.mark.parametrize("field,value,error", [
    ("commit", "0" * 40, "wrong-assembly-commit"),
    ("tree", "0" * 40, "wrong-assembly-tree"),
    ("repository", "opensoft/other", "wrong-assembly-repository"),
    ("commit", "main", "invalid-source-binding"),
])
def test_exact_root_identity_is_required(minimal_root, field, value, error):
    root, commit, tree = minimal_root
    args = dict(repository="opensoft/openMFA", commit=commit, tree=tree, contracts={})
    args[field] = value
    with pytest.raises(CompatibilityError, match=error):
        check_assembly(root, **args)


def test_dirty_and_incomplete_assemblies_refuse(minimal_root):
    root, commit, tree = minimal_root
    with pytest.raises(CompatibilityError, match="incomplete-assembly"):
        check_assembly(root, repository="opensoft/openMFA", commit=commit, tree=tree, contracts={})
    (root / "untracked").write_text("dirty")
    with pytest.raises(CompatibilityError, match="dirty-assembly"):
        check_assembly(root, repository="opensoft/openMFA", commit=commit, tree=tree, contracts={})


def test_installed_package_must_match_every_source_module(tmp_path, monkeypatch):
    source, installed = tmp_path / "source" / "fixture_package", tmp_path / "installed" / "fixture_package"
    source.mkdir(parents=True)
    installed.mkdir(parents=True)
    for directory in (source, installed):
        (directory / "__init__.py").write_text("VALUE = 1\n")
    monkeypatch.setattr(importlib.util, "find_spec", lambda package: SimpleNamespace(origin=str(installed / "__init__.py")))
    result = check_installed_package(source.parent, "fixture_package")
    assert result["files"]["__init__.py"] == hashlib.sha256(b"VALUE = 1\n").hexdigest()
    (installed / "__init__.py").write_text("VALUE = 2\n")
    with pytest.raises(CompatibilityError, match="runtime-package-source-mismatch"):
        check_installed_package(source.parent, "fixture_package")
    (installed / "__init__.py").write_text("VALUE = 1\n")
    (installed / "extra.py").write_text("extra")
    with pytest.raises(CompatibilityError, match="runtime-package-source-mismatch"):
        check_installed_package(source.parent, "fixture_package")


def test_missing_installed_package_never_skips(tmp_path, monkeypatch):
    monkeypatch.setattr(importlib.util, "find_spec", lambda package: None)
    with pytest.raises(CompatibilityError, match="runtime-package-unavailable"):
        check_installed_package(tmp_path, "missing_package")
