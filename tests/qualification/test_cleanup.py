"""Cleanup failures must preserve later cleanup attempts and negative evidence."""
from types import SimpleNamespace
import subprocess

from qualification.cleanup import finalize


def result(stdout="", returncode=0):
    return SimpleNamespace(stdout=stdout, returncode=returncode)


def test_timeout_does_not_abort_other_resources_or_private_state():
    calls = []
    cleaned = []

    def docker(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("ps", "-aq"):
            raise subprocess.TimeoutExpired("docker", 3)
        if args[:3] == ("volume", "ls", "-q") and sum(item[:3] == args[:3] for item in calls) == 1:
            return result("first second\n")
        if args[:3] == ("volume", "rm", "first"):
            raise subprocess.TimeoutExpired("docker", 3)
        return result()

    outcome = finalize(docker, "owner=run", SimpleNamespace(cleanup=lambda: cleaned.append(True)))
    assert cleaned == [True]
    assert outcome["absence_verified"] is False
    assert "containers-listing-exception" in outcome["failures"]
    assert "containers-absence-exception" in outcome["failures"]
    assert "volumes-removal-exception" in outcome["failures"]
    assert ("volume", "rm", "second") in calls
    assert any(item[:3] == ("image", "ls", "-q") for item in calls)


def test_command_failure_and_private_cleanup_failure_still_return_evidence():
    def docker(*args, **kwargs):
        return result(returncode=1)

    def broken_private_cleanup():
        raise OSError("private state unavailable")

    outcome = finalize(docker, "owner=run", SimpleNamespace(cleanup=broken_private_cleanup))
    assert outcome["absence_verified"] is False
    assert "private-temporary-state" in outcome["failures"]
    assert "images-absence" in outcome["failures"]


def test_empty_verified_resources_and_private_cleanup_succeed():
    outcome = finalize(lambda *args, **kwargs: result(), "owner=run", SimpleNamespace(cleanup=lambda: None))
    assert outcome == {"absence_verified": True, "failures": []}
