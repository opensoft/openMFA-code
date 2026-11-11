"""Cleanup qualification must use fresh, case-bound child evidence."""
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qualification import check_cleanup


def report(mode, case):
    return {"case": case, "passed": False,
            "error": "injected-failure-after-start" if mode == "injected-failure" else "InterruptedError",
            "gates": {"resource_creation": True},
            "cleanup": {"absence_verified": True, "failures": []}}


def setup_checker(tmp_path, monkeypatch, *, write_fresh=True, cancelled_case="current-cancelled", returncode=1):
    evidence = tmp_path / "cleanup.json"
    evidence.write_text(json.dumps({"passed": True}))
    for mode in ("injected-failure", "cancelled"):
        evidence.with_name("cleanup-" + mode + ".json").write_text(json.dumps(report(mode, "stale")))
    monkeypatch.setattr("sys.argv", ["check_cleanup", "--wallet-root", "/wallet", "--mfa-root", "/mfa",
                                    "--expected", "/expected", "--evidence", str(evidence),
                                    "--subnet", "198.18.254.16/28"])

    def write(command, mode, case):
        if write_fresh:
            Path(command[command.index("--evidence") + 1]).write_text(json.dumps(report(mode, case)))

    def run(command, **kwargs):
        write(command, "injected-failure", "current-injected")
        return SimpleNamespace(returncode=returncode)

    class Process:
        def __init__(self, command, **kwargs):
            self.stdout = io.StringIO(json.dumps({"event": "services_started", "case": "current-cancelled"}) + "\n")
            self.returncode = returncode
            write(command, "cancelled", cancelled_case)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def poll(self):
            return None

        def terminate(self):
            pass

        def communicate(self, **kwargs):
            return "", None

    class Selector:
        def register(self, *args):
            pass

        def select(self, **kwargs):
            return [True]

        def close(self):
            pass

    monkeypatch.setattr(check_cleanup.subprocess, "run", run)
    monkeypatch.setattr(check_cleanup.subprocess, "Popen", Process)
    monkeypatch.setattr(check_cleanup.selectors, "DefaultSelector", Selector)
    return evidence


def test_previous_report_cannot_qualify_child_that_produced_no_report(tmp_path, monkeypatch):
    evidence = setup_checker(tmp_path, monkeypatch, write_fresh=False)
    with pytest.raises(FileNotFoundError):
        check_cleanup.main()
    assert json.loads(evidence.read_text())["passed"] is False


def test_cancellation_report_must_match_observed_services_case(tmp_path, monkeypatch):
    evidence = setup_checker(tmp_path, monkeypatch, cancelled_case="another-run")
    with pytest.raises(RuntimeError, match="cleanup-exercise-refused:cancelled"):
        check_cleanup.main()
    assert json.loads(evidence.read_text())["passed"] is False


@pytest.mark.parametrize("returncode", [0, -15, 2])
def test_unexpected_child_exit_cannot_qualify_cleanup(tmp_path, monkeypatch, returncode):
    evidence = setup_checker(tmp_path, monkeypatch, returncode=returncode)
    with pytest.raises(RuntimeError, match="cleanup-exercise-refused:injected-failure"):
        check_cleanup.main()
    assert json.loads(evidence.read_text())["passed"] is False


def test_fresh_case_bound_reports_qualify_both_exercises(tmp_path, monkeypatch):
    evidence = setup_checker(tmp_path, monkeypatch)
    check_cleanup.main()
    result = json.loads(evidence.read_text())
    assert result["passed"] is True
    assert result["gates"]["injected-failure"]["case"] == "current-injected"
    assert result["gates"]["cancelled"]["case"] == "current-cancelled"
