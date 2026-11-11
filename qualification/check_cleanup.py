"""Exercise failure and cancellation cleanup using the actual qualification driver."""
import argparse
import json
from pathlib import Path
import selectors
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet-root", type=Path, required=True)
    parser.add_argument("--mfa-root", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--subnet", required=True)
    args = parser.parse_args()
    results = {}
    for mode in ("injected-failure", "cancelled"):
        output = args.evidence.with_name(args.evidence.stem + "-" + mode + ".json")
        command = [sys.executable, str(Path(__file__).with_name("run_isolated.py")),
                   "--wallet-root", str(args.wallet_root), "--mfa-root", str(args.mfa_root),
                   "--expected", str(args.expected), "--evidence", str(output), "--subnet", args.subnet]
        if mode == "injected-failure":
            command.append("--fail-after-start")
            completed = subprocess.run(command, timeout=360)
            returncode = completed.returncode
        else:
            with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
                selector = selectors.DefaultSelector()
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + 300
                started = False
                while time.monotonic() < deadline and process.poll() is None:
                    if not selector.select(timeout=0.5):
                        continue
                    line = process.stdout.readline()
                    if line:
                        print(line.rstrip(), flush=True)
                        event = json.loads(line)
                        if event.get("event") == "services_started":
                            started = True
                            process.terminate()
                            break
                selector.close()
                if not started:
                    process.terminate()
                    process.wait(timeout=120)
                    raise RuntimeError("cancellation-check-did-not-reach-services")
                remaining, _ = process.communicate(timeout=120)
                if remaining:
                    print(remaining.rstrip(), flush=True)
                returncode = process.returncode
        report = json.loads(output.read_text())
        expected_error = "command-refused" if mode == "injected-failure" else "InterruptedError"
        # Error spelling is checked below; unrelated setup failure cannot count
        # as a successful cleanup exercise.
        if mode == "injected-failure":
            valid_error = report.get("error") == "injected-failure-after-start"
        else:
            valid_error = report.get("error") == "InterruptedError"
        if (returncode == 0 or report.get("passed") is not False or not valid_error
                or report.get("gates", {}).get("resource_creation") is not True
                or report.get("cleanup") != {"absence_verified": True, "failures": []}):
            raise RuntimeError("cleanup-exercise-refused:" + mode)
        results[mode] = {"expected_failure_observed": True, "resource_absence_verified": True,
                         "case": report["case"]}
    args.evidence.write_text(json.dumps({"schema": 1, "stage": "isolated-cleanup-conformance",
                                        "passed": True, "gates": results,
                                        "operational_acceptance": False}, indent=2) + "\n")
    print(json.dumps({"passed": True, "cleanup_cases": list(results)}))


if __name__ == "__main__":
    main()
