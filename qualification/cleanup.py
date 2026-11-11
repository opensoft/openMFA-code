"""Best-effort run-owned finalization; failed absence readback never qualifies."""
import subprocess


def cleanup_resources(docker, label):
    failures = []
    for kind, list_command, remove_command in (
        ("containers", ["ps", "-aq"], ["rm", "-f"]),
        ("networks", ["network", "ls", "-q"], ["network", "rm"]),
        ("volumes", ["volume", "ls", "-q"], ["volume", "rm"]),
        ("images", ["image", "ls", "-q"], ["image", "rm"]),
    ):
        identifiers = []
        try:
            listing = docker(*list_command, "--filter", "label=" + label, check=False, timeout=10)
            if listing.returncode:
                failures.append(kind + "-listing")
            else:
                identifiers = list(dict.fromkeys(listing.stdout.split()))
        except (subprocess.SubprocessError, OSError):
            failures.append(kind + "-listing-exception")
        for identifier in identifiers:
            try:
                if docker(*remove_command, identifier, check=False, timeout=10).returncode:
                    failures.append(kind + "-removal")
            except (subprocess.SubprocessError, OSError):
                failures.append(kind + "-removal-exception")
        try:
            readback = docker(*list_command, "--filter", "label=" + label, check=False, timeout=10)
            if readback.returncode or readback.stdout.strip():
                failures.append(kind + "-absence")
        except (subprocess.SubprocessError, OSError):
            failures.append(kind + "-absence-exception")
    return failures


def finalize(docker, label, temporary):
    failures = cleanup_resources(docker, label)
    try:
        temporary.cleanup()
    except OSError:
        failures.append("private-temporary-state")
    return {"absence_verified": not failures, "failures": failures}
