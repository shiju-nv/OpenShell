#!/usr/bin/env python3
"""Give hosted test tasks inherited confinement without changing their arguments."""

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading


CAPABILITIES = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def snapshot(status_path="/proc/self/status"):
    """Observe real kernel state; thread probes use their own procfs status."""
    fields = dict(line.split(":", 1) for line in Path(status_path).read_text().splitlines() if ":" in line)
    return {
        "uids": list(os.getresuid()),
        "gids": list(os.getresgid()),
        "groups": sorted(os.getgroups()),
        "process_group": os.getpgrp(),
        "capabilities": {key: int(fields[key].strip(), 16) for key in CAPABILITIES},
        "no_new_privileges": int(fields["NoNewPrivs"].strip()),
    }


def validate_confinement(observed, original):
    """Require the original identity and process group with no remaining caps."""
    for key in ("uids", "gids", "groups", "process_group"):
        require(observed[key] == original[key], f"Restored {key} differs from the original runner")
    require(observed["no_new_privileges"] == 1, "NoNewPrivs is not set")
    require(set(observed["capabilities"]) == set(CAPABILITIES), "Capability evidence is incomplete")
    require(all(value == 0 for value in observed["capabilities"].values()), "Capabilities remain raised")


def sudo_argv(helper, payload_path, original):
    """Run only the system privilege dropper as root, then an unprivileged verifier."""
    groups = original["groups"]
    return [
        "/usr/bin/sudo", "-n", "--", "/usr/bin/setpriv",
        f"--reuid={original['uids'][0]}", f"--regid={original['gids'][0]}",
        "--groups=" + ",".join(map(str, groups)) if groups else "--clear-groups",
        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
        "--", "/usr/bin/python3", str(helper), "--resume", str(payload_path),
    ]


def probe():
    """Measure the exec-created leader and a new thread before any product runs."""
    result = {"leader": snapshot()}
    errors = []

    def measure_thread():
        try:
            result["thread"] = snapshot("/proc/thread-self/status")
        except BaseException as error:
            errors.append(str(error))

    thread = threading.Thread(target=measure_thread)
    thread.start()
    thread.join()
    require(not errors and "thread" in result, "Thread confinement probe failed")
    print(json.dumps(result))


def resume(payload_path):
    """Restore the private environment only after setpriv removed all privilege."""
    metadata = payload_path.lstat()
    parent = payload_path.parent.lstat()
    require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600,
            "Private handoff must be a regular mode-0600 file")
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700,
            "Private handoff directory must have mode 0700")
    require(metadata.st_uid == parent.st_uid == os.getuid() != 0, "Private handoff owner mismatch")
    payload = json.loads(payload_path.read_text())
    original = payload["original"]
    observed = snapshot()
    validate_confinement(observed, original)
    require(str(Path.cwd()) == payload["cwd"], "Task working directory changed")
    environment = payload["environment"]
    require(environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("RUNNER_ENVIRONMENT") == "github-hosted", "Not a hosted task")
    # The environment can contain runner credentials. Never serialize it into
    # uploaded receipts or argv, and remove its private file before task exec.
    payload_path.unlink()
    payload_path.parent.rmdir()
    os.environ.clear()
    os.environ.update(environment)
    require(dict(os.environ) == environment, "Task environment restoration failed")
    helper = Path(__file__).resolve()
    child = subprocess.run(["/usr/bin/python3", str(helper), "--probe"],
                           capture_output=True, text=True, check=False, timeout=15)
    require(child.returncode == 0, "Confinement exec/thread self-probe failed")
    measurements = json.loads(child.stdout)
    require(set(measurements) == {"leader", "thread"}, "Incomplete self-probe")
    for measurement in measurements.values():
        validate_confinement(measurement, original)
    write_json(Path(payload["evidence"]) / "confinement.json", {
        "schema_version": 1, "passed": True,
        "original": original, "restored": observed, "exec_probe": measurements,
        "environment_restored_exactly": True, "private_handoff_removed": True,
        "cwd": payload["cwd"], "task_argv": payload["argv"],
    })
    # No new session or process group: the existing outer monitor owns the task.
    os.execvpe(payload["argv"][0], payload["argv"], environment)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--resume", type=Path)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    require(sys.platform == "linux", "Hosted confinement requires Linux")
    if args.probe:
        probe()
        return
    if args.resume is not None:
        resume(args.resume)
        return
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "Not a hosted task")
    argv = args.command[1:] if args.command[:1] == ["--"] else args.command
    require(args.evidence is not None and argv, "Evidence and a literal task are required")
    original = snapshot()
    require(len(set(original["uids"])) == len(set(original["gids"])) == 1
            and original["uids"][0] != 0 and original["gids"][0] != 0,
            "Expected a nonroot runner with uniform saved/real/effective identity")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": 1, "passed": False, "task_argv": argv, "exit_code": None}
    private = None

    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)

    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        private = Path(tempfile.mkdtemp(prefix="acceptance-confined-", dir=os.environ["RUNNER_TEMP"]))
        require(not private.is_relative_to(evidence), "Private handoff cannot be uploaded evidence")
        payload_path = private / "environment.json"
        payload = {"original": original, "environment": dict(os.environ),
                   "cwd": str(Path.cwd()), "argv": argv, "evidence": str(evidence)}
        with payload_path.open("x") as stream:
            os.chmod(payload_path, 0o600)
            json.dump(payload, stream)
        launch = sudo_argv(Path(__file__).resolve(), payload_path, original)
        write_json(evidence / "command.json", {"argv": launch, "task_argv": argv,
                   "cwd": str(Path.cwd()), "original": original})
        # Inherit stdin/stdout/stderr and the outer process group. The resumed
        # child rejects sudo configurations that move it to another group.
        completed = subprocess.run(launch, check=False)
        result["exit_code"] = completed.returncode
        receipt = json.loads((evidence / "confinement.json").read_text())
        result["passed"] = completed.returncode == 0 and receipt["passed"] is True
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        # A failed sudo launch may leave the credential-bearing handoff behind.
        # It is outside the upload tree and only these exact owned paths are removed.
        for signum in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, signal.SIG_IGN)
        if private is not None and private.exists():
            (private / "environment.json").unlink(missing_ok=True)
            private.rmdir()
        result["private_handoff_removed"] = private is None or not private.exists()
        write_json(evidence / "result.json", result)
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
