#!/usr/bin/env python3
"""Run the shipping default Docker suite on a dedicated Ubuntu hosted runner."""

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time


ROLES = {"cli", "gateway", "conformance", "sandbox", "supervisor"}
COMMUNITY = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
TASK = ["mise", "run", "--jobs", "1", "e2e"]
ACCEPTANCE_TESTS = (
    "configuration_activation_live_updates_keep_endpoint_credentials_paired",
    "configuration_activation_rejected_image_repair_starts_once",
    "configuration_activation_no_image_policy_is_restrictive",
    "configuration_activation_independent_process_restarts_require_fresh_activation",
    "configuration_composition_repair_preserves_prelaunch_gate",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def validate_manifest(manifest, commit, tree, root):
    """Join downloaded products to the independently selected checkout identity."""
    require(re.fullmatch(r"[0-9a-f]{40}", commit or ""), "Select a full product commit")
    require(manifest.get("schema_version") == 1, "Unknown product manifest schema")
    require(manifest.get("product_commit") == commit, "Product commit differs")
    require(manifest.get("candidate_tree") == tree, "Product tree differs")
    require(set(manifest.get("files", {})) == ROLES, "Incomplete product binary set")
    require(set(manifest.get("images", {})) == {"sandbox", "supervisor"}, "Incomplete runtime images")
    paths = {}
    for role, entry in manifest["files"].items():
        path = (root / entry["path"]).resolve()
        require(path.is_file() and sha256(path) == entry["sha256"], f"Product hash differs: {role}")
        with path.open("rb") as stream:
            header = stream.read(20)
        require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00", f"Expected Linux x86_64 ELF: {role}")
        require(os.access(path, os.X_OK), f"Product is not executable: {role}")
        paths[role] = str(path)
    return paths


def runtime_environment(base, products, images, evidence):
    """Keep toolchain paths while removing inherited test-selection overrides."""
    env = {key: value for key, value in base.items() if not key.startswith("OPENSHELL_")}
    for key in list(env):
        if key.endswith("_RUNNER") and key.startswith("CARGO_TARGET_"):
            env.pop(key)
    for key in ("MISE_SKIP_TASKS", "MISE_TASK_ARGS", "PYTEST_ADDOPTS", "RUST_TEST_FILTER",
                "CARGO_BUILD_TARGET", "CARGO_NET_OFFLINE", "UV_OFFLINE", "UV_NO_SYNC"):
        env.pop(key, None)
    env.update(
        OPENSHELL_BIN=products["cli"], OPENSHELL_GATEWAY_BIN=products["gateway"],
        OPENSHELL_CONFORMANCE_BIN=products["conformance"],
        OPENSHELL_DOCKER_SUPERVISOR_IMAGE=images["supervisor"]["id"],
        OPENSHELL_DOCKER_SANDBOX_RUNTIME_IMAGE=images["sandbox"]["id"],
        OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE=COMMUNITY,
        OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE_PULL_POLICY="never",
        OPENSHELL_MCP_CONFORMANCE_CLIENT_IMAGE="openshell-mcp-conformance-client:acceptance",
        E2E_PARALLEL="5", CONTAINER_ENGINE="docker", DOCKER_HOST="unix:///var/run/docker.sock",
        CARGO_TERM_COLOR="never", NO_COLOR="1", MISE_COLOR="0", PYTHONDONTWRITEBYTECODE="1",
    )
    # Host paths are visible to this runner and its Docker daemon. Keeping the
    # socket-bearing temporary directory short avoids Unix socket path limits.
    temporary = Path("/tmp") / ("os-e2e-" + hashlib.sha256(str(evidence).encode()).hexdigest()[:12])
    temporary.mkdir(mode=0o700, exist_ok=False)
    env["TMPDIR"] = str(temporary)
    return env


def observed_environment(env):
    keys = {"PATH", "LD_LIBRARY_PATH", "TMPDIR", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
            "RUSTC_WRAPPER", "RUSTFLAGS", "E2E_PARALLEL", "CONTAINER_ENGINE", "DOCKER_HOST",
            "IN_NIX_SHELL", "GITHUB_ACTIONS", "UV_CACHE_DIR", "NO_COLOR", "CARGO_TERM_COLOR",
            "ACCEPTANCE_CAPTURE_CONTEXT"}
    return {key: value for key, value in env.items() if key in keys or key.startswith(("OPENSHELL_", "Z3_"))
            or key.startswith("CARGO_TARGET_") and key.endswith("_RUNNER")}


def load_capture():
    """Check the separately reviewed capture helper before importing its code."""
    directory = Path(__file__).resolve().parent
    pin = json.loads((directory / "capture-pins.json").read_text())
    require(pin["relative_path"] == "../remote-capture/remote_capture.py", "Unexpected capture module path")
    path = (directory / pin["relative_path"]).resolve()
    require(sha256(path) == pin["sha256"], "Capture helper changed")
    spec = importlib.util.spec_from_file_location("docker_executable_capture", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_captured_task(capture, root, evidence, env, run, command_record):
    """Capture the two real harnesses from the same unfiltered task invocation."""
    capture_root = evidence / "test-capture"
    env = capture.prepare_capture(root, capture_root, "docker", env, TASK)
    save(evidence / "command.json", dict(command_record, environment=observed_environment(env)))
    status = None
    try:
        output, status = run("default-e2e", TASK, env, check=False)
    finally:
        # A failed or unstarted parent must still leave a failed capture record.
        # The helper's children inherit the workflow monitor's process group.
        proof = capture.finish_capture(capture_root, task_exit_status=status,
                                       task_log=evidence / "default-e2e.log")
    return output, status, proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--products", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    root = Path.cwd().resolve()
    commands = []
    result = {"passed": False, "default_task_passed": False, "full_acceptance_claimed": False,
              "product_commit": os.environ.get("ACCEPTANCE_PRODUCT_COMMIT"),
              "workflow_run": {key: os.environ.get(key) for key in
                               ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")}}

    def run(name, argv, env=None, check=True):
        started = time.time()
        log = evidence / f"{name}.log"
        with log.open("wb") as output:
            process = subprocess.Popen(argv, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for chunk in iter(lambda: process.stdout.read1(65536), b""):
                output.write(chunk)
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            status = process.wait()
        row = {"name": name, "argv": argv, "cwd": str(root), "exit_status": status,
               "started_at": started, "finished_at": time.time(), "log": log.name,
               "log_sha256": sha256(log)}
        commands.append(row)
        save(evidence / "commands.json", commands)
        if check:
            require(status == 0, f"Command failed: {name} (exit {status})")
        return log.read_text(errors="replace"), status

    before_containers = before_networks = None
    env = None
    try:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "Use Ubuntu x86_64 host")
        require(not Path("/.dockerenv").exists(), "Run directly on the hosted VM, outside a job container")
        os_release = Path("/etc/os-release").read_text()
        require('ID=ubuntu' in os_release and 'VERSION_ID="24.04"' in os_release, "Use ubuntu-24.04")
        require(os.environ.get("GITHUB_ACTIONS") == "true", "This entrypoint is for GitHub hosted execution")
        require(os.environ.get("IN_NIX_SHELL"), "Launch this script through nix develop --command")
        commit = run("git-head", ["git", "rev-parse", "HEAD"])[0].strip()
        tree = run("git-tree", ["git", "rev-parse", "HEAD^{tree}"])[0].strip()
        require(commit == result["product_commit"], "Checkout differs from workflow product selection")
        require(not run("git-status-before", ["git", "status", "--porcelain", "--untracked-files=no"])[0].strip(), "Tracked checkout is dirty")
        manifest = json.loads(args.products.read_text())
        products = validate_manifest(manifest, commit, tree, args.products.resolve().parent)
        shutil.copyfile(args.products, evidence / "products.json")
        result.update(candidate_tree=tree, product_manifest_sha256=sha256(args.products))
        for role, spec in manifest["images"].items():
            if "archive" in spec:
                archive = (args.products.resolve().parent / spec["archive"]).resolve()
                require(sha256(archive) == spec["archive_sha256"], f"Image archive differs: {role}")
                run(f"load-{role}", ["docker", "load", "--input", str(archive)])
            inspected = json.loads(run(f"image-{role}", ["docker", "image", "inspect", spec["reference"]])[0])
            require(len(inspected) == 1 and inspected[0]["Id"] == spec["id"], f"Image identity differs: {role}")
            require(inspected[0]["Os"] == "linux" and inspected[0]["Architecture"] == "amd64", "Image architecture differs")
        env = runtime_environment(os.environ, products, manifest["images"], evidence)
        before_containers = set(run("containers-before", ["docker", "ps", "-aq"])[0].split())
        before_networks = set(run("networks-before", ["docker", "network", "ls", "-q", "--no-trunc"])[0].split())
        run("docker-info", ["docker", "info"])
        run("tool-versions", ["mise", "ls", "--current", "--json"], env)
        run("rust-version", ["rustc", "--version", "--verbose"], env)
        for role in ("cli", "gateway", "conformance"):
            run(f"loader-{role}", ["ldd", products[role]], env)
        run("python-sync", ["uv", "sync", "--frozen"], env)
        run("community-pull", ["docker", "pull", COMMUNITY], env)
        run("image-community", ["docker", "image", "inspect", COMMUNITY], env)
        probe = root / "e2e/rust/fixtures/configuration-composition/probe_upstream.py"
        run("host-route", ["python3", str(probe), "--image", COMMUNITY, "--output", str(evidence / "host-route.json")], env)
        route = json.loads((evidence / "host-route.json").read_text())
        address = ipaddress.IPv4Address(route["host_ipv4"])
        require(route["passed"] and route["host_route"] == "host-gateway" and not address.is_loopback, "Host route probe failed")
        env["OPENSHELL_ACCEPTANCE_UPSTREAM_HOST"] = str(address)
        env["OPENSHELL_E2E_HOST_GATEWAY_IP"] = str(address)
        env["OPENSHELL_MCP_CONFORMANCE_HOST_BRIDGE_HOSTNAME"] = str(address)
        command_record = {"argv": TASK, "cwd": str(root), "product_commit": commit, "candidate_tree": tree,
                          "task_inputs": {name: sha256(root / name) for name in
                                          ("mise.toml", "mise.lock", "flake.lock", "tasks/test.toml", "tasks/python.toml", "uv.lock", "e2e/rust/Cargo.toml", "e2e/rust/Cargo.lock")}}
        output, status, capture_proof = run_captured_task(load_capture(), root, evidence, env, run, command_record)
        result["test_capture"] = capture_proof
        named = {name: bool(re.search(r"\btest " + re.escape(name) + r" \.\.\. ok\b", output)) for name in ACCEPTANCE_TESTS}
        # Libtest may interleave --nocapture output with its pretty result lines.
        # These named-line sightings are supplemental; the unfiltered shipping
        # task exit status remains authoritative for this execution receipt.
        result.update(default_exit_status=status, registered_test_lines_observed=named,
                      default_task_passed=status == 0)
        # Keep the raw log authoritative. This convenience extraction does not
        # replace the registered observation validators or a final gate report.
        (evidence / "acceptance-observations.log").write_text("\n".join(line for line in output.splitlines()
            if "ACTIVATION_OBSERVATION " in line or "COMPOSITION_OBSERVATION " in line) + "\n")
        require(result["default_task_passed"], "Default task failed")
        require(capture_proof.get("passed") is True, "Required harness executable capture failed")
        require(not run("git-status-after", ["git", "status", "--porcelain", "--untracked-files=no"])[0].strip(), "Task modified tracked source")
        result["passed"] = True
    except Exception as error:
        result["error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    finally:
        # The shipping wrappers own normal cleanup. Record any leaked resources
        # before removing only resources created on this otherwise dedicated VM.
        if before_containers is not None:
            try:
                containers = set(run("containers-after", ["docker", "ps", "-aq"])[0].split()) - before_containers
                networks = set(run("networks-after", ["docker", "network", "ls", "-q", "--no-trunc"])[0].split()) - before_networks
                result["cleanup"] = {"leaked_containers": sorted(containers), "leaked_networks": sorted(networks)}
                if containers or networks:
                    result["passed"] = False
                for index, container in enumerate(sorted(containers)):
                    run(f"leak-inspect-{index}", ["docker", "inspect", container], check=False)
                    run(f"leak-log-{index}", ["docker", "logs", container], check=False)
                    run(f"leak-remove-{index}", ["docker", "rm", "--force", container])
                for index, network in enumerate(sorted(networks)):
                    run(f"leak-network-remove-{index}", ["docker", "network", "rm", network])
            except Exception as error:
                result.update(passed=False, cleanup_error=str(error))
        save(evidence / "result.json", result)
        assets = {path.name: {"sha256": sha256(path), "bytes": path.stat().st_size}
                  for path in sorted(evidence.iterdir()) if path.is_file() and path.name != "assets.json"}
        capture_result = evidence / "test-capture/capture-result.json"
        if capture_result.is_file():
            assets["test-capture/capture-result.json"] = {"sha256": sha256(capture_result), "bytes": capture_result.stat().st_size}
        save(evidence / "assets.json", assets)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
