#!/usr/bin/env python3
"""Retain the actual hosted Cargo test executable without changing test selection."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid


CANDIDATE_TREE = "f935a3eb7b6dbd9071c851bc63a8e9f1cd6791f8"
HISTORICAL_SOURCE_SHA256 = "41ab5ee8614cee7910b58ed5c5600036f3c32bbc3ae567446d9ec6c357c54030"
HARNESSES = {"policy_activation", "configuration_composition_acceptance"}
# No prefix-based expansion is allowed: hosted credentials may share familiar
# GitHub, Actions, Cargo, or product prefixes with innocent execution settings.
ENV_KEYS = frozenset({
    "PATH", "LD_LIBRARY_PATH", "LIBRARY_PATH", "TMPDIR", "HOME", "CARGO_HOME",
    "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
    "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG",
    "CARGO_PROFILE_RELEASE_DEBUG", "CARGO_NET_OFFLINE", "CARGO_TERM_COLOR",
    "CARGO_MANIFEST_DIR", "CARGO_MANIFEST_PATH", "CARGO_PKG_NAME", "CARGO_PKG_VERSION",
    "RUST_BACKTRACE", "RUST_TEST_THREADS", "IN_NIX_SHELL", "NIX_BUILD_CORES",
    "CC", "CXX", "AR", "PKG_CONFIG_PATH", "PROTOC", "Z3_SYS_Z3_HEADER",
    "Z3_LIBRARY_PATH_OVERRIDE", "NO_COLOR", "MISE_COLOR", "CONTAINER_ENGINE",
    "DOCKER_HOST", "E2E_PARALLEL", "E2E_FEATURES", "E2E_TEST", "OPENSHELL_TELEMETRY_ENABLED",
    "OPENSHELL_BIN", "OPENSHELL_GATEWAY_BIN",
    "OPENSHELL_CONFORMANCE_BIN", "OPENSHELL_DOCKER_SUPERVISOR_IMAGE",
    "OPENSHELL_DOCKER_SANDBOX_RUNTIME_IMAGE", "OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE",
    "OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE_PULL_POLICY",
    "OPENSHELL_MCP_CONFORMANCE_CLIENT_IMAGE", "OPENSHELL_ACCEPTANCE_UPSTREAM_HOST",
    "OPENSHELL_E2E_HOST_GATEWAY_IP", "OPENSHELL_MCP_CONFORMANCE_HOST_BRIDGE_HOSTNAME",
    "ACCEPTANCE_PRODUCT_COMMIT", "ACCEPTANCE_CAPTURE_CONTEXT",
})


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    """Hash a file without buffering a test executable in memory."""
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    """Create a receipt exactly once."""
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def asset(path, evidence):
    """Return a portable, evidence-relative retained file reference."""
    path = Path(path)
    return {"retained_path": str(path.relative_to(evidence)), "sha256": digest(path),
            "size": path.stat().st_size}


def observed_environment(environment, runner_key=None):
    """Serialize only named noncredential execution settings."""
    keys = ENV_KEYS | ({runner_key} if runner_key else set())
    return {key: environment[key] for key in sorted(keys) if key in environment}


def source_snapshot(root, expected_commit, environment):
    """Bind tracked bytes to the selected commit and reviewed product tree."""
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, env=environment)
    require(re.fullmatch(r"[0-9a-f]{40}", expected_commit or ""), "Select a full product commit")
    commit = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    require(commit == expected_commit and tree == CANDIDATE_TREE, "Selected checkout identity differs")
    require(not git("status", "--porcelain", "--untracked-files=no").strip(), "Tracked checkout is dirty")
    files = {}
    for raw in git("ls-files", "-z").split(b"\0"):
        if not raw:
            continue
        name = os.fsdecode(raw)
        path = root / name
        require(path.is_file() or path.is_symlink(), "Missing tracked source: " + name)
        files[name] = ({"symlink": os.readlink(path)} if path.is_symlink()
                       else {"sha256": digest(path), "size": path.stat().st_size})
    inventory_sha256 = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"product_commit": commit, "candidate_tree": tree, "source_inventory_sha256": inventory_sha256,
            "historical_source_sha256": HISTORICAL_SOURCE_SHA256, "files": files}


def tool_context(root, environment):
    """Observe selected launchers and versions inside the actual task environment."""
    result = {}
    for name in ("cargo", "rustc", "rustdoc"):
        selected = environment.get(name.upper()) or shutil.which(name, path=environment.get("PATH"))
        require(selected, "Missing selected tool: " + name)
        path = Path(selected).absolute()
        completed = subprocess.run([str(path), "-vV"], cwd=root, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        require(completed.returncode == 0, "Tool version probe failed: " + name)
        result[name] = {"path": str(path), "resolved_path": str(path.resolve()), "sha256": digest(path),
                        "argv": [str(path), "-vV"], "exit_status": completed.returncode,
                        "output": completed.stdout.decode(errors="replace")}
    hosts = re.findall(r"^host: (\S+)$", result["rustc"]["output"], re.M)
    require(len(hosts) == 1 and re.fullmatch(r"(?:x86_64|aarch64)-unknown-linux-(?:gnu|musl)", hosts[0]),
            "Expected native Linux x86_64 or AArch64 Rust toolchain")
    result["host"] = hosts[0]
    return result


def prepare_metadata(source, evidence, mode, environment, tools):
    """Resolve locked metadata before Cargo holds build locks or launches tests."""
    leaves = ["docker-e2e"] if mode == "docker" else ["test-workspace", "test-server-support"]
    for leaf in leaves:
        directory = evidence / "metadata" / leaf
        directory.mkdir(parents=True)
        argv = [tools["cargo"]["path"], "metadata", "--locked", "--format-version", "1"]
        if leaf == "docker-e2e":
            argv += ["--manifest-path", "e2e/rust/Cargo.toml", "--features", "e2e-docker"]
        elif leaf == "test-server-support":
            argv += ["--features", "openshell-server/test-support"]
        started = time.time()
        completed = subprocess.run(argv, cwd=source, env=environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, check=False)
        (directory / "metadata.log").write_bytes(completed.stdout)
        (directory / "metadata-stderr.log").write_bytes(completed.stderr)
        save(directory / "metadata-receipt.json", {"argv": argv, "cwd": str(source),
             "environment": observed_environment(environment), "started": started, "finished": time.time(),
             "exit_status": completed.returncode, "selection_excludes": ["openshell-server"] if leaf == "test-workspace" else [],
             "stdout": asset(directory / "metadata.log", evidence),
             "stderr": asset(directory / "metadata-stderr.log", evidence)})
        require(completed.returncode == 0, "Read-only locked Cargo metadata failed: " + leaf)
        metadata = json.loads(completed.stdout)
        require(metadata.get("resolve") is not None, "Missing full Cargo resolve graph")
        save(directory / "metadata.json", metadata)


def prepare_capture(source_root, evidence_root, mode, environment, task_argv):
    """Return the task environment with one owned native Cargo runner hook."""
    root, evidence = Path(source_root).resolve(), Path(evidence_root).resolve()
    require(mode in {"native", "docker"}, "Unknown capture mode")
    require(task_argv and all(isinstance(value, str) for value in task_argv), "Missing literal task argv")
    require(not environment.get("CARGO_BUILD_TARGET"), "Cross-target override is not admitted")
    require(not any(key.startswith("CARGO_TARGET_") and key.endswith("_RUNNER") and value
                    for key, value in environment.items()), "Inherited Cargo runner is not admitted")
    require(not environment.get("ACCEPTANCE_CAPTURE_CONTEXT"), "Nested capture is not admitted")
    before = source_snapshot(root, environment.get("ACCEPTANCE_PRODUCT_COMMIT"), environment)
    tools = tool_context(root, environment)
    runner_key = "CARGO_TARGET_" + tools["host"].upper().replace("-", "_") + "_RUNNER"
    runner = [sys.executable, str(Path(__file__).resolve()), "runner"]
    require(all(not re.search(r"\s", value) for value in runner), "Cargo runner path contains whitespace")
    env = environment.copy()
    env[runner_key] = " ".join(runner)
    env["ACCEPTANCE_CAPTURE_CONTEXT"] = str(evidence / "context.json")
    evidence.mkdir(parents=True, exist_ok=False)
    save(evidence / "source-before.json", before)
    save(evidence / "tools.json", tools)
    prepare_metadata(root, evidence, mode, environment, tools)
    require(source_snapshot(root, environment.get("ACCEPTANCE_PRODUCT_COMMIT"), environment) == before,
            "Metadata preparation changed tracked source")
    save(evidence / "context.json", {
        "schema_version": 1, "mode": mode, "source_root": str(root), "evidence_root": str(evidence),
        "task_argv": task_argv, "task_cwd": str(root), "product_commit": before["product_commit"],
        "candidate_tree": before["candidate_tree"], "source_inventory_sha256": before["source_inventory_sha256"],
        "historical_source_sha256": HISTORICAL_SOURCE_SHA256,
        "host": tools["host"], "elf_machine": 62 if tools["host"].startswith("x86_64-") else 183,
        "runner_key": runner_key, "runner": runner,
        "environment": observed_environment(env, runner_key),
        "source_before": asset(evidence / "source-before.json", evidence),
        "tools": asset(evidence / "tools.json", evidence), "adapter_sha256": digest(Path(__file__)),
    })
    return env


def elf_identity(path, machine):
    """Require ELF64 for the observed native Rust host."""
    with Path(path).open("rb") as stream:
        header = stream.read(64)
    require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01"
            and int.from_bytes(header[18:20], "little") == machine
            and int.from_bytes(header[16:18], "little") in (2, 3), "Test executable is not native ELF64")
    return {"class": "ELF64", "endianness": "little", "machine": machine,
            "type": int.from_bytes(header[16:18], "little")}


def retain_executable(original, destination, machine):
    """Copy from an opened inode before execution and reject byte changes."""
    descriptor = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_mode & 0o111,
                "Test executable is not an executable regular file")
        with os.fdopen(os.dup(descriptor), "rb") as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
        destination.chmod(0o555)
        elf = elf_identity(destination, machine)
        copied = digest(destination)
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "Executable changed during copy")
        require(digest(original) == copied, "Retained executable differs from Cargo path")
        return {"sha256": copied, "size": before.st_size, "elf": elf,
                "device": before.st_dev, "inode": before.st_ino}
    finally:
        os.close(descriptor)


def execute_child(argv, environment, directory):
    """Tee pipes unchanged and forward cancellation to the actual child."""
    started, interrupted, previous = time.time(), [], {}
    child = subprocess.Popen(argv, env=environment, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def forward(number, _frame):
        interrupted.append(number)
        if child.poll() is None:
            child.send_signal(number)
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        previous[number] = signal.signal(number, forward)
    try:
        with selectors.DefaultSelector() as selector, (directory / "stdout.log").open("xb") as stdout, \
                (directory / "stderr.log").open("xb") as stderr, (directory / "combined.log").open("xb") as combined:
            selector.register(child.stdout, selectors.EVENT_READ, (stdout, sys.stdout.buffer))
            selector.register(child.stderr, selectors.EVENT_READ, (stderr, sys.stderr.buffer))
            while selector.get_map():
                for key, _event in selector.select(timeout=1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    stream, parent = key.data
                    stream.write(chunk)
                    stream.flush()
                    combined.write(chunk)
                    combined.flush()
                    parent.write(chunk)
                    parent.flush()
        return {"started": started, "finished": time.time(), "exit_status": child.wait(),
                "child_pid": child.pid, "forwarded_signals": interrupted}
    finally:
        # Receipt or pipe failures must not leave an unobserved test running.
        # The caller's existing task monitor continues to own the process group.
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
        for number, handler in previous.items():
            signal.signal(number, handler)


def fingerprint_closure(root):
    """Retain only the root and Cargo value-reachable dependency fingerprints."""
    nodes, values = {}, {}
    for path in sorted(root.parent.parent.glob("*/*.json")):
        value_path = path.with_suffix("")
        if not value_path.is_file():
            continue
        value = value_path.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{16}", value):
            continue
        data = json.loads(path.read_text())
        nodes[path] = data
        values.setdefault(int.from_bytes(bytes.fromhex(value), "little"), []).append(path)
    require(root in nodes, "Missing root fingerprint value")
    pending, selected = [root], set()
    while pending:
        path = pending.pop()
        if path in selected:
            continue
        selected.add(path)
        for dependency in nodes[path]["deps"]:
            require(len(dependency) == 4 and dependency[3] in values, "Incomplete Cargo dependency fingerprint graph")
            pending.extend(values[dependency[3]])
    return sorted(selected), nodes[root]


def depfile_inputs(path, executable, source, target, workspace):
    """Resolve compiler paths and admit only inputs inside the selected roots."""
    text = path.read_text().replace("\\\n", "")
    rules = [line[len(str(executable)) + 2:] for line in text.splitlines()
             if line.startswith(str(executable) + ": ")]
    require(len(rules) == 1, "Depfile lacks exactly one executable rule")
    values = []
    source, target = source.resolve(strict=True), target.resolve(strict=True)
    require(workspace.is_absolute() and workspace.resolve(strict=True) == workspace
            and workspace.is_dir() and workspace.is_relative_to(source),
            "Cargo depfile workspace is outside the selected checkout")
    for name in shlex.split(rules[0]):
        path = Path(name.replace("$$", "$"))
        # include_str! and include_bytes! preserve lexical parent components
        # in rustc depfiles. Resolve them before containment, including symlinks.
        # Cargo makes relative dep-info paths relative to its workspace root,
        # which can be a nested standalone workspace inside the checkout.
        path = (path if path.is_absolute() else workspace / path).resolve(strict=True)
        require(path.is_relative_to(source) or path.is_relative_to(target), "Depfile input escapes source/target roots")
        values.append(path)
    require(values and len(values) == len(set(values)), "Empty or duplicate executable dependencies")
    return values


def capture_provenance(original, directory, context, environment):
    """Bind one executed target to metadata, selected features, and source inputs."""
    evidence, source = Path(context["evidence_root"]), Path(context["source_root"])
    require(original.is_absolute() and original.resolve() == original and original.parent.name == "deps",
            "Cargo executable is not a direct dependency binary")
    stem, suffix = original.name.rsplit("-", 1)
    require(re.fullmatch(r"[0-9a-f]+", suffix), "Invalid Cargo executable suffix")
    profile = original.parent.parent
    roots = sorted((profile / ".fingerprint").glob("*-" + suffix + "/test-*.json"))
    require(len(roots) == 1, "Missing or ambiguous executed test fingerprint")
    fingerprint = roots[0]
    package_name = fingerprint.parent.name.removesuffix("-" + suffix)
    leaf = ("docker-e2e" if context["mode"] == "docker" else
            "test-server-support" if package_name == "openshell-server" else "test-workspace")
    metadata_directory = evidence / "metadata" / leaf
    metadata = json.loads((metadata_directory / "metadata.json").read_text())
    target = Path(metadata["target_directory"]).resolve()
    require(original.is_relative_to(target), "Executed binary is outside metadata target directory")
    packages = [row for row in metadata["packages"] if row["name"] == package_name
                and row["id"] in metadata["workspace_members"]]
    require(len(packages) == 1, "Executed target is not one workspace package")
    package = packages[0]
    manifest = Path(package["manifest_path"])
    workspace = Path(metadata["workspace_root"])
    require(manifest.is_relative_to(workspace) and manifest.is_relative_to(source)
            and Path.cwd() == manifest.parent,
            "Actual runner cwd differs from selected Cargo package")
    targets = []
    for row in package["targets"]:
        kind = "lib" if {"lib", "proc-macro"} & set(row["kind"]) else "bin" if "bin" in row["kind"] else "integration-test"
        if (row["test"] and row["name"].replace("-", "_") == stem
                and fingerprint.name == "test-" + kind + "-" + row["name"] + ".json"):
            targets.append(row)
    require(len(targets) == 1, "Fingerprint does not identify one metadata target")
    selected, root_data = fingerprint_closure(fingerprint)
    features = json.loads(root_data["features"])
    require(isinstance(features, list) and set(features) <= set(package["features"]), "Unknown compiled features")
    if leaf == "test-server-support":
        require("test-support" in features, "Server executable lacks test-support feature")
    artifacts = []
    def retain(path, kind, base=None):
        base = base or target
        require(path.is_file() and path.resolve() == path and path.is_relative_to(base), "Unsafe artifact path")
        relative = path.relative_to(base)
        destination = directory / "artifacts" / ("target" if base == target else "source") / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        before = digest(path)
        with path.open("rb") as inp, destination.open("xb") as out:
            shutil.copyfileobj(inp, out)
        destination.chmod(0o444)
        require(before == digest(path) == digest(destination), "Artifact changed during capture")
        artifacts.append({"kind": kind, "original_path": str(path),
                          "path_root": "target" if base == target else "source", "relative_path": str(relative),
                          **asset(destination, evidence)})
    for path in selected:
        retain(path, "fingerprint")
        retain(path.with_suffix(""), "fingerprint")
    depfile = original.with_suffix(".d")
    retain(depfile, "depfile")
    dependencies = depfile_inputs(depfile, original, source, target, workspace)
    require(Path(targets[0]["src_path"]).resolve(strict=True) in dependencies, "Depfile lacks selected metadata source")
    source_inputs = []
    frozen = json.loads((evidence / "source-before.json").read_text())["files"]
    for path in dependencies:
        # Generated outputs are retained; authored inputs bind to tracked bytes.
        if path.is_relative_to(target):
            require(path.suffix not in {".o", ".a", ".rlib", ".rmeta", ".so"}, "Unexpected compiled depfile input")
            retain(path, "generated-input")
        else:
            require(path.is_relative_to(source) and path.resolve() == path, "Foreign executable source input")
            name = str(path.relative_to(source))
            if name in frozen:
                require(frozen[name].get("sha256") == digest(path), "Source input differs from selected tree")
            else:
                # Generated checkout inputs have their own byte evidence and
                # are never represented as committed or historically frozen.
                retain(path, "generated-input", source)
            source_inputs.append({"source_relative_path": name, "sha256": digest(path), "size": path.stat().st_size})
    save(directory / "artifacts.json", artifacts)
    return {"leaf": leaf, "package_id": package["id"], "package": package_name,
            "target_name": targets[0]["name"], "kind": targets[0]["kind"], "features": features,
            "target_root": str(target), "depfile_base": str(workspace),
            "executable_target_relative_path": str(original.relative_to(target)),
            "source_inputs": source_inputs, "fingerprint_target_relative_path": str(fingerprint.relative_to(target)),
            "metadata": asset(metadata_directory / "metadata.json", evidence),
            "metadata_receipt": asset(metadata_directory / "metadata-receipt.json", evidence),
            "artifacts": asset(directory / "artifacts.json", evidence)}


def cargo_parent():
    """Observe the Cargo process that actually selected this executable."""
    parent = Path("/proc") / str(os.getppid())
    argv = [os.fsdecode(value) for value in (parent / "cmdline").read_bytes().split(b"\0") if value]
    require(argv and "test" in argv and Path(argv[0]).name == "cargo", "Runner was not launched by Cargo test")
    return {"pid": os.getppid(), "argv": argv, "executable": os.readlink(parent / "exe"),
            "sha256": digest(parent / "exe")}


def run_invocation(argv, environment):
    """Capture an actual Cargo runner invocation and preserve its child status."""
    context_path = Path(environment["ACCEPTANCE_CAPTURE_CONTEXT"])
    context = json.loads(context_path.read_text())
    evidence, original = Path(context["evidence_root"]), Path(argv[0])
    stem = original.name.rsplit("-", 1)[0]
    if context["mode"] == "docker" and stem not in HARNESSES:
        # Unselected Docker tests still execute once with identical arguments.
        os.execvpe(argv[0], argv, environment)
    directory = evidence / "invocations" / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=False)
    record = {"schema_version": 1, "capture_id": directory.name, "capture_passed": False,
              "product_commit": context["product_commit"], "candidate_tree": context["candidate_tree"],
              "source_inventory_sha256": context["source_inventory_sha256"],
              "historical_source_sha256": context["historical_source_sha256"], "original_executable": str(original),
              "argv": argv, "cwd": os.getcwd(), "context": asset(context_path, evidence),
              "environment": observed_environment(environment, context["runner_key"])}
    try:
        require(digest(Path(__file__)) == context["adapter_sha256"], "Capture adapter changed")
        require(environment.get(context["runner_key"]) == context["environment"][context["runner_key"]],
                "Owned runner environment changed")
        record["cargo_parent"] = cargo_parent()
        before = retain_executable(original, directory / "binary", context["elf_machine"])
        record.update(executable_sha256_before=before["sha256"], executable_before=before,
                      binary=asset(directory / "binary", evidence))
        record.update(capture_provenance(original, directory, context, environment))
        save(directory / "before.json", record)
        print("ACCEPTANCE_CAPTURE_START " + json.dumps({"id": directory.name, "argv": argv}), file=sys.stderr, flush=True)
        record.update(execute_child(argv, environment, directory))
        record["executable_sha256_after"] = digest(original)
        record["executable_after_elf"] = elf_identity(original, context["elf_machine"])
        for field, name in (("stdout", "stdout.log"), ("stderr", "stderr.log"), ("log", "combined.log")):
            record[field] = asset(directory / name, evidence)
        require(record["executable_sha256_after"] == before["sha256"] == digest(directory / "binary"),
                "Executable changed during actual test")
        for row in record["source_inputs"]:
            require(digest(Path(context["source_root"]) / row["source_relative_path"]) == row["sha256"],
                    "Source input changed during actual test")
        for row in json.loads((directory / "artifacts.json").read_text()):
            require(digest(Path(row["original_path"])) == row["sha256"], "Cargo input changed during actual test")
        record["capture_passed"] = not record["forwarded_signals"]
    except Exception as error:
        record.update(error=type(error).__name__ + ": " + str(error), finished=time.time())
    save(directory / "execution.json", record)
    print("ACCEPTANCE_CAPTURE_END " + json.dumps({"id": directory.name, "capture_passed": record["capture_passed"],
          "exit_status": record.get("exit_status")}), file=sys.stderr, flush=True)
    status = record.get("exit_status", 125) if record["capture_passed"] else 125
    return status if status >= 0 else 128 - status


def finish_capture(evidence_root, *, task_exit_status, task_log):
    """Seal completed invocations even when the original task failed."""
    evidence = Path(evidence_root).resolve()
    context = json.loads((evidence / "context.json").read_text())
    result = {"schema_version": 1, "passed": False, "capture_passed": False,
              "task_exit_status": task_exit_status, "errors": [], "invocations": []}
    try:
        paths = sorted((evidence / "invocations").glob("*/execution.json"))
        directories = list((evidence / "invocations").glob("*"))
        require(paths and len(paths) == len(directories), "Missing or incomplete runner invocation")
        rows = [json.loads(path.read_text()) for path in paths]
        result["invocations"] = [asset(path, evidence) for path in paths]
        require(all(row["capture_passed"] for row in rows), "One or more executable captures failed")
        if context["mode"] == "docker":
            require({row["target_name"] for row in rows} == HARNESSES, "Missing selected Docker harness")
        else:
            require({row["leaf"] for row in rows} == {"test-workspace", "test-server-support"}, "Missing native test context")
        verification_environment = os.environ.copy()
        verification_environment.update(context["environment"])
        after = source_snapshot(Path(context["source_root"]), context["product_commit"], verification_environment)
        save(evidence / "source-after.json", after)
        require(after == json.loads((evidence / "source-before.json").read_text()), "Source changed during shipping task")
        tools = tool_context(Path(context["source_root"]), verification_environment)
        save(evidence / "tools-after.json", tools)
        require(tools == json.loads((evidence / "tools.json").read_text()), "Selected tools changed during task")
        log = Path(task_log).resolve()
        result["task_log"] = {"original_path": str(log), "sha256": digest(log), "size": log.stat().st_size}
        result["capture_passed"] = True
        result["passed"] = task_exit_status == 0 and all(row["exit_status"] == 0 for row in rows)
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    save(evidence / "capture-result.json", result)
    return result


def main():
    """Wrap the literal shipping task, or service Cargo's native runner hook."""
    if sys.argv[1:2] == ["runner"]:
        return run_invocation(sys.argv[2:], os.environ)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["run"])
    parser.add_argument("--mode", choices=["native", "docker"], required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    require("--" in sys.argv, "Separate literal task arguments with --")
    boundary = sys.argv.index("--")
    args = parser.parse_args(sys.argv[1:boundary])
    argv = sys.argv[boundary + 1:]
    environment = prepare_capture(Path.cwd(), args.evidence, args.mode, os.environ, argv)
    execution = execute_child(argv, environment, args.evidence)
    save(args.evidence / "task-execution.json", execution)
    result = finish_capture(args.evidence, task_exit_status=execution["exit_status"], task_log=args.evidence / "combined.log")
    if not result["capture_passed"]:
        return 125
    status = execution["exit_status"]
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    raise SystemExit(main())
