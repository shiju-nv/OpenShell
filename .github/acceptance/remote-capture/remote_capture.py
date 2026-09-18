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


CANDIDATE_TREE = "fcdcfe206a67939ecf30903b6b46bc6953402ce4"
HISTORICAL_SOURCE_SHA256 = "41ab5ee8614cee7910b58ed5c5600036f3c32bbc3ae567446d9ec6c357c54030"
HARNESSES = {"policy_activation", "configuration_composition_acceptance"}
EXAMPLE_MANIFEST = "examples/supervisor-middleware-content-guard/Cargo.toml"
EXAMPLE_PACKAGE = "openshell-supervisor-middleware-content-guard"
EXAMPLE_COMMAND = ["nextest", "run", "--config-file", ".config/nextest.toml",
                   "--manifest-path", EXAMPLE_MANIFEST]
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
    "NEXTEST", "NEXTEST_RUN_ID", "NEXTEST_BINARY_ID", "NEXTEST_TEST_NAME",
    "NEXTEST_ATTEMPT", "NEXTEST_PROFILE", "NEXTEST_VERSION", "NEXTEST_WORKSPACE_ROOT",
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


def cargo_probe_inputs():
    """Describe an inert locked workspace that cannot compile a build script."""
    return {
        "Cargo.toml": '[package]\nname = "capture-tool-probe"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n',
        "Cargo.lock": '# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = "capture-tool-probe"\nversion = "0.0.0"\n',
        "src/lib.rs": "",
    }


def cargo_probe_inspections(environment):
    """Allow only the pinned Cargo version's compiler introspection forms."""
    flags = (environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f") if environment.get("CARGO_ENCODED_RUSTFLAGS") else
             [] if "CARGO_ENCODED_RUSTFLAGS" in environment else shlex.split(environment.get("RUSTFLAGS", "")))
    # Inherited flags may affect discovery, but must never add an input, output,
    # plugin, or emit operation to this otherwise print-only invocation.
    offset = 0
    codegen = {"debuginfo", "opt-level", "debug-assertions", "overflow-checks", "target-feature", "target-cpu",
               "panic", "lto", "codegen-units", "linker", "link-arg", "relocation-model", "code-model", "force-frame-pointers"}
    while offset < len(flags):
        flag = flags[offset]
        if flag in {"--cfg", "-C", "-L", "-A", "-W", "-D", "-F"}:
            require(offset + 1 < len(flags) and flags[offset + 1] and not flags[offset + 1].startswith("-"), "Unsafe inspection flag")
            require(flag != "-C" or flags[offset + 1].split("=", 1)[0] in codegen, "Unsupported inspection codegen flag")
            offset += 2
        else:
            require(flag.startswith("--cfg=") and len(flag) > 6, "Unsupported compiler inspection flag")
            offset += 1
    return [["-vV"], ["-", "--crate-name", "___", "--print=file-names", *flags, "--crate-type", "bin",
            "--crate-type", "rlib", "--crate-type", "dylib", "--crate-type", "cdylib",
            "--crate-type", "staticlib", "--crate-type", "proc-macro", "--print=sysroot",
            "--print=split-debuginfo", "--print=crate-name", "--print=cfg", "-Wwarnings"]]


def cargo_probe_script(adapter, interpreter, directory):
    """Generate the owned wrapper without a shell or environment-selected code."""
    return ("#!" + interpreter + "\nimport runpy, sys\n"
            "sys.argv = " + repr([adapter, "tool-probe", directory]) + " + sys.argv[1:]\n"
            "runpy.run_path(" + repr(adapter) + ", run_name='__main__')\n")


def run_tool_probe(directory, argv):
    """Observe live Cargo while forwarding only empty-input Rustc inspection."""
    directory = Path(directory).resolve(strict=True)
    context = json.loads((directory / "probe-context.json").read_text())
    target = directory / "observations" / uuid.uuid4().hex
    target.mkdir(parents=True, exist_ok=False)
    record = {"argv": argv, "cwd": str(Path.cwd()), "pid": os.getpid(), "started": time.time(), "passed": False}
    try:
        require(digest(Path(__file__)) == context["adapter_sha256"], "Tool observer adapter changed")
        require(argv and argv[0] == context["rustc"]["path"] and argv[1:] in cargo_probe_inspections(context["inspection_environment"]),
                "Unowned compiler inspection")
        require(Path.cwd() == directory / "fixture", "Compiler inspection cwd changed")
        data = sys.stdin.buffer.read() if argv[1:] != ["-vV"] else b""
        record["stdin_size"] = len(data)
        require(not data, "Compiler inspection received source input")
        record["parent"] = process_snapshot(os.getppid())
        require(digest(Path(argv[0])) == context["rustc"]["sha256"], "Inspection compiler changed")
        result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        record.update(exit_status=result.returncode, parent_after=process_snapshot(os.getppid()))
        (target / "stdout.log").write_bytes(result.stdout)
        (target / "stderr.log").write_bytes(result.stderr)
        record.update(stdout=asset(target / "stdout.log", directory), stderr=asset(target / "stderr.log", directory))
        require(record["parent_after"] == record["parent"] and digest(Path(argv[0])) == context["rustc"]["sha256"],
                "Tool inspection process changed")
        record["passed"] = result.returncode == 0
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
    except Exception as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    record["finished"] = time.time()
    save(target / "execution.json", record)
    return record.get("exit_status", 125) if record["passed"] else 125


def observe_cargo_execution(evidence, phase, environment, tools):
    """Bind a launcher to live Cargo without compiling or changing test argv."""
    directory = evidence / "tool-observations" / phase
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    require(directory.resolve(strict=True) == directory and directory.stat().st_uid == os.getuid(), "Unsafe tool probe directory")
    fixture = directory / "fixture"
    for name, content in cargo_probe_inputs().items():
        path = fixture / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    launcher, rustc = tools["cargo"], tools["rustc"]
    adapter, interpreter = str(Path(__file__).resolve()), sys.executable
    require(not any(re.search(r"\s", value) for value in (adapter, interpreter, str(directory))), "Unsafe observer path")
    observer = directory / "observer"
    observer.write_text(cargo_probe_script(adapter, interpreter, str(directory)))
    observer.chmod(0o755)
    inspection_environment = {key: environment[key] for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET") if key in environment}
    require(inspection_environment.get("CARGO_BUILD_TARGET", tools["host"]) in ("", tools["host"]), "Cross-target tool inspection")
    cargo_probe_inspections(inspection_environment)
    save(directory / "probe-context.json", {"adapter_sha256": digest(adapter), "rustc": rustc, "inspection_environment": inspection_environment})
    overrides = {"CARGO_HOME": str(directory / "cargo-home"), "CARGO_TARGET_DIR": str(directory / "target"),
                 "CARGO_CACHE_RUSTC_INFO": "0", "CARGO_NET_OFFLINE": "true", "RUSTC": rustc["path"],
                 "RUSTC_WRAPPER": str(observer), "RUSTC_WORKSPACE_WRAPPER": ""}
    env = {**environment, **overrides}
    argv = [launcher["path"], "metadata", "--locked", "--offline", "--format-version", "1"]
    record = {"schema_version": 1, "phase": phase, "passed": False, "argv": argv, "cwd": str(fixture),
              "probe_root": str(directory), "launcher": launcher.copy(), "interpreter": interpreter,
              "adapter": adapter, "adapter_sha256": digest(adapter), "environment_overrides": overrides,
              "inspection_environment": inspection_environment,
              "environment": observed_environment(env), "started": time.time(),
              "launcher_sha256_before": digest(launcher["path"]),
              "fixture": {name: asset(fixture / name, evidence) for name in cargo_probe_inputs()},
              "observer": asset(observer, evidence), "probe_context": asset(directory / "probe-context.json", evidence)}
    try:
        process = subprocess.Popen(argv, cwd=fixture, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        record["spawned_pid"] = process.pid
        stdout, stderr = process.communicate()
        record.update(exit_status=process.returncode, finished=time.time())
        (directory / "stdout.log").write_bytes(stdout)
        (directory / "stderr.log").write_bytes(stderr)
        record.update(stdout=asset(directory / "stdout.log", evidence), stderr=asset(directory / "stderr.log", evidence))
        paths = sorted((directory / "observations").glob("*/execution.json"))
        record["observations"] = [asset(path, evidence) for path in paths]
        require(process.returncode == 0 and paths and len(paths) == len(list((directory / "observations").iterdir())),
                "Cargo execution probe failed or lacked complete observations")
        rows = [json.loads(path.read_text()) for path in paths]
        parent = rows[0]["parent"]
        require(parent["pid"] == process.pid and parent["argv"][1:] == argv[1:] and parent["cwd"] == str(fixture),
                "Cargo probe was not observed in the launched process")
        executable = Path(parent["executable"])
        require(executable.is_absolute() and executable.resolve(strict=True) == executable
                and executable.name == "cargo" and Path(parent["argv"][0]).resolve(strict=True) == executable
                and digest(executable) == parent["sha256"], "Invalid observed Cargo executable")
        require(all(row["passed"] and row["exit_status"] == 0 and row["parent"] == row["parent_after"] == parent
                    for row in rows), "Cargo observer failed or changed parent")
        require(any(row["argv"][1:] == ["-vV"] for row in rows), "Cargo did not inspect Rustc version")
        record["launcher_sha256_after"] = digest(launcher["path"])
        require(record["launcher_sha256_before"] == record["launcher_sha256_after"] == launcher["sha256"],
                "Cargo launcher changed during probe")
        require(all((fixture / name).read_text() == content for name, content in cargo_probe_inputs().items())
                and not (fixture / "build.rs").exists(), "Cargo probe fixture changed")
        record["execution"] = {"resolved_path": str(executable), "sha256": parent["sha256"]}
        record["passed"] = True
    except Exception as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        record["finished"] = time.time()
        save(directory / "receipt.json", record)
    return record["execution"]


def tool_context(root, environment, evidence, phase, *, include_nextest=False):
    """Observe selected launchers and versions inside the actual task environment."""
    require(evidence.is_absolute() and evidence.resolve(strict=True) == evidence
            and not evidence.is_relative_to(Path(root).resolve(strict=True)), "Tool probes must be outside the product workspace")
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
    # Launcher versions are stable; process IDs and probe paths belong only in
    # the separate receipts so before/after tool equality remains meaningful.
    result["cargo"]["execution"] = observe_cargo_execution(evidence, phase, environment, result)
    if not include_nextest:
        return result
    selected = shutil.which("cargo-nextest", path=environment.get("PATH"))
    require(selected, "Missing selected cargo-nextest")
    path = Path(selected).absolute()
    # The locked Nix package installs an ELF directly. A wrapper requires an
    # explicit launcher-to-process observation, never a basename exception.
    elf_identity(path, 62 if result["host"].startswith("x86_64-") else 183)
    completed = subprocess.run([str(path), "--version"], cwd=root, env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    require(completed.returncode == 0, "Nextest version probe failed")
    result["cargo-nextest"] = {"path": str(path), "resolved_path": str(path.resolve()),
                              "sha256": digest(path), "argv": [str(path), "--version"],
                              "exit_status": completed.returncode,
                              "output": completed.stdout.decode(errors="replace")}
    return result


def prepare_metadata(source, evidence, mode, environment, tools):
    """Resolve locked metadata before Cargo holds build locks or launches tests."""
    leaves = ["docker-e2e"] if mode == "docker" else ["test-workspace", "test-server-support", "test-content-guard"]
    for leaf in leaves:
        directory = evidence / "metadata" / leaf
        directory.mkdir(parents=True)
        argv = [tools["cargo"]["path"], "metadata", "--locked", "--format-version", "1"]
        if leaf == "docker-e2e":
            argv += ["--manifest-path", "e2e/rust/Cargo.toml", "--features", "e2e-docker"]
        elif leaf == "test-server-support":
            argv += ["--features", "openshell-server/test-support"]
        elif leaf == "test-content-guard":
            argv += ["--manifest-path", EXAMPLE_MANIFEST]
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
    require(not any(key.startswith("NEXTEST_") for key in environment),
            "Inherited Nextest selectors are not admitted")
    before = source_snapshot(root, environment.get("ACCEPTANCE_PRODUCT_COMMIT"), environment)
    evidence.mkdir(parents=True, exist_ok=False)
    tools = tool_context(root, environment, evidence, "before", include_nextest=mode == "native")
    runner_key = "CARGO_TARGET_" + tools["host"].upper().replace("-", "_") + "_RUNNER"
    runner = [sys.executable, str(Path(__file__).resolve()), "runner"]
    require(all(not re.search(r"\s", value) for value in runner), "Cargo runner path contains whitespace")
    env = environment.copy()
    env[runner_key] = " ".join(runner)
    env["ACCEPTANCE_CAPTURE_CONTEXT"] = str(evidence / "context.json")
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
        "tool_probe": asset(evidence / "tool-observations/before/receipt.json", evidence),
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
        # Rust may spell one include through several source-relative paths.
        # Validate every spelling before retaining its canonical input once.
        if path not in values:
            values.append(path)
    require(values, "Empty executable dependencies")
    return values


def capture_provenance(original, directory, context, environment, *, example_nextest=False):
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
    require(not example_nextest or context["mode"] == "native" and package_name == EXAMPLE_PACKAGE,
            "Nextest did not select the standalone content-guard package")
    leaf = ("test-content-guard" if example_nextest else "docker-e2e" if context["mode"] == "docker" else
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


def process_snapshot(pid):
    """Bind one live Linux process to its argv, executable, cwd, and birth time."""
    require(type(pid) is int and pid > 0, "Invalid process identifier")
    directory = Path("/proc") / str(pid)
    before = (directory / "stat").read_text()
    fields = before.rsplit(")", 1)[1].split()
    result = {"pid": pid, "ppid": int(fields[1]), "start_ticks": int(fields[19]),
              "argv": [os.fsdecode(value) for value in (directory / "cmdline").read_bytes().split(b"\0") if value],
              "executable": os.readlink(directory / "exe"), "sha256": digest(directory / "exe"),
              "cwd": os.readlink(directory / "cwd")}
    after = (directory / "stat").read_text().rsplit(")", 1)[1].split()
    require(fields[1] == after[1] and fields[19] == after[19], "Process ancestry changed during capture")
    return result


def rustdoc_option(argv, option):
    """Collect both rustdoc option spellings without accepting missing values."""
    values = []
    for offset, value in enumerate(argv):
        if value == option:
            require(offset + 1 < len(argv), "Missing rustdoc option value")
            values.append(argv[offset + 1])
        elif value.startswith(option + "="):
            values.append(value[len(option) + 1:])
    return values


def doctest_provenance(argv, context, environment, parent, cargo):
    """Authenticate rustdoc's temporary executable without Cargo depfile claims."""
    require(context["mode"] == "native", "Doctest capture requires native mode")
    evidence, source = Path(context["evidence_root"]), Path(context["source_root"])
    tools = json.loads((evidence / "tools.json").read_text())
    for row, name in ((parent, "rustdoc"), (cargo, "cargo")):
        selected_tool = tools[name]["execution"] if name == "cargo" else tools[name]
        require(row["argv"] and Path(row["argv"][0]).name == name and
                row["executable"] == selected_tool["resolved_path"] and row["sha256"] == selected_tool["sha256"],
                "Doctest process differs from pinned " + name)
    require(parent["ppid"] == cargo["pid"] and parent["pid"] == os.getppid(), "Broken rustdoc/Cargo parent chain")
    commands = {"test-workspace": ["test", "--workspace", "--exclude", "openshell-server"],
                "test-server-support": ["test", "-p", "openshell-server", "--features", "test-support"]}
    leaves = [name for name, command in commands.items() if cargo["argv"][1:] == command]
    require(len(leaves) == 1 and Path(cargo["cwd"]).resolve(strict=True) == source,
            "Filtered or changed doctest Cargo parent")
    leaf = leaves[0]
    metadata_path = evidence / "metadata" / leaf / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    args = parent["argv"][1:]
    require(args.count("--test") == 1 and not rustdoc_option(args, "--test-args"), "Filtered rustdoc tests")
    require(rustdoc_option(args, "--test-runtool") == context["runner"][:1] and
            rustdoc_option(args, "--test-runtool-arg") == context["runner"][1:], "Foreign rustdoc runner")
    require(rustdoc_option(args, "--target") in ([], [context["host"]]), "Cross-target rustdoc")
    crate = rustdoc_option(args, "--crate-name")
    test_directory = rustdoc_option(args, "--test-run-directory")
    require(len(crate) == len(test_directory) == 1, "Ambiguous rustdoc crate/directory")
    matches = [(package, target) for package in metadata["packages"]
               if package["id"] in metadata["workspace_members"]
               and (package["name"] == "openshell-server") == (leaf == "test-server-support")
               for target in package["targets"] if target["doctest"]
               and set(target["kind"]) & {"lib", "proc-macro"}
               and target["name"].replace("-", "_") == crate[0]]
    require(len(matches) == 1, "Rustdoc does not select one enabled metadata target")
    package, selected = matches[0]
    manifest = Path(package["manifest_path"]).resolve(strict=True)
    source_path = Path(selected["src_path"]).resolve(strict=True)
    require(manifest.is_relative_to(source) and source_path.is_relative_to(source)
            and Path(test_directory[0]).resolve(strict=True) == manifest.parent == Path.cwd(),
            "Rustdoc source/test directory escapes selected package")
    rustdoc_cwd = Path(parent["cwd"]).resolve(strict=True)
    require(rustdoc_cwd.is_relative_to(source), "Rustdoc cwd escapes selected source")
    # The source may be workspace-relative even though the test runs in the
    # package directory. Only the observed rustdoc cwd resolves its spelling.
    selected_args = [value for value in args if not value.startswith("-")
                     and (rustdoc_cwd / value).resolve() == source_path]
    require(len(selected_args) == 1, "Rustdoc argv does not select the metadata source")
    features = sorted(value[len('feature="'):-1] for value in rustdoc_option(args, "--cfg")
                      if value.startswith('feature="') and value.endswith('"'))
    require(len(features) == len(set(features)) and set(features) <= set(package["features"]), "Unknown rustdoc features")
    require(leaf != "test-server-support" or "test-support" in features, "Rustdoc lacks server feature")
    require(environment.get("TMPDIR") == context["environment"].get("TMPDIR") and environment.get("TMPDIR"),
            "Changed or absent doctest temporary root")
    temporary = Path(environment["TMPDIR"])
    require(temporary.is_absolute() and temporary.resolve(strict=True) == temporary and temporary.is_dir(),
            "Noncanonical doctest temporary root")
    original = Path(argv[0])
    require(len(argv) == 1 and original.is_absolute() and original.resolve(strict=True) == original
            and original.name == "rust_out" and original.parent.parent == temporary
            and re.fullmatch(r"rustdoctest[A-Za-z0-9_]+", original.parent.name),
            "Doctest executable escapes its temporary root or changes selection")
    relative = str(source_path.relative_to(source))
    frozen = json.loads((evidence / "source-before.json").read_text())["files"]
    require(relative in frozen and digest(source_path) == frozen[relative]["sha256"], "Rustdoc source differs from selected tree")
    return {"leaf": leaf, "package_id": package["id"], "package": package["name"],
            "target_name": selected["name"], "kind": selected["kind"], "features": features,
            "metadata": asset(metadata_path, evidence),
            "metadata_receipt": asset(metadata_path.with_name("metadata-receipt.json"), evidence),
            "temporary_root": str(temporary), "rustdoc_source": {"source_relative_path": relative, **frozen[relative]},
            "provenance_kind": "rustdoc-source-context", "cargo_fingerprint_retained": False, "depfile_retained": False}


def run_doctest(argv, environment, context_path, context):
    """Capture the actual rustdoc-selected child once and preserve its status."""
    evidence, original = Path(context["evidence_root"]), Path(argv[0])
    directory = evidence / "doctests" / uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=False)
    record = {"schema_version": 1, "capture_kind": "rustdoc", "capture_id": directory.name,
              "capture_passed": False, "product_commit": context["product_commit"],
              "candidate_tree": context["candidate_tree"], "source_inventory_sha256": context["source_inventory_sha256"],
              "historical_source_sha256": context["historical_source_sha256"], "original_executable": str(original),
              "argv": argv, "cwd": os.getcwd(), "context": asset(context_path, evidence),
              "environment": observed_environment(environment, context["runner_key"])}
    try:
        require(digest(Path(__file__)) == context["adapter_sha256"], "Capture adapter changed")
        require(environment.get(context["runner_key"]) == context["environment"][context["runner_key"]],
                "Owned runner environment changed")
        parent = process_snapshot(os.getppid())
        cargo = process_snapshot(parent["ppid"])
        record.update(rustdoc_parent=parent, cargo_parent=cargo)
        record.update(doctest_provenance(argv, context, environment, parent, cargo))
        before = retain_executable(original, directory / "binary", context["elf_machine"])
        record.update(executable_sha256_before=before["sha256"], executable_before=before,
                      binary=asset(directory / "binary", evidence))
        save(directory / "before.json", record)
        print("ACCEPTANCE_DOCTEST_START " + json.dumps({"id": directory.name, "argv": argv}), file=sys.stderr, flush=True)
        record.update(execute_child(argv, environment, directory))
        record.update(executable_sha256_after=digest(original), executable_after_elf=elf_identity(original, context["elf_machine"]))
        for field, name in (("stdout", "stdout.log"), ("stderr", "stderr.log"), ("log", "combined.log")):
            record[field] = asset(directory / name, evidence)
        require(record["executable_sha256_after"] == before["sha256"] == digest(directory / "binary"),
                "Doctest executable changed during execution")
        require(process_snapshot(parent["pid"]) == parent and process_snapshot(cargo["pid"]) == cargo,
                "Doctest parent chain changed during execution")
        selected_source = Path(context["source_root"]) / record["rustdoc_source"]["source_relative_path"]
        require(digest(selected_source) == record["rustdoc_source"]["sha256"], "Rustdoc source changed during execution")
        record["capture_passed"] = not record["forwarded_signals"]
    except Exception as error:
        record.update(error=type(error).__name__ + ": " + str(error), finished=time.time())
    save(directory / "execution.json", record)
    print("ACCEPTANCE_DOCTEST_END " + json.dumps({"id": directory.name, "capture_passed": record["capture_passed"],
          "exit_status": record.get("exit_status")}), file=sys.stderr, flush=True)
    status = record.get("exit_status", 125) if record["capture_passed"] else 125
    return status if status >= 0 else 128 - status


def cargo_parent():
    """Observe the Cargo process that actually selected this executable."""
    parent = Path("/proc") / str(os.getppid())
    argv = [os.fsdecode(value) for value in (parent / "cmdline").read_bytes().split(b"\0") if value]
    require(argv and "test" in argv and Path(argv[0]).name == "cargo", "Runner was not launched by Cargo test")
    return {"pid": os.getppid(), "argv": argv, "executable": os.readlink(parent / "exe"),
            "sha256": digest(parent / "exe")}


def nextest_invocation(parent, tool, context, argv, environment):
    """Authenticate the standalone shipping scope and distinguish list/run calls."""
    source = Path(context["source_root"])
    require(context["mode"] == "native" and parent["argv"][1:] == EXAMPLE_COMMAND
            and parent["cwd"] == str(source), "Changed or filtered content-guard Nextest parent")
    require(parent["executable"] == tool["resolved_path"] and parent["sha256"] == tool["sha256"]
            and Path(parent["argv"][0]).resolve(strict=True) == Path(tool["resolved_path"]),
            "Nextest parent differs from the observed selected tool")
    workspace = str(source / Path(EXAMPLE_MANIFEST).parent)
    require(environment.get("NEXTEST_WORKSPACE_ROOT") == workspace
            and environment.get("CARGO_MANIFEST_DIR") == workspace
            and environment.get("CARGO_PKG_NAME") == EXAMPLE_PACKAGE,
            "Nextest selected a foreign workspace/package")
    run_id = environment.get("NEXTEST_RUN_ID", "")
    require(str(uuid.UUID(run_id)) == run_id and environment.get("NEXTEST_BINARY_ID"),
            "Nextest run/binary identity is absent")
    listing = argv[1:] in (["--list", "--format", "terse"],
                          ["--list", "--format", "terse", "--ignored"])
    name = environment.get("NEXTEST_TEST_NAME")
    if listing:
        require(not name, "Discovery invocation claims an executed test")
    else:
        require(name and argv[1:] in (["--exact", name, "--nocapture"],
                                     ["--exact", name, "--nocapture", "--ignored"]),
                "Unexpected Nextest test selection")
        require(environment.get("NEXTEST") == "1"
                and re.fullmatch(r"[1-9][0-9]*", environment.get("NEXTEST_ATTEMPT", "")),
                "Missing Nextest execution identity")
    return {"phase": "list" if listing else "run", "run_id": run_id,
            "binary_id": environment["NEXTEST_BINARY_ID"], "test_name": name,
            "attempt": environment.get("NEXTEST_ATTEMPT")}


def run_invocation(argv, environment):
    """Capture an actual Cargo runner invocation and preserve its child status."""
    context_path = Path(environment["ACCEPTANCE_CAPTURE_CONTEXT"])
    context = json.loads(context_path.read_text())
    evidence, original = Path(context["evidence_root"]), Path(argv[0])
    stem = original.name.rsplit("-", 1)[0]
    if context["mode"] == "docker" and stem not in HARNESSES:
        # Unselected Docker tests still execute once with identical arguments.
        os.execvpe(argv[0], argv, environment)
    # Rustdoc also uses Cargo's target runner for its temporary executables.
    # The separate route authenticates both parents before executing anything.
    if context["mode"] == "native" and Path(os.readlink(Path("/proc") / str(os.getppid()) / "exe")).name == "rustdoc":
        return run_doctest(argv, environment, context_path, context)
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
        parent = process_snapshot(os.getppid())
        tools = json.loads((evidence / "tools.json").read_text())
        example_nextest = parent["executable"] == tools.get("cargo-nextest", {}).get("resolved_path")
        if example_nextest:
            record["nextest_parent"] = parent
            record["nextest"] = nextest_invocation(parent, tools["cargo-nextest"], context, argv, environment)
        else:
            record["cargo_parent"] = cargo_parent()
        before = retain_executable(original, directory / "binary", context["elf_machine"])
        record.update(executable_sha256_before=before["sha256"], executable_before=before,
                      binary=asset(directory / "binary", evidence))
        record.update(capture_provenance(original, directory, context, environment,
                                         example_nextest=example_nextest))
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
        if example_nextest:
            require(process_snapshot(parent["pid"]) == parent, "Nextest parent changed during execution")
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
        doctest_paths = sorted((evidence / "doctests").glob("*/execution.json"))
        doctest_directories = list((evidence / "doctests").glob("*"))
        require(len(doctest_paths) == len(doctest_directories), "Incomplete doctest capture")
        doctests = [json.loads(path.read_text()) for path in doctest_paths]
        result["doctests"] = [asset(path, evidence) for path in doctest_paths]
        require(context["mode"] == "native" or not doctests, "Docker capture contains doctests")
        require(all(row["capture_passed"] for row in doctests), "One or more doctest captures failed")
        if context["mode"] == "docker":
            require({row["target_name"] for row in rows} == HARNESSES, "Missing selected Docker harness")
        else:
            require({row["leaf"] for row in rows} ==
                    {"test-workspace", "test-server-support", "test-content-guard"}, "Missing native test context")
            example_rows = [row for row in rows if row["leaf"] == "test-content-guard"]
            require(any(row["nextest"]["phase"] == "run" for row in example_rows),
                    "Nextest discovery alone does not prove a test execution")
            require(len({row["nextest"]["run_id"] for row in example_rows}) == 1,
                    "Standalone Nextest records belong to different runs")
        verification_environment = os.environ.copy()
        verification_environment.update(context["environment"])
        after = source_snapshot(Path(context["source_root"]), context["product_commit"], verification_environment)
        save(evidence / "source-after.json", after)
        require(after == json.loads((evidence / "source-before.json").read_text()), "Source changed during shipping task")
        tools = tool_context(Path(context["source_root"]), verification_environment, evidence, "after",
                             include_nextest=context["mode"] == "native")
        result["tool_probe"] = asset(evidence / "tool-observations/after/receipt.json", evidence)
        save(evidence / "tools-after.json", tools)
        require(tools == json.loads((evidence / "tools.json").read_text()), "Selected tools changed during task")
        log = Path(task_log).resolve()
        result["task_log"] = {"original_path": str(log), "sha256": digest(log), "size": log.stat().st_size}
        result["capture_passed"] = True
        result["passed"] = task_exit_status == 0 and all(row["exit_status"] == 0 for row in rows + doctests)
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    save(evidence / "capture-result.json", result)
    return result


def main():
    """Wrap the literal shipping task, or service Cargo's native runner hook."""
    if sys.argv[1:2] == ["runner"]:
        return run_invocation(sys.argv[2:], os.environ)
    if sys.argv[1:2] == ["tool-probe"]:
        return run_tool_probe(sys.argv[2], sys.argv[3:])
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
