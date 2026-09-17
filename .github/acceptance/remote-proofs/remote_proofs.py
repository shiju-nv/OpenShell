#!/usr/bin/env python3
"""Build and run the finite isolated-process proof suites on an Ubuntu host."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys


HERE = Path(__file__).resolve().parent
TRIPLE = "x86_64-unknown-linux-gnu"
SUITES = {
    "boundary": ("verify-boundary.fish", 14),
    "coordinator": ("verify-supervisor-runtime.fish", 2),
    "protocol": ("verify-protocol-runtime.fish", 3),
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def checked_helpers(control_root):
    """Import only the reviewed build helper and exact observer/fixture bytes."""
    pins = json.loads((HERE / "control-pins.json").read_text())
    for name, expected in pins["fixtures"].items():
        require(digest(HERE / "fixtures" / name) == expected, f"Fixture changed: {name}")
    helper = control_root / pins["build_helper"]["relative_path"]
    require(digest(helper) == pins["build_helper"]["sha256"], "Build helper changed")
    spec = importlib.util.spec_from_file_location("proof_build_contract", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, pins


def select_library_artifact(metadata, output, package, source, target):
    """A same-named binary target cannot stand in for the requested library test."""
    packages = [row for row in metadata["packages"] if row["name"] == package]
    require(len(packages) == 1, "Cargo package selection is ambiguous")
    selected = packages[0]
    libraries = [row for row in selected["targets"] if row["kind"] == ["lib"]]
    require(len(libraries) == 1, "Expected one library target")
    library = libraries[0]
    require(Path(selected["manifest_path"]).resolve() == source / "crates" / package / "Cargo.toml", "Package comes from another checkout")
    require(Path(library["src_path"]).resolve() == source / "crates" / package / "src/lib.rs", "Library source differs")
    rows = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("reason") != "compiler-artifact" or row.get("package_id") != selected["id"]:
            continue
        if row.get("target", {}).get("kind") != ["lib"] or not row.get("profile", {}).get("test"):
            continue
        require(row["target"]["name"] == library["name"] and row["target"]["src_path"] == library["src_path"], "Compiled library target differs")
        require(row.get("manifest_path") == selected["manifest_path"], "Compiled manifest differs")
        if row.get("executable"):
            executable = Path(row["executable"]).resolve()
            require(executable.is_relative_to(target / TRIPLE / "release/deps"), "Test executable is outside the fresh target")
            rows.append(row)
    require(len(rows) == 1, "Expected exactly one library test executable")
    return rows[0]


def prepare_fixtures(source, output, pins):
    """Only relocate the expected source; preserve every registered protocol row."""
    shutil.copytree(HERE / "fixtures", output)
    template = json.loads((output / "expected-protocol-observations.template.json").read_text())
    protocol_source = source / template["source"]
    require(digest(protocol_source) == template["source_sha256"], "Protocol test source changed")
    require(len(template["expected_rows"]) == pins["expected_protocol_rows"] == 60, "Protocol row count differs")
    template["source"] = str(protocol_source)
    save(output / "expected-protocol-observations.json", template)
    policy_names = ("cases.json", "policy-a.yaml", "policy-b.yaml", "policy-invalid-binding.yaml")
    (output / "SHA256SUMS").write_text("".join(f"{digest(output / name)}  {name}\n" for name in policy_names))
    # Wrappers recheck the relocated complete fixture set before every suite.
    (output / "RUNTIME_SHA256SUMS").write_text("".join(
        f"{digest(path)}  {path.name}\n" for path in sorted(output.iterdir()) if path.is_file()))
    return {path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file()}


def registered_tests(wrapper):
    return re.findall(r"(?m)^\s+((?:boundary_[a-z]+|identity|configuration)::[\w:]+)\s*\\?\s*$", wrapper)


def completed_suite(directory, tests):
    """Keep each exact invocation and reject a successful zero-test harness."""
    expected = {name.replace("::", "-") + ".run.json" for name in tests}
    require({path.name for path in directory.glob("*.run.json")} == expected, "Missing or extra proof invocation")
    result = []
    for name in tests:
        path = directory / (name.replace("::", "-") + ".run.json")
        row = json.loads(path.read_text())
        require(row["exit_status"] == 0 and name in row["command"], f"Exact proof did not pass: {name}")
        for member in ("log", "command_artifact", "mounted_test_executable"):
            require(digest(row[member]["path"]) == row[member]["sha256"], f"Proof artifact changed: {member}")
        log = Path(row["log"]["path"]).read_text()
        require("test result: ok. 1 passed; 0 failed; 0 ignored;" in log, f"Proof was omitted: {name}")
        result.append({"test": name, "path": str(path), "sha256": digest(path)})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--products", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args()
    helper, pins = checked_helpers(HERE.parent)
    helper.check_runner()
    require(not Path("/.dockerenv").exists(), "Use the hosted VM directly")
    commit = helper.selected_commit()
    root, evidence, target = Path.cwd().resolve(), args.evidence.resolve(), args.target_dir.resolve()
    require(not evidence.exists() and not target.exists(), "Use fresh evidence and proof target directories")
    require(not target.is_relative_to(evidence) and not evidence.is_relative_to(target), "Keep compiler cache outside evidence")
    evidence.mkdir(parents=True)
    logs, exports = evidence / "logs", evidence / "executables"
    logs.mkdir()
    exports.mkdir()
    target.mkdir(parents=True)
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("OPENSHELL_ACTIVATION_") or key == "PYTHONOPTIMIZE":
            env.pop(key)
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET"):
        env.pop(key, None)
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
               CARGO_PROFILE_RELEASE_DEBUG="0", RUSTC_WRAPPER="", CARGO_TERM_COLOR="never",
               OPENSHELL_PROOF_UV_CACHE=str(evidence / "uv-cache"), PYTHONDONTWRITEBYTECODE="1")
    result = {"passed": False, "full_acceptance_claimed": False, "product_commit": commit,
              "candidate_tree": helper.TREE, "groups": {}, "builds": {}, "control_pins_sha256": digest(HERE / "control-pins.json"),
              "command_environment": {key: value for key, value in env.items() if key in
                                      ("CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CARGO_PROFILE_RELEASE_DEBUG", "RUSTC_WRAPPER", "PATH", "IN_NIX_SHELL")
                                      or key.startswith("CARGO_TARGET_") and key.endswith("_LINKER")}}
    before_containers = None
    try:
        result["source_before"] = helper.source_state(root, logs, "before", commit)
        products = json.loads(args.products.read_text())
        require(products["schema_version"] == 1 and products["product_commit"] == commit and products["candidate_tree"] == helper.TREE, "Product source differs")
        assembly = products["assembly_evidence"]
        assembly_path = (args.products.resolve().parent / assembly["path"]).resolve()
        require(digest(assembly_path) == assembly["sha256"], "Image assembly receipt changed")
        assembled = json.loads(assembly_path.read_text())
        require(assembled["passed"] and assembled["product_commit"] == commit and assembled["candidate_tree"] == helper.TREE, "Image assembly did not pass")
        require(products["images"] == assembled["images"] and products["files"] == assembled["files"], "Consumer products differ from image assembly")
        result["products"] = {"path": str(args.products.resolve()), "sha256": digest(args.products), "assembly": {"path": str(assembly_path), "sha256": digest(assembly_path)}}
        sandbox = (args.products.resolve().parent / products["files"]["sandbox"]["path"]).resolve()
        require(digest(sandbox) == products["files"]["sandbox"]["sha256"], "Static boundary executable changed")
        helper.verify_binary(root, logs, "sandbox", sandbox)
        image = products["images"]["supervisor"]
        inspected = json.loads(helper.run(root, logs, "image", ["docker", "image", "inspect", image["reference"]]))
        require(len(inspected) == 1 and inspected[0]["Id"] == image["id"] and inspected[0]["Architecture"] == "amd64" and inspected[0]["Os"] == "linux", "Selected control image differs")
        before_containers = set(helper.run(root, logs, "containers-before", ["docker", "ps", "-aq"]).split())
        for name, argv in (("rustc", ["rustc", "--version", "--verbose"]), ("cargo", ["cargo", "--version"]), ("nix", ["nix", "--version"])):
            helper.run(root, logs, "tool-" + name, argv, env)
        metadata = json.loads(helper.run(root, logs, "cargo-metadata", ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"], env))
        for role in ("sandbox", "supervisor"):
            package = "openshell-" + role
            argv = ["cargo", "test", "--locked", "--release", "--target", TRIPLE, "--target-dir", str(target),
                    "--package", package, "--lib", "--no-run", "--message-format=json-render-diagnostics"]
            output = helper.run(root, logs, "build-" + role, argv, env)
            artifact = select_library_artifact(metadata, output, package, root, target)
            built, exported = Path(artifact["executable"]), exports / (role + "-tests")
            helper.verify_binary(root, logs, role + "-tests", built)
            shutil.copy2(built, exported)
            exported.chmod(0o755)
            require(digest(built) == digest(exported), "Proof executable export changed")
            result["builds"][role] = {"compiler_artifact": artifact, "executable": str(exported), "sha256": digest(exported), "features": artifact["features"]}
        fixtures = evidence / "fixtures"
        result["fixtures"] = prepare_fixtures(root, fixtures, pins)
        env.update(OPENSHELL_ACTIVATION_CONTROL_IMAGE=image["id"], OPENSHELL_ACTIVATION_SANDBOX_BINARY=str(sandbox),
                   OPENSHELL_ACTIVATION_LINUX_TEST_BINARY=result["builds"]["sandbox"]["executable"],
                   OPENSHELL_ACTIVATION_SUPERVISOR_LINUX_TEST_BINARY=result["builds"]["supervisor"]["executable"])
        result["runtime_environment"] = {key: value for key, value in env.items() if key.startswith("OPENSHELL_ACTIVATION_")}
        for suite, (wrapper, count) in SUITES.items():
            tests = registered_tests((fixtures / wrapper).read_text())
            require(len(tests) == count and len(set(tests)) == count, "Registered test roster differs")
            helper.run(root, logs, "run-" + suite, ["fish", "--no-config", str(fixtures / wrapper), "--evidence-dir", str(evidence / suite)], env)
            rows = completed_suite(evidence / suite, tests)
            if suite == "boundary":
                result["groups"]["boundary"] = rows[:12]
                result["groups"]["transport"] = rows[12:]
            else:
                result["groups"][suite] = rows
        observations = json.loads((evidence / "protocol/protocol-observations.json").read_text())
        require(len(observations) == 60, "Protocol observer did not produce all60 registered rows")
        result.update(protocol_observation_count=len(observations), passed=True)
    except Exception as error:
        result["error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    finally:
        try:
            result["source_after"] = helper.source_state(root, logs, "after", commit)
            if before_containers is not None:
                leaked = set(helper.run(root, logs, "containers-after", ["docker", "ps", "-aq"]).split()) - before_containers
                result["leaked_containers"] = sorted(leaked)
                if leaked:
                    result["passed"] = False
                    for index, container in enumerate(sorted(leaked)):
                        helper.run(root, logs, f"cleanup-{index}", ["docker", "rm", "--force", container])
        except Exception as error:
            result.update(passed=False, final_check_error=str(error))
        save(evidence / "result.json", result)
        save(evidence / "assets.json", {str(path.relative_to(evidence)): {"sha256": digest(path), "bytes": path.stat().st_size}
                                       for path in sorted(evidence.rglob("*")) if path.is_file() and path.name != "assets.json"
                                       and not path.is_relative_to(evidence / "uv-cache")})
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
