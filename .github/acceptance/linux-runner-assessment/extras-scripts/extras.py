"""Run one exact stock Branch Checks scope inside the selected candidate Nix shell."""

import argparse
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "build-scripts"))
from build_products import TREE, check_runner, digest, require, run, save, selected_commit, source_state

WORKFLOW = ".github/workflows/branch-checks.yml"
SCOPES = {
    "nextest": ("Test",),
    "telemetry": ("Verify telemetry can be compiled out",
                  "Verify the defaults-without-telemetry feature alias tracks the default feature set"),
    "drivers": ("Verify selective gateway compute-driver builds",),
    "roots": ("Verify system CA roots build mode compiles and excludes bundled Mozilla roots",),
}


def shipping_steps(text):
    """Read literal run blocks only from the pinned workflow's Rust job."""
    section = re.search(r"(?ms)^  rust:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text)
    require(section is not None, "Shipping Rust job is absent")
    names = {name for group in SCOPES.values() for name in group}
    blocks = re.split(r"(?m)^      - ", section.group(1))
    selected = {}
    for block in blocks:
        first, _, rest = block.partition("\n")
        if not first.startswith("name: ") or first[6:] not in names:
            continue
        name = first[6:]
        require(name not in selected, "Duplicate shipping step")
        lines = rest.splitlines()
        index = next((i for i, line in enumerate(lines) if line.startswith("        run: ")), None)
        require(index is not None, f"Shipping command absent: {name}")
        value = lines[index][13:]
        if value == "|":
            body = []
            for line in lines[index + 1:]:
                if line and not line.startswith("          "):
                    break
                body.append(line[10:] if line else "")
            script = "\n".join(body).rstrip("\n") + "\n"
        else:
            require(value and not value.startswith((">", "${{")), "Unexpected shipping command syntax")
            script = value + "\n"
        environment = {"OPENSHELL_TELEMETRY_ENABLED": "false"} if name == "Test" else {}
        if name == "Test":
            require('          OPENSHELL_TELEMETRY_ENABLED: "false"' in lines[:index], "Nextest environment changed")
        selected[name] = {"script": script, "environment": environment}
    require(set(selected) == names, "Shipping scope inventory changed")
    return selected


def pinned_commands(root):
    """Require candidate-owned inputs and the prepared literal command map."""
    binding = json.loads(Path(__file__).with_name("commands.json").read_text())
    for relative, expected in binding["source_inputs"].items():
        require(digest(root / relative) == expected, f"Shipping input changed: {relative}")
    selected = shipping_steps((root / WORKFLOW).read_text())
    require(selected == binding["steps"], "Shipping command bytes differ from prepared scopes")
    return selected, binding


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=SCOPES, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args()
    root, evidence, target = Path.cwd().resolve(), args.evidence.resolve(), args.target_dir.resolve()
    check_runner()
    commit = selected_commit()
    require(not evidence.exists() and not target.exists(), "Use fresh evidence and isolated target directories")
    require(not target.is_relative_to(evidence) and not evidence.is_relative_to(target), "Separate artifacts and compiler target")
    checkout_target = root / "target"
    require(not checkout_target.exists() and not checkout_target.is_symlink(), "Refuse to replace an existing checkout target")
    steps, binding = pinned_commands(root)
    evidence.mkdir(parents=True)
    logs, scripts = evidence / "logs", evidence / "scripts"
    logs.mkdir()
    scripts.mkdir()
    result = {"schema_version": 1, "scope": args.scope, "passed": False, "product_commit": commit,
              "candidate_tree": TREE, "source_inputs": binding["source_inputs"], "commands": [],
              "producer_sha256": digest(Path(__file__)),
              "helper_sha256": digest(Path(__file__).parent.parent / "build-scripts/build_products.py"),
              "target": str(target), "disk_guard_owner": "workflow run_job.py", "owned_target_link_removed": False}
    env = dict(os.environ)
    # Preserve the Nix target linkers, while removing inherited command/profile
    # selectors that would change the shipping scope's Cargo or Nextest meaning.
    for name in list(env):
        if name.startswith(("CARGO_PROFILE_", "NEXTEST_")) or name in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_ENCODED_RUSTDOCFLAGS", "RUSTDOCFLAGS", "OPENSHELL_TELEMETRY_ENABLED", "BASH_ENV"):
            env.pop(name, None)
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never")
    result["environment"] = {key: value for key, value in env.items() if key in
        ("PATH", "IN_NIX_SHELL", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL")
        or key.startswith("CARGO_TARGET_") and key.endswith("_LINKER")}
    owned_link = False
    try:
        result["source_before"] = source_state(root, logs, "before", commit)
        target.mkdir(parents=True)
        # Telemetry's unchanged shipping commands inspect target/debug. An
        # owned ignored symlink makes those literals refer to this job's target.
        run(root, logs, "ignored-target", ["git", "check-ignore", "--", "target/"])
        checkout_target.symlink_to(target, target_is_directory=True)
        owned_link = True
        for name, argv in (("rustc", ["rustc", "--version", "--verbose"]), ("cargo", ["cargo", "--version"]),
                           ("nix", ["nix", "--version"]), ("bash", ["bash", "--version"])):
            run(root, logs, "tool-" + name, argv, env)
        if args.scope == "nextest":
            run(root, logs, "tool-nextest", ["cargo", "nextest", "--version"], env)
        for index, name in enumerate(SCOPES[args.scope], 1):
            spec = steps[name]
            script = scripts / f"{args.scope}-{index}.sh"
            script.write_text(spec["script"])
            row = {"shipping_step": name, "script": str(script.relative_to(evidence)),
                   "sha256": digest(script), "environment": spec["environment"], "passed": False}
            result["commands"].append(row)
            save(evidence / "result.json", result)
            run(root, logs, f"scope-{index}", ["bash", "-euo", "pipefail", str(script)], {**env, **spec["environment"]})
            row["passed"] = True
        result["passed"] = True
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        try:
            if owned_link:
                require(checkout_target.is_symlink() and checkout_target.resolve() == target, "Owned target link changed")
                checkout_target.unlink()
                result["owned_target_link_removed"] = True
            result["source_after"] = source_state(root, logs, "after", commit)
        except BaseException as error:
            result.update(passed=False, final_verification_error=str(error))
        result["assets"] = {str(path.relative_to(evidence)): digest(path)
                            for directory in (logs, scripts) for path in sorted(directory.iterdir()) if path.is_file()}
        save(evidence / "result.json", result)
    require(result["passed"], "Stock compatibility scope failed")


if __name__ == "__main__":
    main()
