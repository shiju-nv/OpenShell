# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run finite, source-bound Rust evidence in an already provisioned Nix shell."""

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from materialize import bundle_file, git, guard, load_manifest, require, sha256

SERVER_TESTS = [
    ("grpc::policy::tests::get_sandbox_policy_status_metadata_", 3, False),
    *[
        ("grpc::policy::tests::" + name, 1, True)
        for name in (
            "global_policy_reads_require_platform_admin",
            "global_policy_requests_reject_workspace_selectors",
            "non_member_gets_permission_denied_not_workspace_oracle",
            "invalid_legacy_latest_history_fails_closed_but_remains_listable",
        )
    ],
]
CLI_TESTS = [
    "run::tests::policy_revision_json_includes_revision_provenance",
    "run::tests::policy_list_json_reuses_metadata_contract",
]
VARIANTS = {
    "server_old_boundary": (
        "openshell-server",
        "crates/openshell-server/src/grpc/policy.rs",
        "grpc::policy::tests::get_sandbox_policy_status_metadata_preserves_invalid_revision_details",
        "invalid revisions must remain inspectable as metadata",
    ),
    "cli_old_boundary": (
        "openshell-cli",
        "crates/openshell-cli/src/run.rs",
        "policy_revision_metadata_invalid_revision_preserves_json_and_bounds_table",
        "invalid revision metadata should be readable",
    ),
    "combined_3444": ("openshell-cli", "crates/openshell-cli/src/run.rs", None, None),
}


def now():
    """Return an unambiguous UTC receipt timestamp."""
    return datetime.now(UTC).isoformat()


def prepare_target(target, worktree):
    """Refuse source-local or cached targets before any compiler can run."""
    require(not target.is_relative_to(worktree), "Target must be outside source")
    target.mkdir(parents=True, exist_ok=True)
    require(not any(target.iterdir()), "Target must initially be empty and isolated")


def verify_dependency_source(text, worktree, required_source, manifest_path):
    """Resolve Cargo's Make-style dependencies in the attested build directory."""
    dependencies = set()
    # Rustc may emit relative paths or escaped absolute paths. Continuations and
    # escaped spaces belong to Make syntax; substring matches cannot bind them.
    for line in text.replace("\\\n", " ").splitlines():
        if line.startswith("# env-dep:CARGO_MANIFEST_DIR="):
            observed = Path(line.partition("=")[2]).resolve()
            require(
                observed == manifest_path.parent.resolve(),
                "Manifest directory belongs to another checkout",
            )
        elif not line.startswith("#"):
            _, separator, values = line.partition(": ")
            if separator:
                for value in shlex.split(values):
                    path = Path(value)
                    dependencies.add(
                        (path if path.is_absolute() else worktree / path).resolve()
                    )
    require(
        (worktree / required_source).resolve() in dependencies,
        "Cargo depfile does not name the selected source checkout",
    )


class Runner:
    """Own one phase, its subprocesses, and append-only command evidence."""

    def __init__(self, args):
        self.worktree = args.worktree.resolve()
        self.bundle = args.bundle.resolve()
        self.output = args.output.resolve()
        require(
            not self.output.is_relative_to(self.worktree),
            "Evidence must be outside the product checkout",
        )
        self.output.mkdir(parents=True, exist_ok=True)
        require(
            not any(self.output.iterdir()), "Preserve attempts; output must be empty"
        )
        self.manifest = load_manifest(self.bundle)
        self.tree = self.manifest["candidate_tree"]
        self.env = dict(os.environ)
        require(
            not any(key.startswith("CARGO_PROFILE_") for key in self.env),
            "Repository profiles must not be overridden",
        )
        for key in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
            self.env.pop(key, None)
        self.env.update(
            CARGO_INCREMENTAL="0",
            CARGO_BUILD_JOBS="2",
            CARGO_TERM_COLOR="never",
            OPENSHELL_TELEMETRY_ENABLED="false",
        )
        require(
            "CARGO_TARGET_DIR" in self.env, "An isolated target directory is required"
        )
        self.target = Path(self.env["CARGO_TARGET_DIR"]).resolve()
        prepare_target(self.target, self.worktree)
        toolchain = self.capture(["rustc", "-vV"])
        require(
            re.search(r"^release: 1\.95\.0$", toolchain, re.M) is not None,
            "Expected repository Rust 1.95.0",
        )
        sysroot = self.capture(["rustc", "--print", "sysroot"]).strip()
        host = next(
            line[6:] for line in toolchain.splitlines() if line.startswith("host: ")
        )
        library_key = (
            "DYLD_FALLBACK_LIBRARY_PATH"
            if os.uname().sysname == "Darwin"
            else "LD_LIBRARY_PATH"
        )
        self.env[library_key] = os.pathsep.join(
            filter(
                None,
                [
                    str(self.target / "debug/deps"),
                    str(self.target / "debug"),
                    str(Path(sysroot) / "lib/rustlib" / host / "lib"),
                    self.env.get(library_key, ""),
                ],
            )
        )
        self.ledger = {
            "phase": args.phase,
            "base_commit": self.manifest["base_commit"],
            "candidate_tree": self.tree,
            "manifest_sha256": sha256(self.bundle / "manifest.json"),
            "runner_sha256": sha256(Path(__file__)),
            "materialize_sha256": sha256(Path(__file__).with_name("materialize.py")),
            "controller_sha": self.env.get("GITHUB_SHA"),
            "toolchain": toolchain,
            "cargo_version": self.capture(["cargo", "--version"]),
            "environment": {
                key: self.env.get(key)
                for key in (
                    "CARGO_TARGET_DIR",
                    "CARGO_BUILD_JOBS",
                    "CARGO_INCREMENTAL",
                    "CARGO_NET_OFFLINE",
                    "RUSTFLAGS",
                    "CARGO_ENCODED_RUSTFLAGS",
                    library_key,
                )
            },
            "started_utc": now(),
            "status": "prepared",
            "commands": [],
            "artifacts": [],
        }
        self.save()

    def capture(self, command):
        """Read tool identity without interpreting it as a test result."""
        return subprocess.check_output(
            command, cwd=self.worktree, env=self.env, text=True
        )

    def save(self):
        """Atomically replace the ledger so interruptions retain readable evidence."""
        temporary = self.output / "ledger.tmp"
        temporary.write_text(json.dumps(self.ledger, indent=2) + "\n")
        temporary.replace(self.output / "ledger.json")

    def command(self, label, command):
        """Guard source and stop only this owned process group on interruption."""
        guard(self.worktree, self.manifest, self.tree)
        log = self.output / (label + ".log")
        require(not log.exists(), f"Repeated command label: {label}")
        row = {
            "label": label,
            "command": command,
            "source_tree": self.tree,
            "started_utc": now(),
            "log": log.name,
        }
        self.ledger["commands"].append(row)
        self.ledger.update(status="running", active_command=label)
        self.save()
        print(f"Running {label}", flush=True)
        process = None
        try:
            with log.open("w") as stream:
                process = subprocess.Popen(
                    command,
                    cwd=self.worktree,
                    env=self.env,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                row["pid"] = process.pid
                self.save()
                while process.poll() is None:
                    require(
                        shutil.disk_usage(self.target).free >= 3 * 2**30,
                        "Owned command stopped to retain 3 GiB disk reserve",
                    )
                    time.sleep(2)
        finally:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            row.update(
                exit_code=process.returncode if process else None,
                finished_utc=now(),
                log_sha256=sha256(log),
            )
            self.save()
        guard(self.worktree, self.manifest, self.tree)
        return row, log

    def attest(self, message, label, required_source, production=False):
        """Retain Cargo provenance and hash the exact executable or production rlib."""
        if production:
            artifact = next(
                Path(name) for name in message["filenames"] if name.endswith(".rlib")
            )
            stem = artifact.stem.removeprefix("lib")
            depfile = artifact.with_name(stem + ".d")
        else:
            artifact = Path(message["executable"])
            stem = artifact.name
            depfile = artifact.with_suffix(".d")
        require(
            artifact.resolve().is_relative_to(self.target),
            "Artifact escapes isolated target",
        )
        dependency_text = depfile.read_text()
        verify_dependency_source(
            dependency_text,
            self.worktree,
            required_source,
            Path(message["manifest_path"]).resolve(),
        )
        package = tomllib.loads(Path(message["manifest_path"]).read_text())["package"][
            "name"
        ]
        fingerprint = (
            artifact.parent.parent
            / ".fingerprint"
            / (package + "-" + stem.rsplit("-", 1)[1])
        )
        require(fingerprint.is_dir(), "Missing compiler fingerprint")
        destination = self.output / label
        destination.mkdir()
        shutil.copy2(depfile, destination / depfile.name)
        shutil.copytree(fingerprint, destination / "fingerprint")
        digest = sha256(artifact)
        row = {
            "source_tree": self.tree,
            "cargo_message": message,
            "artifact_sha256": digest,
            "artifact_path": str(artifact),
            "production_library": production,
            "depfile_sha256": sha256(depfile),
            "evidence_directory": destination.name,
            "fingerprints": {
                path.name: sha256(path)
                for path in fingerprint.iterdir()
                if path.is_file()
            },
        }
        self.ledger["artifacts"].append(row)
        self.save()
        return artifact, digest

    def build(self, label, package, include_lib=True):
        """Compile once, require the precise Cargo targets, and attest each artifact."""
        selectors = (
            ["--lib", "--features", "test-support"]
            if package == "openshell-server"
            else [
                "--test",
                "sandbox_name_fallback_integration",
                *(["--lib"] if include_lib else []),
            ]
        )
        row, log = self.command(
            label,
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                package,
                *selectors,
                "--no-run",
                "--message-format=json",
            ],
        )
        require(row["exit_code"] == 0, "Compilation failure is not behavioral proof")
        messages = []
        for line in log.read_text().splitlines():
            if not line.startswith("{"):
                continue
            message = json.loads(line)
            if (
                message.get("reason") == "compiler-artifact"
                and Path(message["manifest_path"]).resolve()
                == self.worktree / "crates" / package / "Cargo.toml"
            ):
                messages.append(message)
        tests = [
            message
            for message in messages
            if message.get("executable") and message["profile"]["test"]
        ]
        expected = (
            {"openshell_server"}
            if package == "openshell-server"
            else {"sandbox_name_fallback_integration"}
        )
        if package == "openshell-cli" and include_lib:
            expected.add("openshell_cli")
        require(
            len(tests) == len(expected)
            and {m["target"]["name"] for m in tests} == expected,
            "Cargo returned unexpected or missing test executables",
        )
        if package == "openshell-cli":
            libraries = [
                m
                for m in messages
                if m["target"]["name"] == "openshell_cli"
                and not m["profile"]["test"]
                and any(p.endswith(".rlib") for p in m["filenames"])
            ]
            require(
                len(libraries) == 1,
                "Expected the CLI production library linked by integration tests",
            )
            self.attest(
                libraries[0],
                label + "-production",
                "crates/openshell-cli/src/run.rs",
                True,
            )
        binaries = {}
        for message in tests:
            name = message["target"]["name"]
            source = (
                "crates/openshell-server/src/grpc/policy.rs"
                if package == "openshell-server"
                else "crates/openshell-cli/tests/sandbox_name_fallback_integration.rs"
                if name == "sandbox_name_fallback_integration"
                else "crates/openshell-cli/src/run.rs"
            )
            binaries[name] = self.attest(message, label + "-" + name, source)
        return binaries

    def test(self, label, binary, selector, count=1, exact=True, failure_marker=None):
        """A negative passes only after one named test runs and fails as expected."""
        executable, digest = binary
        require(
            sha256(executable) == digest, "Test executable changed before execution"
        )
        row, log = self.command(
            label,
            [str(executable), selector, *(["--exact"] if exact else []), "--nocapture"],
        )
        output = log.read_text()
        summaries = re.findall(
            r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;", output
        )
        if failure_marker:
            passed = (
                row["exit_code"] == 101
                and summaries == [("FAILED", "0", "1")]
                and failure_marker in output
            )
        else:
            passed = row["exit_code"] == 0 and summaries == [("ok", str(count), "0")]
        row.update(
            passed=passed,
            expected_negative=bool(failure_marker),
            expected_failure_marker=failure_marker,
            observed_summaries=summaries,
            executable_sha256=digest,
        )
        self.save()
        require(
            sha256(executable) == digest, "Test executable changed during execution"
        )
        require(passed, f"Expected behavioral result missing: {label}")

    def focused(self):
        """Exercise positives first, then each isolated regression/overlap boundary."""
        server = self.build("candidate-server", "openshell-server")["openshell_server"]
        for index, (test, count, exact) in enumerate(SERVER_TESTS):
            self.test(f"candidate-server-{index}", server, test, count, exact)
        self.checks(
            [
                ("format-workspace", ["cargo", "fmt", "--all", "--", "--check"]),
                (
                    "clippy-server",
                    [
                        "cargo",
                        "clippy",
                        "--locked",
                        "-p",
                        "openshell-server",
                        "--all-targets",
                        "--",
                        "-D",
                        "warnings",
                    ],
                ),
                (
                    "nextest-server",
                    [
                        "cargo",
                        "nextest",
                        "run",
                        "--locked",
                        "--profile",
                        "ci",
                        "-p",
                        "openshell-server",
                        "--features",
                        "test-support",
                    ],
                ),
            ]
        )
        cli = self.build("candidate-cli", "openshell-cli")
        for index, test in enumerate(CLI_TESTS):
            self.test(f"candidate-cli-json-{index}", cli["openshell_cli"], test)
        self.test(
            "candidate-cli-rpc",
            cli["sandbox_name_fallback_integration"],
            "policy_",
            7,
            False,
        )
        candidate_tree = self.manifest["candidate_tree"]
        for name, (package, path, test, marker) in VARIANTS.items():
            variant = self.manifest["variants"][name]
            patch = bundle_file(self.bundle, variant["patch"])
            require(
                sha256(patch) == variant["sha256"], f"Variant digest mismatch: {name}"
            )
            guard(self.worktree, self.manifest, candidate_tree)
            try:
                subprocess.run(
                    ["git", "apply", "--index", str(patch)],
                    cwd=self.worktree,
                    check=True,
                )
                self.tree = variant["expected_tree"]
                guard(self.worktree, self.manifest, self.tree)
                require(
                    git(self.worktree, "diff", "--name-only", candidate_tree, self.tree)
                    == path,
                    "Variant changed files outside its reviewed boundary",
                )
                binaries = self.build(
                    name, package, include_lib=name == "combined_3444"
                )
                if marker:
                    target = (
                        "openshell_server"
                        if package == "openshell-server"
                        else "sandbox_name_fallback_integration"
                    )
                    self.test(
                        name + "-negative",
                        binaries[target],
                        test,
                        failure_marker=marker,
                    )
                else:
                    self.test(
                        name + "-rpc",
                        binaries["sandbox_name_fallback_integration"],
                        "policy_",
                        7,
                        False,
                    )
                    self.test(
                        name + "-unicode",
                        binaries["openshell_cli"],
                        "run::tests::policy_revision_table_handles_unicode_load_errors",
                    )
            finally:
                # This checkout belongs to this phase; restore every changed path even
                # if an input patch fails its scope/tree check after application.
                changed = git(
                    self.worktree, "diff", "--name-only", candidate_tree
                ).splitlines()
                if changed:
                    subprocess.run(
                        [
                            "git",
                            "restore",
                            "--source",
                            candidate_tree,
                            "--staged",
                            "--worktree",
                            "--",
                            *changed,
                        ],
                        cwd=self.worktree,
                        check=True,
                    )
                self.tree = candidate_tree
                guard(self.worktree, self.manifest, candidate_tree)

    def broad(self):
        """Run the explicit Linux Rust gate scope, retaining each independent failure."""
        standalone = [
            "e2e/rust/Cargo.toml",
            "examples/governance-interceptor/Cargo.toml",
            "examples/supervisor-middleware-content-guard/Cargo.toml",
        ]
        commands = [
            ("lockfiles", ["bash", "tasks/scripts/check-cargo-lockfiles.sh"]),
            ("format-workspace", ["cargo", "fmt", "--all", "--", "--check"]),
        ]
        commands += [
            (
                f"format-{i}",
                ["cargo", "fmt", "--manifest-path", path, "--all", "--", "--check"],
            )
            for i, path in enumerate(standalone)
        ]
        commands += [
            ("check-workspace", ["cargo", "check", "--locked", "--workspace"]),
            (
                "check-perf",
                [
                    "cargo",
                    "check",
                    "--locked",
                    "-p",
                    "openshell-sandbox",
                    "--all-targets",
                    "--features",
                    "perf-harness",
                ],
            ),
            (
                "clippy-workspace",
                [
                    "cargo",
                    "clippy",
                    "--locked",
                    "--workspace",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
            (
                "clippy-perf",
                [
                    "cargo",
                    "clippy",
                    "--locked",
                    "-p",
                    "openshell-sandbox",
                    "--all-targets",
                    "--features",
                    "perf-harness",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
        ]
        commands += [
            (
                f"clippy-{i}",
                [
                    "cargo",
                    "clippy",
                    "--locked",
                    "--manifest-path",
                    path,
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            )
            for i, path in enumerate(standalone)
        ]
        commands += [
            (
                "nextest-workspace",
                [
                    "cargo",
                    "nextest",
                    "run",
                    "--locked",
                    "--profile",
                    "ci",
                    "--workspace",
                    "--features",
                    "openshell-server/test-support",
                ],
            ),
            (
                "nextest-content-guard",
                [
                    "cargo",
                    "nextest",
                    "run",
                    "--locked",
                    "--config-file",
                    ".config/nextest.toml",
                    "--profile",
                    "ci",
                    "--manifest-path",
                    standalone[-1],
                ],
            ),
            (
                "doctest-workspace",
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--workspace",
                    "--doc",
                    "--features",
                    "openshell-server/test-support",
                ],
            ),
        ]
        self.checks(commands)

    def checks(self, commands):
        """Retain independent failures and require actual Nextest execution."""
        failed = []
        for label, command in commands:
            row, log = self.command(label, command)
            passed = row["exit_code"] == 0
            if label.startswith("nextest-"):
                summaries = re.findall(
                    r"Summary\s+\[[^\]]+\]\s+(\d+) tests? run", log.read_text()
                )
                row["observed_test_totals"] = summaries
                passed = passed and len(summaries) == 1 and int(summaries[0]) > 0
            row["passed"] = passed
            self.save()
            if not passed:
                failed.append(label)
        require(not failed, f"Rust gates failed or lacked execution evidence: {failed}")


def main():
    """Keep failed and interrupted attempts distinct from completed qualification."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["focused", "broad"], required=True)
    for option in ("worktree", "bundle", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()

    def interrupted(signum, _frame):
        raise InterruptedError(f"Received signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    runner = Runner(args)
    try:
        guard(runner.worktree, runner.manifest, runner.tree)
        getattr(runner, args.phase)()
        runner.ledger.update(status="passed", active_command=None)
    except BaseException as error:
        runner.ledger.update(status="failed", error=repr(error))
        raise
    finally:
        try:
            guard(runner.worktree, runner.manifest, runner.manifest["candidate_tree"])
            runner.ledger["restored_candidate"] = True
        except BaseException as error:
            runner.ledger.update(
                status="failed", restored_candidate=False, restoration_error=repr(error)
            )
            raise
        finally:
            runner.ledger["finished_utc"] = now()
            runner.save()


if __name__ == "__main__":
    main()
