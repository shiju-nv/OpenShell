"""Build one frozen OpenShell product role inside the candidate Nix shell."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

TREE = "945721e3aad8d0b4fab3b93dcf999cebd4fa2bba"
ROLES = {
    "host": {"cli": ("openshell-cli", "openshell"),
             "gateway": ("openshell-gateway", "openshell-gateway"),
             "conformance": ("openshell-conformance-cli", "openshell-conformance")},
    "supervisor": {"supervisor": ("openshell-supervisor", "openshell-supervisor")},
    "sandbox": {"sandbox": ("openshell-sandbox", "openshell-sandbox")},
}


def require(condition, message):
    """Fail closed even when Python assertions are disabled."""
    if not condition:
        raise RuntimeError(message)


def digest(path):
    """Hash executable and receipt bytes without loading whole binaries."""
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    """Write a readable receipt within a newly allocated evidence directory."""
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run(root, logs, name, argv, env=None):
    """Retain argv, raw combined output and status before propagating failure."""
    log, receipt = logs / f"{name}.log", logs / f"{name}.json"
    require(not log.exists() and not receipt.exists(), f"Receipt already exists: {name}")
    row = {"argv": argv, "cwd": str(root), "started_at": time.time(), "exit_status": None}
    save(receipt, row)
    try:
        with log.open("xb") as output:
            process = subprocess.Popen(argv, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for chunk in iter(lambda: process.stdout.read1(65536), b""):
                output.write(chunk)
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            row["exit_status"] = process.wait()
    finally:
        row.update(finished_at=time.time(), log=log.name,
                   log_sha256=digest(log) if log.exists() else None)
        save(receipt, row)
    require(row["exit_status"] == 0, f"Command failed: {name} ({row['exit_status']})")
    return log.read_text(errors="replace")


def selected_commit():
    """Require an explicit commit; a branch name or content hash is insufficient."""
    commit = os.environ.get("ACCEPTANCE_PRODUCT_COMMIT", "")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "ACCEPTANCE_PRODUCT_COMMIT must be a full commit SHA")
    return commit


def check_runner():
    """Keep this entrypoint on the reviewed native GitHub Ubuntu/Nix topology."""
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Use native Linux x86_64")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release.get("ID", "").strip('"') == "ubuntu" and release.get("VERSION_ID", "").strip('"') == "24.04", "Use Ubuntu 24.04")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("IN_NIX_SHELL"), "Run in GitHub Actions through candidate nix develop")


def source_state(root, logs, phase, commit):
    """Check both the selected commit and its complete tracked tree identity."""
    head = run(root, logs, f"{phase}-head", ["git", "rev-parse", "HEAD"]).strip()
    tree = run(root, logs, f"{phase}-tree", ["git", "rev-parse", "HEAD^{tree}"]).strip()
    status = run(root, logs, f"{phase}-status", ["git", "status", "--porcelain=v1", "--untracked-files=no"])
    require(head == commit and tree == TREE and not status.strip(), "Candidate commit/tree differs or tracked checkout is dirty")
    return {"product_commit": head, "candidate_tree": tree, "tracked_clean": True}


def elf_header(path):
    """Reject missing, non-executable, wrong-architecture or non-ELF artifacts."""
    require(path.is_file() and not path.is_symlink() and os.access(path, os.X_OK), f"Expected regular executable: {path}")
    with path.open("rb") as stream:
        header = stream.read(64)
    require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00"
            and int.from_bytes(header[16:18], "little") in (2, 3), f"Expected x86_64 ELF executable: {path}")


def verify_binary(root, logs, role, path):
    """Use repository linkage gates and require the portable GNU interpreter."""
    elf_header(path)
    headers = run(root, logs, f"elf-{role}", ["readelf", "--wide", "--file-header", "--program-headers", str(path)])
    require(re.search(r"^\s*LOAD\s", headers, re.MULTILINE), f"ELF has no load segment: {role}")
    interpreters = re.findall(r"Requesting program interpreter:\s*([^\]]+)\]", headers)
    if role == "sandbox":
        require(not interpreters, "Sandbox must have no ELF interpreter")
        run(root, logs, "static-sandbox", ["bash", "tasks/scripts/verify-static-binary.sh", str(path)])
    else:
        require(interpreters == ["/lib64/ld-linux-x86-64.so.2"], f"Wrong GNU interpreter: {role}")
        versions = run(root, logs, f"versions-{role}", ["readelf", "--version-info", str(path)])
        glibc = re.findall(r"GLIBC_(\d+)\.(\d+)", versions)
        require(glibc and all(tuple(map(int, value)) <= (2, 28) for value in glibc), f"GNU symbol baseline exceeds 2.28: {role}")
        run(root, logs, f"glibc-{role}", ["bash", "tasks/scripts/verify-glibc-symbols.sh", "2.28", str(path)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=ROLES)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args()
    root, output, target = Path.cwd().resolve(), args.output.resolve(), args.target_dir.resolve()
    check_runner()
    commit = selected_commit()
    require(not output.exists() and not target.exists(), "Use new role output and target directories")
    require(output != target and not target.is_relative_to(output) and not output.is_relative_to(target), "Keep target outside uploaded role artifacts")
    output.mkdir(parents=True)
    logs, products = output / "logs", output / "products"
    logs.mkdir()
    products.mkdir()
    target.mkdir(parents=True)
    triple = "x86_64-unknown-linux-musl" if args.role == "sandbox" else "x86_64-unknown-linux-gnu"
    env = dict(os.environ)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET"):
        env.pop(name, None)
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
               CARGO_PROFILE_RELEASE_DEBUG="0", RUSTC_WRAPPER="", CARGO_TERM_COLOR="never")
    manifest = {"schema_version": 1, "passed": False, "role": args.role, "product_commit": commit,
                "candidate_tree": TREE, "target": triple, "files": {}, "build_refs": [],
                "environment": {key: value for key, value in env.items() if key in
                                ("PATH", "IN_NIX_SHELL", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
                                 "CARGO_PROFILE_RELEASE_DEBUG", "RUSTC_WRAPPER", "OPENSHELL_IMAGE_TAG")
                                or key.startswith("CARGO_TARGET_") and key.endswith("_LINKER")},
                "producer_sha256": digest(Path(__file__))}
    try:
        manifest["source_before"] = source_state(root, logs, "before", commit)
        for name, argv in (("rustc", ["rustc", "--version", "--verbose"]), ("cargo", ["cargo", "--version"]),
                           ("nix", ["nix", "--version"]), ("readelf", ["readelf", "--version"])):
            run(root, logs, f"tool-{name}", argv, env)
        for role, (package, binary) in ROLES[args.role].items():
            argv = ["cargo", "build", "--locked", "--release", "--target", triple,
                    "--target-dir", str(target), "--package", package, "--bin", binary]
            run(root, logs, f"cargo-{role}", argv, env)
            built, exported = target / triple / "release" / binary, products / binary
            verify_binary(root, logs, role, built)
            shutil.copy2(built, exported)
            exported.chmod(0o755)
            require(digest(built) == digest(exported), f"Export changed executable: {role}")
            manifest["files"][role] = {"role": role, "path": str(exported.relative_to(output)),
                                       "sha256": digest(exported), "built_path": str(built),
                                       "build_ref": f"logs/cargo-{role}.json"}
        manifest["passed"] = True
    except BaseException as error:
        manifest["error"] = str(error)
        raise
    finally:
        try:
            manifest["source_after"] = source_state(root, logs, "after", commit)
        except BaseException as error:
            manifest.update(passed=False, source_after_error=str(error))
        manifest["build_refs"] = [{"path": str(path.relative_to(output)), "sha256": digest(path)} for path in sorted(logs.iterdir())]
        save(output / "manifest.json", manifest)
    require(manifest["passed"], "Product build or final source verification failed")


if __name__ == "__main__":
    main()
