"""Verify downloaded role products and assemble local candidate runtime images."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import uuid

from build_products import ROLES, TREE, check_runner, digest, elf_header, require, run, save, selected_commit, source_state, verify_binary


def artifact_path(root, relative):
    """Reject path escapes and symlinks in downloaded artifact references."""
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts, "Artifact path escapes role directory")
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), "Artifact symlink is not allowed")
    require(current.is_file() and current.resolve().is_relative_to(root.resolve()), "Artifact is absent or escapes its root")
    return current


def load_products(artifacts, commit):
    """Require the exact five products, original build receipts and source identity."""
    files, manifests = {}, {}
    for group, expected in ROLES.items():
        directory = artifacts / group
        require(not directory.is_symlink() and directory.is_dir(), f"Missing role: {group}")
        manifest_path = artifact_path(directory, "manifest.json")
        manifest = json.loads(manifest_path.read_text())
        require(manifest.get("schema_version") == 1 and manifest.get("passed") is True and manifest.get("role") == group, f"Failed role manifest: {group}")
        require(manifest.get("product_commit") == commit and manifest.get("candidate_tree") == TREE, f"Role source differs: {group}")
        triple = "x86_64-unknown-linux-musl" if group == "sandbox" else "x86_64-unknown-linux-gnu"
        require(manifest.get("target") == triple, f"Role target differs: {group}")
        require(manifest.get("source_before") == manifest.get("source_after") ==
                {"product_commit": commit, "candidate_tree": TREE, "tracked_clean": True}, f"Role source changed: {group}")
        require(set(manifest.get("files", {})) == set(expected), f"Role binary set differs: {group}")
        refs = manifest.get("build_refs", [])
        require(refs and len({row["path"] for row in refs}) == len(refs), "Missing or duplicate build references")
        for row in refs:
            require(digest(artifact_path(directory, row["path"])) == row["sha256"], "Build receipt hash differs")
        by_path = {row["path"] for row in refs}
        for role, (package, binary) in expected.items():
            entry = manifest["files"][role]
            require(entry.get("role") == role and entry.get("path") == f"products/{binary}", f"Unexpected product path: {role}")
            path = artifact_path(directory, entry["path"])
            require(digest(path) == entry["sha256"], f"Product digest differs: {role}")
            elf_header(path)
            build_ref = f"logs/cargo-{role}.json"
            require(entry.get("build_ref") == build_ref and build_ref in by_path, f"Missing Cargo receipt: {role}")
            receipt = json.loads(artifact_path(directory, build_ref).read_text())
            require(receipt.get("exit_status") == 0, f"Failed Cargo receipt: {role}")
            argv = receipt.get("argv", [])
            require(len(argv) == 12 and argv[:7] == ["cargo", "build", "--locked", "--release", "--target", triple, "--target-dir"]
                    and argv[8:] == ["--package", package, "--bin", binary], f"Unexpected Cargo command: {role}")
            raw_log = f"logs/cargo-{role}.log"
            require(receipt.get("log") == f"cargo-{role}.log" and raw_log in by_path
                    and digest(artifact_path(directory, raw_log)) == receipt.get("log_sha256"), f"Cargo raw log differs: {role}")
            files[role] = {"path": str(path.relative_to(artifacts)), "sha256": entry["sha256"]}
        manifests[group] = {"path": str(manifest_path.relative_to(artifacts)), "sha256": digest(manifest_path)}
    return files, manifests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    root, artifacts = Path.cwd().resolve(), args.artifacts.resolve()
    output, evidence = args.output.resolve(), args.evidence.resolve()
    check_runner()
    commit = selected_commit()
    require(output.parent == artifacts and not output.exists() and not evidence.exists(), "Use unused products.json in the artifact root and new evidence")
    evidence.mkdir(parents=True)
    logs = evidence / "logs"
    logs.mkdir()
    result = {"passed": False, "product_commit": commit, "candidate_tree": TREE,
              "producer_sha256": digest(Path(__file__)), "helper_sha256": digest(Path(__file__).with_name("build_products.py")),
              "images": {}, "chains": {}}
    try:
        result["source_before"] = source_state(root, logs, "before", commit)
        files, manifests = load_products(artifacts, commit)
        result.update(files=files, role_manifests=manifests)
        for role, entry in files.items():
            verify_binary(root, logs, role, artifacts / entry["path"])
        run(root, logs, "docker-version", ["docker", "version"])
        archives = artifacts / "images"
        archives.mkdir(exist_ok=False)
        for role in ("sandbox", "supervisor"):
            source = artifacts / files[role]["path"]
            staged = root / "deploy/docker/.build/prebuilt-binaries/amd64" / f"openshell-{role}"
            require(not staged.exists() and not staged.is_symlink(), "Refuse to replace existing staged binary")
            # The repository owns this ignored packaging path; do not stage a
            # binary unless Git confirms the tracked source will remain intact.
            run(root, logs, f"ignored-{role}", ["git", "check-ignore", "--", str(staged.relative_to(root))])
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, staged)
            staged.chmod(0o755)
            wanted = files[role]["sha256"]
            require(digest(staged) == wanted, f"Staging changed binary: {role}")
            suffix = uuid.uuid4().hex[:12]
            reference = f"openshell/{role}:acceptance-{commit[:12]}-{suffix}"
            run(root, logs, f"build-{role}", ["docker", "build", "--platform", "linux/amd64", "--file",
                f"deploy/docker/Dockerfile.{role}", "--target", role, "--tag", reference, "."])
            inspection = json.loads(run(root, logs, f"inspect-{role}", ["docker", "image", "inspect", reference]))
            require(len(inspection) == 1 and inspection[0]["Os"] == "linux" and inspection[0]["Architecture"] == "amd64", "Wrong image architecture")
            image_id = inspection[0]["Id"]
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "Malformed image identity")
            cid = run(root, logs, f"create-{role}", ["docker", "create", "--name", f"acceptance-extract-{suffix}",
                "--network", "none", "--entrypoint", "/unused", image_id]).strip()
            require(re.fullmatch(r"[0-9a-f]{64}", cid), "Malformed extraction container identity")
            extracted = evidence / f"{role}-image-binary"
            try:
                run(root, logs, f"extract-{role}", ["docker", "cp", f"{cid}:/openshell-{role}", str(extracted)])
                require(digest(extracted) == wanted, f"Image contains different binary: {role}")
            finally:
                # Remove only the stopped container created above, including
                # when extraction or byte verification fails.
                run(root, logs, f"remove-{role}", ["docker", "rm", cid])
            archive = archives / f"{role}.tar"
            run(root, logs, f"save-{role}", ["docker", "save", "--output", str(archive), reference])
            result["images"][role] = {"id": image_id, "reference": reference,
                "archive": str(archive.relative_to(artifacts)), "archive_sha256": digest(archive)}
            result["chains"][role] = {"built": files[role], "staged": {"path": str(staged), "sha256": digest(staged)},
                                     "extracted": {"path": str(extracted), "sha256": digest(extracted)}}
        result["passed"] = True
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        try:
            result["source_after"] = source_state(root, logs, "after", commit)
        except BaseException as error:
            result.update(passed=False, source_after_error=str(error))
        save(evidence / "result.json", result)
    require(result["passed"], "Assembly or final source verification failed")
    # Publish the consumer manifest only after every byte chain and the final
    # tracked source identity pass. Partial assemblies retain evidence only.
    save(output, {"schema_version": 1, "product_commit": commit, "candidate_tree": TREE,
                  "files": result["files"], "images": result["images"],
                  "assembly_evidence": {"path": os.path.relpath(evidence / "result.json", artifacts),
                                        "sha256": digest(evidence / "result.json")}})


if __name__ == "__main__":
    main()
