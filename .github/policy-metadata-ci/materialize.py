# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Materialize a reviewed patch without manufacturing a product commit."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def require(condition, message):
    """Reject invalid evidence even when Python runs with optimization enabled."""
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    """Hash files incrementally, including large compiler artifacts."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(worktree, *arguments):
    """Run a checked Git command in the explicitly selected checkout."""
    return subprocess.check_output(["git", *arguments], cwd=worktree, text=True).strip()


def bundle_file(bundle, relative):
    """Keep manifest-selected inputs inside the controller bundle."""
    path = (bundle / relative).resolve()
    require(
        path.is_relative_to(bundle.resolve()) and path.is_file(),
        f"Input escapes bundle or is missing: {relative}",
    )
    return path


def load_manifest(bundle):
    """Validate the versioned source identity shared by both CI phases."""
    manifest = json.loads((bundle / "manifest.json").read_text())
    require(manifest.get("schema_version") == 1, "Unsupported manifest schema")
    for field in ("base_commit", "candidate_tree"):
        require(
            re.fullmatch(r"[0-9a-f]{40}", manifest[field]) is not None,
            f"Invalid full Git identity: {field}",
        )
    patch = bundle_file(bundle, "candidate.patch")
    require(
        sha256(patch) == manifest["candidate_patch_sha256"],
        "Candidate patch digest mismatch",
    )
    return manifest


def guard(worktree, manifest, tree):
    """Bind base, staged tree, working bytes, and absence of extra source files."""
    require(
        git(worktree, "rev-parse", "HEAD") == manifest["base_commit"],
        "Checkout HEAD is not the manifest base",
    )
    require(git(worktree, "write-tree") == tree, "Index tree mismatch")
    subprocess.run(
        ["git", "diff", "--exit-code", "--quiet", "--"], cwd=worktree, check=True
    )
    require(
        not git(worktree, "ls-files", "--others", "--exclude-standard"),
        "Untracked files would make source provenance ambiguous",
    )


def main():
    """Apply only to a pristine base checkout and report its resulting tree."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    worktree, bundle = args.worktree.resolve(), args.bundle.resolve()
    manifest = load_manifest(bundle)
    guard(worktree, manifest, git(worktree, "rev-parse", "HEAD^{tree}"))
    patch = bundle_file(bundle, "candidate.patch")
    subprocess.run(
        ["git", "apply", "--check", "--index", str(patch)], cwd=worktree, check=True
    )
    subprocess.run(["git", "apply", "--index", str(patch)], cwd=worktree, check=True)
    guard(worktree, manifest, manifest["candidate_tree"])
    for path, blob in manifest["source_blobs"].items():
        require(
            git(worktree, "rev-parse", f":{path}") == blob,
            f"Candidate blob mismatch: {path}",
        )
    receipt = {
        "base_commit": manifest["base_commit"],
        "candidate_tree": manifest["candidate_tree"],
        "manifest_sha256": sha256(bundle / "manifest.json"),
        "candidate_patch_sha256": sha256(patch),
    }
    if args.output:
        output = args.output.resolve()
        require(not output.is_relative_to(worktree), "Receipt must be outside source")
        require(not output.exists(), "Preserve existing materialization receipts")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    main()
