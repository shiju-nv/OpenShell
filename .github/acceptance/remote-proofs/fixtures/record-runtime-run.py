"""Record one completed runtime invocation, preserving failures as failures."""

import argparse
import hashlib
import json
import pathlib
import re


def artifact(path):
    path = pathlib.Path(path).resolve()
    with path.open("rb") as source:
        checksum = hashlib.file_digest(source, "sha256").hexdigest()
    return {"path": str(path), "sha256": checksum}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-binary", required=True)
    parser.add_argument("--boundary-binary")
    parser.add_argument("--accounts-directory", type=pathlib.Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--exit-status", type=int, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", args.image), "Run must pin an immutable image ID"
    executable = artifact(args.test_binary)
    result = {
        "command": pathlib.Path(args.command).read_text().strip(),
        "command_artifact": artifact(args.command), "exit_status": args.exit_status,
        "executable": "test", "executable_sha256": executable["sha256"],
        "mounted_test_executable": executable, "image_ids": {"control": args.image},
        "log": artifact(args.log),
    }
    if args.boundary_binary:
        result["spawned_boundary_executable"] = artifact(args.boundary_binary)
    if args.accounts_directory:
        result["account_fixtures"] = {
            name: artifact(args.accounts_directory / name)
            for name in ("passwd.original", "group.original", "passwd.fixture", "group.fixture")
        }
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
