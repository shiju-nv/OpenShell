#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Release unused SDKs only on the disposable hosted VM and retain a receipt."""

import json
import os
import shutil
import subprocess
from pathlib import Path

if (
    os.environ.get("GITHUB_ACTIONS") != "true"
    or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    or os.environ.get("RUNNER_OS") != "Linux"
):
    raise SystemExit("Refusing cleanup outside an ephemeral GitHub-hosted Linux runner")
evidence = Path(os.environ["RUNNER_TEMP"]) / "policy-metadata-evidence"
evidence.mkdir(parents=True, exist_ok=True)
before = shutil.disk_usage("/")._asdict()
removed = []
for name in [
    "/usr/local/lib/android",
    "/usr/share/dotnet",
    "/opt/ghc",
    "/usr/local/.ghcup",
    "/usr/share/swift",
]:
    path = Path(name)
    if path.is_symlink():
        raise SystemExit("Refusing unexpected SDK symlink: " + name)
    if path.exists():
        size = subprocess.check_output(["sudo", "du", "-sk", name], text=True).strip()
        subprocess.run(["sudo", "rm", "-rf", "--", name], check=True)
        removed.append({"path": name, "allocated_kib_before": size})
after = shutil.disk_usage("/")._asdict()
(evidence / "runner-capacity.json").write_text(
    json.dumps(
        {"before": before, "removed_unused_sdks": removed, "after": after}, indent=2
    )
    + "\n"
)
if after["free"] < 16 * 1024**3:
    raise SystemExit("Hosted runner has less than 16 GiB free; no build started")
