# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Read workload records and inspect exact Python workload argv in Linux procfs."""

import json
import os
import pathlib
import sys

program, workload_url, record_prefix = sys.argv[1:]
expected_arguments = [b"-c", program.encode(), workload_url.encode()]
processes = []
for entry in pathlib.Path("/proc").iterdir():
    if not entry.name.isdecimal() or int(entry.name) == os.getpid():
        continue
    try:
        arguments = (entry / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        # The observer has a different -c program and extra arguments. Exact
        # equality avoids treating it or an unrelated process as the workload.
        if arguments[1:] != expected_arguments:
            continue
        fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        processes.append(
            {
                "pid": int(entry.name),
                "state": fields[0],
                "start_ticks": int(fields[19]),
            }
        )
    except (FileNotFoundError, ProcessLookupError):
        # A process may exit between enumerating its PID and reading its files.
        continue


def read_record(name):
    """Return absence explicitly; unreadable evidence must fail the observer."""
    path = pathlib.Path(f"/sandbox/{record_prefix}-{name}")
    return path.read_text() if path.exists() else None


observation = {
    name: read_record(name) for name in ["starts", "heartbeat", "first-request"]
}
observation["processes"] = sorted(processes, key=lambda process: process["pid"])
print(json.dumps(observation))
