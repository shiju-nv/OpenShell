# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Record each real workload launch before attempting controlled egress."""

import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

identity = {
    "pid": os.getpid(),
    "start_ticks": int(
        pathlib.Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
    ),
}
with pathlib.Path("/sandbox/composition-starts").open("a", encoding="utf-8") as starts:
    starts.write(json.dumps(identity, sort_keys=True) + "\n")
    starts.flush()
    os.fsync(starts.fileno())

request = urllib.request.Request(sys.argv[1])
if "COMPOSITION_TOKEN" in os.environ:
    request.add_header("Authorization", "Bearer " + os.environ["COMPOSITION_TOKEN"])
try:
    with urllib.request.urlopen(request, timeout=5) as response:
        outcome = {"status": response.status}
except (OSError, urllib.error.URLError) as error:
    outcome = {"error_type": type(error).__name__}
pathlib.Path("/sandbox/composition-first-request").write_text(json.dumps(outcome))

while True:
    # Atomic replacement prevents an independent reader from observing the empty
    # interval between truncation and writing a heartbeat.
    temporary = pathlib.Path("/sandbox/composition-heartbeat.next")
    temporary.write_text(str(time.monotonic_ns()))
    temporary.replace("/sandbox/composition-heartbeat")
    time.sleep(0.1)
