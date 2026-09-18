#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Enter the candidate's locked native Rust toolchain on the hosted runner."""

import json
import os
import sys
from pathlib import Path

command = sys.argv[1:]
if command[:1] == ["--"]:
    command = command[1:]
if not command:
    raise SystemExit("A command is required")
source = str(Path.cwd())
recipe = str(Path(__file__).with_name("acceptance-shell.nix").resolve())
# These paths are controlled by the checkout, not workflow event text.
expression = (
    "import (builtins.toPath "
    + json.dumps(recipe)
    + ") { source = builtins.toPath "
    + json.dumps(source)
    + "; }"
)
os.execvp(
    "nix", ["nix", "develop", "--impure", "--expr", expression, "--command", *command]
)
