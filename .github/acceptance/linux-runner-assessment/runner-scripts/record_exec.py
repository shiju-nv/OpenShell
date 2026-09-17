#!/usr/bin/env python3
"""Record the selected Nix tools, then preserve the outer guard's process group."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

if not os.environ.get('IN_NIX_SHELL') or len(sys.argv) < 2:
    raise SystemExit('expected a command inside the selected Nix shell')
path = Path(os.environ['ACCEPTANCE_NIX_OBSERVATIONS'])
if path.exists():
    raise SystemExit('tool observations already exist')
tools = {}
for name, flags in [('rustc', ['--version', '--verbose']), ('cargo', ['--version']),
                    ('mise', ['--version']), ('nix', ['--version'])]:
    executable = shutil.which(name)
    if executable is None:
        tools[name] = {'path': None, 'exit_code': 127}
        continue
    result = subprocess.run([executable, *flags], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    tools[name] = {'path': executable, 'exit_code': result.returncode, 'output': result.stdout}
environment = {k: v for k, v in os.environ.items() if k in ['PATH', 'LD_LIBRARY_PATH', 'CARGO_TARGET_DIR', 'RUSTC_WRAPPER', 'MISE_TASK_SKIP', 'TMPDIR'] or k.startswith(('Z3_', 'CARGO_PROFILE_', 'CARGO_TARGET_'))}
path.write_text(json.dumps({'argv': sys.argv[1:], 'cwd': str(Path.cwd()), 'process_group': os.getpgrp(), 'tools': tools, 'environment': environment}, indent=2) + '\n')
# exec keeps the same PID/session: the one outer monitor can stop every child.
os.execvp(sys.argv[1], sys.argv[1:])
