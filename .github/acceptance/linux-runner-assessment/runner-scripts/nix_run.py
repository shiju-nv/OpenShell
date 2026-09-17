#!/usr/bin/env python3
"""Enter the locked candidate toolchain without materializing unrelated targets."""
import argparse
import os
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--target', default='native')
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
command = a.command[1:] if a.command[:1] == ['--'] else a.command
if not command:
    p.error('a command is required')
source = str(Path.cwd())
recipe = str(Path(__file__).with_name('acceptance-shell.nix').resolve())
# JSON string syntax is accepted for these plain absolute Nix string values.
import json
expr = 'import (builtins.toPath ' + json.dumps(recipe) + ') { source = builtins.toPath ' + json.dumps(source) + ';'
if a.target != 'native':
    if a.target != 'x86_64-unknown-linux-musl':
        p.error('unsupported target')
    expr += ' target = ' + json.dumps(a.target) + ';'
expr += ' }'
if os.environ.get('ACCEPTANCE_NIX_OBSERVATIONS'):
    command = ['python3', str(Path(__file__).with_name('record_exec.py').resolve()), *command]
os.execvp('nix', ['nix', 'develop', '--impure', '--expr', expr, '--command', *command])
