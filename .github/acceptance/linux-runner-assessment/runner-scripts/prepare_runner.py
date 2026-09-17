#!/usr/bin/env python3
"""Reclaim only unused SDKs on the disposable hosted VM and record capacity."""
import json
import os
from pathlib import Path
import shutil
import subprocess

if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
    raise SystemExit('refusing cleanup outside an ephemeral GitHub-hosted runner')
evidence = Path(os.environ['RUNNER_TEMP']) / 'acceptance-evidence'
evidence.mkdir(exist_ok=True)
paths = ['/usr/local/lib/android', '/usr/share/dotnet', '/opt/ghc', '/usr/local/.ghcup', '/usr/share/swift']
before = shutil.disk_usage('/')._asdict()
rows = []
for item in paths:
    path = Path(item)
    if path.is_symlink():
        raise SystemExit('refusing unexpected SDK symlink: ' + item)
    if path.exists():
        size = subprocess.check_output(['sudo', 'du', '-sk', item], text=True).strip()
        subprocess.run(['sudo', 'rm', '-rf', '--', item], check=True)
        rows.append({'path': item, 'allocated_kib_before': size})
after = shutil.disk_usage('/')._asdict()
(evidence / 'runner-capacity.json').write_text(json.dumps({'before': before, 'removed_unused_sdk_directories': rows, 'after': after}, indent=2) + '\n')
if after['free'] < 16 * 1024**3:
    raise SystemExit('less than 16 GiB after bounded hosted SDK cleanup; no tool/build phase started')
