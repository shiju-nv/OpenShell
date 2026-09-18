#!/usr/bin/env python3
"""Record literal task commands and stop only this job's child at the disk floor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading
import time

TREE = '8f52780f5fdd124fe2909b88e5951ebded6b2633'
RUST_SKIPS = 'rust:check,rust:lint,rust:format:check,rust:deny:policy,rust:lockfiles:check,test:rust'
COMMANDS = {
    'rust-checks': ['mise', 'run', '--jobs', '1', 'rust:check', ':::', 'rust:lint', ':::', 'rust:format:check', ':::', 'rust:deny:policy'],
    'rust-tests': ['mise', 'run', '--jobs', '1', 'test:rust'],
    'non-rust': ['mise', 'run', '--jobs', '1', 'ci'],
}

def source():
    commit = os.environ.get('ACCEPTANCE_PRODUCT_COMMIT', '')
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('replace the product commit placeholder with the signed 40-character commit')
    def git(*args):
        return subprocess.check_output(['git', *args], text=True).strip()
    observed = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}')}
    if observed != {'commit': commit, 'tree': TREE}:
        raise ValueError('candidate commit/tree mismatch')
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--'], check=True)
    observed['task_sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted([*Path('tasks').glob('*.toml'), Path('mise.toml'), Path('mise.lock'), Path('flake.lock'), Path('rust-toolchain.toml')])}
    return observed

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--suite', choices=[*COMMANDS, 'command', 'verify-source'], required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--nix-target', choices=['native', 'x86_64-unknown-linux-musl'])
    p.add_argument('command', nargs=argparse.REMAINDER)
    args = p.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    start = time.time()
    result = {'passed': False, 'exit_code': None, 'disk_floor_triggered': False}
    def save(name, data):
        (args.evidence / name).write_text(json.dumps(data, indent=2) + '\n')
    try:
        before = source()
        save('source-before.json', before)
        if args.suite == 'verify-source':
            result.update(passed=True, exit_code=0)
            return
        argv = COMMANDS.get(args.suite) or (args.command[1:] if args.command[:1] == ['--'] else args.command)
        if not argv:
            raise ValueError('missing command')
        env = dict(os.environ)
        if args.suite == 'non-rust':
            # Only this downstream job is allowed to adopt successful Rust job leaves.
            if env.get('ACCEPTANCE_RUST_JOBS_PASSED') != 'true':
                raise ValueError('missing successful workflow dependency gate')
            env['MISE_TASK_SKIP'] = RUST_SKIPS
        elif env.get('MISE_TASK_SKIP'):
            raise ValueError('unexpected task skipping')
        if shutil.disk_usage('/').free < 7 * 1024**3:
            raise ValueError('less than 7 GiB available before task execution')
        keys = ['ACCEPTANCE_PRODUCT_COMMIT', 'CARGO_TARGET_DIR', 'CARGO_INCREMENTAL', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'CARGO_PROFILE_RELEASE_DEBUG', 'CARGO_BUILD_JOBS', 'MISE_TASK_SKIP', 'TMPDIR', 'PATH', 'RUSTC_WRAPPER']
        versions = {}
        for tool, flags in [('rustc', ['--version', '--verbose']), ('cargo', ['--version']), ('mise', ['--version']), ('nix', ['--version'])]:
            if shutil.which(tool) is None:
                versions[tool] = {'argv': [tool, *flags], 'exit_code': 127, 'output': 'not installed in this outer environment'}
                continue
            observed = subprocess.run([tool, *flags], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
            versions[tool] = {'argv': [tool, *flags], 'exit_code': observed.returncode, 'output': observed.stdout}
        save('tools.json', versions)
        launch_argv = argv
        if args.nix_target:
            # One monitor owns Nix and its task descendants. The inner recorder
            # uses exec without creating another session or process group.
            env['ACCEPTANCE_NIX_OBSERVATIONS'] = str((args.evidence / 'nix-tools.json').resolve())
            launch_argv = ['python3', str(Path(__file__).with_name('nix_run.py').resolve()), '--target', args.nix_target, '--', *argv]
        save('command.json', {'argv': argv, 'launch_argv': launch_argv, 'cwd': str(Path.cwd()), 'environment': {k: env[k] for k in keys if k in env}})
        samples = []
        done = threading.Event()
        with (args.evidence / 'output.log').open('w') as log:
            child = subprocess.Popen(launch_argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
            def monitor():
                while not done.wait(5):
                    free = shutil.disk_usage('/').free
                    samples.append({'unix_time': time.time(), 'free_bytes': free})
                    if free < 2 * 1024**3:
                        result['disk_floor_triggered'] = True
                        try:
                            os.killpg(child.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        if not done.wait(15):
                            try:
                                os.killpg(child.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        return
            thread = threading.Thread(target=monitor, daemon=True)
            thread.start()
            assert child.stdout is not None
            for line in child.stdout:
                log.write(line)
                log.flush()
                print(line, end='', flush=True)
            result['exit_code'] = child.wait()
            done.set()
            thread.join()
        save('capacity-samples.json', samples)
        after = source()
        save('source-after.json', after)
        if before != after:
            raise ValueError('candidate tracked inputs changed during task')
        result['passed'] = result['exit_code'] == 0 and not result['disk_floor_triggered']
    except Exception as error:
        result['error'] = str(error)
    finally:
        result['elapsed_seconds'] = time.time() - start
        result['free_bytes_after'] = shutil.disk_usage('/').free
        save('result.json', result)
    if not result['passed']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
