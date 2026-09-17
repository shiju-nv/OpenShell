#!/usr/bin/env fish
# Explicitly execute runtime integration tests excluded from ordinary unit runs.
argparse 'evidence-dir=' -- $argv
or exit 2
for required in OPENSHELL_ACTIVATION_SUPERVISOR_LINUX_TEST_BINARY OPENSHELL_ACTIVATION_SANDBOX_BINARY OPENSHELL_ACTIVATION_CONTROL_IMAGE
    if not set -q $required
        printf 'Missing %s; actual coordinator proof cannot run.\n' $required >&2
        exit 2
    end
end
if not string match -qr '^sha256:[0-9a-f]{64}$' -- $OPENSHELL_ACTIVATION_CONTROL_IMAGE
    printf 'Control image must be the attested immutable sha256 ID.\n' >&2
    exit 2
end
for executable in $OPENSHELL_ACTIVATION_SUPERVISOR_LINUX_TEST_BINARY $OPENSHELL_ACTIVATION_SANDBOX_BINARY
    if not test -f "$executable"
        printf 'Candidate Linux executable is unavailable: %s\n' "$executable" >&2
        exit 2
    end
end
set -l fixtures (path resolve (path dirname (status filename)))
set -l evidence "$fixtures/runs/supervisor-runtime-"(date -u +%Y%m%dT%H%M%SZ)
if set -q _flag_evidence_dir
    set evidence $_flag_evidence_dir
end
if test -e "$evidence"
    printf 'Refusing to overwrite evidence: %s\n' "$evidence" >&2
    exit 2
end
mkdir -p "$evidence"
or exit 2
set evidence (path resolve "$evidence")
begin
    cd "$fixtures"
    shasum -a 256 -c SHA256SUMS
    and shasum -a 256 -c RUNTIME_SHA256SUMS
end >"$evidence/fixture-integrity.log" 2>&1
or exit 2
shasum -a 256 $OPENSHELL_ACTIVATION_SUPERVISOR_LINUX_TEST_BINARY $OPENSHELL_ACTIVATION_SANDBOX_BINARY >"$evidence/executables.sha256"
or exit 2
docker image inspect $OPENSHELL_ACTIVATION_CONTROL_IMAGE >"$evidence/control-image.json"
or exit 2
# Preserve every image account. Only the test's absent, unambiguous sandbox
# UID/GID is added, and the resulting files are mounted read-only and hashed.
for account_file in passwd group
    docker run --rm --network none --cap-drop ALL --read-only --entrypoint /bin/cat \
        $OPENSHELL_ACTIVATION_CONTROL_IMAGE /etc/$account_file >"$evidence/$account_file.original"
    or exit 2
end
set -lx UV_CACHE_DIR "$OPENSHELL_PROOF_UV_CACHE"
set -lx UV_OFFLINE 1
set -lx UV_PYTHON_DOWNLOADS never
uv run --no-project python -c '
import pathlib, sys
root = pathlib.Path(sys.argv[1])
for name, addition in [("passwd", "sandbox:x:1000:1000:Sandbox fixture:/tmp:/bin/sh"), ("group", "sandbox:x:1000:")]:
    text = (root / (name + ".original")).read_text()
    rows = [line.split(":") for line in text.splitlines() if line and not line.startswith("#")]
    reserved = [row for row in rows if row[0] == "sandbox" or row[2] == "1000"]
    if reserved:
        assert len(reserved) == 1 and reserved[0][0] == "sandbox" and reserved[0][2] == "1000", (name, "conflicting fixture account")
        if name == "passwd":
            assert reserved[0][3] == "1000", "sandbox primary group must be 1000"
    else:
        text = text.rstrip("\n") + "\n" + addition + "\n"
    target = root / (name + ".fixture")
    target.write_text(text)
    target.chmod(0o644)
' "$evidence"
or exit 2
shasum -a 256 "$evidence/passwd.original" "$evidence/group.original" "$evidence/passwd.fixture" "$evidence/group.fixture" >"$evidence/accounts.sha256"
or exit 2
set -l tests \
    configuration::tests::configuration_activation_runtime_publication_pause_holds_workload \
    configuration::tests::configuration_activation_runtime_rejection_postures_preserve_one_generation
for test_name in $tests
    set -l label (string replace -a :: - $test_name)
    printf 'Running actual coordinator proof %s\n' $test_name
    set -l docker_args run --rm --network none --user 1000:1000 --cap-drop ALL \
        --security-opt seccomp=unconfined --security-opt no-new-privileges=true \
        --read-only --tmpfs /tmp:rw,nosuid,nodev \
        --mount "type=bind,source=$OPENSHELL_ACTIVATION_SUPERVISOR_LINUX_TEST_BINARY,target=/activation-tests,readonly" \
        --mount "type=bind,source=$OPENSHELL_ACTIVATION_SANDBOX_BINARY,target=/activation-sandbox,readonly" \
        --mount "type=bind,source=$fixtures,target=/activation-fixtures,readonly" \
        --mount "type=bind,source=$evidence/passwd.fixture,target=/etc/passwd,readonly" \
        --mount "type=bind,source=$evidence/group.fixture,target=/etc/group,readonly" \
        --env OPENSHELL_ACTIVATION_FIXTURES=/activation-fixtures \
        --env OPENSHELL_ACTIVATION_SANDBOX_BINARY=/activation-sandbox \
        --entrypoint /activation-tests $OPENSHELL_ACTIVATION_CONTROL_IMAGE \
        --ignored --exact $test_name --nocapture
    string join ' ' -- (string escape -- docker $docker_args) >"$evidence/$label.command.fish"
    docker $docker_args >"$evidence/$label.log" 2>&1
    set -l test_status $status
    uv run --no-project python "$fixtures/record-runtime-run.py" \
        --test-binary "$OPENSHELL_ACTIVATION_SUPERVISOR_LINUX_TEST_BINARY" \
        --boundary-binary "$OPENSHELL_ACTIVATION_SANDBOX_BINARY" \
        --accounts-directory "$evidence" \
        --image "$OPENSHELL_ACTIVATION_CONTROL_IMAGE" \
        --command "$evidence/$label.command.fish" --log "$evidence/$label.log" \
        --exit-status $test_status --output "$evidence/$label.run.json"
    or exit $status
    cat "$evidence/$label.log"
    if test $test_status -ne 0
        printf 'Actual coordinator proof failed: %s (exit %s).\n' $test_name $test_status >&2
        exit $test_status
    end
    if not rg -q 'test result: ok\. 1 passed; 0 failed; 0 ignored;' "$evidence/$label.log"
        printf 'Required runtime proof did not execute: %s\n' $test_name >&2
        exit 1
    end
end
uv run --no-project python "$fixtures/verify-runtime-observations.py" "$evidence"
or exit $status
printf 'Actual coordinator slice passed. Gateway admission and workload egress remain separately composed.\n'
