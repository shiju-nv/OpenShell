#!/usr/bin/env fish
# Run real-child Linux boundary tests in an explicit candidate runtime image.
argparse 'evidence-dir=' 'test-name=+' -- $argv
or exit 2
for required in OPENSHELL_ACTIVATION_LINUX_TEST_BINARY OPENSHELL_ACTIVATION_CONTROL_IMAGE
    if not set -q $required
        printf 'Missing %s; Linux process proof cannot run.\n' $required >&2
        exit 2
    end
end
if not string match -qr '^sha256:[0-9a-f]{64}$' -- $OPENSHELL_ACTIVATION_CONTROL_IMAGE
    printf 'Control image must be the attested immutable sha256 ID.\n' >&2
    exit 2
end
if not test -f "$OPENSHELL_ACTIVATION_LINUX_TEST_BINARY"
    printf 'Linux test binary is unavailable: %s\n' "$OPENSHELL_ACTIVATION_LINUX_TEST_BINARY" >&2
    exit 2
end
set -l fixtures (path dirname (status filename))
set -l evidence "$fixtures/runs/boundary-"(date -u +%Y%m%dT%H%M%SZ)
if set -q _flag_evidence_dir
    set evidence $_flag_evidence_dir
end
if test -e "$evidence"
    printf 'Refusing to overwrite evidence: %s\n' "$evidence" >&2
    exit 2
end
mkdir -p "$evidence"
or exit 2
begin
    cd "$fixtures"
    shasum -a 256 -c SHA256SUMS
    and shasum -a 256 -c RUNTIME_SHA256SUMS
end >"$evidence/fixture-integrity.log" 2>&1
or exit 2
shasum -a 256 "$OPENSHELL_ACTIVATION_LINUX_TEST_BINARY" >"$evidence/linux-test.sha256"
or exit 2
docker image inspect $OPENSHELL_ACTIVATION_CONTROL_IMAGE >"$evidence/control-image.json"
or exit 2
set -l tests \
    boundary_server::linux::tests::configuration_activation_holds_real_workload_until_release \
    boundary_server::linux::tests::configuration_activation_confirm_does_not_resume_or_accept_stale_registration \
    boundary_server::linux::tests::configuration_activation_fresh_boundary_rejects_old_receipts \
    boundary_server::linux::tests::configuration_activation_identity_mismatch_matrix_holds_real_workload \
    boundary_server::linux::tests::configuration_activation_abort_requires_explicit_reactivation_of_real_workload \
    boundary_server::linux::tests::configuration_activation_delayed_release_cannot_resume_a_quiesced_workload \
    boundary_io::tests::configuration_activation_freeze_confirms_real_child_stop \
    boundary_io::tests::configuration_activation_freeze_orders_vfork_parent_before_child \
    boundary_server::linux::tests::configuration_activation_same_registration_recovery_preserves_inflight_transaction \
    boundary_server::linux::tests::configuration_activation_startup_policy_repair_invalidates_prior_transition \
    identity::tests::configuration_activation_named_user_fifo_rejected_without_blocking \
    identity::tests::configuration_activation_named_group_fifo_rejected_without_blocking \
    boundary_server::linux::tests::configuration_activation_transport_lost_commit_preserves_one_workload \
    boundary_server::linux::tests::configuration_activation_transport_lost_release_requires_exact_retry
# Exact selection supports focused corrections; full acceptance still requires
# every registered test and all observation matrices in the evidence combiner.
if set -q _flag_test_name
    for selected in $_flag_test_name
        if not contains -- $selected $tests
            printf 'Unknown boundary proof: %s\n' $selected >&2
            exit 2
        end
    end
    set tests $_flag_test_name
end
set -lx UV_CACHE_DIR "$OPENSHELL_PROOF_UV_CACHE"
set -lx UV_OFFLINE 1
set -lx UV_PYTHON_DOWNLOADS never
for test_name in $tests
    set -l label (string replace -a :: - $test_name)
    printf 'Running Linux process proof %s\n' $test_name
    # The test installs its own seccomp rules, exercises ptrace mediation, and
    # must run without root or ambient capabilities. Only /tmp is writable.
    set -l docker_args run --rm --network none --user 1000:1000 --cap-drop ALL \
        --security-opt seccomp=unconfined --security-opt no-new-privileges=true \
        --read-only --tmpfs /tmp:rw,nosuid,nodev \
        --mount "type=bind,source=$OPENSHELL_ACTIVATION_LINUX_TEST_BINARY,target=/activation-tests,readonly" \
        --mount "type=bind,source=$fixtures,target=/activation-fixtures,readonly" \
        --env OPENSHELL_ACTIVATION_FIXTURES=/activation-fixtures \
        --entrypoint /activation-tests $OPENSHELL_ACTIVATION_CONTROL_IMAGE \
        --exact $test_name --nocapture
    string join ' ' -- (string escape -- docker $docker_args) >"$evidence/$label.command.fish"
    docker $docker_args >"$evidence/$label.log" 2>&1
    set -l test_status $status
    uv run --no-project python "$fixtures/record-runtime-run.py" \
        --test-binary "$OPENSHELL_ACTIVATION_LINUX_TEST_BINARY" \
        --image "$OPENSHELL_ACTIVATION_CONTROL_IMAGE" \
        --command "$evidence/$label.command.fish" --log "$evidence/$label.log" \
        --exit-status $test_status --output "$evidence/$label.run.json"
    or exit $status
    cat "$evidence/$label.log"
    if test $test_status -ne 0
        printf 'Linux process proof failed: %s (exit %s).\n' $test_name $test_status >&2
        exit $test_status
    end
    if not rg -q 'test result: ok\. 1 passed; 0 failed; 0 ignored;' "$evidence/$label.log"
        printf 'No exactly matching Linux process proof executed: %s\n' $test_name >&2
        exit 1
    end
end
if set -q _flag_test_name
    printf 'Selected exact Linux tests passed; full boundary observations remain required by the evidence combiner.\n'
    exit 0
end
uv run --no-project python "$fixtures/verify-boundary-observations.py" "$evidence"
or exit $status
printf 'Linux boundary slice passed; authenticated gateway and integrated posture gates remain separate.\n'
