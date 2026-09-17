// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Included in boundary_server's Linux test module so the matrix exercises the
// production transitions with the same real child fixture as reconnect tests.

fn mutate_activation_receipt(
    field: &str,
    identity: &mut ConfigurationActivationIdentity,
    configuration: &mut ConfigurationRevision,
    transition: &mut String,
) {
    match field {
        "configuration_revision" => configuration.config_revision += 1,
        "policy_version" => configuration.policy_version += 1,
        "policy_hash" => configuration.policy_hash.push_str("-different"),
        "policy_source" => {
            configuration.policy_source = openshell_core::proto::PolicySource::Global as i32;
        }
        "provider_revision" => configuration.provider_env_revision += 1,
        "runtime_generation" => identity.runtime_generation.push_str("-different"),
        "session" => identity.boundary_session_id = uuid::Uuid::new_v4().to_string(),
        "supervisor_instance" => {
            identity.supervisor_instance_id = uuid::Uuid::new_v4().to_string();
        }
        "boundary_instance" => identity.boundary_instance_id = uuid::Uuid::new_v4().to_string(),
        "registration_revision" => identity.registration_revision += 1,
        "transition_id" => *transition = uuid::Uuid::new_v4().to_string(),
        _ => panic!("unknown activation receipt field: {field}"),
    }
}

#[test]
fn configuration_activation_identity_mismatch_matrix_holds_real_workload() {
    if isolated_activation_test(
        "configuration_activation_identity_mismatch_matrix_holds_real_workload",
    ) {
        return;
    }
    // The admission token is a gateway ticket, not a boundary coordinate. Its
    // stale/mismatch checks belong to authenticated gateway reporting tests.
    for field in [
        "configuration_revision",
        "policy_version",
        "policy_hash",
        "policy_source",
        "provider_revision",
        "runtime_generation",
        "session",
        "supervisor_instance",
        "boundary_instance",
        "registration_revision",
        "transition_id",
    ] {
        let fixture = RunningActivationFixture::new();
        let old = test_active_receipt(&fixture.boundary);
        let old_pid = fixture.workload_pid();
        let prepared = fixture.prepare_next();
        fixture.assert_held(&old);

        let mut wrong_preparation = prepared.clone();
        mutate_activation_receipt(
            field,
            &mut wrong_preparation.identity,
            &mut wrong_preparation.configuration,
            &mut wrong_preparation.transition_id,
        );
        assert_ne!(wrong_preparation, prepared);
        assert!(
            fixture
                .boundary
                .commit_configuration(&wrong_preparation)
                .is_err(),
            "commit accepted a mismatched {field}"
        );
        fixture.assert_held(&old);
        assert_eq!(
            fixture.boundary.configuration_snapshot().unwrap().installed,
            Some(old.configuration.clone()),
            "mismatched {field} changed the installed generation"
        );

        let installed = fixture.boundary.commit_configuration(&prepared).unwrap();
        let mut wrong_installation = installed.clone();
        mutate_activation_receipt(
            field,
            &mut wrong_installation.identity,
            &mut wrong_installation.configuration,
            &mut wrong_installation.transition_id,
        );
        assert_ne!(wrong_installation, installed);
        assert!(
            fixture
                .boundary
                .release_configuration(&wrong_installation)
                .is_err(),
            "release accepted a mismatched {field}"
        );
        fixture.assert_held(&old);
        let held_heartbeat = fixture.heartbeat();
        let released = fixture.boundary.release_configuration(&installed).unwrap();
        fixture.wait_for_heartbeat(held_heartbeat);
        assert_eq!(released.configuration, prepared.configuration);
        assert_eq!(fixture.workload_pid(), old_pid);
        assert_eq!(fixture.start_count(), 1);
        println!(
            "configuration_activation_observation {}",
            serde_json::json!({
                "scenario": "exact-activation-mismatch-matrix",
                "field": field,
                "pid": old_pid,
                "starts": fixture.start_count(),
                "held_heartbeat": held_heartbeat,
                "released_heartbeat": fixture.heartbeat(),
                "old_configuration": old.configuration,
                "candidate_configuration": prepared.configuration,
                "wrong_commit_rejected": true,
                "wrong_release_rejected": true,
            })
        );
    }
}

#[test]
fn configuration_activation_abort_requires_explicit_reactivation_of_real_workload() {
    if isolated_activation_test(
        "configuration_activation_abort_requires_explicit_reactivation_of_real_workload",
    ) {
        return;
    }
    let fixture = RunningActivationFixture::new();
    let old = test_active_receipt(&fixture.boundary);
    let old_environment = lock(&fixture.boundary.activation).provider_env.clone();
    let pid = fixture.workload_pid();
    let prepared = fixture.prepare_next();
    fixture.assert_held(&old);
    fixture.boundary.abort_configuration(&prepared).unwrap();
    fixture.boundary.abort_configuration(&prepared).unwrap();
    // Abort invalidates the candidate but never implies permission to resume.
    // A fail-closed caller can remain in this state until a repair is accepted.
    fixture.assert_held(&old);
    assert!(fixture.boundary.commit_configuration(&prepared).is_err());
    assert_eq!(
        fixture.boundary.configuration_snapshot().unwrap().installed,
        Some(old.configuration.clone())
    );
    assert_eq!(
        lock(&fixture.boundary.activation).provider_env,
        old_environment
    );
    let stale_installation = InstalledBoundaryConfiguration {
        identity: old.identity.clone(),
        transition_id: old.transition_id.clone(),
        configuration: old.configuration.clone(),
    };
    assert!(
        fixture
            .boundary
            .release_configuration(&stale_installation)
            .is_err()
    );
    fixture.assert_held(&old);
    let held_heartbeat = fixture.heartbeat();
    // Retaining the last accepted configuration requires a new exact transition;
    // replaying the old release token cannot reopen execution after quiescence.
    let snapshot = fixture.boundary.configuration_snapshot().unwrap();
    let retained = fixture
        .boundary
        .prepare_configuration(
            snapshot.identity,
            snapshot.installed,
            old.configuration.clone(),
            old_environment,
        )
        .unwrap();
    assert_ne!(retained.transition_id, old.transition_id);
    let installed = fixture.boundary.commit_configuration(&retained).unwrap();
    fixture.assert_held(&old);
    fixture.boundary.release_configuration(&installed).unwrap();
    fixture.wait_for_heartbeat(held_heartbeat);
    assert_eq!(fixture.workload_pid(), pid);
    assert_eq!(fixture.start_count(), 1);
    println!(
        "configuration_activation_observation {}",
        serde_json::json!({
            "scenario": "aborted-candidate-reactivation",
            "pid": pid,
            "starts": fixture.start_count(),
            "held_heartbeat": held_heartbeat,
            "released_heartbeat": fixture.heartbeat(),
            "accepted_configuration": old.configuration,
            "candidate_credentials_installed": false,
            "old_release_rejected": true,
        })
    );
}

#[test]
fn configuration_activation_delayed_release_cannot_resume_a_quiesced_workload() {
    if isolated_activation_test(
        "configuration_activation_delayed_release_cannot_resume_a_quiesced_workload",
    ) {
        return;
    }
    let fixture = RunningActivationFixture::new();
    let old = test_active_receipt(&fixture.boundary);
    let prepared = fixture.prepare_next();
    let installed = fixture.boundary.commit_configuration(&prepared).unwrap();
    let released = fixture.boundary.release_configuration(&installed).unwrap();
    let heartbeat = fixture.heartbeat();
    fixture.wait_for_heartbeat(heartbeat);
    fixture
        .boundary
        .quiesce_configuration(&released.identity)
        .unwrap();
    fixture.assert_held(&released);
    assert!(fixture.boundary.commit_configuration(&prepared).is_err());
    assert!(fixture.boundary.release_configuration(&installed).is_err());
    fixture.assert_held(&released);
    let snapshot = fixture.boundary.configuration_snapshot().unwrap();
    let environment = lock(&fixture.boundary.activation).provider_env.clone();
    let retry = fixture
        .boundary
        .prepare_configuration(
            snapshot.identity,
            snapshot.installed,
            released.configuration.clone(),
            environment,
        )
        .unwrap();
    let retry_installation = fixture.boundary.commit_configuration(&retry).unwrap();
    let before = fixture.heartbeat();
    fixture
        .boundary
        .release_configuration(&retry_installation)
        .unwrap();
    fixture.wait_for_heartbeat(before);
    assert_eq!(fixture.start_count(), 1);
    assert_eq!(old.identity, released.identity);
    println!(
        "configuration_activation_observation {}",
        serde_json::json!({
            "scenario": "delayed-release-after-quiesce",
            "pid": fixture.workload_pid(),
            "starts": fixture.start_count(),
            "delayed_commit_rejected": true,
            "delayed_release_rejected": true,
            "released_heartbeat": fixture.heartbeat(),
        })
    );
}
