// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::tests::{
    CONFIGURATION_TEST_GATEWAY_TOKEN_ID, configuration_activation_poll,
    configuration_activation_report, mcp_policy_with_versions, test_sandbox, with_sandbox,
};
use super::super::{
    decode_policy_from_global_settings, deterministic_policy_hash,
    handle_report_sandbox_configuration, handle_update_config, load_global_settings,
};
use super::*;
use crate::grpc::test_support::{authed_request, test_server_state};
use crate::policy_store::PolicyStoreExt;
use openshell_core::endpoint_status::endpoint_id;
use openshell_core::proto::{
    ConfigurationAdmissionState, EndpointObservation, GetSandboxConfigResponse, GetSandboxRequest,
    NetworkEndpoint, NetworkPolicyRule, SandboxCondition, SandboxConfigurationAdmission,
    SandboxPhase, UpdateConfigRequest, workspace_selector,
};
use tonic::Code;

fn test_initial_endpoint_status(endpoint_id: &str, host: &str, path: &str) -> EndpointStatus {
    EndpointStatus {
        endpoint_id: endpoint_id.to_string(),
        host: host.to_string(),
        ports: vec![443],
        path: path.to_string(),
        last_result: EndpointResult::NoObservedExchange as i32,
        last_reported_at: String::new(),
    }
}

fn ready_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "True".to_string(),
        reason: "SupervisorReady".to_string(),
        ..Default::default()
    }
}

fn assert_same_conditions(actual: &[SandboxCondition], expected: &[SandboxCondition]) {
    let mut actual = actual.to_vec();
    let mut expected = expected.to_vec();
    actual.sort_by(|left, right| left.r#type.cmp(&right.r#type));
    expected.sort_by(|left, right| left.r#type.cmp(&right.r#type));
    assert_eq!(actual, expected);
}

fn register_session(state: &ServerState, sandbox_id: &str, session_id: &str) {
    let (session_tx, _session_rx) = tokio::sync::mpsc::channel(1);
    let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();
    state.supervisor_sessions.register(
        sandbox_id.to_string(),
        session_id.to_string(),
        session_tx,
        shutdown_tx,
    );
}

async fn stored_sandbox(state: &ServerState, sandbox_id: &str) -> Sandbox {
    state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .expect("load sandbox")
        .expect("sandbox remains present")
}

async fn public_status(state: &Arc<ServerState>, sandbox_id: &str) -> SandboxStatus {
    crate::grpc::sandbox::handle_get_sandbox(
        state,
        authed_request(GetSandboxRequest {
            name: sandbox_id.to_string(),
            workspace_scope: Some(workspace_selector("default")),
        }),
    )
    .await
    .expect("public sandbox status")
    .into_inner()
    .sandbox
    .expect("sandbox remains present")
    .status
    .expect("status remains present")
}

async fn endpoint_server_state() -> Arc<ServerState> {
    let mut state = test_server_state().await;
    let key = openshell_bootstrap::jwt::generate_jwt_key().expect("generate launch signing key");
    Arc::get_mut(&mut state)
        .expect("uniquely owned test state")
        .sandbox_session_jwt_authority = Some(Arc::new(
        crate::auth::sandbox_jwt::SandboxSessionJwtAuthority::from_pem(
            key.signing_key_pem.as_bytes(),
            key.public_key_pem.as_bytes(),
            key.kid,
            "test-gateway",
            std::time::Duration::from_hours(1),
        )
        .expect("launch authority"),
    ));
    state
}

async fn register_configuration_runtime(state: &Arc<ServerState>, sandbox_id: &str) {
    let mut sandbox = stored_sandbox(state, sandbox_id).await;
    let identity = crate::auth::sandbox_session::PersistedSandboxIdentity {
        runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
            "activation-generation",
        )
        .expect("runtime generation"),
        auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).expect("credential epoch"),
        gateway_token_id: CONFIGURATION_TEST_GATEWAY_TOKEN_ID,
        refresh_replay: None,
    };
    identity.write(
        &mut sandbox
            .metadata
            .as_mut()
            .expect("sandbox metadata")
            .annotations,
    );
    let admission = SandboxConfigurationAdmission {
        instance_id: uuid::Uuid::new_v4().to_string(),
        runtime_generation: "activation-generation".to_string(),
        boundary_instance_id: uuid::Uuid::new_v4().to_string(),
        boundary_session_id: uuid::Uuid::new_v4().to_string(),
        state: ConfigurationAdmissionState::Pending.into(),
        ..Default::default()
    };
    let status = sandbox.status.get_or_insert_with(Default::default);
    status.phase = SandboxPhase::Provisioning.into();
    status
        .main_process_instance_id
        .clone_from(&admission.instance_id);
    status.configuration_activation_authorized = Some(false);
    status.conditions = vec![SandboxCondition {
        r#type: "ComputeReady".to_string(),
        ..ready_condition()
    }];
    state
        .store
        .put_message(&sandbox)
        .await
        .expect("store runtime identity");
    let registration = handle_report_sandbox_configuration(
        state,
        configuration_activation_report(sandbox_id, admission, "", ""),
    )
    .await
    .expect("register control and boundary")
    .into_inner();
    assert!(!registration.control_registration_grant.is_empty());
}

async fn issue_configuration(
    state: &Arc<ServerState>,
    sandbox_id: &str,
) -> (SandboxConfigurationAdmission, GetSandboxConfigResponse) {
    let sandbox = stored_sandbox(state, sandbox_id).await;
    let mut admission = sandbox
        .status
        .expect("sandbox status")
        .configuration_admission
        .expect("registered runtime");
    let config = configuration_activation_poll(state, sandbox_id, &admission.instance_id).await;
    assert!(
        config.configuration_admitted,
        "{}",
        config.configuration_error
    );
    admission.registration_revision = config.configuration_registration_revision;
    admission.delivery_revision = config.configuration_delivery_revision;
    admission
        .configuration_snapshot
        .clone_from(&config.configuration_snapshot);
    admission.policy_version = config.version;
    admission.policy_hash.clone_from(&config.policy_hash);
    admission.policy_source = config.policy_source;
    admission.config_revision = config.config_revision;
    admission.provider_env_revision = config.provider_env_revision;
    admission.activation_confirmed = false;
    // Endpoint authority belongs to the gateway-issued snapshot, not the report.
    admission.endpoint_configuration = None;
    (admission, config)
}

async fn accept_held_configuration(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    admission: &mut SandboxConfigurationAdmission,
) {
    admission.state = ConfigurationAdmissionState::Accepted.into();
    admission.activation_confirmed = false;
    handle_report_sandbox_configuration(
        state,
        configuration_activation_report(sandbox_id, admission.clone(), "", ""),
    )
    .await
    .expect("accept exact installed configuration while held");
}

async fn confirm_configuration(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    mut admission: SandboxConfigurationAdmission,
) {
    accept_held_configuration(state, sandbox_id, &mut admission).await;
    admission.activation_confirmed = true;
    handle_report_sandbox_configuration(
        state,
        configuration_activation_report(sandbox_id, admission, "", ""),
    )
    .await
    .expect("confirm exact released configuration");
}

async fn activate_policy_configuration(state: &Arc<ServerState>, sandbox_id: &str, version: u32) {
    let (admission, _) = issue_configuration(state, sandbox_id).await;
    assert_eq!(admission.policy_version, version);
    confirm_configuration(state, sandbox_id, admission).await;
}

async fn sandbox_with_accepted_endpoint_result(
    sandbox_id: &str,
) -> (Arc<ServerState>, ReportEndpointStatusRequest) {
    let state = endpoint_server_state().await;
    let mut policy = mcp_policy_with_versions(&["2025-11-25"]);
    let endpoint = &mut policy
        .network_policies
        .get_mut("mcp")
        .expect("MCP rule")
        .endpoints[0];
    endpoint.host = "tools.example.com".to_string();
    endpoint.path = "/mcp".to_string();
    let mut sandbox = test_sandbox(sandbox_id, sandbox_id, policy.clone(), Vec::new());
    sandbox.status = Some(SandboxStatus {
        sandbox_name: sandbox_id.to_string(),
        phase: SandboxPhase::Ready as i32,
        conditions: vec![ready_condition()],
        ..Default::default()
    });
    state
        .store
        .put_message(&sandbox)
        .await
        .expect("store sandbox");
    state
        .store
        .put_policy_revision(
            &format!("{sandbox_id}-v1"),
            sandbox_id,
            "default",
            1,
            &policy.encode_to_vec(),
            &deterministic_policy_hash(&policy),
        )
        .await
        .expect("store policy revision");
    register_configuration_runtime(&state, sandbox_id).await;
    activate_policy_configuration(&state, sandbox_id, 1).await;

    register_session(&state, sandbox_id, "session-a");
    reset_endpoint_status_for_supervisor_session(&state, sandbox_id, "session-a")
        .await
        .expect("reset session evidence");
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority(sandbox_id, "session-a")
    );
    let sandbox = stored_sandbox(&state, sandbox_id).await;
    let context = active_endpoint_context(&sandbox);
    let endpoint_id = context
        .endpoints
        .keys()
        .next()
        .expect("MCP endpoint")
        .clone();
    let report = ReportEndpointStatusRequest {
        sandbox_id: sandbox_id.to_string(),
        policy_hash: context.policy_hash,
        provider_env_revision: context.provider_env_revision,
        observations: vec![EndpointObservation {
            endpoint_id: endpoint_id.clone(),
            result: EndpointResult::HttpResponseReceived as i32,
        }],
        observed_endpoint_ids: vec![endpoint_id],
        supervisor_session_id: "session-a".to_string(),
        report_sequence: 1,
    };
    handle_report_endpoint_status(
        &state,
        with_sandbox(Request::new(report.clone()), sandbox_id),
    )
    .await
    .expect("accept endpoint result");
    (state, report)
}

async fn assert_confirmation_preserves_endpoint_evidence(
    state: &Arc<ServerState>,
    report: ReportEndpointStatusRequest,
    version: u32,
) {
    let before = public_status(state, &report.sandbox_id).await;
    assert_eq!(before.endpoint_statuses.len(), 1);
    assert_eq!(
        before.endpoint_statuses[0].last_result,
        EndpointResult::HttpResponseReceived as i32
    );
    assert!(!before.endpoint_statuses[0].last_reported_at.is_empty());
    let cursor = state
        .supervisor_sessions
        .endpoint_report_cursor(&report.sandbox_id, &report.supervisor_session_id);

    activate_policy_configuration(state, &report.sandbox_id, version).await;

    let after = public_status(state, &report.sandbox_id).await;
    assert_eq!(after.current_policy_version, version);
    assert_eq!(after.endpoint_statuses, before.endpoint_statuses);
    assert_eq!(after.phase, before.phase);
    assert_same_conditions(&after.conditions, &before.conditions);
    assert_eq!(
        state
            .supervisor_sessions
            .endpoint_report_cursor(&report.sandbox_id, &report.supervisor_session_id),
        cursor
    );

    // The endpoint RPC may have committed before its acknowledgement was lost.
    // A later configuration confirmation cannot invalidate that immutable retry.
    let committed = stored_sandbox(state, &report.sandbox_id).await;
    handle_report_endpoint_status(
        state,
        with_sandbox(Request::new(report.clone()), &report.sandbox_id),
    )
    .await
    .expect("retry accepted endpoint report");
    assert_eq!(stored_sandbox(state, &report.sandbox_id).await, committed);
}

#[tokio::test]
async fn configuration_confirmation_retry_preserves_endpoint_evidence() {
    let (state, report) = sandbox_with_accepted_endpoint_result("endpoint-loaded-retry").await;

    assert_confirmation_preserves_endpoint_evidence(&state, report, 1).await;
}

#[tokio::test]
async fn unchanged_policy_revision_preserves_endpoint_evidence() {
    let sandbox_id = "endpoint-unchanged-revision";
    let (state, report) = sandbox_with_accepted_endpoint_result(sandbox_id).await;
    let sandbox = stored_sandbox(&state, sandbox_id).await;
    let revision = handle_update_config(
        &state,
        authed_request(UpdateConfigRequest {
            name: sandbox_id.to_string(),
            policy: sandbox.spec.expect("sandbox spec").policy,
            annotations: HashMap::from([("audit".to_string(), "v2".to_string())]),
            workspace_scope: Some(workspace_selector("default")),
            ..Default::default()
        }),
    )
    .await
    .expect("create metadata-only policy revision")
    .into_inner();
    assert_eq!(revision.version, 2);
    assert_eq!(revision.policy_hash, report.policy_hash);

    assert_confirmation_preserves_endpoint_evidence(&state, report, 2).await;
}

#[tokio::test]
async fn endpoint_observation_requires_confirmed_configuration() {
    let state = endpoint_server_state().await;
    let sandbox_id = "endpoint-initial-confirmation";
    let policy = mcp_policy_with_versions(&["2025-11-25"]);
    let endpoint_id = endpoint_id(&policy.network_policies["mcp"].endpoints[0]);
    state
        .store
        .put_message(&test_sandbox(sandbox_id, sandbox_id, policy, Vec::new()))
        .await
        .expect("store sandbox");
    register_configuration_runtime(&state, sandbox_id).await;
    let (mut admission, _) = issue_configuration(&state, sandbox_id).await;
    register_session(&state, sandbox_id, "session-a");
    reset_endpoint_status_for_supervisor_session(&state, sandbox_id, "session-a")
        .await
        .expect("reset unconfirmed session");
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority(sandbox_id, "session-a")
    );
    let report = ReportEndpointStatusRequest {
        sandbox_id: sandbox_id.to_string(),
        policy_hash: admission.policy_hash.clone(),
        provider_env_revision: admission.provider_env_revision,
        observations: vec![EndpointObservation {
            endpoint_id: endpoint_id.clone(),
            result: EndpointResult::HttpResponseReceived.into(),
        }],
        observed_endpoint_ids: vec![endpoint_id],
        supervisor_session_id: "session-a".to_string(),
        report_sequence: 1,
    };

    // Neither a delivered ticket nor an accepted-but-held runtime may publish
    // observations before the boundary confirms release of that configuration.
    for held in [false, true] {
        if held {
            accept_held_configuration(&state, sandbox_id, &mut admission).await;
        }
        let before = stored_sandbox(&state, sandbox_id).await;
        let error = handle_report_endpoint_status(
            &state,
            with_sandbox(Request::new(report.clone()), sandbox_id),
        )
        .await
        .expect_err("unconfirmed endpoint observation is rejected");
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(stored_sandbox(&state, sandbox_id).await, before);
        assert!(
            public_status(&state, sandbox_id)
                .await
                .endpoint_statuses
                .is_empty()
        );
        assert!(
            state
                .supervisor_sessions
                .endpoint_report_cursor(sandbox_id, "session-a")
                .is_none()
        );
    }

    confirm_configuration(&state, sandbox_id, admission).await;
    handle_report_endpoint_status(&state, with_sandbox(Request::new(report), sandbox_id))
        .await
        .expect("confirmed runtime accepts its first observation");
    let status = public_status(&state, sandbox_id).await;
    assert_eq!(
        status.endpoint_statuses[0].last_result,
        EndpointResult::HttpResponseReceived as i32
    );
}

#[tokio::test]
async fn configuration_confirmation_does_not_read_mutable_provider_catalog() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let sandbox_id = "endpoint-policy-catalog-snapshot";
    let (state, report) = sandbox_with_accepted_endpoint_result(sandbox_id).await;
    let policy = stored_sandbox(&state, sandbox_id)
        .await
        .spec
        .expect("sandbox spec")
        .policy
        .expect("sandbox policy");
    state
        .store
        .put_policy_revision(
            "same-policy-new-revision",
            sandbox_id,
            "default",
            2,
            &policy.encode_to_vec(),
            &report.policy_hash,
        )
        .await
        .expect("store equivalent policy revision");
    let fetch_count = Arc::new(AtomicUsize::new(0));
    let mut state = Arc::into_inner(state).expect("uniquely owned test state");
    let mut profile_a = openshell_providers::builtin_profiles()
        .iter()
        .find(|profile| profile.id == "github")
        .expect("valid built-in provider profile")
        .to_proto();
    profile_a.id = "snapshot-provider".to_string();
    profile_a.display_name = "catalog-a".to_string();
    let mut profile_b = profile_a.clone();
    profile_b.display_name = "catalog-b".to_string();
    state.provider_profile_sources =
        crate::provider_profile_sources::ProviderProfileSources::from_test_snapshot_sequence(
            vec![
                ("catalog-a".to_string(), vec![profile_a]),
                ("catalog-b".to_string(), vec![profile_b]),
            ],
            Arc::clone(&fetch_count),
        );
    let state = Arc::new(state);
    let before = public_status(&state, sandbox_id).await;
    let (admission, _) = issue_configuration(&state, sandbox_id).await;
    assert_eq!(admission.policy_version, 2);
    let issued_fetch_count = fetch_count.load(Ordering::SeqCst);
    assert_eq!(issued_fetch_count, 1);

    confirm_configuration(&state, sandbox_id, admission).await;

    assert_eq!(fetch_count.load(Ordering::SeqCst), issued_fetch_count);
    let after = public_status(&state, sandbox_id).await;
    assert_eq!(after.current_policy_version, 2);
    assert_eq!(after.endpoint_statuses, before.endpoint_statuses);
    assert_eq!(after.phase, before.phase);
    assert_same_conditions(&after.conditions, &before.conditions);
}

#[tokio::test]
async fn loaded_policy_hash_cycle_resets_endpoint_evidence() {
    let sandbox_id = "endpoint-policy-hash-cycle";
    let (state, report) = sandbox_with_accepted_endpoint_result(sandbox_id).await;
    let sandbox = stored_sandbox(&state, sandbox_id).await;
    let original_policy = sandbox
        .spec
        .expect("sandbox spec")
        .policy
        .expect("sandbox policy");
    let original_status = public_status(&state, sandbox_id).await;
    let mut changed_policy = original_policy.clone();
    changed_policy
        .network_policies
        .get_mut("mcp")
        .expect("MCP rule")
        .endpoints[0]
        .rules[0]
        .allow
        .as_mut()
        .expect("MCP allow rule")
        .method = "tools/call".to_string();

    // A changed permission resets evidence even when the public endpoint address
    // stays the same. Returning to the old hash cannot revive its old cursor.
    for (policy, version) in [(changed_policy, 2), (original_policy, 3)] {
        let revision = handle_update_config(
            &state,
            authed_request(UpdateConfigRequest {
                name: sandbox_id.to_string(),
                policy: Some(policy),
                workspace_scope: Some(workspace_selector("default")),
                ..Default::default()
            }),
        )
        .await
        .expect("update policy permission")
        .into_inner();
        assert_eq!(revision.version, version);
        if version == 2 {
            assert_ne!(revision.policy_hash, report.policy_hash);
        } else {
            assert_eq!(revision.policy_hash, report.policy_hash);
        }
        activate_policy_configuration(&state, sandbox_id, version).await;
        let status = public_status(&state, sandbox_id).await;
        assert_eq!(status.current_policy_version, version);
        assert_eq!(status.endpoint_statuses.len(), 1);
        assert_eq!(
            status.endpoint_statuses[0],
            EndpointStatus {
                last_result: EndpointResult::NoObservedExchange as i32,
                last_reported_at: String::new(),
                ..original_status.endpoint_statuses[0].clone()
            }
        );
        assert_eq!(status.phase, original_status.phase);
        assert_eq!(status.conditions, original_status.conditions);
    }

    let reset = stored_sandbox(&state, sandbox_id).await;
    handle_report_endpoint_status(&state, with_sandbox(Request::new(report), sandbox_id))
        .await
        .expect("acknowledge already committed endpoint report");
    assert_eq!(stored_sandbox(&state, sandbox_id).await, reset);
}

#[tokio::test]
async fn global_policy_update_waits_for_endpoint_report_guard() {
    let state = test_server_state().await;
    let policy = mcp_policy_with_versions(&["2025-11-25"]);
    let updates = [
        UpdateConfigRequest {
            policy: Some(policy),
            global: true,
            ..Default::default()
        },
        UpdateConfigRequest {
            setting_key: super::super::POLICY_SETTING_KEY.to_string(),
            delete_setting: true,
            global: true,
            ..Default::default()
        },
    ];

    for (index, update) in updates.into_iter().enumerate() {
        let before = load_global_settings(state.store.as_ref())
            .await
            .expect("read settings before update");
        let guard = state.compute.sandbox_sync_guard().await;
        let mut pending = Box::pin(handle_update_config(&state, authed_request(update)));

        // Poll the actual writer while an endpoint report owns the mutation
        // boundary. Both replacing and deleting global policy must wait.
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(100), pending.as_mut()).await;
        assert!(
            result.is_err(),
            "global policy update committed while endpoint report guard was held: {result:?}"
        );
        let during = load_global_settings(state.store.as_ref())
            .await
            .expect("read settings while writer waits");
        assert_eq!(during.revision, before.revision);
        assert_eq!(during.settings, before.settings);

        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .expect("global policy update completes after guard release")
            .expect("global policy update succeeds");
        let after = load_global_settings(state.store.as_ref())
            .await
            .expect("read updated settings");
        assert_eq!(
            decode_policy_from_global_settings(&after)
                .expect("decode global policy")
                .is_some(),
            index == 0
        );
    }
}

#[test]
fn expected_endpoint_statuses_canonicalize_identity_and_distinguish_paths() {
    let policy = ProtoSandboxPolicy {
        network_policies: HashMap::from([(
            "mcp".to_string(),
            NetworkPolicyRule {
                endpoints: vec![
                    NetworkEndpoint {
                        host: "API.Example.COM".to_string(),
                        ports: vec![443, 443],
                        path: "**".to_string(),
                        protocol: " MCP ".to_string(),
                        ..Default::default()
                    },
                    NetworkEndpoint {
                        host: "api.example.com".to_string(),
                        port: 443,
                        path: "/**".to_string(),
                        protocol: "mcp".to_string(),
                        provider_credentialed: true,
                        ..Default::default()
                    },
                    NetworkEndpoint {
                        host: "api.example.com".to_string(),
                        port: 443,
                        path: "/mcp/private/**".to_string(),
                        protocol: "mcp".to_string(),
                        ..Default::default()
                    },
                    NetworkEndpoint {
                        host: "api.example.com".to_string(),
                        port: 443,
                        path: "/ignored".to_string(),
                        protocol: "rest".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };

    let endpoints = expected_endpoint_statuses(&policy);

    assert_eq!(endpoints.len(), 2);
    let root_endpoint_id = endpoint_id(&policy.network_policies["mcp"].endpoints[0]);
    let private_endpoint_id = endpoint_id(&policy.network_policies["mcp"].endpoints[2]);
    assert_ne!(root_endpoint_id, private_endpoint_id);
    assert_eq!(
        endpoints[&root_endpoint_id],
        ExpectedEndpoint {
            provider_credentialed: true,
            status: test_initial_endpoint_status(&root_endpoint_id, "api.example.com", "/**"),
        }
    );
    assert_eq!(
        endpoints[&private_endpoint_id].status,
        test_initial_endpoint_status(&private_endpoint_id, "api.example.com", "/mcp/private/**")
    );
}

#[tokio::test]
async fn report_endpoint_status_rejects_stale_configuration_epoch() {
    let state = endpoint_server_state().await;
    let sandbox_id = "endpoint-stale";
    state
        .store
        .put_message(&test_sandbox(
            sandbox_id,
            "endpoint-stale",
            mcp_policy_with_versions(&["2025-11-25"]),
            Vec::new(),
        ))
        .await
        .expect("store sandbox");
    register_configuration_runtime(&state, sandbox_id).await;
    let (admission, config) = issue_configuration(&state, sandbox_id).await;
    confirm_configuration(&state, sandbox_id, admission).await;
    let before = stored_sandbox(&state, sandbox_id).await;
    let endpoint = &config
        .policy
        .as_ref()
        .expect("effective policy")
        .network_policies["mcp"]
        .endpoints[0];
    let observation = EndpointObservation {
        endpoint_id: endpoint_id(endpoint),
        result: EndpointResult::NoObservedExchange as i32,
    };
    let (session_tx, _session_rx) = tokio::sync::mpsc::channel(1);
    let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();
    state.supervisor_sessions.register(
        sandbox_id.to_string(),
        "session-current".to_string(),
        session_tx,
        shutdown_tx,
    );
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority(sandbox_id, "session-current")
    );

    for request in [
        ReportEndpointStatusRequest {
            sandbox_id: sandbox_id.to_string(),
            policy_hash: format!("stale-{}", config.policy_hash),
            provider_env_revision: config.provider_env_revision,
            observations: vec![observation.clone()],
            observed_endpoint_ids: Vec::new(),
            supervisor_session_id: "session-current".to_string(),
            report_sequence: 1,
        },
        ReportEndpointStatusRequest {
            sandbox_id: sandbox_id.to_string(),
            policy_hash: config.policy_hash.clone(),
            provider_env_revision: config.provider_env_revision.wrapping_add(1),
            observations: vec![observation.clone()],
            observed_endpoint_ids: Vec::new(),
            supervisor_session_id: "session-current".to_string(),
            report_sequence: 1,
        },
    ] {
        let error =
            handle_report_endpoint_status(&state, with_sandbox(Request::new(request), sandbox_id))
                .await
                .expect_err("stale endpoint status must be rejected");
        assert_eq!(error.code(), Code::FailedPrecondition);
    }

    assert_eq!(stored_sandbox(&state, sandbox_id).await, before);
    assert!(
        state
            .supervisor_sessions
            .endpoint_report_cursor(sandbox_id, "session-current")
            .is_none()
    );
}

#[test]
fn endpoint_snapshot_rejects_credential_failure_for_uncredentialed_path() {
    let expected = BTreeMap::from([(
        "endpoint:v1:public".to_string(),
        ExpectedEndpoint {
            provider_credentialed: false,
            status: test_initial_endpoint_status(
                "endpoint:v1:public",
                "api.example.com",
                "/mcp/public/**",
            ),
        },
    )]);
    let reported = vec![EndpointObservation {
        endpoint_id: "endpoint:v1:public".to_string(),
        result: EndpointResult::CredentialUnavailable as i32,
    }];
    let error = validate_endpoint_snapshot(&reported, &[], &expected)
        .expect_err("uncredentialed endpoint cannot report credential failure");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(
        error.message(),
        "credential-unavailable requires a credentialed tool server endpoint"
    );
}

#[test]
fn endpoint_results_preserve_address_and_lifecycle_through_failure_recovery_and_reset() {
    let mut sandbox = test_sandbox(
        "sandbox-id",
        "sandbox-name",
        ProtoSandboxPolicy::default(),
        Vec::new(),
    );
    sandbox.status = Some(SandboxStatus {
        sandbox_name: "sandbox-name".to_string(),
        phase: SandboxPhase::Ready as i32,
        conditions: vec![ready_condition()],
        endpoint_statuses: vec![test_initial_endpoint_status(
            "obsolete",
            "retired.example.com",
            "/old",
        )],
        ..Default::default()
    });
    let initial = test_initial_endpoint_status("current", "api.example.com", "/mcp/private/**");
    for (result, time) in [
        (EndpointResult::TransportFailed, "2026-09-05T01:00:00.000Z"),
        (
            EndpointResult::HttpResponseReceived,
            "2026-09-05T02:00:00.000Z",
        ),
        (
            EndpointResult::NoObservedExchange,
            "2026-09-05T03:00:00.000Z",
        ),
    ] {
        let reports = BTreeMap::from([(
            "current".to_string(),
            EndpointStatus {
                last_result: result as i32,
                ..initial.clone()
            },
        )]);
        let observed = if result == EndpointResult::NoObservedExchange {
            HashSet::new()
        } else {
            HashSet::from(["current".to_string()])
        };
        reconcile_endpoint_statuses(&mut sandbox, &reports, &observed, time);

        let status = sandbox.status.as_ref().expect("status remains present");
        assert_eq!(status.phase, SandboxPhase::Ready as i32);
        assert_eq!(status.conditions, vec![ready_condition()]);
        assert_eq!(
            status.endpoint_statuses,
            vec![EndpointStatus {
                last_result: result as i32,
                last_reported_at: if result == EndpointResult::NoObservedExchange {
                    String::new()
                } else {
                    time.to_string()
                },
                ..initial.clone()
            }]
        );
    }
}

#[test]
fn endpoint_reconciliation_advances_only_observed_endpoint_timestamp() {
    let mut sandbox = test_sandbox(
        "sandbox-id",
        "sandbox-name",
        ProtoSandboxPolicy::default(),
        Vec::new(),
    );
    let endpoint_a = EndpointStatus {
        last_result: EndpointResult::HttpResponseReceived as i32,
        last_reported_at: "2026-09-05T01:01:00.000Z".to_string(),
        ..test_initial_endpoint_status("a", "a.example.com", "/**")
    };
    let endpoint_b = EndpointStatus {
        last_result: EndpointResult::TransportFailed as i32,
        last_reported_at: "2026-09-05T01:11:00.000Z".to_string(),
        ..test_initial_endpoint_status("b", "b.example.com", "/**")
    };
    sandbox.status = Some(SandboxStatus {
        endpoint_statuses: vec![endpoint_a.clone(), endpoint_b.clone()],
        ..Default::default()
    });
    let reports = BTreeMap::from([
        ("a".to_string(), endpoint_a.clone()),
        ("b".to_string(), endpoint_b.clone()),
    ]);
    reconcile_endpoint_statuses(
        &mut sandbox,
        &reports,
        &HashSet::from(["a".to_string()]),
        "2026-09-05T02:00:00.000Z",
    );
    let status = sandbox.status.expect("status remains present");
    assert_eq!(
        status.endpoint_statuses,
        vec![
            EndpointStatus {
                last_reported_at: "2026-09-05T02:00:00.000Z".to_string(),
                ..endpoint_a
            },
            endpoint_b
        ]
    );
}

#[test]
fn endpoint_snapshot_requires_marker_for_new_observed_result() {
    let mut sandbox = test_sandbox(
        "sandbox-id",
        "sandbox-name",
        ProtoSandboxPolicy::default(),
        Vec::new(),
    );
    let endpoint = EndpointStatus {
        last_result: EndpointResult::HttpResponseReceived as i32,
        ..test_initial_endpoint_status("endpoint", "api.example.com", "/**")
    };
    let reports = BTreeMap::from([("endpoint".to_string(), endpoint)]);
    let error = validate_endpoint_observation_markers(&sandbox, &reports, &HashSet::new())
        .expect_err("a new result requires an observation marker");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(
        error.message(),
        "a new tool server endpoint result must be marked as observed"
    );
    let observed = HashSet::from(["endpoint".to_string()]);
    validate_endpoint_observation_markers(&sandbox, &reports, &observed)
        .expect("new evidence marked");
    reconcile_endpoint_statuses(
        &mut sandbox,
        &reports,
        &observed,
        "2026-09-05T01:00:00.000Z",
    );
    validate_endpoint_observation_markers(&sandbox, &reports, &HashSet::new())
        .expect("retained evidence");
    invalidate_endpoint_status_without_session(&mut sandbox);
    assert!(validate_endpoint_observation_markers(&sandbox, &reports, &HashSet::new()).is_err());
    reconcile_endpoint_statuses(
        &mut sandbox,
        &reports,
        &observed,
        "2026-09-05T02:00:00.000Z",
    );
    assert_eq!(
        sandbox.status.expect("status").endpoint_statuses[0].last_reported_at,
        "2026-09-05T02:00:00.000Z"
    );
}

#[test]
fn endpoint_reconciliation_initializes_status_name_and_unknown_result() {
    let mut sandbox = test_sandbox(
        "sandbox-id",
        "sandbox-name",
        ProtoSandboxPolicy::default(),
        Vec::new(),
    );
    sandbox.status = None;
    let expected_phase = sandbox.phase();
    let expected_policy_version = sandbox.current_policy_version();
    let endpoint = test_initial_endpoint_status("endpoint", "api.example.com", "/**");
    let reports = BTreeMap::from([("endpoint".to_string(), endpoint.clone())]);
    reconcile_endpoint_statuses(
        &mut sandbox,
        &reports,
        &HashSet::new(),
        "2026-09-05T04:00:00.000Z",
    );
    let status = sandbox.status.expect("status initialized");
    assert_eq!(status.endpoint_statuses, vec![endpoint]);
    assert_eq!(status.sandbox_name, "sandbox-name");
    assert_eq!(status.phase, expected_phase);
    assert_eq!(status.current_policy_version, expected_policy_version);
    assert!(status.conditions.is_empty());
}

#[tokio::test]
async fn startup_reconciliation_invalidates_status_from_previous_sessions() {
    let state = test_server_state().await;
    let sandbox_id = "endpoint-startup-invalidation";
    let mut sandbox = test_sandbox(
        sandbox_id,
        sandbox_id,
        mcp_policy_with_versions(&["2025-11-25"]),
        Vec::new(),
    );
    let initial = test_initial_endpoint_status("old-session", "api.example.com", "/mcp");
    sandbox.status = Some(SandboxStatus {
        sandbox_name: sandbox_id.to_string(),
        endpoint_statuses: vec![EndpointStatus {
            last_result: EndpointResult::HttpResponseReceived as i32,
            last_reported_at: "2026-09-05T01:01:00.000Z".to_string(),
            ..initial.clone()
        }],
        conditions: vec![ready_condition()],
        ..Default::default()
    });
    state
        .store
        .put_message(&sandbox)
        .await
        .expect("store prior session status");
    invalidate_endpoint_status_on_startup(&state)
        .await
        .expect("startup reconciliation");
    let status = stored_sandbox(&state, sandbox_id)
        .await
        .status
        .expect("status remains present");
    assert_eq!(status.endpoint_statuses, vec![initial]);
    assert_eq!(status.conditions, vec![ready_condition()]);
}

#[tokio::test]
async fn report_endpoint_status_is_session_bound_and_retry_idempotent() {
    let state = endpoint_server_state().await;
    let sandbox_id = "endpoint-session";
    let mut policy = mcp_policy_with_versions(&["2025-11-25"]);
    let endpoints = &mut policy
        .network_policies
        .get_mut("mcp")
        .expect("MCP rule")
        .endpoints;
    endpoints[0].path = "/mcp/observed/**".to_string();
    let mut unobserved = endpoints[0].clone();
    unobserved.path = "/mcp/unobserved/**".to_string();
    endpoints.push(unobserved);
    let mut sandbox = test_sandbox(sandbox_id, sandbox_id, policy, Vec::new());
    sandbox.status = Some(SandboxStatus {
        sandbox_name: sandbox_id.to_string(),
        phase: SandboxPhase::Ready as i32,
        conditions: vec![ready_condition()],
        ..Default::default()
    });
    state
        .store
        .put_message(&sandbox)
        .await
        .expect("store sandbox");
    register_configuration_runtime(&state, sandbox_id).await;
    let (admission, config) = issue_configuration(&state, sandbox_id).await;
    confirm_configuration(&state, sandbox_id, admission).await;
    let confirmed_conditions = public_status(&state, sandbox_id).await.conditions;
    let endpoints = &config.policy.as_ref().expect("policy").network_policies["mcp"].endpoints;
    let observed_id = endpoint_id(&endpoints[0]);
    let unobserved_id = endpoint_id(&endpoints[1]);
    assert_ne!(observed_id, unobserved_id);
    let mut initial = endpoints
        .iter()
        .map(initial_endpoint_status)
        .collect::<Vec<_>>();
    initial.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));

    register_session(&state, sandbox_id, "session-a");
    reset_endpoint_status_for_supervisor_session(&state, sandbox_id, "session-a")
        .await
        .expect("session reset");
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority(sandbox_id, "session-a")
    );
    let initial_status = public_status(&state, sandbox_id).await;
    assert_eq!(initial_status.endpoint_statuses, initial);
    assert_eq!(initial_status.conditions, confirmed_conditions);

    let report = ReportEndpointStatusRequest {
        sandbox_id: sandbox_id.to_string(),
        policy_hash: config.policy_hash,
        provider_env_revision: config.provider_env_revision,
        observations: vec![
            EndpointObservation {
                endpoint_id: observed_id.clone(),
                result: EndpointResult::TransportFailed as i32,
            },
            EndpointObservation {
                endpoint_id: unobserved_id,
                result: EndpointResult::NoObservedExchange as i32,
            },
        ],
        observed_endpoint_ids: vec![observed_id.clone()],
        supervisor_session_id: "session-a".to_string(),
        report_sequence: 1,
    };
    handle_report_endpoint_status(
        &state,
        with_sandbox(Request::new(report.clone()), sandbox_id),
    )
    .await
    .expect("first report");
    let first = stored_sandbox(&state, sandbox_id).await;
    let public = public_status(&state, sandbox_id).await;
    assert_eq!(public.phase, SandboxPhase::Ready as i32);
    assert_eq!(public.conditions, confirmed_conditions);
    let mut expected = initial.clone();
    let observed = expected
        .iter_mut()
        .find(|endpoint| endpoint.endpoint_id == observed_id)
        .expect("observed endpoint");
    observed.last_result = EndpointResult::TransportFailed as i32;
    observed.last_reported_at.clone_from(
        &public
            .endpoint_statuses
            .iter()
            .find(|endpoint| endpoint.endpoint_id == observed_id)
            .expect("public endpoint")
            .last_reported_at,
    );
    assert!(!observed.last_reported_at.is_empty());
    assert_eq!(public.endpoint_statuses, expected);

    handle_report_endpoint_status(
        &state,
        with_sandbox(Request::new(report.clone()), sandbox_id),
    )
    .await
    .expect("identical retry");
    assert_eq!(stored_sandbox(&state, sandbox_id).await, first);
    let mut conflicting_retry = report.clone();
    conflicting_retry.observations[0].result = EndpointResult::UpstreamRejected as i32;
    let error = handle_report_endpoint_status(
        &state,
        with_sandbox(Request::new(conflicting_retry), sandbox_id),
    )
    .await
    .expect_err("sequence body is immutable");
    assert_eq!(error.code(), Code::InvalidArgument);

    let mut newer = report.clone();
    newer.report_sequence = 9;
    newer.observations[0].result = EndpointResult::HttpResponseReceived as i32;
    handle_report_endpoint_status(
        &state,
        with_sandbox(Request::new(newer.clone()), sandbox_id),
    )
    .await
    .expect("new complete snapshot with a sequence gap");
    let newest = stored_sandbox(&state, sandbox_id).await;
    let recovered = public_status(&state, sandbox_id).await;
    assert_eq!(recovered.phase, SandboxPhase::Ready as i32);
    assert_eq!(recovered.conditions, confirmed_conditions);
    assert_eq!(
        recovered
            .endpoint_statuses
            .iter()
            .find(|endpoint| endpoint.endpoint_id == observed_id)
            .expect("recovered endpoint")
            .last_result,
        EndpointResult::HttpResponseReceived as i32
    );
    let error = handle_report_endpoint_status(
        &state,
        with_sandbox(Request::new(report.clone()), sandbox_id),
    )
    .await
    .expect_err("older sequence rejected");
    assert_eq!(error.code(), Code::FailedPrecondition);
    handle_report_endpoint_status(&state, with_sandbox(Request::new(newer), sandbox_id))
        .await
        .expect("newest identical retry");
    assert_eq!(stored_sandbox(&state, sandbox_id).await, newest);

    assert!(
        state
            .supervisor_sessions
            .remove_if_current(sandbox_id, "session-a")
            .is_some()
    );
    reset_endpoint_status_after_supervisor_disconnect(&state, sandbox_id)
        .await
        .expect("disconnect reset");
    let disconnected = public_status(&state, sandbox_id).await;
    assert_eq!(disconnected.endpoint_statuses, initial);
    assert_eq!(disconnected.conditions, confirmed_conditions);
    register_session(&state, sandbox_id, "session-b");
    reset_endpoint_status_for_supervisor_session(&state, sandbox_id, "session-b")
        .await
        .expect("replacement reset");
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority(sandbox_id, "session-b")
    );
    let error =
        handle_report_endpoint_status(&state, with_sandbox(Request::new(report), sandbox_id))
            .await
            .expect_err("superseded session rejected");
    assert_eq!(error.code(), Code::PermissionDenied);
    assert_eq!(
        public_status(&state, sandbox_id).await.endpoint_statuses,
        initial
    );
}

#[tokio::test]
async fn confirmed_configuration_and_endpoint_inventory_commit_atomically() {
    let state = endpoint_server_state().await;
    let sandbox_id = "endpoint-policy-activation";
    let mut old_policy = mcp_policy_with_versions(&["2025-11-25"]);
    old_policy
        .network_policies
        .get_mut("mcp")
        .expect("MCP policy")
        .endpoints[0]
        .host = "retired.example.com".to_string();
    let initial_old = initial_endpoint_status(&old_policy.network_policies["mcp"].endpoints[0]);
    let mut sandbox = test_sandbox(sandbox_id, sandbox_id, old_policy, Vec::new());
    sandbox.status = Some(SandboxStatus {
        sandbox_name: sandbox_id.to_string(),
        endpoint_statuses: vec![EndpointStatus {
            last_result: EndpointResult::HttpResponseReceived as i32,
            last_reported_at: "2026-09-05T01:00:00.000Z".to_string(),
            ..initial_old
        }],
        ..Default::default()
    });
    state
        .store
        .put_message(&sandbox)
        .await
        .expect("store sandbox");
    register_configuration_runtime(&state, sandbox_id).await;
    let active_policy = mcp_policy_with_versions(&["2025-11-25"]);
    let policy_hash = deterministic_policy_hash(&active_policy);
    let initial_active =
        initial_endpoint_status(&active_policy.network_policies["mcp"].endpoints[0]);
    state
        .store
        .put_policy_revision(
            "active-revision",
            sandbox_id,
            "default",
            1,
            &active_policy.encode_to_vec(),
            &policy_hash,
        )
        .await
        .expect("store active revision");
    let (active_admission, _) = issue_configuration(&state, sandbox_id).await;
    assert_eq!(active_admission.policy_version, 1);

    let mut pending_policy = active_policy;
    pending_policy
        .network_policies
        .get_mut("mcp")
        .expect("MCP policy")
        .endpoints[0]
        .host = "pending.example.com".to_string();
    let initial_pending =
        initial_endpoint_status(&pending_policy.network_policies["mcp"].endpoints[0]);
    state
        .store
        .put_policy_revision(
            "pending-revision",
            sandbox_id,
            "default",
            2,
            &pending_policy.encode_to_vec(),
            &deterministic_policy_hash(&pending_policy),
        )
        .await
        .expect("store pending revision");

    // Confirmation commits the inventory in the issued receipt, even when a
    // newer policy row exists but has not been delivered to this runtime.
    confirm_configuration(&state, sandbox_id, active_admission).await;
    let stored = stored_sandbox(&state, sandbox_id).await;
    assert_eq!(stored.current_policy_version(), 1);
    let context = active_endpoint_context(&stored);
    assert_eq!(context.policy_hash, policy_hash);
    assert_eq!(
        context.endpoints.keys().cloned().collect::<Vec<_>>(),
        vec![initial_active.endpoint_id.clone()]
    );
    let status = stored.status.expect("status");
    assert_eq!(status.endpoint_statuses, vec![initial_active.clone()]);

    register_session(&state, sandbox_id, "active-session");
    reset_endpoint_status_for_supervisor_session(&state, sandbox_id, "active-session")
        .await
        .expect("reset active endpoints");
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority(sandbox_id, "active-session")
    );
    assert_eq!(
        public_status(&state, sandbox_id).await.endpoint_statuses,
        vec![initial_active.clone()]
    );
    handle_report_endpoint_status(
        &state,
        with_sandbox(
            Request::new(ReportEndpointStatusRequest {
                sandbox_id: sandbox_id.to_string(),
                policy_hash: context.policy_hash,
                provider_env_revision: context.provider_env_revision,
                observations: vec![EndpointObservation {
                    endpoint_id: initial_active.endpoint_id.clone(),
                    result: EndpointResult::HttpResponseReceived as i32,
                }],
                observed_endpoint_ids: vec![initial_active.endpoint_id.clone()],
                supervisor_session_id: "active-session".to_string(),
                report_sequence: 1,
            }),
            sandbox_id,
        ),
    )
    .await
    .expect("accepted inventory remains authoritative while the next policy is pending");
    let reported = public_status(&state, sandbox_id).await;
    assert_eq!(reported.endpoint_statuses.len(), 1);
    let endpoint = &reported.endpoint_statuses[0];
    assert!(!endpoint.last_reported_at.is_empty());
    assert_eq!(
        endpoint,
        &EndpointStatus {
            last_result: EndpointResult::HttpResponseReceived as i32,
            last_reported_at: endpoint.last_reported_at.clone(),
            ..initial_active
        }
    );

    let (mut pending_admission, _) = issue_configuration(&state, sandbox_id).await;
    assert_eq!(pending_admission.policy_version, 2);
    assert_eq!(
        public_status(&state, sandbox_id).await.endpoint_statuses,
        reported.endpoint_statuses
    );
    accept_held_configuration(&state, sandbox_id, &mut pending_admission).await;
    let held = public_status(&state, sandbox_id).await;
    assert_eq!(held.current_policy_version, 1);
    assert_eq!(held.endpoint_statuses, reported.endpoint_statuses);
    confirm_configuration(&state, sandbox_id, pending_admission).await;
    let replaced = public_status(&state, sandbox_id).await;
    assert_eq!(replaced.current_policy_version, 2);
    assert_eq!(replaced.endpoint_statuses, vec![initial_pending]);

    let mut empty_policy = pending_policy;
    empty_policy.network_policies.clear();
    state
        .store
        .put_policy_revision(
            "empty-revision",
            sandbox_id,
            "default",
            3,
            &empty_policy.encode_to_vec(),
            &deterministic_policy_hash(&empty_policy),
        )
        .await
        .expect("store empty inventory policy");
    activate_policy_configuration(&state, sandbox_id, 3).await;
    let cleared = public_status(&state, sandbox_id).await;
    assert_eq!(cleared.current_policy_version, 3);
    assert!(cleared.endpoint_statuses.is_empty());
    assert_eq!(cleared.conditions, replaced.conditions);
    assert_eq!(cleared.phase, replaced.phase);
}
