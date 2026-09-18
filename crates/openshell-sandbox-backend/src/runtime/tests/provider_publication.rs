// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::provider_credentials::ProviderCredentialState;

async fn acknowledged_exec(
    credentials: ProviderCredentialState,
    generation: u64,
    permits: Option<Arc<tokio::sync::Semaphore>>,
) -> (
    RemoteExec,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let current = credentials.snapshot();
    let mut activation = test_activation();
    activation.configuration.provider_env_revision = current.revision;
    activation.provider_env_installation_id = current.installation_id.clone();
    activation.publication_generation = generation;
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (client, server) = configuration_client_with_service(TestGrpcBoundary {
        wait_for_half_close: false,
        expected_token: "a".repeat(32),
        requests: requests.clone(),
        mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        mediation_ready: false,
        response_override: Some(Response::ConfigurationSnapshot {
            snapshot: BoundaryConfigurationSnapshot {
                identity: activation.identity.clone(),
                installed: Some(activation.configuration.clone()),
                publication_generation: generation,
                provider_env_installation_id: Some(current.installation_id.clone()),
                active: true,
            },
        }),
        response_permits: permits,
    })
    .await;
    client.publish_activation(0, &activation).unwrap();
    (
        RemoteExec {
            client,
            provider_credentials: credentials,
        },
        requests,
        server,
    )
}

#[tokio::test]
async fn reconstructed_backend_resumes_the_running_boundary_publication_generation() {
    let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
    let (original, requests, server) = acknowledged_exec(credentials.clone(), 9, None).await;
    let reconstructed = RemoteExec {
        client: original.client.clone(),
        provider_credentials: credentials.clone(),
    };
    let installed = reconstructed
        .synchronize_provider_environment()
        .await
        .unwrap();
    assert_eq!(
        installed.installation_id,
        credentials.snapshot().installation_id
    );
    assert_eq!(installed.revision, 6);
    assert_eq!(installed.session_id, test_session_id());
    assert_eq!(
        original
            .client
            .active_configuration(6)
            .unwrap()
            .publication_generation,
        9
    );
    assert_eq!(
        requests.load(Ordering::Acquire),
        1,
        "acknowledgement only reads the accepted installation"
    );
    server.abort();
}

#[tokio::test]
async fn provider_environment_acknowledges_the_exact_local_snapshot_and_checked_generation() {
    let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
    let (old, requests, old_server) = acknowledged_exec(credentials.clone(), 1, None).await;
    let empty = old.synchronize_provider_environment().await.unwrap();
    credentials.install_child_env_snapshot(6, HashMap::from([("TOKEN".into(), "restored".into())]));
    assert!(
        old.synchronize_provider_environment().await.is_err(),
        "same-revision repair requires its own activation"
    );
    assert_eq!(
        requests.load(Ordering::Acquire),
        1,
        "reporting must not independently publish a repair"
    );
    let (repaired, _, repaired_server) = acknowledged_exec(credentials.clone(), 2, None).await;
    let installed = repaired.synchronize_provider_environment().await.unwrap();
    assert_eq!(empty.revision, installed.revision);
    assert_ne!(empty.installation_id, installed.installation_id);
    assert_eq!(
        installed.installation_id,
        credentials.snapshot().installation_id
    );
    repaired.client.hold_activation(false);
    assert!(
        repaired.synchronize_provider_environment().await.is_err(),
        "recovery cannot renew evidence before fresh release"
    );
    old_server.abort();
    repaired_server.abort();
}

#[tokio::test]
async fn provider_acknowledgement_rejects_same_revision_repair_while_response_is_pending() {
    let credentials = ProviderCredentialState::from_child_env_snapshot(6, HashMap::new());
    let permits = Arc::new(tokio::sync::Semaphore::new(0));
    let (remote, requests, server) =
        acknowledged_exec(credentials.clone(), 1, Some(permits.clone())).await;
    let acknowledgement =
        tokio::spawn(async move { remote.synchronize_provider_environment().await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while requests.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    credentials.install_child_env_snapshot(6, HashMap::from([("TOKEN".into(), "repaired".into())]));
    permits.add_permits(1);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), acknowledgement)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    server.abort();
}
