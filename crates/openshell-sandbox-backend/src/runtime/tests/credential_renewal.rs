// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use tokio_stream::StreamExt as _;

#[derive(Clone)]
struct RenewingGrpcBoundary {
    inner: TestGrpcBoundary,
    expected_token: Arc<std::sync::RwLock<String>>,
    failures: Arc<std::sync::atomic::AtomicUsize>,
    failure_code: tonic::Code,
    response_override: Arc<std::sync::Mutex<Option<Response>>>,
}

#[tonic::async_trait]
impl IsolationBoundary for RenewingGrpcBoundary {
    type ExchangeStream = TestGrpcStream;
    type MediateStream = TestGrpcStream;

    async fn exchange(
        &self,
        request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
    ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
        if self
            .failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(tonic::Status::new(
                self.failure_code,
                "injected boundary failure",
            ));
        }
        let mut inner = self.inner.clone();
        inner.expected_token = self.expected_token.read().unwrap().clone();
        inner.response_override = self.response_override.lock().unwrap().clone();
        inner.exchange(request).await
    }

    async fn mediate(
        &self,
        request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
    ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
        self.exchange(request).await
    }
}

async fn renewing_boundary_client(
    failure_code: tonic::Code,
) -> (
    Arc<BoundaryClient>,
    RenewingGrpcBoundary,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let certificate = test_certificate();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = RenewingGrpcBoundary {
        inner: TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            response_override: None,
            response_permits: None,
        },
        expected_token: Arc::new(std::sync::RwLock::new("a".repeat(32))),
        failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        failure_code,
        response_override: Arc::new(std::sync::Mutex::new(None)),
    };
    let server_service = service.clone();
    let server_accepted = accepted.clone();
    let server = tokio::spawn(async move {
        // Aborting the fixture also closes every child TLS connection.
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(certificate.server_config.clone())
                .accept(stream)
                .await
                .unwrap();
            server_accepted.fetch_add(1, Ordering::AcqRel);
            let service = server_service.clone();
            connections.spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(IsolationBoundaryServer::new(service))
                    .serve_with_incoming(
                        tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(Box::new(stream)))])
                            .chain(tokio_stream::pending()),
                    )
                    .await
                    .unwrap();
            });
        }
    });
    let client = Arc::new(BoundaryClient::new(
        tls_runtime_descriptor(address, certificate.client_tls),
        test_bearer(&"a".repeat(32)),
        test_supervisor_instance_id(),
    ));
    client
        .call_idempotent(Request::Attach {
            supervisor_instance_id: client.supervisor_instance_id,
            registration_grant: "test-grant".to_string(),
            registration_revision: 1,
            policy: Box::new(SandboxPolicyWire::from(sandbox().policy)),
            resource_claims: std::collections::BTreeMap::new(),
        })
        .await
        .unwrap();
    client.call_idempotent(Request::Confirm).await.unwrap();
    client.activation.lock().unwrap().identity = Some(test_activation().identity);
    (client, service, accepted, server)
}

#[tokio::test]
async fn same_epoch_renewal_reauthenticates_without_closing_pending_stream() {
    let (client, service, accepted, server) =
        renewing_boundary_client(tonic::Code::Unavailable).await;
    let active = test_activation();
    client.publish_activation(0, &active).unwrap();
    // Authenticate a stream that remains open across both bearer renewals.
    let mut pending = client
        .open_grpc_stream(GrpcStreamKind::Exchange)
        .await
        .unwrap();
    for (index, token) in ["b".repeat(32), "c".repeat(32)].into_iter().enumerate() {
        *service.expected_token.write().unwrap() = token.clone();
        client
            .sandbox_bearer
            .update(
                SecretJwt::parse(token).unwrap(),
                i64::MAX,
                openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            )
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            client.ensure_current_credential_connection(),
        )
        .await
        .expect("renewal must complete")
        .unwrap();
        assert_eq!(
            service.inner.requests.load(Ordering::Acquire),
            3 + index,
            "each renewed bearer must authenticate a Confirm RPC"
        );
        assert_eq!(
            accepted.load(Ordering::Acquire),
            1,
            "renewal must reuse the physical connection"
        );
        assert_eq!(client.active_configuration(1).unwrap(), active);
        assert_eq!(client.configuration_attempt_epoch(0).unwrap(), 0);
        assert!(*client.readiness().borrow());
    }
    let request = BoundaryClient::prepare_request(Request::Wait {
        process_id: "pending".into(),
    })
    .unwrap();
    pending
        .write_all(&encode_frame(&request).unwrap())
        .await
        .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        crate::boundary_protocol::read_frame_async::<_, ResponseEnvelope>(&mut pending),
    )
    .await
    .expect("pending stream must survive renewal")
    .unwrap();
    assert!(matches!(response.response, Response::Exited { .. }));
    server.abort();
}

#[tokio::test]
async fn failed_renewal_keeps_authenticated_fingerprint_and_retries() {
    for failure_code in [tonic::Code::Unavailable, tonic::Code::PermissionDenied] {
        let (client, service, accepted, server) = renewing_boundary_client(failure_code).await;
        let original = client.grpc_channel.lock().await.clone().unwrap();
        let renewed_token = "b".repeat(32);
        *service.expected_token.write().unwrap() = renewed_token.clone();
        client
            .sandbox_bearer
            .update(
                SecretJwt::parse(renewed_token).unwrap(),
                i64::MAX,
                openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            )
            .unwrap();

        // A refused confirmation must remain visible to the monitor, including
        // an authentication denial; no fingerprint may suppress its next check.
        service.failures.store(1, Ordering::Release);
        let result = client.ensure_current_credential_connection().await;
        match failure_code {
            tonic::Code::PermissionDenied => {
                assert!(matches!(result, Err(BackendError::Denied(_))));
            }
            _ => assert!(matches!(result, Err(BackendError::Unavailable(_)))),
        }
        let failed = client.grpc_channel.lock().await.clone().unwrap();
        assert_eq!(failed.bearer_fingerprint, original.bearer_fingerprint);
        assert_eq!(failed.generation, original.generation);
        assert_eq!(service.inner.requests.load(Ordering::Acquire), 2);

        client.ensure_current_credential_connection().await.unwrap();
        let confirmed = client.grpc_channel.lock().await.clone().unwrap();
        assert_ne!(confirmed.bearer_fingerprint, original.bearer_fingerprint);
        assert_eq!(confirmed.generation, original.generation);
        assert_eq!(service.inner.requests.load(Ordering::Acquire), 3);
        assert_eq!(accepted.load(Ordering::Acquire), 1);

        // The confirmed credential needs no further RPC until it changes.
        client.ensure_current_credential_connection().await.unwrap();
        assert_eq!(service.inner.requests.load(Ordering::Acquire), 3);
        server.abort();
    }
}

#[tokio::test]
async fn confirmation_authenticates_captured_bearer_after_slot_changes() {
    let (client, service, accepted, server) =
        renewing_boundary_client(tonic::Code::Unavailable).await;
    let credential = BoundaryCredential::capture(&client.sandbox_bearer).unwrap();
    // Race a later slot update with an already captured confirmation. The peer
    // still expects the captured token; rereading the slot would be rejected.
    client
        .sandbox_bearer
        .update(
            SecretJwt::parse("b".repeat(32)).unwrap(),
            i64::MAX,
            openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
        )
        .unwrap();
    let channel = client
        .grpc_channel
        .lock()
        .await
        .as_ref()
        .unwrap()
        .channel
        .clone();
    let envelope = BoundaryClient::prepare_request(Request::Confirm).unwrap();
    let response = client
        .exchange_on_channel(channel, &envelope, &credential)
        .await
        .unwrap();
    assert!(matches!(response, Response::Confirmed { .. }));
    assert_eq!(service.inner.requests.load(Ordering::Acquire), 3);
    assert_eq!(accepted.load(Ordering::Acquire), 1);
    server.abort();
}

#[tokio::test]
async fn attachment_replay_uses_one_captured_bearer_after_slot_changes() {
    let (client, service, accepted, server) =
        renewing_boundary_client(tonic::Code::Unavailable).await;
    let credential = BoundaryCredential::capture(&client.sandbox_bearer).unwrap();
    let attach = client.attach_request.lock().unwrap().clone().unwrap();
    let confirm = client.confirm_request.lock().unwrap().clone().unwrap();
    let channel = client
        .grpc_channel
        .lock()
        .await
        .as_ref()
        .unwrap()
        .channel
        .clone();
    // The peer still accepts only the captured bearer, so rereading the slot
    // during discovery, attachment or confirmation must fail this replay.
    client
        .sandbox_bearer
        .update(
            SecretJwt::parse("b".repeat(32)).unwrap(),
            i64::MAX,
            openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
        )
        .unwrap();
    client
        .replay_attachment(channel, &attach, Some(&confirm), &credential)
        .await
        .unwrap();
    assert_eq!(service.inner.requests.load(Ordering::Acquire), 5);
    assert_eq!(accepted.load(Ordering::Acquire), 1);
    server.abort();
}

#[tokio::test]
async fn replacement_connections_hold_activation_without_cancelling_pending_configuration() {
    for transport_recovery in [false, true] {
        let (client, service, accepted, server) =
            renewing_boundary_client(tonic::Code::Unavailable).await;
        client.publish_activation(0, &test_activation()).unwrap();
        let original = client.grpc_channel.lock().await.clone().unwrap();
        let renewed_token = "b".repeat(32);
        *service.expected_token.write().unwrap() = renewed_token.clone();
        let credential_epoch =
            openshell_core::jwt::CredentialEpoch::new(if transport_recovery { 1 } else { 2 })
                .unwrap();
        client
            .sandbox_bearer
            .update(
                SecretJwt::parse(renewed_token).unwrap(),
                i64::MAX,
                credential_epoch,
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            if transport_recovery {
                client.recover_after_unavailable().await
            } else {
                client.ensure_current_credential_connection().await
            }
        })
        .await
        .expect("authenticated replacement must complete")
        .unwrap();

        let replaced = client.grpc_channel.lock().await.clone().unwrap();
        assert_eq!(replaced.credential_epoch, credential_epoch);
        assert_eq!(
            replaced.bearer_fingerprint,
            BoundaryCredential::capture(&client.sandbox_bearer)
                .unwrap()
                .fingerprint
        );
        assert_ne!(replaced.generation, original.generation);
        assert_eq!(accepted.load(Ordering::Acquire), 2);
        assert_eq!(service.inner.requests.load(Ordering::Acquire), 5);
        assert!(!*client.readiness().borrow());
        assert!(client.active_configuration(1).is_err());
        // Transport repair preserves the pending transaction, but its old
        // acknowledgement cannot release execution on the replacement channel.
        assert_eq!(client.configuration_attempt_epoch(0).unwrap(), 1);
        assert!(client.publish_activation(0, &test_activation()).is_err());
        server.abort();
    }
}

#[tokio::test]
async fn same_epoch_renewal_rejects_changed_resource_evidence() {
    let (client, service, accepted, server) =
        renewing_boundary_client(tonic::Code::Unavailable).await;
    client.publish_activation(0, &test_activation()).unwrap();
    let original = client.grpc_channel.lock().await.clone().unwrap();
    let renewed_token = "b".repeat(32);
    *service.expected_token.write().unwrap() = renewed_token.clone();
    client
        .sandbox_bearer
        .update(
            SecretJwt::parse(renewed_token).unwrap(),
            i64::MAX,
            openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
        )
        .unwrap();
    let mut evidence = test_confirmation_evidence();
    evidence
        .resource_claims
        .insert("unexpected-device".into(), "changed".into());
    *service.response_override.lock().unwrap() = Some(Response::Confirmed {
        evidence: Box::new(evidence),
    });

    assert!(matches!(
        client.ensure_current_credential_connection().await,
        Err(BackendError::Confirm(_))
    ));
    let refused = client.grpc_channel.lock().await.clone().unwrap();
    assert_eq!(refused.generation, original.generation);
    assert_eq!(refused.bearer_fingerprint, original.bearer_fingerprint);
    assert_eq!(client.active_configuration(1).unwrap(), test_activation());
    assert_eq!(client.configuration_attempt_epoch(0).unwrap(), 0);

    // A rejected acknowledgement never suppresses a later authenticated retry.
    *service.response_override.lock().unwrap() = None;
    client.ensure_current_credential_connection().await.unwrap();
    assert_ne!(
        client
            .grpc_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .bearer_fingerprint,
        original.bearer_fingerprint
    );
    assert_eq!(service.inner.requests.load(Ordering::Acquire), 4);
    assert_eq!(accepted.load(Ordering::Acquire), 1);
    server.abort();
}
