// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use backend_setup::{BackendServices, BackendSetup, BuiltBackend, LaunchIdentity, PreparedBackend};
use openshell_core::proto::{
    GatewayMessage, GetSandboxConfigRequest, GetSandboxConfigResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse,
    ReportPolicyStatusRequest, ReportPolicyStatusResponse, ReportSandboxConfigurationRequest,
    ReportSandboxConfigurationResponse, SessionAccepted, SupervisorMessage, UpdateConfigRequest,
    UpdateConfigResponse, gateway_message, supervisor_message,
};
use openshell_isolation_interface::contract::{BackendError, ResolvedWorkloadIdentity};
use std::sync::atomic::Ordering;
use tonic::codegen::tokio_stream::{StreamExt as _, wrappers::TcpListenerStream};
use tonic::codegen::{Body, BoxFuture, BoxStream, Bytes, Service, StdError, http};

#[derive(Clone)]
struct PolicySyncCase {
    write: UpdateConfigResponse,
    created: bool,
    snapshot: GetSandboxConfigResponse,
}

#[derive(Clone, Default)]
struct LegacyReadyProbe {
    ready_event: Arc<tokio::sync::Notify>,
    premature_ready: Arc<AtomicBool>,
    discovered: Arc<AtomicBool>,
    policy_sync: Arc<std::sync::Mutex<Option<PolicySyncCase>>>,
    policy_reports: Arc<std::sync::Mutex<Vec<ReportPolicyStatusRequest>>>,
    attach_refusal:
        Arc<std::sync::Mutex<Option<(ReportSandboxConfigurationRequest, AttachPolicyRefusal)>>>,
}

#[derive(Clone)]
struct LegacyGateway {
    probe: LegacyReadyProbe,
}

impl tonic::server::NamedService for LegacyGateway {
    const NAME: &'static str = "openshell.v1.OpenShell";
}

struct LegacyConnect(LegacyReadyProbe);

impl tonic::server::StreamingService<SupervisorMessage> for LegacyConnect {
    type Response = GatewayMessage;
    type ResponseStream = BoxStream<GatewayMessage>;
    type Future = BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;

    fn call(
        &mut self,
        request: tonic::Request<tonic::Streaming<SupervisorMessage>>,
    ) -> Self::Future {
        let probe = self.0.clone();
        Box::pin(async move {
            let message = request
                .into_inner()
                .message()
                .await?
                .expect("supervisor hello");
            assert!(matches!(
                message.payload,
                Some(supervisor_message::Payload::Hello(_))
            ));

            // A pre-push gateway ignores workload_pending and records Ready
            // on connection. The restart's existing admission is accepted.
            probe.premature_ready.store(true, Ordering::SeqCst);
            probe.ready_event.notify_one();
            let accepted = GatewayMessage {
                payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                    session_id: "legacy-session".into(),
                    ..Default::default()
                })),
            };
            let stream = futures::stream::once(async move { Ok(accepted) })
                .chain(futures::stream::pending());
            let stream: Self::ResponseStream = Box::pin(stream);
            Ok(tonic::Response::new(stream))
        })
    }
}

struct FixedUnary<R>(R);

struct PolicyStatusRecorder(LegacyReadyProbe);

struct ConfigurationReportRecorder(LegacyReadyProbe);

impl tonic::server::UnaryService<ReportSandboxConfigurationRequest>
    for ConfigurationReportRecorder
{
    type Response = ReportSandboxConfigurationResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<ReportSandboxConfigurationRequest>) -> Self::Future {
        let probe = self.0.clone();
        Box::pin(async move {
            if let Some(reason) = AttachPolicyRefusal::from_metadata(request.metadata())? {
                *probe.attach_refusal.lock().unwrap() = Some((request.into_inner(), reason));
            }
            Ok(tonic::Response::new(ReportSandboxConfigurationResponse {}))
        })
    }
}

impl tonic::server::UnaryService<ReportPolicyStatusRequest> for PolicyStatusRecorder {
    type Response = ReportPolicyStatusResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<ReportPolicyStatusRequest>) -> Self::Future {
        self.0
            .policy_reports
            .lock()
            .unwrap()
            .push(request.into_inner());
        Box::pin(async { Ok(tonic::Response::new(ReportPolicyStatusResponse {})) })
    }
}

impl<Q, R> tonic::server::UnaryService<Q> for FixedUnary<R>
where
    Q: Send + 'static,
    R: Clone + Send + 'static,
{
    type Response = R;
    type Future = BoxFuture<tonic::Response<R>, tonic::Status>;

    fn call(&mut self, _request: tonic::Request<Q>) -> Self::Future {
        let response = self.0.clone();
        Box::pin(async move { Ok(tonic::Response::new(response)) })
    }
}

async fn legacy_unary<B, Q, R>(
    request: http::Request<B>,
    response: R,
) -> http::Response<tonic::body::Body>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<StdError> + Send,
    Q: prost::Message + Default + Send + 'static,
    R: prost::Message + Default + Clone + Send + 'static,
{
    tonic::server::Grpc::new(tonic_prost::ProstCodec::<R, Q>::default())
        .unary(FixedUnary(response), request)
        .await
}

impl<B> Service<http::Request<B>> for LegacyGateway
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let probe = self.probe.clone();
        Box::pin(async move {
            let response = match request.uri().path() {
                "/openshell.v1.OpenShell/ConnectSupervisor" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        GatewayMessage,
                        SupervisorMessage,
                    >::default())
                    .streaming(LegacyConnect(probe), request)
                    .await
                }
                "/openshell.v1.OpenShell/GetSandboxConfig" => {
                    let scripted = probe
                        .policy_sync
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map(|case| case.snapshot.clone());
                    let snapshot = scripted.unwrap_or_else(|| {
                        let mut policy = openshell_policy::restrictive_default_policy();
                        enrich_proto_baseline_paths(&mut policy);
                        GetSandboxConfigResponse {
                            policy: Some(policy),
                            version: 1,
                            policy_hash: "legacy-policy".into(),
                            config_revision: 7,
                            workspace: "default".into(),
                            configuration_admitted: true,
                            configuration_instance_id: "configuration-1".into(),
                            policy_source: openshell_core::proto::PolicySource::Sandbox.into(),
                            policy_validation_failure_mode: "fail_closed".into(),
                            ..Default::default()
                        }
                    });
                    legacy_unary::<B, GetSandboxConfigRequest, _>(request, snapshot).await
                }
                "/openshell.v1.OpenShell/GetSandboxProviderEnvironment" => {
                    legacy_unary::<B, GetSandboxProviderEnvironmentRequest, _>(
                        request,
                        GetSandboxProviderEnvironmentResponse::default(),
                    )
                    .await
                }
                "/openshell.v1.OpenShell/ReportSandboxConfiguration" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        ReportSandboxConfigurationResponse,
                        ReportSandboxConfigurationRequest,
                    >::default())
                    .unary(ConfigurationReportRecorder(probe), request)
                    .await
                }
                "/openshell.v1.OpenShell/ReportPolicyStatus" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        ReportPolicyStatusResponse,
                        ReportPolicyStatusRequest,
                    >::default())
                    .unary(PolicyStatusRecorder(probe), request)
                    .await
                }
                "/openshell.v1.OpenShell/UpdateConfig" => {
                    let (write, created) = probe.policy_sync.lock().unwrap().as_ref().map_or_else(
                        || {
                            (
                                UpdateConfigResponse {
                                    version: 1,
                                    policy_hash: "legacy-policy".into(),
                                    ..Default::default()
                                },
                                false,
                            )
                        },
                        |case| (case.write.clone(), case.created),
                    );
                    let mut response =
                        legacy_unary::<B, UpdateConfigRequest, _>(request, write).await;
                    if created {
                        response.headers_mut().insert(
                            openshell_core::startup_policy::POLICY_REVISION_CREATED_HEADER,
                            http::HeaderValue::from_static("true"),
                        );
                    }
                    response
                }
                _ => http::Response::builder()
                    .status(200)
                    .header("grpc-status", "12")
                    .header("content-type", "application/grpc")
                    .body(tonic::body::Body::empty())
                    .unwrap(),
            };
            Ok(response)
        })
    }
}

#[tokio::test]
async fn attach_refusal_policy_history_omits_private_backend_diagnostics() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let probe = LegacyReadyProbe::default();
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(LegacyGateway {
                probe: probe.clone(),
            })
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let gateway = openshell_core::grpc_client::GatewayEndpoint::new(
        endpoint,
        openshell_core::grpc_client::GatewayCredentials::from_gateway_token("test-token").unwrap(),
    );
    let revision = LoadedPolicyRevision {
        version: 3,
        policy_hash: "admitted-policy".into(),
        config_revision: 7,
        policy_source: openshell_core::proto::PolicySource::Sandbox,
        admission_instance_id: Some("instance-1".into()),
        provider_env_revision: 1,
    };
    let origin = LoadedPolicyOrigin::Gateway {
        revision: Some(revision.clone()),
        has_last_valid_policy: true,
    };
    let refusal = miette::Report::new(backend_setup::BackendAttachError(
        BackendError::AttachPolicyRefused {
            reason: AttachPolicyRefusal::WorkloadIdentityMismatch,
            detail: "PRIVATE-SENTINEL".into(),
        },
    ));
    let reason = backend_setup::attach_policy_refusal(&refusal).unwrap();

    timeout(
        Duration::from_secs(5),
        report_attach_refusal(&gateway, "sandbox-id", &origin, Some(&revision), reason),
    )
    .await
    .expect("report the startup-owned policy failure");

    let (report, reported_reason) = probe.attach_refusal.lock().unwrap().take().unwrap();
    assert_eq!(reported_reason, reason);
    assert_eq!(report.sandbox_id, "sandbox-id");
    assert!(report.expected_instance_id.is_empty());
    let admission = report.admission.unwrap();
    assert_eq!(
        admission.state,
        i32::from(openshell_core::proto::ConfigurationAdmissionState::Rejected)
    );
    assert!(admission.error.is_empty());

    {
        let reports = probe.policy_reports.lock().unwrap();
        let [report] = reports.as_slice() else {
            panic!("expected one policy failure report, got {reports:?}");
        };
        assert_eq!(report.sandbox_id, "sandbox-id");
        assert_eq!(report.version, 3);
        assert_eq!(
            report.status,
            i32::from(openshell_core::proto::PolicyStatus::Failed)
        );
        assert_eq!(report.load_error, reason.message());
    }
    assert!(refusal.to_string().contains("PRIVATE-SENTINEL"));
    server.abort();
    let _ = server.await;
}

struct HeldBackendSetup {
    session_id: openshell_core::SandboxSessionId,
    probe: LegacyReadyProbe,
}

impl BackendSetup for HeldBackendSetup {
    fn backend_name(&self) -> &'static str {
        "test-held"
    }

    fn decode(
        &self,
        _payload: &[u8],
    ) -> Result<(LaunchIdentity, Box<dyn PreparedBackend>), BackendError> {
        Ok((
            LaunchIdentity {
                sandbox_id: "sb-legacy-restart".into(),
                generation: "generation-1".into(),
                session_id: self.session_id,
                workload_identity: ResolvedWorkloadIdentity::new(
                    1000,
                    1000,
                    Vec::new(),
                    "test".into(),
                    "test-image".into(),
                )?,
                vm_policy_identity: None,
            },
            Box::new(HeldPreparedBackend(self.probe.clone())),
        ))
    }
}

struct HeldPreparedBackend(LegacyReadyProbe);

#[tonic::async_trait]
impl PreparedBackend for HeldPreparedBackend {
    async fn discover_policy(
        &self,
        _bearer: openshell_core::jwt::SessionBearerTokenSlot,
        _attach_request_timeout: Duration,
    ) -> Result<(Option<String>, bool), BackendError> {
        self.0.discovered.store(true, Ordering::SeqCst);
        Ok((None, false))
    }

    fn build(self: Box<Self>, _services: BackendServices) -> Result<BuiltBackend, BackendError> {
        Err(BackendError::Attach("test boundary remains held".into()))
    }
}

#[tokio::test]
async fn config_push_regression_legacy_gateway_never_observes_ready_before_workload() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let probe = LegacyReadyProbe::default();
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(LegacyGateway {
                probe: probe.clone(),
            })
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let session_id = openshell_core::SandboxSessionId::new();
    let auth_bundle = openshell_core::jwt::SupervisorAuthBundle {
        session_id,
        runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
            "generation-1",
        )
        .unwrap(),
        session_rotation: openshell_core::jwt::SessionRotation::new(1).unwrap(),
        auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
        gateway_token: openshell_core::jwt::SecretJwt::parse("test-gateway-token").unwrap(),
        gateway_expires_at: 0,
        sandbox_token: openshell_core::jwt::SecretJwt::parse("test-sandbox-token").unwrap(),
        sandbox_expires_at: 0,
        ssh_host_private_key: None,
        traces_otlp_headers: None,
        ocsf_otlp_headers: None,
        agent_otlp_headers: None,
        otlp_tls: Vec::new(),
        traces_otlp_tls: None,
        ocsf_otlp_tls: None,
        agent_otlp_tls: None,
    };
    let setup = HeldBackendSetup {
        session_id,
        probe: probe.clone(),
    };
    let config = SandboxInstanceConfig {
        app_router: None,
        command: vec!["true".into()],
        workdir: None,
        timeout_secs: 0,
        interactive: false,
        await_main_process_attachment: false,
        sandbox_id: Some("sb-legacy-restart".into()),
        sandbox: Some("legacy-restart".into()),
        container_image: String::new(),
        container_image_uid: None,
        openshell_endpoint: Some(endpoint),
        gateway_home: None,
        policy_rules: None,
        policy_data: None,
        ssh_socket_path: None,
        shared_ssh_socket: false,
        upstream_proxy_args:
            openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs::default(),
        additional_ca_bundle: None,
        policy_dns_ipv6_egress: openshell_supervisor_network::run::PolicyDnsIpv6Egress::Disabled,
        nat64_prefixes: Vec::new(),
        backend_descriptor: openshell_isolation_interface::contract::BackendDescriptor {
            backend_name: "test-held".into(),
            payload: Vec::new(),
        },
        auth_bundle,
        admitted_isolation_backend: Some("test-held".into()),
        main_exit_marker: None,
        attach_request_timeout: Duration::from_mins(5),
        trace_context: None,
        provider_identity: openshell_supervisor_network::run::ProviderIdentitySource::default(),
        proxy_tls: openshell_supervisor_network::run::ProxyTlsFiles::default(),
        takeover: None,
        supervisor_recovery_timeout_secs: None,
        otlp_agent_endpoint: None,
        otlp_agent_protocol: openshell_core::sandbox_env::OtlpProtocol::Grpc,
    };
    let bindings = SandboxInstanceBindings::dedicated(
        &config,
        openshell_core::grpc_client::GatewayCredentials::from_auth_bundle(&config.auth_bundle)
            .unwrap(),
        openshell_ocsf::OcsfJsonSettings::default(),
    );
    let startup = run_sandbox_with_backend(&setup, config, bindings, None, None);
    tokio::pin!(startup);
    let result = tokio::select! {
        () = probe.ready_event.notified() => None,
        result = &mut startup => Some(result),
        () = tokio::time::sleep(Duration::from_secs(5)) => panic!("startup must reach the held boundary or the legacy readiness event"),
    };
    server.abort();
    let _ = server.await;
    assert!(
        probe.discovered.load(Ordering::SeqCst),
        "fixture reaches authenticated image discovery"
    );
    assert!(
        !probe.premature_ready.load(Ordering::SeqCst),
        "a legacy gateway must not observe a Ready event while the workload is still unstarted"
    );
    let error = result
        .expect("startup reaches the deliberately held backend")
        .unwrap_err();
    assert!(error.to_string().contains("test boundary remains held"));
}

#[tokio::test]
async fn policy_sync_preserves_write_receipt_separately_from_refetched_policy() {
    for (created, write_version, snapshot_version, expected_receipt) in [
        (true, 2, 2, Some(2)),
        (true, 2, 3, Some(2)),
        (false, 2, 2, None),
        (true, 0, 2, None),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let probe = LegacyReadyProbe::default();
        *probe.policy_sync.lock().unwrap() = Some(PolicySyncCase {
            write: UpdateConfigResponse {
                version: write_version,
                ..Default::default()
            },
            created,
            snapshot: GetSandboxConfigResponse {
                version: snapshot_version,
                policy_source: openshell_core::proto::PolicySource::Sandbox.into(),
                policy_validation_failure_mode: "fail_closed".into(),
                workspace: "default".into(),
                ..Default::default()
            },
        });
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(LegacyGateway { probe })
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let gateway = RemoteStartupGateway {
            gateway: Some(openshell_core::grpc_client::GatewayEndpoint::new(
                endpoint,
                openshell_core::grpc_client::GatewayCredentials::from_gateway_token("test-token")
                    .unwrap(),
            )),
        };
        let receipt = gateway
            .sync(
                "sandbox",
                &openshell_policy::restrictive_default_policy(),
                "default",
            )
            .await
            .expect("sync the policy through the production RPC helper");
        let snapshot = gateway.snapshot("sandbox", Some("default")).await.unwrap();
        assert_eq!(snapshot.version, snapshot_version);
        assert_eq!(receipt, expected_receipt);
        server.abort();
        let _ = server.await;
    }
}
