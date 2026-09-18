// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Included in the Linux boundary tests so the transport wrapper can delegate to
// the actual authenticated service and observe its real workload fixture.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LostConfigurationResponse {
    Commit,
    Release,
}

struct ConfigurationResponseLoss {
    operation: LostConfigurationResponse,
    armed: AtomicBool,
    observed: Mutex<Option<Response>>,
    observed_notification: tokio::sync::Notify,
    close_response: tokio::sync::Notify,
}

impl ConfigurationResponseLoss {
    fn new(operation: LostConfigurationResponse) -> Self {
        Self {
            operation,
            armed: AtomicBool::new(false),
            observed: Mutex::new(None),
            observed_notification: tokio::sync::Notify::new(),
            close_response: tokio::sync::Notify::new(),
        }
    }

    fn should_drop(&self, response: &Response) -> bool {
        let matches = matches!(
            (self.operation, response),
            (
                LostConfigurationResponse::Commit,
                Response::ConfigurationCommitted { .. }
            ) | (
                LostConfigurationResponse::Release,
                Response::ConfigurationReleased { .. }
            )
        );
        matches && self.armed.swap(false, Ordering::AcqRel)
    }

    async fn wait_for_completed_operation(&self) -> Response {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.observed_notification.notified(),
        )
        .await
        .expect("actual boundary operation must finish before its response is lost");
        lock(&self.observed)
            .clone()
            .expect("completed response captured")
    }
}

#[derive(Clone)]
struct ConfigurationLossGrpcService {
    actual: GrpcBoundaryService,
    loss: Arc<ConfigurationResponseLoss>,
}

#[tonic::async_trait]
impl IsolationBoundary for ConfigurationLossGrpcService {
    type ExchangeStream = GrpcResponseStream;
    type MediateStream = GrpcResponseStream;

    async fn exchange(
        &self,
        request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
    ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
        use tokio_stream::StreamExt as _;

        // Authentication, authorization, request decoding, and the operation
        // itself all run through the production service before interception.
        let mut actual = self.actual.exchange(request).await?.into_inner();
        let loss = self.loss.clone();
        let (outbound, receiver) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let mut first_frame = Vec::new();
            let mut forwarded_first_frame = false;
            while let Some(chunk) = actual.next().await {
                let chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        let _ = outbound.send(Err(error)).await;
                        return;
                    }
                };
                if forwarded_first_frame {
                    if outbound.send(Ok(chunk)).await.is_err() {
                        return;
                    }
                    continue;
                }
                first_frame.extend_from_slice(&chunk.data);
                let Some(header) = first_frame.get(..4) else {
                    continue;
                };
                let declared =
                    u32::from_be_bytes(header.try_into().expect("frame header")) as usize;
                if first_frame.len() < declared + 4 {
                    continue;
                }
                let response: ResponseEnvelope =
                    openshell_sandbox_backend::boundary_protocol::decode_frame(
                        &first_frame[..declared + 4],
                    )
                    .expect("production response frame");
                if loss.should_drop(&response.response) {
                    *lock(&loss.observed) = Some(response.response);
                    loss.observed_notification.notify_one();
                    // Hold only the reply, after install/resume has happened.
                    // The test observes independent child state before ending
                    // this real HTTP/2 stream without the successful response.
                    loss.close_response.notified().await;
                    let _ = outbound
                        .send(Err(tonic::Status::unavailable(
                            "test transport discarded the completed response",
                        )))
                        .await;
                    return;
                }
                if outbound
                    .send(Ok(BoundaryChunk {
                        data: std::mem::take(&mut first_frame),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
                forwarded_first_frame = true;
            }
        });
        Ok(tonic::Response::new(ReceiverStream::new(receiver)))
    }

    async fn mediate(
        &self,
        request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
    ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
        self.actual.mediate(request).await
    }
}

async fn serve_configuration_loss_connection(
    stream: openshell_isolation_interface::contract::BoundaryDuplexStream,
    boundary: Arc<BoundaryRuntime>,
    loss: Arc<ConfigurationResponseLoss>,
) {
    let connection_id = SandboxConnectionId::new();
    let (shutdown, closed) = tokio::sync::watch::channel(());
    boundary.register_connection(connection_id, shutdown.clone());
    let actual = GrpcBoundaryService {
        runtime: boundary.clone(),
        connection_id,
        connection_expiry: Arc::new(ConnectionExpiry::new(shutdown.clone())),
        connection_closed: closed.clone(),
    };
    let incoming = tokio_stream::StreamExt::chain(
        tokio_stream::iter([Ok::<_, io::Error>(GrpcServerIo {
            stream,
            _connection_alive: shutdown,
            _disconnect: TransportDisconnectGuard {
                runtime: Arc::downgrade(&boundary),
                connection_id,
            },
        })]),
        tokio_stream::pending(),
    );
    let mut closed = closed;
    let _ = tonic::transport::Server::builder()
        .add_service(IsolationBoundaryServer::new(ConfigurationLossGrpcService {
            actual,
            loss,
        }))
        .serve_with_incoming_shutdown(incoming, async move {
            let _ = closed.changed().await;
        })
        .await;
    boundary.transport_disconnected(connection_id);
}

struct ConfigurationTransportFixture {
    controller: Arc<dyn openshell_isolation_interface::contract::BoundaryConfiguration>,
    running: Box<dyn openshell_isolation_interface::contract::RunningBoundary>,
    initial_activation: ActivatedBoundaryConfiguration,
    providers: ProviderCredentialState,
    loss: Arc<ConfigurationResponseLoss>,
    server: tokio::task::JoinHandle<()>,
}

impl ConfigurationTransportFixture {
    async fn connect(
        fixture: &RunningActivationFixture,
        operation: LostConfigurationResponse,
    ) -> Self {
        use openshell_isolation_interface::contract::{BackendRegistry, SandboxContext};
        use openshell_sandbox_backend::boundary_protocol::{
            SandboxRuntimeDescriptor, SandboxTransport,
        };

        let (server_tls, client_tls) = stage_test_tls(fixture.directory.path(), "activation-loss");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            load_tls_server_config(&server_tls).expect("actual server TLS configuration"),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind actual TLS backend endpoint");
        let address = listener.local_addr().expect("actual endpoint address");
        let boundary = fixture.boundary.clone();
        let loss = Arc::new(ConfigurationResponseLoss::new(operation));
        let server_loss = loss.clone();
        let server = tokio::spawn(async move {
            // The task owns all accepted connections so aborting the fixture
            // closes their transports and runs production disconnect guards.
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("accept actual backend connection");
                        let acceptor = acceptor.clone();
                        let boundary = boundary.clone();
                        let loss = server_loss.clone();
                        connections.spawn(async move {
                            let stream = acceptor.accept(stream).await.expect("TLS handshake");
                            serve_configuration_loss_connection(Box::new(stream), boundary, loss).await;
                        });
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        result.expect("boundary transport task");
                    }
                }
            }
        });
        let previous = fixture.boundary.configuration_snapshot().unwrap();
        let supervisor: SupervisorInstanceId =
            previous.identity.supervisor_instance_id.parse().unwrap();
        let (_, token) = test_auth_material(&fixture.boundary.config.boundary_id);
        let expires_at = openshell_core::jwt::parse_exp_secs(&token).unwrap();
        let providers = ProviderCredentialState::from_child_env_snapshot(
            4,
            std::collections::HashMap::from([(
                "CONFIGURATION_TEST_TOKEN".to_string(),
                "credential-a".to_string(),
            )]),
        );
        let backend = Arc::new(openshell_sandbox_backend::OpenShellRuntimeBackend::new(
            Arc::new(Mutex::new(None)),
            providers.clone(),
            openshell_core::jwt::SessionBearerTokenSlot::new(
                openshell_core::jwt::SecretJwt::parse(token).unwrap(),
                expires_at,
                fixture.boundary.config.auth_epoch,
            )
            .unwrap(),
            supervisor,
        ));
        let descriptor = SandboxRuntimeDescriptor {
            boundary_id: fixture.boundary.config.boundary_id.clone(),
            generation: fixture.boundary.config.generation.clone(),
            session_id: fixture.boundary.config.session_id,
            workload_identity: fixture.boundary.config.workload_identity.clone(),
            transport: SandboxTransport::Tcp {
                authority: address.to_string(),
                addresses: vec![address],
            },
            tls: client_tls,
            host_gateway_ip: None,
            resource_claims: fixture.boundary.config.resource_claims.clone(),
            driver_fence: fixture.boundary.config.driver_fence.clone(),
        };
        let mut registry = BackendRegistry::new();
        registry.register(backend).unwrap();
        let (backend, descriptor) = registry
            .resolve(
                descriptor.backend_descriptor().unwrap(),
                openshell_sandbox_backend::BACKEND_NAME,
            )
            .unwrap();
        let bootstrap = backend.discover(&descriptor).await.unwrap();
        assert!(bootstrap.identity.same_incarnation(&previous.identity));
        let bound = backend
            .attach(
                descriptor,
                SandboxContext {
                    sandbox_id: fixture.boundary.config.boundary_id.clone(),
                    session_id: fixture.boundary.config.session_id,
                    policy: fixture.policy.clone().into(),
                    agent: openshell_isolation_interface::AgentSpec {
                        program: fixture.spec.program.clone(),
                        args: fixture.spec.args.clone(),
                        workdir: fixture.spec.workdir.clone(),
                        timeout_secs: fixture.spec.timeout_secs,
                        interactive: fixture.spec.interactive,
                    },
                    identity: fixture.boundary.config.workload_identity.clone(),
                    registration_grant: openshell_core::jwt::SecretJwt::parse(
                        test_registration_grant(
                            &fixture.boundary,
                            supervisor,
                            previous.identity.registration_revision,
                        ),
                    )
                    .unwrap(),
                    registration_revision: previous.identity.registration_revision,
                },
            )
            .await
            .expect("attach actual backend to the existing workload");
        let measured = fixture
            .boundary
            .measure_confirmation_evidence()
            .expect("measure the actual hardened test process before backend confirmation");
        println!(
            "configuration transport confirmation: no_new_privileges={} sandbox_dumpable={} core_limit_zero={} capabilities={:?} identity_matches={}",
            measured.no_new_privileges,
            measured.sandbox_dumpable,
            measured.core_limit_zero,
            measured.capabilities,
            measured.identity == fixture.boundary.config.workload_identity,
        );
        measured
            .validate(&fixture.boundary.config.workload_identity)
            .expect("actual process evidence must satisfy the unchanged backend contract");
        let ready = bound.confirm().await.unwrap().into_boundary();
        let controller = ready.configuration();
        assert!(!*controller.readiness().borrow());
        let snapshot = controller.snapshot().await.unwrap();
        let initial = snapshot.installed.clone().unwrap();
        let prepared = controller
            .prepare(
                snapshot.installed,
                snapshot.publication_generation,
                initial,
                providers.snapshot().child_env.clone(),
                providers.snapshot().installation_id.clone(),
            )
            .await
            .unwrap();
        let installed = controller.commit(&prepared).await.unwrap();
        let initial_activation = controller.release(&installed).await.unwrap();
        let running = ready
            .start_agent()
            .await
            .expect("replay initial launch through TLS");
        assert_eq!(fixture.start_count(), 1);
        assert!(*controller.readiness().borrow());
        Self {
            controller,
            running,
            initial_activation,
            providers,
            loss,
            server,
        }
    }

    async fn prepare_next(&self) -> PreparedBoundaryConfiguration {
        let snapshot = self.controller.snapshot().await.unwrap();
        let mut candidate = snapshot.installed.clone().unwrap();
        candidate.config_revision += 1;
        candidate.provider_env_revision = 7;
        let child_env = std::collections::HashMap::from([(
            "CONFIGURATION_TEST_TOKEN".to_string(),
            "credential-b".to_string(),
        )]);
        let prepared_providers =
            ProviderCredentialState::from_child_env_snapshot(7, child_env.clone());
        let prepared = self
            .controller
            .prepare(
                snapshot.installed,
                snapshot.publication_generation,
                candidate,
                child_env.clone(),
                prepared_providers.snapshot().installation_id.clone(),
            )
            .await
            .unwrap();
        self.providers.install_prepared(&prepared_providers);
        prepared
    }

    async fn assert_backend_exec_blocked(&self, fixture: &RunningActivationFixture) {
        assert!(!*self.controller.readiness().borrow());
        assert!(
            self.running
                .exec()
                .exec(openshell_isolation_interface::contract::ExecSpec {
                    program: "/bin/sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        "printf forbidden > \"$1/forbidden-exec\"".to_string(),
                        "blocked-exec".to_string(),
                        fixture.directory.path().to_string_lossy().into_owned(),
                    ],
                    env: Vec::new(),
                    workdir: None,
                    pty: false,
                })
                .await
                .is_err()
        );
        assert!(!fixture.directory.path().join("forbidden-exec").exists());
    }

    async fn assert_backend_exec_credential(
        &self,
        fixture: &RunningActivationFixture,
        expected: &str,
    ) {
        let session = self
            .running
            .exec()
            .exec(openshell_isolation_interface::contract::ExecSpec {
                program: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "printf '%s' \"$CONFIGURATION_TEST_TOKEN\" > \"$1/accepted-exec\"".to_string(),
                    "accepted-exec".to_string(),
                    fixture.directory.path().to_string_lossy().into_owned(),
                ],
                env: Vec::new(),
                workdir: None,
                pty: false,
            })
            .await
            .expect("released backend must permit a real exec");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), session.process.wait())
                .await
                .expect("accepted exec must finish")
                .expect("accepted exec exit"),
            openshell_isolation_interface::contract::BoundaryExitStatus::Exited(0)
        ));
        assert_eq!(
            std::fs::read_to_string(fixture.directory.path().join("accepted-exec")).unwrap(),
            expected,
            "actual exec must receive only the installed provider generation"
        );
    }
}

impl Drop for ConfigurationTransportFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn harden_transport_test_process() {
    // These tests run in their own child process. Establish the same process
    // prerequisites as the sandbox entrypoint before starting runtime threads,
    // which inherit no_new_privs, and before spawning the real workload.
    capctl::prctl::set_no_new_privs().expect("prevent test process privilege escalation");
    make_boundary_nondumpable().expect("apply actual boundary nondumpability");
    disable_core_dumps().expect("apply actual boundary core limits");
}

#[test]
fn configuration_activation_transport_lost_commit_preserves_one_workload() {
    if isolated_activation_test(
        "configuration_activation_transport_lost_commit_preserves_one_workload",
    ) {
        return;
    }
    harden_transport_test_process();
    let fixture = RunningActivationFixture::new();
    let pid = fixture.workload_pid();
    fixture.runtime.block_on(async {
        let transport = ConfigurationTransportFixture::connect(&fixture, LostConfigurationResponse::Commit).await;
        transport.assert_backend_exec_credential(&fixture, "credential-a").await;
        let prepared = transport.prepare_next().await;
        transport.loss.armed.store(true, Ordering::Release);
        let controller = transport.controller.clone();
        let request = prepared.clone();
        let first_commit = tokio::spawn(async move { controller.commit(&request).await });
        let Response::ConfigurationCommitted { installed: observed } =
            transport.loss.wait_for_completed_operation().await
        else {
            panic!("interceptor did not observe actual installation");
        };
        assert!(!first_commit.is_finished());
        assert_eq!(fixture.boundary.configuration_snapshot().unwrap().installed, Some(prepared.configuration.clone()));
        let held_heartbeat = fixture.heartbeat();
        fixture.assert_held(&transport.initial_activation);
        transport.assert_backend_exec_blocked(&fixture).await;
        println!("configuration transport observation: operation=commit phase=reply-lost pid={pid} starts={} heartbeat={held_heartbeat} backend_ready={}", fixture.start_count(), *transport.controller.readiness().borrow());
        transport.loss.close_response.notify_one();
        let retried = tokio::time::timeout(Duration::from_secs(5), first_commit)
            .await
            .expect("lost commit must finish its recovery attempt")
            .unwrap()
            .expect("same-registration transport recovery retries the exact commit");
        assert_eq!(retried, *observed);
        transport.assert_backend_exec_blocked(&fixture).await;
        let installed = transport.controller.commit(&prepared).await.expect("exact commit retry must retain the installed transition");
        assert_eq!(installed, *observed);
        assert!(!*transport.controller.readiness().borrow());
        transport.controller.release(&installed).await.unwrap();
        fixture.wait_for_heartbeat(held_heartbeat);
        assert!(*transport.controller.readiness().borrow());
        transport.assert_backend_exec_credential(&fixture, "credential-b").await;
        assert_eq!(fixture.workload_pid(), pid);
        assert_eq!(fixture.start_count(), 1);
        println!("configuration transport observation: operation=commit phase=retry-accepted pid={pid} starts={} heartbeat={} backend_ready={}", fixture.start_count(), fixture.heartbeat(), *transport.controller.readiness().borrow());
    });
}

#[test]
fn configuration_activation_transport_lost_release_requires_exact_retry() {
    if isolated_activation_test(
        "configuration_activation_transport_lost_release_requires_exact_retry",
    ) {
        return;
    }
    harden_transport_test_process();
    let fixture = RunningActivationFixture::new();
    let pid = fixture.workload_pid();
    fixture.runtime.block_on(async {
        let transport = ConfigurationTransportFixture::connect(&fixture, LostConfigurationResponse::Release).await;
        transport.assert_backend_exec_credential(&fixture, "credential-a").await;
        let prepared = transport.prepare_next().await;
        let installed = transport.controller.commit(&prepared).await.unwrap();
        let held_heartbeat = fixture.heartbeat();
        transport.loss.armed.store(true, Ordering::Release);
        let controller = transport.controller.clone();
        let request = installed.clone();
        let first_release = tokio::spawn(async move { controller.release(&request).await });
        let Response::ConfigurationReleased { activated: observed } =
            transport.loss.wait_for_completed_operation().await
        else {
            panic!("interceptor did not observe actual workload release");
        };
        assert!(!first_release.is_finished());
        fixture.wait_for_heartbeat(held_heartbeat);
        assert!(fixture.boundary.configuration_snapshot().unwrap().active);
        transport.assert_backend_exec_blocked(&fixture).await;
        println!("configuration transport observation: operation=release phase=reply-lost pid={pid} starts={} heartbeat={} backend_ready={}", fixture.start_count(), fixture.heartbeat(), *transport.controller.readiness().borrow());
        transport.loss.close_response.notify_one();
        let retried = tokio::time::timeout(Duration::from_secs(5), first_release)
            .await
            .expect("lost release must finish its recovery attempt")
            .unwrap()
            .expect("same-registration transport recovery retries the exact release");
        assert_eq!(retried, *observed);
        assert!(*transport.controller.readiness().borrow());
        let activated = transport.controller.release(&installed).await.expect("exact release retry must retain the installed transition");
        assert_eq!(activated, *observed);
        assert!(*transport.controller.readiness().borrow());
        transport.assert_backend_exec_credential(&fixture, "credential-b").await;
        assert_eq!(fixture.workload_pid(), pid);
        assert_eq!(fixture.start_count(), 1);
        println!("configuration transport observation: operation=release phase=retry-accepted pid={pid} starts={} heartbeat={} backend_ready={}", fixture.start_count(), fixture.heartbeat(), *transport.controller.readiness().borrow());
    });
}
