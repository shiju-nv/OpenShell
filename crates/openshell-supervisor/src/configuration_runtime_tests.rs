// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Included only in Linux configuration tests. The gateway delivery is controlled
// here; workload execution, TLS, boundary transitions, OPA, and credentials use
// their production implementations.

use openshell_isolation_interface::contract::{
    BackendRegistry, BoundaryExitStatus, DriverFenceEvidence, ExecSpec, SandboxContext,
};
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport, SupervisorInstanceId,
    generate_sandbox_tls_material,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

struct RuntimeDelivery {
    snapshot: Mutex<SettingsPollResult>,
    providers: Mutex<ProviderEnvironmentResult>,
    reports: Mutex<Vec<SandboxConfigurationAdmission>>,
}

#[tonic::async_trait]
impl ConfigurationGateway for RuntimeDelivery {
    async fn snapshot(&self, _issue: bool) -> Result<SettingsPollResult> {
        Ok(self.snapshot.lock().expect("delivery lock").clone())
    }

    async fn provider(&self) -> Result<ProviderEnvironmentResult> {
        Ok(copy_runtime_provider(
            &self.providers.lock().expect("provider delivery lock"),
        ))
    }

    async fn sync_policy(
        &self,
        _policy: &openshell_core::proto::SandboxPolicy,
        _workspace: &str,
    ) -> Result<()> {
        panic!("already selected fixture policy must not be synchronized again")
    }

    async fn report(
        &self,
        admission: &SandboxConfigurationAdmission,
        _expected_instance: &str,
        _expected_boundary: &str,
    ) -> Result<openshell_core::proto::ReportSandboxConfigurationResponse> {
        self.reports
            .lock()
            .expect("report lock")
            .push(admission.clone());
        Ok(Default::default())
    }

    async fn middleware_credentials(
        &self,
        _snapshot: &SettingsPollResult,
    ) -> Result<HashMap<String, openshell_extension_core::BearerTokenSlot>> {
        Ok(HashMap::new())
    }

    async fn refresh_credentials(&self) -> Result<()> {
        Ok(())
    }
}

struct PausedRuntimeBoundary {
    actual: Arc<dyn BoundaryConfiguration>,
    armed: AtomicBool,
    prepared: tokio::sync::Notify,
    proceed: tokio::sync::Notify,
}

#[tonic::async_trait]
impl BoundaryConfiguration for PausedRuntimeBoundary {
    fn identity(&self) -> ConfigurationActivationIdentity {
        self.actual.identity()
    }

    fn readiness(&self) -> watch::Receiver<bool> {
        self.actual.readiness()
    }

    async fn snapshot(&self) -> std::result::Result<BoundaryConfigurationSnapshot, BackendError> {
        self.actual.snapshot().await
    }

    async fn prepare(
        &self,
        expected: Option<ConfigurationRevision>,
        candidate: ConfigurationRevision,
        child_env: HashMap<String, String>,
    ) -> std::result::Result<PreparedBoundaryConfiguration, BackendError> {
        let receipt = self.actual.prepare(expected, candidate, child_env).await?;
        // This barrier follows the actual remote acknowledgement. A process
        // observation made here proves the kernel hold precedes publication.
        if self.armed.swap(false, Ordering::AcqRel) {
            self.prepared.notify_one();
            self.proceed.notified().await;
        }
        Ok(receipt)
    }

    async fn commit(
        &self,
        prepared: &PreparedBoundaryConfiguration,
    ) -> std::result::Result<InstalledBoundaryConfiguration, BackendError> {
        self.actual.commit(prepared).await
    }

    async fn release(
        &self,
        installed: &InstalledBoundaryConfiguration,
    ) -> std::result::Result<ActivatedBoundaryConfiguration, BackendError> {
        self.actual.release(installed).await
    }

    async fn abort(
        &self,
        prepared: &PreparedBoundaryConfiguration,
    ) -> std::result::Result<(), BackendError> {
        self.actual.abort(prepared).await
    }

    async fn quiesce(&self) -> std::result::Result<(), BackendError> {
        self.actual.quiesce().await
    }

    async fn refresh_registration(
        &self,
        grant: openshell_core::jwt::SecretJwt,
        revision: u64,
    ) -> std::result::Result<(), BackendError> {
        self.actual.refresh_registration(grant, revision).await
    }
}

struct RuntimeEndpoint {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    server: tokio::task::JoinHandle<()>,
}

impl RuntimeEndpoint {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream bind");
        let port = listener.local_addr().expect("upstream address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("upstream connection");
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    bytes.push(stream.read_u8().await.expect("upstream request byte"));
                    assert!(bytes.len() < 4096, "bounded synthetic request");
                }
                captured
                    .lock()
                    .expect("request lock")
                    .push(String::from_utf8(bytes).expect("HTTP request"));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await
                    .expect("upstream response");
            }
        });
        Self {
            port,
            requests,
            server,
        }
    }
}

impl Drop for RuntimeEndpoint {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct RuntimeBoundaryProcess {
    child: std::process::Child,
    directory: tempfile::TempDir,
}

impl Drop for RuntimeBoundaryProcess {
    fn drop(&mut self) {
        // An assertion failure must not leave a serving boundary or workload.
        // The boundary owns its process tree; its children also have parent-death
        // protection when the test must forcefully reap this process.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct RuntimeProcessFixture {
    process: RuntimeBoundaryProcess,
    running: Box<dyn RunningBoundary>,
    boundary: Arc<PausedRuntimeBoundary>,
    gateway: Arc<RuntimeDelivery>,
    runtime: RuntimeConfiguration,
    candidate: SettingsPollResult,
    provider_b: ProviderEnvironmentResult,
    endpoint_a: RuntimeEndpoint,
    endpoint_b: RuntimeEndpoint,
}

fn runtime_provider(generation: u64, port: u16, tag: &str) -> ProviderEnvironmentResult {
    let mut result = provider(generation);
    result
        .environment
        .insert("CONFIGURATION_TEST_TOKEN".into(), tag.into());
    result.static_credential_bindings.insert(
        "CONFIGURATION_TEST_TOKEN".into(),
        openshell_core::proto::StaticCredentialBinding {
            endpoints: vec![openshell_core::proto::StaticCredentialEndpointBinding {
                host: "127.0.0.1".into(),
                port: u32::from(port),
                path: "/**".into(),
            }],
            credential_identity: format!(
                "service-{}:CONFIGURATION_TEST_TOKEN",
                if generation == 5 { "a" } else { "b" }
            ),
            workload_credential_handle: if generation == 5 { "a" } else { "b" }.repeat(64),
        },
    );
    result
}

fn copy_runtime_provider(provider: &ProviderEnvironmentResult) -> ProviderEnvironmentResult {
    ProviderEnvironmentResult {
        environment: provider.environment.clone(),
        provider_env_revision: provider.provider_env_revision,
        credential_expires_at_ms: provider.credential_expires_at_ms.clone(),
        dynamic_credentials: provider.dynamic_credentials.clone(),
        static_credential_bindings: provider.static_credential_bindings.clone(),
        non_secret_environment_keys: provider.non_secret_environment_keys.clone(),
    }
}

fn runtime_policy(
    directory: &std::path::Path,
    label: &str,
    port: u16,
) -> openshell_core::proto::SandboxPolicy {
    let fixtures = std::env::var_os("OPENSHELL_ACTIVATION_FIXTURES")
        .expect("frozen fixture directory is required");
    let yaml = std::fs::read_to_string(
        std::path::Path::new(&fixtures).join(format!("policy-{label}.yaml")),
    )
    .expect("frozen policy fixture");
    let rendered = yaml
        .replace(&format!("egress-{label}.invalid"), "127.0.0.1")
        .replace("18443", &port.to_string())
        .replace("/usr/bin/python*", "/bin/sh")
        .replace("/usr/local/bin/python*", "/bin/sh")
        .replace("/sandbox/.uv/python/*/bin/python*", "/bin/sh");
    std::fs::write(
        directory.join(format!("rendered-policy-{label}.yaml")),
        &rendered,
    )
    .expect("rendered policy evidence");
    openshell_policy::parse_sandbox_policy(&rendered).expect("materialized policy")
}

fn runtime_policy_evidence(
    directory: &std::path::Path,
    label: &str,
    policy: Option<&openshell_core::proto::SandboxPolicy>,
) -> String {
    let rendered = std::fs::read_to_string(directory.join(format!("rendered-policy-{label}.yaml")))
        .expect("materialized policy evidence");
    // Bind the recorded YAML to the installed protobuf, including the actual
    // endpoint port and workload binary substitutions used by this process.
    let parsed = openshell_policy::parse_sandbox_policy(&rendered)
        .expect("materialized policy evidence parses");
    assert_eq!(Some(&parsed), policy);
    rendered
}

impl RuntimeProcessFixture {
    async fn new() -> Self {
        Self::new_with_protocol_case(None, false).await
    }

    #[allow(
        clippy::too_many_lines,
        reason = "stages one complete authenticated Linux boundary lifecycle"
    )]
    async fn new_with_protocol_case(
        protocol_case: Option<&ProtocolRuntimeCase>,
        validate_protocol_startup: bool,
    ) -> Self {
        use openshell_core::jwt::{
            ControlRegistrationGrant, CredentialEpoch, DEFAULT_SESSION_TOKEN_TTL, SandboxId,
            SandboxRuntimeIdentity, SecretJwt, SessionBearerTokenSlot, SessionJwtIssuer,
            SessionRotation, SystemJwtClock,
        };

        let binary = std::env::var_os("OPENSHELL_ACTIVATION_SANDBOX_BINARY")
            .expect("candidate Linux boundary binary is required; this proof must not skip");
        assert!(std::path::Path::new(&binary).is_absolute());
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        assert_eq!(
            (uid, gid),
            (1000, 1000),
            "fixture sandbox account is UID/GID 1000"
        );
        let mut groups: Vec<_> = nix::unistd::getgroups()
            .expect("current groups")
            .into_iter()
            .map(nix::unistd::Gid::as_raw)
            .filter(|group| *group != gid)
            .collect();
        groups.sort_unstable();
        groups.dedup();
        let workload_identity =
            ResolvedWorkloadIdentity::new(uid, gid, groups, "fixture".into(), "a".repeat(64))
                .expect("numeric workload identity");
        let directory = tempfile::tempdir_in("/tmp").expect("runtime directory");
        let session_id = openshell_core::SandboxSessionId::new();
        let supervisor = SupervisorInstanceId::new();
        let generation = "configuration-runtime-fixture";
        let sandbox_id = format!("configuration-{session_id}");
        let tls = generate_sandbox_tls_material(session_id).expect("TLS material");
        let server_tls = SandboxTlsServerConfig {
            certificate_chain_path: directory.path().join("boundary.crt.fixture"),
            private_key_path: directory.path().join("boundary.key.fixture"),
        };
        std::fs::write(
            &server_tls.certificate_chain_path,
            tls.certificate_chain_pem,
        )
        .expect("TLS certificate");
        std::fs::write(&server_tls.private_key_path, tls.private_key_pem).expect("TLS private key");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("gateway signing key");
        let issuer = SessionJwtIssuer::from_ed25519_pem(
            key.serialize_pem().as_bytes(),
            "runtime-fixture",
            "runtime-fixture-gateway",
            DEFAULT_SESSION_TOKEN_TTL,
            Arc::new(SystemJwtClock),
        )
        .expect("session issuer");
        let runtime_identity = SandboxRuntimeIdentity {
            sandbox_id: SandboxId::parse(&sandbox_id).expect("sandbox ID"),
            runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                generation,
            )
            .expect("runtime generation"),
            auth_epoch: CredentialEpoch::new(1).expect("credential epoch"),
        };
        let token = issuer
            .mint_pair(&runtime_identity)
            .expect("signed runtime token")
            .sandbox;
        let socket_path = directory.path().join("boundary.sock");
        let fence = DriverFenceEvidence::Docker {
            container_id: std::env::var("HOSTNAME").expect("proof container identity"),
            network_mode: "none".into(),
            unexpected_networks: Vec::new(),
        };
        let config = BoundaryConfig {
            boundary_id: sandbox_id.clone(),
            generation: generation.into(),
            session_id,
            session_rotation: SessionRotation::new(1).expect("rotation"),
            auth_epoch: runtime_identity.auth_epoch,
            gateway_id: "runtime-fixture-gateway".into(),
            verification_keys: vec![GatewayVerificationKey {
                key_id: "runtime-fixture".into(),
                public_key_pem: key.public_key_pem(),
            }],
            listener: BoundaryListener::Unix {
                socket_path: socket_path.clone(),
                tls: server_tls,
            },
            resource_claims: Default::default(),
            resource_claim_files: Default::default(),
            workload_identity: workload_identity.clone(),
            driver_fence: fence.clone(),
            child_env: HashMap::new(),
        };
        let config_path = directory.path().join("boundary.json");
        std::fs::write(&config_path, config.encode().expect("bootstrap JSON"))
            .expect("bootstrap file");
        let log =
            std::fs::File::create(directory.path().join("boundary.log")).expect("boundary log");
        let child = std::process::Command::new(binary)
            .args(["--bootstrap"])
            .arg(&config_path)
            .args(["--log-level", "warn"])
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("log clone"))
            .stderr(log)
            .spawn()
            .expect("candidate boundary process");
        let mut process = RuntimeBoundaryProcess { child, directory };
        let deadline = std::time::Instant::now() + Duration::from_secs(45);
        while !socket_path.exists() {
            if let Some(status) = process.child.try_wait().expect("boundary status") {
                panic!(
                    "boundary qualification exited {status}: {}",
                    std::fs::read_to_string(process.directory.path().join("boundary.log"))
                        .expect("qualification log")
                );
            }
            assert!(
                std::time::Instant::now() < deadline,
                "boundary listener startup timed out"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let endpoint_a = RuntimeEndpoint::new().await;
        let endpoint_b = RuntimeEndpoint::new().await;
        let mut initial = snapshot(11);
        initial.version = 7;
        initial.provider_env_revision = 5;
        initial.policy = Some(runtime_policy(
            process.directory.path(),
            "a",
            endpoint_a.port,
        ));
        if let Some(case) = protocol_case {
            initial.policy = Some(protocol_runtime_policy(
                initial.policy.as_ref().expect("initial policy"),
                case,
            ));
        }
        let provider_a = runtime_provider(5, endpoint_a.port, "cred-A");
        let (engine, policy, credentials) =
            prepare_components(&initial, provider_a).expect("initial actual OPA and providers");
        let backend = Arc::new(openshell_sandbox_backend::OpenShellRuntimeBackend::new(
            Arc::new(Mutex::new(None)),
            credentials.clone(),
            SessionBearerTokenSlot::new(token.token, token.expires_at, runtime_identity.auth_epoch)
                .expect("runtime bearer slot"),
            supervisor,
        ));
        let descriptor = SandboxRuntimeDescriptor {
            boundary_id: sandbox_id.clone(),
            generation: generation.into(),
            session_id,
            workload_identity: workload_identity.clone(),
            transport: SandboxTransport::Unix { socket_path },
            tls: SandboxTlsClientConfig {
                server_name: tls.server_name,
                trust_anchor_pem: tls.trust_anchor_pem,
            },
            host_gateway_ip: None,
            resource_claims: Default::default(),
            driver_fence: fence,
        };
        let mut registry = BackendRegistry::new();
        registry.register(backend).expect("backend registration");
        let (backend, descriptor) = registry
            .resolve(
                descriptor.backend_descriptor().expect("descriptor"),
                openshell_sandbox_backend::BACKEND_NAME,
            )
            .expect("verified descriptor");
        let bootstrap = backend
            .discover(&descriptor)
            .await
            .expect("actual workload discovery");
        let mut identity = bootstrap.identity.clone();
        identity.registration_revision = 1;
        let grant = issuer
            .mint_control_registration(&ControlRegistrationGrant {
                runtime_identity,
                supervisor_instance_id: supervisor.to_string().parse().expect("control UUID"),
                boundary_session_id: session_id.to_string().parse().expect("session UUID"),
                boundary_instance_id: identity
                    .boundary_instance_id
                    .parse()
                    .expect("boundary UUID"),
                registration_revision: 1,
            })
            .expect("signed control grant");
        initial
            .runtime_generation
            .clone_from(&identity.runtime_generation);
        initial
            .configuration_instance_id
            .clone_from(&identity.supervisor_instance_id);
        initial
            .configuration_boundary_instance_id
            .clone_from(&identity.boundary_instance_id);
        initial.configuration_registration_revision = 1;
        let spec = openshell_isolation_interface::AgentSpec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "printf '%s\\n' \"$$\" >> \"$1/starts\"; while :; do printf 'beat\\n' >> \"$1/heartbeat\"; sleep 0.02; done".into(), "configuration-workload".into(), process.directory.path().to_string_lossy().into_owned()],
            workdir: Some(process.directory.path().to_string_lossy().into_owned()), timeout_secs: 120, interactive: false,
        };
        let bound = backend
            .attach(
                descriptor,
                SandboxContext {
                    sandbox_id,
                    session_id,
                    policy,
                    agent: spec,
                    identity: workload_identity,
                    registration_grant: SecretJwt::parse(grant.token.expose_secret())
                        .expect("registration JWT"),
                    registration_revision: 1,
                },
            )
            .await
            .expect("authenticated actual attachment");
        let ready = bound
            .confirm()
            .await
            .expect("actual Linux enforcement confirmation")
            .into_boundary();
        if let Some(case) = protocol_case {
            return protocol_runtime_start_fixture(
                *case,
                validate_protocol_startup,
                ProtocolRuntimeStartup {
                    process,
                    ready,
                    bootstrap,
                    initial,
                    credentials,
                    endpoint_a,
                    endpoint_b,
                },
            )
            .await;
        }
        let actual = ready.configuration();
        let prepared = actual
            .prepare(
                None,
                revision(&initial),
                credentials.child_env_with_gcp_resolved(),
            )
            .await
            .expect("initial prepare");
        let installed = actual.commit(&prepared).await.expect("initial commit");
        actual.release(&installed).await.expect("initial release");
        let running = ready
            .start_agent()
            .await
            .expect("sole main workload launch");
        let boundary = Arc::new(PausedRuntimeBoundary {
            actual,
            armed: AtomicBool::new(false),
            prepared: tokio::sync::Notify::new(),
            proceed: tokio::sync::Notify::new(),
        });
        let mut candidate = initial.clone();
        candidate.config_revision = 12;
        candidate.version = 8;
        candidate.provider_env_revision = 6;
        candidate.configuration_delivery_revision = 12;
        candidate.configuration_snapshot = "snapshot-12".into();
        candidate.policy_hash = "policy-12".into();
        candidate.policy = Some(runtime_policy(
            process.directory.path(),
            "b",
            endpoint_b.port,
        ));
        let provider_b = runtime_provider(6, endpoint_b.port, "cred-B");
        let gateway = Arc::new(RuntimeDelivery {
            snapshot: Mutex::new(candidate.clone()),
            providers: Mutex::new(copy_runtime_provider(&provider_b)),
            reports: Mutex::new(Vec::new()),
        });
        let (readiness, _) = watch::channel(true);
        let (workspace, _) = watch::channel(String::new());
        let runtime = RuntimeConfiguration {
            session: ConfigurationSession {
                gateway: gateway.clone(),
                instance_id: identity.supervisor_instance_id.clone(),
                runtime_generation: generation.into(),
                identity: Some(identity),
                startup_pending: false,
                startup_failures: AtomicU32::new(0),
            },
            boundary: boundary.clone(),
            snapshot: initial,
            engine: Arc::new(engine),
            credentials,
            readiness,
            ocsf_enabled: Arc::new(AtomicBool::new(false)),
            agent_proposals: openshell_core::proposals::AgentProposals::default(),
            policy_local: None,
            workspace,
            extension_credentials: openshell_extension_core::ExtensionCredentialStore::new(),
            connector: super::super::default_middleware_connector(),
            endpoint_observation_tx: None,
            interval: Duration::from_secs(1),
        };
        let fixture = Self {
            process,
            running,
            boundary,
            gateway,
            runtime,
            candidate,
            provider_b,
            endpoint_a,
            endpoint_b,
        };
        fixture.wait_heartbeat(0).await;
        assert_eq!(fixture.start_count(), 1);
        println!(
            "configuration_activation_runtime_observation {}",
            serde_json::json!({
                "scenario": "runtime-generation-binding",
                "identity": fixture.boundary.identity(),
                "A": revision(&fixture.runtime.snapshot),
                "B": revision(&fixture.candidate),
                "policy_a": runtime_policy_evidence(fixture.process.directory.path(), "a", fixture.runtime.snapshot.policy.as_ref()),
                "policy_b": runtime_policy_evidence(fixture.process.directory.path(), "b", fixture.candidate.policy.as_ref()),
                "materialized_yaml_matches_snapshot": true,
            })
        );
        fixture
    }

    fn heartbeat(&self) -> usize {
        std::fs::read_to_string(self.process.directory.path().join("heartbeat"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    fn start_count(&self) -> usize {
        std::fs::read_to_string(self.process.directory.path().join("starts"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    fn pid(&self) -> u32 {
        std::fs::read_to_string(self.process.directory.path().join("starts"))
            .expect("start record")
            .lines()
            .next()
            .expect("workload start")
            .parse()
            .expect("workload PID")
    }

    async fn wait_heartbeat(&self, after: usize) -> usize {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.heartbeat() <= after {
            assert!(
                std::time::Instant::now() < deadline,
                "workload heartbeat did not advance"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.heartbeat()
    }

    async fn exec_probe(&self, should_run: bool) {
        let marker = self.process.directory.path().join("exec-marker");
        let _ = std::fs::remove_file(&marker);
        let result = self
            .running
            .exec()
            .exec(ExecSpec {
                program: "/bin/sh".into(),
                args: vec![
                    "-c".into(),
                    "printf '%s' \"$CONFIGURATION_TEST_TOKEN\" > \"$1\"".into(),
                    "configuration-exec".into(),
                    marker.to_string_lossy().into_owned(),
                ],
                env: Vec::new(),
                workdir: Some(self.process.directory.path().to_string_lossy().into_owned()),
                pty: false,
            })
            .await;
        if should_run {
            assert_eq!(
                result
                    .expect("accepted exec")
                    .process
                    .wait()
                    .await
                    .expect("exec completion"),
                BoundaryExitStatus::Exited(0)
            );
            assert_eq!(
                std::fs::read_to_string(marker).expect("exec credential handle"),
                self.runtime.credentials.snapshot().child_env["CONFIGURATION_TEST_TOKEN"],
                "actual exec environment must match the installed provider generation"
            );
        } else {
            assert!(result.is_err(), "held boundary accepted exec");
            assert!(!marker.exists(), "rejected exec ran workload instructions");
        }
    }

    async fn assert_held(&self) -> usize {
        assert!(!*self.boundary.readiness().borrow());
        let heartbeat = self.heartbeat();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            self.heartbeat(),
            heartbeat,
            "held workload continued executing"
        );
        self.exec_probe(false).await;
        heartbeat
    }

    async fn stop(&self) {
        self.running
            .terminate()
            .await
            .expect("terminate actual workload");
    }
}

async fn runtime_endpoint_probe(
    engine: &OpaEngine,
    credentials: &ProviderCredentialState,
    endpoint: &RuntimeEndpoint,
    expected: Option<&str>,
) {
    let decision = engine
        .evaluate_network(&openshell_supervisor_network::opa::NetworkInput {
            host: "127.0.0.1".into(),
            port: endpoint.port,
            binary_path: "/bin/sh".into(),
            binary_sha256: "fixture-binary".into(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        })
        .expect("actual OPA decision");
    let count = endpoint.requests.lock().expect("request lock").len();
    let Some(expected) = expected else {
        assert!(!decision.allowed, "unaccepted endpoint became authorized");
        assert_eq!(endpoint.requests.lock().expect("request lock").len(), count);
        return;
    };
    assert!(
        decision.allowed,
        "accepted endpoint denied: {}",
        decision.reason
    );
    let child = credentials.snapshot();
    let placeholder = child
        .child_env
        .get("CONFIGURATION_TEST_TOKEN")
        .expect("workload credential handle");
    let resolver = credentials
        .resolver_for_endpoint("127.0.0.1", endpoint.port, "/probe")
        .expect("endpoint resolver");
    let rewritten = resolver
        .rewrite_header_value(placeholder)
        .expect("bound credential rewrite")
        .expect("placeholder must be replaced with its endpoint credential");
    assert_eq!(rewritten, expected);
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", endpoint.port))
        .await
        .expect("controlled upstream");
    stream.write_all(format!("GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {rewritten}\r\n\r\n").as_bytes()).await.expect("probe request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("probe response");
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let requests = endpoint.requests.lock().expect("request lock");
    assert_eq!(requests.len(), count + 1);
    assert!(requests[count].contains(&format!("Authorization: Bearer {expected}\r\n")));
}

#[tokio::test]
#[ignore = "requires the candidate boundary executable and isolated Linux fixture"]
#[allow(
    clippy::too_many_lines,
    reason = "keeps before, held, and released process observations in one scenario"
)]
async fn configuration_activation_runtime_publication_pause_holds_workload() {
    let mut fixture = RuntimeProcessFixture::new().await;
    let pid = fixture.pid();
    runtime_endpoint_probe(
        &fixture.runtime.engine,
        &fixture.runtime.credentials,
        &fixture.endpoint_a,
        Some("cred-A"),
    )
    .await;
    runtime_endpoint_probe(
        &fixture.runtime.engine,
        &fixture.runtime.credentials,
        &fixture.endpoint_b,
        None,
    )
    .await;
    let engine = fixture.runtime.engine.clone();
    let credentials = fixture.runtime.credentials.clone();
    let ready = fixture.runtime.readiness.subscribe();
    fixture.boundary.armed.store(true, Ordering::Release);
    let candidate = fixture.candidate.clone();
    // Borrow the coordinator separately so the observation branch can inspect
    // independent process files while the exact production future is suspended.
    let held = {
        let reconcile = fixture.runtime.reconcile_snapshot(candidate);
        tokio::pin!(reconcile);
        tokio::select! {
            result = &mut reconcile => panic!("activation completed before pause: {result:?}"),
            () = fixture.boundary.prepared.notified() => {}
            () = tokio::time::sleep(Duration::from_secs(10)) => panic!("remote prepare did not reach publication barrier"),
        }
        assert!(!*ready.borrow());
        assert_eq!(credentials.snapshot().revision, 5);
        assert_eq!(engine.current_generation(), 0);
        assert!(!*fixture.boundary.readiness().borrow());
        let held = std::fs::read_to_string(fixture.process.directory.path().join("heartbeat"))
            .expect("heartbeat")
            .lines()
            .count();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            std::fs::read_to_string(fixture.process.directory.path().join("heartbeat"))
                .expect("held heartbeat")
                .lines()
                .count(),
            held
        );
        let exec = fixture
            .running
            .exec()
            .exec(ExecSpec {
                program: "/bin/true".into(),
                args: Vec::new(),
                env: Vec::new(),
                workdir: None,
                pty: false,
            })
            .await;
        assert!(exec.is_err(), "exec must fail before publication");
        runtime_endpoint_probe(&engine, &credentials, &fixture.endpoint_a, Some("cred-A")).await;
        runtime_endpoint_probe(&engine, &credentials, &fixture.endpoint_b, None).await;
        fixture.boundary.proceed.notify_one();
        reconcile.await.expect("complete exact paused activation");
        held
    };
    let resumed = fixture.wait_heartbeat(held).await;
    assert_eq!(fixture.pid(), pid);
    assert_eq!(fixture.start_count(), 1);
    fixture.exec_probe(true).await;
    assert!(*fixture.runtime.readiness.borrow());
    assert_eq!(credentials.snapshot().revision, 6);
    assert_eq!(engine.current_generation(), 1);
    runtime_endpoint_probe(&engine, &credentials, &fixture.endpoint_a, None).await;
    runtime_endpoint_probe(&engine, &credentials, &fixture.endpoint_b, Some("cred-B")).await;
    println!(
        "configuration_activation_runtime_observation {}",
        serde_json::json!({"scenario":"atomic-live-publication", "pid_before":pid,"pid_after":fixture.pid(),"start_count":fixture.start_count(),"heartbeat_held":held,"heartbeat_after":resumed,"held_exec_denied":true,"held_readiness":false,"ready_after":*fixture.runtime.readiness.borrow(),"provider_before":5,"provider_while_held":5,"provider_after":credentials.snapshot().revision,"opa_generation_before":0,"opa_generation_while_held":0,"opa_generation_after":engine.current_generation(),"probe_origin":"actual-coordinator-opa-and-provider-state","upstream_a":*fixture.endpoint_a.requests.lock().expect("request lock"),"upstream_b":*fixture.endpoint_b.requests.lock().expect("request lock")})
    );
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "requires the candidate boundary executable and isolated Linux fixture"]
#[allow(
    clippy::too_many_lines,
    reason = "checks each rejection posture and subsequent repair against the same real child"
)]
async fn configuration_activation_runtime_rejection_postures_preserve_one_generation() {
    for mode in [
        openshell_core::PolicyValidationFailureMode::RetainLastValid,
        openshell_core::PolicyValidationFailureMode::FailClosed,
    ] {
        for fault in [
            "unresolved-binding",
            "provider-revision-mismatch",
            "opa-rejection",
        ] {
            let mut fixture = RuntimeProcessFixture::new().await;
            let pid = fixture.pid();
            let initial = revision(&fixture.runtime.snapshot);
            let mut candidate = fixture.candidate.clone();
            candidate.policy_validation_failure_mode = mode;
            match fault {
                "unresolved-binding" => {
                    // The real gateway separately proves this rejection. This
                    // seam delivers that verdict to the real runtime coordinator.
                    candidate.configuration_admitted = false;
                    candidate.configuration_error = "service-b binding is unresolved".into();
                }
                "provider-revision-mismatch" => {
                    fixture
                        .gateway
                        .providers
                        .lock()
                        .expect("provider lock")
                        .provider_env_revision += 1
                }
                "opa-rejection" => {
                    candidate.policy.as_mut().expect("policy").landlock =
                        Some(openshell_core::proto::LandlockPolicy {
                            compatibility: "invalid".into(),
                        })
                }
                _ => unreachable!("enumerated faults"),
            }
            fixture
                .runtime
                .reconcile_snapshot(candidate)
                .await
                .expect("repairable runtime rejection");
            let retains = mode == openshell_core::PolicyValidationFailureMode::RetainLastValid;
            let before = fixture.heartbeat();
            let observed = if retains {
                fixture.exec_probe(true).await;
                fixture.wait_heartbeat(before).await
            } else {
                fixture.assert_held().await
            };
            assert_eq!(*fixture.runtime.readiness.borrow(), retains);
            assert_eq!(fixture.runtime.credentials.snapshot().revision, 5);
            assert_eq!(
                fixture
                    .boundary
                    .snapshot()
                    .await
                    .expect("boundary snapshot")
                    .installed,
                Some(initial.clone())
            );
            assert!(
                fixture
                    .gateway
                    .reports
                    .lock()
                    .expect("reports")
                    .iter()
                    .all(
                        |report| report.state == i32::from(ConfigurationAdmissionState::Rejected)
                            && !report.activation_confirmed
                    )
            );
            runtime_endpoint_probe(
                &fixture.runtime.engine,
                &fixture.runtime.credentials,
                &fixture.endpoint_a,
                retains.then_some("cred-A"),
            )
            .await;
            runtime_endpoint_probe(
                &fixture.runtime.engine,
                &fixture.runtime.credentials,
                &fixture.endpoint_b,
                None,
            )
            .await;
            *fixture.gateway.providers.lock().expect("provider lock") =
                copy_runtime_provider(&fixture.provider_b);
            fixture
                .runtime
                .reconcile_snapshot(fixture.candidate.clone())
                .await
                .expect("repair installs a complete generation");
            let repaired = fixture.wait_heartbeat(observed).await;
            assert_eq!(fixture.pid(), pid);
            assert_eq!(fixture.start_count(), 1);
            assert!(*fixture.runtime.readiness.borrow());
            fixture.exec_probe(true).await;
            runtime_endpoint_probe(
                &fixture.runtime.engine,
                &fixture.runtime.credentials,
                &fixture.endpoint_a,
                None,
            )
            .await;
            runtime_endpoint_probe(
                &fixture.runtime.engine,
                &fixture.runtime.credentials,
                &fixture.endpoint_b,
                Some("cred-B"),
            )
            .await;
            println!(
                "configuration_activation_runtime_observation {}",
                serde_json::json!({"scenario":"rejected-live-posture", "posture":if retains {"retain_last_valid"} else {"fail_closed"},"fault":fault,"pid_before":pid,"pid_after":fixture.pid(),"start_count":fixture.start_count(),"heartbeat_before":before,"heartbeat_after_rejection":observed,"heartbeat_after_repair":repaired,"rejected_ready":retains,"rejected_exec_allowed":retains,"retained_installation":initial,"provider_after_rejection":5,"provider_after_repair":fixture.runtime.credentials.snapshot().revision,"ready_after_repair":*fixture.runtime.readiness.borrow(),"probe_origin":"actual-coordinator-opa-and-provider-state","upstream_a":*fixture.endpoint_a.requests.lock().expect("request lock"),"upstream_b":*fixture.endpoint_b.requests.lock().expect("request lock")})
            );
            fixture.stop().await;
        }
    }
}
