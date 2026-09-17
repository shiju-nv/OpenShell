// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Included alongside the Linux runtime fixture. Gateway delivery is controlled;
// preparation, OPA installation, authenticated boundary transactions, and the
// workload process use the production implementations.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProtocolRuntimeCase {
    Rest,
    Graphql,
    Websocket,
    JsonRpc,
    McpOmitted,
    McpEmptyProto,
    McpRevisions,
}

impl ProtocolRuntimeCase {
    const ALL: [Self; 7] = [
        Self::Rest,
        Self::Graphql,
        Self::Websocket,
        Self::JsonRpc,
        Self::McpOmitted,
        Self::McpEmptyProto,
        Self::McpRevisions,
    ];

    fn protocol(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::Graphql => "graphql",
            Self::Websocket => "websocket",
            Self::JsonRpc => "json-rpc",
            Self::McpOmitted | Self::McpEmptyProto | Self::McpRevisions => "mcp",
        }
    }
}

fn protocol_runtime_endpoint_mut(
    policy: &mut openshell_core::proto::SandboxPolicy,
) -> &mut openshell_core::proto::NetworkEndpoint {
    let rule = policy
        .network_policies
        .get_mut("activation_fixture")
        .expect("controlled network policy");
    assert_eq!(rule.endpoints.len(), 1);
    &mut rule.endpoints[0]
}

fn protocol_runtime_policy(
    base: &openshell_core::proto::SandboxPolicy,
    case: ProtocolRuntimeCase,
) -> openshell_core::proto::SandboxPolicy {
    use openshell_core::proto::{GraphqlOperation, L7Allow, L7QueryMatcher, L7Rule, McpOptions};

    let mut policy = base.clone();
    let endpoint = protocol_runtime_endpoint_mut(&mut policy);
    endpoint.protocol = case.protocol().to_ascii_uppercase();
    endpoint.enforcement = "enforce".into();
    endpoint.access.clear();
    endpoint.path = "/probe".into();
    let mut allow = L7Allow::default();
    match case {
        ProtocolRuntimeCase::Rest | ProtocolRuntimeCase::Websocket => {
            allow.method = "GET".into();
            allow.path = "/probe".into();
            allow.query.insert(
                "view".into(),
                L7QueryMatcher {
                    any: vec!["summary".into(), "detail".into()],
                    ..Default::default()
                },
            );
            endpoint.allow_encoded_slash = true;
            if case == ProtocolRuntimeCase::Rest {
                endpoint.websocket_credential_rewrite = true;
                endpoint.request_body_credential_rewrite = true;
            }
        }
        ProtocolRuntimeCase::Graphql => {
            allow.operation_type = "query".into();
            allow.operation_name = "Status*".into();
            allow.fields = vec!["viewer".into()];
            endpoint.persisted_queries = "allow_registered".into();
            endpoint.graphql_max_body_bytes = 8192;
            endpoint.graphql_persisted_queries.insert(
                "saved-status".into(),
                GraphqlOperation {
                    operation_type: "query".into(),
                    operation_name: "Status".into(),
                    fields: vec!["viewer".into()],
                },
            );
        }
        ProtocolRuntimeCase::JsonRpc => {
            allow.method = "status".into();
            endpoint.json_rpc_max_body_bytes = 8192;
        }
        ProtocolRuntimeCase::McpOmitted
        | ProtocolRuntimeCase::McpEmptyProto
        | ProtocolRuntimeCase::McpRevisions => {
            allow.method = "tools/call".into();
            allow.params.insert(
                "name".into(),
                L7QueryMatcher {
                    glob: "read_status".into(),
                    ..Default::default()
                },
            );
            endpoint.json_rpc_max_body_bytes = 8192;
            endpoint.mcp = match case {
                ProtocolRuntimeCase::McpOmitted => None,
                ProtocolRuntimeCase::McpEmptyProto => Some(McpOptions::default()),
                ProtocolRuntimeCase::McpRevisions => Some(McpOptions {
                    strict_tool_names: Some(false),
                    allow_all_known_mcp_methods: Some(false),
                    versions: vec!["2025-11-25".into(), "2025-03-26".into()],
                }),
                _ => unreachable!("MCP-only branch"),
            };
        }
    }
    endpoint.rules = vec![L7Rule { allow: Some(allow) }];
    policy
}

fn protocol_runtime_invalid_candidates(
    base: &openshell_core::proto::SandboxPolicy,
    case: ProtocolRuntimeCase,
) -> Vec<(&'static str, openshell_core::proto::SandboxPolicy)> {
    use openshell_core::proto::McpOptions;

    if case.protocol() != "mcp" {
        let mut misplaced = base.clone();
        protocol_runtime_endpoint_mut(&mut misplaced).mcp = Some(McpOptions::default());
        let mut invalid_rule = base.clone();
        let allow = protocol_runtime_endpoint_mut(&mut invalid_rule).rules[0]
            .allow
            .as_mut()
            .expect("protocol allow rule");
        let fault = match case {
            ProtocolRuntimeCase::Rest | ProtocolRuntimeCase::Websocket => {
                allow.query.get_mut("view").expect("query matcher").glob = "*".into();
                "conflicting-query-matchers"
            }
            ProtocolRuntimeCase::Graphql => {
                allow.operation_type = "invalid".into();
                "invalid-graphql-operation"
            }
            ProtocolRuntimeCase::JsonRpc => {
                allow.params.insert(
                    "name".into(),
                    openshell_core::proto::L7QueryMatcher {
                        glob: "read_status".into(),
                        ..Default::default()
                    },
                );
                "json-rpc-params-matcher"
            }
            _ => unreachable!("non-MCP branch"),
        };
        return vec![("misplaced-mcp-options", misplaced), (fault, invalid_rule)];
    }
    // These positive variants share the same MCP validator. The omitted case
    // exercises its rejection matrix once per startup/update posture.
    if case != ProtocolRuntimeCase::McpOmitted {
        return Vec::new();
    }
    [
        ("empty-revision", vec![""]),
        ("duplicate-revision", vec!["2025-11-25", "2025-11-25"]),
        ("padded-revision", vec![" 2025-11-25"]),
        ("unsupported-revision", vec!["2099-01-01"]),
        ("draft-revision", vec!["draft"]),
    ]
    .into_iter()
    .map(|(name, versions)| {
        let mut policy = base.clone();
        protocol_runtime_endpoint_mut(&mut policy).mcp = Some(McpOptions {
            versions: versions.into_iter().map(str::to_owned).collect(),
            ..Default::default()
        });
        (name, policy)
    })
    .collect()
}

fn protocol_runtime_assert_installed(
    engine: &OpaEngine,
    case: ProtocolRuntimeCase,
    port: u16,
) -> serde_json::Value {
    let input = openshell_supervisor_network::opa::NetworkInput {
        host: "127.0.0.1".into(),
        port,
        binary_path: "/bin/sh".into(),
        binary_sha256: "fixture-binary".into(),
        ancestors: Vec::new(),
        cmdline_paths: Vec::new(),
    };
    let config = engine
        .query_endpoint_config(&input)
        .expect("installed endpoint query")
        .expect("installed L7 endpoint");
    let typed = openshell_supervisor_network::l7::parse_l7_config(&config)
        .expect("installed typed L7 configuration");
    let value = serde_json::to_value(config).expect("serializable endpoint configuration");
    assert_eq!(value["protocol"], case.protocol());
    assert_eq!(value["path"], "/probe");
    assert_eq!(value["enforcement"], "enforce");
    let allow = &value["rules"][0]["allow"];
    match case {
        ProtocolRuntimeCase::Rest | ProtocolRuntimeCase::Websocket => {
            assert_eq!(allow["method"], "GET");
            assert_eq!(allow["path"], "/probe");
            assert_eq!(
                allow["query"]["view"]["any"],
                serde_json::json!(["summary", "detail"])
            );
            assert!(typed.allow_encoded_slash);
            assert_eq!(
                typed.websocket_credential_rewrite,
                case == ProtocolRuntimeCase::Rest
            );
            assert_eq!(
                typed.request_body_credential_rewrite,
                case == ProtocolRuntimeCase::Rest
            );
        }
        ProtocolRuntimeCase::Graphql => {
            assert_eq!(allow["operation_type"], "query");
            assert_eq!(allow["operation_name"], "Status*");
            assert_eq!(allow["fields"], serde_json::json!(["viewer"]));
            assert_eq!(typed.graphql_max_body_bytes, 8192);
            assert_eq!(value["persisted_queries"], "allow_registered");
            assert_eq!(
                value["graphql_persisted_queries"]["saved-status"],
                serde_json::json!({"operation_type":"query", "operation_name":"Status", "fields":["viewer"]})
            );
        }
        ProtocolRuntimeCase::JsonRpc => {
            assert_eq!(allow["method"], "status");
            assert_eq!(typed.json_rpc_max_body_bytes, 8192);
        }
        ProtocolRuntimeCase::McpOmitted
        | ProtocolRuntimeCase::McpEmptyProto
        | ProtocolRuntimeCase::McpRevisions => {
            assert_eq!(allow["method"], "tools/call");
            assert_eq!(allow["params"]["name"]["glob"], "read_status");
            assert_eq!(typed.json_rpc_max_body_bytes, 8192);
            let expected = if case == ProtocolRuntimeCase::McpRevisions {
                serde_json::json!(["2025-03-26", "2025-11-25"])
            } else {
                serde_json::json!(["2025-11-25"])
            };
            assert_eq!(value["mcp_versions"], expected);
            assert_eq!(
                typed.mcp_strict_tool_names,
                case != ProtocolRuntimeCase::McpRevisions
            );
            if case == ProtocolRuntimeCase::McpRevisions {
                assert_eq!(value["mcp_allow_all_known_mcp_methods"], false);
            }
        }
    }
    if case.protocol() != "mcp" {
        assert!(typed.mcp_versions.is_empty());
        assert!(value.get("mcp_versions").is_none());
        assert!(value.get("mcp_strict_tool_names").is_none());
        assert!(value.get("mcp_allow_all_known_mcp_methods").is_none());
    }
    value
}

struct ProtocolRuntimeStartup {
    process: RuntimeBoundaryProcess,
    ready: Box<dyn openshell_isolation_interface::contract::ReadyBoundary>,
    bootstrap: BoundaryBootstrap,
    initial: SettingsPollResult,
    credentials: ProviderCredentialState,
    endpoint_a: RuntimeEndpoint,
    endpoint_b: RuntimeEndpoint,
}

struct ProtocolRuntimePrepared {
    session: ConfigurationSession,
    gateway: Arc<RuntimeDelivery>,
    configuration: PreparedConfiguration,
    observations: Vec<serde_json::Value>,
}

fn protocol_runtime_delivery(
    initial: &SettingsPollResult,
    offset: usize,
    label: &str,
    policy: openshell_core::proto::SandboxPolicy,
) -> SettingsPollResult {
    let mut snapshot = initial.clone();
    snapshot.config_revision += u64::try_from(offset).expect("bounded case offset");
    snapshot.version += u32::try_from(offset).expect("bounded case offset");
    snapshot.configuration_delivery_revision += u64::try_from(offset).expect("bounded case offset");
    snapshot.configuration_snapshot = format!("protocol-delivery-{label}");
    snapshot.policy_hash = format!("protocol-policy-{label}");
    snapshot.policy = Some(policy);
    snapshot
}

fn protocol_runtime_report_tail(
    gateway: &RuntimeDelivery,
    before: usize,
    expected: &SettingsPollResult,
    identity: &ConfigurationActivationIdentity,
    state: ConfigurationAdmissionState,
) -> Vec<serde_json::Value> {
    let reports = gateway.reports.lock().expect("reports lock");
    let appended = reports
        .get(before..)
        .expect("append-only admission reports");
    assert!(
        !appended.is_empty(),
        "the current attempt did not report admission"
    );
    let policy_source: i32 = expected.policy_source.into();
    for report in appended {
        assert_eq!(report.state, i32::from(state));
        assert_eq!(report.instance_id, expected.configuration_instance_id);
        assert_eq!(report.policy_version, expected.version);
        assert_eq!(report.policy_hash, expected.policy_hash);
        assert_eq!(report.config_revision, expected.config_revision);
        assert_eq!(report.provider_env_revision, expected.provider_env_revision);
        assert_eq!(report.runtime_generation, expected.runtime_generation);
        assert_eq!(
            report.boundary_instance_id,
            expected.configuration_boundary_instance_id
        );
        assert_eq!(report.boundary_session_id, identity.boundary_session_id);
        assert_eq!(report.policy_source, policy_source);
        assert_eq!(
            report.configuration_snapshot,
            expected.configuration_snapshot
        );
        assert_eq!(
            report.registration_revision,
            expected.configuration_registration_revision
        );
        assert_eq!(
            report.delivery_revision,
            expected.configuration_delivery_revision
        );
        if state == ConfigurationAdmissionState::Rejected {
            assert!(!report.activation_confirmed);
            assert!(!report.error.is_empty());
        } else {
            assert!(report.error.is_empty());
        }
    }
    if state == ConfigurationAdmissionState::Accepted {
        // Acceptance is reported once installation completes and then confirmed
        // after release/start. An older report cannot satisfy either transition.
        assert!(
            !appended
                .first()
                .expect("nonempty reports")
                .activation_confirmed
        );
        assert!(
            appended
                .last()
                .expect("nonempty reports")
                .activation_confirmed
        );
        assert!(
            appended
                .windows(2)
                .all(|pair| !pair[0].activation_confirmed || pair[1].activation_confirmed)
        );
    }
    // Validate the typed receipt before projecting every wire field. Generated
    // admission messages intentionally do not provide a serialization contract.
    appended
        .iter()
        .map(|report| {
            serde_json::json!({
                "instance_id": report.instance_id,
                "state": report.state,
                "policy_version": report.policy_version,
                "policy_hash": report.policy_hash,
                "config_revision": report.config_revision,
                "provider_env_revision": report.provider_env_revision,
                "error": report.error,
                "runtime_generation": report.runtime_generation,
                "boundary_instance_id": report.boundary_instance_id,
                "boundary_session_id": report.boundary_session_id,
                "policy_source": report.policy_source,
                "configuration_snapshot": report.configuration_snapshot,
                "activation_confirmed": report.activation_confirmed,
                "registration_revision": report.registration_revision,
                "delivery_revision": report.delivery_revision,
            })
        })
        .collect()
}

fn protocol_runtime_workload_pids(directory: &std::path::Path) -> Vec<u32> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("process census") {
        let entry = entry.expect("process entry");
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let command = match std::fs::read(entry.path().join("cmdline")) {
            Ok(command) => command,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("cannot inspect process {pid}: {error}"),
        };
        // Match the actual shell argv, independently of marker-file writes.
        // A failed census is a proof failure, never evidence of zero children.
        let argv: Vec<_> = command.split(|byte| *byte == 0).collect();
        if argv.windows(2).any(|pair| {
            pair[0] == b"configuration-workload" && pair[1] == directory.as_os_str().as_bytes()
        }) {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps rejected deliveries and their one eventual prepared result on the same startup future"
)]
// Retain ownership across validation awaits: the ready boundary is Send,
// but need not be Sync. Return the same startup state for launch afterward.
async fn protocol_runtime_validate_startup(
    case: ProtocolRuntimeCase,
    validate_faults: bool,
    input: ProtocolRuntimeStartup,
) -> (ProtocolRuntimePrepared, ProtocolRuntimeStartup) {
    let actual = input.ready.configuration();
    let identity = actual.identity();
    let mut policy = input
        .initial
        .policy
        .clone()
        .expect("initial protocol policy");
    enrich_from_boundary(&mut policy, &input.bootstrap);
    let faults = if validate_faults {
        protocol_runtime_invalid_candidates(&policy, case)
    } else {
        Vec::new()
    };
    let valid = protocol_runtime_delivery(
        &input.initial,
        faults.len(),
        &format!("startup-{case:?}-valid"),
        policy,
    );
    let rejected: Vec<_> = faults
        .into_iter()
        .enumerate()
        .map(|(offset, (fault, policy))| {
            (
                fault,
                protocol_runtime_delivery(
                    &input.initial,
                    offset,
                    &format!("startup-{case:?}-{fault}"),
                    policy,
                ),
            )
        })
        .collect();
    let gateway = Arc::new(RuntimeDelivery {
        snapshot: Mutex::new(
            rejected
                .first()
                .map_or_else(|| valid.clone(), |(_, snapshot)| snapshot.clone()),
        ),
        providers: Mutex::new(runtime_provider(5, input.endpoint_a.port, "cred-A")),
        reports: Mutex::new(Vec::new()),
    });
    let session = ConfigurationSession {
        gateway: gateway.clone(),
        instance_id: identity.supervisor_instance_id.clone(),
        runtime_generation: identity.runtime_generation.clone(),
        identity: Some(identity.clone()),
        startup_pending: true,
        startup_failures: AtomicU32::new(0),
    };
    let connector = super::super::default_middleware_connector();
    let mut observations = Vec::new();
    let configuration = {
        let preparation = session.prepare_startup(&input.bootstrap, &connector);
        tokio::pin!(preparation);
        let mut before = 0;
        for (index, (fault, snapshot)) in rejected.iter().enumerate() {
            let deadline = tokio::time::sleep(Duration::from_secs(5));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    result = &mut preparation => panic!("invalid {case:?}/{fault} escaped startup validation: {}", result.is_ok()),
                    () = &mut deadline => panic!("startup rejection was not reported for {case:?}/{fault}"),
                    () = tokio::time::sleep(Duration::from_millis(10)) => {
                        if gateway.reports.lock().expect("reports lock").len() > before { break; }
                    }
                }
            }
            let reports = protocol_runtime_report_tail(
                &gateway,
                before,
                snapshot,
                &identity,
                ConfigurationAdmissionState::Rejected,
            );
            before += reports.len();
            let observed = actual
                .snapshot()
                .await
                .expect("actual held boundary snapshot");
            assert!(!observed.active);
            assert!(observed.installed.is_none());
            assert!(!*actual.readiness().borrow());
            let directory = input.process.directory.path();
            let census = protocol_runtime_workload_pids(directory);
            assert!(census.is_empty());
            assert!(!directory.join("starts").exists());
            assert!(!directory.join("heartbeat").exists());
            assert!(
                input
                    .endpoint_a
                    .requests
                    .lock()
                    .expect("upstream requests")
                    .is_empty()
            );
            observations.push(serde_json::json!({"phase":"startup-rejected-and-repaired", "protocol":case.protocol(), "case":format!("{case:?}"), "fault":fault, "boundary":observed, "starts_before_commit":0, "workload_processes_before_commit":census, "upstream_requests":0, "reports":reports, "delivery":"controlled", "transport":"actual-authenticated-boundary"}));
            *gateway.snapshot.lock().expect("delivery lock") = rejected
                .get(index + 1)
                .map_or_else(|| valid.clone(), |(_, snapshot)| snapshot.clone());
        }
        tokio::time::timeout(Duration::from_secs(5), preparation)
            .await
            .expect("startup repair completed")
            .expect("valid repaired startup")
    };
    assert_eq!(revision(&configuration.snapshot), revision(&valid));
    assert_eq!(
        configuration.snapshot.configuration_snapshot,
        valid.configuration_snapshot
    );
    protocol_runtime_assert_installed(&configuration.engine, case, input.endpoint_a.port);
    assert!(
        actual
            .snapshot()
            .await
            .expect("precommit snapshot")
            .installed
            .is_none()
    );
    assert!(protocol_runtime_workload_pids(input.process.directory.path()).is_empty());
    (
        ProtocolRuntimePrepared {
            session,
            gateway,
            configuration,
            observations,
        },
        input,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "constructs a real startup coordinator from the exact repaired preparation"
)]
async fn protocol_runtime_start_fixture(
    case: ProtocolRuntimeCase,
    validate_faults: bool,
    input: ProtocolRuntimeStartup,
) -> RuntimeProcessFixture {
    let (
        ProtocolRuntimePrepared {
            session,
            gateway,
            mut configuration,
            observations,
        },
        mut input,
    ) = protocol_runtime_validate_startup(case, validate_faults, input).await;
    input
        .ready
        .update_startup_policy(configuration.policy.clone())
        .await
        .expect("install repaired process policy before launch");
    configuration
        .install_startup_registry()
        .expect("install repaired middleware registry");
    // The backend already holds a clone of this credential store. Publish the
    // prepared values into that same store before startup consumes its child env.
    input
        .credentials
        .install_prepared(&configuration.credentials);
    let boundary = Arc::new(PausedRuntimeBoundary {
        actual: input.ready.configuration(),
        armed: AtomicBool::new(false),
        prepared: tokio::sync::Notify::new(),
        proceed: tokio::sync::Notify::new(),
    });
    let (readiness, _) = watch::channel(false);
    let (workspace, _) = watch::channel(String::new());
    let mut runtime = RuntimeConfiguration {
        session,
        boundary: boundary.clone(),
        snapshot: configuration.snapshot,
        engine: Arc::new(configuration.engine),
        credentials: input.credentials,
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
    let before = gateway.reports.lock().expect("reports lock").len();
    let running = runtime.start_workload(input.ready, &input.bootstrap).await.expect("production startup installs, releases, starts, and confirms the repaired configuration");
    let accepted = protocol_runtime_report_tail(
        &gateway,
        before,
        &runtime.snapshot,
        &boundary.identity(),
        ConfigurationAdmissionState::Accepted,
    );
    let state = boundary
        .snapshot()
        .await
        .expect("accepted startup boundary");
    assert!(state.active);
    assert_eq!(state.installed, Some(revision(&runtime.snapshot)));
    let candidate = protocol_runtime_delivery(
        &runtime.snapshot,
        1,
        &format!("update-{case:?}-valid"),
        runtime_policy(input.process.directory.path(), "b", input.endpoint_b.port),
    );
    let mut candidate = candidate;
    candidate.provider_env_revision = 6;
    let provider_b = runtime_provider(6, input.endpoint_b.port, "cred-B");
    *gateway.snapshot.lock().expect("delivery lock") = candidate.clone();
    *gateway.providers.lock().expect("provider lock") = copy_runtime_provider(&provider_b);
    let fixture = RuntimeProcessFixture {
        process: input.process,
        running,
        boundary,
        gateway,
        runtime,
        candidate,
        provider_b,
        endpoint_a: input.endpoint_a,
        endpoint_b: input.endpoint_b,
    };
    fixture.wait_heartbeat(0).await;
    assert_eq!(fixture.start_count(), 1);
    assert_eq!(
        protocol_runtime_workload_pids(fixture.process.directory.path()),
        [fixture.pid()]
    );
    for mut observation in observations {
        observation["repaired_installation"] =
            serde_json::to_value(&state).expect("startup state JSON");
        observation["accepted_reports"] = serde_json::to_value(&accepted).expect("admission JSON");
        println!("configuration_protocol_runtime_observation {observation}");
    }
    fixture
}

fn protocol_runtime_start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("live process stat");
    // The parenthesized executable name can contain spaces or closing
    // parentheses. The final delimiter precedes field 3; starttime is field 22.
    stat.rsplit_once(')')
        .expect("process name delimiter")
        .1
        .split_whitespace()
        .nth(19)
        .expect("process starttime field")
        .parse()
        .expect("numeric process starttime")
}

#[test]
fn configuration_activation_protocol_authored_empty_is_not_proto_omission() {
    let omitted = "version: 1\nnetwork_policies:\n  activation_fixture:\n    endpoints:\n      - host: example.com\n        port: 443\n        protocol: mcp\n        rules: [{allow: {method: tools/list}}]\n    binaries: [{path: /bin/sh}]\n";
    let lowered = openshell_policy::parse_sandbox_policy(omitted).expect("authored omission");
    let endpoint = &lowered.network_policies["activation_fixture"].endpoints[0];
    assert_eq!(
        endpoint
            .mcp
            .as_ref()
            .expect("materialized MCP options")
            .versions,
        ["2025-11-25"]
    );
    let explicit_empty = omitted.replace(
        "        protocol: mcp\n",
        "        protocol: mcp\n        mcp: {versions: []}\n",
    );
    assert!(
        openshell_policy::parse_sandbox_policy(&explicit_empty).is_err(),
        "authored empty arrays must fail before protobuf erases list presence"
    );
    for mcp in [None, Some(openshell_core::proto::McpOptions::default())] {
        let mut protobuf = lowered.clone();
        protocol_runtime_endpoint_mut(&mut protobuf).mcp = mcp;
        assert!(
            OpaEngine::from_proto(&protobuf).is_ok(),
            "an absent or empty protobuf repeated field has the pinned default"
        );
    }
}

#[tokio::test]
#[ignore = "requires the candidate boundary executable and isolated Linux fixture"]
async fn configuration_activation_protocol_startup_matrix() {
    for case in ProtocolRuntimeCase::ALL {
        let fixture = Box::pin(RuntimeProcessFixture::new_with_protocol_case(
            Some(&case),
            true,
        ))
        .await;
        assert_eq!(fixture.start_count(), 1);
        let state = fixture
            .boundary
            .snapshot()
            .await
            .expect("activated boundary");
        assert!(state.active);
        assert_eq!(state.installed, Some(revision(&fixture.runtime.snapshot)));
        let installed = protocol_runtime_assert_installed(
            &fixture.runtime.engine,
            case,
            fixture.endpoint_a.port,
        );
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
        fixture.exec_probe(true).await;
        let first_accepted = fixture
            .gateway
            .reports
            .lock()
            .expect("reports lock")
            .iter()
            .position(|report| report.state == i32::from(ConfigurationAdmissionState::Accepted))
            .expect("startup acceptance report");
        let accepted = protocol_runtime_report_tail(
            &fixture.gateway,
            first_accepted,
            &fixture.runtime.snapshot,
            &fixture.boundary.identity(),
            ConfigurationAdmissionState::Accepted,
        );
        println!(
            "configuration_protocol_runtime_observation {}",
            serde_json::json!({"phase":"startup-activated", "case":format!("{case:?}"), "installed":installed, "boundary":state, "accepted_reports":accepted, "pid":fixture.pid(), "start_ticks":protocol_runtime_start_ticks(fixture.pid()), "starts":fixture.start_count(), "upstream":*fixture.endpoint_a.requests.lock().expect("upstream requests"), "probe_scope":"installed-network-decision-and-credential-rewrite"})
        );
        fixture.stop().await;
    }
}

#[tokio::test]
#[ignore = "requires the candidate boundary executable and isolated Linux fixture"]
#[allow(
    clippy::too_many_lines,
    reason = "keeps rejection posture and repair observations bound to the same live child"
)]
async fn configuration_activation_protocol_update_matrix() {
    for case in ProtocolRuntimeCase::ALL {
        for mode in [
            openshell_core::PolicyValidationFailureMode::RetainLastValid,
            openshell_core::PolicyValidationFailureMode::FailClosed,
        ] {
            let mut fixture = Box::pin(RuntimeProcessFixture::new_with_protocol_case(
                Some(&case),
                false,
            ))
            .await;
            let initial = revision(&fixture.runtime.snapshot);
            let pid = fixture.pid();
            let start_ticks = protocol_runtime_start_ticks(pid);
            let before = protocol_runtime_assert_installed(
                &fixture.runtime.engine,
                case,
                fixture.endpoint_a.port,
            );
            let valid = protocol_runtime_policy(
                fixture.candidate.policy.as_ref().expect("candidate policy"),
                case,
            );
            fixture.candidate.policy = Some(valid.clone());
            let retains = mode == openshell_core::PolicyValidationFailureMode::RetainLastValid;
            let faults = protocol_runtime_invalid_candidates(&valid, case);
            let repaired = protocol_runtime_delivery(
                &fixture.candidate,
                faults.len(),
                &format!("update-{case:?}-repaired"),
                valid,
            );
            for (offset, (fault, invalid)) in faults.into_iter().enumerate() {
                let mut candidate = protocol_runtime_delivery(
                    &fixture.candidate,
                    offset,
                    &format!("update-{case:?}-{fault}"),
                    invalid,
                );
                candidate.policy_validation_failure_mode = mode;
                let report_count = fixture.gateway.reports.lock().expect("reports lock").len();
                fixture
                    .runtime
                    .reconcile_snapshot(candidate.clone())
                    .await
                    .expect("repairable protocol rejection");
                let reports = protocol_runtime_report_tail(
                    &fixture.gateway,
                    report_count,
                    &candidate,
                    &fixture.boundary.identity(),
                    ConfigurationAdmissionState::Rejected,
                );
                assert_eq!(*fixture.runtime.readiness.borrow(), retains);
                assert_eq!(fixture.runtime.credentials.snapshot().revision, 5);
                assert_eq!(revision(&fixture.runtime.snapshot), initial);
                let state = fixture
                    .boundary
                    .snapshot()
                    .await
                    .expect("boundary snapshot after rejection");
                assert_eq!(state.installed, Some(initial.clone()));
                assert_eq!(state.active, retains);
                assert_eq!(
                    protocol_runtime_assert_installed(
                        &fixture.runtime.engine,
                        case,
                        fixture.endpoint_a.port
                    ),
                    before
                );
                let beat = if retains {
                    fixture.exec_probe(true).await;
                    fixture.wait_heartbeat(fixture.heartbeat()).await
                } else {
                    fixture.assert_held().await
                };
                assert_eq!(fixture.pid(), pid);
                assert_eq!(protocol_runtime_start_ticks(pid), start_ticks);
                assert_eq!(fixture.start_count(), 1);
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
                println!(
                    "configuration_protocol_runtime_observation {}",
                    serde_json::json!({"phase":"update-rejected", "case":format!("{case:?}"), "fault":fault, "retains":retains, "boundary":state, "pid":pid, "start_ticks":start_ticks, "starts":fixture.start_count(), "heartbeat":beat, "provider_revision":fixture.runtime.credentials.snapshot().revision, "reports":reports})
                );
            }
            let beat = fixture.heartbeat();
            fixture.candidate = repaired;
            let report_count = fixture.gateway.reports.lock().expect("reports lock").len();
            fixture
                .runtime
                .reconcile_snapshot(fixture.candidate.clone())
                .await
                .expect("valid protocol repair");
            let reports = protocol_runtime_report_tail(
                &fixture.gateway,
                report_count,
                &fixture.candidate,
                &fixture.boundary.identity(),
                ConfigurationAdmissionState::Accepted,
            );
            fixture.wait_heartbeat(beat).await;
            assert_eq!(fixture.pid(), pid);
            assert_eq!(protocol_runtime_start_ticks(pid), start_ticks);
            assert_eq!(fixture.start_count(), 1);
            assert!(*fixture.runtime.readiness.borrow());
            fixture.exec_probe(true).await;
            let installed = protocol_runtime_assert_installed(
                &fixture.runtime.engine,
                case,
                fixture.endpoint_b.port,
            );
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
            let state = fixture
                .boundary
                .snapshot()
                .await
                .expect("repaired boundary snapshot");
            assert!(state.active);
            assert_eq!(state.installed, Some(revision(&fixture.candidate)));
            assert_eq!(fixture.runtime.credentials.snapshot().revision, 6);
            println!(
                "configuration_protocol_runtime_observation {}",
                serde_json::json!({"phase":"update-repaired", "case":format!("{case:?}"), "retains":retains, "boundary":state, "installed":installed, "pid":pid, "start_ticks":start_ticks, "starts":fixture.start_count(), "provider_revision":fixture.runtime.credentials.snapshot().revision, "reports":reports, "upstream":*fixture.endpoint_b.requests.lock().expect("upstream requests"), "probe_scope":"installed-network-decision-and-credential-rewrite"})
            );
            fixture.stop().await;
        }
    }
}
