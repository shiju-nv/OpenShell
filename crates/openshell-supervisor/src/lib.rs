// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` supervisor library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

// `defaults-without-telemetry` is an alias for the default feature set minus
// `telemetry`, not a switch that turns telemetry off. Cargo cannot subtract a
// default feature, so adding it on top of the defaults would otherwise produce
// a telemetry-on build that reads as telemetry-free. Fail the build instead.
#[cfg(all(feature = "telemetry", feature = "defaults-without-telemetry"))]
compile_error!(
    "features `telemetry` and `defaults-without-telemetry` are mutually exclusive; \
     build a telemetry-free supervisor with `--no-default-features --features defaults-without-telemetry`"
);

mod activity_aggregator;
mod configuration;
mod denial_aggregator;
mod endpoint_status;
mod mechanistic_mapper;

use miette::{IntoDiagnostic, Result, WrapErr};
use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::time::Duration;
use tracing::{debug, info, warn};

use openshell_core::PolicyValidationFailureMode;

use openshell_ocsf::{
    ActionId, ActivityId, ConfigStateChangeBuilder, DetectionFindingBuilder, DispositionId,
    EventContext, FindingInfo, OcsfEvent, SeverityId, StateId, StatusId, ocsf_emit,
};

// ---------------------------------------------------------------------------
// OCSF Context
// ---------------------------------------------------------------------------
//
// The following log sites intentionally remain as plain `tracing` macros
// and are NOT migrated to OCSF builders:
//
// - DEBUG/TRACE events (zombie reaping, ip commands, gRPC connects, PTY state)
// - Transient "about to do X" events where the result is logged separately
//   (e.g., "Fetching sandbox policy via gRPC", "Creating OPA engine from proto")
// - Internal SSH channel warnings (unknown channel, PTY resize failures)
// - Denial flush telemetry (the individual denials are already OCSF events)
// - Status reporting failures (sync to gateway, non-actionable)
// - Route refresh interval validation warnings
//
// These are operational plumbing that don't represent security decisions,
// policy changes, or observable sandbox behavior worth structuring.
// ---------------------------------------------------------------------------

/// Re-export the process-wide OCSF sandbox context getter.
///
/// The singleton lives in `openshell-ocsf` so both supervisor leaves can
/// reach it without depending on `openshell-sandbox`. Initialised once during
/// `run_sandbox()` startup via `openshell_ocsf::ctx::set_ctx`.
pub(crate) use openshell_ocsf::ctx::ctx as ocsf_ctx;

async fn retain_remote_access_plane(
    proxy_exited: impl Future<Output = ()>,
    shutdown_requested: impl Future<Output = ()>,
) -> Result<()> {
    tokio::pin!(proxy_exited);
    tokio::pin!(shutdown_requested);
    tokio::select! {
        () = &mut proxy_exited => Err(miette::miette!(
            "control-mode proxy accept loop exited unexpectedly"
        )),
        () = &mut shutdown_requested => Ok(()),
    }
}

async fn completion_phase_or_shutdown<F, S>(phase: F, mut shutdown: Pin<&mut S>) -> bool
where
    F: Future<Output = ()>,
    S: Future<Output = ()> + ?Sized,
{
    tokio::pin!(phase);
    tokio::select! {
        () = &mut phase => false,
        () = &mut shutdown => true,
    }
}

struct ControlReadiness {
    task: tokio::task::JoinHandle<()>,
    path: std::path::PathBuf,
}

impl ControlReadiness {
    fn start(
        path: std::path::PathBuf,
        mut session_readiness: Option<tokio::sync::watch::Receiver<bool>>,
        mut configuration_readiness: Option<tokio::sync::watch::Receiver<bool>>,
        mut boundary_readiness: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> Result<Self> {
        prepare_control_readiness_path(&path)?;
        let initially_ready = readiness_value(&session_readiness)
            && readiness_value(&configuration_readiness)
            && readiness_value(&boundary_readiness);
        let listener = initially_ready
            .then(|| tokio::net::UnixListener::bind(&path))
            .transpose()
            .into_diagnostic()
            .wrap_err_with(|| format!("bind supervisor readiness socket on {}", path.display()))?;
        let task_path = path.clone();
        let task = tokio::spawn(async move {
            let mut listener = listener;
            loop {
                let ready = readiness_value(&session_readiness)
                    && readiness_value(&configuration_readiness)
                    && readiness_value(&boundary_readiness);
                if !ready {
                    // Session authentication, runtime release, and the final
                    // gateway acknowledgement are independent readiness gates.
                    listener.take();
                    let _ = std::fs::remove_file(&task_path);
                    let changed = tokio::select! {
                        changed = readiness_changed(&mut session_readiness) => changed,
                        changed = readiness_changed(&mut configuration_readiness) => changed,
                        changed = readiness_changed(&mut boundary_readiness) => changed,
                    };
                    if changed.is_err() {
                        break;
                    }
                    continue;
                }
                if listener.is_none() {
                    match prepare_control_readiness_path(&task_path)
                        .and_then(|()| tokio::net::UnixListener::bind(&task_path).into_diagnostic())
                    {
                        Ok(rebound) => listener = Some(rebound),
                        Err(error) => {
                            tracing::warn!(%error, "control-mode readiness rebind failed; retrying");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                }
                let Some(active_listener) = listener.as_ref() else {
                    continue;
                };
                let changed = tokio::select! {
                    accepted = active_listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => drop(stream),
                            Err(error) => {
                                tracing::warn!(%error, "control-mode readiness accept failed; retrying");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                        Ok(())
                    },
                    changed = readiness_changed(&mut session_readiness) => changed,
                    changed = readiness_changed(&mut configuration_readiness) => changed,
                    changed = readiness_changed(&mut boundary_readiness) => changed,
                };
                if changed.is_err() {
                    break;
                }
            }
            let _ = std::fs::remove_file(&task_path);
        });
        Ok(Self { task, path })
    }
}

fn readiness_value(readiness: &Option<tokio::sync::watch::Receiver<bool>>) -> bool {
    readiness
        .as_ref()
        .is_none_or(|readiness| readiness.has_changed().is_ok() && *readiness.borrow())
}

async fn readiness_changed(
    readiness: &mut Option<tokio::sync::watch::Receiver<bool>>,
) -> std::result::Result<(), tokio::sync::watch::error::RecvError> {
    match readiness {
        Some(readiness) => readiness.changed().await,
        None => std::future::pending().await,
    }
}

#[cfg(unix)]
fn prepare_control_readiness_path(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    if !path.is_absolute() {
        return Err(miette::miette!(
            "supervisor readiness socket path must be absolute"
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("create readiness directory {}", parent.display()))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::getuid().as_raw()
            {
                return Err(miette::miette!(
                    "refusing unsafe existing readiness path {}",
                    path.display()
                ));
            }
            std::fs::remove_file(path)
                .into_diagnostic()
                .wrap_err_with(|| format!("remove stale readiness socket {}", path.display()))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .into_diagnostic()
                .wrap_err_with(|| format!("inspect readiness path {}", path.display()));
        }
    }
    Ok(())
}

impl Drop for ControlReadiness {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Check whether the live supervisor owns its private readiness socket.
#[cfg(unix)]
pub fn check_control_readiness(path: &std::path::Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(miette::miette!("health socket path must be absolute"));
    }
    std::os::unix::net::UnixStream::connect(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("connect supervisor readiness socket {}", path.display()))?;
    Ok(())
}

/// Health subcommands are unsupported on non-Unix hosts.
#[cfg(not(unix))]
pub fn check_control_readiness(_path: &std::path::Path) -> Result<()> {
    Err(miette::miette!(
        "supervisor readiness sockets require a Unix host"
    ))
}

#[cfg(unix)]
async fn wait_for_control_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("install control SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install control SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_control_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

use openshell_core::denial::DenialEvent;
use openshell_core::policy::{NetworkMode, NetworkPolicy, ProxyPolicy, SandboxPolicy};
use openshell_core::proposals::AgentProposals;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_supervisor_network::opa::OpaEngine;
use openshell_supervisor_network::proxy::ProxyHandle;
use openshell_supervisor_process::skills;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;

fn shared_ssh_socket_from_env() -> bool {
    std::env::var(openshell_core::sandbox_env::SSH_SOCKET_SHARED)
        .is_ok_and(|value| shared_ssh_socket_value(&value))
}

fn shared_ssh_socket_value(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true")
}

struct PreparedNetworkProxyTlsDir {
    path: std::path::PathBuf,
    _temporary: Option<tempfile::TempDir>,
}

fn prepare_network_proxy_tls_dir(
    requested: Option<std::path::PathBuf>,
) -> Result<PreparedNetworkProxyTlsDir> {
    let Some(requested) = requested else {
        let mut builder = tempfile::Builder::new();
        builder.prefix("openshell-supervisor-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let temporary = builder
            .tempdir()
            .into_diagnostic()
            .wrap_err("create private network-proxy TLS directory")?;
        return Ok(PreparedNetworkProxyTlsDir {
            path: temporary.path().to_path_buf(),
            _temporary: Some(temporary),
        });
    };

    match std::fs::symlink_metadata(&requested) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(miette::miette!(
                "network-proxy TLS directory must not be a symlink: {}",
                requested.display()
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(miette::miette!(
                "network-proxy TLS path is not a directory: {}",
                requested.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;

                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                builder
                    .create(&requested)
                    .into_diagnostic()
                    .wrap_err_with(|| {
                        format!(
                            "create private network-proxy TLS directory {}",
                            requested.display()
                        )
                    })?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir(&requested)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "create private network-proxy TLS directory {}",
                        requested.display()
                    )
                })?;
        }
        Err(error) => return Err(error).into_diagnostic(),
    }

    let path = requested
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "resolve network-proxy TLS directory {}",
                requested.display()
            )
        })?;
    validate_network_proxy_tls_dir(&path)?;
    Ok(PreparedNetworkProxyTlsDir {
        path,
        _temporary: None,
    })
}

#[cfg(unix)]
fn validate_network_proxy_tls_dir(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let effective_uid = nix::unistd::geteuid().as_raw();
    for (index, component) in path.ancestors().enumerate() {
        let metadata = std::fs::metadata(component)
            .into_diagnostic()
            .wrap_err_with(|| format!("inspect TLS directory component {}", component.display()))?;
        let mode = metadata.mode();
        if !metadata.is_dir() {
            return Err(miette::miette!(
                "TLS directory component is not a directory: {}",
                component.display()
            ));
        }
        if metadata.uid() != 0 && metadata.uid() != effective_uid {
            return Err(miette::miette!(
                "TLS directory component is owned by an untrusted user: {}",
                component.display()
            ));
        }
        if index == 0 {
            if metadata.uid() != effective_uid || mode & 0o022 != 0 {
                return Err(miette::miette!(
                    "network-proxy TLS directory must be owned by the current user and not group- or world-writable: {}",
                    component.display()
                ));
            }
        } else if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(miette::miette!(
                "TLS directory has an untrusted writable ancestor: {}",
                component.display()
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_network_proxy_tls_dir(path: &std::path::Path) -> Result<()> {
    if !path.is_dir() {
        return Err(miette::miette!(
            "network-proxy TLS path is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

/// Run the supervisor as an explicit HTTP/CONNECT network proxy.
///
/// This role deliberately bypasses the Isolation Backend: it does not attach
/// a Sandbox Runtime, launch a workload, or claim process and binary identity.
/// It reuses the same local Rego/YAML policy engine and proxy implementation as
/// sandbox supervision.
///
/// # Errors
///
/// Returns an error when policy loading or proxy startup fails, or when the
/// proxy accept loop exits unexpectedly.
pub async fn run_network_proxy(
    listen: std::net::SocketAddr,
    policy_rules: String,
    policy_data: String,
    tls_dir: Option<std::path::PathBuf>,
    upstream_proxy_args: openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs,
) -> Result<i32> {
    if !listen.ip().is_loopback() {
        return Err(miette::miette!(
            "network-proxy listener must use a loopback address: {listen}"
        ));
    }

    let hostname = std::fs::read_to_string("/etc/hostname").map_or_else(
        |_| "openshell-supervisor".to_string(),
        |value| value.trim().to_string(),
    );
    if !openshell_ocsf::ctx::set_ctx(EventContext {
        sandbox_id: String::new(),
        sandbox_name: "network-proxy".to_string(),
        container_image: String::new(),
        hostname,
        product_version: openshell_core::VERSION.to_string(),
        proxy_ip: listen.ip(),
        proxy_port: listen.port(),
    }) {
        debug!("OCSF context already initialized, keeping existing");
    }

    let (mut policy, opa_engine) = load_policy(&policy_rules, &policy_data).await?;
    policy.network = NetworkPolicy {
        mode: NetworkMode::Proxy,
        proxy: Some(ProxyPolicy {
            http_addr: Some(listen),
        }),
    };

    let provider_credentials = ProviderCredentialState::from_environment(
        0,
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    );
    let (_, workspace_rx) = tokio::sync::watch::channel(String::new());
    let tls_dir = prepare_network_proxy_tls_dir(tls_dir)?;
    let mut networking = openshell_supervisor_network::run::run_networking(
        &policy,
        None,
        Some(&opa_engine),
        None,
        Arc::new(AtomicU32::new(0)),
        false,
        &provider_credentials,
        None,
        Some("network-proxy"),
        None,
        None,
        None,
        None,
        AgentProposals::new(false),
        workspace_rx,
        &upstream_proxy_args,
        Some(&tls_dir.path),
        None,
        #[cfg(target_os = "linux")]
        None,
        None,
    )
    .await?;

    if let Some((ca_certificate, trust_bundle)) = networking.ca_file_paths.as_ref() {
        info!(
            ca_certificate = %ca_certificate.display(),
            trust_bundle = %trust_bundle.display(),
            "Network-proxy trust files ready"
        );
    }

    let proxy = networking
        .proxy
        .as_mut()
        .ok_or_else(|| miette::miette!("network-proxy role did not start a proxy listener"))?;
    let bound = proxy
        .http_addr()
        .ok_or_else(|| miette::miette!("network-proxy role did not bind an explicit listener"))?;
    let exited = proxy
        .take_exit_receiver()
        .ok_or_else(|| miette::miette!("network-proxy exit monitor is unavailable"))?;
    info!(%bound, "Network-proxy role ready");

    tokio::select! {
        _ = exited => Err(miette::miette!("network-proxy accept loop exited unexpectedly")),
        () = wait_for_control_shutdown_signal() => {
            drop(networking);
            Ok(0)
        }
    }
}

/// Run a command in the sandbox.
///
/// # Errors
///
/// Returns an error if the command fails to start or encounters a fatal error.
#[allow(
    clippy::too_many_arguments,
    clippy::implicit_hasher,
    clippy::similar_names,
    clippy::fn_params_excessive_bools
)]
pub async fn run_sandbox(
    command: Vec<String>,
    workdir: Option<String>,
    timeout_secs: u64,
    interactive: bool,
    await_main_process_attachment: bool,
    sandbox_id: Option<String>,
    sandbox: Option<String>,
    openshell_endpoint: Option<String>,
    policy_rules: Option<String>,
    policy_data: Option<String>,
    ssh_socket_path: Option<String>,
    health_socket_path: Option<std::path::PathBuf>,
    ocsf_enabled: Arc<AtomicBool>,
    upstream_proxy_args: openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs,
    backend_descriptor: openshell_isolation_interface::contract::BackendDescriptor,
    auth_bundle: openshell_core::jwt::SupervisorAuthBundle,
    admitted_isolation_backend: Option<String>,
    main_exit_marker: Option<std::path::PathBuf>,
) -> Result<i32> {
    // An empty command is the versioned scratch-sandbox sentinel. The
    // external supervisor cannot inspect the workload filesystem, so preserve
    // it for openshell-sandbox to resolve against the agent image.
    let (program, args) = command.split_first().map_or_else(
        || (String::new(), Vec::new()),
        |(program, args)| (program.clone(), args.to_vec()),
    );

    // Initialize the process-wide OCSF context early so that events emitted
    // during policy loading (filesystem config, validation) have a context.
    // Proxy IP/port use defaults here; the boundary mediation source carries
    // workload-side connection metadata.
    {
        let hostname = std::fs::read_to_string("/etc/hostname").map_or_else(
            |_| "openshell-sandbox".to_string(),
            |s| s.trim().to_string(),
        );

        if !openshell_ocsf::ctx::set_ctx(EventContext {
            sandbox_id: sandbox_id.clone().unwrap_or_default(),
            sandbox_name: sandbox.as_deref().unwrap_or_default().to_string(),
            container_image: std::env::var("OPENSHELL_CONTAINER_IMAGE").unwrap_or_default(),
            hostname,
            product_version: openshell_core::VERSION.to_string(),
            proxy_ip: std::net::IpAddr::from([127, 0, 0, 1]),
            proxy_port: 3128,
        }) {
            debug!("OCSF context already initialized, keeping existing");
        }
    }

    // Extension credentials are owned by this supervisor and shared by every
    // gateway connection it opens, so the middleware registry's bearer slots
    // and the policy poll loop that rotates them stay the same objects.
    let extension_credentials = openshell_extension_core::ExtensionCredentialStore::new();

    // Gateway authentication and control identity precede every configuration
    // request. The same control ID owns admission, boundary, and access sessions.
    let control_instance =
        openshell_sandbox_backend::boundary_protocol::SupervisorInstanceId::new();
    let control_instance_id = control_instance.to_string();
    let admitted_backend_name = admitted_isolation_backend.ok_or_else(|| {
        miette::miette!("runtime descriptor supplied without an admitted isolation backend")
    })?;
    let runtime_descriptor: openshell_sandbox_backend::boundary_protocol::SandboxRuntimeDescriptor =
        serde_json::from_slice(&backend_descriptor.payload)
            .map_err(|error| miette::miette!("decode sandbox runtime descriptor: {error}"))?;
    if auth_bundle.runtime_generation.as_str() != runtime_descriptor.generation {
        return Err(miette::miette!(
            "supervisor authentication bundle does not match runtime generation"
        ));
    }
    if policy_rules.is_some() || policy_data.is_some() {
        return Err(miette::miette!(
            "Gateway-managed workloads require gateway policy admission; use the network-proxy role for local policy files"
        ));
    }
    let id = sandbox_id
        .as_ref()
        .ok_or_else(|| miette::miette!("Sandbox ID is required for configuration admission"))?;
    let endpoint = openshell_endpoint.as_ref().ok_or_else(|| {
        miette::miette!("Gateway endpoint is required for configuration admission")
    })?;
    let sandbox_name = sandbox
        .as_ref()
        .ok_or_else(|| miette::miette!("Sandbox name is required for configuration admission"))?;
    let sandbox_bearer = openshell_core::grpc_client::install_supervisor_auth_bundle(&auth_bundle)?;
    let provider_credentials = ProviderCredentialState::from_environment(
        0,
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    );
    let ca_file_paths = Arc::new(std::sync::Mutex::new(None));
    let backend: Arc<dyn openshell_isolation_interface::contract::IsolationBackend> =
        Arc::new(openshell_sandbox_backend::OpenShellRuntimeBackend::new(
            ca_file_paths.clone(),
            provider_credentials.clone(),
            sandbox_bearer,
            control_instance,
        ));
    let mut registry = openshell_isolation_interface::contract::BackendRegistry::new();
    registry
        .register(backend)
        .map_err(|error| miette::miette!(error.to_string()))?;
    let (backend, verified) = registry
        .resolve(backend_descriptor.clone(), &admitted_backend_name)
        .map_err(|error| miette::miette!(error.to_string()))?;
    let mut configuration_session = configuration::ConfigurationSession::register(
        endpoint.clone(),
        id.clone(),
        sandbox_name.clone(),
        control_instance_id.clone(),
        runtime_descriptor.generation.clone(),
        extension_credentials.clone(),
    )
    .await?;
    // Discovery is authenticated but cannot attach, unfreeze, or launch a
    // workload. Policy and filesystem facts come from the workload image.
    let bootstrap = backend
        .discover(&verified)
        .await
        .map_err(|error| miette::miette!(error.to_string()))?;
    if bootstrap.workload_identity != runtime_descriptor.workload_identity {
        return Err(miette::miette!(
            "Boundary discovery changed the admitted workload identity"
        ));
    }
    let _ = configuration_session.register_boundary(&bootstrap).await?;
    let connector = default_middleware_connector();
    let workspace = workdir;
    let (mut initial_configuration, bound) = loop {
        let prepared = configuration_session
            .prepare_startup(&bootstrap, &connector)
            .await?;
        // Admission repair can outlive a grant's authentication lifetime.
        // Refresh the same registration before trying to attach the boundary.
        let (registration_grant, registration_revision) =
            configuration_session.registration_grant().await?;
        let (_, verified) = registry
            .resolve(backend_descriptor.clone(), &admitted_backend_name)
            .map_err(|error| miette::miette!(error.to_string()))?;
        let context = openshell_isolation_interface::contract::SandboxContext {
            sandbox_id: id.clone(),
            session_id: runtime_descriptor.session_id,
            policy: prepared.policy.clone(),
            agent: openshell_isolation_interface::AgentSpec {
                program: program.clone(),
                args: args.clone(),
                workdir: workspace.clone(),
                timeout_secs,
                interactive,
            },
            identity: runtime_descriptor.workload_identity.clone(),
            registration_grant,
            registration_revision,
        };
        match backend.attach(verified, context).await {
            Ok(bound) => break (prepared, bound),
            Err(openshell_isolation_interface::contract::BackendError::Configuration(_)) => {
                // Invalid selected image/user policy remains repairable while
                // no workload has consumed launch-time filesystem controls.
                configuration_session
                    .reject_startup(
                        &prepared.snapshot,
                        "Selected process policy does not match the workload identity",
                    )
                    .await?;
            }
            Err(error) => return Err(miette::miette!(error.to_string())),
        }
    };
    initial_configuration.install_startup_registry()?;
    provider_credentials.install_prepared(&initial_configuration.credentials);
    let initial_snapshot = initial_configuration.snapshot;
    let policy = initial_configuration.policy;
    let retained_proto = initial_snapshot.policy.clone();
    let opa_engine = Some(Arc::new(initial_configuration.engine));
    let openshell_endpoint_for_proxy = openshell_endpoint.clone();
    let sandbox_name_for_agg = sandbox.clone();
    let agent_proposals = AgentProposals::new(agent_proposals_enabled_from_settings(
        &initial_snapshot.settings,
    ));
    apply_ocsf_json_setting(&ocsf_enabled, &initial_snapshot.settings);
    let entrypoint_pid = Arc::new(AtomicU32::new(0));
    let boundary_configuration = bound.configuration();
    let remote_boundary = (bound, admitted_backend_name, ca_file_paths);

    // The denial channel is owned by the orchestrator: the proxy (in the
    // networking leaf) and the bypass monitor (in the process leaf) both
    // produce DenialEvents that the denial aggregator (orchestrator-side)
    // consumes via the matching receiver. Both leaves are pure producers;
    // the orchestrator owns the consumer task spawned below.
    let (denial_tx, denial_rx): (Option<UnboundedSender<DenialEvent>>, _) = if sandbox_id.is_some()
    {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // Anonymous activity channel: same orchestrator-owned pattern as the
    // denial channel. The proxy and the bypass monitor both emit per-event
    // activity records; the orchestrator-side aggregator drains, sanitizes,
    // and flushes anonymous summaries to the gateway.
    let (activity_tx, activity_rx) = if sandbox_id.is_some() {
        let (tx, rx) =
            tokio::sync::mpsc::channel(openshell_core::activity::ACTIVITY_EVENT_QUEUE_CAPACITY);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // Endpoint observations are bounded and never backpressure proxied traffic.
    // Reports are authorized by the currently accepted supervisor session.
    let (endpoint_observation_tx, endpoint_status_rx) = if sandbox_id.is_some() {
        let (sender, receiver) = openshell_core::endpoint_status::endpoint_status_channel();
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };
    let (supervisor_session_updates, supervisor_session_id) =
        tokio::sync::watch::channel::<Option<String>>(None);
    endpoint_status::reset(
        endpoint_observation_tx.as_ref(),
        retained_proto.as_ref(),
        &initial_snapshot.policy_hash,
        provider_credentials.snapshot().revision,
    )
    .await;

    // Workspace watch: the policy poll loop learns the workspace from
    // GetSandboxConfig and broadcasts it. Flush tasks and the policy.local
    // API read the current value so proposals target the correct workspace.
    let (workspace_tx, workspace_rx) = tokio::sync::watch::channel(String::new());

    let remote_network_source = remote_boundary.0.network_mediation_source();
    let remote_host_gateway_ip = remote_boundary.0.host_gateway_ip();
    let (remote_ready, backend_name, ca_file_paths) = {
        let (bound, backend_name, ca_file_paths) = remote_boundary;
        let ready = bound
            .confirm()
            .await
            .map_err(|error| miette::miette!(error.to_string()))?;
        info!(backend = %backend_name, "Isolation boundary enforcement confirmed");
        (ready, backend_name, ca_file_paths)
    };

    let mut networking = Some(
        openshell_supervisor_network::run::run_networking(
            &policy,
            None,
            opa_engine.as_ref(),
            retained_proto.as_ref(),
            entrypoint_pid.clone(),
            // The sandbox supplies already-resolved identities across the
            // boundary. The host supervisor cannot inspect its mount or PID
            // namespace, so waiting for a host-visible entrypoint PID would
            // unnecessarily delay DNS and network readiness.
            false,
            &provider_credentials,
            sandbox_id.as_deref(),
            sandbox_name_for_agg.as_deref(),
            openshell_endpoint_for_proxy.as_deref(),
            denial_tx,
            activity_tx,
            endpoint_observation_tx.clone(),
            agent_proposals.clone(),
            workspace_rx.clone(),
            &upstream_proxy_args,
            None,
            remote_host_gateway_ip,
            #[cfg(target_os = "linux")]
            None,
            Some(remote_network_source),
        )
        .await?,
    );

    ca_file_paths
        .lock()
        .map_err(|_| miette::miette!("boundary CA path lock is poisoned"))?
        .clone_from(
            &networking
                .as_ref()
                .and_then(|runtime| runtime.ca_file_paths.clone()),
        );
    let remote_ready = (remote_ready, backend_name);

    // Spawn the denial-aggregator flush task. The aggregator drains proxy
    // denial events, batches them, and ships summaries to the gateway via
    // `SubmitPolicyAnalysis`.
    if let (Some(rx), Some(endpoint)) = (denial_rx, openshell_endpoint_for_proxy.as_deref()) {
        // SubmitPolicyAnalysis resolves by sandbox *name*, not UUID — fall
        // back to the ID when the name isn't set.
        let agg_name = sandbox_name_for_agg
            .clone()
            .or_else(|| sandbox_id.clone())
            .unwrap_or_default();
        let agg_endpoint = endpoint.to_string();
        let flush_interval_secs: u64 = std::env::var("OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        let aggregator = denial_aggregator::DenialAggregator::new(rx, flush_interval_secs);
        let denial_workspace_gate = workspace_rx.clone();
        let denial_workspace_rx = workspace_rx.clone();

        tokio::spawn(async move {
            aggregator
                .run(
                    |summaries| {
                        let endpoint = agg_endpoint.clone();
                        let sandbox_name = agg_name.clone();
                        let workspace = denial_workspace_rx.borrow().clone();
                        async move {
                            if let Err(e) = flush_proposals_to_gateway(
                                &endpoint,
                                &sandbox_name,
                                &workspace,
                                summaries,
                            )
                            .await
                            {
                                warn!(error = %e, "Failed to flush denial summaries to gateway");
                            }
                        }
                    },
                    move || !denial_workspace_gate.borrow().is_empty(),
                )
                .await;
        });
    }

    // Spawn the activity-aggregator flush task. The aggregator drains
    // anonymous activity events from the proxy, sanitizes deny groups,
    // and ships periodic summaries to the gateway.
    if let (Some(rx), Some(endpoint)) = (activity_rx, openshell_endpoint_for_proxy.as_deref()) {
        let agg_name = sandbox_name_for_agg
            .clone()
            .or_else(|| sandbox_id.clone())
            .unwrap_or_default();
        let agg_endpoint = endpoint.to_string();
        let flush_interval_secs = activity_aggregator::activity_flush_interval_secs_from_env(
            std::env::var("OPENSHELL_ACTIVITY_FLUSH_INTERVAL_SECS")
                .ok()
                .as_deref(),
        );

        let aggregator = activity_aggregator::ActivityAggregator::new(rx, flush_interval_secs);
        let activity_workspace_gate = workspace_rx.clone();
        let activity_workspace_rx = workspace_rx.clone();

        tokio::spawn(async move {
            aggregator
                .run(
                    move |summary| {
                        let endpoint = agg_endpoint.clone();
                        let sandbox_name = agg_name.clone();
                        let workspace = activity_workspace_rx.borrow().clone();
                        async move {
                            if let Err(e) = flush_activity_to_gateway(
                                &endpoint,
                                &sandbox_name,
                                &workspace,
                                summary,
                            )
                            .await
                            {
                                warn!(error = %e, "Failed to flush activity summary to gateway");
                            }
                        }
                    },
                    move || !activity_workspace_gate.borrow().is_empty(),
                )
                .await;
        });
    }

    let (configuration_readiness_tx, configuration_readiness_rx) =
        tokio::sync::watch::channel(false);
    // Keep the passive reporter alive through startup repair and retained
    // remote access, then cancel it when this supervisor runtime is dropped.
    let _endpoint_reporter = if let Some(receiver) = endpoint_status_rx {
        let client = openshell_core::grpc_client::CachedOpenShellClient::connect(endpoint).await?;
        Some(endpoint_status::Reporter::start(
            client,
            id.clone(),
            receiver,
            supervisor_session_id,
        ))
    } else {
        None
    };
    let mut configuration_runtime = configuration::RuntimeConfiguration {
        session: configuration_session,
        boundary: boundary_configuration.clone(),
        snapshot: initial_snapshot,
        engine: opa_engine
            .clone()
            .ok_or_else(|| miette::miette!("Configuration engine is unavailable"))?,
        credentials: provider_credentials.clone(),
        readiness: configuration_readiness_tx,
        ocsf_enabled: ocsf_enabled.clone(),
        agent_proposals: agent_proposals.clone(),
        policy_local: networking
            .as_ref()
            .map(|runtime| runtime.policy_local_ctx.clone()),
        workspace: workspace_tx,
        extension_credentials: extension_credentials.clone(),
        connector,
        endpoint_observation_tx,
        interval: Duration::from_secs(
            std::env::var("OPENSHELL_POLICY_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(10),
        ),
    };
    let (confirmed, backend_name) = remote_ready;

    let proxy_exited: Pin<Box<dyn Future<Output = ()> + Send>> = if let Some(rx) = networking
        .as_mut()
        .and_then(|n| n.proxy.as_mut())
        .and_then(ProxyHandle::take_exit_receiver)
    {
        Box::pin(async {
            let _ = rx.await;
        })
    } else {
        Box::pin(std::future::pending())
    };
    tokio::pin!(proxy_exited);

    let exit_code = {
        let running = configuration_runtime
            .start_workload(confirmed.into_boundary(), &bootstrap)
            .await?;
        info!(backend = %backend_name, "Isolation boundary agent started");
        let mut configuration_task = configuration::ConfigurationTask::start(configuration_runtime);
        let agent = running.agent();
        let boundary_access = openshell_supervisor_process::delegated::start_boundary_access(
            control_instance_id.clone(),
            sandbox_id.as_deref(),
            openshell_endpoint.as_deref(),
            ssh_socket_path.as_deref(),
            shared_ssh_socket_from_env(),
            networking
                .as_ref()
                .and_then(|runtime| runtime.ca_file_paths.clone()),
            running.exec(),
            running.loopback_connector(),
            agent.clone(),
            Some(supervisor_session_updates),
        )
        .await?;
        info!(backend = %backend_name, "Control-mode access plane started");
        let mut control_readiness = if let Some(path) = health_socket_path {
            Some(ControlReadiness::start(
                path,
                boundary_access.session_readiness(),
                Some(configuration_readiness_rx),
                Some(boundary_configuration.readiness()),
            )?)
        } else {
            None
        };
        let instance_id = boundary_access.instance_id().to_string();
        let wait_agent = agent.clone();
        let shutdown_requested = wait_for_control_shutdown_signal();
        tokio::pin!(shutdown_requested);
        let wait = async move {
            wait_agent
                .wait()
                .await
                .map(|status| match status {
                    openshell_isolation_interface::contract::BoundaryExitStatus::Exited(code) => {
                        code
                    }
                    openshell_isolation_interface::contract::BoundaryExitStatus::Signaled(
                        signal,
                    ) => 128_i32.saturating_add(signal),
                })
                .map_err(|error| miette::miette!(error.to_string()))
        };
        let (exit_code, mut retain_access) = tokio::select! {
            result = wait => (result?, true),
            result = configuration_task.completion() => {
                return Err(match result {
                    Ok(Err(error)) => error,
                    Ok(Ok(())) => miette::miette!("Configuration reconciliation exited unexpectedly"),
                    Err(error) => miette::miette!("Configuration reconciliation task failed: {error}"),
                });
            }
            () = &mut proxy_exited => {
                let _ = running.terminate().await;
                return Err(miette::miette!(
                    "control-mode proxy accept loop exited unexpectedly"
                ));
            }
            () = &mut shutdown_requested => {
                let _ = agent
                    .signal(openshell_isolation_interface::contract::BoundarySignal::Term)
                    .await;
                let status = if let Ok(result) = timeout(Duration::from_secs(5), agent.wait()).await {
                    result
                } else {
                    let _ = agent.terminate().await;
                    agent.wait().await
                }
                .map_err(|error| miette::miette!(error.to_string()))?;
                let exit_code = match status {
                    openshell_isolation_interface::contract::BoundaryExitStatus::Exited(code) => code,
                    openshell_isolation_interface::contract::BoundaryExitStatus::Signaled(signal) => {
                        128_i32.saturating_add(signal)
                    }
                };
                running
                    .terminate()
                    .await
                    .map_err(|error| miette::miette!(
                        "sandbox did not acknowledge terminal state: {error}"
                    ))?;
                (exit_code, false)
            }
        };
        if !retain_access {
            control_readiness.take();
        }
        boundary_access
            .publish_main_exit(exit_code, await_main_process_attachment)
            .await;
        // `shutdown_requested` has already completed when shutdown won the
        // lifecycle select above and must not be polled again.
        let mut completion_cancelled = !retain_access;
        if retain_access && let Some(marker) = main_exit_marker.as_deref() {
            persist_main_exit_marker(marker, exit_code)
                .into_diagnostic()
                .wrap_err("persist canonical-process completion marker")?;
        }
        if !completion_cancelled
            && let (Some(endpoint), Some(id)) =
                (openshell_endpoint.as_deref(), sandbox_id.as_deref())
        {
            let report = openshell_supervisor_process::delegated::report_main_process_exit(
                endpoint,
                id,
                &instance_id,
                exit_code,
            );
            completion_cancelled =
                completion_phase_or_shutdown(report, shutdown_requested.as_mut()).await;
        }
        if !completion_cancelled {
            let drain = boundary_access.drain_main_terminal_delivery();
            completion_cancelled =
                completion_phase_or_shutdown(drain, shutdown_requested.as_mut()).await;
        }
        if !completion_cancelled
            && let (Some(endpoint), Some(id)) =
                (openshell_endpoint.as_deref(), sandbox_id.as_deref())
        {
            let finalize = openshell_supervisor_process::delegated::finalize_main_process_exit(
                endpoint,
                id,
                &instance_id,
            );
            completion_cancelled =
                completion_phase_or_shutdown(finalize, shutdown_requested.as_mut()).await;
        }
        if completion_cancelled {
            retain_access = false;
            control_readiness.take();
        }
        if retain_access {
            info!(backend = %backend_name, "Canonical process exited; retaining control-mode access plane");
            tokio::select! {
                result = retain_remote_access_plane(&mut proxy_exited, &mut shutdown_requested) => result?,
                result = configuration_task.completion() => {
                    return Err(match result {
                        Ok(Err(error)) => error,
                        Ok(Ok(())) => miette::miette!("Configuration reconciliation exited unexpectedly"),
                        Err(error) => miette::miette!("Configuration reconciliation task failed: {error}"),
                    });
                }
            }
        }
        drop(control_readiness);
        drop(running);
        drop(boundary_access);
        exit_code
    };

    // Drop networking explicitly so proxy tasks tear down before we return.
    drop(networking);

    Ok(exit_code)
}

fn persist_main_exit_marker(path: &std::path::Path, exit_code: i32) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("completion marker has no parent: {}", path.display()),
            )
        })?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("completion marker has no file name: {}", path.display()),
        )
    })?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    writeln!(file, "exit_code={exit_code}")?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    std::fs::File::open(parent)?.sync_all()
}

/// Flush aggregated denial summaries to the gateway via `SubmitPolicyAnalysis`.
async fn flush_proposals_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    workspace: &str,
    summaries: Vec<denial_aggregator::FlushableDenialSummary>,
) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialSummary, L7RequestSample};

    let client = CachedOpenShellClient::connect(endpoint).await?;
    client.set_workspace(workspace.to_string());

    let proto_summaries: Vec<DenialSummary> = summaries
        .into_iter()
        .map(|s| DenialSummary {
            sandbox_id: String::new(),
            host: s.host,
            port: u32::from(s.port),
            binary: s.binary,
            ancestors: s.ancestors,
            deny_reason: s.deny_reason,
            first_seen_time: openshell_core::time::timestamp_from_millis(s.first_seen_ms).ok(),
            last_seen_time: openshell_core::time::timestamp_from_millis(s.last_seen_ms).ok(),
            count: s.count,
            suppressed_count: 0,
            total_count: s.count,
            sample_cmdlines: s.sample_cmdlines,
            binary_sha256: String::new(),
            persistent: false,
            denial_stage: s.denial_stage,
            l7_request_samples: s
                .l7_samples
                .into_iter()
                .map(|l| L7RequestSample {
                    method: l.method,
                    path: l.path,
                    decision: "deny".to_string(),
                    count: l.count,
                })
                .collect(),
            l7_inspection_active: false,
        })
        .collect();

    // Run the mechanistic mapper sandbox-side to generate proposals.
    // The gateway is a thin persistence + validation layer — it never
    // generates proposals itself.
    let proposals = mechanistic_mapper::generate_proposals(&proto_summaries);

    info!(
        sandbox_name = %sandbox_name,
        summaries = proto_summaries.len(),
        proposals = proposals.len(),
        "Flushed denial analysis to gateway"
    );

    client
        .submit_policy_analysis(
            sandbox_name,
            proto_summaries,
            proposals,
            Vec::new(),
            "mechanistic",
        )
        .await?;

    Ok(())
}

/// Flush an anonymous activity summary to the gateway via `SubmitPolicyAnalysis`.
async fn flush_activity_to_gateway(
    endpoint: &str,
    sandbox_name: &str,
    workspace: &str,
    summary: activity_aggregator::FlushableActivitySummary,
) -> Result<()> {
    use openshell_core::grpc_client::CachedOpenShellClient;
    use openshell_core::proto::{DenialGroupCount, NetworkActivitySummary};

    let client = CachedOpenShellClient::connect(endpoint).await?;
    client.set_workspace(workspace.to_string());

    let proto_summary = NetworkActivitySummary {
        network_activity_count: summary.network_activity_count,
        denied_action_count: summary.denied_action_count,
        denials_by_group: summary
            .denials_by_group
            .into_iter()
            .map(|(group, count)| DenialGroupCount {
                deny_group: group,
                denied_count: count,
            })
            .collect(),
    };

    info!(
        sandbox_name = %sandbox_name,
        network_activity_count = proto_summary.network_activity_count,
        denied_action_count = proto_summary.denied_action_count,
        "Flushed activity summary to gateway"
    );

    client
        .submit_policy_analysis(
            sandbox_name,
            Vec::new(),
            Vec::new(),
            vec![proto_summary],
            "activity",
        )
        .await?;

    Ok(())
}

// ============================================================================
// Baseline filesystem path enrichment
// ============================================================================

/// Minimum read-only paths required for a proxy-mode sandbox child process to
/// function: dynamic linker, shared libraries, DNS resolution, CA certs,
/// Python venv, openshell logs, process info, and random bytes.
///
/// `/proc` and `/dev/urandom` are included here for the same reasons they
/// appear in `restrictive_default_policy()`: virtually every process needs
/// them.  Before the Landlock per-path fix (#677) these were effectively free
/// because a missing path silently disabled the entire ruleset; now they must
/// be explicit.
const PROXY_BASELINE_READ_ONLY: &[&str] = &[
    "/usr",
    "/lib",
    "/etc",
    "/app",
    "/var/log",
    "/proc",
    "/dev/urandom",
];

/// Minimum read-write paths required for a proxy-mode sandbox child process.
/// The active workspace is granted separately through `include_workdir`.
// `/dev/null` is opened by common child-process launchers when they construct
// piped or discarded stdio. Without it, tools such as uv report EACCES while
// probing an otherwise executable interpreter under an explicit filesystem
// policy.
const PROXY_BASELINE_READ_WRITE: &[&str] = &["/tmp", "/dev/null"];

/// GPU read-only paths.
///
/// `/run/nvidia-persistenced`: NVML tries to connect to the persistenced
/// socket at init time.  If the directory exists but Landlock denies traversal
/// (EACCES vs ECONNREFUSED), NVML returns `NVML_ERROR_INSUFFICIENT_PERMISSIONS`
/// even though the daemon is optional.  Only read/traversal access is needed.
///
/// `/usr/lib/wsl`: On WSL2, CDI bind-mounts GPU libraries (libdxcore.so,
/// libcuda.so.1.1, etc.) into paths under `/usr/lib/wsl/`.  Although `/usr`
/// is already in `PROXY_BASELINE_READ_ONLY`, individual file bind-mounts may
/// not be covered by the parent-directory Landlock rule when the mount crosses
/// a filesystem boundary.  Listing `/usr/lib/wsl` explicitly ensures traversal
/// is permitted regardless of Landlock's cross-mount behaviour.
const GPU_BASELINE_READ_ONLY: &[&str] = &[
    "/run/nvidia-persistenced",
    "/usr/lib/wsl", // WSL2: CDI-injected GPU library directory
];

/// GPU read-write paths (static).
///
/// `/dev/nvidiactl`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools`,
/// `/dev/nvidia-modeset`: control and UVM devices injected by CDI on native
/// Linux.  Landlock restricts `open(2)` on device files even when DAC allows
/// it; these need read-write because NVML/CUDA opens them with `O_RDWR`.
/// These devices do not exist on WSL2 and will be skipped by the existence
/// check during local baseline enrichment.
///
/// `/dev/dxg`: On WSL2, NVIDIA GPUs are exposed through the DXG kernel driver
/// (DirectX Graphics) rather than the native nvidia* devices.  CDI injects
/// `/dev/dxg` as the sole GPU device node; it does not exist on native Linux
/// and will be skipped there by the existence check.
///
/// `/proc`: CUDA writes to `/proc/<pid>/task/<tid>/comm` during `cuInit()`
/// to set thread names.  Without write access, `cuInit()` returns error 304.
/// Must use `/proc` (not `/proc/self/task`) because Landlock rules bind to
/// inodes and child processes have different procfs inodes than the parent.
///
/// Per-GPU device files (`/dev/nvidia0`, …) are enumerated at runtime by
/// `enumerate_gpu_device_nodes()` since the count varies.
const GPU_BASELINE_READ_WRITE: &[&str] = &[
    "/dev/nvidiactl",
    "/dev/nvidia-uvm",
    "/dev/nvidia-uvm-tools",
    "/dev/nvidia-modeset",
    "/dev/dxg", // WSL2: DXG device (GPU via DirectX kernel driver, injected by CDI)
    "/proc",
];

/// Returns true if GPU devices are present in the container.
///
/// Checks both the native Linux NVIDIA control device (`/dev/nvidiactl`) and
/// the WSL2 DXG device (`/dev/dxg`).  CDI injects exactly one of these
/// depending on the host kernel; the other will not exist.
fn has_gpu_devices() -> bool {
    std::path::Path::new("/dev/nvidiactl").exists() || std::path::Path::new("/dev/dxg").exists()
}

/// Enumerate per-GPU device nodes (`/dev/nvidia0`, `/dev/nvidia1`, …).
fn enumerate_gpu_device_nodes() -> Vec<String> {
    let mut paths = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(suffix) = name.strip_prefix("nvidia") {
                if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                paths.push(entry.path().to_string_lossy().into_owned());
            }
        }
    }
    paths
}

fn push_unique(paths: &mut Vec<String>, path: String) {
    if !paths.iter().any(|p| p == &path) {
        paths.push(path);
    }
}

fn collect_baseline_enrichment_paths(
    include_proxy: bool,
    include_gpu: bool,
    gpu_device_nodes: Vec<String>,
) -> (Vec<String>, Vec<String>) {
    let mut ro = Vec::new();
    let mut rw = Vec::new();

    if include_proxy {
        for &path in PROXY_BASELINE_READ_ONLY {
            push_unique(&mut ro, path.to_string());
        }
        for &path in PROXY_BASELINE_READ_WRITE {
            push_unique(&mut rw, path.to_string());
        }
    }

    if include_gpu {
        for &path in GPU_BASELINE_READ_ONLY {
            push_unique(&mut ro, path.to_string());
        }
        for &path in GPU_BASELINE_READ_WRITE {
            push_unique(&mut rw, path.to_string());
        }
        for path in gpu_device_nodes {
            push_unique(&mut rw, path);
        }
    }

    // A path promoted to read_write (e.g. /proc for GPU) should not also
    // appear in read_only — Landlock handles the overlap correctly but the
    // duplicate is confusing when inspecting the effective policy.
    ro.retain(|p| !rw.contains(p));

    (ro, rw)
}

fn active_baseline_enrichment_paths(include_proxy: bool) -> (Vec<String>, Vec<String>) {
    let include_gpu = has_gpu_devices();
    let gpu_device_nodes = if include_gpu {
        enumerate_gpu_device_nodes()
    } else {
        Vec::new()
    };
    collect_baseline_enrichment_paths(include_proxy, include_gpu, gpu_device_nodes)
}

/// Collect all active baseline paths for tests and diagnostics.
/// Returns `(read_only, read_write)` as owned `String` vecs.
#[cfg(test)]
fn baseline_enrichment_paths() -> (Vec<String>, Vec<String>) {
    active_baseline_enrichment_paths(true)
}

fn enrich_proto_baseline_paths_with<F>(
    proto: &mut openshell_core::proto::SandboxPolicy,
    ro: &[String],
    rw: &[String],
    path_exists: F,
) -> bool
where
    F: Fn(&str) -> bool,
{
    if ro.is_empty() && rw.is_empty() {
        return false;
    }

    let fs = proto
        .filesystem
        .get_or_insert_with(|| openshell_core::proto::FilesystemPolicy {
            include_workdir: true,
            ..Default::default()
        });

    let mut modified = false;
    for path in ro {
        if !fs.read_only.iter().any(|p| p == path) && !fs.read_write.iter().any(|p| p == path) {
            if !path_exists(path) {
                debug!(
                    path,
                    "Baseline read-only path does not exist, skipping enrichment"
                );
                continue;
            }
            fs.read_only.push(path.clone());
            modified = true;
        }
    }
    for path in rw {
        if fs.read_write.iter().any(|p| p == path) {
            continue;
        }
        if !path_exists(path) {
            debug!(
                path,
                "Baseline read-write path does not exist, skipping enrichment"
            );
            continue;
        }
        if fs.read_only.iter().any(|p| p == path) {
            if path == "/proc" {
                info!(
                    path,
                    "Promoting /proc from read-only to read-write for GPU runtime compatibility"
                );
                fs.read_only.retain(|p| p != path);
                fs.read_write.push(path.clone());
                modified = true;
            }
            continue;
        }
        fs.read_write.push(path.clone());
        modified = true;
    }

    modified
}

/// Ensure a `SandboxPolicy` (Rust type) includes the baseline filesystem
/// paths required by proxy-mode sandboxes and GPU runtimes. Used for the
/// local-file code path where no proto is available.
fn enrich_sandbox_baseline_paths(policy: &mut SandboxPolicy) {
    let (ro, rw) =
        active_baseline_enrichment_paths(matches!(policy.network.mode, NetworkMode::Proxy));
    if ro.is_empty() && rw.is_empty() {
        return;
    }

    let mut modified = false;
    for path in &ro {
        let p = std::path::PathBuf::from(path);
        if !policy.filesystem.read_only.contains(&p) && !policy.filesystem.read_write.contains(&p) {
            if !p.exists() {
                debug!(
                    path,
                    "Baseline read-only path does not exist, skipping enrichment"
                );
                continue;
            }
            policy.filesystem.read_only.push(p);
            modified = true;
        }
    }
    for path in &rw {
        let p = std::path::PathBuf::from(path);
        if policy.filesystem.read_only.contains(&p) || policy.filesystem.read_write.contains(&p) {
            continue;
        }
        if !p.exists() {
            debug!(
                path,
                "Baseline read-write path does not exist, skipping enrichment"
            );
            continue;
        }
        policy.filesystem.read_write.push(p);
        modified = true;
    }

    if modified {
        ocsf_emit!(
            ConfigStateChangeBuilder::new(ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "enriched")
                .message("Enriched policy with baseline filesystem paths for proxy mode")
                .build()
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::iter_on_single_items,
    clippy::similar_names,
    clippy::manual_string_new,
    clippy::doc_markdown,
    reason = "Test code: test fixtures often use idiomatic forms not flagged in production."
)]
mod baseline_tests {
    use super::*;
    use openshell_core::policy::{FilesystemPolicy, LandlockPolicy, ProcessPolicy};
    use std::path::PathBuf;

    #[test]
    fn proc_not_in_both_read_only_and_read_write_when_gpu_present() {
        // When GPU devices are present, /proc is promoted to read_write
        // (CUDA needs to write /proc/<pid>/task/<tid>/comm). It should
        // NOT also appear in read_only.
        if !has_gpu_devices() {
            // Can't test GPU dedup without GPU devices; skip silently.
            return;
        }
        let (ro, rw) = baseline_enrichment_paths();
        assert!(
            rw.contains(&"/proc".to_string()),
            "/proc should be in read_write when GPU is present"
        );
        assert!(
            !ro.contains(&"/proc".to_string()),
            "/proc should NOT be in read_only when it is already in read_write"
        );
    }

    #[test]
    fn proc_in_read_only_without_gpu() {
        if has_gpu_devices() {
            // On a GPU host we can't test the non-GPU path; skip silently.
            return;
        }
        let (ro, _rw) = baseline_enrichment_paths();
        assert!(
            ro.contains(&"/proc".to_string()),
            "/proc should be in read_only when GPU is not present"
        );
    }

    #[test]
    fn baseline_read_write_does_not_hardcode_sandbox() {
        let (_ro, rw) = baseline_enrichment_paths();
        assert!(rw.contains(&"/tmp".to_string()));
        assert!(rw.contains(&"/dev/null".to_string()));
        assert!(!rw.contains(&"/sandbox".to_string()));
    }

    #[test]
    fn enumerate_gpu_device_nodes_skips_bare_nvidia() {
        // "nvidia" (without a trailing digit) is a valid /dev entry on some
        // systems but is not a per-GPU device node.  The enumerator must
        // not match it.
        let nodes = enumerate_gpu_device_nodes();
        assert!(
            !nodes.contains(&"/dev/nvidia".to_string()),
            "bare /dev/nvidia should not be enumerated: {nodes:?}"
        );
    }

    #[test]
    fn no_duplicate_paths_in_baseline() {
        let (ro, rw) = baseline_enrichment_paths();
        // No path should appear in both lists.
        for path in &ro {
            assert!(
                !rw.contains(path),
                "path {path} appears in both read_only and read_write"
            );
        }
    }

    #[test]
    fn proto_enrichment_preserves_explicit_read_only_for_baseline_read_write_paths() {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.filesystem = Some(openshell_core::proto::FilesystemPolicy {
            read_only: vec!["/tmp".to_string()],
            read_write: vec![],
            include_workdir: false,
        });
        policy.network_policies.insert(
            "test".into(),
            openshell_core::proto::NetworkPolicyRule {
                name: "test-rule".into(),
                endpoints: vec![openshell_core::proto::NetworkEndpoint {
                    host: "example.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let (ro, rw) = collect_baseline_enrichment_paths(true, false, Vec::new());
        enrich_proto_baseline_paths_with(&mut policy, &ro, &rw, |path| path == "/tmp");

        let filesystem = policy.filesystem.expect("filesystem policy");
        assert!(
            filesystem.read_only.contains(&"/tmp".to_string()),
            "explicit read_only baseline path should be preserved"
        );
        assert!(
            !filesystem.read_write.contains(&"/tmp".to_string()),
            "baseline enrichment must not promote explicit read_only /tmp to read_write"
        );
    }

    #[test]
    fn proto_gpu_enrichment_promotes_proc_without_network_policy() {
        let mut policy = openshell_policy::restrictive_default_policy();
        assert!(
            policy.network_policies.is_empty(),
            "regression setup must exercise the no-network default path"
        );
        let (ro, rw) =
            collect_baseline_enrichment_paths(false, true, vec!["/dev/nvidia0".to_string()]);

        let enriched = enrich_proto_baseline_paths_with(&mut policy, &ro, &rw, |path| {
            matches!(path, "/proc" | "/dev/nvidia0")
        });

        let filesystem = policy.filesystem.expect("filesystem policy");
        assert!(
            enriched,
            "GPU enrichment should not require network policies"
        );
        assert!(
            filesystem.read_write.contains(&"/dev/nvidia0".to_string()),
            "GPU enrichment should add enumerated device nodes without network policies"
        );
        assert!(
            !filesystem.read_only.contains(&"/proc".to_string()),
            "GPU enrichment should remove /proc from read_only"
        );
        assert!(
            filesystem.read_write.contains(&"/proc".to_string()),
            "GPU enrichment should promote /proc to read_write"
        );
    }

    #[test]
    fn gpu_baseline_read_write_contains_dxg() {
        // /dev/dxg must be present so WSL2 sandboxes get the Landlock
        // read-write rule for the CDI-injected DXG device.  The existence
        // check during local baseline enrichment skips it on native Linux.
        assert!(
            GPU_BASELINE_READ_WRITE.contains(&"/dev/dxg"),
            "/dev/dxg must be in GPU_BASELINE_READ_WRITE for WSL2 support"
        );
    }

    #[test]
    fn local_enrichment_preserves_explicit_read_only_for_baseline_read_write_paths() {
        let mut policy = SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only: vec![PathBuf::from("/tmp")],
                read_write: vec![],
                include_workdir: false,
            },
            network: NetworkPolicy {
                mode: NetworkMode::Proxy,
                proxy: Some(ProxyPolicy { http_addr: None }),
            },
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy::default(),
        };

        enrich_sandbox_baseline_paths(&mut policy);

        assert!(
            policy.filesystem.read_only.contains(&PathBuf::from("/tmp")),
            "explicit read_only baseline path should be preserved"
        );
        assert!(
            !policy
                .filesystem
                .read_write
                .contains(&PathBuf::from("/tmp")),
            "baseline enrichment must not promote explicit read_only /tmp to read_write"
        );
    }

    #[test]
    fn gpu_baseline_read_only_contains_usr_lib_wsl() {
        // /usr/lib/wsl must be present so CDI-injected WSL2 GPU library
        // bind-mounts are accessible under Landlock.  Skipped on native Linux.
        assert!(
            GPU_BASELINE_READ_ONLY.contains(&"/usr/lib/wsl"),
            "/usr/lib/wsl must be in GPU_BASELINE_READ_ONLY for WSL2 CDI library paths"
        );
    }

    #[test]
    fn has_gpu_devices_reflects_dxg_or_nvidiactl() {
        // Verify the OR logic: result must match the manual disjunction of
        // the two path checks.  Passes in all environments.
        let nvidiactl = std::path::Path::new("/dev/nvidiactl").exists();
        let dxg = std::path::Path::new("/dev/dxg").exists();
        assert_eq!(
            has_gpu_devices(),
            nvidiactl || dxg,
            "has_gpu_devices() should be true iff /dev/nvidiactl or /dev/dxg exists"
        );
    }
}

/// Returns `true` if the error is transient and worth retrying.
///
/// Walks the `miette::Report` error chain looking for a `tonic::Status`. If
/// found, only the gRPC codes that represent transient failures are retryable.
/// If no `tonic::Status` is present (e.g. a raw connection error), assume the
/// failure is transient.
fn is_retryable_error(err: &miette::Report) -> bool {
    let mut source: Option<&dyn std::error::Error> = Some(err.as_ref());
    while let Some(e) = source {
        if let Some(status) = e.downcast_ref::<tonic::Status>() {
            return matches!(
                status.code(),
                tonic::Code::Unavailable
                    | tonic::Code::DeadlineExceeded
                    | tonic::Code::ResourceExhausted
                    | tonic::Code::Aborted
                    | tonic::Code::Internal
                    | tonic::Code::Unknown
            );
        }
        source = e.source();
    }
    true
}

/// Load the standalone endpoint-only proxy from explicit local policy files.
///
/// Managed workloads obtain their policy through configuration admission;
/// this role has no gateway configuration or provider environment to acknowledge.
async fn load_policy(
    policy_rules: &str,
    policy_data: &str,
) -> Result<(SandboxPolicy, Arc<OpaEngine>)> {
    ocsf_emit!(ConfigStateChangeBuilder::new(ocsf_ctx())
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .state(StateId::Other, "loading")
        .unmapped("policy_rules", serde_json::json!(policy_rules))
        .unmapped("policy_data", serde_json::json!(policy_data))
        .message(format!(
            "Loading OPA policy engine from local files [rules:{policy_rules} data:{policy_data}]"
        ))
        .build());
    let validate_middleware_config = |implementation: &str, config: &prost_types::Struct| {
        openshell_supervisor_middleware_builtins::validate_config(implementation, config)
            .map_err(|error| error.to_string())
    };
    let engine = OpaEngine::from_files_for_endpoint_only_proxy(
        std::path::Path::new(policy_rules),
        std::path::Path::new(policy_data),
        Some(&validate_middleware_config),
    )?;
    install_builtin_middleware_registry(&engine).await?;
    let config = engine.query_sandbox_config()?;
    let mut policy = SandboxPolicy {
        version: 1,
        filesystem: config.filesystem,
        network: NetworkPolicy {
            mode: NetworkMode::Proxy,
            proxy: Some(ProxyPolicy { http_addr: None }),
        },
        landlock: config.landlock,
        process: config.process,
    };
    enrich_sandbox_baseline_paths(&mut policy);
    Ok((policy, Arc::new(engine)))
}

type MiddlewareConnector = Arc<
    dyn Fn(
            Vec<openshell_core::proto::SupervisorMiddlewareService>,
            MiddlewareAuthentication,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<openshell_supervisor_middleware::MiddlewareRegistry>,
                    > + Send,
            >,
        > + Send
        + Sync,
>;

#[derive(Clone, Default)]
struct MiddlewareAuthentication {
    credentials: std::collections::HashMap<String, openshell_extension_core::BearerTokenSlot>,
    enabled: bool,
}

fn default_middleware_connector() -> MiddlewareConnector {
    Arc::new(|services, authentication| {
        Box::pin(async move { connect_middleware_registry(&services, &authentication).await })
    })
}

async fn connect_middleware_registry(
    services: &[openshell_core::proto::SupervisorMiddlewareService],
    authentication: &MiddlewareAuthentication,
) -> Result<openshell_supervisor_middleware::MiddlewareRegistry> {
    if authentication.enabled {
        openshell_supervisor_middleware::MiddlewareRegistry::connect_services_authenticated(
            openshell_supervisor_middleware_builtins::services(),
            services.to_vec(),
            &authentication.credentials,
        )
        .await
    } else {
        openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            services.to_vec(),
        )
        .await
    }
}

async fn install_builtin_middleware_registry(opa_engine: &OpaEngine) -> Result<()> {
    let registry = openshell_supervisor_middleware::MiddlewareRegistry::connect_services(
        openshell_supervisor_middleware_builtins::services(),
        Vec::new(),
    )
    .await?;
    opa_engine.replace_middleware_registry(registry)
}

/// Wait the configured poll interval, but never past the point at which an
/// installed extension credential must be rotated.
fn next_poll_delay(
    store: &openshell_extension_core::ExtensionCredentialStore,
    interval: Duration,
) -> Duration {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    store.next_refresh_delay(interval, now_ms)
}

/// Drop credentials for services no longer in the installed registry.
///
/// Call only after a registry swap succeeds, so a failed candidate cannot
/// invalidate the last-known-good clients.
fn retain_extension_credentials(
    store: &openshell_extension_core::ExtensionCredentialStore,
    installed: &[openshell_core::proto::SupervisorMiddlewareService],
    extension_authentication_enabled: bool,
) {
    let retained = if extension_authentication_enabled {
        installed
            .iter()
            .map(|service| service.name.as_str())
            .collect()
    } else {
        std::collections::HashSet::default()
    };
    store.retain(&retained);
}

#[derive(Debug, PartialEq, Eq)]
struct PolicyValidationFailureDisposition {
    configured_mode: PolicyValidationFailureMode,
    mode: PolicyValidationFailureMode,
    previous_policy_active: bool,
    active_generation: u64,
}

fn apply_policy_validation_failure(
    engine: &OpaEngine,
    configured_mode: PolicyValidationFailureMode,
    has_last_valid_policy: bool,
    version: u32,
    error: &str,
) -> Result<PolicyValidationFailureDisposition> {
    let mode = if has_last_valid_policy {
        configured_mode
    } else {
        PolicyValidationFailureMode::FailClosed
    };
    match mode {
        PolicyValidationFailureMode::FailClosed => {
            let reason = format!(
                "policy validation failed; fail-closed quarantine is active; candidate version {version} rejected: {error}"
            );
            let active_generation = engine.enter_fail_closed(reason)?;
            Ok(PolicyValidationFailureDisposition {
                configured_mode,
                mode,
                previous_policy_active: false,
                active_generation,
            })
        }
        PolicyValidationFailureMode::RetainLastValid => {
            let active_generation = engine.exit_fail_closed()?;
            Ok(PolicyValidationFailureDisposition {
                configured_mode,
                mode,
                previous_policy_active: true,
                active_generation,
            })
        }
    }
}

fn policy_validation_failure_events(
    disposition: &PolicyValidationFailureDisposition,
    version: u32,
    policy_hash: &str,
    error: &str,
) -> [OcsfEvent; 2] {
    let previous_policy_state = if disposition.previous_policy_active {
        "IS active"
    } else {
        "IS NOT active"
    };
    let state = if disposition.previous_policy_active {
        (StateId::Enabled, "retained_last_valid")
    } else {
        (StateId::Disabled, "fail_closed")
    };
    let message = format!(
        "Policy validation failed; configured_mode={} effective_mode={}; previous policy {previous_policy_state} [version:{version} active_generation:{} error:{error}]",
        disposition.configured_mode.as_str(),
        disposition.mode.as_str(),
        disposition.active_generation,
    );
    let finding_uid = format!("policy-validation-failed-{version}");
    let version_string = version.to_string();
    let config = ConfigStateChangeBuilder::new(ocsf_ctx())
        .severity(SeverityId::High)
        .status(StatusId::Failure)
        .state(state.0, state.1)
        .unmapped("candidate_version", serde_json::json!(version))
        .unmapped("candidate_policy_hash", serde_json::json!(policy_hash))
        .unmapped(
            "validation_failure_mode",
            serde_json::json!(disposition.mode.as_str()),
        )
        .unmapped(
            "configured_validation_failure_mode",
            serde_json::json!(disposition.configured_mode.as_str()),
        )
        .unmapped(
            "previous_policy_active",
            serde_json::json!(disposition.previous_policy_active),
        )
        .unmapped(
            "active_generation",
            serde_json::json!(disposition.active_generation),
        )
        .unmapped("validation_error", serde_json::json!(error))
        .message(message.clone())
        .build();
    let finding = DetectionFindingBuilder::new(ocsf_ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::High)
        .is_alert(true)
        .finding_info(
            FindingInfo::new(&finding_uid, "Invalid policy generation rejected").with_desc(error),
        )
        .evidence_pairs(&[
            ("candidate_version", &version_string),
            ("candidate_policy_hash", policy_hash),
            ("validation_failure_mode", disposition.mode.as_str()),
            (
                "configured_validation_failure_mode",
                disposition.configured_mode.as_str(),
            ),
            (
                "previous_policy_active",
                if disposition.previous_policy_active {
                    "true"
                } else {
                    "false"
                },
            ),
        ])
        .remediation("Submit a valid, unambiguous policy generation")
        .message(message)
        .build();
    [config, finding]
}

fn emit_policy_validation_failure(
    disposition: &PolicyValidationFailureDisposition,
    version: u32,
    policy_hash: &str,
    error: &str,
) {
    for event in policy_validation_failure_events(disposition, version, policy_hash, error) {
        ocsf_emit!(event);
    }
}

fn apply_ocsf_json_setting(
    enabled: &AtomicBool,
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) {
    use std::sync::atomic::Ordering;

    let new_ocsf = extract_bool_setting(settings, "ocsf_json_enabled").unwrap_or(false);
    let prev_ocsf = enabled.swap(new_ocsf, Ordering::Relaxed);
    if new_ocsf != prev_ocsf {
        info!(ocsf_json_enabled = new_ocsf, "OCSF JSONL logging toggled");
    }
}

/// Extract a bool value from an effective setting, if present.
fn extract_bool_setting(
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    key: &str,
) -> Option<bool> {
    use openshell_core::proto::setting_value;
    settings
        .get(key)
        .and_then(|es| es.value.as_ref())
        .and_then(|sv| sv.value.as_ref())
        .and_then(|v| match v {
            setting_value::Value::BoolValue(b) => Some(*b),
            _ => None,
        })
}

fn agent_proposals_enabled_from_settings(
    settings: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) -> bool {
    extract_bool_setting(
        settings,
        openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY,
    )
    .unwrap_or(false)
}

fn apply_agent_proposals_enabled(
    agent_proposals: &AgentProposals,
    enabled: bool,
    source: &'static str,
    config_revision: Option<u64>,
    install_static_skills: impl FnOnce() -> Result<skills::InstalledSkills>,
) {
    let previously_enabled = agent_proposals.swap_enabled(enabled);
    if enabled == previously_enabled {
        return;
    }

    info!(
        agent_policy_proposals_enabled = enabled,
        source, config_revision, "agent-driven policy proposals toggled"
    );

    if enabled && !previously_enabled {
        match install_static_skills() {
            Ok(installed) => info!(
                path = %installed.policy_advisor.display(),
                "Installed sandbox agent skill on toggle-on"
            ),
            Err(error) => warn!(
                error = %error,
                "Failed to install sandbox agent skill on toggle-on"
            ),
        }
    }
}

/// Log individual setting changes between two snapshots.
fn log_setting_changes(
    old: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
    new: &std::collections::HashMap<String, openshell_core::proto::EffectiveSetting>,
) {
    for (key, new_es) in new {
        let new_val = format_setting_value(new_es);
        match old.get(key) {
            Some(old_es) => {
                let old_val = format_setting_value(old_es);
                if old_val != new_val {
                    ocsf_emit!(
                        ConfigStateChangeBuilder::new(ocsf_ctx())
                            .severity(SeverityId::Informational)
                            .status(StatusId::Success)
                            .state(StateId::Enabled, "updated")
                            .unmapped("key", serde_json::json!(key))
                            .unmapped("old", serde_json::json!(old_val.clone()))
                            .unmapped("new", serde_json::json!(new_val.clone()))
                            .message(format!(
                                "Setting changed [key:{key} old:{old_val} new:{new_val}]"
                            ))
                            .build()
                    );
                }
            }
            None => {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(ocsf_ctx())
                        .severity(SeverityId::Informational)
                        .status(StatusId::Success)
                        .state(StateId::Enabled, "enabled")
                        .unmapped("key", serde_json::json!(key))
                        .unmapped("value", serde_json::json!(new_val.clone()))
                        .message(format!("Setting added [key:{key} value:{new_val}]"))
                        .build()
                );
            }
        }
    }
    for key in old.keys() {
        if !new.contains_key(key) {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(ocsf_ctx())
                    .severity(SeverityId::Informational)
                    .status(StatusId::Success)
                    .state(StateId::Disabled, "disabled")
                    .unmapped("key", serde_json::json!(key))
                    .message(format!("Setting removed [key:{key}]"))
                    .build()
            );
        }
    }
}

/// Format an `EffectiveSetting` value for log display.
fn format_setting_value(es: &openshell_core::proto::EffectiveSetting) -> String {
    use openshell_core::proto::setting_value;
    match es.value.as_ref().and_then(|sv| sv.value.as_ref()) {
        None => "<unset>".to_string(),
        Some(setting_value::Value::StringValue(v)) => v.clone(),
        Some(setting_value::Value::BoolValue(v)) => v.to_string(),
        Some(setting_value::Value::IntValue(v)) => v.to_string(),
        Some(setting_value::Value::BytesValue(_)) => "<bytes>".to_string(),
    }
}

#[cfg(test)]
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::iter_on_single_items,
    clippy::similar_names,
    clippy::manual_string_new,
    clippy::doc_markdown,
    reason = "Test code: test fixtures often use idiomatic forms not flagged in production."
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn effective_bool(value: bool) -> openshell_core::proto::EffectiveSetting {
        openshell_core::proto::EffectiveSetting {
            value: Some(openshell_core::proto::SettingValue {
                value: Some(openshell_core::proto::setting_value::Value::BoolValue(
                    value,
                )),
            }),
            scope: openshell_core::proto::SettingScope::Global.into(),
        }
    }

    #[test]
    fn shared_ssh_socket_setting_is_explicit() {
        assert!(shared_ssh_socket_value("1"));
        assert!(shared_ssh_socket_value("true"));
        assert!(shared_ssh_socket_value("TRUE"));
        assert!(!shared_ssh_socket_value("0"));
        assert!(!shared_ssh_socket_value("yes"));
    }

    #[cfg(unix)]
    #[test]
    fn network_proxy_tls_directory_is_private_and_not_symlinked() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let automatic = prepare_network_proxy_tls_dir(None).expect("private default directory");
        let mode = std::fs::metadata(&automatic.path)
            .expect("default directory metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);

        let root = tempfile::tempdir().expect("temporary root");
        let target = root.path().join("target");
        std::fs::create_dir(&target).expect("target directory");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
            .expect("private target permissions");
        let link = root.path().join("link");
        symlink(&target, &link).expect("TLS directory symlink");
        assert!(prepare_network_proxy_tls_dir(Some(link)).is_err());

        let writable = root.path().join("writable");
        std::fs::create_dir(&writable).expect("writable directory");
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777))
            .expect("writable permissions");
        assert!(prepare_network_proxy_tls_dir(Some(writable)).is_err());
    }

    #[tokio::test]
    async fn control_readiness_exists_only_while_guard_is_live() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("health.sock");
        let readiness = ControlReadiness::start(path.clone(), None, None, None)
            .expect("start readiness listener");
        check_control_readiness(&path).expect("running supervisor accepts readiness probes");

        drop(readiness);
        tokio::task::yield_now().await;
        assert!(check_control_readiness(&path).is_err());
    }

    #[tokio::test]
    async fn control_readiness_tracks_supervisor_session() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("health.sock");
        let (session_tx, session_rx) = tokio::sync::watch::channel(true);
        let _readiness = ControlReadiness::start(path.clone(), Some(session_rx), None, None)
            .expect("start readiness listener");
        check_control_readiness(&path).expect("accepted session is ready");

        session_tx.send_replace(false);
        timeout(Duration::from_secs(1), async {
            while check_control_readiness(&path).is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lost session removes readiness socket");

        session_tx.send_replace(true);
        timeout(Duration::from_secs(1), async {
            while check_control_readiness(&path).is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement session restores readiness socket");
    }

    #[test]
    fn control_readiness_rejects_relative_path() {
        let error = prepare_control_readiness_path(std::path::Path::new("health.sock"))
            .expect_err("relative readiness path must be rejected");
        assert!(error.to_string().contains("must be absolute"));
    }

    #[tokio::test]
    async fn configuration_activation_readiness_requires_session_boundary_and_final_ack() {
        let root = tempfile::tempdir().expect("readiness directory");
        let path = root.path().join("health.sock");
        let (session, session_rx) = tokio::sync::watch::channel(true);
        let (configuration, configuration_rx) = tokio::sync::watch::channel(false);
        let (boundary, boundary_rx) = tokio::sync::watch::channel(false);
        let _readiness = ControlReadiness::start(
            path.clone(),
            Some(session_rx),
            Some(configuration_rx),
            Some(boundary_rx),
        )
        .expect("readiness monitor");
        assert!(check_control_readiness(&path).is_err());
        boundary.send_replace(true);
        tokio::task::yield_now().await;
        assert!(
            check_control_readiness(&path).is_err(),
            "boundary release alone is insufficient"
        );
        configuration.send_replace(true);
        timeout(Duration::from_secs(1), async {
            while check_control_readiness(&path).is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fully acknowledged activation is ready");
        for gate in [&configuration, &boundary, &session] {
            gate.send_replace(false);
            timeout(Duration::from_secs(1), async {
                while check_control_readiness(&path).is_ok() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("each failed gate removes readiness");
            gate.send_replace(true);
            timeout(Duration::from_secs(1), async {
                while check_control_readiness(&path).is_err() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("restored gate permits readiness");
        }
    }

    #[test]
    fn main_exit_marker_atomically_replaces_previous_value() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("main-exited");
        std::fs::write(&marker, b"stale\n").unwrap();

        persist_main_exit_marker(&marker, 23).unwrap();

        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "exit_code=23\n");
        assert!(
            !directory
                .path()
                .join(format!(".main-exited.tmp-{}", std::process::id()))
                .exists()
        );
    }

    #[tokio::test]
    async fn remote_access_plane_outlives_main_completion_until_teardown() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let retained = retain_remote_access_plane(std::future::pending(), async {
            let _ = shutdown_rx.await;
        });
        tokio::pin!(retained);

        assert!(
            timeout(Duration::from_millis(10), &mut retained)
                .await
                .is_err(),
            "access plane must remain live after canonical process completion"
        );
        shutdown_tx.send(()).expect("request teardown");
        timeout(Duration::from_secs(1), &mut retained)
            .await
            .expect("teardown should release retained access plane")
            .expect("clean teardown");
    }

    #[tokio::test]
    async fn completion_retry_phase_is_cancelled_by_shutdown() {
        let mut shutdown = Box::pin(std::future::ready(()));
        assert!(
            completion_phase_or_shutdown(std::future::pending(), shutdown.as_mut()).await,
            "shutdown must cancel an indefinitely retrying completion phase"
        );
    }

    #[test]
    fn apply_agent_proposals_enabled_installs_only_on_false_to_true() {
        let agent_proposals = AgentProposals::default();
        let installs = AtomicUsize::new(0);

        apply_agent_proposals_enabled(&agent_proposals, true, "test", Some(1), || {
            installs.fetch_add(1, Ordering::Relaxed);
            Ok(skills::InstalledSkills {
                policy_advisor: std::path::PathBuf::from("/tmp/policy_advisor.md"),
                policy_advisor_skill: std::path::PathBuf::from("/tmp/SKILL.md"),
                agents: None,
            })
        });
        assert!(agent_proposals.enabled());
        assert_eq!(installs.load(Ordering::Relaxed), 1);

        apply_agent_proposals_enabled(&agent_proposals, true, "test", Some(2), || {
            installs.fetch_add(1, Ordering::Relaxed);
            Ok(skills::InstalledSkills {
                policy_advisor: std::path::PathBuf::from("/tmp/policy_advisor.md"),
                policy_advisor_skill: std::path::PathBuf::from("/tmp/SKILL.md"),
                agents: None,
            })
        });
        assert_eq!(installs.load(Ordering::Relaxed), 1);

        apply_agent_proposals_enabled(&agent_proposals, false, "test", Some(3), || {
            installs.fetch_add(1, Ordering::Relaxed);
            Ok(skills::InstalledSkills {
                policy_advisor: std::path::PathBuf::from("/tmp/policy_advisor.md"),
                policy_advisor_skill: std::path::PathBuf::from("/tmp/SKILL.md"),
                agents: None,
            })
        });
        assert!(!agent_proposals.enabled());
        assert_eq!(installs.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn apply_ocsf_json_setting_enables_from_initial_settings_snapshot() {
        let enabled = AtomicBool::new(false);
        let mut settings = std::collections::HashMap::new();
        settings.insert("ocsf_json_enabled".to_string(), effective_bool(true));

        apply_ocsf_json_setting(&enabled, &settings);

        assert!(enabled.load(Ordering::Relaxed));
    }

    #[test]
    fn apply_ocsf_json_setting_disables_when_setting_is_unset() {
        let enabled = AtomicBool::new(true);
        let settings = std::collections::HashMap::new();

        apply_ocsf_json_setting(&enabled, &settings);

        assert!(!enabled.load(Ordering::Relaxed));
    }

    #[test]
    fn agent_proposals_setting_enables_from_initial_settings_snapshot() {
        let mut settings = std::collections::HashMap::new();
        settings.insert(
            openshell_core::settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY.to_string(),
            effective_bool(true),
        );

        assert!(agent_proposals_enabled_from_settings(&settings));
    }

    #[test]
    fn agent_proposals_setting_defaults_false_when_unset() {
        let settings = std::collections::HashMap::new();

        assert!(!agent_proposals_enabled_from_settings(&settings));
    }

    // ---- Local-file policy startup tests ----

    #[tokio::test]
    async fn local_file_startup_normalizes_matchers_and_rejects_malformed_policy() {
        use openshell_supervisor_network::opa::NetworkInput;

        let files = tempfile::tempdir().expect("policy directory");
        let rules_path = files.path().join("policy.rego");
        let data_path = files.path().join("policy.yaml");
        std::fs::write(
            &rules_path,
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
        )
        .expect("write policy rules");
        std::fs::write(
            &data_path,
            r#"
network_policies:
  startup:
    endpoints:
      - host: startup.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/**", query: { scope: "public-*" } }
    binaries:
      - { path: /usr/bin/curl }
"#,
        )
        .expect("write raw policy");
        let rules = rules_path.to_string_lossy().into_owned();
        let data = data_path.to_string_lossy().into_owned();
        let startup = || load_policy(&rules, &data);
        let (_, engine) = startup().await.expect("load valid local policy");
        assert!(!engine.binary_identity_required());
        // The standalone proxy cannot observe callers. The ordinary file loader
        // must still enforce binary identity for consumers that can observe it.
        let identity_engine = OpaEngine::from_files(&rules_path, &data_path)
            .expect("load identity-required local policy");
        assert!(identity_engine.binary_identity_required());
        // Installing the built-in registry creates the first active generation.
        assert_eq!(engine.current_generation(), 1);

        let mut input = NetworkInput {
            host: "startup.example.com".into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: String::new(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        assert!(
            engine
                .evaluate_network(&input)
                .expect("allowed binary")
                .allowed
        );
        assert!(
            identity_engine
                .evaluate_network(&input)
                .expect("allowed binary with identity")
                .allowed
        );
        let endpoint = engine
            .query_endpoint_config(&input)
            .expect("query startup endpoint")
            .expect("startup endpoint must exist");
        let endpoint: serde_json::Value =
            serde_json::from_str(&endpoint.to_json_str().expect("serialize endpoint"))
                .expect("endpoint JSON");
        assert_eq!(
            endpoint["rules"][0]["allow"]["query"]["scope"],
            serde_json::json!({ "glob": "public-*" }),
        );
        input.binary_path = "/usr/bin/unlisted".into();
        assert!(
            !identity_engine
                .evaluate_network(&input)
                .expect("unlisted binary")
                .allowed
        );

        assert!(
            engine
                .evaluate_network(&input)
                .expect("endpoint-only proxy does not match binary identity")
                .allowed
        );

        // A malformed new startup must fail before returning an active evaluator.
        std::fs::write(&data_path, "network_policies: []\n").expect("write malformed policy");
        let Err(error) = startup().await else {
            panic!("malformed startup must reject");
        };
        assert!(
            error
                .to_string()
                .contains("network_policies must be an object")
        );
    }

    #[tokio::test]
    async fn failed_external_startup_registry_build_preserves_installed_builtins() {
        let engine = OpaEngine::from_proto(&openshell_policy::restrictive_default_policy())
            .expect("build OPA engine");
        install_builtin_middleware_registry(&engine)
            .await
            .expect("install built-in middleware registry");
        let builtins_generation = engine.current_generation();
        assert_eq!(builtins_generation, 1);

        let invalid_external = openshell_core::proto::SupervisorMiddlewareService {
            name: "unavailable-guard".into(),
            grpc_endpoint: "http://127.0.0.1:1".into(),
            max_payload_bytes: 1024,
            ..Default::default()
        };
        connect_middleware_registry(&[invalid_external], &MiddlewareAuthentication::default())
            .await
            .expect_err("unavailable external service must not replace built-ins");

        assert_eq!(engine.current_generation(), builtins_generation);
    }

    #[test]
    fn fail_closed_validation_failure_deactivates_previous_generation() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let previous_generation = engine.current_generation();

        let disposition = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::FailClosed,
            true,
            7,
            "conflicting tls metadata",
        )
        .unwrap();

        assert!(!disposition.previous_policy_active);
        assert!(disposition.active_generation > previous_generation);
        assert!(
            engine
                .fail_closed_reason()
                .expect("quarantine reason")
                .contains("candidate version 7 rejected")
        );
    }

    #[test]
    fn retain_validation_failure_keeps_previous_generation_active() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();
        let previous_generation = engine.current_generation();

        let quarantined = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::FailClosed,
            true,
            6,
            "conflicting tls metadata",
        )
        .unwrap();
        assert!(!quarantined.previous_policy_active);

        let disposition = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::RetainLastValid,
            true,
            7,
            "conflicting tls metadata",
        )
        .unwrap();

        assert!(disposition.previous_policy_active);
        assert!(disposition.active_generation > quarantined.active_generation);
        assert!(disposition.active_generation > previous_generation);
        assert!(engine.fail_closed_reason().is_none());
    }

    #[test]
    fn retain_validation_failure_without_last_valid_policy_stays_fail_closed() {
        let engine = OpaEngine::from_strings(
            include_str!("../../openshell-supervisor-network/data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .unwrap();

        let disposition = apply_policy_validation_failure(
            &engine,
            PolicyValidationFailureMode::RetainLastValid,
            false,
            1,
            "conflicting tls metadata",
        )
        .unwrap();

        assert_eq!(
            disposition.configured_mode,
            PolicyValidationFailureMode::RetainLastValid
        );
        assert_eq!(disposition.mode, PolicyValidationFailureMode::FailClosed);
        assert!(!disposition.previous_policy_active);
        assert!(engine.fail_closed_reason().is_some());

        let [config, _] = policy_validation_failure_events(
            &disposition,
            1,
            "sha256:test",
            "conflicting tls metadata",
        );
        let config = config.to_json().unwrap();
        assert_eq!(config["unmapped"]["validation_failure_mode"], "fail_closed");
        assert_eq!(
            config["unmapped"]["configured_validation_failure_mode"],
            "retain_last_valid"
        );
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("previous policy IS NOT active")
        );
    }

    #[test]
    fn validation_failure_ocsf_states_whether_previous_policy_is_active() {
        let fail_closed = PolicyValidationFailureDisposition {
            configured_mode: PolicyValidationFailureMode::FailClosed,
            mode: PolicyValidationFailureMode::FailClosed,
            previous_policy_active: false,
            active_generation: 9,
        };
        let [config, finding] = policy_validation_failure_events(
            &fail_closed,
            8,
            "sha256:test",
            "conflicting tls metadata",
        );
        let config = config.to_json().unwrap();
        assert_eq!(config["class_uid"], 5019);
        assert_eq!(config["status"], "Failure");
        assert_eq!(config["unmapped"]["validation_failure_mode"], "fail_closed");
        assert_eq!(
            config["unmapped"]["configured_validation_failure_mode"],
            "fail_closed"
        );
        assert_eq!(config["unmapped"]["previous_policy_active"], false);
        assert_eq!(
            config["unmapped"]["validation_error"],
            "conflicting tls metadata"
        );
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("previous policy IS NOT active")
        );
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("error:conflicting tls metadata")
        );

        let finding = finding.to_json().unwrap();
        assert_eq!(finding["class_uid"], 2004);
        assert_eq!(finding["action"], "Denied");
        assert_eq!(finding["disposition"], "Blocked");

        let retained = PolicyValidationFailureDisposition {
            configured_mode: PolicyValidationFailureMode::RetainLastValid,
            mode: PolicyValidationFailureMode::RetainLastValid,
            previous_policy_active: true,
            active_generation: 4,
        };
        let [config, _] = policy_validation_failure_events(
            &retained,
            8,
            "sha256:test",
            "conflicting tls metadata",
        );
        let config = config.to_json().unwrap();
        assert_eq!(config["unmapped"]["previous_policy_active"], true);
        assert!(
            config["message"]
                .as_str()
                .unwrap()
                .contains("previous policy IS active")
        );
    }
}
