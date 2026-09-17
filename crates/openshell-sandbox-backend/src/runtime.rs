// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side RFC 0012 backend for an already-provisioned remote boundary.

#![allow(unsafe_code)]

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::mem::size_of;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd as _, IntoRawFd as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::proto::{BoundaryChunk, isolation_boundary_client::IsolationBoundaryClient};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use openshell_isolation_interface::AgentSpec;
use openshell_isolation_interface::contract::{
    ActivatedBoundaryConfiguration, BackendError, BoundBoundary, BoundaryBootstrap,
    BoundaryConfiguration, BoundaryConfigurationSnapshot, BoundaryDuplexStream, BoundaryExec,
    BoundaryExitStatus, BoundaryInput, BoundaryLoopbackConnector, BoundaryOutput, BoundaryProcess,
    BoundarySignal, BoundaryTerminal, ConfigurationActivationIdentity, ConfigurationRevision,
    ConfirmedBoundary, ExecSession, ExecSpec, InstalledBoundaryConfiguration, IsolationBackend,
    LoopbackTarget, MediationTiming, NetworkMediationSource, PendingDnsQuery, PendingTcpOpen,
    PreparedBoundaryConfiguration, ProcessAttachment, ReadyBoundary, RunningBoundary,
    SandboxContext, TcpOpenDecision, TcpOpenDenial, VerifiedBackendDescriptor,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio_stream::wrappers::ReceiverStream;

use crate::boundary_protocol::{
    AgentSpecWire, DnsQueryResultWire, ExecSpecWire, ExitStatusWire, MAX_CONTROL_FRAME_BYTES,
    Request, RequestEnvelope, Response, ResponseEnvelope, STREAM_EXIT, STREAM_STDERR, STREAM_STDIN,
    STREAM_STDIN_CLOSED, STREAM_STDOUT, SandboxPolicyWire, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTransport, SignalWire, decode_frame, encode_frame,
    read_stream_frame, validate_resource_claims, write_stream_frame,
};
use crate::mediation::{self, DnsQueryWire, MediationFrame, MediationFrameKind};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Initial attachment may include runtime image pulls and trusted bootstrap
/// work before the boundary begins listening. Keep this aligned with the
/// driver bootstrap grace period rather than the normal operation timeout.
const ATTACH_REQUEST_TIMEOUT: Duration = Duration::from_mins(5);
/// How long one control call keeps retrying boundary connect attempts. Boot-time
/// callers retry whole calls above this; past boot, exhausting this window
/// means the remote boundary (or its launcher) is gone rather than still starting.
const CONNECT_RETRY_TIMEOUT: Duration = Duration::from_secs(30);

fn begin_recovery_window(
    deadline: &mut Option<tokio::time::Instant>,
    failure_time: tokio::time::Instant,
) -> tokio::time::Instant {
    *deadline.get_or_insert(failure_time + CONNECT_RETRY_TIMEOUT)
}

/// Host-side `OpenShell` Sandbox Protocol implementation registered with the supervisor.
#[derive(Debug)]
pub struct OpenShellRuntimeBackend {
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
    supervisor_instance_id: crate::boundary_protocol::SupervisorInstanceId,
    bootstrap: std::sync::Mutex<Option<BoundaryBootstrap>>,
}

impl OpenShellRuntimeBackend {
    /// Bind discovery, attachment, and activation to the caller's one control process identity.
    pub fn new(
        ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
        provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
        sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
        supervisor_instance_id: crate::boundary_protocol::SupervisorInstanceId,
    ) -> Self {
        Self {
            ca_file_paths,
            provider_credentials,
            sandbox_bearer,
            supervisor_instance_id,
            bootstrap: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait]
impl IsolationBackend for OpenShellRuntimeBackend {
    fn backend_name(&self) -> &str {
        crate::BACKEND_NAME
    }

    async fn discover(
        &self,
        descriptor: &VerifiedBackendDescriptor,
    ) -> Result<BoundaryBootstrap, BackendError> {
        let runtime_descriptor: SandboxRuntimeDescriptor =
            serde_json::from_slice(descriptor.payload()).map_err(|error| {
                BackendError::Descriptor(format!("decode runtime descriptor: {error}"))
            })?;
        validate_transport_descriptor(&runtime_descriptor)?;
        let client = BoundaryClient::new(
            runtime_descriptor,
            self.sandbox_bearer.clone(),
            self.supervisor_instance_id,
        );
        let response = client
            .call_idempotent(Request::DescribeWorkload {
                supervisor_instance_id: self.supervisor_instance_id,
                resource_claims: client.runtime_descriptor.resource_claims.clone(),
            })
            .await?;
        let Response::WorkloadDescribed { bootstrap } = response else {
            return Err(unexpected_response("workload_described", &response));
        };
        client.validate_identity(&bootstrap.identity, false)?;
        if bootstrap.workload_identity != client.runtime_descriptor.workload_identity {
            return Err(BackendError::Descriptor(
                "discovered workload identity does not match runtime descriptor".to_string(),
            ));
        }
        let mut previous = self
            .bootstrap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if previous
            .as_ref()
            .is_some_and(|previous| !previous.identity.same_incarnation(&bootstrap.identity))
        {
            return Err(BackendError::Terminated(
                "boundary incarnation changed during discovery".to_string(),
            ));
        }
        *previous = Some((*bootstrap).clone());
        Ok(*bootstrap)
    }

    async fn attach(
        &self,
        descriptor: VerifiedBackendDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        let runtime_descriptor: SandboxRuntimeDescriptor =
            serde_json::from_slice(descriptor.payload()).map_err(|error| {
                BackendError::Descriptor(format!("decode runtime descriptor: {error}"))
            })?;
        validate_runtime_descriptor(&runtime_descriptor, &sandbox)?;
        let host_gateway_ip = runtime_descriptor.host_gateway_ip;
        let resource_claims = runtime_descriptor.resource_claims.clone();
        let generation = runtime_descriptor.generation.clone();
        let session_id = runtime_descriptor.session_id;
        let driver_fence = runtime_descriptor.driver_fence.clone();
        let client = Arc::new(BoundaryClient::new(
            runtime_descriptor,
            self.sandbox_bearer.clone(),
            self.supervisor_instance_id,
        ));
        let bootstrap = self
            .bootstrap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                BackendError::Attach("workload discovery must precede attachment".to_string())
            })?;
        if bootstrap.workload_identity != sandbox.identity {
            return Err(BackendError::Descriptor(
                "admitted workload identity does not match discovery".to_string(),
            ));
        }
        if sandbox.registration_revision == 0
            || sandbox.registration_grant.expose_secret().is_empty()
        {
            return Err(BackendError::Attach(
                "attachment requires an issued control registration".to_string(),
            ));
        }
        let response = client
            .call_idempotent(Request::Attach {
                supervisor_instance_id: client.supervisor_instance_id,
                registration_grant: sandbox.registration_grant.expose_secret().to_string(),
                registration_revision: sandbox.registration_revision,
                policy: Box::new(SandboxPolicyWire::from(sandbox.policy.clone())),
                resource_claims: resource_claims.clone(),
            })
            .await?;
        let Response::Attached { snapshot } = response else {
            return Err(unexpected_response("attached", &response));
        };
        client.validate_attached(&snapshot, sandbox.registration_revision)?;
        if !bootstrap
            .identity
            .same_incarnation(&snapshot.configuration.identity)
        {
            return Err(BackendError::Terminated(
                "boundary incarnation changed after discovery".to_string(),
            ));
        }
        client
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .identity = Some(snapshot.configuration.identity);
        Ok(Box::new(RemoteBound {
            client: client.clone(),
            agent: sandbox.agent,
            policy: sandbox.policy,
            sandbox_id: sandbox.sandbox_id,
            mediation: Arc::new(RemoteNetworkMediation { client }),
            host_gateway_ip,
            ca_file_paths: self.ca_file_paths.clone(),
            provider_credentials: self.provider_credentials.clone(),
            identity: sandbox.identity,
            generation,
            session_id,
            resource_claims,
            driver_fence,
        }))
    }
}

fn validate_runtime_descriptor(
    runtime_descriptor: &SandboxRuntimeDescriptor,
    sandbox: &SandboxContext,
) -> Result<(), BackendError> {
    if runtime_descriptor.boundary_id != sandbox.sandbox_id {
        return Err(BackendError::Descriptor(format!(
            "boundary {:?} does not match sandbox {:?}",
            runtime_descriptor.boundary_id, sandbox.sandbox_id
        )));
    }
    if runtime_descriptor.session_id != sandbox.session_id {
        return Err(BackendError::Descriptor(
            "runtime descriptor session ID does not match admitted sandbox session".to_string(),
        ));
    }
    if runtime_descriptor.workload_identity != sandbox.identity {
        return Err(BackendError::Descriptor(
            "runtime descriptor workload identity does not match admitted sandbox identity"
                .to_string(),
        ));
    }
    validate_transport_descriptor(runtime_descriptor)
}

fn validate_transport_descriptor(
    runtime_descriptor: &SandboxRuntimeDescriptor,
) -> Result<(), BackendError> {
    if runtime_descriptor.generation.is_empty() {
        return Err(BackendError::Descriptor(
            "boundary generation must not be empty".to_string(),
        ));
    }
    validate_resource_claims(&runtime_descriptor.resource_claims)?;
    runtime_descriptor.driver_fence.validate()?;
    match &runtime_descriptor.transport {
        SandboxTransport::Unix { socket_path } => {
            validate_socket_path(socket_path)?;
        }
        SandboxTransport::Tcp {
            authority,
            addresses,
        } => {
            if authority.is_empty() || addresses.is_empty() {
                return Err(BackendError::Descriptor(
                    "boundary TCP transport requires an authority and at least one address"
                        .to_string(),
                ));
            }
            for address in addresses {
                validate_tcp_address(*address)?;
            }
        }
        SandboxTransport::Vsock { guest_cid, port } => {
            if *guest_cid < 3 {
                return Err(BackendError::Descriptor(
                    "boundary CID must be at least 3".to_string(),
                ));
            }
            validate_control_port(*port)?;
        }
    }
    validate_client_tls(&runtime_descriptor.tls)?;
    Ok(())
}

fn validate_tcp_address(address: std::net::SocketAddr) -> Result<(), BackendError> {
    if address.port() == 0 || address.ip().is_unspecified() {
        Err(BackendError::Descriptor(
            "boundary TCP address must have a concrete IP and nonzero port".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn validate_client_tls(tls: &SandboxTlsClientConfig) -> Result<(), BackendError> {
    rustls::pki_types::ServerName::try_from(tls.server_name.clone()).map_err(|error| {
        BackendError::Descriptor(format!(
            "boundary TLS server name {:?} is invalid: {error}",
            tls.server_name
        ))
    })?;
    tls_client_config(tls).map(|_| ())
}

fn tls_client_config(tls: &SandboxTlsClientConfig) -> Result<rustls::ClientConfig, BackendError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certificates = rustls_pemfile::certs(&mut tls.trust_anchor_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            BackendError::Descriptor(format!("parse boundary TLS CA certificate: {error}"))
        })?;
    if certificates.is_empty() {
        return Err(BackendError::Descriptor(
            "boundary TLS CA certificate PEM contains no certificates".to_string(),
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|error| {
            BackendError::Descriptor(format!("load boundary TLS CA certificate: {error}"))
        })?;
    }
    let mut config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

fn validate_socket_path(path: &std::path::Path) -> Result<(), BackendError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(BackendError::Descriptor(
            "boundary control Unix socket path must be absolute".to_string(),
        ))
    }
}

fn validate_control_port(port: u32) -> Result<(), BackendError> {
    if port == 0 {
        Err(BackendError::Descriptor(
            "boundary control port must be nonzero".to_string(),
        ))
    } else {
        Ok(())
    }
}

struct RemoteBound {
    client: Arc<BoundaryClient>,
    agent: AgentSpec,
    policy: openshell_core::policy::SandboxPolicy,
    sandbox_id: String,
    mediation: Arc<RemoteNetworkMediation>,
    host_gateway_ip: Option<std::net::IpAddr>,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
    identity: openshell_isolation_interface::contract::ResolvedWorkloadIdentity,
    generation: String,
    session_id: openshell_core::SandboxSessionId,
    resource_claims: std::collections::BTreeMap<String, String>,
    driver_fence: openshell_isolation_interface::contract::DriverFenceEvidence,
}

#[async_trait]
impl BoundBoundary for RemoteBound {
    fn configuration(&self) -> Arc<dyn BoundaryConfiguration> {
        self.client.clone()
    }

    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        self.mediation.clone()
    }

    fn host_gateway_ip(&self) -> Option<std::net::IpAddr> {
        self.host_gateway_ip
    }

    async fn confirm(self: Box<Self>) -> Result<ConfirmedBoundary, BackendError> {
        let response = self.client.call_idempotent(Request::Confirm).await?;
        let Response::Confirmed { evidence } = response else {
            return Err(unexpected_response("confirmed_with_evidence", &response));
        };
        if evidence.generation != self.generation
            || evidence.session_id != self.session_id
            || evidence.resource_claims != self.resource_claims
            || evidence.driver_fence != self.driver_fence
        {
            return Err(BackendError::Confirm(
                "sandbox confirmation generation, session, resource claims, or driver fence do not match runtime descriptor"
                    .to_string(),
            ));
        }
        self.client.start_credential_monitor();
        ConfirmedBoundary::try_new(
            Box::new(RemoteReady {
                client: self.client,
                agent: self.agent,
                policy: self.policy,
                sandbox_id: self.sandbox_id,
                ca_file_paths: self.ca_file_paths,
                provider_credentials: self.provider_credentials,
            }),
            *evidence,
            &self.identity,
        )
    }
}

struct RemoteReady {
    client: Arc<BoundaryClient>,
    agent: AgentSpec,
    policy: openshell_core::policy::SandboxPolicy,
    sandbox_id: String,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
}

#[async_trait]
impl ReadyBoundary for RemoteReady {
    fn configuration(&self) -> Arc<dyn BoundaryConfiguration> {
        self.client.clone()
    }

    async fn update_startup_policy(
        &mut self,
        policy: openshell_core::policy::SandboxPolicy,
    ) -> Result<(), BackendError> {
        let candidate = SandboxPolicyWire::from(policy.clone());
        if candidate == SandboxPolicyWire::from(self.policy.clone()) {
            // A replacement control may attach to an already-started main.
            // Exact policy replay is harmless and must not invalidate its receipts.
            return Ok(());
        }
        self.client.invalidate_activation();
        let _operation = self.client.activation_operations.lock().await;
        let snapshot = self.client.snapshot().await?;
        if snapshot.active {
            return Err(BackendError::Denied(
                "startup policy replacement requires a held boundary".to_string(),
            ));
        }
        let mut request = self
            .client
            .attach_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|envelope| envelope.request.clone())
            .ok_or_else(|| {
                BackendError::Attach(
                    "startup policy replacement requires an attached boundary".to_string(),
                )
            })?;
        let Request::Attach {
            policy: selected_policy,
            ..
        } = &mut request
        else {
            return Err(BackendError::Attach(
                "cached startup attachment has the wrong operation".to_string(),
            ));
        };
        **selected_policy = candidate;
        // The boundary validates selectors against its local account database
        // and rejects changed static policy after the main process has started.
        self.client.call_idempotent(request).await?;
        self.client.call_idempotent(Request::Confirm).await?;
        self.policy = policy;
        Ok(())
    }

    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let ca_paths = self
            .ca_file_paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (ca_cert, ca_bundle) = if let Some((ca_cert, ca_bundle)) = ca_paths {
            let ca_cert = tokio::fs::read(&ca_cert).await.map_err(|error| {
                BackendError::Process(format!("read host proxy CA {}: {error}", ca_cert.display()))
            })?;
            let ca_bundle = tokio::fs::read(&ca_bundle).await.map_err(|error| {
                BackendError::Process(format!(
                    "read host proxy CA bundle {}: {error}",
                    ca_bundle.display()
                ))
            })?;
            (Some(ca_cert), Some(ca_bundle))
        } else {
            (None, None)
        };
        let activation = self
            .client
            .active_configuration(self.provider_credentials.revision())?;
        let response = self
            .client
            .call_idempotent(Request::StartAgent {
                sandbox_id: self.sandbox_id,
                spec: AgentSpecWire::from(self.agent),
                policy: Box::new(SandboxPolicyWire::from(self.policy)),
                ca_cert,
                ca_bundle,
                activation: activation.clone(),
            })
            .await?;
        let Response::Started {
            process_id,
            provider_env_revision,
            activation: acknowledged,
        } = response
        else {
            return Err(unexpected_response("started", &response));
        };
        if let Err(error) =
            validate_launch_acknowledgement(&activation, &acknowledged, provider_env_revision)
        {
            self.client.invalidate_activation();
            return Err(error);
        }
        self.client.require_active(&activation)?;
        let process = Arc::new(RemoteProcess {
            client: self.client.clone(),
            process_id,
            exit_status: std::sync::Mutex::new(None),
        });
        Ok(Box::new(RemoteRunning {
            process,
            terminated: tokio::sync::Mutex::new(false),
            exec: Arc::new(RemoteExec {
                client: self.client.clone(),
                provider_credentials: self.provider_credentials,
            }),
            loopback_connector: Arc::new(RemoteLoopbackConnector {
                client: self.client,
            }),
        }))
    }
}

struct RemoteRunning {
    process: Arc<RemoteProcess>,
    terminated: tokio::sync::Mutex<bool>,
    exec: Arc<RemoteExec>,
    loopback_connector: Arc<RemoteLoopbackConnector>,
}

#[async_trait]
impl RunningBoundary for RemoteRunning {
    fn agent(&self) -> Arc<dyn BoundaryProcess> {
        self.process.clone()
    }

    fn exec(&self) -> Arc<dyn BoundaryExec> {
        self.exec.clone()
    }

    fn loopback_connector(&self) -> Arc<dyn BoundaryLoopbackConnector> {
        self.loopback_connector.clone()
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        let mut terminated = self.terminated.lock().await;
        if *terminated {
            return Ok(());
        }
        let response = self
            .process
            .client
            .call_idempotent(Request::TerminateBoundary)
            .await?;
        let Response::BoundaryTerminated { main_exit_status } = response else {
            return Err(unexpected_response("boundary_terminated", &response));
        };
        let status = main_exit_status.ok_or_else(|| {
            BackendError::Process("terminated boundary omitted the launched main's status".into())
        })?;
        // Terminal acknowledgement revokes remote Wait authorization. Retain
        // its observed status before success so all later waits remain local.
        self.process.record_exit_status(status.into())?;
        *terminated = true;
        Ok(())
    }
}

struct RemoteProcess {
    client: Arc<BoundaryClient>,
    process_id: String,
    exit_status: std::sync::Mutex<Option<ExitStatusWire>>,
}

impl RemoteProcess {
    fn cached_exit_status(&self) -> Option<BoundaryExitStatus> {
        self.exit_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(Into::into)
    }

    fn record_exit_status(&self, status: BoundaryExitStatus) -> Result<(), BackendError> {
        let status = ExitStatusWire::from(status);
        let mut cached = self
            .exit_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cached.is_some_and(|previous| previous != status) {
            return Err(BackendError::Process(
                "boundary returned conflicting canonical process exit status".into(),
            ));
        }
        *cached = Some(status);
        Ok(())
    }
}

#[async_trait]
impl BoundaryProcess for RemoteProcess {
    async fn attach(&self) -> Result<ProcessAttachment, BackendError> {
        open_process_attachment(self.client.clone(), self.process_id.clone()).await
    }

    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        if let Some(status) = self.cached_exit_status() {
            return Ok(status);
        }
        let response = self
            .client
            .call_wait(Request::Wait {
                process_id: self.process_id.clone(),
            })
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                // A concurrent terminal receipt may arrive after this wait
                // starts but before remote authorization rejects it.
                if let Some(status) = self.cached_exit_status() {
                    return Ok(status);
                }
                return Err(match error {
                    BackendError::Unavailable(message) => {
                        BackendError::Terminated(format!("boundary lost during wait: {message}"))
                    }
                    error => error,
                });
            }
        };
        let Response::Exited { status } = response else {
            return Err(unexpected_response("exited", &response));
        };
        let status = status.into();
        self.record_exit_status(status)?;
        Ok(status)
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let response = self
            .client
            .call_idempotent(Request::Signal {
                process_id: self.process_id.clone(),
                signal: SignalWire::from(signal),
            })
            .await?;
        expect_response(response, "signaled")
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        let response = self
            .client
            .call_idempotent(Request::Terminate {
                process_id: self.process_id.clone(),
            })
            .await?;
        expect_response(response, "terminated")
    }
}

async fn open_process_attachment(
    client: Arc<BoundaryClient>,
    process_id: String,
) -> Result<ProcessAttachment, BackendError> {
    let (stream, response) = client
        .call_stream(Request::AttachProcess {
            process_id: process_id.clone(),
        })
        .await?;
    let Response::ProcessAttached {
        terminal: has_terminal,
    } = response
    else {
        return Err(unexpected_response("process_attached", &response));
    };
    let (network_reader, network_writer) = tokio::io::split(stream);
    let (stdin, stdin_pump) = tokio::io::duplex(64 * 1024);
    let (stdout, stdout_pump) = tokio::io::duplex(64 * 1024);
    let (stderr, stderr_pump) = tokio::io::duplex(64 * 1024);
    tokio::spawn(pump_exec_input(stdin_pump, network_writer));
    tokio::spawn(pump_process_responses(
        network_reader,
        stdout_pump,
        stderr_pump,
    ));
    let terminal: Option<Arc<dyn BoundaryTerminal>> = if has_terminal {
        let terminal: Arc<dyn BoundaryTerminal> = Arc::new(RemoteTerminal { client, process_id });
        Some(terminal)
    } else {
        None
    };
    let stderr: Option<BoundaryOutput> = if has_terminal {
        None
    } else {
        let stderr: BoundaryOutput = Box::new(stderr);
        Some(stderr)
    };
    Ok(ProcessAttachment {
        stdin: Box::new(stdin),
        stdout: Box::new(stdout),
        stderr,
        terminal,
    })
}

async fn pump_process_responses(
    mut network: tokio::io::ReadHalf<BoundaryDuplexStream>,
    mut stdout: tokio::io::DuplexStream,
    mut stderr: tokio::io::DuplexStream,
) {
    loop {
        match read_stream_frame(&mut network).await {
            Ok(Some((STREAM_STDOUT, payload))) => {
                if stdout.write_all(&payload).await.is_err() {
                    return;
                }
            }
            Ok(Some((STREAM_STDERR, payload))) => {
                if stderr.write_all(&payload).await.is_err() {
                    return;
                }
            }
            Ok(Some((STREAM_EXIT, _)) | None) | Err(_) => return,
            Ok(Some((_channel, _))) => return,
        }
    }
}

struct RemoteExec {
    client: Arc<BoundaryClient>,
    provider_credentials: openshell_core::provider_credentials::ProviderCredentialState,
}

#[async_trait]
impl BoundaryExec for RemoteExec {
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError> {
        // Exec consumes the accepted environment. It cannot independently install
        // provider updates ahead of the policy/configuration activation transaction.
        let activation = self
            .client
            .active_configuration(self.provider_credentials.revision())?;
        open_exec_session(self.client.clone(), spec, activation).await
    }
}

struct RemoteLoopbackConnector {
    client: Arc<BoundaryClient>,
}

#[async_trait]
impl BoundaryLoopbackConnector for RemoteLoopbackConnector {
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        let (stream, response) = self
            .client
            .call_stream(Request::LoopbackConnect {
                host: target.host(),
                port: target.port(),
            })
            .await?;
        match response {
            Response::PortConnected => Ok(stream),
            response => Err(unexpected_response("port_connected", &response)),
        }
    }
}

struct RemoteExecProcess {
    client: Arc<BoundaryClient>,
    process_id: String,
}

#[async_trait]
impl BoundaryProcess for RemoteExecProcess {
    async fn attach(&self) -> Result<ProcessAttachment, BackendError> {
        open_process_attachment(self.client.clone(), self.process_id.clone()).await
    }

    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        RemoteProcess {
            client: self.client.clone(),
            process_id: self.process_id.clone(),
            exit_status: std::sync::Mutex::new(None),
        }
        .wait()
        .await
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        expect_response(
            self.client
                .call_idempotent(Request::ExecSignal {
                    process_id: self.process_id.clone(),
                    signal: SignalWire::from(signal),
                })
                .await?,
            "signaled",
        )
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.signal(BoundarySignal::Kill).await
    }
}

struct RemoteTerminal {
    client: Arc<BoundaryClient>,
    process_id: String,
}

#[async_trait]
impl BoundaryTerminal for RemoteTerminal {
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError> {
        let response = self
            .client
            .call_idempotent(Request::Resize {
                process_id: self.process_id.clone(),
                cols,
                rows,
            })
            .await?;
        if matches!(response, Response::Resized) {
            Ok(())
        } else {
            Err(unexpected_response("resized", &response))
        }
    }
}

async fn open_exec_session(
    client: Arc<BoundaryClient>,
    spec: ExecSpec,
    activation: ActivatedBoundaryConfiguration,
) -> Result<ExecSession, BackendError> {
    let (stream, response) = client
        .call_stream_idempotent(Request::Exec {
            spec: ExecSpecWire::from(spec),
            activation: activation.clone(),
        })
        .await?;
    let Response::ExecStarted {
        process_id,
        pty,
        activation: acknowledged,
    } = response
    else {
        return Err(unexpected_response("exec_started", &response));
    };
    if let Err(error) = validate_launch_acknowledgement(
        &activation,
        &acknowledged,
        acknowledged.configuration.provider_env_revision,
    ) {
        client.invalidate_activation();
        return Err(error);
    }
    client.require_active(&activation)?;
    let (network_reader, network_writer) = tokio::io::split(stream);
    let (stdin, stdin_pump) = tokio::io::duplex(64 * 1024);
    let (stdout, stdout_pump) = tokio::io::duplex(64 * 1024);
    let (stderr, stderr_pump) = tokio::io::duplex(64 * 1024);
    tokio::spawn(pump_exec_input(stdin_pump, network_writer));
    tokio::spawn(pump_process_responses(
        network_reader,
        stdout_pump,
        stderr_pump,
    ));

    let process: Arc<dyn BoundaryProcess> = Arc::new(RemoteExecProcess {
        client: client.clone(),
        process_id: process_id.clone(),
    });
    let terminal: Option<Arc<dyn BoundaryTerminal>> = if pty {
        Some(Arc::new(RemoteTerminal { client, process_id }))
    } else {
        None
    };
    let stdin: BoundaryInput = Box::new(stdin);
    let stdout: BoundaryOutput = Box::new(stdout);
    let stderr: Option<BoundaryOutput> = if pty { None } else { Some(Box::new(stderr)) };
    Ok(ExecSession {
        process,
        stdin: Some(stdin),
        stdout,
        stderr,
        terminal,
    })
}

async fn pump_exec_input(
    mut input: tokio::io::DuplexStream,
    mut network: tokio::io::WriteHalf<BoundaryDuplexStream>,
) {
    let mut buffer = vec![0; 16 * 1024];
    loop {
        match input.read(&mut buffer).await {
            Ok(0) => {
                let _ = write_stream_frame(&mut network, STREAM_STDIN_CLOSED, &[]).await;
                return;
            }
            Ok(read) => {
                if write_stream_frame(&mut network, STREAM_STDIN, &buffer[..read])
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Pulls boundary proxy connections over independent HTTP/2 streams.
///
/// DNS control messages share the compact persistent mediation
/// session, but TCP byte streams use HTTP/2's native multiplexing. Nesting all
/// TCP connections inside one application-level writer creates avoidable
/// head-of-line blocking during concurrent TLS handshakes.
struct RemoteNetworkMediation {
    client: Arc<BoundaryClient>,
}

#[async_trait]
impl NetworkMediationSource for RemoteNetworkMediation {
    async fn accept_tcp(&self) -> Result<PendingTcpOpen, BackendError> {
        let (stream, response) = self
            .client
            .accept_mediation(|_| self.client.open_exchange(Request::AcceptNetwork))
            .await?;
        let Response::NetworkConnected {
            identity,
            destination,
            socket,
            policy_generation,
            timing,
        } = response
        else {
            return Err(unexpected_response("network_connected", &response));
        };
        let (decision, completion) = tokio::sync::oneshot::channel();
        let (proxy_stream, transport_stream) = tokio::io::duplex(64 * 1024);
        tokio::spawn(complete_network_open(stream, transport_stream, completion));
        Ok(PendingTcpOpen {
            stream: Box::new(proxy_stream),
            binary_identity: identity.into_result(),
            destination,
            socket,
            policy_generation,
            timing: MediationTiming {
                sandbox_notification_to_queue: Duration::from_micros(
                    timing.notification_to_queue_us,
                ),
                sandbox_queue_wait: Duration::from_micros(timing.queue_wait_us),
                supervisor_received_at: Instant::now(),
            },
            decision,
        })
    }

    async fn accept_dns(&self) -> Result<PendingDnsQuery, BackendError> {
        self.client
            .accept_mediation(|epoch| async move {
                let session = self.client.mediation_session(epoch).await?;
                session.accept_dns().await
            })
            .await
    }
}

async fn complete_network_open(
    mut boundary: BoundaryDuplexStream,
    mut transport: tokio::io::DuplexStream,
    completion: tokio::sync::oneshot::Receiver<TcpOpenDecision>,
) {
    let decision = completion
        .await
        .unwrap_or(TcpOpenDecision::Denied(TcpOpenDenial::MediationUnavailable));
    let Ok(payload) = serde_json::to_vec(&decision) else {
        return;
    };
    if write_stream_frame(
        &mut boundary,
        crate::boundary_protocol::STREAM_NETWORK_DECISION,
        &payload,
    )
    .await
    .is_err()
    {
        return;
    }
    if matches!(decision, TcpOpenDecision::RelayReady) {
        let _ = tokio::io::copy_bidirectional(&mut boundary, &mut transport).await;
    }
}

const MEDIATION_EVENT_QUEUE: usize = 256;
struct OutboundMediationFrame {
    kind: MediationFrameKind,
    stream_id: u64,
    payload: Vec<u8>,
}

struct ClientMediationSession {
    activation_epoch: u64,
    dns: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<PendingDnsQuery>>,
    healthy: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl ClientMediationSession {
    fn start(
        stream: BoundaryDuplexStream,
        activation_epoch: u64,
        mut activation_changes: tokio::sync::watch::Receiver<bool>,
    ) -> Arc<Self> {
        let (dns_tx, dns_rx) = tokio::sync::mpsc::channel(MEDIATION_EVENT_QUEUE);
        let healthy = Arc::new(AtomicBool::new(true));
        let task_healthy = healthy.clone();
        let task = tokio::spawn(async move {
            // Subscribe before opening the stream: a delayed successful open may
            // reach the boundary after its hold watcher has already advanced.
            // A local hold must close that lane even if release immediately follows.
            tokio::select! {
                biased;
                _ = activation_changes.changed() => {},
                result = run_client_mediation(stream, dns_tx) => {
                    if let Err(error) = result {
                        tracing::debug!(%error, "persistent mediation session ended");
                    }
                }
            }
            task_healthy.store(false, Ordering::Release);
        });
        Arc::new(Self {
            activation_epoch,
            dns: tokio::sync::Mutex::new(dns_rx),
            healthy,
            task,
        })
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    fn retire(&self) {
        self.healthy.store(false, Ordering::Release);
        // The task owns the stream and therefore the boundary's exclusive DNS
        // lease. Retire it even while an old accept still owns this session.
        self.task.abort();
    }

    async fn accept_dns(&self) -> Result<PendingDnsQuery, BackendError> {
        self.dns.lock().await.recv().await.ok_or_else(|| {
            BackendError::Unavailable("persistent DNS mediation session ended".to_string())
        })
    }
}

impl Drop for ClientMediationSession {
    fn drop(&mut self) {
        // Cancellation between the opening acknowledgement and cache publication
        // must not detach a live stream that prevents the next lane from opening.
        self.retire();
    }
}

async fn run_client_mediation(
    stream: BoundaryDuplexStream,
    dns_tx: tokio::sync::mpsc::Sender<PendingDnsQuery>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (outbound_tx, mut outbound_rx) =
        tokio::sync::mpsc::channel::<OutboundMediationFrame>(MEDIATION_EVENT_QUEUE);
    let writer_task = async {
        while let Some(frame) = outbound_rx.recv().await {
            mediation::write_frame(&mut writer, frame.kind, frame.stream_id, &frame.payload)
                .await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let reader_task = async {
        while let Some(frame) = mediation::read_frame(&mut reader).await? {
            dispatch_client_mediation_frame(frame, &dns_tx, &outbound_tx).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::pin!(writer_task);
    tokio::pin!(reader_task);
    let result = tokio::select! {
        result = &mut writer_task => result,
        result = &mut reader_task => result,
    };
    result
}

async fn dispatch_client_mediation_frame(
    frame: MediationFrame,
    dns_tx: &tokio::sync::mpsc::Sender<PendingDnsQuery>,
    outbound: &tokio::sync::mpsc::Sender<OutboundMediationFrame>,
) -> std::io::Result<()> {
    match frame.kind {
        MediationFrameKind::DnsQuery => {
            let query: DnsQueryWire = mediation::decode_json(&frame.payload)?;
            let (response, completion) =
                tokio::sync::oneshot::channel::<Result<Vec<u8>, BackendError>>();
            let outbound = outbound.clone();
            tokio::spawn(async move {
                let response = match completion.await {
                    Ok(Ok(response)) => DnsQueryResultWire::Response(response),
                    Ok(Err(error)) => DnsQueryResultWire::Error(error.to_string()),
                    Err(_) => DnsQueryResultWire::Error(
                        "supervisor dropped the mediated DNS query".to_string(),
                    ),
                };
                if let Ok(payload) = mediation::encode_json(&response) {
                    let _ = outbound
                        .send(OutboundMediationFrame {
                            kind: MediationFrameKind::DnsResponse,
                            stream_id: frame.stream_id,
                            payload,
                        })
                        .await;
                }
            });
            dns_tx
                .send(PendingDnsQuery {
                    message: query.request,
                    transport: query.transport,
                    binary_identity: query.identity.into_result(),
                    timing: MediationTiming {
                        sandbox_notification_to_queue: Duration::from_micros(
                            query.timing.notification_to_queue_us,
                        ),
                        sandbox_queue_wait: Duration::from_micros(query.timing.queue_wait_us),
                        supervisor_received_at: Instant::now(),
                    },
                    response,
                })
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "DNS mediation consumer stopped",
                    )
                })?;
        }
        MediationFrameKind::DnsResponse => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unexpected supervisor-bound mediation frame {:?}",
                    frame.kind
                ),
            ));
        }
    }
    Ok(())
}

struct BoundaryClient {
    runtime_descriptor: SandboxRuntimeDescriptor,
    supervisor_instance_id: crate::boundary_protocol::SupervisorInstanceId,
    sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
    grpc_channel: tokio::sync::Mutex<Option<CachedGrpcChannel>>,
    mediation: tokio::sync::Mutex<Option<Arc<ClientMediationSession>>>,
    mediation_open: tokio::sync::Mutex<()>,
    attach_request: std::sync::Mutex<Option<RequestEnvelope>>,
    confirm_request: std::sync::Mutex<Option<RequestEnvelope>>,
    reconnect: tokio::sync::Mutex<()>,
    next_connection_generation: AtomicU64,
    credential_monitor_started: AtomicBool,
    activation: std::sync::Mutex<ConfigurationState>,
    activation_operations: tokio::sync::Mutex<()>,
    activation_ready: tokio::sync::watch::Sender<bool>,
}

/// Receipt publication shares one lock with transport invalidation, so a late
/// response from a replaced connection cannot restore workload readiness.
#[derive(Default)]
struct ConfigurationState {
    identity: Option<ConfigurationActivationIdentity>,
    activated: Option<ActivatedBoundaryConfiguration>,
    epoch: u64,
    cancellation_epoch: u64,
}

#[derive(Clone)]
struct CachedGrpcChannel {
    credential_epoch: openshell_core::jwt::CredentialEpoch,
    generation: u64,
    channel: tonic::transport::Channel,
}

impl BoundaryClient {
    fn new(
        runtime_descriptor: SandboxRuntimeDescriptor,
        sandbox_bearer: openshell_core::jwt::SessionBearerTokenSlot,
        supervisor_instance_id: crate::boundary_protocol::SupervisorInstanceId,
    ) -> Self {
        Self {
            runtime_descriptor,
            supervisor_instance_id,
            sandbox_bearer,
            grpc_channel: tokio::sync::Mutex::new(None),
            mediation: tokio::sync::Mutex::new(None),
            mediation_open: tokio::sync::Mutex::new(()),
            attach_request: std::sync::Mutex::new(None),
            confirm_request: std::sync::Mutex::new(None),
            reconnect: tokio::sync::Mutex::new(()),
            next_connection_generation: AtomicU64::new(1),
            credential_monitor_started: AtomicBool::new(false),
            activation: std::sync::Mutex::new(ConfigurationState::default()),
            activation_operations: tokio::sync::Mutex::new(()),
            activation_ready: tokio::sync::watch::channel(false).0,
        }
    }

    fn validate_identity(
        &self,
        identity: &ConfigurationActivationIdentity,
        registered: bool,
    ) -> Result<(), BackendError> {
        if registered {
            identity.validate()
        } else {
            identity.validate_bootstrap()
        }
        .map_err(|error| BackendError::Confirm(error.to_string()))?;
        if identity.runtime_generation != self.runtime_descriptor.generation
            || identity.boundary_session_id != self.runtime_descriptor.session_id.to_string()
            || identity.supervisor_instance_id != self.supervisor_instance_id.to_string()
        {
            return Err(BackendError::Confirm(
                "boundary activation identity does not match runtime descriptor or control process"
                    .to_string(),
            ));
        }
        let state = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(previous) = &state.identity {
            if !previous.same_incarnation(identity) {
                return Err(BackendError::Terminated(
                    "boundary incarnation changed; a new authorized runtime generation is required"
                        .to_string(),
                ));
            }
            if registered && previous.registration_revision != identity.registration_revision {
                return Err(BackendError::Denied(
                    "boundary registration revision does not match attached control".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_attached(
        &self,
        snapshot: &crate::boundary_protocol::SessionSnapshotWire,
        registration_revision: u64,
    ) -> Result<(), BackendError> {
        self.validate_identity(&snapshot.configuration.identity, true)?;
        if snapshot.generation != self.runtime_descriptor.generation
            || snapshot.configuration.identity.registration_revision != registration_revision
        {
            return Err(BackendError::Confirm(
                "attached generation or registration does not match requested identity".to_string(),
            ));
        }
        if let Some(configuration) = &snapshot.configuration.installed {
            configuration
                .validate()
                .map_err(|error| BackendError::Confirm(error.to_string()))?;
        }
        Ok(())
    }

    fn validate_confirmation(
        &self,
        evidence: &openshell_isolation_interface::contract::SandboxConfirmEvidence,
    ) -> Result<(), BackendError> {
        if evidence.generation != self.runtime_descriptor.generation
            || evidence.session_id != self.runtime_descriptor.session_id
            || evidence.resource_claims != self.runtime_descriptor.resource_claims
            || evidence.driver_fence != self.runtime_descriptor.driver_fence
            || evidence.identity != self.runtime_descriptor.workload_identity
        {
            return Err(BackendError::Confirm(
                "reconnected boundary confirmation does not match admitted runtime".to_string(),
            ));
        }
        evidence.validate(&self.runtime_descriptor.workload_identity)
    }

    fn invalidate_activation(&self) -> u64 {
        self.hold_activation(true).0
    }

    fn hold_activation(&self, cancel_operation: bool) -> (u64, u64) {
        let mut state = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.epoch = state.epoch.wrapping_add(1);
        if cancel_operation {
            state.cancellation_epoch = state.cancellation_epoch.wrapping_add(1);
        }
        state.activated = None;
        self.activation_ready.send_if_modified(|ready| {
            let changed = *ready;
            *ready = false;
            changed
        });
        (state.epoch, state.cancellation_epoch)
    }

    fn configuration_attempt_epoch(&self, cancellation_epoch: u64) -> Result<u64, BackendError> {
        let state = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.cancellation_epoch != cancellation_epoch {
            return Err(BackendError::Unavailable(
                "configuration operation was superseded while awaiting acknowledgement".to_string(),
            ));
        }
        Ok(state.epoch)
    }

    /// Retry only this pending operation after authenticated transport recovery.
    /// A reconnect can preserve its transaction, but an explicit hold, abort,
    /// or policy replacement cancels it and can never be repaired by retrying.
    async fn call_configuration(
        &self,
        request: Request,
        cancellation_epoch: u64,
    ) -> Result<(Response, u64), BackendError> {
        let envelope = Self::prepare_request(request)?;
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                self.configuration_attempt_epoch(cancellation_epoch)?;
                self.ensure_current_credential_connection().await?;
                let attempt_epoch = self.configuration_attempt_epoch(cancellation_epoch)?;
                match self.exchange_envelope(&envelope).await {
                    Ok(response) => {
                        let response_epoch =
                            self.configuration_attempt_epoch(cancellation_epoch)?;
                        if response_epoch != attempt_epoch {
                            // A response racing a different connection cannot
                            // acknowledge activation. Retry the exact operation
                            // on the newly confirmed connection before accepting it.
                            continue;
                        }
                        return Ok((response, response_epoch));
                    }
                    Err(BackendError::Unavailable(message))
                        if is_transport_unavailable(&message) =>
                    {
                        self.recover_after_unavailable().await?;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| {
            BackendError::Unavailable(
                "boundary configuration acknowledgement timed out".to_string(),
            )
        })?
    }

    fn publish_activation(
        &self,
        epoch: u64,
        activated: &ActivatedBoundaryConfiguration,
    ) -> Result<(), BackendError> {
        let mut state = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.epoch != epoch {
            return Err(BackendError::Unavailable("boundary reconnected before activation acknowledgement; configuration remains unready".to_string()));
        }
        state.activated = Some(activated.clone());
        self.activation_ready.send_replace(true);
        Ok(())
    }

    fn require_epoch(&self, epoch: u64) -> Result<(), BackendError> {
        if self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .epoch
            != epoch
        {
            return Err(BackendError::Unavailable("boundary connection changed during configuration transition; fresh admission is required".to_string()));
        }
        Ok(())
    }

    fn active_configuration(
        &self,
        provider_revision: u64,
    ) -> Result<ActivatedBoundaryConfiguration, BackendError> {
        let state = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let activated = state.activated.as_ref().ok_or_else(|| {
            BackendError::Denied("boundary configuration has not been released".to_string())
        })?;
        if activated.configuration.provider_env_revision != provider_revision {
            return Err(BackendError::Denied(
                "provider environment does not match active configuration".to_string(),
            ));
        }
        Ok(activated.clone())
    }

    fn require_active(
        &self,
        expected: &ActivatedBoundaryConfiguration,
    ) -> Result<(), BackendError> {
        let state = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.activated.as_ref() != Some(expected) {
            return Err(BackendError::Denied(
                "boundary activation changed during workload request".to_string(),
            ));
        }
        Ok(())
    }

    async fn replay_attachment(
        &self,
        channel: tonic::transport::Channel,
        attach: &RequestEnvelope,
        confirm: Option<&RequestEnvelope>,
    ) -> Result<(), BackendError> {
        // A replacement boundary rejects the previous process's signed grant.
        // Discover first so that replacement is classified as terminal instead
        // of entering credential repair against a different workload incarnation.
        let discovery = Self::prepare_request(Request::DescribeWorkload {
            supervisor_instance_id: self.supervisor_instance_id,
            resource_claims: self.runtime_descriptor.resource_claims.clone(),
        })?;
        let response = self
            .exchange_on_channel(channel.clone(), &discovery)
            .await?;
        let Response::WorkloadDescribed { bootstrap } = response else {
            return Err(unexpected_response("workload_described", &response));
        };
        self.validate_identity(&bootstrap.identity, false)?;
        if bootstrap.workload_identity != self.runtime_descriptor.workload_identity {
            return Err(BackendError::Terminated(
                "boundary workload identity changed during recovery".to_string(),
            ));
        }
        let Request::Attach {
            registration_revision,
            ..
        } = &attach.request
        else {
            return Err(BackendError::Attach(
                "cached boundary attachment has the wrong operation".to_string(),
            ));
        };
        let response = self.exchange_on_channel(channel.clone(), attach).await?;
        let Response::Attached { snapshot } = response else {
            return Err(unexpected_response("attached", &response));
        };
        self.validate_attached(&snapshot, *registration_revision)?;
        if let Some(confirm) = confirm {
            let response = self.exchange_on_channel(channel, confirm).await?;
            let Response::Confirmed { evidence } = response else {
                return Err(unexpected_response("confirmed", &response));
            };
            self.validate_confirmation(&evidence)?;
        }
        Ok(())
    }

    async fn call_idempotent(&self, request: Request) -> Result<Response, BackendError> {
        let remember_attach = matches!(request, Request::Attach { .. });
        let remember_confirm = matches!(request, Request::Confirm);
        let timeout = if remember_attach {
            ATTACH_REQUEST_TIMEOUT
        } else {
            REQUEST_TIMEOUT
        };
        let envelope = Self::prepare_request(request)?;
        tokio::time::timeout(timeout, async {
            loop {
                match self.exchange_envelope(&envelope).await {
                    Ok(response) => {
                        // Cache only verified lifecycle acknowledgements. Recovery
                        // must never replay a request whose peer rejected its identity.
                        match (&envelope.request, &response) {
                            (Request::Attach { registration_revision, .. }, Response::Attached { snapshot }) => {
                                self.validate_attached(snapshot, *registration_revision)?;
                            }
                            (Request::Confirm, Response::Confirmed { evidence }) => {
                                self.validate_confirmation(evidence)?;
                            }
                            (Request::Attach { .. }, _) => return Err(unexpected_response("attached", &response)),
                            (Request::Confirm, _) => return Err(unexpected_response("confirmed", &response)),
                            _ => {}
                        }
                        if remember_attach {
                            *self
                                .attach_request
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(envelope.clone());
                        }
                        if remember_confirm {
                            *self
                                .confirm_request
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(envelope.clone());
                        }
                        return Ok(response);
                    }
                    Err(BackendError::Unavailable(message))
                        if is_transport_unavailable(&message) =>
                    {
                        self.recover_after_unavailable().await?;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| {
            BackendError::Unavailable(
                "boundary idempotent control request timed out while waiting for remote boundary boot".to_string(),
            )
        })?
    }

    async fn call_wait(&self, request: Request) -> Result<Response, BackendError> {
        let envelope = Self::prepare_request(request)?;
        let mut recovery_deadline = None;
        loop {
            match self.exchange_envelope(&envelope).await {
                Ok(response) => return Ok(response),
                Err(BackendError::Unavailable(message)) if is_transport_unavailable(&message) => {
                    let deadline =
                        begin_recovery_window(&mut recovery_deadline, tokio::time::Instant::now());
                    if tokio::time::Instant::now() >= deadline {
                        return Err(BackendError::Unavailable(message));
                    }
                    self.recover_after_unavailable().await?;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn call_stream(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let envelope = Self::prepare_request(request)?;
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                match self.open_exchange_envelope(&envelope).await {
                    Ok(response) => return Ok(response),
                    Err(BackendError::Unavailable(message))
                        if is_transport_unavailable(&message) =>
                    {
                        self.recover_after_unavailable().await?;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| BackendError::Unavailable("boundary stream request timed out".to_string()))?
    }

    async fn call_stream_idempotent(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let envelope = Self::prepare_request(request)?;
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                match self.open_exchange_envelope(&envelope).await {
                    Ok(response) => return Ok(response),
                    Err(BackendError::Unavailable(message))
                        if is_transport_unavailable(&message) =>
                    {
                        self.recover_after_unavailable().await?;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| {
            BackendError::Unavailable("boundary idempotent stream request timed out".to_string())
        })?
    }

    #[cfg(test)]
    async fn exchange(&self, request: Request) -> Result<Response, BackendError> {
        let (_, response) = self.open_exchange(request).await?;
        Ok(response)
    }

    fn prepare_request(request: Request) -> Result<RequestEnvelope, BackendError> {
        RequestEnvelope::new(request)
            .map_err(|error| BackendError::Process(format!("encode control request: {error}")))
    }

    async fn open_exchange(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let envelope = Self::prepare_request(request)?;
        self.open_exchange_envelope(&envelope).await
    }

    async fn exchange_envelope(
        &self,
        envelope: &RequestEnvelope,
    ) -> Result<Response, BackendError> {
        let (_, response) = self.open_exchange_envelope(envelope).await?;
        Ok(response)
    }

    async fn open_exchange_envelope(
        &self,
        envelope: &RequestEnvelope,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let request_id = envelope.request_id.clone();
        let mut stream = self.open_grpc_stream(GrpcStreamKind::Exchange).await?;
        let frame = encode_frame(envelope)
            .map_err(|error| BackendError::Process(format!("encode control request: {error}")))?;
        stream.write_all(&frame).await.map_err(|error| {
            BackendError::Unavailable(format!("write boundary control request: {error}"))
        })?;
        // `tokio-rustls` may retain part of a large plaintext frame in its
        // internal TLS buffer. Flush before waiting for the response so the
        // synchronous boundary reader can receive the complete request.
        stream.flush().await.map_err(|error| {
            BackendError::Unavailable(format!("flush boundary control request: {error}"))
        })?;
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await.map_err(|error| {
            BackendError::Unavailable(format!("read boundary control response header: {error}"))
        })?;
        let declared = u32::from_be_bytes(header) as usize;
        if declared > MAX_CONTROL_FRAME_BYTES {
            return Err(BackendError::Process(format!(
                "boundary control response is too large: {declared} bytes"
            )));
        }
        let mut frame = Vec::with_capacity(4 + declared);
        frame.extend_from_slice(&header);
        frame.resize(4 + declared, 0);
        stream.read_exact(&mut frame[4..]).await.map_err(|error| {
            BackendError::Unavailable(format!("read boundary control response: {error}"))
        })?;
        let response: ResponseEnvelope = decode_frame(&frame)
            .map_err(|error| BackendError::Process(format!("decode control response: {error}")))?;
        if response.request_id != request_id {
            return Err(BackendError::Process(format!(
                "boundary response ID {} did not match request ID {request_id}",
                response.request_id
            )));
        }
        let response = match response.response {
            Response::Error { kind, message } => Err(guest_error(kind, message)),
            response => Ok(response),
        }?;
        Ok((stream, response))
    }

    async fn open_grpc_stream(
        &self,
        kind: GrpcStreamKind,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        self.ensure_current_credential_connection().await?;
        let channel = self.grpc_channel().await?;
        open_grpc_client_stream(channel, kind, &self.sandbox_bearer).await
    }

    async fn ensure_current_credential_connection(&self) -> Result<(), BackendError> {
        let credential_epoch = self.sandbox_bearer.credential_epoch().ok_or_else(|| {
            BackendError::Unavailable("Sandbox Protocol credential unavailable".to_string())
        })?;
        if self
            .grpc_channel
            .lock()
            .await
            .as_ref()
            .is_none_or(|cached| cached.credential_epoch == credential_epoch)
        {
            return Ok(());
        }

        let _reconnect = self.reconnect.lock().await;
        if self
            .grpc_channel
            .lock()
            .await
            .as_ref()
            .is_some_and(|cached| cached.credential_epoch == credential_epoch)
        {
            return Ok(());
        }
        let attach = self
            .attach_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                BackendError::Unavailable(
                    "cannot rotate Sandbox Protocol connection before attach".to_string(),
                )
            })?;
        let confirm = self
            .confirm_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                BackendError::Unavailable(
                    "cannot rotate Sandbox Protocol connection before confirmation".to_string(),
                )
            })?;
        // Authentication/confirmation establishes connection ownership only.
        // Configuration acceptance must be repeated before any workload resumes.
        self.hold_activation(false);
        let channel = self.build_grpc_channel().await?;
        self.replay_attachment(channel.clone(), &attach, Some(&confirm))
            .await?;
        *self.grpc_channel.lock().await = Some(CachedGrpcChannel {
            credential_epoch,
            generation: self
                .next_connection_generation
                .fetch_add(1, Ordering::Relaxed),
            channel,
        });
        *self.mediation.lock().await = None;
        Ok(())
    }

    /// Replace a failed physical transport and replay the authenticated
    /// lifecycle needed to make the new HTTP/2 connection authoritative.
    async fn recover_after_unavailable(&self) -> Result<(), BackendError> {
        let observed_generation = self
            .grpc_channel
            .lock()
            .await
            .as_ref()
            .map(|cached| cached.generation);
        let _reconnect = self.reconnect.lock().await;
        if self
            .grpc_channel
            .lock()
            .await
            .as_ref()
            .map(|cached| cached.generation)
            != observed_generation
        {
            return Ok(());
        }

        self.hold_activation(false);
        *self.grpc_channel.lock().await = None;
        *self.mediation.lock().await = None;
        let attach = self
            .attach_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(attach) = attach else {
            return Ok(());
        };
        let confirm = self
            .confirm_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let credential_epoch = self.sandbox_bearer.credential_epoch().ok_or_else(|| {
            BackendError::Unavailable("Sandbox Protocol credential unavailable".to_string())
        })?;
        let channel = self.build_grpc_channel().await?;
        self.replay_attachment(channel.clone(), &attach, confirm.as_ref())
            .await?;
        *self.grpc_channel.lock().await = Some(CachedGrpcChannel {
            credential_epoch,
            generation: self
                .next_connection_generation
                .fetch_add(1, Ordering::Relaxed),
            channel,
        });
        Ok(())
    }

    fn start_credential_monitor(self: &Arc<Self>) {
        if self.credential_monitor_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let client = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(client) = client.upgrade() else {
                    return;
                };
                if let Err(error) = client.ensure_current_credential_connection().await {
                    tracing::warn!(%error, "failed to rotate Sandbox Protocol connection");
                }
            }
        });
    }

    async fn exchange_on_channel(
        &self,
        channel: tonic::transport::Channel,
        envelope: &RequestEnvelope,
    ) -> Result<Response, BackendError> {
        let request_id = envelope.request_id.clone();
        let mut stream =
            open_grpc_client_stream(channel, GrpcStreamKind::Exchange, &self.sandbox_bearer)
                .await?;
        let frame = encode_frame(envelope)
            .map_err(|error| BackendError::Process(format!("encode control request: {error}")))?;
        stream.write_all(&frame).await.map_err(|error| {
            BackendError::Unavailable(format!("write boundary control request: {error}"))
        })?;
        stream.flush().await.map_err(|error| {
            BackendError::Unavailable(format!("flush boundary control request: {error}"))
        })?;
        let response =
            crate::boundary_protocol::read_frame_async::<_, ResponseEnvelope>(&mut stream)
                .await
                .map_err(|error| {
                    BackendError::Unavailable(format!("read boundary control response: {error}"))
                })?;
        if response.request_id != request_id {
            return Err(BackendError::Process(
                "boundary response ID did not match request ID".to_string(),
            ));
        }
        match response.response {
            Response::Error { kind, message } => Err(guest_error(kind, message)),
            response => Ok(response),
        }
    }

    fn active_mediation_epoch(&self) -> Option<u64> {
        let state = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.activated.as_ref().map(|_| state.epoch)
    }

    /// Network consumers start before initial release and outlive later holds.
    /// A hold retires their streams; only a fresh acknowledged release permits
    /// another accept. Other failures must still reach the supervising task.
    async fn accept_mediation<T, F, Fut>(&self, mut accept: F) -> Result<T, BackendError>
    where
        F: FnMut(u64) -> Fut,
        Fut: Future<Output = Result<T, BackendError>>,
    {
        let mut readiness = self.activation_ready.subscribe();
        loop {
            let epoch = loop {
                if let Some(epoch) = self.active_mediation_epoch() {
                    break epoch;
                }
                readiness.changed().await.map_err(|_| {
                    BackendError::Terminated("boundary activation monitor ended".to_string())
                })?;
            };
            let result = accept(epoch).await;
            if self.active_mediation_epoch() != Some(epoch)
                && matches!(&result, Ok(_) | Err(BackendError::Unavailable(_)))
            {
                // Discard stale successes as well as streams closed by hold.
                // Authentication and identity failures remain terminal even
                // when their connection recovery also revoked readiness.
                continue;
            }
            return result;
        }
    }

    async fn mediation_session(
        &self,
        activation_epoch: u64,
    ) -> Result<Arc<ClientMediationSession>, BackendError> {
        if let Some(session) = self.healthy_mediation_session(activation_epoch).await? {
            return Ok(session);
        }

        // Serialize creation without holding the cached-session mutex. Opening
        // a stream may rotate credentials or recover the physical connection;
        // both paths clear the cache and must be free to acquire that mutex.
        let _opening = self.mediation_open.lock().await;
        if let Some(session) = self.healthy_mediation_session(activation_epoch).await? {
            return Ok(session);
        }

        // The boundary owns exclusive-lease retirement and bounds replacement
        // waiting. Never multiply that deadline with message-matching retries.
        let session = tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                match self.open_mediation_session(activation_epoch).await {
                    Ok(session) => return Ok(session),
                    Err(BackendError::Unavailable(message))
                        if is_transport_unavailable(&message) =>
                    {
                        self.require_epoch(activation_epoch)?;
                        self.recover_after_unavailable().await?;
                        // Recovery holds the boundary. Return to the outer
                        // readiness wait instead of reopening while held.
                        self.require_epoch(activation_epoch)?;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| {
            BackendError::Unavailable("boundary mediation attach timed out".to_string())
        })??;
        let mut cached = self.mediation.lock().await;
        // The cache lock can suspend after a successful open. Reject a retired
        // epoch before publishing; dropping the owned session also closes its lane.
        self.require_epoch(activation_epoch)?;
        *cached = Some(session.clone());
        Ok(session)
    }

    async fn healthy_mediation_session(
        &self,
        activation_epoch: u64,
    ) -> Result<Option<Arc<ClientMediationSession>>, BackendError> {
        let mut cached = self.mediation.lock().await;
        // A stale waiter must never retire a lane already opened by a newer epoch.
        self.require_epoch(activation_epoch)?;
        if let Some(session) = cached.as_ref()
            && session.is_healthy()
            && session.activation_epoch == activation_epoch
        {
            return Ok(Some(session.clone()));
        }
        if let Some(session) = cached.take() {
            session.retire();
        }
        Ok(None)
    }

    async fn open_mediation_session(
        &self,
        activation_epoch: u64,
    ) -> Result<Arc<ClientMediationSession>, BackendError> {
        let activation_changes = self.activation_ready.subscribe();
        self.require_epoch(activation_epoch)?;
        let mut stream = self.open_grpc_stream(GrpcStreamKind::Mediate).await?;
        let envelope = Self::prepare_request(Request::OpenMediation)?;
        let request_id = envelope.request_id.clone();
        let frame = encode_frame(&envelope)
            .map_err(|error| BackendError::Process(format!("encode mediation attach: {error}")))?;
        stream.write_all(&frame).await.map_err(|error| {
            BackendError::Unavailable(format!("write mediation attach: {error}"))
        })?;
        stream.flush().await.map_err(|error| {
            BackendError::Unavailable(format!("flush mediation attach: {error}"))
        })?;
        let response =
            crate::boundary_protocol::read_frame_async::<_, ResponseEnvelope>(&mut stream)
                .await
                .map_err(|error| {
                    BackendError::Unavailable(format!("read mediation attach: {error}"))
                })?;
        if response.request_id != request_id {
            return Err(BackendError::Process(
                "mediation attach response ID did not match request".to_string(),
            ));
        }
        match response.response {
            Response::MediationReady => {}
            Response::Error { kind, message } => return Err(guest_error(kind, message)),
            response => return Err(unexpected_response("mediation_ready", &response)),
        }
        self.require_epoch(activation_epoch)?;
        Ok(ClientMediationSession::start(
            stream,
            activation_epoch,
            activation_changes,
        ))
    }

    async fn grpc_channel(&self) -> Result<tonic::transport::Channel, BackendError> {
        let mut state = self.grpc_channel.lock().await;
        if let Some(cached) = state.as_ref() {
            return Ok(cached.channel.clone());
        }
        let credential_epoch = self.sandbox_bearer.credential_epoch().ok_or_else(|| {
            BackendError::Unavailable("Sandbox Protocol credential unavailable".to_string())
        })?;
        let channel = self.build_grpc_channel().await?;
        *state = Some(CachedGrpcChannel {
            credential_epoch,
            generation: self
                .next_connection_generation
                .fetch_add(1, Ordering::Relaxed),
            channel: channel.clone(),
        });
        Ok(channel)
    }

    async fn build_grpc_channel(&self) -> Result<tonic::transport::Channel, BackendError> {
        let runtime_descriptor = self.runtime_descriptor.clone();
        let endpoint =
            tonic::transport::Endpoint::from_static("http://boundary.openshell.internal")
                .initial_stream_window_size(16 * 1024 * 1024)
                .initial_connection_window_size(16 * 1024 * 1024)
                .http2_keep_alive_interval(Duration::from_secs(10))
                .keep_alive_while_idle(true);
        let channel = endpoint
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let runtime_descriptor = runtime_descriptor.clone();
                async move {
                    connect_boundary_with_retry(&runtime_descriptor)
                        .await
                        .map(TokioIo::new)
                        .map_err(|error| std::io::Error::other(error.to_string()))
                }
            }))
            .await
            .map_err(|error| {
                BackendError::Unavailable(format!("start boundary gRPC channel: {error}"))
            })?;
        Ok(channel)
    }

    #[cfg(test)]
    async fn connect_boundary_once(&self) -> Result<BoundaryDuplexStream, BackendError> {
        connect_boundary_once(&self.runtime_descriptor).await
    }
}

#[async_trait]
impl BoundaryConfiguration for BoundaryClient {
    fn identity(&self) -> ConfigurationActivationIdentity {
        self.activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .identity
            .clone()
            .unwrap_or_else(|| ConfigurationActivationIdentity {
                runtime_generation: self.runtime_descriptor.generation.clone(),
                boundary_session_id: self.runtime_descriptor.session_id.to_string(),
                supervisor_instance_id: self.supervisor_instance_id.to_string(),
                boundary_instance_id: String::new(),
                registration_revision: 0,
            })
    }

    fn readiness(&self) -> tokio::sync::watch::Receiver<bool> {
        self.activation_ready.subscribe()
    }

    async fn snapshot(&self) -> Result<BoundaryConfigurationSnapshot, BackendError> {
        let identity = self.identity();
        self.validate_identity(&identity, true)?;
        let response = self
            .call_idempotent(Request::ConfigurationSnapshot { identity })
            .await?;
        let Response::ConfigurationSnapshot { snapshot } = response else {
            return Err(unexpected_response("configuration_snapshot", &response));
        };
        self.validate_identity(&snapshot.identity, true)?;
        if let Some(configuration) = &snapshot.installed {
            configuration
                .validate()
                .map_err(|error| BackendError::Confirm(error.to_string()))?;
        } else if snapshot.active {
            return Err(BackendError::Confirm(
                "boundary reported active without installed configuration".to_string(),
            ));
        }
        let released_tuple_changed = self
            .activation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .activated
            .as_ref()
            .is_some_and(|activated| {
                snapshot.active && snapshot.installed.as_ref() != Some(&activated.configuration)
            });
        if released_tuple_changed {
            self.invalidate_activation();
            return Err(BackendError::Confirm(
                "boundary snapshot changed the released configuration without activation"
                    .to_string(),
            ));
        }
        // A snapshot does not prove gateway acceptance or convey a release token.
        // Only release may publish readiness, even if the peer reports active.
        if !snapshot.active
            && self
                .activation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .activated
                .is_some()
        {
            self.invalidate_activation();
        }
        Ok(snapshot)
    }

    async fn prepare(
        &self,
        expected: Option<ConfigurationRevision>,
        candidate: ConfigurationRevision,
        child_env: HashMap<String, String>,
    ) -> Result<PreparedBoundaryConfiguration, BackendError> {
        let _operation = self.activation_operations.lock().await;
        candidate
            .validate()
            .map_err(|error| BackendError::Configuration(error.to_string()))?;
        if let Some(expected) = &expected {
            expected
                .validate()
                .map_err(|error| BackendError::Configuration(error.to_string()))?;
        }
        if child_env
            .iter()
            .any(|(key, value)| key.is_empty() || key.contains(['=', '\0']) || value.contains('\0'))
        {
            return Err(BackendError::Configuration(
                "provider environment contains an invalid variable".to_string(),
            ));
        }
        let identity = self.identity();
        self.validate_identity(&identity, true)?;
        let request = Request::PrepareConfiguration {
            identity: identity.clone(),
            expected: expected.clone(),
            configuration: candidate.clone(),
            provider_env: child_env,
        };
        // Validate the frame before closing admission so malformed oversized
        // inputs cannot start a boundary transition or expose their contents.
        encode_frame(&Self::prepare_request(request.clone())?).map_err(|_| {
            BackendError::Configuration(
                "provider configuration exceeds the control frame limit".to_string(),
            )
        })?;
        let (_, cancellation_epoch) = self.hold_activation(true);
        let (response, epoch) = self.call_configuration(request, cancellation_epoch).await?;
        let Response::ConfigurationPrepared { prepared } = response else {
            return Err(unexpected_response("configuration_prepared", &response));
        };
        validate_prepared_receipt(&prepared, &identity, &expected, &candidate)?;
        self.require_epoch(epoch)?;
        Ok(*prepared)
    }

    async fn commit(
        &self,
        prepared: &PreparedBoundaryConfiguration,
    ) -> Result<InstalledBoundaryConfiguration, BackendError> {
        let _operation = self.activation_operations.lock().await;
        self.validate_identity(&prepared.identity, true)?;
        validate_prepared_receipt(
            prepared,
            &self.identity(),
            &prepared.expected,
            &prepared.configuration,
        )?;
        let (_, cancellation_epoch) = self.hold_activation(true);
        let (response, epoch) = self
            .call_configuration(
                Request::CommitConfiguration {
                    prepared: Box::new(prepared.clone()),
                },
                cancellation_epoch,
            )
            .await?;
        let Response::ConfigurationCommitted { installed } = response else {
            return Err(unexpected_response("configuration_committed", &response));
        };
        validate_installed_receipt(&installed, prepared)?;
        self.require_epoch(epoch)?;
        Ok(*installed)
    }

    async fn release(
        &self,
        installed: &InstalledBoundaryConfiguration,
    ) -> Result<ActivatedBoundaryConfiguration, BackendError> {
        let _operation = self.activation_operations.lock().await;
        self.validate_identity(&installed.identity, true)?;
        installed
            .configuration
            .validate()
            .map_err(|error| BackendError::Configuration(error.to_string()))?;
        validate_transition_id(&installed.transition_id)?;
        let (_, cancellation_epoch) = self.hold_activation(true);
        let (response, epoch) = self
            .call_configuration(
                Request::ReleaseConfiguration {
                    installed: Box::new(installed.clone()),
                },
                cancellation_epoch,
            )
            .await?;
        let Response::ConfigurationReleased { activated } = response else {
            return Err(unexpected_response("configuration_released", &response));
        };
        validate_released_receipt(&activated, installed)?;
        self.publish_activation(epoch, &activated)?;
        Ok(*activated)
    }

    async fn abort(&self, prepared: &PreparedBoundaryConfiguration) -> Result<(), BackendError> {
        self.validate_identity(&prepared.identity, true)?;
        self.invalidate_activation();
        let _operation = self.activation_operations.lock().await;
        let response = self
            .call_idempotent(Request::AbortConfiguration {
                prepared: Box::new(prepared.clone()),
            })
            .await?;
        if !matches!(response, Response::ConfigurationAborted) {
            return Err(unexpected_response("configuration_aborted", &response));
        }
        // Aborting never restores the previous release token. Retention of a
        // previous candidate must use a fresh prepare/commit/accept/release.
        Ok(())
    }

    async fn quiesce(&self) -> Result<(), BackendError> {
        self.invalidate_activation();
        let _operation = self.activation_operations.lock().await;
        let identity = self.identity();
        self.validate_identity(&identity, true)?;
        let response = self
            .call_idempotent(Request::QuiesceConfiguration { identity })
            .await?;
        if !matches!(response, Response::ConfigurationQuiesced) {
            return Err(unexpected_response("configuration_quiesced", &response));
        }
        Ok(())
    }

    async fn refresh_registration(
        &self,
        grant: openshell_core::jwt::SecretJwt,
        registration_revision: u64,
    ) -> Result<(), BackendError> {
        if registration_revision != self.identity().registration_revision {
            return Err(BackendError::Denied(
                "registration refresh must retain the current registration revision".to_string(),
            ));
        }
        let mut attach = self
            .attach_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(envelope) = attach.as_ref() else {
            return Err(BackendError::Attach(
                "cannot refresh registration before attachment".to_string(),
            ));
        };
        let mut request = envelope.request.clone();
        let Request::Attach {
            registration_grant, ..
        } = &mut request
        else {
            return Err(BackendError::Attach(
                "cached registration has the wrong operation".to_string(),
            ));
        };
        *registration_grant = grant.expose_secret().to_string();
        // The refreshed grant changes the signed attachment body. Give it a
        // matching digest and fresh idempotency key before reconnect replay.
        *attach = Some(Self::prepare_request(request)?);
        Ok(())
    }
}

fn validate_transition_id(transition_id: &str) -> Result<(), BackendError> {
    if transition_id.is_empty()
        || transition_id.len() > 256
        || transition_id.chars().any(char::is_whitespace)
    {
        return Err(BackendError::Confirm(
            "invalid configuration transition identity".to_string(),
        ));
    }
    Ok(())
}

fn validate_prepared_receipt(
    receipt: &PreparedBoundaryConfiguration,
    identity: &ConfigurationActivationIdentity,
    expected: &Option<ConfigurationRevision>,
    candidate: &ConfigurationRevision,
) -> Result<(), BackendError> {
    identity
        .validate()
        .map_err(|error| BackendError::Configuration(error.to_string()))?;
    candidate
        .validate()
        .map_err(|error| BackendError::Configuration(error.to_string()))?;
    if let Some(expected) = expected {
        expected
            .validate()
            .map_err(|error| BackendError::Configuration(error.to_string()))?;
    }
    validate_transition_id(&receipt.transition_id)?;
    if &receipt.identity != identity
        || &receipt.expected != expected
        || &receipt.configuration != candidate
    {
        return Err(BackendError::Confirm("prepared configuration receipt does not match requested identity, previous tuple, or candidate".to_string()));
    }
    Ok(())
}

fn validate_installed_receipt(
    receipt: &InstalledBoundaryConfiguration,
    prepared: &PreparedBoundaryConfiguration,
) -> Result<(), BackendError> {
    if receipt.identity != prepared.identity
        || receipt.transition_id != prepared.transition_id
        || receipt.configuration != prepared.configuration
    {
        return Err(BackendError::Confirm(
            "installed configuration receipt does not match preparation".to_string(),
        ));
    }
    Ok(())
}

fn validate_released_receipt(
    receipt: &ActivatedBoundaryConfiguration,
    installed: &InstalledBoundaryConfiguration,
) -> Result<(), BackendError> {
    if receipt.identity != installed.identity
        || receipt.transition_id != installed.transition_id
        || receipt.configuration != installed.configuration
    {
        return Err(BackendError::Confirm(
            "released configuration receipt does not match installation".to_string(),
        ));
    }
    Ok(())
}

fn validate_launch_acknowledgement(
    expected: &ActivatedBoundaryConfiguration,
    acknowledged: &ActivatedBoundaryConfiguration,
    provider_revision: u64,
) -> Result<(), BackendError> {
    if acknowledged != expected || provider_revision != expected.configuration.provider_env_revision
    {
        return Err(BackendError::Confirm(
            "workload acknowledgement does not match released configuration and provider revision"
                .to_string(),
        ));
    }
    Ok(())
}

async fn connect_boundary_with_retry(
    runtime_descriptor: &SandboxRuntimeDescriptor,
) -> Result<BoundaryDuplexStream, BackendError> {
    let deadline = tokio::time::Instant::now() + CONNECT_RETRY_TIMEOUT;
    loop {
        match connect_boundary_once(runtime_descriptor).await {
            Ok(stream) => return Ok(stream),
            Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
}

async fn connect_boundary_once(
    runtime_descriptor: &SandboxRuntimeDescriptor,
) -> Result<BoundaryDuplexStream, BackendError> {
    let stream: BoundaryDuplexStream = match &runtime_descriptor.transport {
        #[cfg(unix)]
        SandboxTransport::Unix { socket_path } => {
            let stream = UnixStream::connect(socket_path).await.map_err(|error| {
                BackendError::Unavailable(format!(
                    "connect to mapped boundary control socket {}: {error}",
                    socket_path.display()
                ))
            })?;
            Box::new(stream)
        }
        #[cfg(not(unix))]
        SandboxTransport::Unix { .. } => {
            return Err(BackendError::Unavailable(
                "Unix boundary transport requires a Unix host".to_string(),
            ));
        }
        SandboxTransport::Tcp {
            authority,
            addresses,
        } => {
            let stream = openshell_core::net::connect_tcp_nodelay_best_effort(addresses)
                .await
                .map_err(|error| {
                    BackendError::Unavailable(format!(
                        "connect to boundary TLS endpoint {authority}: {error}"
                    ))
                })?;
            enable_boundary_tcp_keepalive(&stream);
            Box::new(stream)
        }
        SandboxTransport::Vsock { guest_cid, port } => connect_host_vsock(*guest_cid, *port)?,
    };
    let tls = &runtime_descriptor.tls;
    let server_name =
        rustls::pki_types::ServerName::try_from(tls.server_name.clone()).map_err(|error| {
            BackendError::Descriptor(format!(
                "boundary TLS server name {:?} is invalid: {error}",
                tls.server_name
            ))
        })?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_client_config(tls)?));
    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| {
            BackendError::Unavailable(format!("authenticate sandbox channel: {error}"))
        })?;
    Ok(Box::new(stream))
}

#[derive(Clone, Copy)]
enum GrpcStreamKind {
    Exchange,
    Mediate,
}

async fn open_grpc_client_stream(
    channel: tonic::transport::Channel,
    kind: GrpcStreamKind,
    sandbox_bearer: &openshell_core::jwt::SessionBearerTokenSlot,
) -> Result<BoundaryDuplexStream, BackendError> {
    let (application, bridge) = tokio::io::duplex(256 * 1024);
    let (reader, writer) = tokio::io::split(bridge);
    let (outbound, outbound_rx) = tokio::sync::mpsc::channel::<BoundaryChunk>(64);
    tokio::spawn(pump_to_grpc(reader, outbound));
    let mut client = IsolationBoundaryClient::new(channel)
        .max_decoding_message_size(64 * 1024)
        .max_encoding_message_size(64 * 1024);
    let mut request = tonic::Request::new(ReceiverStream::new(outbound_rx));
    let authorization = sandbox_bearer.authorization_metadata().map_err(|error| {
        BackendError::Unavailable(format!("Sandbox Protocol credential unavailable: {error}"))
    })?;
    request
        .metadata_mut()
        .insert("authorization", authorization);
    let response = match kind {
        GrpcStreamKind::Exchange => client.exchange(request).await,
        GrpcStreamKind::Mediate => client.mediate(request).await,
    }
    .map_err(|error| match error.code() {
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
            BackendError::Denied(format!("authenticate Sandbox Protocol stream: {error}"))
        }
        _ => BackendError::Unavailable(format!("open boundary gRPC stream: {error}")),
    })?;
    tokio::spawn(pump_from_grpc(response.into_inner(), writer));
    Ok(Box::new(application))
}

async fn pump_to_grpc<R>(mut reader: R, sender: tokio::sync::mpsc::Sender<BoundaryChunk>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(read) => read,
            Err(error) => {
                tracing::debug!(%error, "boundary gRPC request reader ended");
                return;
            }
        };
        if read == 0 {
            return;
        }
        if sender
            .send(BoundaryChunk {
                data: buffer[..read].to_vec(),
            })
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn pump_from_grpc<W>(mut stream: tonic::Streaming<BoundaryChunk>, mut writer: W)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        match stream.message().await {
            Ok(Some(chunk)) => {
                if let Err(error) = writer.write_all(&chunk.data).await {
                    tracing::debug!(%error, "boundary gRPC response writer ended");
                    return;
                }
            }
            Ok(None) => {
                let _ = writer.shutdown().await;
                return;
            }
            Err(error) => {
                tracing::debug!(%error, "boundary gRPC response stream ended");
                // The sibling read half keeps the split duplex alive. Close the
                // response direction so the client observes EOF and reconnects.
                let _ = writer.shutdown().await;
                return;
            }
        }
    }
}

fn enable_boundary_tcp_keepalive(stream: &tokio::net::TcpStream) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

#[cfg(target_os = "linux")]
fn connect_host_vsock(
    guest_cid: u32,
    control_port: u32,
) -> Result<BoundaryDuplexStream, BackendError> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(BackendError::Unavailable(format!(
            "create host vsock: {}",
            std::io::Error::last_os_error()
        )));
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let family = libc::sa_family_t::try_from(libc::AF_VSOCK).map_err(|error| {
        BackendError::Unavailable(format!("convert host vsock address family: {error}"))
    })?;
    let address = libc::sockaddr_vm {
        svm_family: family,
        svm_reserved1: 0,
        svm_port: control_port,
        svm_cid: guest_cid,
        svm_zero: [0; 4],
    };
    let address_length =
        libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>()).map_err(|error| {
            BackendError::Unavailable(format!("convert host vsock address length: {error}"))
        })?;
    let result = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            (&raw const address).cast::<libc::sockaddr>(),
            address_length,
        )
    };
    if result != 0 {
        return Err(BackendError::Unavailable(format!(
            "connect host vsock CID {guest_cid} port {control_port}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd.into_raw_fd()) };
    stream.set_nonblocking(true).map_err(|error| {
        BackendError::Unavailable(format!("set host vsock nonblocking: {error}"))
    })?;
    let stream = UnixStream::from_std(stream).map_err(|error| {
        BackendError::Unavailable(format!("register host vsock with Tokio: {error}"))
    })?;
    Ok(Box::new(stream))
}

#[cfg(not(target_os = "linux"))]
fn connect_host_vsock(
    _guest_cid: u32,
    _control_port: u32,
) -> Result<BoundaryDuplexStream, BackendError> {
    Err(BackendError::Unavailable(
        "host AF_VSOCK transport is supported only on Linux".to_string(),
    ))
}

fn expect_response(response: Response, expected: &str) -> Result<(), BackendError> {
    let matches = matches!(
        (&response, expected),
        (Response::Attached { .. }, "attached")
            | (Response::Confirmed { .. }, "confirmed")
            | (Response::Signaled, "signaled")
            | (Response::Terminated, "terminated")
    );
    if matches {
        Ok(())
    } else {
        Err(unexpected_response(expected, &response))
    }
}

fn unexpected_response(expected: &str, _response: &Response) -> BackendError {
    BackendError::Process(format!(
        "expected boundary response {expected:?}, received a different response kind"
    ))
}

fn guest_error(kind: crate::boundary_protocol::BoundaryErrorKind, message: String) -> BackendError {
    use crate::boundary_protocol::BoundaryErrorKind;
    let message = format!("boundary process leaf: {message}");
    match kind {
        BoundaryErrorKind::Invalid => BackendError::Descriptor(message),
        BoundaryErrorKind::Configuration => BackendError::Configuration(message),
        BoundaryErrorKind::Denied => BackendError::Denied(message),
        BoundaryErrorKind::Unavailable => BackendError::Unavailable(message),
        BoundaryErrorKind::Terminated => BackendError::Terminated(message),
        BoundaryErrorKind::Process => BackendError::Process(message),
    }
}

fn is_transport_unavailable(message: &str) -> bool {
    !message.starts_with("boundary process leaf:")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;
    use crate::boundary_protocol::generate_sandbox_tls_material;
    use crate::proto::{
        BoundaryChunk,
        isolation_boundary_server::{IsolationBoundary, IsolationBoundaryServer},
    };
    use openshell_core::jwt::{SecretJwt, SessionBearerTokenSlot};
    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };

    fn test_supervisor_instance_id() -> crate::boundary_protocol::SupervisorInstanceId {
        "22222222-2222-4222-8222-222222222222"
            .parse()
            .expect("supervisor instance")
    }

    fn test_activation() -> ActivatedBoundaryConfiguration {
        ActivatedBoundaryConfiguration {
            identity: ConfigurationActivationIdentity {
                runtime_generation: "test-generation".to_string(),
                boundary_session_id: test_session_id().to_string(),
                supervisor_instance_id: test_supervisor_instance_id().to_string(),
                boundary_instance_id: "33333333-3333-4333-8333-333333333333".to_string(),
                registration_revision: 1,
            },
            configuration: ConfigurationRevision {
                config_revision: 1,
                policy_version: 1,
                policy_hash: "sha256:test".to_string(),
                policy_source: openshell_core::proto::PolicySource::Sandbox as i32,
                provider_env_revision: 1,
            },
            transition_id: "test-transition".to_string(),
        }
    }

    fn test_prepared() -> PreparedBoundaryConfiguration {
        let activation = test_activation();
        PreparedBoundaryConfiguration {
            identity: activation.identity,
            transition_id: activation.transition_id,
            expected: None,
            configuration: activation.configuration,
        }
    }

    fn test_installed() -> InstalledBoundaryConfiguration {
        let activation = test_activation();
        InstalledBoundaryConfiguration {
            identity: activation.identity,
            transition_id: activation.transition_id,
            configuration: activation.configuration,
        }
    }

    async fn configuration_client(
        response_override: Option<Response>,
    ) -> (Arc<BoundaryClient>, tokio::task::JoinHandle<()>) {
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            response_override,
            response_permits: None,
        };
        configuration_client_with_service(service).await
    }

    async fn configuration_client_with_service<T: IsolationBoundary>(
        service: T,
    ) -> (Arc<BoundaryClient>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tonic::transport::Server::builder()
                .add_service(IsolationBoundaryServer::new(service))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(stream)]))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let client = Arc::new(BoundaryClient::new(
            tls_runtime_descriptor(address, test_certificate().client_tls),
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        ));
        *client.grpc_channel.lock().await = Some(CachedGrpcChannel {
            credential_epoch: openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            generation: 1,
            channel,
        });
        client.activation.lock().unwrap().identity = Some(test_activation().identity);
        (client, server)
    }

    fn shutdown_test_running(client: Arc<BoundaryClient>) -> RemoteRunning {
        RemoteRunning {
            process: Arc::new(RemoteProcess {
                client: client.clone(),
                process_id: "test-generation:main:0".to_string(),
                exit_status: std::sync::Mutex::new(None),
            }),
            terminated: tokio::sync::Mutex::new(false),
            exec: Arc::new(RemoteExec {
                client: client.clone(),
                provider_credentials: openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(1, HashMap::new()),
            }),
            loopback_connector: Arc::new(RemoteLoopbackConnector { client }),
        }
    }

    #[tokio::test]
    async fn shutdown_receipt_caches_main_status_without_post_terminal_rpc() {
        for status in [ExitStatusWire::Exited(7), ExitStatusWire::Signaled(15)] {
            let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (client, server) = configuration_client_with_service(TestGrpcBoundary {
                wait_for_half_close: false,
                expected_token: "a".repeat(32),
                requests: requests.clone(),
                mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                mediation_ready: false,
                response_override: Some(Response::BoundaryTerminated {
                    main_exit_status: Some(status),
                }),
                response_permits: None,
            })
            .await;
            let running = shutdown_test_running(client);
            let retained_agent = running.agent();
            running.terminate().await.expect("terminal receipt");
            // A new remote Wait would receive the wrong response kind here.
            // Stable status and repeat termination must use the received proof.
            for _ in 0..2 {
                assert_eq!(
                    ExitStatusWire::from(retained_agent.wait().await.unwrap()),
                    status
                );
                running
                    .terminate()
                    .await
                    .expect("repeat acknowledged teardown");
            }
            assert_eq!(
                requests.load(Ordering::Acquire),
                1,
                "terminal receipt must eliminate later RPCs"
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn shutdown_receipt_rejects_missing_or_conflicting_main_status() {
        for main_exit_status in [None, Some(ExitStatusWire::Exited(8))] {
            let (client, server) =
                configuration_client(Some(Response::BoundaryTerminated { main_exit_status })).await;
            let running = shutdown_test_running(client);
            running
                .process
                .record_exit_status(BoundaryExitStatus::Exited(7))
                .unwrap();
            let error = running
                .terminate()
                .await
                .expect_err("running main requires a matching observed status");
            assert!(error.to_string().contains(if main_exit_status.is_none() {
                "omitted"
            } else {
                "conflicting"
            }));
            assert!(
                !*running.terminated.lock().await,
                "invalid receipt is not terminal proof"
            );
            assert_eq!(
                ExitStatusWire::from(running.agent().wait().await.unwrap()),
                ExitStatusWire::Exited(7)
            );
            server.abort();
        }
    }

    async fn assert_mediation_waits_and_reopens(dns: bool) {
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let permits = Arc::new(tokio::sync::Semaphore::new(0));
        let (client, server) = configuration_client_with_service(TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: requests.clone(),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            response_override: Some(Response::Error {
                kind: crate::boundary_protocol::BoundaryErrorKind::Unavailable,
                message: "network stream ended".to_string(),
            }),
            response_permits: Some(permits.clone()),
        })
        .await;
        let source = RemoteNetworkMediation {
            client: client.clone(),
        };
        let mut accepted = tokio::spawn(async move {
            if dns {
                source.accept_dns().await.map(|_| ())
            } else {
                source.accept_tcp().await.map(|_| ())
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut accepted)
                .await
                .is_err()
        );
        assert_eq!(
            requests.load(Ordering::Acquire),
            0,
            "held startup makes no network request"
        );
        client.publish_activation(0, &test_activation()).unwrap();
        wait_for_network_requests(&requests, 1).await;
        let epoch = client.invalidate_activation();
        permits.add_permits(1);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut accepted)
                .await
                .is_err()
        );
        assert_eq!(
            requests.load(Ordering::Acquire),
            1,
            "a retired accept waits for release"
        );
        client
            .publish_activation(epoch, &test_activation())
            .unwrap();
        wait_for_network_requests(&requests, 2).await;
        permits.add_permits(1);
        assert!(
            matches!(
                tokio::time::timeout(Duration::from_secs(1), accepted)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(BackendError::Unavailable(_))
            ),
            "a failure in the current epoch remains terminal"
        );
        assert_eq!(requests.load(Ordering::Acquire), 2);
        server.abort();
    }

    async fn wait_for_network_requests(requests: &std::sync::atomic::AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while requests.load(Ordering::Acquire) < expected {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("released mediation issues its request");
    }

    #[tokio::test]
    async fn configuration_activation_tcp_accept_waits_and_reopens_after_hold() {
        assert_mediation_waits_and_reopens(false).await;
    }

    #[tokio::test]
    async fn configuration_activation_dns_accept_waits_and_reopens_after_hold() {
        assert_mediation_waits_and_reopens(true).await;
    }

    #[tokio::test]
    async fn configuration_activation_mediation_discards_stale_success_and_preserves_identity_failure()
     {
        let (client, server) = configuration_client(None).await;
        client.publish_activation(0, &test_activation()).unwrap();
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let accepted = client
            .accept_mediation(|_| async {
                let attempt = attempts.fetch_add(1, Ordering::AcqRel);
                if attempt == 0 {
                    let epoch = client.invalidate_activation();
                    client
                        .publish_activation(epoch, &test_activation())
                        .unwrap();
                }
                Ok(attempt)
            })
            .await
            .unwrap();
        assert_eq!(
            accepted, 1,
            "an old stream success cannot cross activation epochs"
        );
        let result: Result<(), BackendError> = client
            .accept_mediation(|_| async {
                client.invalidate_activation();
                Err(BackendError::Terminated("replacement boundary".to_string()))
            })
            .await;
        assert!(matches!(result, Err(BackendError::Terminated(_))));
        server.abort();
    }

    struct MediationLeaseTestState {
        opens: std::sync::atomic::AtomicUsize,
        first_open_entered: tokio::sync::Semaphore,
        first_open_permit: tokio::sync::Semaphore,
        closed: tokio::sync::Semaphore,
        lease: tokio::sync::Mutex<()>,
        responses: tokio::sync::Mutex<Vec<(usize, DnsQueryResultWire)>>,
        response_received: tokio::sync::Notify,
    }

    impl MediationLeaseTestState {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                opens: std::sync::atomic::AtomicUsize::new(0),
                first_open_entered: tokio::sync::Semaphore::new(0),
                first_open_permit: tokio::sync::Semaphore::new(0),
                closed: tokio::sync::Semaphore::new(0),
                lease: tokio::sync::Mutex::new(()),
                responses: tokio::sync::Mutex::new(Vec::new()),
                response_received: tokio::sync::Notify::new(),
            })
        }

        async fn require_dns_response(&self, attempt: usize) {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let notified = self.response_received.notified();
                    if self.responses.lock().await.iter().any(|(index, response)| {
                        *index == attempt
                            && *response == DnsQueryResultWire::Response(vec![4, 5, 6])
                    }) {
                        return;
                    }
                    notified.await;
                }
            })
            .await
            .expect("current lane receives the completed DNS response");
        }
    }

    struct MediationLeaseTestBoundary(Arc<MediationLeaseTestState>);

    #[tonic::async_trait]
    impl IsolationBoundary for MediationLeaseTestBoundary {
        type ExchangeStream = TestGrpcStream;
        type MediateStream = TestGrpcStream;

        async fn exchange(
            &self,
            _request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
        ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
            Err(tonic::Status::unimplemented(
                "test only opens mediation streams",
            ))
        }

        async fn mediate(
            &self,
            request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
        ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
            let state = self.0.clone();
            let mut inbound = request.into_inner();
            let (outbound, outbound_rx) = tokio::sync::mpsc::channel(1);
            tokio::spawn(async move {
                let mut frame = Vec::new();
                while !complete_control_frame(&frame) {
                    let Some(chunk) = inbound.message().await.unwrap() else {
                        return;
                    };
                    frame.extend_from_slice(&chunk.data);
                }
                let envelope: RequestEnvelope = decode_frame(&frame).unwrap();
                assert!(matches!(envelope.request, Request::OpenMediation));
                let attempt = state.opens.fetch_add(1, Ordering::AcqRel);
                if attempt == 0 {
                    state.first_open_entered.add_permits(1);
                    state.first_open_permit.acquire().await.unwrap().forget();
                }
                // Hold the same exclusive lease as the boundary until this actual
                // gRPC request stream closes, including while it is otherwise idle.
                let lease = tokio::time::timeout(Duration::from_secs(1), state.lease.lock()).await;
                let response = if lease.is_ok() {
                    Response::MediationReady
                } else {
                    Response::Error {
                        kind: crate::boundary_protocol::BoundaryErrorKind::Denied,
                        message: "a mediation session is already active".to_string(),
                    }
                };
                let mut frame = encode_frame(&ResponseEnvelope {
                    request_id: envelope.request_id,
                    response,
                })
                .unwrap();
                let Ok(lease) = lease else {
                    let _ = outbound.send(Ok(BoundaryChunk { data: frame })).await;
                    return;
                };
                let query = DnsQueryWire {
                    request: vec![u8::try_from(attempt).unwrap(), 2, 3],
                    transport: openshell_isolation_interface::contract::DnsTransport::Udp,
                    identity: crate::boundary_protocol::BinaryIdentityWire::Resolved {
                        binary_path: PathBuf::from("/usr/bin/dig"),
                        binary_digest: Some("a".repeat(64).parse().unwrap()),
                        ancestors: Vec::new(),
                        cmdline_paths: Vec::new(),
                    },
                    timing: crate::boundary_protocol::MediationTimingWire::default(),
                };
                mediation::write_frame(
                    &mut frame,
                    MediationFrameKind::DnsQuery,
                    42,
                    &mediation::encode_json(&query).unwrap(),
                )
                .await
                .unwrap();
                let _ = outbound.send(Ok(BoundaryChunk { data: frame })).await;
                let mut received = Vec::new();
                while let Ok(Some(chunk)) = inbound.message().await {
                    received.extend_from_slice(&chunk.data);
                    if received.len() < 13 {
                        continue;
                    }
                    let length = u32::from_be_bytes(received[9..13].try_into().unwrap()) as usize;
                    if received.len() < 13 + length {
                        continue;
                    }
                    let reply = mediation::read_frame(&mut received.as_slice())
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(reply.kind, MediationFrameKind::DnsResponse);
                    let response = mediation::decode_json(&reply.payload).unwrap();
                    state.responses.lock().await.push((attempt, response));
                    state.response_received.notify_one();
                    received.drain(..13 + length);
                }
                drop(lease);
                state.closed.add_permits(1);
            });
            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(
                outbound_rx,
            ))))
        }
    }

    #[tokio::test]
    async fn configuration_activation_late_mediation_open_retires_lease_before_replacement() {
        let state = MediationLeaseTestState::new();
        let (client, server) =
            configuration_client_with_service(MediationLeaseTestBoundary(state.clone())).await;
        client.publish_activation(0, &test_activation()).unwrap();
        let source = RemoteNetworkMediation {
            client: client.clone(),
        };
        let accepted = tokio::spawn(async move { source.accept_dns().await });
        state.first_open_entered.acquire().await.unwrap().forget();
        let epoch = client.invalidate_activation();
        client
            .publish_activation(epoch, &test_activation())
            .unwrap();
        // The delayed request reaches the boundary only after the new release.
        // Its stream cannot observe the old boundary hold and must close locally.
        state.first_open_permit.add_permits(1);
        let query = tokio::time::timeout(Duration::from_secs(3), accepted)
            .await
            .expect("replacement mediation must complete without another hold or reconnect")
            .unwrap()
            .expect("current activation opens a replacement lane");
        assert_eq!(query.message, [1, 2, 3]);
        query.response.send(Ok(vec![4, 5, 6])).unwrap();
        state.require_dns_response(1).await;
        assert_eq!(state.opens.load(Ordering::Acquire), 2);
        assert_eq!(state.closed.available_permits(), 1);
        assert_eq!(
            client
                .grpc_channel
                .lock()
                .await
                .as_ref()
                .unwrap()
                .generation,
            1
        );
        assert_eq!(client.active_mediation_epoch(), Some(epoch));
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_cancelled_mediation_open_releases_unpublished_lease() {
        let state = MediationLeaseTestState::new();
        let (client, server) =
            configuration_client_with_service(MediationLeaseTestBoundary(state.clone())).await;
        client.publish_activation(0, &test_activation()).unwrap();
        state.first_open_permit.add_permits(1);
        let (acknowledged, acknowledgement) = tokio::sync::oneshot::channel();
        let opening_client = client.clone();
        let opening = tokio::spawn(async move {
            let session = opening_client.open_mediation_session(0).await.unwrap();
            // Ensure the stream task has delivered its first frame and is idle;
            // receiver closure on a not-yet-delivered frame cannot satisfy cleanup.
            let query = session.accept_dns().await.unwrap();
            acknowledged.send(()).unwrap();
            // This is the ownership interval while mediation_session waits to
            // publish its acknowledged session into the async cache mutex.
            std::future::pending::<()>().await;
            drop(query);
            drop(session);
        });
        acknowledgement.await.unwrap();
        opening.abort();
        assert!(opening.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), state.closed.acquire())
            .await
            .expect("cancelling an acknowledged open closes its actual gRPC stream")
            .unwrap()
            .forget();
        assert!(client.mediation.lock().await.is_none());
        let source = RemoteNetworkMediation {
            client: client.clone(),
        };
        let query = tokio::time::timeout(Duration::from_secs(2), source.accept_dns())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(query.message, [1, 2, 3]);
        query.response.send(Ok(vec![4, 5, 6])).unwrap();
        state.require_dns_response(1).await;
        assert_eq!(state.opens.load(Ordering::Acquire), 2);
        assert_eq!(client.active_mediation_epoch(), Some(0));
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_hold_closes_cached_mediation_with_retained_session() {
        let state = MediationLeaseTestState::new();
        let (client, server) =
            configuration_client_with_service(MediationLeaseTestBoundary(state.clone())).await;
        client.publish_activation(0, &test_activation()).unwrap();
        state.first_open_permit.add_permits(1);
        let retired = client.mediation_session(0).await.unwrap();
        let old_query = retired.accept_dns().await.unwrap();
        let epoch = client.invalidate_activation();
        client
            .publish_activation(epoch, &test_activation())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), state.closed.acquire())
            .await
            .expect("hold closes a cached stream even while old accepts retain its session")
            .unwrap()
            .forget();
        assert!(!retired.is_healthy());
        assert!(client.healthy_mediation_session(0).await.is_err());
        let source = RemoteNetworkMediation {
            client: client.clone(),
        };
        let query = tokio::time::timeout(Duration::from_secs(2), source.accept_dns())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(query.message, [1, 2, 3]);
        query.response.send(Ok(vec![4, 5, 6])).unwrap();
        state.require_dns_response(1).await;
        assert_eq!(state.opens.load(Ordering::Acquire), 2);
        assert_eq!(client.active_mediation_epoch(), Some(epoch));
        drop(old_query);
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_requires_exact_prepare_commit_release_receipts() {
        let (client, server) = configuration_client(None).await;
        let readiness = client.readiness();
        let prepared = client
            .prepare(None, test_activation().configuration, HashMap::new())
            .await
            .unwrap();
        assert!(!*readiness.borrow());
        let installed = client.commit(&prepared).await.unwrap();
        assert!(!*readiness.borrow());
        assert!(client.active_configuration(1).is_err());
        let activated = client.release(&installed).await.unwrap();
        assert!(*readiness.borrow());
        assert_eq!(client.active_configuration(1).unwrap(), activated);
        assert!(client.active_configuration(2).is_err());
        client.quiesce().await.unwrap();
        assert!(!*readiness.borrow());
        assert!(client.active_configuration(1).is_err());
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_rejects_wrong_peer_install_and_release_tuples() {
        let mut wrong_installed = test_installed();
        wrong_installed.configuration.provider_env_revision += 1;
        let (client, server) = configuration_client(Some(Response::ConfigurationCommitted {
            installed: Box::new(wrong_installed),
        }))
        .await;
        assert!(client.commit(&test_prepared()).await.is_err());
        assert!(!*client.readiness().borrow());
        server.abort();

        let mut wrong_activated = test_activation();
        wrong_activated.identity.registration_revision += 1;
        let (client, server) = configuration_client(Some(Response::ConfigurationReleased {
            activated: Box::new(wrong_activated),
        }))
        .await;
        assert!(client.release(&test_installed()).await.is_err());
        assert!(!*client.readiness().borrow());
        server.abort();

        let mut wrong_prepared = test_prepared();
        wrong_prepared.expected = Some(wrong_prepared.configuration.clone());
        let (client, server) = configuration_client(Some(Response::ConfigurationPrepared {
            prepared: Box::new(wrong_prepared),
        }))
        .await;
        assert!(
            client
                .prepare(None, test_activation().configuration, HashMap::new())
                .await
                .is_err()
        );
        assert!(!*client.readiness().borrow());
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_rejects_wrong_start_and_exec_receipts() {
        let mut wrong_activated = test_activation();
        wrong_activated.configuration.provider_env_revision += 1;
        let (client, server) = configuration_client(Some(Response::Started {
            process_id: "test-generation:main:0".to_string(),
            provider_env_revision: 2,
            activation: wrong_activated.clone(),
        }))
        .await;
        client.publish_activation(0, &test_activation()).unwrap();
        let context = sandbox();
        let ready = RemoteReady {
            client,
            agent: context.agent,
            policy: context.policy,
            sandbox_id: context.sandbox_id,
            ca_file_paths: Arc::new(std::sync::Mutex::new(None)),
            provider_credentials: openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(1, HashMap::new()),
        };
        assert!(Box::new(ready).start_agent().await.is_err());
        server.abort();

        let (client, server) = configuration_client(Some(Response::ExecStarted {
            process_id: "test-generation:exec:1".to_string(),
            pty: false,
            activation: wrong_activated,
        }))
        .await;
        client.publish_activation(0, &test_activation()).unwrap();
        assert!(
            open_exec_session(
                client,
                ExecSpec {
                    program: "/bin/true".to_string(),
                    args: Vec::new(),
                    env: Vec::new(),
                    workdir: None,
                    pty: false,
                },
                test_activation()
            )
            .await
            .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_snapshot_cannot_replace_a_released_tuple() {
        let mut unexpected = test_activation().configuration;
        unexpected.provider_env_revision += 1;
        let (client, server) = configuration_client(Some(Response::ConfigurationSnapshot {
            snapshot: BoundaryConfigurationSnapshot {
                identity: test_activation().identity,
                installed: Some(unexpected),
                active: true,
            },
        }))
        .await;
        client.publish_activation(0, &test_activation()).unwrap();
        assert!(client.snapshot().await.is_err());
        assert!(!*client.readiness().borrow());
        assert!(client.active_configuration(1).is_err());
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_invalid_candidate_preserves_existing_release() {
        let (client, server) = configuration_client(None).await;
        client.publish_activation(0, &test_activation()).unwrap();
        let mut invalid = test_activation().configuration;
        invalid.config_revision = 0;
        assert!(client.prepare(None, invalid, HashMap::new()).await.is_err());
        assert!(*client.readiness().borrow());
        assert!(
            client
                .prepare(
                    None,
                    test_activation().configuration,
                    HashMap::from([("BAD=KEY".to_string(), "redacted".to_string())])
                )
                .await
                .is_err()
        );
        assert!(*client.readiness().borrow());
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_reconnect_epoch_rejects_late_release() {
        let (client, server) = configuration_client(None).await;
        client.publish_activation(0, &test_activation()).unwrap();
        let observed_epoch = client.activation.lock().unwrap().epoch;
        client.invalidate_activation();
        assert!(
            client
                .publish_activation(observed_epoch, &test_activation())
                .is_err()
        );
        assert!(!*client.readiness().borrow());
        assert!(client.active_configuration(1).is_err());
        let mut replacement = test_activation().identity;
        replacement.boundary_instance_id = "44444444-4444-4444-8444-444444444444".to_string();
        assert!(matches!(
            client.validate_identity(&replacement, true),
            Err(BackendError::Terminated(_))
        ));
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_replacement_is_terminal_before_stale_grant_replay() {
        let mut identity = test_activation().identity;
        identity.boundary_instance_id = "44444444-4444-4444-8444-444444444444".to_string();
        identity.registration_revision = 0;
        let (client, server) = configuration_client(Some(Response::WorkloadDescribed {
            bootstrap: Box::new(BoundaryBootstrap {
                identity,
                workload_identity: sandbox().identity,
                image_policy:
                    openshell_isolation_interface::contract::ImagePolicyDiscovery::Missing,
                filesystem_baseline:
                    openshell_isolation_interface::contract::BoundaryFilesystemBaseline::default(),
            }),
        }))
        .await;
        let channel = client
            .grpc_channel
            .lock()
            .await
            .as_ref()
            .unwrap()
            .channel
            .clone();
        let attach = BoundaryClient::prepare_request(Request::Attach {
            supervisor_instance_id: test_supervisor_instance_id(),
            registration_grant: "old-boundary-grant".to_string(),
            registration_revision: 1,
            policy: Box::new(SandboxPolicyWire::from(sandbox().policy)),
            resource_claims: std::collections::BTreeMap::new(),
        })
        .unwrap();
        assert!(matches!(
            client.replay_attachment(channel, &attach, None).await,
            Err(BackendError::Terminated(_))
        ));
        assert!(!*client.readiness().borrow());
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_retry_token_survives_only_transport_recovery() {
        let (client, server) = configuration_client(None).await;
        let (original_epoch, operation) = client.hold_activation(true);
        client.hold_activation(false);
        let retry_epoch = client
            .configuration_attempt_epoch(operation)
            .expect("same operation may retry");
        assert_ne!(original_epoch, retry_epoch);
        assert!(
            client
                .publish_activation(original_epoch, &test_activation())
                .is_err()
        );
        client.invalidate_activation();
        assert!(client.configuration_attempt_epoch(operation).is_err());
        assert!(
            client
                .publish_activation(retry_epoch, &test_activation())
                .is_err()
        );
        assert!(!*client.readiness().borrow());
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_startup_policy_refresh_updates_cached_attachment() {
        let (client, server) = configuration_client(None).await;
        let context = sandbox();
        client
            .call_idempotent(Request::Attach {
                supervisor_instance_id: test_supervisor_instance_id(),
                registration_grant: "same-registration".to_string(),
                registration_revision: 1,
                policy: Box::new(SandboxPolicyWire::from(context.policy.clone())),
                resource_claims: std::collections::BTreeMap::new(),
            })
            .await
            .unwrap();
        let mut ready = RemoteReady {
            client: client.clone(), agent: context.agent, policy: context.policy.clone(), sandbox_id: context.sandbox_id,
            ca_file_paths: Arc::new(std::sync::Mutex::new(None)),
            provider_credentials: openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(1, HashMap::new()),
        };
        let mut repaired = context.policy;
        repaired
            .filesystem
            .read_only
            .push(PathBuf::from("/tmp/repaired"));
        ready.update_startup_policy(repaired.clone()).await.unwrap();
        assert_eq!(
            SandboxPolicyWire::from(ready.policy.clone()),
            SandboxPolicyWire::from(repaired.clone())
        );
        let epoch = client.activation.lock().unwrap().epoch;
        ready.update_startup_policy(repaired.clone()).await.unwrap();
        assert_eq!(
            client.activation.lock().unwrap().epoch,
            epoch,
            "exact policy replay preserves receipts"
        );
        assert!(!*client.readiness().borrow());
        let cached = client.attach_request.lock().unwrap();
        let envelope = cached.as_ref().unwrap();
        envelope.validate_payload_digest().unwrap();
        let Request::Attach {
            policy,
            registration_grant,
            ..
        } = &envelope.request
        else {
            panic!("attachment");
        };
        assert_eq!(**policy, SandboxPolicyWire::from(repaired));
        assert_eq!(registration_grant, "same-registration");
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_startup_policy_refresh_rejects_active_boundary() {
        let (client, server) = configuration_client(Some(Response::ConfigurationSnapshot {
            snapshot: BoundaryConfigurationSnapshot {
                identity: test_activation().identity,
                installed: Some(test_activation().configuration),
                active: true,
            },
        }))
        .await;
        let context = sandbox();
        let original = SandboxPolicyWire::from(context.policy.clone());
        let mut ready = RemoteReady {
            client: client.clone(), agent: context.agent, policy: context.policy.clone(), sandbox_id: context.sandbox_id,
            ca_file_paths: Arc::new(std::sync::Mutex::new(None)),
            provider_credentials: openshell_core::provider_credentials::ProviderCredentialState::from_child_env_snapshot(1, HashMap::new()),
        };
        let mut repaired = context.policy;
        repaired
            .filesystem
            .read_only
            .push(PathBuf::from("/tmp/repaired"));
        assert!(matches!(
            ready.update_startup_policy(repaired).await,
            Err(BackendError::Denied(_))
        ));
        assert_eq!(SandboxPolicyWire::from(ready.policy), original);
        assert!(!*client.readiness().borrow());
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_registration_refresh_keeps_current_fence() {
        let (client, server) = configuration_client(None).await;
        *client.attach_request.lock().unwrap() = Some(
            BoundaryClient::prepare_request(Request::Attach {
                supervisor_instance_id: test_supervisor_instance_id(),
                registration_grant: "old-grant".to_string(),
                registration_revision: 1,
                policy: Box::new(SandboxPolicyWire::from(sandbox().policy)),
                resource_claims: std::collections::BTreeMap::new(),
            })
            .unwrap(),
        );
        client.publish_activation(0, &test_activation()).unwrap();
        assert!(
            client
                .refresh_registration(SecretJwt::parse("replacement").unwrap(), 2)
                .await
                .is_err()
        );
        client
            .refresh_registration(SecretJwt::parse("replacement").unwrap(), 1)
            .await
            .unwrap();
        assert!(*client.readiness().borrow());
        let attach = client.attach_request.lock().unwrap();
        attach.as_ref().unwrap().validate_payload_digest().unwrap();
        let Request::Attach {
            registration_grant,
            registration_revision,
            ..
        } = &attach.as_ref().unwrap().request
        else {
            panic!("attachment");
        };
        assert_eq!(registration_grant, "replacement");
        assert_eq!(*registration_revision, 1);
        server.abort();
    }

    #[test]
    fn configuration_activation_receipts_bind_every_revision_coordinate() {
        let original = test_activation();
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.configuration.config_revision += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.configuration.policy_version += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.configuration.policy_hash.push('x');
        variants.push(changed);
        let mut changed = original.clone();
        changed.configuration.policy_source += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.configuration.provider_env_revision += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.identity.runtime_generation.push('x');
        variants.push(changed);
        let mut changed = original.clone();
        changed.identity.boundary_session_id.push('x');
        variants.push(changed);
        let mut changed = original.clone();
        changed.identity.supervisor_instance_id.push('x');
        variants.push(changed);
        let mut changed = original.clone();
        changed.identity.boundary_instance_id.push('x');
        variants.push(changed);
        let mut changed = original.clone();
        changed.identity.registration_revision += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.transition_id.push('x');
        variants.push(changed);
        for changed in variants {
            assert!(validate_released_receipt(&changed, &test_installed()).is_err());
            assert!(validate_launch_acknowledgement(&original, &changed, 1).is_err());
        }
        assert!(validate_launch_acknowledgement(&original, &original, 2).is_err());
    }

    fn test_driver_fence() -> openshell_isolation_interface::contract::DriverFenceEvidence {
        openshell_isolation_interface::contract::DriverFenceEvidence::Vm {
            generation: "test-generation".to_string(),
            network_device_count: 0,
        }
    }

    #[tokio::test]
    async fn boundary_tcp_connections_enable_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connected = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
        let (_server, _) = listener.accept().await.unwrap();
        let client = connected.await.unwrap().unwrap();

        enable_boundary_tcp_keepalive(&client);

        assert!(socket2::SockRef::from(&client).keepalive().unwrap());
    }

    #[derive(Clone)]
    struct TestGrpcBoundary {
        wait_for_half_close: bool,
        expected_token: String,
        requests: Arc<std::sync::atomic::AtomicUsize>,
        mediation_failures: Arc<std::sync::atomic::AtomicUsize>,
        mediation_ready: bool,
        response_override: Option<Response>,
        response_permits: Option<Arc<tokio::sync::Semaphore>>,
    }

    type TestGrpcStream = Pin<
        Box<dyn tokio_stream::Stream<Item = Result<BoundaryChunk, tonic::Status>> + Send + 'static>,
    >;

    #[tonic::async_trait]
    impl IsolationBoundary for TestGrpcBoundary {
        type ExchangeStream = TestGrpcStream;
        type MediateStream = TestGrpcStream;

        async fn exchange(
            &self,
            request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
        ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
            let authorization = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok());
            if authorization != Some(format!("Bearer {}", self.expected_token).as_str()) {
                return Err(tonic::Status::unauthenticated(
                    "Sandbox Protocol bearer token did not match",
                ));
            }
            let mut inbound = request.into_inner();
            let wait_for_half_close = self.wait_for_half_close;
            let requests = self.requests.clone();
            let mediation_ready = self.mediation_ready;
            let response_override = self.response_override.clone();
            let response_permits = self.response_permits.clone();
            let (outbound, outbound_rx) = tokio::sync::mpsc::channel(1);
            tokio::spawn(async move {
                let mut frame = Vec::new();
                loop {
                    match inbound.message().await {
                        Ok(Some(chunk)) => {
                            frame.extend_from_slice(&chunk.data);
                            if !wait_for_half_close && complete_control_frame(&frame) {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            let _ = outbound.send(Err(error)).await;
                            return;
                        }
                    }
                }
                requests.fetch_add(1, Ordering::AcqRel);
                let response = if complete_control_frame(&frame) {
                    let envelope: RequestEnvelope = match decode_frame(&frame) {
                        Ok(envelope) => envelope,
                        Err(error) => {
                            let _ = outbound
                                .send(Err(tonic::Status::invalid_argument(error.to_string())))
                                .await;
                            return;
                        }
                    };
                    match encode_frame(&ResponseEnvelope {
                        request_id: envelope.request_id,
                        response: response_override.unwrap_or_else(|| match envelope.request {
                            Request::DescribeWorkload {
                                supervisor_instance_id,
                                ..
                            } => {
                                let mut identity = test_activation().identity;
                                identity.supervisor_instance_id =
                                    supervisor_instance_id.to_string();
                                identity.registration_revision = 0;
                                Response::WorkloadDescribed { bootstrap: Box::new(BoundaryBootstrap {
                                    identity,
                                    workload_identity: sandbox().identity,
                                    image_policy: openshell_isolation_interface::contract::ImagePolicyDiscovery::Missing,
                                    filesystem_baseline: openshell_isolation_interface::contract::BoundaryFilesystemBaseline::default(),
                                }) }
                            }
                            Request::Attach {
                                supervisor_instance_id,
                                registration_revision,
                                ..
                            } => {
                                let mut identity = test_activation().identity;
                                identity.supervisor_instance_id =
                                    supervisor_instance_id.to_string();
                                identity.registration_revision = registration_revision;
                                Response::Attached {
                                    snapshot: crate::boundary_protocol::SessionSnapshotWire {
                                        generation: "test-generation".to_string(),
                                        configuration: BoundaryConfigurationSnapshot {
                                            identity,
                                            installed: None,
                                            active: false,
                                        },
                                        processes: Vec::new(),
                                    },
                                }
                            }
                            Request::ConfigurationSnapshot { identity } => {
                                Response::ConfigurationSnapshot {
                                    snapshot: BoundaryConfigurationSnapshot {
                                        identity,
                                        installed: None,
                                        active: false,
                                    },
                                }
                            }
                            Request::PrepareConfiguration {
                                identity,
                                expected,
                                configuration,
                                ..
                            } => Response::ConfigurationPrepared {
                                prepared: Box::new(PreparedBoundaryConfiguration {
                                    identity,
                                    expected,
                                    configuration,
                                    transition_id: "test-transition".to_string(),
                                }),
                            },
                            Request::CommitConfiguration { prepared } => {
                                Response::ConfigurationCommitted {
                                    installed: Box::new(InstalledBoundaryConfiguration {
                                        identity: prepared.identity,
                                        configuration: prepared.configuration,
                                        transition_id: prepared.transition_id,
                                    }),
                                }
                            }
                            Request::ReleaseConfiguration { installed } => {
                                Response::ConfigurationReleased {
                                    activated: Box::new(ActivatedBoundaryConfiguration {
                                        identity: installed.identity,
                                        configuration: installed.configuration,
                                        transition_id: installed.transition_id,
                                    }),
                                }
                            }
                            Request::AbortConfiguration { .. } => Response::ConfigurationAborted,
                            Request::QuiesceConfiguration { .. } => Response::ConfigurationQuiesced,
                            Request::Confirm => Response::Confirmed {
                                evidence: Box::new(test_confirmation_evidence()),
                            },
                            Request::OpenMediation if mediation_ready => Response::MediationReady,
                            Request::OpenMediation => Response::Error {
                                kind: crate::boundary_protocol::BoundaryErrorKind::Denied,
                                message: "a mediation session is already active".to_string(),
                            },
                            Request::Wait { .. } => Response::Exited {
                                status: ExitStatusWire::Exited(23),
                            },
                            Request::Exec { activation, .. } => Response::ExecStarted {
                                process_id: "test-generation:exec:1".to_string(),
                                pty: false,
                                activation,
                            },
                            Request::AttachProcess { .. } => {
                                Response::ProcessAttached { terminal: false }
                            }
                            Request::Signal { .. } | Request::ExecSignal { .. } => {
                                Response::Signaled
                            }
                            Request::Terminate { .. } => Response::Terminated,
                            Request::TerminateBoundary => Response::BoundaryTerminated {
                                main_exit_status: Some(ExitStatusWire::Exited(23)),
                            },
                            Request::Resize { .. } => Response::Resized,
                            Request::LoopbackConnect { .. } => Response::PortConnected,
                            Request::StartAgent { activation, .. } => Response::Started {
                                process_id: "test-generation:main:0".to_string(),
                                provider_env_revision: activation
                                    .configuration
                                    .provider_env_revision,
                                activation,
                            },
                            Request::AcceptNetwork => Response::Error {
                                kind: crate::boundary_protocol::BoundaryErrorKind::Unavailable,
                                message: "no pending network request".to_string(),
                            },
                        }),
                    }) {
                        Ok(response) => response,
                        Err(error) => {
                            let _ = outbound
                                .send(Err(tonic::Status::internal(error.to_string())))
                                .await;
                            return;
                        }
                    }
                } else {
                    b"complete response".to_vec()
                };
                if let Some(permits) = response_permits {
                    permits
                        .acquire()
                        .await
                        .expect("test response permit")
                        .forget();
                }
                let _ = outbound.send(Ok(BoundaryChunk { data: response })).await;
            });
            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(
                outbound_rx,
            ))))
        }

        async fn mediate(
            &self,
            request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
        ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
            if self
                .mediation_failures
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(tonic::Status::unavailable(
                    "injected mediation transport failure",
                ));
            }
            self.exchange(request).await
        }
    }

    fn complete_control_frame(frame: &[u8]) -> bool {
        frame.len() >= 4
            && frame.len()
                >= 4 + usize::try_from(u32::from_be_bytes(
                    frame[..4].try_into().expect("frame header"),
                ))
                .expect("frame length")
    }

    #[tokio::test]
    async fn mediation_denial_is_not_retried_or_cached_as_a_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: requests.clone(),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            response_override: None,
            response_permits: None,
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tonic::transport::Server::builder()
                .add_service(IsolationBoundaryServer::new(service))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(stream)]))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, test_certificate().client_tls),
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        );
        *client.grpc_channel.lock().await = Some(CachedGrpcChannel {
            credential_epoch: openshell_core::jwt::CredentialEpoch::new(1).expect("test epoch"),
            generation: 1,
            channel,
        });
        // A caller may try again later, but each call makes exactly one
        // bounded attach attempt and preserves the server's typed denial.
        for expected_requests in 1..=2 {
            let epoch = client.activation.lock().unwrap().epoch;
            assert!(matches!(
                client.mediation_session(epoch).await,
                Err(BackendError::Denied(_))
            ));
            assert_eq!(requests.load(Ordering::Acquire), expected_requests);
            assert!(client.mediation.lock().await.is_none());
        }
        server.abort();
    }

    #[tokio::test]
    async fn configuration_activation_recovery_replays_attach_and_confirm_without_release() {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_requests = requests.clone();
        let server_accepted = accepted.clone();
        let server_config = certificate.server_config.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let stream = tokio_rustls::TlsAcceptor::from(server_config.clone())
                    .accept(stream)
                    .await
                    .unwrap();
                server_accepted.fetch_add(1, Ordering::AcqRel);
                let service = TestGrpcBoundary {
                    wait_for_half_close: false,
                    expected_token: "a".repeat(32),
                    requests: server_requests.clone(),
                    mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    mediation_ready: false,
                    response_override: None,
                    response_permits: None,
                };
                tokio::spawn(async move {
                    tonic::transport::Server::builder()
                        .add_service(IsolationBoundaryServer::new(service))
                        .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(
                            TestTlsIo(Box::new(stream)),
                        )]))
                        .await
                        .unwrap();
                });
            }
        });
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        );
        let attach = Request::Attach {
            supervisor_instance_id: client.supervisor_instance_id,
            registration_grant: "test-grant".to_string(),
            registration_revision: 1,
            policy: Box::new(SandboxPolicyWire::from(sandbox().policy)),
            resource_claims: std::collections::BTreeMap::new(),
        };
        assert!(matches!(
            client.call_idempotent(attach).await.unwrap(),
            Response::Attached { .. }
        ));
        assert!(matches!(
            client.call_idempotent(Request::Confirm).await.unwrap(),
            Response::Confirmed { .. }
        ));

        client.activation.lock().unwrap().identity = Some(test_activation().identity);
        client.publish_activation(0, &test_activation()).unwrap();
        let readiness = client.readiness();
        assert!(*readiness.borrow());
        client.recover_after_unavailable().await.unwrap();
        assert!(!*readiness.borrow());
        assert!(client.active_configuration(1).is_err());
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("replacement connection accepted")
            .unwrap();
        assert_eq!(accepted.load(Ordering::Acquire), 2);
        assert_eq!(requests.load(Ordering::Acquire), 5);
    }

    #[test]
    fn wait_recovery_window_begins_at_transport_failure() {
        let wait_started = tokio::time::Instant::now();
        let failure_time = wait_started + CONNECT_RETRY_TIMEOUT + Duration::from_secs(5);
        let mut deadline = None;

        assert_eq!(
            begin_recovery_window(&mut deadline, failure_time),
            failure_time + CONNECT_RETRY_TIMEOUT
        );
    }

    #[tokio::test]
    async fn mediation_transport_failure_recovers_without_deadlocking_the_cache() {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mediation_failures = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let server_config = certificate.server_config.clone();
        let server_requests = requests.clone();
        let server_failures = mediation_failures.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let stream = tokio_rustls::TlsAcceptor::from(server_config.clone())
                    .accept(stream)
                    .await
                    .unwrap();
                let service = TestGrpcBoundary {
                    wait_for_half_close: false,
                    expected_token: "a".repeat(32),
                    requests: server_requests.clone(),
                    mediation_failures: server_failures.clone(),
                    mediation_ready: true,
                    response_override: None,
                    response_permits: None,
                };
                tokio::spawn(async move {
                    tonic::transport::Server::builder()
                        .add_service(IsolationBoundaryServer::new(service))
                        .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(
                            TestTlsIo(Box::new(stream)),
                        )]))
                        .await
                        .unwrap();
                });
            }
        });
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        );
        let attach = Request::Attach {
            supervisor_instance_id: client.supervisor_instance_id,
            registration_grant: "test-grant".to_string(),
            registration_revision: 1,
            policy: Box::new(SandboxPolicyWire::from(sandbox().policy)),
            resource_claims: std::collections::BTreeMap::new(),
        };
        assert!(matches!(
            client.call_idempotent(attach).await.unwrap(),
            Response::Attached { .. }
        ));
        assert!(matches!(
            client.call_idempotent(Request::Confirm).await.unwrap(),
            Response::Confirmed { .. }
        ));

        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), client.mediation_session(0))
                .await
                .expect("mediation recovery must not deadlock"),
            Err(BackendError::Unavailable(_))
        ));
        assert!(!*client.readiness().borrow());
        let epoch = client.activation.lock().unwrap().epoch;
        client
            .publish_activation(epoch, &test_activation())
            .unwrap();
        client
            .mediation_session(epoch)
            .await
            .expect("fresh release permits a replacement session");
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("replacement physical connection must be accepted")
            .unwrap();
        assert_eq!(mediation_failures.load(Ordering::Acquire), 0);
        assert_eq!(requests.load(Ordering::Acquire), 6);
    }

    #[tokio::test]
    async fn grpc_stream_preserves_response_after_request_half_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = TestGrpcBoundary {
            wait_for_half_close: true,
            expected_token: "a".repeat(32),
            requests,
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            response_override: None,
            response_permits: None,
        };
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tonic::transport::Server::builder()
                .add_service(IsolationBoundaryServer::new(service))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(stream)]))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut stream = open_grpc_client_stream(
            channel,
            GrpcStreamKind::Exchange,
            &test_bearer(&"a".repeat(32)),
        )
        .await
        .unwrap();
        stream.write_all(b"finite request").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = [0_u8; 17];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"complete response");
        drop(stream);
        server.abort();
    }

    #[tokio::test]
    async fn persistent_dns_exchange_returns_supervisor_response() {
        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let (_activation, activation_changes) = tokio::sync::watch::channel(true);
        let session = ClientMediationSession::start(Box::new(client_stream), 0, activation_changes);
        let server = tokio::spawn(async move {
            let query = DnsQueryWire {
                request: vec![1, 2, 3],
                transport: openshell_isolation_interface::contract::DnsTransport::Udp,
                identity: crate::boundary_protocol::BinaryIdentityWire::Resolved {
                    binary_path: PathBuf::from("/usr/bin/dig"),
                    binary_digest: Some("a".repeat(64).parse().unwrap()),
                    ancestors: Vec::new(),
                    cmdline_paths: Vec::new(),
                },
                timing: crate::boundary_protocol::MediationTimingWire::default(),
            };
            mediation::write_frame(
                &mut server_stream,
                MediationFrameKind::DnsQuery,
                42,
                &mediation::encode_json(&query).unwrap(),
            )
            .await
            .unwrap();
            let reply = mediation::read_frame(&mut server_stream)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.kind, MediationFrameKind::DnsResponse);
            assert_eq!(reply.stream_id, 42);
            assert_eq!(
                mediation::decode_json::<DnsQueryResultWire>(&reply.payload).unwrap(),
                DnsQueryResultWire::Response(vec![4, 5, 6])
            );
        });
        let query = session.accept_dns().await.unwrap();
        assert_eq!(query.message, [1, 2, 3]);
        assert_eq!(
            query.binary_identity.unwrap().binary_path,
            PathBuf::from("/usr/bin/dig")
        );
        query.response.send(Ok(vec![4, 5, 6])).unwrap();
        server.await.unwrap();
    }

    struct TestCertificate {
        client_tls: SandboxTlsClientConfig,
        server_config: Arc<rustls::ServerConfig>,
    }

    fn test_certificate() -> TestCertificate {
        test_certificate_with_protocol_versions(&[&rustls::version::TLS13])
    }

    fn test_certificate_with_protocol_versions(
        protocol_versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> TestCertificate {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let material =
            generate_sandbox_tls_material(test_session_id()).expect("generate test material");
        let certificates = rustls_pemfile::certs(&mut material.certificate_chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse server certificate");
        let private_key = rustls_pemfile::private_key(&mut material.private_key_pem.as_bytes())
            .expect("parse server private key")
            .expect("server private key");
        let mut server_config =
            rustls::ServerConfig::builder_with_protocol_versions(protocol_versions)
                .with_no_client_auth()
                .with_single_cert(certificates, private_key)
                .expect("build test TLS server config");
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        TestCertificate {
            client_tls: SandboxTlsClientConfig {
                server_name: material.server_name,
                trust_anchor_pem: material.trust_anchor_pem,
            },
            server_config: Arc::new(server_config),
        }
    }

    fn tls_runtime_descriptor(
        address: std::net::SocketAddr,
        tls: SandboxTlsClientConfig,
    ) -> SandboxRuntimeDescriptor {
        SandboxRuntimeDescriptor {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Tcp {
                authority: "sandbox.test".to_string(),
                addresses: vec![address],
            },
            tls,
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
        }
    }

    fn test_session_id() -> openshell_core::SandboxSessionId {
        "550e8400-e29b-41d4-a716-446655440000"
            .parse()
            .expect("test session ID")
    }

    fn test_bearer(token: &str) -> SessionBearerTokenSlot {
        SessionBearerTokenSlot::new(
            SecretJwt::parse(token).expect("test bearer"),
            i64::MAX,
            openshell_core::jwt::CredentialEpoch::new(1).expect("test epoch"),
        )
        .expect("test bearer slot")
    }

    async fn spawn_tls_boundary(
        certificate: Arc<rustls::ServerConfig>,
        expected_token: String,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(stream) = tokio_rustls::TlsAcceptor::from(certificate)
                .accept(stream)
                .await
            else {
                return;
            };
            serve_test_grpc(Box::new(stream), expected_token).await;
        });
        (address, task)
    }

    async fn serve_test_grpc(stream: BoundaryDuplexStream, expected_token: String) {
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token,
            requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            response_override: None,
            response_permits: None,
        };
        tonic::transport::Server::builder()
            .add_service(IsolationBoundaryServer::new(service))
            .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                stream,
            ))]))
            .await
            .unwrap();
    }

    fn sandbox() -> SandboxContext {
        SandboxContext {
            sandbox_id: "sandbox-1".to_string(),
            session_id: test_session_id(),
            registration_grant: SecretJwt::parse("test-grant").unwrap(),
            registration_revision: 1,
            policy: SandboxPolicy {
                version: 1,
                filesystem: FilesystemPolicy::default(),
                network: NetworkPolicy::default(),
                landlock: LandlockPolicy::default(),
                process: ProcessPolicy::default(),
            },
            agent: AgentSpec {
                program: "/bin/true".to_string(),
                args: Vec::new(),
                workdir: Some("/sandbox".to_string()),
                timeout_secs: 5,
                interactive: false,
            },
            identity: openshell_isolation_interface::contract::ResolvedWorkloadIdentity::new(
                10_001,
                10_001,
                Vec::new(),
                "test".to_string(),
                "sha256:test".to_string(),
            )
            .expect("identity"),
        }
    }

    fn test_confirmation_evidence()
    -> openshell_isolation_interface::contract::SandboxConfirmEvidence {
        openshell_isolation_interface::contract::SandboxConfirmEvidence {
            generation: "test-generation".to_string(),
            identity: sandbox().identity,
            capabilities: openshell_isolation_interface::contract::CapabilityEvidence {
                inheritable: 0,
                permitted: 0,
                effective: 0,
                bounding: 0,
                ambient: 0,
            },
            no_new_privileges: true,
            sandbox_dumpable: false,
            child_dumpable: true,
            core_limit_zero: true,
            native_architecture: std::env::consts::ARCH.to_string(),
            kernel_release: "test".to_string(),
            seccomp: openshell_isolation_interface::contract::SeccompEvidence {
                new_listener: true,
                notification_round_trip: true,
                id_validation: true,
                addfd_send: true,
                retained_socket_operation: true,
                proc_fd_identity: true,
                task_memory_read: true,
                task_memory_write: true,
                cancellation: true,
            },
            landlock_abi: 3,
            landlock_allow_deny: true,
            udp_dns_round_trip: true,
            tcp_dns_round_trip: true,
            tcp_allow_round_trip: true,
            tcp_deny_round_trip: true,
            authenticated_supervisor: true,
            session_id: test_session_id(),
            driver_fence: test_driver_fence(),
            runtime_exit_terminates_workload: true,
            resource_claims: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn runtime_descriptor_debug_redacts_trust_anchor() {
        let certificate = test_certificate();
        let runtime_descriptor = SandboxRuntimeDescriptor {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Unix {
                socket_path: PathBuf::from("/tmp/vsock.sock"),
            },
            tls: certificate.client_tls.clone(),
            host_gateway_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
        };
        let debug = format!("{runtime_descriptor:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&certificate.client_tls.trust_anchor_pem));
    }

    #[test]
    fn runtime_descriptor_must_match_sandbox() {
        let runtime_descriptor = SandboxRuntimeDescriptor {
            boundary_id: "other".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Unix {
                socket_path: PathBuf::from("/tmp/vsock.sock"),
            },
            tls: test_certificate().client_tls,
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
        };
        assert!(matches!(
            validate_runtime_descriptor(&runtime_descriptor, &sandbox()),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[test]
    fn runtime_descriptor_rejects_an_unspecified_tcp_target() {
        let runtime_descriptor = SandboxRuntimeDescriptor {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Tcp {
                authority: "sandbox.test".to_string(),
                addresses: vec!["0.0.0.0:5500".parse().expect("valid address")],
            },
            tls: test_certificate().client_tls,
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
        };
        assert!(matches!(
            validate_runtime_descriptor(&runtime_descriptor, &sandbox()),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[test]
    fn runtime_descriptor_accepts_a_concrete_tcp_target() {
        let runtime_descriptor = SandboxRuntimeDescriptor {
            boundary_id: "sandbox-1".to_string(),
            generation: "test-generation".to_string(),
            session_id: test_session_id(),
            workload_identity: sandbox().identity,
            transport: SandboxTransport::Tcp {
                authority: "sandbox.test".to_string(),
                addresses: vec!["10.42.0.7:5500".parse().expect("valid address")],
            },
            tls: test_certificate().client_tls,
            host_gateway_ip: None,
            resource_claims: std::collections::BTreeMap::new(),
            driver_fence: test_driver_fence(),
        };
        validate_runtime_descriptor(&runtime_descriptor, &sandbox())
            .expect("TCP runtime descriptor should be valid");
    }

    #[test]
    fn runtime_descriptor_rejects_invalid_tls_configuration() {
        let runtime_descriptor = tls_runtime_descriptor(
            "127.0.0.1:5500".parse().expect("valid address"),
            SandboxTlsClientConfig {
                server_name: "not a dns name!".to_string(),
                trust_anchor_pem: "not a certificate".to_string(),
            },
        );
        assert!(matches!(
            validate_runtime_descriptor(&runtime_descriptor, &sandbox()),
            Err(BackendError::Descriptor(_))
        ));
    }

    #[tokio::test]
    async fn tls_tcp_round_trip_verifies_server_certificate() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        );

        assert_eq!(
            client
                .exchange(Request::Confirm)
                .await
                .expect("TLS request"),
            Response::Confirmed {
                evidence: Box::new(test_confirmation_evidence()),
            }
        );
        server.abort();
    }

    #[tokio::test]
    async fn tls_tcp_rejects_tls12_only_server() {
        let certificate = test_certificate_with_protocol_versions(&[&rustls::version::TLS12]);
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client_config = tls_client_config(&certificate.client_tls).expect("client TLS config");
        let server_name =
            rustls::pki_types::ServerName::try_from(certificate.client_tls.server_name.clone())
                .expect("server name");
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect to TLS test server");

        assert!(
            tokio_rustls::TlsConnector::from(Arc::new(client_config))
                .connect(server_name, stream)
                .await
                .is_err()
        );
        server.await.expect("TLS test server task");
    }

    #[tokio::test]
    async fn exec_wait_survives_output_loss_and_reattachment() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client = Arc::new(BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        ));
        client.activation.lock().unwrap().activated = Some(test_activation());
        let session = open_exec_session(
            client,
            ExecSpec {
                program: "/bin/true".to_string(),
                args: Vec::new(),
                env: Vec::new(),
                workdir: None,
                pty: false,
            },
            test_activation(),
        )
        .await
        .unwrap();
        // The test peer closes its I/O stream without an exit frame. Neither
        // that loss nor a dropped reader can invalidate the process handle.
        drop(session.stdin);
        drop(session.stdout);
        drop(session.stderr);
        let attachment = session.process.attach().await.unwrap();
        drop(attachment);
        for _ in 0..2 {
            assert_eq!(
                session.process.wait().await.unwrap(),
                BoundaryExitStatus::Exited(23)
            );
        }
        server.abort();
    }

    struct TestTlsIo(BoundaryDuplexStream);

    impl tokio::io::AsyncRead for TestTlsIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(context, buffer)
        }
    }

    impl tokio::io::AsyncWrite for TestTlsIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(context)
        }
    }

    impl tonic::transport::server::Connected for TestTlsIo {
        type ConnectInfo = ();

        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    #[tokio::test]
    async fn grpc_session_reuses_one_tls_connection_for_concurrent_requests() {
        const REQUESTS: usize = 8;
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gRPC test boundary");
        let address = listener.local_addr().expect("gRPC listener address");
        let server_config = certificate.server_config;
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_by_server = accepted.clone();
        let handled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = TestGrpcBoundary {
            wait_for_half_close: false,
            expected_token: "a".repeat(32),
            requests: handled.clone(),
            mediation_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mediation_ready: false,
            response_override: None,
            response_permits: None,
        };
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept TLS session");
                accepted_by_server.fetch_add(1, Ordering::AcqRel);
                let stream = tokio_rustls::TlsAcceptor::from(server_config.clone())
                    .accept(stream)
                    .await
                    .expect("authenticate gRPC TLS session");
                let service = service.clone();
                tokio::spawn(async move {
                    tonic::transport::Server::builder()
                        .add_service(IsolationBoundaryServer::new(service))
                        .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(
                            TestTlsIo(Box::new(stream)),
                        )]))
                        .await
                        .expect("serve test gRPC connection");
                });
            }
        });
        let client = Arc::new(BoundaryClient::new(
            SandboxRuntimeDescriptor {
                boundary_id: "sandbox-1".to_string(),
                generation: "test-generation".to_string(),
                session_id: test_session_id(),
                workload_identity: sandbox().identity,
                transport: SandboxTransport::Tcp {
                    authority: "sandbox.test".to_string(),
                    addresses: vec![address],
                },
                tls: certificate.client_tls,
                host_gateway_ip: None,
                resource_claims: std::collections::BTreeMap::new(),
                driver_fence: test_driver_fence(),
            },
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        ));
        let mut requests = Vec::new();
        for _ in 0..REQUESTS {
            let client = client.clone();
            requests.push(tokio::spawn(async move {
                let response = client
                    .exchange(Request::Confirm)
                    .await
                    .expect("gRPC confirm request");
                assert!(matches!(response, Response::Confirmed { .. }));
            }));
        }
        for request in requests {
            request.await.expect("gRPC client request");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(handled.load(Ordering::Acquire), REQUESTS);
        assert_eq!(accepted.load(Ordering::Acquire), 1);
        server.abort();
    }

    #[tokio::test]
    async fn tls_tcp_flushes_large_control_requests_before_reading_response() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(certificate.server_config, "a".repeat(32)).await;
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        );
        let context = sandbox();

        assert!(matches!(
            client
                .exchange(Request::StartAgent {
                    sandbox_id: context.sandbox_id,
                    spec: AgentSpecWire::from(context.agent),
                    policy: Box::new(SandboxPolicyWire::from(context.policy)),
                    ca_cert: Some(vec![b'c'; 16 * 1024]),
                    ca_bundle: Some(vec![b'b'; 256 * 1024]),
                    activation: test_activation(),
                })
                .await
                .expect("large TLS request"),
            Response::Started { .. }
        ));
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tls_unix_flushes_large_control_requests_before_reading_response() {
        let socket_path = std::env::temp_dir().join(format!(
            "openshell-large-control-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let certificate = test_certificate();
        let server_config = certificate.server_config;
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind test socket");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(stream)
                .await
                .unwrap();
            serve_test_grpc(Box::new(stream), "a".repeat(32)).await;
        });
        let context = sandbox();
        let client = BoundaryClient::new(
            SandboxRuntimeDescriptor {
                boundary_id: "sandbox-1".to_string(),
                generation: "test-generation".to_string(),
                session_id: test_session_id(),
                workload_identity: context.identity.clone(),
                transport: SandboxTransport::Unix {
                    socket_path: socket_path.clone(),
                },
                tls: certificate.client_tls,
                host_gateway_ip: None,
                resource_claims: std::collections::BTreeMap::new(),
                driver_fence: test_driver_fence(),
            },
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        );

        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                client.exchange(Request::StartAgent {
                    sandbox_id: context.sandbox_id,
                    spec: AgentSpecWire::from(context.agent),
                    policy: Box::new(SandboxPolicyWire::from(context.policy)),
                    ca_cert: Some(vec![b'c'; 16 * 1024]),
                    ca_bundle: Some(vec![b'b'; 256 * 1024]),
                    activation: test_activation(),
                })
            )
            .await
            .expect("large Unix TLS request timed out")
            .expect("large Unix TLS request"),
            Response::Started { .. }
        ));
        server.abort();
        let _ = std::fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn tls_tcp_preserves_boundary_token_authentication() {
        let certificate = test_certificate();
        let (address, server) = spawn_tls_boundary(
            certificate.server_config,
            "expected-token-expected-token-12".to_string(),
        )
        .await;
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer("incorrect-token-incorrect-token"),
            test_supervisor_instance_id(),
        );

        assert!(matches!(
            client.exchange(Request::Confirm).await,
            Err(BackendError::Denied(_))
        ));
        server.abort();
    }

    #[tokio::test]
    async fn tls_tcp_rejects_an_untrusted_server_certificate() {
        let presented = test_certificate();
        let trusted = test_certificate();
        let (address, server) = spawn_tls_boundary(presented.server_config, "a".repeat(32)).await;
        let client = BoundaryClient::new(
            tls_runtime_descriptor(address, trusted.client_tls),
            test_bearer(&"a".repeat(32)),
            test_supervisor_instance_id(),
        );

        assert!(matches!(
            client.connect_boundary_once().await,
            Err(BackendError::Unavailable(_))
        ));
        // The server observes the client's fatal alert and may fail its accept;
        // completing the task is sufficient for this rejection test.
        let _ = server.await;
    }
}
