// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process and access-plane assembly for the capability-free sandbox boundary.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

#[cfg(target_os = "linux")]
use miette::WrapErr as _;
use miette::{IntoDiagnostic as _, Result};
use openshell_core::policy::SandboxPolicy;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation_interface::contract::{
    BoundaryExec, BoundaryLoopbackConnector, BoundarySignal,
};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, LaunchTypeId, Process as OcsfProcess,
    ProcessActivityBuilder, SeverityId, StatusId, ocsf_emit,
};

use crate::process::{ProcessHandle, ProcessStatus, ResolvedWorkspace};

fn ocsf_ctx() -> &'static openshell_ocsf::EventContext {
    openshell_ocsf::ctx::ctx()
}

/// Spawn the admitted workload without placing the gateway or policy authority
/// inside its boundary.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn spawn_workload(
    launcher: &openshell_isolation_interface::linux::workload_launcher::WorkloadLauncher,
    program: &str,
    args: &[String],
    workdir: Option<&str>,
    timeout_secs: u64,
    interactive: bool,
    policy: &SandboxPolicy,
    entrypoint_pid: Arc<AtomicU32>,
    provider_credentials: ProviderCredentialState,
    provider_env: std::collections::HashMap<String, String>,
    ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    boundary_runtime: Option<Arc<crate::boundary_io::BoundaryRuntimeState>>,
) -> Result<SpawnedAgent> {
    // The boundary already runs as the verified workload identity. Selecting
    // a workdir must not launch a process that needs broader workspace
    // permissions; validate existing authority without preparing ownership.
    #[cfg(target_os = "linux")]
    if let Some(workdir) = workdir {
        crate::process::validate_workload_workspace_as_effective_identity(std::path::Path::new(workdir))
            .wrap_err_with(|| {
                format!(
                    "WorkspaceValidationFailed: WorkingDir '{workdir}' must already be writable by the workload identity"
                )
            })?;
    }

    // Driver-selected workspaces are the sandbox identity's home. This keeps
    // canonical and later exec processes consistent for image WorkingDir and
    // the managed /sandbox fallback without consulting privileged account
    // setup inside the capability-free boundary.
    let workspace = ResolvedWorkspace::new(workdir.map(str::to_string), true);

    #[cfg(target_os = "linux")]
    {
        let mode = if std::env::var_os("OPENSHELL_REQUIRE_RUNTIME_PID_LIMIT").is_some() {
            crate::process::RuntimePidLimitMode::Require
        } else {
            crate::process::RuntimePidLimitMode::Warn
        };
        crate::process::check_runtime_pid_limit(mode).wrap_err("check runtime PID limit")?;
    }

    let boundary_runtime = boundary_runtime
        .unwrap_or_else(crate::boundary_io::BoundaryRuntimeState::new_exclusive_pid_namespace);
    let mut user_environment: std::collections::HashMap<String, String> =
        std::env::var(openshell_core::sandbox_env::USER_ENVIRONMENT)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();
    user_environment.retain(|key, _value| !crate::process::is_proxy_env_var(key));
    let loopback_connector: Arc<dyn BoundaryLoopbackConnector> = Arc::new(
        crate::boundary_io::LocalLoopbackConnector::new(Some(boundary_runtime.clone())),
    );
    let boundary_exec: Arc<dyn BoundaryExec> =
        Arc::new(crate::boundary_exec::LocalBoundaryExec::new(
            policy.clone(),
            workspace.owned_root(),
            ca_file_paths.clone().map(Arc::new),
            provider_credentials,
            user_environment,
            boundary_runtime.clone(),
            launcher.clone(),
        ));

    #[cfg(target_os = "linux")]
    let mut handle = ProcessHandle::spawn(
        launcher,
        program,
        args,
        &workspace,
        interactive,
        policy,
        ca_file_paths.as_ref(),
        &provider_env,
    )
    .wrap_err("spawn delegated workload process")?;
    #[cfg(not(target_os = "linux"))]
    let mut handle = ProcessHandle::spawn(
        program,
        args,
        &workspace,
        interactive,
        policy,
        ca_file_paths.as_ref(),
        &provider_env,
    )?;

    entrypoint_pid.store(handle.pid(), Ordering::Release);
    let main_session = crate::main_session::MainSession::new(handle.take_io(), handle.pid());
    let (terminal, signal_lock) = handle.signaling_state();
    boundary_runtime
        .register_process_group(handle.pid(), terminal.clone(), signal_lock)
        .map_err(|error| miette::miette!(error.to_string()))?;

    ocsf_emit!(
        ProcessActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .launch_type(LaunchTypeId::Spawn)
            .process(OcsfProcess::new(program, i64::from(handle.pid())))
            .message(format!("Process started: pid={}", handle.pid()))
            .build()
    );

    Ok(SpawnedAgent {
        handle,
        timeout_secs,
        terminal,
        main_session,
        boundary_exec,
        loopback_connector,
        boundary_runtime,
    })
}

/// Owned workload process and its live boundary capabilities.
pub struct SpawnedAgent {
    handle: ProcessHandle,
    timeout_secs: u64,
    terminal: Arc<AtomicBool>,
    main_session: Arc<crate::main_session::MainSession>,
    boundary_exec: Arc<dyn BoundaryExec>,
    loopback_connector: Arc<dyn BoundaryLoopbackConnector>,
    boundary_runtime: Arc<crate::boundary_io::BoundaryRuntimeState>,
}

impl SpawnedAgent {
    #[must_use]
    pub fn signaler(&self) -> AgentSignaler {
        AgentSignaler {
            pid: self.handle.pid(),
            terminal: self.terminal.clone(),
            boundary_runtime: self.boundary_runtime.clone(),
        }
    }

    #[must_use]
    pub fn boundary_exec(&self) -> Arc<dyn BoundaryExec> {
        self.boundary_exec.clone()
    }

    #[must_use]
    pub fn loopback_connector(&self) -> Arc<dyn BoundaryLoopbackConnector> {
        self.loopback_connector.clone()
    }

    /// Retained canonical-process I/O owned by the boundary.
    #[must_use]
    pub fn main_session(&self) -> Arc<crate::main_session::MainSession> {
        self.main_session.clone()
    }

    /// Wait for the canonical process to exit, enforcing its admitted
    /// wall-clock timeout. A timeout that expires while activation holds the
    /// process queues its termination signals until release. Completion does
    /// not end the boundary: exec and loopback forwarding remain available
    /// until the boundary owner tears down the retained runtime.
    pub async fn wait(&mut self) -> Result<ProcessStatus> {
        let signaler = self.signaler();
        let status = wait_with_timeout(self.handle.wait(), self.timeout_secs, &signaler).await?;
        self.boundary_runtime
            .unregister_process_group(self.handle.pid(), &self.terminal);
        let _ = self.main_session.finish(status.code(), false).await;
        self.main_session.mark_terminal_reported();
        Ok(status)
    }
}

/// Enforce the admitted deadline without canceling the owned child wait.
/// A hold can outlive this deadline; signal delivery waits for explicit release.
async fn wait_with_timeout(
    wait: impl Future<Output = std::io::Result<ProcessStatus>>,
    timeout_secs: u64,
    signaler: &AgentSignaler,
) -> Result<ProcessStatus> {
    tokio::pin!(wait);
    if timeout_secs == 0 {
        return wait.await.into_diagnostic();
    }
    if let Ok(status) = tokio::time::timeout(Duration::from_secs(timeout_secs), &mut wait).await {
        return status.into_diagnostic();
    }
    let _ = signaler.term();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = signaler.kill();
    wait.await.into_diagnostic()
}

/// Process-group signal handle that respects the boundary's activation hold.
#[derive(Clone)]
pub struct AgentSignaler {
    pid: u32,
    terminal: Arc<AtomicBool>,
    boundary_runtime: Arc<crate::boundary_io::BoundaryRuntimeState>,
}

#[cfg(unix)]
impl AgentSignaler {
    fn deliver(&self, signal: BoundarySignal) -> Result<()> {
        self.boundary_runtime
            .signal_process_group(self.pid, &self.terminal, signal)
            .map_err(|error| miette::miette!(error.to_string()))
    }

    /// Request graceful termination, deferring delivery while activation holds.
    pub fn term(&self) -> Result<()> {
        self.deliver(BoundarySignal::Term)
    }

    /// Request forced termination, deferring delivery while activation holds.
    pub fn kill(&self) -> Result<()> {
        self.deliver(BoundarySignal::Kill)
    }

    /// Request interruption, deferring delivery while activation holds.
    pub fn interrupt(&self) -> Result<()> {
        self.deliver(BoundarySignal::Int)
    }

    /// Request hangup, deferring delivery while activation holds.
    pub fn hangup(&self) -> Result<()> {
        self.deliver(BoundarySignal::Hup)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    include!("delegated_hold_tests.rs");
}
