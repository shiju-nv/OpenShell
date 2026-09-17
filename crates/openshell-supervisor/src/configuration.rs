// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Complete configuration preparation and activation for a remote workload.

#![expect(
    clippy::redundant_pub_crate,
    reason = "Coordination types are intentionally restricted to the parent module"
)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use miette::{IntoDiagnostic as _, Result};
use openshell_core::configuration::{ConfigurationActivationIdentity, ConfigurationRevision};
use openshell_core::grpc_client::{ProviderEnvironmentResult, SettingsPollResult};
use openshell_core::proto::{ConfigurationAdmissionState, SandboxConfigurationAdmission};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation_interface::contract::{
    ActivatedBoundaryConfiguration, BoundaryBootstrap, BoundaryConfiguration, ImagePolicyDiscovery,
    InstalledBoundaryConfiguration, PreparedBoundaryConfiguration,
};
use openshell_supervisor_network::opa::OpaEngine;
use tokio::sync::watch;

use super::{
    MiddlewareAuthentication, MiddlewareConnector, SandboxPolicy,
    agent_proposals_enabled_from_settings, apply_agent_proposals_enabled, apply_ocsf_json_setting,
    apply_policy_validation_failure, emit_policy_validation_failure,
    enrich_proto_baseline_paths_with, is_retryable_error, log_setting_changes, next_poll_delay,
    retain_extension_credentials, skills,
};

const STARTUP_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_FAILURE_LIMIT: u32 = 5;

/// Bound connection setup and the complete unary response, including a peer
/// that keeps its transport healthy without completing the requested operation.
async fn startup_operation<T>(
    name: &'static str,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(STARTUP_OPERATION_TIMEOUT, operation)
        .await
        .map_err(|_| {
            openshell_core::grpc_client::grpc_status_error(tonic::Status::deadline_exceeded(
                format!("{name} timed out after 10 seconds"),
            ))
        })?
}

/// Keep the transport category available without publishing remote payloads in
/// admission diagnostics. Untyped connection failures are operational failures.
fn preparation_operation_error(error: miette::Report, diagnostic: &'static str) -> miette::Report {
    let code = grpc_status_code(&error).unwrap_or(tonic::Code::Unavailable);
    openshell_core::grpc_client::grpc_status_error(tonic::Status::new(code, diagnostic))
}

/// The gateway operations whose successful responses bind a delivered snapshot.
#[tonic::async_trait]
pub(super) trait ConfigurationGateway: Send + Sync {
    /// Read observer state or issue the next immutable activation snapshot.
    async fn snapshot(&self, issue: bool) -> Result<SettingsPollResult>;
    /// Fetch the provider environment whose revision is checked before use.
    async fn provider(&self) -> Result<ProviderEnvironmentResult>;
    /// Persist selected image policy before obtaining an activation ticket.
    async fn sync_policy(
        &self,
        policy: &openshell_core::proto::SandboxPolicy,
        workspace: &str,
    ) -> Result<()>;
    /// Compare and persist registration or installation evidence.
    async fn report(
        &self,
        admission: &SandboxConfigurationAdmission,
        expected_instance: &str,
        expected_boundary: &str,
    ) -> Result<openshell_core::proto::ReportSandboxConfigurationResponse>;
    /// Prepare service authentication slots for the selected middleware registry.
    async fn middleware_credentials(
        &self,
        snapshot: &SettingsPollResult,
    ) -> Result<HashMap<String, openshell_extension_core::BearerTokenSlot>>;
    /// Rotate credentials attached to the currently installed service registry.
    async fn refresh_credentials(&self) -> Result<()>;
}

struct RemoteConfigurationGateway {
    endpoint: String,
    sandbox_id: String,
    sandbox: String,
    instance_id: String,
    client: openshell_core::grpc_client::CachedOpenShellClient,
}

#[tonic::async_trait]
impl ConfigurationGateway for RemoteConfigurationGateway {
    async fn snapshot(&self, issue: bool) -> Result<SettingsPollResult> {
        if issue {
            self.client
                .poll_configuration_settings(&self.sandbox_id, &self.instance_id)
                .await
        } else {
            self.client.poll_settings(&self.sandbox_id).await
        }
    }

    async fn provider(&self) -> Result<ProviderEnvironmentResult> {
        openshell_core::grpc_client::fetch_provider_environment(&self.endpoint, &self.sandbox_id)
            .await
    }

    async fn sync_policy(
        &self,
        policy: &openshell_core::proto::SandboxPolicy,
        workspace: &str,
    ) -> Result<()> {
        openshell_core::grpc_client::sync_policy_and_fetch_snapshot(
            &self.endpoint,
            &self.sandbox_id,
            &self.sandbox,
            policy,
            workspace,
        )
        .await?;
        Ok(())
    }

    async fn report(
        &self,
        admission: &SandboxConfigurationAdmission,
        expected_instance: &str,
        expected_boundary: &str,
    ) -> Result<openshell_core::proto::ReportSandboxConfigurationResponse> {
        openshell_core::grpc_client::report_sandbox_configuration(
            &self.endpoint,
            &self.sandbox_id,
            admission,
            expected_instance,
            expected_boundary,
        )
        .await
    }

    async fn middleware_credentials(
        &self,
        snapshot: &SettingsPollResult,
    ) -> Result<HashMap<String, openshell_extension_core::BearerTokenSlot>> {
        if snapshot.extension_authentication_enabled {
            self.client
                .extension_credentials_for(&snapshot.supervisor_middleware_services)
                .await
        } else {
            Ok(HashMap::new())
        }
    }

    async fn refresh_credentials(&self) -> Result<()> {
        self.client.refresh_installed_extension_credentials().await
    }
}

/// One registered control process, shared by admission and boundary attachment.
pub(super) struct ConfigurationSession {
    gateway: Arc<dyn ConfigurationGateway>,
    instance_id: String,
    runtime_generation: String,
    identity: Option<ConfigurationActivationIdentity>,
    startup_pending: bool,
    startup_failures: AtomicU32,
}

impl ConfigurationSession {
    /// Register one control process before image parsing can reject startup.
    pub(super) async fn register(
        endpoint: String,
        sandbox_id: String,
        sandbox: String,
        instance_id: String,
        runtime_generation: String,
        extension_credentials: openshell_extension_core::ExtensionCredentialStore,
    ) -> Result<Self> {
        let client = startup_operation(
            "Configuration gateway connection",
            openshell_core::grpc_client::CachedOpenShellClient::connect_with_credentials(
                &endpoint,
                extension_credentials,
            ),
        )
        .await?;
        let gateway = Arc::new(RemoteConfigurationGateway {
            endpoint,
            sandbox_id,
            sandbox,
            instance_id: instance_id.clone(),
            client,
        });
        Self::register_with_gateway(gateway, instance_id, runtime_generation).await
    }

    async fn register_with_gateway(
        gateway: Arc<dyn ConfigurationGateway>,
        instance_id: String,
        runtime_generation: String,
    ) -> Result<Self> {
        // Capture replacement fences once. A delayed retry must never rebase
        // them and displace a newer control process.
        let session = Self {
            gateway,
            instance_id,
            runtime_generation,
            identity: None,
            startup_pending: true,
            startup_failures: AtomicU32::new(0),
        };
        let registration = session
            .retry_operation("Control registration snapshot", || {
                session.gateway.snapshot(false)
            })
            .await?;
        if registration.runtime_generation != session.runtime_generation {
            return Err(miette::miette!(
                "Configuration belongs to a different runtime generation"
            ));
        }
        let admission = SandboxConfigurationAdmission {
            instance_id: session.instance_id.clone(),
            runtime_generation: session.runtime_generation.clone(),
            state: ConfigurationAdmissionState::Pending.into(),
            ..Default::default()
        };
        session
            .retry_operation("Control registration", || {
                session.gateway.report(
                    &admission,
                    &registration.configuration_instance_id,
                    &registration.configuration_boundary_instance_id,
                )
            })
            .await?;
        Ok(session)
    }

    async fn operation<T>(
        &self,
        name: &'static str,
        operation: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        if self.startup_pending {
            startup_operation(name, operation).await
        } else {
            operation.await
        }
    }

    async fn retry_operation<T, F, Fut>(&self, name: &'static str, mut operation: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        if !self.startup_pending {
            return operation().await;
        }
        loop {
            match self.operation(name, operation()).await {
                Ok(value) => return Ok(value),
                Err(error) => self.retry_after_failure(error).await?,
            }
        }
    }

    async fn retry_after_failure(&self, error: miette::Report) -> Result<()> {
        if !is_retryable_error(&error) {
            return Err(error);
        }
        // One startup budget spans snapshots, providers, and activation. A
        // successful poll cannot conceal persistent failure in a later phase.
        if self.startup_pending
            && self.startup_failures.fetch_add(1, Ordering::Relaxed) + 1 >= STARTUP_FAILURE_LIMIT
        {
            return Err(error.wrap_err("Startup configuration failed after 5 operational attempts"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    /// Bind workload discovery to a gateway-signed attachment registration.
    pub(super) async fn register_boundary(
        &mut self,
        bootstrap: &BoundaryBootstrap,
    ) -> Result<(openshell_core::jwt::SecretJwt, u64)> {
        let mut identity = bootstrap.identity.clone();
        identity.validate_bootstrap().into_diagnostic()?;
        let control_instance_mismatch = identity.supervisor_instance_id != self.instance_id;
        if identity.runtime_generation != self.runtime_generation || control_instance_mismatch {
            return Err(miette::miette!(
                "Boundary discovery returned a different control identity"
            ));
        }
        let admission = SandboxConfigurationAdmission {
            instance_id: self.instance_id.clone(),
            runtime_generation: self.runtime_generation.clone(),
            boundary_instance_id: identity.boundary_instance_id.clone(),
            boundary_session_id: identity.boundary_session_id.clone(),
            state: ConfigurationAdmissionState::Pending.into(),
            ..Default::default()
        };
        let response = self
            .retry_operation("Boundary registration", || {
                self.gateway.report(&admission, &self.instance_id, "")
            })
            .await?;
        identity.registration_revision = response.registration_revision;
        identity.validate().into_diagnostic()?;
        self.identity = Some(identity);
        Ok((
            openshell_core::jwt::SecretJwt::parse(response.control_registration_grant)
                .into_diagnostic()?,
            response.registration_revision,
        ))
    }

    fn identity(&self) -> Result<&ConfigurationActivationIdentity> {
        self.identity
            .as_ref()
            .ok_or_else(|| miette::miette!("Boundary registration is incomplete"))
    }

    /// Refresh the signed attachment proof without replacing its registration.
    pub(super) async fn registration_grant(&self) -> Result<(openshell_core::jwt::SecretJwt, u64)> {
        let identity = self.identity()?;
        let admission = SandboxConfigurationAdmission {
            instance_id: identity.supervisor_instance_id.clone(),
            runtime_generation: identity.runtime_generation.clone(),
            boundary_instance_id: identity.boundary_instance_id.clone(),
            boundary_session_id: identity.boundary_session_id.clone(),
            registration_revision: identity.registration_revision,
            state: ConfigurationAdmissionState::Pending.into(),
            ..Default::default()
        };
        let response = self
            .retry_operation("Boundary registration grant", || {
                self.gateway.report(
                    &admission,
                    &self.instance_id,
                    &identity.boundary_instance_id,
                )
            })
            .await?;
        if response.registration_revision != identity.registration_revision {
            return Err(miette::miette!(
                "Attachment grant changed the registered runtime identity"
            ));
        }
        Ok((
            openshell_core::jwt::SecretJwt::parse(response.control_registration_grant)
                .into_diagnostic()?,
            response.registration_revision,
        ))
    }

    /// Prepare a complete candidate without granting workload execution.
    pub(super) async fn prepare_startup(
        &self,
        bootstrap: &BoundaryBootstrap,
        connector: &MiddlewareConnector,
    ) -> Result<PreparedConfiguration> {
        loop {
            let snapshot = match self
                .operation(
                    "Startup configuration snapshot",
                    self.gateway.snapshot(true),
                )
                .await
            {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    self.retry_after_failure(error).await?;
                    continue;
                }
            };
            self.validate_snapshot(&snapshot)?;
            let Some(mut policy) = snapshot.policy.clone() else {
                if !snapshot.configuration_error.is_empty() {
                    self.reject_startup(&snapshot, "Effective policy composition is invalid")
                        .await?;
                    continue;
                }
                let discovered = match &bootstrap.image_policy {
                    ImagePolicyDiscovery::Missing => openshell_policy::restrictive_default_policy(),
                    ImagePolicyDiscovery::Present { yaml } => {
                        let Ok(policy) = openshell_policy::parse_sandbox_policy(yaml) else {
                            self.reject_startup(&snapshot, "Image policy is invalid; replace the sandbox policy to repair configuration").await?;
                            continue;
                        };
                        policy
                    }
                    ImagePolicyDiscovery::Invalid { .. } => {
                        self.reject_startup(&snapshot, "Image policy is unreadable; replace the sandbox policy to repair configuration").await?;
                        continue;
                    }
                };
                let mut discovered = discovered;
                enrich_from_boundary(&mut discovered, bootstrap);
                openshell_policy::strip_provider_rule_names(&mut discovered);
                self.sync_startup_policy(&discovered, &snapshot).await?;
                // Synchronization is a write, not a delivery ticket. Fetch a
                // new immutable snapshot before preparing its providers.
                continue;
            };
            if enrich_from_boundary(&mut policy, bootstrap) {
                openshell_policy::strip_provider_rule_names(&mut policy);
                self.sync_startup_policy(&policy, &snapshot).await?;
                continue;
            }
            match self.prepare(&snapshot, connector, None).await {
                Ok(prepared) => return Ok(prepared),
                Err(error) if grpc_status_code(&error).is_some() => {
                    self.retry_after_failure(error).await?;
                }
                Err(error) => {
                    // Preparation exposes fixed diagnostic categories, never
                    // raw policy, credential, or remote service error payloads.
                    self.reject_startup(&snapshot, &error.to_string()).await?;
                }
            }
        }
    }

    async fn sync_startup_policy(
        &self,
        policy: &openshell_core::proto::SandboxPolicy,
        snapshot: &SettingsPollResult,
    ) -> Result<()> {
        match self
            .operation(
                "Startup policy synchronization",
                self.gateway.sync_policy(policy, &snapshot.workspace),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    grpc_status_code(&error),
                    Some(tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition)
                ) =>
            {
                // A valid image document can still have invalid provider or
                // middleware bindings. Expose a fixed rejection for its issued
                // ticket and keep polling so an operator can replace it.
                self.reject_startup(
                    snapshot,
                    "Selected startup policy was rejected; replace the policy or repair its provider and middleware bindings",
                )
                .await
            }
            Err(error) if is_retryable_error(&error) => {
                // An operator repair can win the image-policy CAS. Return to
                // fresh polling instead of resubmitting stale image contents;
                // this also resolves an unknown result after transport loss.
                self.retry_after_failure(error).await
            }
            Err(error) => Err(error),
        }
    }

    /// Keep a rejected startup repairable without authorizing workload release.
    pub(super) async fn reject_startup(
        &self,
        snapshot: &SettingsPollResult,
        error: &str,
    ) -> Result<()> {
        match self
            .report(
                snapshot,
                ConfigurationAdmissionState::Rejected,
                false,
                error,
            )
            .await
        {
            Ok(()) => {
                // An acknowledged authored-configuration rejection can wait for
                // operator repair indefinitely; transport success alone cannot
                // reset the operational failure budget.
                self.startup_failures.store(0, Ordering::Relaxed);
            }
            Err(error) => {
                // A newer delivery supersedes this diagnostic too. Startup must
                // return to polling instead of retrying an obsolete rejection.
                if is_obsolete_delivery(&error) {
                    self.retry_after_failure(error).await?;
                } else {
                    return Err(error);
                }
            }
        }
        emit_rejection(error);
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    fn validate_snapshot(&self, snapshot: &SettingsPollResult) -> Result<()> {
        let identity = self.identity()?;
        // The delivery's configuration instance identifies the signed supervisor.
        let control_instance_mismatch =
            snapshot.configuration_instance_id != identity.supervisor_instance_id;
        if snapshot.runtime_generation != identity.runtime_generation
            || control_instance_mismatch
            || snapshot.configuration_boundary_instance_id != identity.boundary_instance_id
            || snapshot.configuration_registration_revision != identity.registration_revision
            || snapshot.configuration_snapshot.is_empty()
        {
            return Err(miette::miette!(
                "Configuration delivery does not match the registered runtime"
            ));
        }
        Ok(())
    }

    async fn prepare(
        &self,
        snapshot: &SettingsPollResult,
        connector: &MiddlewareConnector,
        previous: Option<&SettingsPollResult>,
    ) -> Result<PreparedConfiguration> {
        self.validate_snapshot(snapshot)?;
        let provider = self
            .operation("Provider environment", self.gateway.provider())
            .await
            .map_err(|error| {
                preparation_operation_error(error, "Provider environment is unavailable")
            })?;
        if self.startup_pending
            && snapshot.configuration_admitted
            && provider.provider_env_revision != snapshot.provider_env_revision
        {
            // A concurrently rotated provider requires a fresh snapshot, not
            // an authored-policy rejection that resets the startup budget.
            return Err(openshell_core::grpc_client::grpc_status_error(
                tonic::Status::aborted(
                    "Provider revision changed during configuration preparation",
                ),
            ));
        }
        let (engine, policy, credentials) = prepare_components(snapshot, provider)?;
        let registry_changed = previous.is_none_or(|previous| {
            previous.supervisor_middleware_services != snapshot.supervisor_middleware_services
                || previous.extension_authentication_enabled
                    != snapshot.extension_authentication_enabled
        });
        let middleware_registry = if registry_changed {
            let credentials = self
                .operation(
                    "Middleware authentication",
                    self.gateway.middleware_credentials(snapshot),
                )
                .await
                .map_err(|error| {
                    preparation_operation_error(error, "Middleware authentication is unavailable")
                })?;
            Some(
                self.operation(
                    "Middleware registry preparation",
                    connector(
                        snapshot.supervisor_middleware_services.clone(),
                        MiddlewareAuthentication {
                            credentials,
                            enabled: snapshot.extension_authentication_enabled,
                        },
                    ),
                )
                .await
                .map_err(|error| {
                    preparation_operation_error(error, "Middleware registry preparation failed")
                })?,
            )
        } else {
            None
        };
        Ok(PreparedConfiguration {
            snapshot: snapshot.clone(),
            policy,
            engine,
            credentials,
            middleware_registry,
        })
    }

    async fn report(
        &self,
        snapshot: &SettingsPollResult,
        state: ConfigurationAdmissionState,
        activation_confirmed: bool,
        error: &str,
    ) -> Result<()> {
        self.validate_snapshot(snapshot)?;
        let identity = self.identity()?;
        let admission = SandboxConfigurationAdmission {
            instance_id: identity.supervisor_instance_id.clone(),
            state: state.into(),
            policy_version: snapshot.version,
            policy_hash: snapshot.policy_hash.clone(),
            config_revision: snapshot.config_revision,
            provider_env_revision: snapshot.provider_env_revision,
            error: error.to_string(),
            runtime_generation: identity.runtime_generation.clone(),
            boundary_instance_id: identity.boundary_instance_id.clone(),
            boundary_session_id: identity.boundary_session_id.clone(),
            policy_source: snapshot.policy_source.into(),
            configuration_snapshot: snapshot.configuration_snapshot.clone(),
            activation_confirmed,
            registration_revision: identity.registration_revision,
            delivery_revision: snapshot.configuration_delivery_revision,
        };
        // Lost transport acknowledgements retry this exact admission. An
        // aborted delivery requires the caller to hold and prepare a fresh
        // snapshot; a replaced registration remains a terminal failure.
        loop {
            match self
                .operation(
                    "Configuration admission report",
                    self.gateway.report(
                        &admission,
                        &self.instance_id,
                        &identity.boundary_instance_id,
                    ),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(error) if is_obsolete_delivery(&error) => return Err(error),
                Err(error) => self.retry_after_failure(error).await?,
            }
        }
    }

    /// Install a complete held generation and obtain release authorization.
    pub(super) async fn install_startup(
        &self,
        boundary: &dyn BoundaryConfiguration,
        snapshot: &SettingsPollResult,
        credentials: &ProviderCredentialState,
    ) -> Result<()> {
        let current = boundary.snapshot().await.map_err(backend_error)?;
        if &current.identity != self.identity()? {
            return Err(miette::miette!(
                "Boundary installation identity changed before startup"
            ));
        }
        let expected = current.installed;
        let candidate = revision(snapshot);
        let prepared = boundary
            .prepare(
                expected.clone(),
                candidate.clone(),
                credentials.child_env_with_gcp_resolved(),
            )
            .await
            .map_err(backend_error)?;
        validate_preparation(&prepared, self.identity()?, &expected, &candidate)?;
        let installed = boundary.commit(&prepared).await.map_err(backend_error)?;
        validate_installation(&installed, &prepared)?;
        self.report(snapshot, ConfigurationAdmissionState::Accepted, false, "")
            .await?;
        let released = boundary.release(&installed).await.map_err(backend_error)?;
        if let Err(error) = validate_release(&released, &installed) {
            let _ = boundary.quiesce().await;
            return Err(error);
        }
        Ok(())
    }

    /// Report readiness only after the boundary acknowledges actual activation.
    pub(super) async fn confirm_activation(&self, snapshot: &SettingsPollResult) -> Result<()> {
        use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};

        self.report(snapshot, ConfigurationAdmissionState::Accepted, true, "")
            .await?;
        ocsf_emit!(
            ConfigStateChangeBuilder::new(super::ocsf_ctx())
                .severity(SeverityId::Informational)
                .status(StatusId::Success)
                .state(StateId::Enabled, "activated")
                .unmapped(
                    "config_revision",
                    serde_json::json!(snapshot.config_revision)
                )
                .unmapped(
                    "provider_env_revision",
                    serde_json::json!(snapshot.provider_env_revision)
                )
                .unmapped("policy_hash", serde_json::json!(snapshot.policy_hash))
                .message("Complete configuration installed, released, and acknowledged")
                .build()
        );
        Ok(())
    }
}

/// Prepared values have no references to mutable installed provider state.
pub(super) struct PreparedConfiguration {
    pub(super) snapshot: SettingsPollResult,
    pub(super) policy: SandboxPolicy,
    pub(super) engine: OpaEngine,
    pub(super) credentials: ProviderCredentialState,
    middleware_registry: Option<openshell_supervisor_middleware::MiddlewareRegistry>,
}

impl PreparedConfiguration {
    /// Attach the prepared middleware registry before networking can consume OPA.
    pub(super) fn install_startup_registry(&mut self) -> Result<()> {
        if let Some(registry) = self.middleware_registry.take() {
            self.engine.replace_middleware_registry(registry)?;
        }
        Ok(())
    }
}

fn prepare_components(
    snapshot: &SettingsPollResult,
    provider: ProviderEnvironmentResult,
) -> Result<(OpaEngine, SandboxPolicy, ProviderCredentialState)> {
    if !snapshot.configuration_admitted {
        return Err(miette::miette!(
            "Effective configuration admission rejected"
        ));
    }
    if snapshot.provider_env_revision != provider.provider_env_revision {
        return Err(miette::miette!(
            "Provider revision changed during configuration preparation"
        ));
    }
    revision(snapshot).validate().into_diagnostic()?;
    let policy = snapshot
        .policy
        .as_ref()
        .ok_or_else(|| miette::miette!("Effective policy is unavailable"))?;
    let engine = OpaEngine::from_proto(policy)
        .map_err(|_| miette::miette!("Policy failed runtime validation"))?;
    let process_policy = SandboxPolicy::try_from(policy.clone())
        .map_err(|_| miette::miette!("Process or filesystem policy failed validation"))?;
    let credentials = ProviderCredentialState::from_bound_environment(
        provider.provider_env_revision,
        provider.environment,
        provider.credential_expires_at_ms,
        provider.dynamic_credentials,
        provider.static_credential_bindings,
        provider.non_secret_environment_keys,
    )
    .map_err(|_| miette::miette!("Provider credential bindings are invalid"))?;
    Ok((engine, process_policy, credentials))
}

fn enrich_from_boundary(
    policy: &mut openshell_core::proto::SandboxPolicy,
    bootstrap: &BoundaryBootstrap,
) -> bool {
    enrich_proto_baseline_paths_with(
        policy,
        &bootstrap.filesystem_baseline.read_only,
        &bootstrap.filesystem_baseline.read_write,
        |_| true,
    )
}

fn revision(snapshot: &SettingsPollResult) -> ConfigurationRevision {
    ConfigurationRevision {
        config_revision: snapshot.config_revision,
        policy_version: snapshot.version,
        policy_hash: snapshot.policy_hash.clone(),
        policy_source: snapshot.policy_source.into(),
        provider_env_revision: snapshot.provider_env_revision,
    }
}

fn validate_preparation(
    prepared: &PreparedBoundaryConfiguration,
    identity: &ConfigurationActivationIdentity,
    expected: &Option<ConfigurationRevision>,
    candidate: &ConfigurationRevision,
) -> Result<()> {
    if &prepared.identity != identity
        || &prepared.expected != expected
        || &prepared.configuration != candidate
        || prepared.transition_id.is_empty()
    {
        return Err(miette::miette!(
            "Boundary prepared a different configuration"
        ));
    }
    Ok(())
}

fn validate_installation(
    installed: &InstalledBoundaryConfiguration,
    prepared: &PreparedBoundaryConfiguration,
) -> Result<()> {
    if installed.identity != prepared.identity
        || installed.configuration != prepared.configuration
        || installed.transition_id != prepared.transition_id
    {
        return Err(miette::miette!(
            "Boundary acknowledged a different installation"
        ));
    }
    Ok(())
}

fn validate_release(
    released: &ActivatedBoundaryConfiguration,
    installed: &InstalledBoundaryConfiguration,
) -> Result<()> {
    if released.identity != installed.identity
        || released.configuration != installed.configuration
        || released.transition_id != installed.transition_id
    {
        return Err(miette::miette!(
            "Boundary acknowledged a different activation"
        ));
    }
    Ok(())
}

fn backend_error(error: openshell_isolation_interface::contract::BackendError) -> miette::Report {
    miette::miette!(error.to_string())
}

/// The gateway uses Aborted when a delivered ticket or service identity changed.
fn is_obsolete_delivery(error: &miette::Report) -> bool {
    grpc_status_code(error) == Some(tonic::Code::Aborted)
}

fn grpc_status_code(error: &miette::Report) -> Option<tonic::Code> {
    let mut source: Option<&dyn std::error::Error> = Some(error.as_ref());
    while let Some(error) = source {
        if let Some(status) = error.downcast_ref::<tonic::Status>() {
            return Some(status.code());
        }
        source = error.source();
    }
    None
}

fn emit_rejection(error: &str) {
    use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};
    ocsf_emit!(
        ConfigStateChangeBuilder::new(super::ocsf_ctx())
            .severity(SeverityId::High)
            .status(StatusId::Failure)
            .state(StateId::Disabled, "configuration_error")
            .message(error)
            .build()
    );
}

/// Shared live state; only the transition loop may publish a new generation.
pub(super) struct RuntimeConfiguration {
    pub(super) session: ConfigurationSession,
    pub(super) boundary: Arc<dyn BoundaryConfiguration>,
    pub(super) snapshot: SettingsPollResult,
    pub(super) engine: Arc<OpaEngine>,
    pub(super) credentials: ProviderCredentialState,
    pub(super) readiness: watch::Sender<bool>,
    pub(super) ocsf_enabled: Arc<AtomicBool>,
    pub(super) agent_proposals: openshell_core::proposals::AgentProposals,
    pub(super) policy_local:
        Option<Arc<openshell_supervisor_network::policy_local::PolicyLocalContext>>,
    pub(super) workspace: watch::Sender<String>,
    pub(super) extension_credentials: openshell_extension_core::ExtensionCredentialStore,
    pub(super) connector: MiddlewareConnector,
    /// Inventory changes follow successful local policy/credential publication.
    pub(super) endpoint_observation_tx:
        Option<openshell_core::endpoint_status::EndpointObservationSender>,
    pub(super) interval: Duration,
}

/// Abort reconciliation when its owning supervisor access plane is dropped.
pub(super) struct ConfigurationTask(tokio::task::JoinHandle<Result<()>>);

impl ConfigurationTask {
    /// Run configuration reconciliation for the lifetime of its access plane.
    pub(super) fn start(runtime: RuntimeConfiguration) -> Self {
        Self(tokio::spawn(runtime.run()))
    }

    /// Observe fatal reconciliation failure alongside process and proxy exit.
    pub(super) fn completion(&mut self) -> &mut tokio::task::JoinHandle<Result<()>> {
        &mut self.0
    }
}

impl Drop for ConfigurationTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl RuntimeConfiguration {
    /// Consume the launch handle once, retaining its workload through acknowledgement repair.
    pub(super) async fn start_workload(
        &mut self,
        mut ready: Box<dyn openshell_isolation_interface::contract::ReadyBoundary>,
        bootstrap: &BoundaryBootstrap,
    ) -> Result<Box<dyn openshell_isolation_interface::contract::RunningBoundary>> {
        self.install_startup(ready.as_mut(), bootstrap).await?;
        let running = ready.start_agent().await.map_err(backend_error)?;
        self.confirm_startup().await?;
        // Live reconciliation retains its existing recovery policy only after
        // one workload has a confirmed activation. Startup recovery stays bounded.
        self.session.startup_pending = false;
        Ok(running)
    }

    /// Recover obsolete startup deliveries before consuming the sole launch handle.
    pub(super) async fn install_startup(
        &mut self,
        ready: &mut dyn openshell_isolation_interface::contract::ReadyBoundary,
        bootstrap: &BoundaryBootstrap,
    ) -> Result<()> {
        loop {
            match self
                .session
                .install_startup(self.boundary.as_ref(), &self.snapshot, &self.credentials)
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) if is_obsolete_delivery(&error) => {
                    self.readiness.send_replace(false);
                    self.boundary.quiesce().await.map_err(backend_error)?;
                    if self.session.startup_pending {
                        self.session.retry_after_failure(error).await?;
                    }
                }
                Err(error) => return Err(error),
            }
            loop {
                let prepared = self
                    .session
                    .prepare_startup(bootstrap, &self.connector)
                    .await?;
                let (grant, revision) = self.session.registration_grant().await?;
                self.boundary
                    .refresh_registration(grant, revision)
                    .await
                    .map_err(backend_error)?;
                match ready.update_startup_policy(prepared.policy.clone()).await {
                    Ok(()) => {}
                    Err(openshell_isolation_interface::contract::BackendError::Configuration(
                        _,
                    )) => {
                        self.session
                            .reject_startup(
                                &prepared.snapshot,
                                "Selected process policy does not match the workload identity",
                            )
                            .await?;
                        continue;
                    }
                    Err(error) => return Err(backend_error(error)),
                }
                // The boundary remains held, and its future launch now uses
                // this prepared static policy. Publish its matching network
                // policy and credentials before committing child inputs.
                self.engine.reload_configuration_from_proto_with_pid(
                    prepared
                        .snapshot
                        .policy
                        .as_ref()
                        .ok_or_else(|| miette::miette!("Prepared startup policy is missing"))?,
                    0,
                    prepared.middleware_registry,
                    || {
                        self.credentials.install_prepared(&prepared.credentials);
                    },
                )?;
                self.reset_endpoint_inventory(&prepared.snapshot).await;
                self.snapshot = prepared.snapshot;
                break;
            }
        }
    }

    /// Finish acknowledgement while retaining the already-started workload handle.
    pub(super) async fn confirm_startup(&mut self) -> Result<()> {
        match self.session.confirm_activation(&self.snapshot).await {
            Ok(()) => return self.record_activation(self.snapshot.clone()).await,
            Err(error) => {
                // Main may already be running. Recovery must stop it before
                // polling and re-admit without invoking start_agent again.
                self.readiness.send_replace(false);
                self.boundary.quiesce().await.map_err(backend_error)?;
                if !is_obsolete_delivery(&error) {
                    return Err(error);
                }
                if self.session.startup_pending {
                    self.session.retry_after_failure(error).await?;
                }
            }
        }
        loop {
            let snapshot = self.poll_snapshot().await?;
            self.reconcile_snapshot(snapshot).await?;
            if *self.readiness.borrow() {
                return Ok(());
            }
            // Invalid replacement configuration remains an operator-repair
            // loop while the existing workload is held and readiness is false.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Reconcile complete generations and hold execution if reconciliation ends.
    pub(super) async fn run(mut self) -> Result<()> {
        let result = self.reconcile().await;
        // A stopped configuration task cannot leave an apparently healthy
        // access plane. Quiescence also invalidates exec after a fatal fence.
        self.readiness.send_replace(false);
        let _ = self.boundary.quiesce().await;
        result
    }

    async fn reconcile(&mut self) -> Result<()> {
        let mut boundary_readiness = self.boundary.readiness();
        loop {
            // Transport reconnect revokes activation immediately. Wake on that
            // change instead of waiting a full policy poll interval to repair it.
            tokio::select! {
                () = tokio::time::sleep(next_poll_delay(&self.extension_credentials, self.interval)) => {}
                changed = boundary_readiness.changed() => {
                    changed.into_diagnostic()?;
                    if *boundary_readiness.borrow_and_update() {
                        continue;
                    }
                    self.readiness.send_replace(false);
                }
            }
            let snapshot = match self.session.gateway.snapshot(true).await {
                Ok(snapshot) => snapshot,
                Err(error) if is_retryable_error(&error) => {
                    let _ = self.session.gateway.refresh_credentials().await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let (grant, registration_revision) = self.session.registration_grant().await?;
            self.boundary
                .refresh_registration(grant, registration_revision)
                .await
                .map_err(backend_error)?;
            self.reconcile_snapshot(snapshot).await?;
        }
    }
    async fn reconcile_snapshot(&mut self, mut snapshot: SettingsPollResult) -> Result<()> {
        loop {
            match self.install_snapshot(snapshot).await {
                Err(error) if is_obsolete_delivery(&error) => {
                    // Final confirmation can lose its ticket after release.
                    // Hold before polling, including under retain-last-valid,
                    // because that release no longer has current acceptance.
                    self.readiness.send_replace(false);
                    self.boundary.quiesce().await.map_err(backend_error)?;
                    if self.session.startup_pending {
                        self.session.retry_after_failure(error).await?;
                    }
                    snapshot = self.poll_snapshot().await?;
                }
                Err(error)
                    if self.session.startup_pending
                        && is_retryable_error(&error)
                        && grpc_status_code(&error).is_some() =>
                {
                    self.readiness.send_replace(false);
                    self.boundary.quiesce().await.map_err(backend_error)?;
                    self.session.retry_after_failure(error).await?;
                    snapshot = self.poll_snapshot().await?;
                }
                result => return result,
            }
        }
    }

    async fn poll_snapshot(&self) -> Result<SettingsPollResult> {
        loop {
            match self
                .session
                .operation(
                    "Configuration recovery snapshot",
                    self.session.gateway.snapshot(true),
                )
                .await
            {
                Ok(snapshot) => {
                    self.session.validate_snapshot(&snapshot)?;
                    let (grant, revision) = self.session.registration_grant().await?;
                    self.boundary
                        .refresh_registration(grant, revision)
                        .await
                        .map_err(backend_error)?;
                    return Ok(snapshot);
                }
                Err(error) if is_retryable_error(&error) => {
                    if self.session.startup_pending {
                        self.session.retry_after_failure(error).await?;
                    }
                    let _ = self
                        .session
                        .operation(
                            "Extension credential refresh",
                            self.session.gateway.refresh_credentials(),
                        )
                        .await;
                    if !self.session.startup_pending {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn install_snapshot(&mut self, snapshot: SettingsPollResult) -> Result<()> {
        self.session.validate_snapshot(&snapshot)?;
        let current = self.boundary.snapshot().await.map_err(backend_error)?;
        if &current.identity != self.session.identity()? {
            return Err(miette::miette!(
                "Boundary incarnation changed; a new runtime generation is required"
            ));
        }
        if current.active
            && revision(&snapshot) == revision(&self.snapshot)
            && snapshot.configuration_snapshot == self.snapshot.configuration_snapshot
        {
            self.session
                .operation(
                    "Extension credential refresh",
                    self.session.gateway.refresh_credentials(),
                )
                .await?;
            return Ok(());
        }
        let prepared = match self
            .session
            .prepare(&snapshot, &self.connector, Some(&self.snapshot))
            .await
        {
            Ok(prepared) => prepared,
            Err(error) if self.session.startup_pending && grpc_status_code(&error).is_some() => {
                return Err(error);
            }
            Err(error) => {
                let diagnostic = format!("{error}; previous credentials remain installed");
                if snapshot.policy_validation_failure_mode
                    == openshell_core::PolicyValidationFailureMode::FailClosed
                    || !current.active
                {
                    self.readiness.send_replace(false);
                    self.boundary.quiesce().await.map_err(backend_error)?;
                }
                let disposition = apply_policy_validation_failure(
                    &self.engine,
                    snapshot.policy_validation_failure_mode,
                    true,
                    snapshot.version,
                    &diagnostic,
                )?;
                emit_policy_validation_failure(
                    &disposition,
                    snapshot.version,
                    &snapshot.policy_hash,
                    &diagnostic,
                );
                self.session
                    .report(
                        &snapshot,
                        ConfigurationAdmissionState::Rejected,
                        false,
                        &diagnostic,
                    )
                    .await?;
                if self.session.startup_pending {
                    self.session.startup_failures.store(0, Ordering::Relaxed);
                }
                return Ok(());
            }
        };
        self.readiness.send_replace(false);
        let expected = current.installed;
        let candidate = revision(&snapshot);
        let staged = self
            .boundary
            .prepare(
                expected.clone(),
                candidate.clone(),
                prepared.credentials.child_env_with_gcp_resolved(),
            )
            .await
            .map_err(backend_error)?;
        validate_preparation(&staged, self.session.identity()?, &expected, &candidate)?;
        let policy = snapshot
            .policy
            .as_ref()
            .ok_or_else(|| miette::miette!("Prepared configuration lost its policy"))?;
        if let Err(error) = self.engine.reload_configuration_from_proto_with_pid(
            policy,
            0,
            prepared.middleware_registry,
            || {
                self.credentials.install_prepared(&prepared.credentials);
            },
        ) {
            // No local callback runs on failed validation. Abort discards
            // staged child inputs and leaves the boundary held for repair.
            let _ = self.boundary.abort(&staged).await;
            return Err(error);
        }
        // The local policy and provider state now agree while the workload is
        // still held. Retire old observation handles before releasing traffic;
        // rejected preparations never replace the last installed inventory.
        self.reset_endpoint_inventory(&snapshot).await;
        let installed = self.boundary.commit(&staged).await.map_err(backend_error)?;
        validate_installation(&installed, &staged)?;
        self.session
            .report(&snapshot, ConfigurationAdmissionState::Accepted, false, "")
            .await?;
        let released = self
            .boundary
            .release(&installed)
            .await
            .map_err(backend_error)?;
        validate_release(&released, &installed)?;
        self.session.confirm_activation(&snapshot).await?;

        self.record_activation(snapshot).await
    }

    async fn reset_endpoint_inventory(&self, snapshot: &SettingsPollResult) {
        super::endpoint_status::reset(
            self.endpoint_observation_tx.as_ref(),
            snapshot.policy.as_ref(),
            &snapshot.policy_hash,
            self.credentials.snapshot().revision,
        )
        .await;
    }

    async fn record_activation(&mut self, snapshot: SettingsPollResult) -> Result<()> {
        let policy = snapshot
            .policy
            .as_ref()
            .ok_or_else(|| miette::miette!("Accepted configuration lost its policy"))?;
        if let Some(policy_local) = self.policy_local.as_ref() {
            policy_local.set_current_policy(policy.clone()).await;
        }
        log_setting_changes(&self.snapshot.settings, &snapshot.settings);
        apply_ocsf_json_setting(&self.ocsf_enabled, &snapshot.settings);
        apply_agent_proposals_enabled(
            &self.agent_proposals,
            agent_proposals_enabled_from_settings(&snapshot.settings),
            "configuration activation",
            Some(snapshot.config_revision),
            skills::install_static_skills,
        );
        retain_extension_credentials(
            &self.extension_credentials,
            &snapshot.supervisor_middleware_services,
            snapshot.extension_authentication_enabled,
        );
        self.workspace.send_replace(snapshot.workspace.clone());
        self.snapshot = snapshot;
        self.readiness.send_replace(true);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_isolation_interface::contract::{
        BackendError, BoundaryConfigurationSnapshot, BoundaryFilesystemBaseline,
        ResolvedWorkloadIdentity, RunningBoundary,
    };
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(target_os = "linux")]
    include!("configuration_runtime_tests.rs");

    #[cfg(target_os = "linux")]
    include!("configuration_protocol_runtime_tests.rs");

    fn identity() -> ConfigurationActivationIdentity {
        ConfigurationActivationIdentity {
            runtime_generation: "runtime-1".into(),
            boundary_session_id: "session-1".into(),
            supervisor_instance_id: "control-1".into(),
            boundary_instance_id: "boundary-1".into(),
            registration_revision: 3,
        }
    }

    fn snapshot(generation: u64) -> SettingsPollResult {
        SettingsPollResult {
            configuration_instance_id: "control-1".into(),
            configuration_admitted: true,
            configuration_error: String::new(),
            runtime_generation: "runtime-1".into(),
            configuration_boundary_instance_id: "boundary-1".into(),
            configuration_snapshot: format!("snapshot-{generation}"),
            configuration_registration_revision: 3,
            configuration_delivery_revision: generation,
            policy: Some(openshell_policy::restrictive_default_policy()),
            version: u32::try_from(generation).expect("test generation fits"),
            policy_hash: format!("policy-{generation}"),
            config_revision: generation,
            policy_source: openshell_core::proto::PolicySource::Sandbox,
            settings: HashMap::new(),
            global_policy_version: 0,
            provider_env_revision: generation,
            supervisor_middleware_services: Vec::new(),
            workspace: "test-workspace".into(),
            policy_validation_failure_mode: openshell_core::PolicyValidationFailureMode::FailClosed,
            extension_authentication_enabled: false,
        }
    }

    fn provider(revision: u64) -> ProviderEnvironmentResult {
        ProviderEnvironmentResult {
            environment: HashMap::new(),
            provider_env_revision: revision,
            credential_expires_at_ms: HashMap::new(),
            dynamic_credentials: HashMap::new(),
            static_credential_bindings: HashMap::new(),
            non_secret_environment_keys: Vec::new(),
        }
    }

    fn bootstrap(image_policy: ImagePolicyDiscovery) -> BoundaryBootstrap {
        BoundaryBootstrap {
            identity: identity(),
            workload_identity: ResolvedWorkloadIdentity::new(
                1000,
                1000,
                Vec::new(),
                "image".into(),
                "image-digest".into(),
            )
            .expect("workload identity"),
            image_policy,
            filesystem_baseline: BoundaryFilesystemBaseline::default(),
        }
    }

    struct Gateway {
        snapshot: Mutex<SettingsPollResult>,
        provider_revision: AtomicU64,
        reject_authorization: AtomicBool,
        report_faults: Mutex<std::collections::VecDeque<ReportFault>>,
        report_attempts: Mutex<Vec<SandboxConfigurationAdmission>>,
        record_polls: AtomicBool,
        sync_repair: Mutex<Option<openshell_core::proto::SandboxPolicy>>,
        sync_error: Mutex<Option<tonic::Code>>,
        events: Arc<Mutex<Vec<String>>>,
    }

    struct ReportFault {
        confirmed: bool,
        code: tonic::Code,
        message: &'static str,
        replacement: Option<SettingsPollResult>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StartupCall {
        RegistrationSnapshot,
        Snapshot,
        Provider,
        Sync,
        Registration,
        Rejection,
        Acceptance,
        Confirmation,
        Middleware,
    }

    #[derive(Clone, Copy)]
    enum StartupFault {
        Pending,
        Status(tonic::Code),
    }

    struct StartupFaultGateway {
        inner: Arc<Gateway>,
        selected: StartupCall,
        fault: StartupFault,
        failures: u32,
        calls: AtomicU32,
    }

    impl StartupFaultGateway {
        async fn before(&self, call: StartupCall) -> Result<()> {
            if self.selected != call || self.calls.fetch_add(1, Ordering::Relaxed) >= self.failures
            {
                return Ok(());
            }
            match self.fault {
                StartupFault::Pending => std::future::pending().await,
                StartupFault::Status(code) => Err(openshell_core::grpc_client::grpc_status_error(
                    tonic::Status::new(code, "private remote failure payload"),
                )),
            }
        }
    }

    #[tonic::async_trait]
    impl ConfigurationGateway for StartupFaultGateway {
        async fn snapshot(&self, issue: bool) -> Result<SettingsPollResult> {
            self.before(if issue {
                StartupCall::Snapshot
            } else {
                StartupCall::RegistrationSnapshot
            })
            .await?;
            self.inner.snapshot(issue).await
        }

        async fn provider(&self) -> Result<ProviderEnvironmentResult> {
            self.before(StartupCall::Provider).await?;
            self.inner.provider().await
        }

        async fn sync_policy(
            &self,
            policy: &openshell_core::proto::SandboxPolicy,
            workspace: &str,
        ) -> Result<()> {
            self.before(StartupCall::Sync).await?;
            self.inner.sync_policy(policy, workspace).await
        }

        async fn report(
            &self,
            admission: &SandboxConfigurationAdmission,
            expected_instance: &str,
            expected_boundary: &str,
        ) -> Result<openshell_core::proto::ReportSandboxConfigurationResponse> {
            let call = match ConfigurationAdmissionState::try_from(admission.state)
                .expect("admission state")
            {
                ConfigurationAdmissionState::Pending => StartupCall::Registration,
                ConfigurationAdmissionState::Rejected => StartupCall::Rejection,
                ConfigurationAdmissionState::Accepted if admission.activation_confirmed => {
                    StartupCall::Confirmation
                }
                ConfigurationAdmissionState::Accepted => StartupCall::Acceptance,
                ConfigurationAdmissionState::Unspecified => {
                    panic!("unexpected unspecified admission")
                }
            };
            self.before(call).await?;
            self.inner
                .report(admission, expected_instance, expected_boundary)
                .await
        }

        async fn middleware_credentials(
            &self,
            snapshot: &SettingsPollResult,
        ) -> Result<HashMap<String, openshell_extension_core::BearerTokenSlot>> {
            self.before(StartupCall::Middleware).await?;
            self.inner.middleware_credentials(snapshot).await
        }

        async fn refresh_credentials(&self) -> Result<()> {
            self.inner.refresh_credentials().await
        }
    }

    fn fault_startup(
        runtime: &mut RuntimeConfiguration,
        gateway: &Arc<Gateway>,
        selected: StartupCall,
        fault: StartupFault,
        failures: u32,
    ) -> Arc<StartupFaultGateway> {
        let fault = Arc::new(StartupFaultGateway {
            inner: gateway.clone(),
            selected,
            fault,
            failures,
            calls: AtomicU32::new(0),
        });
        runtime.session.startup_pending = true;
        runtime.session.gateway = fault.clone();
        fault
    }

    #[tokio::test(start_paused = true)]
    async fn configuration_startup_pending_gateway_operations_exhaust_budget() {
        for call in [
            StartupCall::RegistrationSnapshot,
            StartupCall::Registration,
            StartupCall::Snapshot,
            StartupCall::Provider,
            StartupCall::Sync,
            StartupCall::Middleware,
            StartupCall::Rejection,
            StartupCall::Acceptance,
            StartupCall::Confirmation,
        ] {
            let (mut runtime, gateway, boundary, events) = runtime();
            let fault = fault_startup(
                &mut runtime,
                &gateway,
                call,
                StartupFault::Pending,
                u32::MAX,
            );
            if call == StartupCall::Sync {
                gateway.snapshot.lock().expect("snapshot").policy = None;
            }
            let operation = async {
                match call {
                    StartupCall::RegistrationSnapshot | StartupCall::Registration => {
                        ConfigurationSession::register_with_gateway(
                            fault.clone(),
                            "control-1".into(),
                            "runtime-1".into(),
                        )
                        .await
                        .map(|_| ())
                    }
                    StartupCall::Acceptance | StartupCall::Confirmation => runtime
                        .start_workload(
                            Box::new(Ready { boundary }),
                            &bootstrap(ImagePolicyDiscovery::Missing),
                        )
                        .await
                        .map(|_| ()),
                    StartupCall::Rejection => {
                        runtime
                            .session
                            .reject_startup(&runtime.snapshot, "invalid authored policy")
                            .await
                    }
                    _ => runtime
                        .session
                        .prepare_startup(
                            &bootstrap(ImagePolicyDiscovery::Missing),
                            &runtime.connector,
                        )
                        .await
                        .map(|_| ()),
                }
            };
            let error = tokio::time::timeout(Duration::from_secs(70), operation)
                .await
                .expect("pending startup operations must terminate")
                .expect_err("no operation completed");
            assert!(
                error.to_string().contains("5 operational attempts"),
                "{call:?}: {error}"
            );
            assert_eq!(fault.calls.load(Ordering::Relaxed), 5, "{call:?}");
            let starts = events
                .lock()
                .expect("events")
                .iter()
                .filter(|event| *event == "start")
                .count();
            assert_eq!(starts, usize::from(call == StartupCall::Confirmation));
            if call == StartupCall::Confirmation {
                assert!(
                    !*runtime.readiness.borrow(),
                    "unconfirmed workload must remain held"
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn configuration_startup_boundary_registration_and_grant_are_bounded() {
        for refresh in [false, true] {
            let (mut runtime, gateway, _, _) = runtime();
            let fault = fault_startup(
                &mut runtime,
                &gateway,
                StartupCall::Registration,
                StartupFault::Pending,
                u32::MAX,
            );
            let mut discovery = bootstrap(ImagePolicyDiscovery::Missing);
            // Registration validates canonical process UUIDs before issuing
            // its RPC, so this fixture must reach the pending gateway call.
            discovery.identity.boundary_session_id = "11111111-1111-4111-8111-111111111111".into();
            discovery.identity.supervisor_instance_id =
                "22222222-2222-4222-8222-222222222222".into();
            discovery.identity.boundary_instance_id = "33333333-3333-4333-8333-333333333333".into();
            runtime
                .session
                .instance_id
                .clone_from(&discovery.identity.supervisor_instance_id);
            runtime.session.identity = Some(discovery.identity.clone());
            discovery.identity.registration_revision = 0;
            let operation = async {
                if refresh {
                    runtime.session.registration_grant().await
                } else {
                    runtime.session.register_boundary(&discovery).await
                }
            };
            let error = tokio::time::timeout(Duration::from_secs(70), operation)
                .await
                .expect("pending registration must terminate")
                .expect_err("registration never responded");
            assert!(
                error.to_string().contains("5 operational attempts"),
                "{error}"
            );
            assert_eq!(fault.calls.load(Ordering::Relaxed), 5);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn configuration_startup_successful_snapshots_do_not_reset_provider_or_sync_failures() {
        for call in [
            StartupCall::Provider,
            StartupCall::Sync,
            StartupCall::Middleware,
        ] {
            let (mut runtime, gateway, _, events) = runtime();
            let fault = fault_startup(
                &mut runtime,
                &gateway,
                call,
                StartupFault::Status(tonic::Code::Unavailable),
                u32::MAX,
            );
            if call == StartupCall::Sync {
                gateway.snapshot.lock().expect("snapshot").policy = None;
            }
            let error = tokio::time::timeout(
                Duration::from_secs(15),
                runtime.session.prepare_startup(
                    &bootstrap(ImagePolicyDiscovery::Missing),
                    &runtime.connector,
                ),
            )
            .await
            .expect("operational failure must terminate")
            .err()
            .expect("persistent unavailable");
            assert_eq!(fault.calls.load(Ordering::Relaxed), 5);
            assert!(error.to_string().contains("5 operational attempts"));
            assert!(
                !events
                    .lock()
                    .expect("events")
                    .iter()
                    .any(|event| event.starts_with("report:Rejected")),
                "infrastructure failure must not reset the repair budget"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn configuration_startup_provider_and_middleware_authentication_errors_are_terminal() {
        for call in [StartupCall::Provider, StartupCall::Middleware] {
            for code in [tonic::Code::PermissionDenied, tonic::Code::Unauthenticated] {
                let (mut runtime, gateway, _, events) = runtime();
                let fault = fault_startup(
                    &mut runtime,
                    &gateway,
                    call,
                    StartupFault::Status(code),
                    u32::MAX,
                );
                let error = tokio::time::timeout(
                    Duration::from_secs(1),
                    runtime.session.prepare_startup(
                        &bootstrap(ImagePolicyDiscovery::Missing),
                        &runtime.connector,
                    ),
                )
                .await
                .expect("permanent errors must not retry")
                .err()
                .expect("authentication failed");
                assert_eq!(grpc_status_code(&error), Some(code));
                assert_eq!(fault.calls.load(Ordering::Relaxed), 1);
                assert!(!error.to_string().contains("private remote failure payload"));
                assert!(
                    !events
                        .lock()
                        .expect("events")
                        .iter()
                        .any(|event| event.starts_with("report:"))
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn configuration_startup_acknowledged_policy_rejection_allows_fresh_operational_budget() {
        let (mut runtime, gateway, boundary, events) = runtime();
        runtime.session.startup_failures.store(4, Ordering::Relaxed);
        runtime
            .session
            .reject_startup(&runtime.snapshot, "invalid authored policy")
            .await
            .expect("gateway acknowledged rejection");
        assert_eq!(runtime.session.startup_failures.load(Ordering::Relaxed), 0);
        let fault = fault_startup(
            &mut runtime,
            &gateway,
            StartupCall::Provider,
            StartupFault::Status(tonic::Code::Unavailable),
            4,
        );
        runtime
            .session
            .prepare_startup(
                &bootstrap(ImagePolicyDiscovery::Missing),
                &runtime.connector,
            )
            .await
            .expect("repair may survive a fresh operational budget");
        runtime
            .start_workload(
                Box::new(Ready { boundary }),
                &bootstrap(ImagePolicyDiscovery::Missing),
            )
            .await
            .expect("one launch succeeds");
        assert_eq!(fault.calls.load(Ordering::Relaxed), 5);
        assert!(!runtime.session.startup_pending);
        assert_eq!(
            events
                .lock()
                .expect("events")
                .iter()
                .filter(|event| *event == "start")
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn configuration_live_reports_keep_recovery_beyond_startup_budget() {
        let (mut runtime, gateway, _, _) = runtime();
        let fault = fault_startup(
            &mut runtime,
            &gateway,
            StartupCall::Acceptance,
            StartupFault::Status(tonic::Code::Unavailable),
            6,
        );
        runtime.session.startup_pending = false;
        runtime
            .session
            .report(
                &runtime.snapshot,
                ConfigurationAdmissionState::Accepted,
                false,
                "",
            )
            .await
            .expect("live reconciliation retains retry behavior");
        assert_eq!(fault.calls.load(Ordering::Relaxed), 7);
        assert_eq!(runtime.session.startup_failures.load(Ordering::Relaxed), 0);
    }

    #[tonic::async_trait]
    impl ConfigurationGateway for Gateway {
        async fn snapshot(&self, _issue: bool) -> Result<SettingsPollResult> {
            let snapshot = self.snapshot.lock().expect("snapshot lock").clone();
            if self.record_polls.load(Ordering::Relaxed) {
                self.events
                    .lock()
                    .expect("events lock")
                    .push(format!("poll:{}", snapshot.configuration_snapshot));
            }
            Ok(snapshot)
        }

        async fn provider(&self) -> Result<ProviderEnvironmentResult> {
            Ok(provider(self.provider_revision.load(Ordering::Relaxed)))
        }

        async fn sync_policy(
            &self,
            policy: &openshell_core::proto::SandboxPolicy,
            _workspace: &str,
        ) -> Result<()> {
            self.events.lock().expect("events lock").push("sync".into());
            let sync_error = self.sync_error.lock().expect("sync error lock").take();
            if let Some(code) = sync_error {
                return Err(
                    openshell_core::grpc_client::grpc_status_error(tonic::Status::new(
                        code,
                        "credential_binding service-b rejected: private-test-payload",
                    ))
                    .wrap_err("failed to sync policy to server"),
                );
            }
            let repair = self.sync_repair.lock().expect("repair lock").take();
            if let Some(repair) = repair {
                self.snapshot.lock().expect("snapshot lock").policy = Some(repair);
                return Err(openshell_core::grpc_client::grpc_status_error(
                    tonic::Status::aborted("sandbox changed during image backfill"),
                ));
            }
            self.snapshot.lock().expect("snapshot lock").policy = Some(policy.clone());
            Ok(())
        }

        async fn report(
            &self,
            admission: &SandboxConfigurationAdmission,
            _expected_instance: &str,
            _expected_boundary: &str,
        ) -> Result<openshell_core::proto::ReportSandboxConfigurationResponse> {
            let state =
                ConfigurationAdmissionState::try_from(admission.state).expect("valid state");
            self.events.lock().expect("events lock").push(format!(
                "report:{state:?}:{}",
                admission.activation_confirmed
            ));
            self.report_attempts
                .lock()
                .expect("attempts lock")
                .push(admission.clone());
            let fault = {
                let mut faults = self.report_faults.lock().expect("faults lock");
                if state == ConfigurationAdmissionState::Accepted
                    && faults
                        .front()
                        .is_some_and(|fault| fault.confirmed == admission.activation_confirmed)
                {
                    faults.pop_front()
                } else {
                    None
                }
            };
            if let Some(fault) = fault {
                if let Some(replacement) = fault.replacement {
                    self.provider_revision
                        .store(replacement.provider_env_revision, Ordering::Relaxed);
                    *self.snapshot.lock().expect("snapshot lock") = replacement;
                }
                self.events
                    .lock()
                    .expect("events lock")
                    .push(format!("fault:{:?}", fault.code));
                return Err(openshell_core::grpc_client::grpc_status_error(
                    tonic::Status::new(fault.code, fault.message),
                ));
            }
            if state == ConfigurationAdmissionState::Accepted
                && self.reject_authorization.load(Ordering::Relaxed)
            {
                return Err(openshell_core::grpc_client::grpc_status_error(
                    tonic::Status::failed_precondition("registration was replaced"),
                ));
            }
            Ok(openshell_core::proto::ReportSandboxConfigurationResponse {
                control_registration_grant: "test-registration-grant".into(),
                registration_revision: 3,
            })
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

    struct Boundary {
        identity: Mutex<ConfigurationActivationIdentity>,
        installed: Mutex<Option<ConfigurationRevision>>,
        ready: watch::Sender<bool>,
        wrong_commit: AtomicBool,
        credentials: ProviderCredentialState,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[tonic::async_trait]
    impl BoundaryConfiguration for Boundary {
        fn identity(&self) -> ConfigurationActivationIdentity {
            self.identity.lock().expect("identity lock").clone()
        }

        fn readiness(&self) -> watch::Receiver<bool> {
            self.ready.subscribe()
        }

        async fn snapshot(
            &self,
        ) -> std::result::Result<BoundaryConfigurationSnapshot, BackendError> {
            Ok(BoundaryConfigurationSnapshot {
                identity: self.identity(),
                installed: self.installed.lock().expect("installation lock").clone(),
                active: *self.ready.borrow(),
            })
        }

        async fn prepare(
            &self,
            expected: Option<ConfigurationRevision>,
            candidate: ConfigurationRevision,
            _child_env: HashMap<String, String>,
        ) -> std::result::Result<PreparedBoundaryConfiguration, BackendError> {
            self.events.lock().expect("events lock").push(format!(
                "prepare:credentials:{}",
                self.credentials.snapshot().revision
            ));
            self.ready.send_replace(false);
            assert_eq!(*self.installed.lock().expect("installation lock"), expected);
            Ok(PreparedBoundaryConfiguration {
                identity: self.identity(),
                transition_id: "transition-1".into(),
                expected,
                configuration: candidate,
            })
        }

        async fn commit(
            &self,
            prepared: &PreparedBoundaryConfiguration,
        ) -> std::result::Result<InstalledBoundaryConfiguration, BackendError> {
            self.events.lock().expect("events lock").push(format!(
                "commit:credentials:{}",
                self.credentials.snapshot().revision
            ));
            assert!(!*self.ready.borrow());
            *self.installed.lock().expect("installation lock") =
                Some(prepared.configuration.clone());
            let mut installed = InstalledBoundaryConfiguration {
                identity: prepared.identity.clone(),
                transition_id: prepared.transition_id.clone(),
                configuration: prepared.configuration.clone(),
            };
            if self.wrong_commit.load(Ordering::Relaxed) {
                installed.configuration.provider_env_revision += 1;
            }
            Ok(installed)
        }

        async fn release(
            &self,
            installed: &InstalledBoundaryConfiguration,
        ) -> std::result::Result<ActivatedBoundaryConfiguration, BackendError> {
            self.events
                .lock()
                .expect("events lock")
                .push("release".into());
            self.ready.send_replace(true);
            Ok(ActivatedBoundaryConfiguration {
                identity: installed.identity.clone(),
                transition_id: installed.transition_id.clone(),
                configuration: installed.configuration.clone(),
            })
        }

        async fn abort(
            &self,
            _prepared: &PreparedBoundaryConfiguration,
        ) -> std::result::Result<(), BackendError> {
            self.ready.send_replace(false);
            Ok(())
        }

        async fn quiesce(&self) -> std::result::Result<(), BackendError> {
            self.events
                .lock()
                .expect("events lock")
                .push("quiesce".into());
            self.ready.send_replace(false);
            Ok(())
        }

        async fn refresh_registration(
            &self,
            _grant: openshell_core::jwt::SecretJwt,
            _revision: u64,
        ) -> std::result::Result<(), BackendError> {
            Ok(())
        }
    }

    type RuntimeFixture = (
        RuntimeConfiguration,
        Arc<Gateway>,
        Arc<Boundary>,
        Arc<Mutex<Vec<String>>>,
    );

    fn runtime() -> RuntimeFixture {
        let initial = snapshot(1);
        let (_, _, credentials) =
            prepare_components(&initial, provider(1)).expect("initial components");
        let events = Arc::new(Mutex::new(Vec::new()));
        let gateway = Arc::new(Gateway {
            snapshot: Mutex::new(snapshot(2)),
            provider_revision: AtomicU64::new(2),
            reject_authorization: AtomicBool::new(false),
            report_faults: Mutex::new(std::collections::VecDeque::new()),
            report_attempts: Mutex::new(Vec::new()),
            record_polls: AtomicBool::new(false),
            sync_repair: Mutex::new(None),
            sync_error: Mutex::new(None),
            events: events.clone(),
        });
        let (ready, _) = watch::channel(true);
        let boundary = Arc::new(Boundary {
            identity: Mutex::new(identity()),
            installed: Mutex::new(Some(revision(&initial))),
            ready,
            wrong_commit: AtomicBool::new(false),
            credentials: credentials.clone(),
            events: events.clone(),
        });
        let (readiness, _) = watch::channel(true);
        let (workspace, _) = watch::channel(String::new());
        let runtime = RuntimeConfiguration {
            session: ConfigurationSession {
                gateway: gateway.clone(),
                instance_id: "control-1".into(),
                runtime_generation: "runtime-1".into(),
                identity: Some(identity()),
                // This fixture starts with an installed active generation.
                startup_pending: false,
                startup_failures: AtomicU32::new(0),
            },
            boundary: boundary.clone(),
            snapshot: initial.clone(),
            engine: Arc::new(
                OpaEngine::from_proto(initial.policy.as_ref().expect("policy"))
                    .expect("initial engine"),
            ),
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
        (runtime, gateway, boundary, events)
    }

    struct Ready {
        boundary: Arc<Boundary>,
    }

    #[tonic::async_trait]
    impl openshell_isolation_interface::contract::ReadyBoundary for Ready {
        fn configuration(&self) -> Arc<dyn BoundaryConfiguration> {
            self.boundary.clone()
        }

        async fn update_startup_policy(
            &mut self,
            _policy: SandboxPolicy,
        ) -> std::result::Result<(), BackendError> {
            assert!(
                !*self.boundary.ready.borrow(),
                "policy replacement must be held"
            );
            self.boundary
                .events
                .lock()
                .expect("events lock")
                .push("startup-policy".into());
            Ok(())
        }

        async fn start_agent(
            self: Box<Self>,
        ) -> std::result::Result<Box<dyn RunningBoundary>, BackendError> {
            assert!(*self.boundary.ready.borrow(), "start requires release");
            self.boundary
                .events
                .lock()
                .expect("events lock")
                .push("start".into());
            Ok(Box::new(Running))
        }
    }

    struct Running;

    #[tonic::async_trait]
    impl RunningBoundary for Running {
        fn agent(&self) -> Arc<dyn openshell_isolation_interface::contract::BoundaryProcess> {
            panic!("activation tests do not inspect the returned process")
        }

        fn exec(&self) -> Arc<dyn openshell_isolation_interface::contract::BoundaryExec> {
            panic!("activation tests do not open exec")
        }

        fn loopback_connector(
            &self,
        ) -> Arc<dyn openshell_isolation_interface::contract::BoundaryLoopbackConnector> {
            panic!("activation tests do not open loopback")
        }

        async fn terminate(&self) -> std::result::Result<(), BackendError> {
            Ok(())
        }
    }

    fn supersede_report(gateway: &Gateway, confirmed: bool, reason: &'static str) {
        gateway.record_polls.store(true, Ordering::Relaxed);
        gateway
            .report_faults
            .lock()
            .expect("faults lock")
            .push_back(ReportFault {
                confirmed,
                code: tonic::Code::Aborted,
                message: reason,
                replacement: Some(snapshot(3)),
            });
    }

    fn assert_recovery_order(events: &[String]) {
        let aborted = events
            .iter()
            .position(|event| event == "fault:Aborted")
            .expect("obsolete report");
        let quiesced = events
            .iter()
            .enumerate()
            .skip(aborted + 1)
            .find(|(_, event)| *event == "quiesce")
            .map(|(index, _)| index)
            .expect("held after obsolete report");
        let polled = events
            .iter()
            .enumerate()
            .skip(aborted + 1)
            .find(|(_, event)| event.starts_with("poll:"))
            .map(|(index, _)| index)
            .expect("replacement poll");
        assert!(
            quiesced < polled,
            "must hold before fetching replacement: {events:?}"
        );
    }

    #[tokio::test]
    async fn configuration_activation_startup_sync_validation_waits_for_operator_repair() {
        const IMAGE_POLICY: &str = include_str!(
            "../../../e2e/rust/fixtures/configuration-activation/policy-invalid-binding.yaml"
        );
        let parsed = openshell_policy::parse_sandbox_policy(IMAGE_POLICY)
            .expect("unresolved provider binding is syntactically valid policy");
        assert!(parsed.network_policies.values().any(|rule| {
            rule.endpoints.iter().any(|endpoint| {
                endpoint
                    .credential_binding
                    .as_ref()
                    .is_some_and(|binding| binding.provider == "service-b")
            })
        }));
        for code in [
            tonic::Code::InvalidArgument,
            tonic::Code::FailedPrecondition,
        ] {
            let (mut runtime, gateway, boundary, events) = runtime();
            gateway.snapshot.lock().expect("snapshot lock").policy = None;
            *gateway.sync_error.lock().expect("sync error lock") = Some(code);
            boundary.ready.send_replace(false);
            let bootstrap = bootstrap(ImagePolicyDiscovery::Present {
                yaml: IMAGE_POLICY.into(),
            });
            let prepared = {
                let preparation = runtime
                    .session
                    .prepare_startup(&bootstrap, &runtime.connector);
                tokio::pin!(preparation);
                let rejection = async {
                    loop {
                        if events
                            .lock()
                            .expect("events lock")
                            .iter()
                            .any(|event| event == "report:Rejected:false")
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                };
                tokio::select! {
                    result = &mut preparation => panic!("sync validation returned before repair: {}", result.is_ok()),
                    result = tokio::time::timeout(Duration::from_secs(1), rejection) => result.expect("rejection is visible"),
                }
                {
                    let events = events.lock().expect("events lock");
                    assert_eq!(*events, ["sync", "report:Rejected:false"]);
                    assert!(
                        !*boundary.ready.borrow(),
                        "rejected image never releases the workload"
                    );
                }
                {
                    let reports = gateway.report_attempts.lock().expect("attempts lock");
                    assert_eq!(reports.len(), 1);
                    assert!(
                        !reports[0].error.contains("private-test-payload"),
                        "remote validation payload must not enter diagnostics"
                    );
                }
                gateway.snapshot.lock().expect("snapshot lock").policy =
                    Some(openshell_policy::restrictive_default_policy());
                tokio::time::timeout(Duration::from_secs(3), preparation)
                    .await
                    .expect("operator repair is polled")
                    .expect("replacement prepares")
            };
            runtime.snapshot = prepared.snapshot;
            runtime.engine = Arc::new(prepared.engine);
            runtime.credentials.install_prepared(&prepared.credentials);
            let _running = runtime
                .start_workload(Box::new(Ready { boundary }), &bootstrap)
                .await
                .expect("repaired configuration starts");
            let events = events.lock().expect("events lock");
            assert_eq!(events.iter().filter(|event| *event == "start").count(), 1);
            assert_eq!(events.iter().filter(|event| *event == "release").count(), 1);
        }
    }

    #[tokio::test]
    async fn configuration_activation_startup_sync_authentication_failure_remains_fatal() {
        for code in [tonic::Code::Unauthenticated, tonic::Code::PermissionDenied] {
            let (runtime, gateway, _, events) = runtime();
            gateway.snapshot.lock().expect("snapshot lock").policy = None;
            *gateway.sync_error.lock().expect("sync error lock") = Some(code);
            let error = tokio::time::timeout(
                Duration::from_secs(1),
                runtime.session.prepare_startup(
                    &bootstrap(ImagePolicyDiscovery::Missing),
                    &runtime.connector,
                ),
            )
            .await
            .expect("auth failure must not retry")
            .err()
            .expect("auth failure is terminal");
            assert_eq!(grpc_status_code(&error), Some(code));
            assert_eq!(*events.lock().expect("events lock"), ["sync"]);
        }
    }

    #[tokio::test]
    async fn configuration_activation_startup_sync_unavailable_repolls() {
        let (runtime, gateway, _, events) = runtime();
        gateway.snapshot.lock().expect("snapshot lock").policy = None;
        *gateway.sync_error.lock().expect("sync error lock") = Some(tonic::Code::Unavailable);
        let prepared = tokio::time::timeout(
            Duration::from_secs(3),
            runtime.session.prepare_startup(
                &bootstrap(ImagePolicyDiscovery::Missing),
                &runtime.connector,
            ),
        )
        .await
        .expect("transport retry returns to polling")
        .expect("subsequent sync succeeds");
        assert!(prepared.snapshot.policy.is_some());
        assert_eq!(*events.lock().expect("events lock"), ["sync", "sync"]);
    }

    #[tokio::test]
    async fn configuration_activation_startup_image_sync_conflict_reads_operator_repair() {
        let (runtime, gateway, _, events) = runtime();
        gateway.snapshot.lock().expect("snapshot lock").policy = None;
        let mut repair = openshell_policy::restrictive_default_policy();
        repair
            .filesystem
            .as_mut()
            .expect("filesystem policy")
            .read_only
            .push("/operator-repair".into());
        *gateway.sync_repair.lock().expect("repair lock") = Some(repair.clone());
        let prepared = tokio::time::timeout(
            Duration::from_secs(3),
            runtime.session.prepare_startup(
                &bootstrap(ImagePolicyDiscovery::Missing),
                &runtime.connector,
            ),
        )
        .await
        .expect("image CAS conflict returns to polling")
        .expect("operator repair prepares");
        assert_eq!(prepared.snapshot.policy, Some(repair));
        assert_eq!(
            events
                .lock()
                .expect("events lock")
                .iter()
                .filter(|event| *event == "sync")
                .count(),
            1,
            "the stale image is not resubmitted"
        );
    }

    #[tokio::test]
    async fn configuration_activation_startup_obsolete_delivery_repairs_before_one_launch() {
        for reason in [
            "configuration delivery changed; poll and install again",
            "gateway policy services changed; poll and install again",
        ] {
            let (mut runtime, gateway, boundary, events) = runtime();
            supersede_report(&gateway, false, reason);
            let ready = Box::new(Ready {
                boundary: boundary.clone(),
            });
            let _running = tokio::time::timeout(
                Duration::from_secs(1),
                runtime.start_workload(ready, &bootstrap(ImagePolicyDiscovery::Missing)),
            )
            .await
            .expect("obsolete ticket must return to polling")
            .expect("replacement starts");
            let events = events.lock().expect("events lock");
            assert_recovery_order(&events);
            assert_eq!(events.iter().filter(|event| *event == "release").count(), 1);
            assert_eq!(events.iter().filter(|event| *event == "start").count(), 1);
            assert!(events.iter().any(|event| event == "startup-policy"));
            assert_eq!(runtime.snapshot.configuration_snapshot, "snapshot-3");
            assert!(*runtime.readiness.borrow());
        }
    }

    #[tokio::test]
    async fn configuration_activation_startup_obsolete_confirmation_keeps_one_launch() {
        let (mut runtime, gateway, boundary, events) = runtime();
        supersede_report(
            &gateway,
            true,
            "configuration delivery changed; poll and install again",
        );
        let _running = tokio::time::timeout(
            Duration::from_secs(1),
            runtime.start_workload(
                Box::new(Ready { boundary }),
                &bootstrap(ImagePolicyDiscovery::Missing),
            ),
        )
        .await
        .expect("confirmation must return to polling")
        .expect("replacement confirms");
        let events = events.lock().expect("events lock");
        assert_recovery_order(&events);
        assert_eq!(events.iter().filter(|event| *event == "start").count(), 1);
        assert_eq!(events.iter().filter(|event| *event == "release").count(), 2);
        assert!(!events.iter().any(|event| event == "startup-policy"));
        assert_eq!(runtime.snapshot.configuration_snapshot, "snapshot-3");
        assert!(*runtime.readiness.borrow());
    }

    #[tokio::test]
    async fn configuration_activation_live_obsolete_delivery_repolls_while_held() {
        for confirmed in [false, true] {
            let (mut runtime, gateway, boundary, events) = runtime();
            supersede_report(
                &gateway,
                confirmed,
                "configuration delivery changed; poll and install again",
            );
            tokio::time::timeout(
                Duration::from_secs(1),
                runtime.reconcile_snapshot(snapshot(2)),
            )
            .await
            .expect("obsolete report must not retry forever")
            .expect("replacement activates");
            let events = events.lock().expect("events lock");
            assert_recovery_order(&events);
            assert_eq!(
                events.iter().filter(|event| *event == "release").count(),
                if confirmed { 2 } else { 1 }
            );
            assert_eq!(runtime.credentials.revision(), 3);
            assert_eq!(runtime.snapshot.configuration_snapshot, "snapshot-3");
            assert!(*boundary.ready.borrow());
            assert!(*runtime.readiness.borrow());
        }
    }

    #[tokio::test]
    async fn configuration_activation_unavailable_retries_the_same_admission() {
        let (mut runtime, gateway, _, events) = runtime();
        gateway
            .report_faults
            .lock()
            .expect("faults lock")
            .push_back(ReportFault {
                confirmed: false,
                code: tonic::Code::Unavailable,
                message: "transport response lost",
                replacement: None,
            });
        tokio::time::timeout(
            Duration::from_secs(3),
            runtime.reconcile_snapshot(snapshot(2)),
        )
        .await
        .expect("transport retry completes")
        .expect("activation");
        let attempts = gateway.report_attempts.lock().expect("attempts lock");
        assert_eq!(attempts.len(), 3);
        assert_eq!(
            attempts[0], attempts[1],
            "lost acknowledgement retries exact immutable admission"
        );
        let events = events.lock().expect("events lock");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("prepare:"))
                .count(),
            1
        );
        assert_eq!(events.iter().filter(|event| *event == "release").count(), 1);
        assert_eq!(runtime.snapshot.configuration_snapshot, "snapshot-2");
    }

    #[tokio::test]
    async fn configuration_activation_startup_replaced_registration_never_launches() {
        let (mut runtime, gateway, boundary, events) = runtime();
        gateway.reject_authorization.store(true, Ordering::Relaxed);
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                runtime.start_workload(
                    Box::new(Ready {
                        boundary: boundary.clone()
                    }),
                    &bootstrap(ImagePolicyDiscovery::Missing)
                ),
            )
            .await
            .expect("identity replacement is terminal")
            .is_err()
        );
        assert!(!*boundary.ready.borrow());
        assert!(
            !events
                .lock()
                .expect("events lock")
                .iter()
                .any(|event| event == "start" || event == "release")
        );
    }

    #[tokio::test]
    async fn configuration_activation_publishes_credentials_only_while_held_and_reports_release() {
        let (mut runtime, _, boundary, events) = runtime();
        runtime
            .reconcile_snapshot(snapshot(2))
            .await
            .expect("activation");
        assert_eq!(
            *events.lock().expect("events lock"),
            [
                "prepare:credentials:1",
                "commit:credentials:2",
                "report:Accepted:false",
                "release",
                "report:Accepted:true"
            ]
        );
        assert_eq!(runtime.credentials.snapshot().revision, 2);
        assert_eq!(runtime.engine.current_generation(), 1);
        assert!(*runtime.readiness.borrow());
        assert!(*boundary.ready.borrow());
        runtime
            .reconcile_snapshot(snapshot(2))
            .await
            .expect("unchanged activation");
        assert_eq!(
            events.lock().expect("events lock").len(),
            5,
            "identical delivery must not release or acknowledge twice"
        );
    }

    #[tokio::test]
    async fn configuration_activation_resets_endpoint_inventory_after_matching_publication() {
        use openshell_core::endpoint_status::EndpointStatusCommand;

        let (mut runtime, _, _, _) = runtime();
        let (sender, mut receiver) = openshell_core::endpoint_status::endpoint_status_channel();
        runtime.endpoint_observation_tx = Some(sender);

        runtime
            .reconcile_snapshot(snapshot(2))
            .await
            .expect("activation");
        let EndpointStatusCommand::Reset { config_version, .. } =
            receiver.try_recv().expect("installed inventory reset")
        else {
            panic!("configuration installation must reset the inventory");
        };
        assert_eq!(config_version.policy_hash, "policy-2");
        assert_eq!(config_version.provider_env_revision, 2);
        assert_eq!(runtime.credentials.snapshot().revision, 2);
        assert_eq!(runtime.snapshot.policy_hash, config_version.policy_hash);
        assert_eq!(runtime.engine.current_generation(), 1);

        runtime
            .reconcile_snapshot(snapshot(2))
            .await
            .expect("unchanged activation");
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn configuration_activation_rejected_pair_preserves_endpoint_inventory() {
        let (mut runtime, gateway, _, _) = runtime();
        let (sender, mut receiver) = openshell_core::endpoint_status::endpoint_status_channel();
        runtime.endpoint_observation_tx = Some(sender);
        gateway.provider_revision.store(3, Ordering::Relaxed);
        let mut candidate = snapshot(2);
        candidate.policy_validation_failure_mode =
            openshell_core::PolicyValidationFailureMode::RetainLastValid;

        runtime
            .reconcile_snapshot(candidate)
            .await
            .expect("repairable rejection");

        assert_eq!(runtime.snapshot.policy_hash, "policy-1");
        assert_eq!(runtime.credentials.snapshot().revision, 1);
        assert_eq!(runtime.engine.current_generation(), 0);
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn configuration_activation_provider_mismatch_preserves_the_accepted_generation() {
        let (mut runtime, gateway, boundary, events) = runtime();
        gateway.provider_revision.store(3, Ordering::Relaxed);
        let mut candidate = snapshot(2);
        candidate.policy_validation_failure_mode =
            openshell_core::PolicyValidationFailureMode::RetainLastValid;
        runtime
            .reconcile_snapshot(candidate)
            .await
            .expect("repairable rejection");
        assert_eq!(runtime.credentials.snapshot().revision, 1);
        assert_eq!(runtime.engine.current_generation(), 0);
        assert!(*boundary.ready.borrow());
        assert!(*runtime.readiness.borrow());
        assert_eq!(
            *events.lock().expect("events lock"),
            ["report:Rejected:false"]
        );
    }

    #[tokio::test]
    async fn configuration_activation_rejected_candidate_stays_held_until_repair() {
        let (mut runtime, gateway, boundary, events) = runtime();
        gateway.provider_revision.store(3, Ordering::Relaxed);
        runtime
            .reconcile_snapshot(snapshot(2))
            .await
            .expect("repairable rejection");
        assert_eq!(runtime.credentials.snapshot().revision, 1);
        assert!(!*boundary.ready.borrow());
        assert!(!*runtime.readiness.borrow());
        assert_eq!(
            *events.lock().expect("events lock"),
            ["quiesce", "report:Rejected:false"]
        );
        gateway.provider_revision.store(2, Ordering::Relaxed);
        runtime
            .reconcile_snapshot(snapshot(2))
            .await
            .expect("repair");
        assert_eq!(runtime.credentials.snapshot().revision, 2);
        assert!(*runtime.readiness.borrow());
    }

    #[tokio::test]
    async fn configuration_activation_wrong_installation_ack_never_releases() {
        let (mut runtime, _, boundary, events) = runtime();
        boundary.wrong_commit.store(true, Ordering::Relaxed);
        assert!(runtime.reconcile_snapshot(snapshot(2)).await.is_err());
        assert!(!*runtime.readiness.borrow());
        assert!(!*boundary.ready.borrow());
        assert_eq!(
            *events.lock().expect("events lock"),
            ["prepare:credentials:1", "commit:credentials:2"]
        );
    }

    #[tokio::test]
    async fn configuration_activation_gateway_rejection_never_releases() {
        let (mut runtime, gateway, boundary, events) = runtime();
        gateway.reject_authorization.store(true, Ordering::Relaxed);
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                runtime.reconcile_snapshot(snapshot(2))
            )
            .await
            .expect("a replaced registration must not be retried indefinitely")
            .is_err()
        );
        assert!(!*runtime.readiness.borrow());
        assert!(!*boundary.ready.borrow());
        assert_eq!(
            *events.lock().expect("events lock"),
            [
                "prepare:credentials:1",
                "commit:credentials:2",
                "report:Accepted:false"
            ]
        );
    }

    #[tokio::test]
    async fn configuration_activation_new_boundary_incarnation_cannot_resume() {
        let (mut runtime, _, boundary, events) = runtime();
        boundary
            .identity
            .lock()
            .expect("identity lock")
            .boundary_instance_id = "boundary-2".into();
        boundary.ready.send_replace(false);
        assert!(runtime.reconcile_snapshot(snapshot(2)).await.is_err());
        assert!(events.lock().expect("events lock").is_empty());
        assert_eq!(runtime.credentials.snapshot().revision, 1);
    }

    #[tokio::test]
    async fn configuration_activation_reconnect_revalidates_the_existing_tuple() {
        let (mut runtime, gateway, boundary, events) = runtime();
        gateway.provider_revision.store(1, Ordering::Relaxed);
        boundary.ready.send_replace(false);
        runtime
            .reconcile_snapshot(snapshot(1))
            .await
            .expect("revalidation");
        assert_eq!(
            *events.lock().expect("events lock"),
            [
                "prepare:credentials:1",
                "commit:credentials:1",
                "report:Accepted:false",
                "release",
                "report:Accepted:true"
            ]
        );
        assert_eq!(
            runtime.engine.current_generation(),
            1,
            "reconnection must invalidate pre-reconnect policy guards"
        );
    }

    #[tokio::test]
    async fn configuration_activation_startup_waits_for_image_policy_repair_without_accepting() {
        let (runtime, gateway, _, events) = runtime();
        gateway.snapshot.lock().expect("snapshot lock").policy = None;
        let bootstrap = bootstrap(ImagePolicyDiscovery::Present {
            yaml: "[invalid policy".into(),
        });
        let preparation = runtime
            .session
            .prepare_startup(&bootstrap, &runtime.connector);
        tokio::pin!(preparation);
        let wait_for_rejection = async {
            loop {
                if events
                    .lock()
                    .expect("events lock")
                    .iter()
                    .any(|event| event == "report:Rejected:false")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        };
        tokio::select! {
            result = &mut preparation => panic!("invalid image was accepted: {}", result.is_ok()),
            result = tokio::time::timeout(Duration::from_secs(1), wait_for_rejection) => result.expect("rejection must become visible"),
        }
        gateway.snapshot.lock().expect("snapshot lock").policy =
            Some(openshell_policy::restrictive_default_policy());
        let prepared = tokio::time::timeout(Duration::from_secs(3), preparation)
            .await
            .expect("repair is retried")
            .expect("valid repaired candidate");
        assert_eq!(prepared.snapshot.provider_env_revision, 2);
        assert_eq!(
            *events.lock().expect("events lock"),
            ["report:Rejected:false"],
            "preparation alone must never acknowledge installation or authorize launch"
        );
    }

    #[tokio::test]
    async fn configuration_activation_missing_image_policy_installs_a_restrictive_default() {
        let (runtime, gateway, _, events) = runtime();
        gateway.snapshot.lock().expect("snapshot lock").policy = None;
        let prepared = runtime
            .session
            .prepare_startup(
                &bootstrap(ImagePolicyDiscovery::Missing),
                &runtime.connector,
            )
            .await
            .expect("restrictive candidate");
        let decision = prepared
            .engine
            .evaluate_network(&openshell_supervisor_network::opa::NetworkInput {
                host: "unconfigured.example".into(),
                port: 443,
                binary_path: "/usr/bin/curl".into(),
                binary_sha256: "test-binary".into(),
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            })
            .expect("evaluate default policy");
        assert!(!decision.allowed);
        assert_eq!(*events.lock().expect("events lock"), ["sync"]);
    }

    #[tokio::test]
    async fn configuration_activation_invalid_opa_candidate_keeps_previous_credentials() {
        for mode in [
            openshell_core::PolicyValidationFailureMode::FailClosed,
            openshell_core::PolicyValidationFailureMode::RetainLastValid,
        ] {
            let (mut runtime, _, boundary, events) = runtime();
            let mut candidate = snapshot(2);
            candidate.policy_validation_failure_mode = mode;
            candidate.policy.as_mut().expect("policy").landlock =
                Some(openshell_core::proto::LandlockPolicy {
                    compatibility: "invalid".into(),
                });
            runtime
                .reconcile_snapshot(candidate)
                .await
                .expect("repairable rejection");
            assert_eq!(runtime.credentials.snapshot().revision, 1);
            assert_eq!(
                *boundary.ready.borrow(),
                mode == openshell_core::PolicyValidationFailureMode::RetainLastValid
            );
            assert!(events.lock().expect("events lock").iter().all(|event| {
                !event.starts_with("prepare") && !event.starts_with("commit") && event != "release"
            }));
        }
    }

    #[test]
    fn configuration_activation_invalid_policy_never_prepares_credentials() {
        let mut invalid = snapshot(2);
        invalid.policy.as_mut().expect("policy").landlock =
            Some(openshell_core::proto::LandlockPolicy {
                compatibility: "invalid".into(),
            });
        assert!(prepare_components(&invalid, provider(2)).is_err());
        assert!(prepare_components(&snapshot(2), provider(3)).is_err());
    }

    #[test]
    fn configuration_activation_rejects_each_wrong_receipt_identity() {
        let prepared = PreparedBoundaryConfiguration {
            identity: identity(),
            transition_id: "transition-1".into(),
            expected: Some(revision(&snapshot(1))),
            configuration: revision(&snapshot(2)),
        };
        let installed = InstalledBoundaryConfiguration {
            identity: prepared.identity.clone(),
            transition_id: prepared.transition_id.clone(),
            configuration: prepared.configuration.clone(),
        };
        let mut candidates = Vec::new();
        let mut changed = installed.clone();
        changed.configuration.config_revision += 1;
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.configuration.policy_version += 1;
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.configuration.policy_hash.push('x');
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.configuration.policy_source += 1;
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.configuration.provider_env_revision += 1;
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.identity.runtime_generation.push('x');
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.identity.boundary_session_id.push('x');
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.identity.supervisor_instance_id.push('x');
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.identity.boundary_instance_id.push('x');
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.identity.registration_revision += 1;
        candidates.push(changed);
        let mut changed = installed.clone();
        changed.transition_id.push('x');
        candidates.push(changed);
        for changed in candidates {
            assert!(validate_installation(&changed, &prepared).is_err());
        }
        validate_installation(&installed, &prepared).expect("matching receipt");
    }
}
