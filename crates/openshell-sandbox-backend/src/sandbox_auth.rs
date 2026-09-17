// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transport-neutral authentication for `OpenShell` Sandbox Protocol connections.

use std::sync::Mutex;

use openshell_core::configuration::ConfigurationActivationIdentity;
use openshell_core::jwt::{
    AuthenticatedSandboxSession, CredentialEpoch, SandboxId, SessionJwtError, SessionJwtVerifier,
};
use openshell_core::sandbox_generation::SandboxGenerationId;
use tonic::metadata::MetadataMap;
use uuid::Uuid;

/// Server-local identity assigned after a byte stream completes TLS.
///
/// It cannot be supplied by a compute driver or workload. Protocol handlers use
/// it to bind authenticated requests to the connection that performed attach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SandboxConnectionId(Uuid);

impl SandboxConnectionId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SandboxConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Principal returned only after strict bearer validation and identity binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxProtocolPrincipal {
    connection_id: SandboxConnectionId,
    session: AuthenticatedSandboxSession,
}

impl SandboxProtocolPrincipal {
    #[must_use]
    pub const fn connection_id(&self) -> SandboxConnectionId {
        self.connection_id
    }

    #[must_use]
    pub const fn session(&self) -> &AuthenticatedSandboxSession {
        &self.session
    }
}

/// Validates Sandbox Protocol metadata without depending on its byte transport.
pub struct SandboxProtocolAuthenticator {
    verifier: SessionJwtVerifier,
    expected_sandbox_id: SandboxId,
    expected_runtime_generation: SandboxGenerationId,
    expected_auth_epoch: CredentialEpoch,
}

impl std::fmt::Debug for SandboxProtocolAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxProtocolAuthenticator")
            .field("verifier", &self.verifier)
            .field("expected_sandbox_id", &self.expected_sandbox_id)
            .field(
                "expected_runtime_generation",
                &self.expected_runtime_generation,
            )
            .field("expected_auth_epoch", &self.expected_auth_epoch)
            .finish()
    }
}

impl SandboxProtocolAuthenticator {
    #[must_use]
    pub const fn new(
        verifier: SessionJwtVerifier,
        expected_sandbox_id: SandboxId,
        expected_runtime_generation: SandboxGenerationId,
        expected_auth_epoch: CredentialEpoch,
    ) -> Self {
        Self {
            verifier,
            expected_sandbox_id,
            expected_runtime_generation,
            expected_auth_epoch,
        }
    }

    pub fn authenticate(
        &self,
        connection_id: SandboxConnectionId,
        metadata: &MetadataMap,
    ) -> Result<SandboxProtocolPrincipal, SandboxAuthError> {
        let mut values = metadata.get_all("authorization").iter();
        let value = values.next().ok_or(SandboxAuthError::MissingBearer)?;
        if values.next().is_some() {
            return Err(SandboxAuthError::DuplicateBearer);
        }
        let value = value
            .to_str()
            .map_err(|_| SandboxAuthError::InvalidBearer)?;
        let token = value
            .strip_prefix("Bearer ")
            .filter(|token| !token.is_empty() && !token.chars().any(char::is_whitespace))
            .ok_or(SandboxAuthError::InvalidBearer)?;
        let session = self.verifier.verify(token)?;
        if session.sandbox_id != self.expected_sandbox_id {
            return Err(SandboxAuthError::WrongSandbox);
        }
        if session.runtime_generation != self.expected_runtime_generation {
            return Err(SandboxAuthError::WrongRuntimeGeneration);
        }
        if session.auth_epoch != self.expected_auth_epoch {
            return Err(SandboxAuthError::StaleCredentialEpoch);
        }
        Ok(SandboxProtocolPrincipal {
            connection_id,
            session,
        })
    }

    /// Verify the gateway's explicit registration grant against local runtime facts.
    ///
    /// The ordinary Sandbox Protocol bearer proves runtime membership only.
    /// This separate grant authorizes a particular control process and boundary
    /// incarnation without changing the immutable credential revocation epoch.
    pub fn verify_control_registration(
        &self,
        raw: &str,
        expected: &ConfigurationActivationIdentity,
    ) -> Result<VerifiedControlRegistration, SandboxAuthError> {
        expected
            .validate()
            .map_err(|_| SandboxAuthError::InvalidRegistration)?;
        let authenticated = self.verifier.verify_control_registration(raw)?;
        let grant = authenticated.grant;
        if grant.runtime_identity.sandbox_id != self.expected_sandbox_id
            || grant.runtime_identity.runtime_generation != self.expected_runtime_generation
            || grant.runtime_identity.auth_epoch != self.expected_auth_epoch
            || grant.runtime_identity.runtime_generation.as_str() != expected.runtime_generation
            || grant.supervisor_instance_id.to_string() != expected.supervisor_instance_id
            || grant.boundary_session_id.to_string() != expected.boundary_session_id
            || grant.boundary_instance_id.to_string() != expected.boundary_instance_id
            || grant.registration_revision != expected.registration_revision
        {
            return Err(SandboxAuthError::InvalidRegistration);
        }
        Ok(VerifiedControlRegistration {
            identity: expected.clone(),
        })
    }
}

/// Registration minted only after signature and local-runtime verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedControlRegistration {
    identity: ConfigurationActivationIdentity,
}

impl VerifiedControlRegistration {
    /// Exact signed identity authorized for attachment.
    #[must_use]
    pub fn identity(&self) -> &ConfigurationActivationIdentity {
        &self.identity
    }
}

/// Connections fenced by an authenticated registration replacement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistrationAttachment {
    /// Old physical connections that the caller must close.
    pub replaced_connections: Vec<SandboxConnectionId>,
    /// A newer registration displaced the previous control process.
    ///
    /// The caller must hold workloads before confirming or releasing its successor.
    pub replaced_registration: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveConnection {
    id: SandboxConnectionId,
    epoch: CredentialEpoch,
}

#[derive(Debug)]
struct ConnectionState {
    active: Option<ActiveConnection>,
    pending: Option<ActiveConnection>,
    highest_epoch: Option<CredentialEpoch>,
    registration: Option<ConfigurationActivationIdentity>,
    terminal: bool,
}

/// Enforces one active connection and monotonically increasing registration fences.
#[derive(Debug)]
pub struct SandboxConnectionRegistry {
    state: Mutex<ConnectionState>,
}

impl SandboxConnectionRegistry {
    #[must_use]
    pub fn new(
        _session_id: openshell_core::SandboxSessionId,
        _session_rotation: openshell_core::jwt::SessionRotation,
    ) -> Self {
        Self {
            state: Mutex::new(ConnectionState {
                active: None,
                pending: None,
                highest_epoch: None,
                registration: None,
                terminal: false,
            }),
        }
    }

    /// Stage a signed registration and fence any older registered control process.
    ///
    /// An equal revision may only replay the exact signed identity. A higher
    /// revision immediately invalidates the previous connection; configuration
    /// activation remains a separate hold/commit/release protocol.
    pub fn attach(
        &self,
        principal: &SandboxProtocolPrincipal,
        registration: &VerifiedControlRegistration,
    ) -> Result<RegistrationAttachment, SandboxAuthError> {
        let epoch = principal.session.auth_epoch;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal {
            return Err(SandboxAuthError::TerminalSession);
        }
        let candidate = registration.identity();
        let replaced_registration = match state.registration.as_ref() {
            Some(current) if candidate.registration_revision < current.registration_revision => {
                return Err(SandboxAuthError::StaleRegistration);
            }
            Some(current) if candidate.registration_revision == current.registration_revision => {
                if candidate != current {
                    return Err(SandboxAuthError::WrongSupervisorInstance);
                }
                false
            }
            Some(_) => true,
            None => false,
        };
        if state.highest_epoch.is_some_and(|highest| epoch < highest) {
            return Err(SandboxAuthError::StaleCredentialEpoch);
        }
        let mut result = RegistrationAttachment {
            replaced_registration,
            ..Default::default()
        };
        // A verified newer registration, not a larger bearer epoch or an
        // untrusted UUID, is the only authority for replacing a control process.
        if replaced_registration {
            if let Some(active) = state.active.take() {
                result.replaced_connections.push(active.id);
            }
            if let Some(pending) = state.pending.take() {
                result.replaced_connections.push(pending.id);
            }
        }
        state.registration = Some(candidate.clone());
        if let Some(active) = state.active
            && active.id == principal.connection_id
            && active.epoch == epoch
        {
            return Ok(result);
        }
        if let Some(pending) = state.pending {
            if pending.id == principal.connection_id && pending.epoch == epoch {
                return Ok(result);
            }
            if epoch < pending.epoch {
                return Err(SandboxAuthError::StaleCredentialEpoch);
            }
        }
        if let Some(pending) = state.pending {
            result.replaced_connections.push(pending.id);
        }
        state.highest_epoch = Some(epoch);
        state.pending = Some(ActiveConnection {
            id: principal.connection_id,
            epoch,
        });
        Ok(result)
    }

    /// Promote an attached, confirmed candidate to the active connection. The
    /// returned ID is the previously active connection, which may now be
    /// closed without creating an unsupervised interval.
    pub fn confirm(
        &self,
        principal: &SandboxProtocolPrincipal,
    ) -> Result<Option<SandboxConnectionId>, SandboxAuthError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal {
            return Err(SandboxAuthError::TerminalSession);
        }
        if state
            .active
            .is_some_and(|active| active.id == principal.connection_id)
        {
            return Ok(None);
        }
        let pending = state
            .pending
            .filter(|pending| pending.id == principal.connection_id)
            .ok_or(SandboxAuthError::ConnectionNotAttached)?;
        let replaced = state.active.map(|active| active.id);
        state.active = Some(pending);
        state.pending = None;
        Ok(replaced)
    }

    /// Confirm may run on either the active connection (an idempotent replay)
    /// or its staged replacement. Other operations require the active one.
    pub fn require_attached(
        &self,
        principal: &SandboxProtocolPrincipal,
    ) -> Result<(), SandboxAuthError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal {
            return Err(SandboxAuthError::TerminalSession);
        }
        if state
            .active
            .is_some_and(|active| active.id == principal.connection_id)
            || state
                .pending
                .is_some_and(|pending| pending.id == principal.connection_id)
        {
            Ok(())
        } else {
            Err(SandboxAuthError::ConnectionNotAttached)
        }
    }

    pub fn require_active(
        &self,
        principal: &SandboxProtocolPrincipal,
    ) -> Result<(), SandboxAuthError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal {
            return Err(SandboxAuthError::TerminalSession);
        }
        if state
            .active
            .is_none_or(|active| active.id != principal.connection_id)
        {
            return Err(SandboxAuthError::ConnectionNotAttached);
        }
        Ok(())
    }

    /// Remove a physical connection. Returns `true` only when it was the
    /// confirmed active connection and recovery must begin.
    pub fn disconnect(&self, connection_id: SandboxConnectionId) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let was_active = state
            .active
            .is_some_and(|active| active.id == connection_id);
        if was_active {
            state.active = None;
        }
        if state
            .pending
            .is_some_and(|pending| pending.id == connection_id)
        {
            state.pending = None;
        }
        was_active
    }

    pub fn mark_terminal(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.terminal = true;
        state.active = None;
        state.pending = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxAuthError {
    #[error("authorization metadata is missing")]
    MissingBearer,
    #[error("authorization metadata must occur exactly once")]
    DuplicateBearer,
    #[error("authorization metadata is not a valid bearer credential")]
    InvalidBearer,
    #[error("sandbox JWT validation failed: {0}")]
    Jwt(#[from] SessionJwtError),
    #[error("authenticated sandbox identity does not match this runtime")]
    WrongSandbox,
    #[error("authenticated runtime generation does not match this sandbox runtime")]
    WrongRuntimeGeneration,
    #[error("Sandbox Protocol credential epoch is stale")]
    StaleCredentialEpoch,
    #[error("sandbox runtime is already bound to another supervisor process")]
    WrongSupervisorInstance,
    #[error("control registration does not match the authenticated runtime")]
    InvalidRegistration,
    #[error("control registration revision is stale")]
    StaleRegistration,
    #[error("Sandbox Protocol connection has not completed attach")]
    ConnectionNotAttached,
    #[error("sandbox session is terminal")]
    TerminalSession,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openshell_core::jwt::{
        DEFAULT_SESSION_TOKEN_TTL, JwtClock, SandboxRuntimeIdentity, SessionJwtIssuer,
        SessionTokenProfile, SessionVerificationKey,
    };
    use openshell_core::sandbox_generation::SandboxGenerationId;
    use rcgen::{KeyPair, PKCS_ED25519};

    use super::*;

    #[derive(Debug)]
    struct FixedClock;

    impl JwtClock for FixedClock {
        fn now_unix_seconds(&self) -> i64 {
            1_900_000_000
        }
    }

    fn fixture(
        epoch: u64,
    ) -> (
        SandboxProtocolAuthenticator,
        openshell_core::jwt::MintedSessionToken,
    ) {
        let (authenticator, token, _) = fixture_with_issuer(epoch);
        (authenticator, token)
    }

    fn fixture_with_issuer(
        epoch: u64,
    ) -> (
        SandboxProtocolAuthenticator,
        openshell_core::jwt::MintedSessionToken,
        SessionJwtIssuer,
    ) {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("generate key");
        let public_key_pem = key.public_key_pem().into_bytes();
        let clock: Arc<dyn JwtClock> = Arc::new(FixedClock);
        let sandbox_id = SandboxId::parse("sandbox-a").expect("sandbox ID");
        let issuer = SessionJwtIssuer::from_ed25519_pem(
            key.serialize_pem().as_bytes(),
            "current",
            "test",
            DEFAULT_SESSION_TOKEN_TTL,
            clock.clone(),
        )
        .expect("issuer");
        let verifier = SessionJwtVerifier::new(
            "test",
            SessionTokenProfile::Sandbox,
            [SessionVerificationKey {
                key_id: "current".to_string(),
                public_key_pem,
            }],
            clock,
        )
        .expect("verifier");
        let token = issuer
            .mint_pair(&SandboxRuntimeIdentity {
                sandbox_id: sandbox_id.clone(),
                runtime_generation: SandboxGenerationId::parse("generation-1")
                    .expect("runtime generation"),
                auth_epoch: CredentialEpoch::new(epoch).expect("epoch"),
            })
            .expect("token pair")
            .sandbox;
        (
            SandboxProtocolAuthenticator::new(
                verifier,
                sandbox_id,
                SandboxGenerationId::parse("generation-1").expect("runtime generation"),
                CredentialEpoch::new(epoch).expect("epoch"),
            ),
            token,
            issuer,
        )
    }

    fn registry_for(_principal: &SandboxProtocolPrincipal) -> SandboxConnectionRegistry {
        SandboxConnectionRegistry::new(
            openshell_core::SandboxSessionId::new(),
            openshell_core::jwt::SessionRotation::new(1).expect("rotation"),
        )
    }

    fn metadata(token: &str) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            format!("Bearer {token}").parse().expect("metadata value"),
        );
        metadata
    }

    fn registration(
        instance: crate::boundary_protocol::SupervisorInstanceId,
        revision: u64,
    ) -> VerifiedControlRegistration {
        VerifiedControlRegistration {
            identity: ConfigurationActivationIdentity {
                runtime_generation: "generation-1".to_string(),
                boundary_session_id: "11111111-1111-4111-8111-111111111111".to_string(),
                supervisor_instance_id: instance.to_string(),
                boundary_instance_id: "22222222-2222-4222-8222-222222222222".to_string(),
                registration_revision: revision,
            },
        }
    }

    #[test]
    fn bearer_metadata_must_occur_exactly_once() {
        let (authenticator, token) = fixture(1);
        assert_eq!(
            authenticator.authenticate(SandboxConnectionId::new(), &MetadataMap::new()),
            Err(SandboxAuthError::MissingBearer)
        );
        let mut duplicate = metadata(token.token.expose_secret());
        duplicate.append(
            "authorization",
            format!("Bearer {}", token.token.expose_secret())
                .parse()
                .expect("metadata value"),
        );
        assert_eq!(
            authenticator.authenticate(SandboxConnectionId::new(), &duplicate),
            Err(SandboxAuthError::DuplicateBearer)
        );
    }

    #[test]
    fn configuration_activation_reconnect_reuses_registration_and_terminal_is_final() {
        let (first_authenticator, first_token) = fixture(1);
        let first_id = SandboxConnectionId::new();
        let first = first_authenticator
            .authenticate(first_id, &metadata(first_token.token.expose_secret()))
            .expect("first principal");
        let registry = registry_for(&first);
        let instance = crate::boundary_protocol::SupervisorInstanceId::new();
        let registration = registration(instance, 1);
        assert_eq!(
            registry.attach(&first, &registration),
            Ok(RegistrationAttachment::default())
        );
        assert_eq!(
            registry.attach(&first, &registration),
            Ok(RegistrationAttachment::default())
        );
        assert_eq!(registry.confirm(&first), Ok(None));
        assert_eq!(registry.confirm(&first), Ok(None));

        assert!(registry.disconnect(first_id));
        assert_eq!(
            registry.attach(&first, &registration),
            Ok(RegistrationAttachment::default())
        );
        assert_eq!(registry.confirm(&first), Ok(None));
        registry.mark_terminal();
        assert_eq!(
            registry.require_active(&first),
            Err(SandboxAuthError::TerminalSession)
        );
        assert_eq!(
            registry.attach(&first, &registration),
            Err(SandboxAuthError::TerminalSession)
        );
    }

    #[test]
    fn configuration_activation_equal_registration_cannot_replace_control_instance() {
        let (authenticator, token) = fixture(1);
        let first_id = SandboxConnectionId::new();
        let first = authenticator
            .authenticate(first_id, &metadata(token.token.expose_secret()))
            .expect("first principal");
        let registry = registry_for(&first);
        let first_instance = crate::boundary_protocol::SupervisorInstanceId::new();
        registry
            .attach(&first, &registration(first_instance, 1))
            .expect("attach first supervisor");
        registry.confirm(&first).expect("confirm first supervisor");
        assert!(registry.disconnect(first_id));

        let replacement_id = SandboxConnectionId::new();
        let replacement = authenticator
            .authenticate(replacement_id, &metadata(token.token.expose_secret()))
            .expect("replacement principal");
        assert_eq!(
            registry.attach(
                &replacement,
                &registration(crate::boundary_protocol::SupervisorInstanceId::new(), 1),
            ),
            Err(SandboxAuthError::WrongSupervisorInstance)
        );
        assert_eq!(
            registry.attach(&replacement, &registration(first_instance, 1)),
            Ok(RegistrationAttachment::default())
        );
    }

    #[test]
    fn configuration_activation_same_registration_transport_waits_for_confirmation() {
        let (first_authenticator, first_token) = fixture(1);
        let first_id = SandboxConnectionId::new();
        let first = first_authenticator
            .authenticate(first_id, &metadata(first_token.token.expose_secret()))
            .expect("first principal");
        let replacement_id = SandboxConnectionId::new();
        let replacement = first_authenticator
            .authenticate(replacement_id, &metadata(first_token.token.expose_secret()))
            .expect("replacement principal");
        let registry = registry_for(&first);
        let instance = crate::boundary_protocol::SupervisorInstanceId::new();
        registry
            .attach(&first, &registration(instance, 1))
            .expect("attach first");
        registry.confirm(&first).expect("confirm first");

        assert_eq!(
            registry.attach(&replacement, &registration(instance, 1)),
            Ok(RegistrationAttachment::default())
        );
        registry
            .require_active(&first)
            .expect("first remains active");
        assert_eq!(
            registry.require_active(&replacement),
            Err(SandboxAuthError::ConnectionNotAttached)
        );
        registry
            .require_attached(&replacement)
            .expect("replacement may confirm");
        assert_eq!(registry.confirm(&replacement), Ok(Some(first_id)));
        assert_eq!(
            registry.require_active(&first),
            Err(SandboxAuthError::ConnectionNotAttached)
        );
        registry
            .require_active(&replacement)
            .expect("replacement became active");
    }

    #[test]
    fn configuration_activation_new_registration_fences_old_control_before_confirmation() {
        let (authenticator, token) = fixture(1);
        let first_id = SandboxConnectionId::new();
        let first = authenticator
            .authenticate(first_id, &metadata(token.token.expose_secret()))
            .expect("first principal");
        let replacement = authenticator
            .authenticate(
                SandboxConnectionId::new(),
                &metadata(token.token.expose_secret()),
            )
            .expect("replacement principal");
        let registry = registry_for(&first);
        let old = registration(crate::boundary_protocol::SupervisorInstanceId::new(), 1);
        let new = registration(crate::boundary_protocol::SupervisorInstanceId::new(), 2);
        registry.attach(&first, &old).expect("old registration");
        registry.confirm(&first).expect("old connection");
        let attachment = registry
            .attach(&replacement, &new)
            .expect("new signed registration");
        assert!(attachment.replaced_registration);
        assert_eq!(attachment.replaced_connections, vec![first_id]);
        assert_eq!(
            registry.require_active(&first),
            Err(SandboxAuthError::ConnectionNotAttached)
        );
        assert_eq!(
            registry.require_active(&replacement),
            Err(SandboxAuthError::ConnectionNotAttached)
        );
        assert_eq!(
            registry.attach(&first, &old),
            Err(SandboxAuthError::StaleRegistration)
        );
        registry
            .confirm(&replacement)
            .expect("replacement confirmation");
        assert_eq!(registry.require_active(&replacement), Ok(()));
        assert_eq!(
            registry.attach(&first, &old),
            Err(SandboxAuthError::StaleRegistration)
        );
    }

    #[test]
    fn configuration_activation_signed_registration_matches_every_local_coordinate() {
        let (authenticator, bearer, issuer) = fixture_with_issuer(1);
        let expected =
            registration(crate::boundary_protocol::SupervisorInstanceId::new(), 7).identity;
        let grant = openshell_core::jwt::ControlRegistrationGrant {
            runtime_identity: SandboxRuntimeIdentity {
                sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox ID"),
                runtime_generation: SandboxGenerationId::parse("generation-1")
                    .expect("runtime generation"),
                auth_epoch: CredentialEpoch::new(1).expect("epoch"),
            },
            supervisor_instance_id: expected
                .supervisor_instance_id
                .parse()
                .expect("control UUID"),
            boundary_session_id: expected.boundary_session_id.parse().expect("session UUID"),
            boundary_instance_id: expected
                .boundary_instance_id
                .parse()
                .expect("boundary UUID"),
            registration_revision: expected.registration_revision,
        };
        let signed = issuer
            .mint_control_registration(&grant)
            .expect("signed registration");
        assert_eq!(
            authenticator
                .verify_control_registration(signed.token.expose_secret(), &expected)
                .expect("verified grant")
                .identity(),
            &expected,
        );
        assert!(
            authenticator
                .verify_control_registration(bearer.token.expose_secret(), &expected)
                .is_err(),
            "a runtime bearer cannot authorize control replacement"
        );
        // Both grants are correctly signed and structurally valid. The launch
        // authenticator must still reject another sandbox or credential epoch.
        for field in ["sandbox_id", "auth_epoch"] {
            let mut wrong_grant = grant.clone();
            match field {
                "sandbox_id" => {
                    wrong_grant.runtime_identity.sandbox_id =
                        SandboxId::parse("sandbox-b").expect("valid different sandbox");
                }
                "auth_epoch" => {
                    wrong_grant.runtime_identity.auth_epoch =
                        CredentialEpoch::new(2).expect("valid different epoch");
                }
                _ => unreachable!("fixed launch coordinate fixture"),
            }
            let wrong_signed = issuer
                .mint_control_registration(&wrong_grant)
                .expect("well-formed signed mismatching grant");
            assert_eq!(
                authenticator
                    .verify_control_registration(wrong_signed.token.expose_secret(), &expected),
                Err(SandboxAuthError::InvalidRegistration),
                "valid signed grant for another {field} must reject",
            );
        }
        for field in ["runtime", "session", "control", "boundary", "registration"] {
            let mut wrong = expected.clone();
            match field {
                "runtime" => wrong.runtime_generation = "different-runtime".to_string(),
                "session" => wrong.boundary_session_id = Uuid::new_v4().to_string(),
                "control" => wrong.supervisor_instance_id = Uuid::new_v4().to_string(),
                "boundary" => wrong.boundary_instance_id = Uuid::new_v4().to_string(),
                "registration" => wrong.registration_revision += 1,
                _ => unreachable!("fixed coordinate fixture"),
            }
            assert_eq!(
                authenticator.verify_control_registration(signed.token.expose_secret(), &wrong),
                Err(SandboxAuthError::InvalidRegistration),
                "mismatched {field} must reject the grant",
            );
        }
    }
}
