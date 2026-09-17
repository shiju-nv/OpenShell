// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! JWT inspection and authenticated sandbox session and registration profiles.
//!
//! [`parse_exp_secs`] only inspects expiry for client-side refresh scheduling;
//! it never authenticates a token. With the `jwt` feature, dedicated issuer
//! and verifier methods enforce separate signed profiles for gateway access,
//! sandbox access, and control registration.

/// Decode the numeric `exp` claim (Unix seconds) from a JWT payload without
/// verifying the signature.
///
/// Returns `None` when `token` is not a parseable JWT or has no integer `exp`
/// claim. A leading `Bearer ` prefix is tolerated so callers can pass either a
/// raw token or an `authorization` header value.
#[must_use]
pub fn parse_exp_secs(token: &str) -> Option<i64> {
    use base64::Engine;
    let raw = token.strip_prefix("Bearer ").unwrap_or(token);
    let mut parts = raw.splitn(3, '.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value.get("exp")?.as_i64()
}

#[cfg(feature = "jwt")]
mod session {
    use std::collections::BTreeMap;
    use std::fmt;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{
        Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    };
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use crate::SandboxSessionId;
    use crate::sandbox_generation::SandboxGenerationId;

    pub const GATEWAY_SESSION_JWT_TYPE: &str = "openshell-gateway-session+jwt";
    pub const SANDBOX_SESSION_JWT_TYPE: &str = "openshell-sandbox-session+jwt";
    pub const SANDBOX_SESSION_AUDIENCE: &str = "openshell-sandbox";
    /// JOSE type reserved for gateway-approved control registrations.
    pub const CONTROL_REGISTRATION_JWT_TYPE: &str = "openshell-control-registration+jwt";
    /// Audience accepted only by explicit control-registration verification.
    pub const CONTROL_REGISTRATION_AUDIENCE: &str = "openshell-control-registration";
    pub const DEFAULT_SESSION_TOKEN_TTL: Duration = Duration::from_hours(1);
    pub const MIN_SESSION_TOKEN_TTL: Duration = Duration::from_mins(1);
    pub const MAX_SESSION_TOKEN_TTL: Duration = Duration::from_hours(1);
    pub const MAX_SESSION_CLOCK_LEEWAY: Duration = Duration::from_secs(30);

    const GATEWAY_ISSUER_PREFIX: &str = "openshell-gateway:";
    const SANDBOX_SUBJECT_PREFIX: &str = "spiffe://openshell/sandbox/";

    /// Canonical sandbox identity carried by both session-token profiles.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct SandboxId(String);

    impl SandboxId {
        pub fn parse(value: impl Into<String>) -> Result<Self, SessionJwtError> {
            let value = value.into();
            if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
                return Err(SessionJwtError::InvalidSandboxId);
            }
            Ok(Self(value))
        }

        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl fmt::Display for SandboxId {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.0)
        }
    }

    /// Monotonic order for authenticated Sandbox Protocol connections.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct CredentialEpoch(u64);

    impl CredentialEpoch {
        pub fn new(value: u64) -> Result<Self, SessionJwtError> {
            if value == 0 {
                return Err(SessionJwtError::InvalidCredentialEpoch);
            }
            Ok(Self(value))
        }

        #[must_use]
        pub const fn get(self) -> u64 {
            self.0
        }
    }

    /// Monotonic identity for Sandbox Protocol attachment state.
    ///
    /// This is a protocol coordination value, not part of JWT authorization.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct SessionRotation(u64);

    impl SessionRotation {
        pub fn new(value: u64) -> Result<Self, SessionJwtError> {
            if value == 0 {
                return Err(SessionJwtError::InvalidSessionRotation);
            }
            Ok(Self(value))
        }

        #[must_use]
        pub const fn get(self) -> u64 {
            self.0
        }

        pub fn successor(self) -> Result<Self, SessionJwtError> {
            self.0
                .checked_add(1)
                .ok_or(SessionJwtError::SessionRotationOverflow)
                .and_then(Self::new)
        }
    }

    /// The only component authorized by either sandbox-session token profile.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum SessionComponent {
        #[serde(rename = "openshell-supervisor")]
        OpenShellSupervisor,
    }

    /// Exact token profile. The profile chooses both the JOSE `typ` and JWT `aud`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SessionTokenProfile {
        Gateway,
        Sandbox,
    }

    impl SessionTokenProfile {
        #[must_use]
        pub const fn token_type(self) -> &'static str {
            match self {
                Self::Gateway => GATEWAY_SESSION_JWT_TYPE,
                Self::Sandbox => SANDBOX_SESSION_JWT_TYPE,
            }
        }

        fn audience(self, issuer: &str) -> &str {
            match self {
                Self::Gateway => issuer,
                Self::Sandbox => SANDBOX_SESSION_AUDIENCE,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SessionClaims {
        iss: String,
        sub: String,
        aud: String,
        iat: i64,
        exp: i64,
        jti: String,
        sandbox_id: SandboxId,
        runtime_generation: SandboxGenerationId,
        auth_epoch: CredentialEpoch,
        component: SessionComponent,
    }

    /// Durable identity shared by every short-lived token for one sandbox runtime.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SandboxRuntimeIdentity {
        pub sandbox_id: SandboxId,
        pub runtime_generation: SandboxGenerationId,
        pub auth_epoch: CredentialEpoch,
    }

    /// Gateway authorization for one control process to attach to one boundary.
    ///
    /// The boundary must compare every identity field with its trusted launch
    /// and attach state, then enforce monotonic registration revisions. A valid
    /// signature alone does not authorize replacing a newer registration.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ControlRegistrationGrant {
        /// Durable sandbox launch and authentication identity.
        pub runtime_identity: SandboxRuntimeIdentity,
        /// Control process authorized by the gateway registration.
        pub supervisor_instance_id: Uuid,
        /// Boundary session assigned by the compute driver.
        pub boundary_session_id: Uuid,
        /// Fresh incarnation of the boundary process accepting the control.
        pub boundary_instance_id: Uuid,
        /// Positive registration order persisted and checked by the gateway.
        pub registration_revision: u64,
    }

    impl ControlRegistrationGrant {
        fn validate(&self) -> Result<(), SessionJwtError> {
            // Serde-transparent identity types can bypass their constructors;
            // validate again before signing or trusting deserialized claims.
            SandboxId::parse(self.runtime_identity.sandbox_id.as_str())?;
            SandboxGenerationId::parse(self.runtime_identity.runtime_generation.as_str())
                .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?;
            CredentialEpoch::new(self.runtime_identity.auth_epoch.get())?;
            if self.supervisor_instance_id.is_nil()
                || self.boundary_session_id.is_nil()
                || self.boundary_instance_id.is_nil()
            {
                return Err(SessionJwtError::InvalidRegistrationIdentity);
            }
            if self.registration_revision == 0 {
                return Err(SessionJwtError::InvalidRegistrationRevision);
            }
            Ok(())
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ControlRegistrationClaims {
        iss: String,
        sub: String,
        aud: String,
        iat: i64,
        exp: i64,
        jti: String,
        sandbox_id: SandboxId,
        runtime_generation: SandboxGenerationId,
        auth_epoch: CredentialEpoch,
        component: SessionComponent,
        supervisor_instance_id: String,
        boundary_session_id: String,
        boundary_instance_id: String,
        registration_revision: u64,
    }

    /// A signature-verified grant whose current registration must still be fenced.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AuthenticatedControlRegistration {
        /// Exact gateway-authorized runtime and process identities.
        pub grant: ControlRegistrationGrant,
        /// Unique identifier of this signed token, independent of its revision.
        pub token_id: Uuid,
        /// Signed issue time in Unix seconds.
        pub issued_at: i64,
        /// Signed expiration time in Unix seconds.
        pub expires_at: i64,
    }

    /// A JWT whose contents are deliberately omitted from `Debug` output and
    /// zeroed when its final owner is dropped.
    #[derive(Clone)]
    pub struct SecretJwt(Zeroizing<String>);

    impl SecretJwt {
        pub fn parse(value: impl Into<String>) -> Result<Self, SessionJwtError> {
            let value = value.into();
            if value.is_empty() || value.chars().any(char::is_whitespace) {
                return Err(SessionJwtError::InvalidTokenEncoding);
            }
            Ok(Self(Zeroizing::new(value)))
        }

        #[must_use]
        pub fn expose_secret(&self) -> &str {
            self.0.as_str()
        }
    }

    impl fmt::Debug for SecretJwt {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("SecretJwt([REDACTED])")
        }
    }

    impl Serialize for SecretJwt {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.expose_secret())
        }
    }

    impl<'de> Deserialize<'de> for SecretJwt {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let value = String::deserialize(deserializer)?;
            Self::parse(value).map_err(serde::de::Error::custom)
        }
    }

    /// Trusted launch input delivered only to `openshell-supervisor`.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SupervisorAuthBundle {
        /// Correlates the two ends of one Sandbox Protocol launch. This value
        /// is not carried in JWTs and is not an authorization identity.
        pub session_id: SandboxSessionId,
        pub runtime_generation: SandboxGenerationId,
        /// Orders protocol attachment replacement, independently of auth.
        pub session_rotation: SessionRotation,
        pub auth_epoch: CredentialEpoch,
        pub gateway_token: SecretJwt,
        pub gateway_expires_at: i64,
        pub sandbox_token: SecretJwt,
        pub sandbox_expires_at: i64,
    }

    /// Gateway-created authentication input trusted by a compute driver.
    ///
    /// Drivers split this structure: the supervisor receives `supervisor`,
    /// while the sandbox receives only the gateway identity and public keys.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SandboxLaunchAuthentication {
        pub supervisor: SupervisorAuthBundle,
        pub gateway_id: String,
        pub verification_keys: Vec<SessionVerificationKey>,
    }

    impl SandboxLaunchAuthentication {
        pub fn validate(&self) -> Result<(), SessionJwtError> {
            self.supervisor.validate()?;
            validate_gateway_id(&self.gateway_id)?;
            if self.verification_keys.is_empty() {
                return Err(SessionJwtError::NoVerificationKeys);
            }
            let mut key_ids = std::collections::BTreeSet::new();
            for key in &self.verification_keys {
                validate_key_id(key.key_id.clone())?;
                if key.public_key_pem.is_empty() {
                    return Err(SessionJwtError::InvalidVerificationKey);
                }
                if !key_ids.insert(key.key_id.as_str()) {
                    return Err(SessionJwtError::DuplicateKeyId);
                }
            }
            Ok(())
        }
    }

    impl fmt::Debug for SandboxLaunchAuthentication {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SandboxLaunchAuthentication")
                .field("supervisor", &self.supervisor)
                .field("gateway_id", &self.gateway_id)
                .field(
                    "verification_key_ids",
                    &self
                        .verification_keys
                        .iter()
                        .map(|key| key.key_id.as_str())
                        .collect::<Vec<_>>(),
                )
                .finish()
        }
    }

    impl SupervisorAuthBundle {
        pub fn validate(&self) -> Result<(), SessionJwtError> {
            if self.gateway_expires_at <= 0 || self.sandbox_expires_at <= 0 {
                return Err(SessionJwtError::InvalidLifetime);
            }
            SandboxGenerationId::parse(self.runtime_generation.to_string())
                .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?;
            SessionRotation::new(self.session_rotation.get())?;
            Ok(())
        }

        pub fn sandbox_bearer_slot(&self) -> Result<SessionBearerTokenSlot, SessionJwtError> {
            SessionBearerTokenSlot::new(
                self.sandbox_token.clone(),
                self.sandbox_expires_at,
                self.auth_epoch,
            )
        }
    }

    impl fmt::Debug for SupervisorAuthBundle {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SupervisorAuthBundle")
                .field("session_id", &self.session_id)
                .field("runtime_generation", &self.runtime_generation)
                .field("session_rotation", &self.session_rotation)
                .field("auth_epoch", &self.auth_epoch)
                .field("gateway_token", &"[REDACTED]")
                .field("gateway_expires_at", &self.gateway_expires_at)
                .field("sandbox_token", &"[REDACTED]")
                .field("sandbox_expires_at", &self.sandbox_expires_at)
                .finish()
        }
    }

    #[derive(Clone, Debug)]
    pub struct MintedSessionToken {
        pub token: SecretJwt,
        pub expires_at: i64,
        pub token_id: Uuid,
    }

    #[derive(Clone, Debug)]
    pub struct MintedSessionTokenPair {
        pub gateway: MintedSessionToken,
        pub sandbox: MintedSessionToken,
        pub auth_epoch: CredentialEpoch,
    }

    /// Refreshable Sandbox Protocol bearer credential shared by all streams on
    /// the supervisor's current HTTP/2 connection.
    #[derive(Clone)]
    pub struct SessionBearerTokenSlot {
        inner: Arc<std::sync::RwLock<Option<StoredBearer>>>,
    }

    #[derive(Clone)]
    struct StoredBearer {
        token: SecretJwt,
        expires_at: i64,
        credential_epoch: CredentialEpoch,
    }

    impl SessionBearerTokenSlot {
        #[must_use]
        pub fn empty() -> Self {
            Self {
                inner: Arc::new(std::sync::RwLock::new(None)),
            }
        }

        pub fn new(
            token: SecretJwt,
            expires_at: i64,
            credential_epoch: CredentialEpoch,
        ) -> Result<Self, SessionJwtError> {
            let slot = Self::empty();
            slot.update(token, expires_at, credential_epoch)?;
            Ok(slot)
        }

        pub fn update(
            &self,
            token: SecretJwt,
            expires_at: i64,
            credential_epoch: CredentialEpoch,
        ) -> Result<(), SessionJwtError> {
            if expires_at <= 0 {
                return Err(SessionJwtError::InvalidLifetime);
            }
            let mut stored = self
                .inner
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if stored
                .as_ref()
                .is_some_and(|current| credential_epoch < current.credential_epoch)
            {
                return Err(SessionJwtError::StaleCredentialEpoch);
            }
            *stored = Some(StoredBearer {
                token,
                expires_at,
                credential_epoch,
            });
            Ok(())
        }

        pub fn clear(&self) {
            *self
                .inner
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }

        #[must_use]
        pub fn expires_at(&self) -> Option<i64> {
            self.inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(|stored| stored.expires_at)
        }

        #[must_use]
        pub fn credential_epoch(&self) -> Option<CredentialEpoch> {
            self.inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(|stored| stored.credential_epoch)
        }

        pub fn authorization_metadata(
            &self,
        ) -> Result<tonic::metadata::AsciiMetadataValue, SessionJwtError> {
            let stored = self
                .inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stored = stored.as_ref().ok_or(SessionJwtError::TokenUnavailable)?;
            if stored.expires_at <= SystemJwtClock.now_unix_seconds() {
                return Err(SessionJwtError::Expired);
            }
            format!("Bearer {}", stored.token.expose_secret())
                .parse()
                .map_err(|_| SessionJwtError::InvalidTokenEncoding)
        }
    }

    impl Default for SessionBearerTokenSlot {
        fn default() -> Self {
            Self::empty()
        }
    }

    impl fmt::Debug for SessionBearerTokenSlot {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SessionBearerTokenSlot")
                .field("expires_at", &self.expires_at())
                .field("credential_epoch", &self.credential_epoch())
                .finish_non_exhaustive()
        }
    }

    pub trait JwtClock: Send + Sync {
        fn now_unix_seconds(&self) -> i64;
    }

    #[derive(Debug)]
    pub struct SystemJwtClock;

    impl JwtClock for SystemJwtClock {
        fn now_unix_seconds(&self) -> i64 {
            i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs()),
            )
            .unwrap_or(i64::MAX)
        }
    }

    /// Gateway-side issuer shared by both token profiles.
    pub struct SessionJwtIssuer {
        encoding_key: EncodingKey,
        key_id: String,
        issuer: String,
        ttl: Duration,
        clock: Arc<dyn JwtClock>,
    }

    impl fmt::Debug for SessionJwtIssuer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SessionJwtIssuer")
                .field("key_id", &self.key_id)
                .field("issuer", &self.issuer)
                .field("ttl", &self.ttl)
                .finish_non_exhaustive()
        }
    }

    impl SessionJwtIssuer {
        pub fn from_ed25519_pem(
            signing_key_pem: &[u8],
            key_id: impl Into<String>,
            gateway_id: &str,
            ttl: Duration,
            clock: Arc<dyn JwtClock>,
        ) -> Result<Self, SessionJwtError> {
            install_crypto_provider();
            validate_ttl(ttl)?;
            let key_id = validate_key_id(key_id.into())?;
            let gateway_id = validate_gateway_id(gateway_id)?;
            let encoding_key = EncodingKey::from_ed_pem(signing_key_pem)
                .map_err(|_| SessionJwtError::InvalidSigningKey)?;
            Ok(Self {
                encoding_key,
                key_id,
                issuer: format!("{GATEWAY_ISSUER_PREFIX}{gateway_id}"),
                ttl,
                clock,
            })
        }

        pub fn mint_pair(
            &self,
            identity: &SandboxRuntimeIdentity,
        ) -> Result<MintedSessionTokenPair, SessionJwtError> {
            self.mint_pair_with_gateway_token_id(identity, Uuid::new_v4())
        }

        /// Mint a token pair whose gateway-facing credential has a caller-owned
        /// lineage identifier.
        ///
        /// The gateway persists this identifier before returning the token so
        /// refresh can reject every superseded bearer across all replicas. The
        /// Sandbox Protocol credential remains independently identified.
        pub fn mint_pair_with_gateway_token_id(
            &self,
            identity: &SandboxRuntimeIdentity,
            gateway_token_id: Uuid,
        ) -> Result<MintedSessionTokenPair, SessionJwtError> {
            self.mint_pair_with_token_metadata(
                identity,
                gateway_token_id,
                Uuid::new_v4(),
                self.clock.now_unix_seconds(),
            )
        }

        /// Mint a reproducible token pair for a persisted refresh successor.
        pub fn mint_pair_with_token_metadata(
            &self,
            identity: &SandboxRuntimeIdentity,
            gateway_token_id: Uuid,
            sandbox_token_id: Uuid,
            issued_at: i64,
        ) -> Result<MintedSessionTokenPair, SessionJwtError> {
            Ok(MintedSessionTokenPair {
                gateway: self.mint(
                    SessionTokenProfile::Gateway,
                    identity,
                    gateway_token_id,
                    issued_at,
                )?,
                sandbox: self.mint(
                    SessionTokenProfile::Sandbox,
                    identity,
                    sandbox_token_id,
                    issued_at,
                )?,
                auth_epoch: identity.auth_epoch,
            })
        }

        /// Sign the exact registration accepted by the gateway's durable CAS.
        ///
        /// Call only after persisting the registration. Reissuing the same
        /// registration keeps its revision and renews only the token lifetime.
        pub fn mint_control_registration(
            &self,
            grant: &ControlRegistrationGrant,
        ) -> Result<MintedSessionToken, SessionJwtError> {
            grant.validate()?;
            let issued_at = self.clock.now_unix_seconds();
            let expires_at = issued_at
                .checked_add(
                    i64::try_from(self.ttl.as_secs())
                        .map_err(|_| SessionJwtError::InvalidLifetime)?,
                )
                .ok_or(SessionJwtError::InvalidLifetime)?;
            let token_id = Uuid::new_v4();
            let claims = ControlRegistrationClaims {
                iss: self.issuer.clone(),
                sub: format!(
                    "{SANDBOX_SUBJECT_PREFIX}{}",
                    grant.runtime_identity.sandbox_id
                ),
                aud: CONTROL_REGISTRATION_AUDIENCE.to_string(),
                iat: issued_at,
                exp: expires_at,
                jti: token_id.to_string(),
                sandbox_id: grant.runtime_identity.sandbox_id.clone(),
                runtime_generation: grant.runtime_identity.runtime_generation.clone(),
                auth_epoch: grant.runtime_identity.auth_epoch,
                component: SessionComponent::OpenShellSupervisor,
                supervisor_instance_id: grant.supervisor_instance_id.to_string(),
                boundary_session_id: grant.boundary_session_id.to_string(),
                boundary_instance_id: grant.boundary_instance_id.to_string(),
                registration_revision: grant.registration_revision,
            };
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some(self.key_id.clone());
            header.typ = Some(CONTROL_REGISTRATION_JWT_TYPE.to_string());
            let token = encode(&header, &claims, &self.encoding_key)
                .map_err(|_| SessionJwtError::SigningFailed)?;
            Ok(MintedSessionToken {
                token: SecretJwt::parse(token)?,
                expires_at,
                token_id,
            })
        }

        fn mint(
            &self,
            profile: SessionTokenProfile,
            identity: &SandboxRuntimeIdentity,
            token_id: Uuid,
            issued_at: i64,
        ) -> Result<MintedSessionToken, SessionJwtError> {
            let expires_at = issued_at.saturating_add(
                i64::try_from(self.ttl.as_secs()).map_err(|_| SessionJwtError::InvalidLifetime)?,
            );
            let claims = SessionClaims {
                iss: self.issuer.clone(),
                sub: format!("{SANDBOX_SUBJECT_PREFIX}{}", identity.sandbox_id),
                aud: profile.audience(&self.issuer).to_string(),
                iat: issued_at,
                exp: expires_at,
                jti: token_id.to_string(),
                sandbox_id: identity.sandbox_id.clone(),
                runtime_generation: identity.runtime_generation.clone(),
                auth_epoch: identity.auth_epoch,
                component: SessionComponent::OpenShellSupervisor,
            };
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some(self.key_id.clone());
            header.typ = Some(profile.token_type().to_string());
            let token = encode(&header, &claims, &self.encoding_key)
                .map_err(|_| SessionJwtError::SigningFailed)?;
            Ok(MintedSessionToken {
                token: SecretJwt::parse(token)?,
                expires_at,
                token_id,
            })
        }
    }

    /// One accepted public key from the immutable sandbox verification bundle.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SessionVerificationKey {
        pub key_id: String,
        pub public_key_pem: Vec<u8>,
    }

    /// Strict verifier used by either the gateway or the Sandbox Protocol.
    pub struct SessionJwtVerifier {
        keys: BTreeMap<String, DecodingKey>,
        issuer: String,
        profile: SessionTokenProfile,
        clock: Arc<dyn JwtClock>,
    }

    impl fmt::Debug for SessionJwtVerifier {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SessionJwtVerifier")
                .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
                .field("issuer", &self.issuer)
                .field("profile", &self.profile)
                .finish_non_exhaustive()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AuthenticatedSandboxSession {
        pub sandbox_id: SandboxId,
        pub runtime_generation: SandboxGenerationId,
        pub auth_epoch: CredentialEpoch,
        pub token_id: Uuid,
        pub issued_at: i64,
        pub expires_at: i64,
    }

    impl SessionJwtVerifier {
        pub fn new(
            gateway_id: &str,
            profile: SessionTokenProfile,
            keys: impl IntoIterator<Item = SessionVerificationKey>,
            clock: Arc<dyn JwtClock>,
        ) -> Result<Self, SessionJwtError> {
            install_crypto_provider();
            let gateway_id = validate_gateway_id(gateway_id)?;
            let mut parsed = BTreeMap::new();
            for key in keys {
                let key_id = validate_key_id(key.key_id)?;
                let decoding_key = DecodingKey::from_ed_pem(&key.public_key_pem)
                    .map_err(|_| SessionJwtError::InvalidVerificationKey)?;
                if parsed.insert(key_id, decoding_key).is_some() {
                    return Err(SessionJwtError::DuplicateKeyId);
                }
            }
            if parsed.is_empty() {
                return Err(SessionJwtError::NoVerificationKeys);
            }
            Ok(Self {
                keys: parsed,
                issuer: format!("{GATEWAY_ISSUER_PREFIX}{gateway_id}"),
                profile,
                clock,
            })
        }

        pub fn verify(&self, token: &str) -> Result<AuthenticatedSandboxSession, SessionJwtError> {
            install_crypto_provider();
            let header = decode_header(token).map_err(|_| SessionJwtError::InvalidToken)?;
            if header.alg != Algorithm::EdDSA {
                return Err(SessionJwtError::WrongAlgorithm);
            }
            if header.typ.as_deref() != Some(self.profile.token_type()) {
                return Err(SessionJwtError::WrongTokenType);
            }
            let key_id = header.kid.ok_or(SessionJwtError::MissingKeyId)?;
            let key = self
                .keys
                .get(&key_id)
                .ok_or(SessionJwtError::UnknownKeyId)?;
            let mut validation = Validation::new(Algorithm::EdDSA);
            validation.algorithms = vec![Algorithm::EdDSA];
            validation.validate_exp = false;
            validation.validate_aud = false;
            validation.set_required_spec_claims(&["iss", "aud", "iat", "exp", "sub", "jti"]);
            let claims = decode::<SessionClaims>(token, key, &validation)
                .map_err(|_| SessionJwtError::InvalidToken)?
                .claims;
            self.validate_claims(claims)
        }

        /// Authenticate a control-registration grant using the trusted gateway keys.
        ///
        /// This deliberately selects a separate type and audience, regardless of
        /// the verifier's session profile. Session credentials cannot stand in for
        /// a registration grant, and grants cannot authenticate session requests.
        pub fn verify_control_registration(
            &self,
            token: &str,
        ) -> Result<AuthenticatedControlRegistration, SessionJwtError> {
            install_crypto_provider();
            let header = decode_header(token).map_err(|_| SessionJwtError::InvalidToken)?;
            if header.alg != Algorithm::EdDSA {
                return Err(SessionJwtError::WrongAlgorithm);
            }
            if header.typ.as_deref() != Some(CONTROL_REGISTRATION_JWT_TYPE) {
                return Err(SessionJwtError::WrongTokenType);
            }
            let key_id = header.kid.ok_or(SessionJwtError::MissingKeyId)?;
            let key = self
                .keys
                .get(&key_id)
                .ok_or(SessionJwtError::UnknownKeyId)?;
            let mut validation = Validation::new(Algorithm::EdDSA);
            validation.validate_exp = false;
            validation.validate_aud = false;
            validation.set_required_spec_claims(&["iss", "aud", "iat", "exp", "sub", "jti"]);
            let claims = decode::<ControlRegistrationClaims>(token, key, &validation)
                .map_err(|_| SessionJwtError::InvalidToken)?
                .claims;
            if claims.iss != self.issuer {
                return Err(SessionJwtError::WrongIssuer);
            }
            if claims.aud != CONTROL_REGISTRATION_AUDIENCE {
                return Err(SessionJwtError::WrongAudience);
            }
            if claims.sub != format!("{SANDBOX_SUBJECT_PREFIX}{}", claims.sandbox_id) {
                return Err(SessionJwtError::SubjectMismatch);
            }
            let token_id = Uuid::parse_str(&claims.jti).map_err(|_| SessionJwtError::InvalidJti)?;
            if token_id.is_nil() {
                return Err(SessionJwtError::InvalidJti);
            }
            self.validate_lifetime(claims.iat, claims.exp)?;
            let grant = ControlRegistrationGrant {
                runtime_identity: SandboxRuntimeIdentity {
                    sandbox_id: claims.sandbox_id,
                    runtime_generation: claims.runtime_generation,
                    auth_epoch: claims.auth_epoch,
                },
                supervisor_instance_id: Uuid::parse_str(&claims.supervisor_instance_id)
                    .map_err(|_| SessionJwtError::InvalidToken)?,
                boundary_session_id: Uuid::parse_str(&claims.boundary_session_id)
                    .map_err(|_| SessionJwtError::InvalidToken)?,
                boundary_instance_id: Uuid::parse_str(&claims.boundary_instance_id)
                    .map_err(|_| SessionJwtError::InvalidToken)?,
                registration_revision: claims.registration_revision,
            };
            grant.validate()?;
            Ok(AuthenticatedControlRegistration {
                grant,
                token_id,
                issued_at: claims.iat,
                expires_at: claims.exp,
            })
        }

        fn validate_claims(
            &self,
            claims: SessionClaims,
        ) -> Result<AuthenticatedSandboxSession, SessionJwtError> {
            if claims.iss != self.issuer {
                return Err(SessionJwtError::WrongIssuer);
            }
            if claims.aud != self.profile.audience(&self.issuer) {
                return Err(SessionJwtError::WrongAudience);
            }
            if claims.sub != format!("{SANDBOX_SUBJECT_PREFIX}{}", claims.sandbox_id) {
                return Err(SessionJwtError::SubjectMismatch);
            }
            SandboxGenerationId::parse(claims.runtime_generation.to_string())
                .map_err(|_| SessionJwtError::InvalidRuntimeIdentity)?;
            let token_id = Uuid::parse_str(&claims.jti).map_err(|_| SessionJwtError::InvalidJti)?;
            self.validate_lifetime(claims.iat, claims.exp)?;
            Ok(AuthenticatedSandboxSession {
                sandbox_id: claims.sandbox_id,
                runtime_generation: claims.runtime_generation,
                auth_epoch: claims.auth_epoch,
                token_id,
                issued_at: claims.iat,
                expires_at: claims.exp,
            })
        }

        fn validate_lifetime(
            &self,
            issued_at: i64,
            expires_at: i64,
        ) -> Result<(), SessionJwtError> {
            if expires_at <= issued_at {
                return Err(SessionJwtError::InvalidLifetime);
            }
            let lifetime = expires_at.saturating_sub(issued_at);
            if lifetime > i64::try_from(MAX_SESSION_TOKEN_TTL.as_secs()).unwrap_or(i64::MAX) {
                return Err(SessionJwtError::InvalidLifetime);
            }
            let now = self.clock.now_unix_seconds();
            let leeway = i64::try_from(MAX_SESSION_CLOCK_LEEWAY.as_secs()).unwrap_or(30);
            if issued_at > now.saturating_add(leeway) {
                return Err(SessionJwtError::IssuedInFuture);
            }
            if expires_at < now.saturating_sub(leeway) {
                return Err(SessionJwtError::Expired);
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum SessionJwtError {
        #[error("sandbox ID is invalid")]
        InvalidSandboxId,
        #[error("gateway ID is invalid")]
        InvalidGatewayId,
        #[error("credential epoch must be positive")]
        InvalidCredentialEpoch,
        #[error("credential epoch does not advance the active credential")]
        StaleCredentialEpoch,
        #[error("session rotation must be positive")]
        InvalidSessionRotation,
        #[error("session rotation overflow")]
        SessionRotationOverflow,
        #[error("sandbox runtime identity is missing")]
        MissingRuntimeIdentity,
        #[error("sandbox runtime identity is invalid")]
        InvalidRuntimeIdentity,
        /// A registered process or session UUID is nil.
        #[error("control registration process and session identities must be non-nil UUIDs")]
        InvalidRegistrationIdentity,
        /// Registration ordering cannot use the unregistered zero sentinel.
        #[error("control registration revision must be positive")]
        InvalidRegistrationRevision,
        #[error("key ID is invalid")]
        InvalidKeyId,
        #[error("verification key IDs must be unique")]
        DuplicateKeyId,
        #[error("at least one verification key is required")]
        NoVerificationKeys,
        #[error("Ed25519 signing key is invalid")]
        InvalidSigningKey,
        #[error("Ed25519 verification key is invalid")]
        InvalidVerificationKey,
        #[error("session token lifetime must be between 60 and 3600 seconds")]
        InvalidLifetime,
        #[error("session token profile does not match its claims")]
        ProfileMismatch,
        #[error("session token could not be signed")]
        SigningFailed,
        #[error("session token encoding is invalid")]
        InvalidTokenEncoding,
        #[error("session token is unavailable")]
        TokenUnavailable,
        #[error("session token is invalid")]
        InvalidToken,
        #[error("session token algorithm must be EdDSA")]
        WrongAlgorithm,
        #[error("session token type is invalid")]
        WrongTokenType,
        #[error("session token key ID is missing")]
        MissingKeyId,
        #[error("session token key ID is unknown")]
        UnknownKeyId,
        #[error("session token issuer is invalid")]
        WrongIssuer,
        #[error("session token audience is invalid")]
        WrongAudience,
        #[error("session token subject does not match its sandbox ID")]
        SubjectMismatch,
        #[error("session token ID is not a UUID")]
        InvalidJti,
        #[error("session token was issued in the future")]
        IssuedInFuture,
        #[error("session token has expired")]
        Expired,
    }

    fn install_crypto_provider() {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    }

    fn validate_ttl(ttl: Duration) -> Result<(), SessionJwtError> {
        if !(MIN_SESSION_TOKEN_TTL..=MAX_SESSION_TOKEN_TTL).contains(&ttl) {
            return Err(SessionJwtError::InvalidLifetime);
        }
        Ok(())
    }

    fn validate_gateway_id(gateway_id: &str) -> Result<&str, SessionJwtError> {
        if gateway_id.is_empty()
            || gateway_id.trim() != gateway_id
            || gateway_id.chars().any(char::is_whitespace)
        {
            return Err(SessionJwtError::InvalidGatewayId);
        }
        Ok(gateway_id)
    }

    fn validate_key_id(key_id: String) -> Result<String, SessionJwtError> {
        if key_id.is_empty() || key_id.trim() != key_id || key_id.chars().any(char::is_whitespace) {
            return Err(SessionJwtError::InvalidKeyId);
        }
        Ok(key_id)
    }
}

#[cfg(feature = "jwt")]
pub use session::*;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        exp: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<&'a str>,
    }

    fn jwt_with_payload(payload: &TestClaims<'_>) -> String {
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let header = b64(br#"{"alg":"none","typ":"JWT"}"#);
        let body = b64(serde_json::to_vec(payload).unwrap().as_slice());
        format!("{header}.{body}.")
    }

    #[test]
    fn reads_integer_exp() {
        let token = jwt_with_payload(&TestClaims {
            exp: Some(1_900_000_000),
            sub: None,
        });
        assert_eq!(parse_exp_secs(&token), Some(1_900_000_000));
    }

    #[test]
    fn tolerates_bearer_prefix() {
        let token = jwt_with_payload(&TestClaims {
            exp: Some(42),
            sub: None,
        });
        assert_eq!(parse_exp_secs(&format!("Bearer {token}")), Some(42));
    }

    #[test]
    fn none_for_missing_exp_or_non_jwt() {
        assert_eq!(
            parse_exp_secs(&jwt_with_payload(&TestClaims {
                exp: None,
                sub: Some("x"),
            })),
            None
        );
        assert_eq!(parse_exp_secs("not-a-jwt"), None);
        assert_eq!(parse_exp_secs(""), None);
    }

    #[cfg(feature = "jwt")]
    mod session_tests {
        use std::sync::Arc;

        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use rcgen::{KeyPair, PKCS_ED25519};
        use serde::Serialize;

        use super::super::session::*;
        use crate::SandboxSessionId;
        use crate::sandbox_generation::SandboxGenerationId;

        #[derive(Debug)]
        struct FixedClock(i64);

        impl JwtClock for FixedClock {
            fn now_unix_seconds(&self) -> i64 {
                self.0
            }
        }

        fn fixture() -> (
            SessionJwtIssuer,
            SessionJwtVerifier,
            SessionJwtVerifier,
            SandboxRuntimeIdentity,
        ) {
            let key = KeyPair::generate_for(&PKCS_ED25519).expect("generate Ed25519 key");
            let public_key_pem = key.public_key_pem().into_bytes();
            let clock: Arc<dyn JwtClock> = Arc::new(FixedClock(1_900_000_000));
            let issuer = SessionJwtIssuer::from_ed25519_pem(
                key.serialize_pem().as_bytes(),
                "current",
                "test",
                DEFAULT_SESSION_TOKEN_TTL,
                clock.clone(),
            )
            .expect("issuer");
            let key = || SessionVerificationKey {
                key_id: "current".to_string(),
                public_key_pem: public_key_pem.clone(),
            };
            let gateway = SessionJwtVerifier::new(
                "test",
                SessionTokenProfile::Gateway,
                [key()],
                clock.clone(),
            )
            .expect("gateway verifier");
            let sandbox =
                SessionJwtVerifier::new("test", SessionTokenProfile::Sandbox, [key()], clock)
                    .expect("sandbox verifier");
            let identity = SandboxRuntimeIdentity {
                sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox ID"),
                runtime_generation: SandboxGenerationId::parse("generation-1")
                    .expect("runtime generation"),
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
            };
            (issuer, gateway, sandbox, identity)
        }

        #[test]
        fn token_profiles_are_not_interchangeable() {
            let (issuer, gateway, sandbox, identity) = fixture();
            let pair = issuer.mint_pair(&identity).expect("token pair");

            let gateway_session = gateway
                .verify(pair.gateway.token.expose_secret())
                .expect("gateway token");
            assert_eq!(gateway_session.auth_epoch, identity.auth_epoch);

            let sandbox_session = sandbox
                .verify(pair.sandbox.token.expose_secret())
                .expect("sandbox token");
            assert_eq!(sandbox_session.auth_epoch, identity.auth_epoch);

            assert_eq!(
                gateway.verify(pair.sandbox.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );
            assert_eq!(
                sandbox.verify(pair.gateway.token.expose_secret()),
                Err(SessionJwtError::WrongTokenType)
            );
        }

        fn registration_grant(identity: SandboxRuntimeIdentity) -> ControlRegistrationGrant {
            ControlRegistrationGrant {
                runtime_identity: identity,
                supervisor_instance_id: uuid::Uuid::new_v4(),
                boundary_session_id: uuid::Uuid::new_v4(),
                boundary_instance_id: uuid::Uuid::new_v4(),
                registration_revision: 7,
            }
        }

        #[test]
        fn configuration_activation_registration_profiles_are_not_interchangeable() {
            let (issuer, gateway, sandbox, identity) = fixture();
            let pair = issuer.mint_pair(&identity).expect("session pair");
            let grant = registration_grant(identity);
            let minted = issuer
                .mint_control_registration(&grant)
                .expect("registration token");
            let authenticated = sandbox
                .verify_control_registration(minted.token.expose_secret())
                .expect("authenticated registration");
            assert_eq!(authenticated.grant, grant);
            assert_eq!(authenticated.token_id, minted.token_id);
            assert_eq!(authenticated.issued_at, 1_900_000_000);
            assert_eq!(authenticated.expires_at, minted.expires_at);

            for verifier in [&gateway, &sandbox] {
                assert_eq!(
                    verifier.verify(minted.token.expose_secret()),
                    Err(SessionJwtError::WrongTokenType)
                );
                for session_token in [&pair.gateway.token, &pair.sandbox.token] {
                    assert_eq!(
                        verifier.verify_control_registration(session_token.expose_secret()),
                        Err(SessionJwtError::WrongTokenType)
                    );
                }
            }

            let renewed = issuer
                .mint_control_registration(&grant)
                .expect("renew registration token");
            assert_ne!(renewed.token_id, minted.token_id);
            assert_eq!(
                sandbox
                    .verify_control_registration(renewed.token.expose_secret())
                    .expect("renewed registration")
                    .grant,
                grant
            );
        }

        fn signed_registration_claims(
            mutate: impl FnOnce(&mut serde_json::Value),
        ) -> (SessionJwtVerifier, String) {
            let key = KeyPair::generate_for(&PKCS_ED25519).expect("generate Ed25519 key");
            let verifier = SessionJwtVerifier::new(
                "test",
                SessionTokenProfile::Sandbox,
                [SessionVerificationKey {
                    key_id: "current".to_string(),
                    public_key_pem: key.public_key_pem().into_bytes(),
                }],
                Arc::new(FixedClock(1_900_000_000)),
            )
            .expect("registration verifier");
            // Build the wire claims independently of the production struct so
            // malformed signed inputs exercise validation after deserialization.
            let mut claims = serde_json::json!({
                "iss": "openshell-gateway:test",
                "sub": "spiffe://openshell/sandbox/sandbox-a",
                "aud": CONTROL_REGISTRATION_AUDIENCE,
                "iat": 1_900_000_000_i64,
                "exp": 1_900_003_600_i64,
                "jti": uuid::Uuid::new_v4().to_string(),
                "sandbox_id": "sandbox-a",
                "runtime_generation": "generation-1",
                "auth_epoch": 1,
                "component": "openshell-supervisor",
                "supervisor_instance_id": uuid::Uuid::new_v4().to_string(),
                "boundary_session_id": uuid::Uuid::new_v4().to_string(),
                "boundary_instance_id": uuid::Uuid::new_v4().to_string(),
                "registration_revision": 7,
            });
            mutate(&mut claims);
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some("current".to_string());
            header.typ = Some(CONTROL_REGISTRATION_JWT_TYPE.to_string());
            let token = encode(
                &header,
                &claims,
                &EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).expect("encoding key"),
            )
            .expect("sign registration claims");
            (verifier, token)
        }

        #[test]
        fn configuration_activation_registration_accepts_exact_wire_profile() {
            let (verifier, token) = signed_registration_claims(|_| {});
            let authenticated = verifier
                .verify_control_registration(&token)
                .expect("valid signed registration claims");
            assert_eq!(authenticated.grant.registration_revision, 7);
            assert_eq!(
                authenticated.grant.runtime_identity.sandbox_id.as_str(),
                "sandbox-a"
            );
        }

        #[test]
        fn configuration_activation_registration_rejects_wrong_claim_purpose() {
            for (field, value, expected) in [
                (
                    "iss",
                    "openshell-gateway:other",
                    SessionJwtError::WrongIssuer,
                ),
                (
                    "aud",
                    SANDBOX_SESSION_AUDIENCE,
                    SessionJwtError::WrongAudience,
                ),
                (
                    "sub",
                    "spiffe://openshell/sandbox/another-sandbox",
                    SessionJwtError::SubjectMismatch,
                ),
            ] {
                let (verifier, token) = signed_registration_claims(|claims| {
                    claims[field] = serde_json::json!(value);
                });
                assert_eq!(verifier.verify_control_registration(&token), Err(expected));
            }
        }

        #[test]
        fn configuration_activation_registration_rejects_invalid_identity_claims() {
            for (field, value, expected) in [
                (
                    "runtime_generation",
                    serde_json::json!("Invalid/Generation"),
                    SessionJwtError::InvalidRuntimeIdentity,
                ),
                (
                    "auth_epoch",
                    serde_json::json!(0),
                    SessionJwtError::InvalidCredentialEpoch,
                ),
                (
                    "registration_revision",
                    serde_json::json!(0),
                    SessionJwtError::InvalidRegistrationRevision,
                ),
                (
                    "supervisor_instance_id",
                    serde_json::json!(uuid::Uuid::nil().to_string()),
                    SessionJwtError::InvalidRegistrationIdentity,
                ),
                (
                    "boundary_session_id",
                    serde_json::json!(uuid::Uuid::nil().to_string()),
                    SessionJwtError::InvalidRegistrationIdentity,
                ),
                (
                    "boundary_instance_id",
                    serde_json::json!(uuid::Uuid::nil().to_string()),
                    SessionJwtError::InvalidRegistrationIdentity,
                ),
            ] {
                let (verifier, token) = signed_registration_claims(|claims| {
                    claims[field] = value;
                });
                assert_eq!(verifier.verify_control_registration(&token), Err(expected));
            }
            let (verifier, token) = signed_registration_claims(|claims| {
                claims["sandbox_id"] = serde_json::json!(" ");
                claims["sub"] = serde_json::json!("spiffe://openshell/sandbox/ ");
            });
            assert_eq!(
                verifier.verify_control_registration(&token),
                Err(SessionJwtError::InvalidSandboxId)
            );
        }

        #[test]
        fn configuration_activation_registration_rejects_malformed_claim_shapes() {
            for (field, value) in [
                ("aud", serde_json::json!([CONTROL_REGISTRATION_AUDIENCE])),
                ("component", serde_json::json!("unknown-component")),
                ("supervisor_instance_id", serde_json::json!("not-a-uuid")),
                ("registration_revision", serde_json::json!(-1)),
                ("registration_revision", serde_json::Value::Null),
                ("unexpected_permission", serde_json::json!(true)),
            ] {
                let (verifier, token) = signed_registration_claims(|claims| {
                    claims[field] = value;
                });
                assert_eq!(
                    verifier.verify_control_registration(&token),
                    Err(SessionJwtError::InvalidToken)
                );
            }
        }

        #[test]
        fn configuration_activation_registration_rejects_stale_or_invalid_lifetimes() {
            for (issued_at, expires_at, expected) in [
                (1_899_996_000, 1_899_999_600, SessionJwtError::Expired),
                (
                    1_900_000_031,
                    1_900_003_600,
                    SessionJwtError::IssuedInFuture,
                ),
                (
                    1_900_000_000,
                    1_900_000_000,
                    SessionJwtError::InvalidLifetime,
                ),
                (
                    1_900_000_000,
                    1_900_003_601,
                    SessionJwtError::InvalidLifetime,
                ),
            ] {
                let (verifier, token) = signed_registration_claims(|claims| {
                    claims["iat"] = serde_json::json!(issued_at);
                    claims["exp"] = serde_json::json!(expires_at);
                });
                assert_eq!(verifier.verify_control_registration(&token), Err(expected));
            }
            for token_id in ["not-a-uuid".to_string(), uuid::Uuid::nil().to_string()] {
                let (verifier, token) = signed_registration_claims(|claims| {
                    claims["jti"] = serde_json::json!(token_id);
                });
                assert_eq!(
                    verifier.verify_control_registration(&token),
                    Err(SessionJwtError::InvalidJti)
                );
            }
        }

        #[test]
        fn configuration_activation_registration_rejects_wrong_signature() {
            let (issuer, _gateway, _sandbox, identity) = fixture();
            let (_other_issuer, _other_gateway, other_sandbox, _other_identity) = fixture();
            let minted = issuer
                .mint_control_registration(&registration_grant(identity))
                .expect("registration token");
            assert_eq!(
                other_sandbox.verify_control_registration(minted.token.expose_secret()),
                Err(SessionJwtError::InvalidToken)
            );
        }

        #[test]
        fn configuration_activation_registration_issuer_rejects_invalid_identity() {
            let (issuer, _gateway, _sandbox, identity) = fixture();
            let valid = registration_grant(identity);
            for field in 0..4 {
                let mut grant = valid.clone();
                match field {
                    0 => grant.supervisor_instance_id = uuid::Uuid::nil(),
                    1 => grant.boundary_session_id = uuid::Uuid::nil(),
                    2 => grant.boundary_instance_id = uuid::Uuid::nil(),
                    _ => grant.registration_revision = 0,
                }
                let expected = if field == 3 {
                    SessionJwtError::InvalidRegistrationRevision
                } else {
                    SessionJwtError::InvalidRegistrationIdentity
                };
                assert_eq!(
                    issuer
                        .mint_control_registration(&grant)
                        .expect_err("invalid grant"),
                    expected
                );
            }
        }

        #[test]
        fn token_debug_is_redacted() {
            let (issuer, _gateway, _sandbox, identity) = fixture();
            let pair = issuer.mint_pair(&identity).expect("token pair");
            let debug = format!("{:?}", pair.sandbox.token);
            assert_eq!(debug, "SecretJwt([REDACTED])");
            assert!(!debug.contains(pair.sandbox.token.expose_secret()));
        }

        #[test]
        fn supervisor_auth_bundle_round_trips_without_exposing_secrets_in_debug() {
            let (issuer, _gateway, _sandbox, identity) = fixture();
            let pair = issuer.mint_pair(&identity).expect("token pair");
            let bundle = SupervisorAuthBundle {
                session_id: SandboxSessionId::new(),
                session_rotation: SessionRotation::new(1).expect("session rotation"),
                runtime_generation: identity.runtime_generation.clone(),
                auth_epoch: identity.auth_epoch,
                gateway_token: pair.gateway.token,
                gateway_expires_at: pair.gateway.expires_at,
                sandbox_token: pair.sandbox.token,
                sandbox_expires_at: pair.sandbox.expires_at,
            };

            let encoded = serde_json::to_vec(&bundle).expect("serialize auth bundle");
            let decoded: SupervisorAuthBundle =
                serde_json::from_slice(&encoded).expect("deserialize auth bundle");
            assert_eq!(decoded.auth_epoch, bundle.auth_epoch);
            assert_eq!(
                decoded.gateway_token.expose_secret(),
                bundle.gateway_token.expose_secret()
            );
            assert_eq!(
                decoded.sandbox_token.expose_secret(),
                bundle.sandbox_token.expose_secret()
            );

            let debug = format!("{bundle:?}");
            assert!(!debug.contains(bundle.gateway_token.expose_secret()));
            assert!(!debug.contains(bundle.sandbox_token.expose_secret()));
            assert_eq!(debug.matches("[REDACTED]").count(), 2);
        }

        #[derive(Serialize)]
        struct AudienceArrayClaims<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: [&'a str; 1],
            iat: i64,
            exp: i64,
            jti: String,
            sandbox_id: &'a str,
            runtime_generation: &'a str,
            auth_epoch: CredentialEpoch,
            component: SessionComponent,
        }

        #[test]
        fn audience_arrays_are_rejected() {
            let key = KeyPair::generate_for(&PKCS_ED25519).expect("generate Ed25519 key");
            let clock: Arc<dyn JwtClock> = Arc::new(FixedClock(1_900_000_000));
            let verifier = SessionJwtVerifier::new(
                "test",
                SessionTokenProfile::Gateway,
                [SessionVerificationKey {
                    key_id: "current".to_string(),
                    public_key_pem: key.public_key_pem().into_bytes(),
                }],
                clock,
            )
            .expect("verifier");
            let claims = AudienceArrayClaims {
                iss: "openshell-gateway:test",
                sub: "spiffe://openshell/sandbox/sandbox-a",
                aud: ["openshell-gateway:test"],
                iat: 1_900_000_000,
                exp: 1_900_003_600,
                jti: uuid::Uuid::new_v4().to_string(),
                sandbox_id: "sandbox-a",
                runtime_generation: "generation-1",
                auth_epoch: CredentialEpoch::new(1).expect("auth epoch"),
                component: SessionComponent::OpenShellSupervisor,
            };
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some("current".to_string());
            header.typ = Some(GATEWAY_SESSION_JWT_TYPE.to_string());
            let token = encode(
                &header,
                &claims,
                &EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).expect("encoding key"),
            )
            .expect("token");
            assert_eq!(verifier.verify(&token), Err(SessionJwtError::InvalidToken));
        }
    }
}
