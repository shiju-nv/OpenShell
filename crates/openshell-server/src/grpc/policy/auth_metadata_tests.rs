// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Real signed bearers straddle a persisted rotation without changing launch identity.
struct AuthMetadataFixture {
    state: Arc<ServerState>,
    id: String,
    principal: Principal,
    retired_token_id: uuid::Uuid,
    authenticator: crate::auth::sandbox_jwt::SandboxSessionJwtAuthenticator,
    retired_headers: http::HeaderMap,
    current_headers: http::HeaderMap,
}

impl AuthMetadataFixture {
    async fn new() -> Self {
        use crate::auth::authenticator::Authenticator;
        use crate::auth::sandbox_session::{PersistedSandboxIdentity, RefreshRequestHash};

        let state = test_server_state().await;
        let id = uuid::Uuid::new_v4().to_string();
        let identity = PersistedSandboxIdentity::new().unwrap();
        let mut sandbox = test_sandbox(
            &id,
            "auth-metadata",
            openshell_policy::restrictive_default_policy(),
            Vec::new(),
        );
        identity.write(&mut sandbox.metadata.as_mut().unwrap().annotations);
        state.store.put_message(&sandbox).await.unwrap();
        let key = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
        let authority = Arc::new(
            crate::auth::sandbox_jwt::SandboxSessionJwtAuthority::from_pem(
                key.signing_key_pem.as_bytes(),
                key.public_key_pem.as_bytes(),
                key.kid,
                "test-gateway",
                std::time::Duration::from_hours(1),
            )
            .unwrap(),
        );
        let retired = authority.mint_persisted_launch(&id, &identity).unwrap();
        let authenticated = authority
            .verify_gateway_token(retired.supervisor.gateway_token.expose_secret())
            .unwrap();
        let successor = identity.next_gateway_token(
            RefreshRequestHash::from_extension_services(&[]),
            chrono::Utc::now().timestamp(),
            30,
        );
        crate::auth::sandbox_session::rotate_gateway_token(
            state.store.as_ref(),
            &authenticated,
            &successor,
        )
        .await
        .unwrap();
        let current = authority.mint_persisted_launch(&id, &successor).unwrap();
        let headers = |token: &str| {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "authorization",
                http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
            headers
        };
        let retired_headers = headers(retired.supervisor.gateway_token.expose_secret());
        let current_headers = headers(current.supervisor.gateway_token.expose_secret());
        let authenticator = crate::auth::sandbox_jwt::SandboxSessionJwtAuthenticator::new(
            authority,
            state.store.clone(),
        );
        let principal = authenticator
            .authenticate(&current_headers, "/openshell.v1.OpenShell/UpdateConfig")
            .await
            .unwrap()
            .unwrap();
        let fixture = Self {
            state,
            id,
            principal,
            retired_token_id: identity.gateway_token_id,
            authenticator,
            retired_headers,
            current_headers,
        };
        fixture.assert_bearer_authority().await;
        fixture
    }

    fn request(
        &self,
        update: UpdateConfigRequest,
        sandbox_caller: bool,
    ) -> Request<UpdateConfigRequest> {
        let mut request = Request::new(update);
        if sandbox_caller {
            request.extensions_mut().insert(self.principal.clone());
            request
        } else {
            with_user(request)
        }
    }

    async fn assert_bearer_authority(&self) {
        use crate::auth::authenticator::Authenticator;

        assert_eq!(
            self.authenticator
                .authenticate(
                    &self.retired_headers,
                    "/openshell.v1.OpenShell/UpdateConfig"
                )
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated,
            "policy metadata must not restore the retired signed bearer"
        );
        assert!(
            self.authenticator
                .authenticate(
                    &self.current_headers,
                    "/openshell.v1.OpenShell/UpdateConfig"
                )
                .await
                .unwrap()
                .is_some(),
            "current signed bearer must remain authorized"
        );
    }

    async fn persisted_state(
        &self,
    ) -> (
        Sandbox,
        Vec<PolicyRecord>,
        serde_json::Value,
        serde_json::Value,
    ) {
        // Capture policy history and settings as well as the sandbox CAS version;
        // rejection after a secondary write would otherwise escape this check.
        let settings_snapshot = |settings: StoredSettings| {
            // The stored payload omits resource_version, but a rejected update
            // must also leave the settings object's CAS metadata unchanged.
            serde_json::json!({
                "revision": settings.revision,
                "settings": settings.settings,
                "resource_version": settings.resource_version,
            })
        };
        (
            self.state
                .store
                .get_message::<Sandbox>(&self.id)
                .await
                .unwrap()
                .unwrap(),
            self.state
                .store
                .list_policies(&self.id, 100, 0)
                .await
                .unwrap(),
            settings_snapshot(
                load_sandbox_settings(self.state.store.as_ref(), "default", "auth-metadata")
                    .await
                    .unwrap(),
            ),
            settings_snapshot(
                load_global_settings(self.state.store.as_ref())
                    .await
                    .unwrap(),
            ),
        )
    }
}

#[tokio::test]
async fn update_config_auth_metadata_rejects_authority_annotations_without_mutation() {
    let fixture = AuthMetadataFixture::new().await;
    let before = fixture.persisted_state().await;
    let stored = &before.0.metadata.as_ref().unwrap().annotations;
    let replay_until = stored["internal.openshell.ai/refresh-replay-until"]
        .parse::<i64>()
        .unwrap();
    let issued_at = stored["internal.openshell.ai/refresh-issued-at"]
        .parse::<i64>()
        .unwrap();
    let changed = [
        (
            "internal.openshell.ai/gateway-token-id",
            fixture.retired_token_id.to_string(),
        ),
        (
            "internal.openshell.ai/previous-gateway-token-id",
            uuid::Uuid::from_u128(99).to_string(),
        ),
        (
            "internal.openshell.ai/refresh-replay-until",
            (replay_until + 60).to_string(),
        ),
        (
            "internal.openshell.ai/refresh-request-hash",
            crate::auth::sandbox_session::RefreshRequestHash::from_extension_services(&[
                "replacement-service".to_string(),
            ])
            .to_string(),
        ),
        (
            "internal.openshell.ai/refresh-issued-at",
            (issued_at - 1).to_string(),
        ),
        (
            "internal.openshell.ai/refresh-rotation-id",
            uuid::Uuid::from_u128(99).to_string(),
        ),
        (
            "internal.openshell.ai/runtime-generation",
            "replacement-runtime".to_string(),
        ),
        ("internal.openshell.ai/auth-epoch", "2".to_string()),
    ];
    for sandbox_caller in [true, false] {
        for (key, replacement) in &changed {
            for value in [replacement, &stored[*key]] {
                // Include ordinary provenance in the rejected request so a guard
                // that filters keys after persisting metadata cannot pass.
                let request = fixture.request(
                    UpdateConfigRequest {
                        name: "auth-metadata".to_string(),
                        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                        policy: before.0.spec.as_ref().unwrap().policy.clone(),
                        annotations: HashMap::from([
                            ((*key).to_string(), value.clone()),
                            (
                                "example.com/review-note".to_string(),
                                "must-not-persist".to_string(),
                            ),
                        ]),
                        ..Default::default()
                    },
                    sandbox_caller,
                );
                let result = handle_update_config(&fixture.state, request).await;
                if result.is_ok()
                    && sandbox_caller
                    && *key == "internal.openshell.ai/gateway-token-id"
                    && value == replacement
                {
                    use crate::auth::authenticator::Authenticator;

                    // If the authority write succeeds, establish its effect on
                    // real bearer authentication before reporting the rejection failure.
                    let restored = fixture.persisted_state().await;
                    assert_eq!(
                        restored.0.metadata.as_ref().unwrap().annotations[*key],
                        fixture.retired_token_id.to_string()
                    );
                    assert!(
                        fixture
                            .authenticator
                            .authenticate(
                                &fixture.retired_headers,
                                "/openshell.v1.OpenShell/UpdateConfig"
                            )
                            .await
                            .unwrap()
                            .is_some(),
                        "persisted rollback restores fresh authentication of the retired bearer"
                    );
                    eprintln!(
                        "Observed: policy annotations restored the retired gateway bearer and fresh authentication accepted it"
                    );
                }
                let error = result.expect_err("auth metadata must be rejected before any mutation");
                assert_eq!(
                    error.code(),
                    Code::InvalidArgument,
                    "{key}, sandbox={sandbox_caller}"
                );
                assert_eq!(
                    fixture.persisted_state().await,
                    before,
                    "{key}, sandbox={sandbox_caller}"
                );
                fixture.assert_bearer_authority().await;
            }
        }
    }
}

#[tokio::test]
async fn update_config_auth_metadata_rejects_setting_before_mutation() {
    let fixture = AuthMetadataFixture::new().await;
    let before = fixture.persisted_state().await;
    let request = fixture.request(
        UpdateConfigRequest {
            name: "auth-metadata".to_string(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            setting_key: settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY.to_string(),
            setting_value: Some(SettingValue {
                value: Some(setting_value::Value::BoolValue(true)),
            }),
            annotations: HashMap::from([(
                "internal.openshell.ai/gateway-token-id".to_string(),
                fixture.retired_token_id.to_string(),
            )]),
            ..Default::default()
        },
        false,
    );
    let error = handle_update_config(&fixture.state, request)
        .await
        .expect_err("authority metadata must be rejected before the settings write");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(fixture.persisted_state().await, before);
    fixture.assert_bearer_authority().await;
}

#[tokio::test]
async fn update_config_auth_metadata_preserves_ordinary_annotations() {
    for sandbox_caller in [true, false] {
        let fixture = AuthMetadataFixture::new().await;
        let before = fixture.persisted_state().await;
        let identity_before = crate::auth::sandbox_session::PersistedSandboxIdentity::read(
            &before.0.metadata.as_ref().unwrap().annotations,
        )
        .unwrap();
        let annotations = HashMap::from([
            (
                "example.com/review-note".to_string(),
                "retained".to_string(),
            ),
            (
                "internal.openshell.ai/operator-note".to_string(),
                "also-retained".to_string(),
            ),
        ]);
        let request = fixture.request(
            UpdateConfigRequest {
                name: "auth-metadata".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                policy: before.0.spec.as_ref().unwrap().policy.clone(),
                annotations: annotations.clone(),
                ..Default::default()
            },
            sandbox_caller,
        );
        let response = handle_update_config(&fixture.state, request)
            .await
            .expect("ordinary policy annotations remain supported")
            .into_inner();
        let after = fixture.persisted_state().await;
        let metadata = after.0.metadata.as_ref().unwrap();
        for (key, value) in &annotations {
            assert_eq!(metadata.annotations.get(key), Some(value));
            assert_eq!(response.annotations.get(key), Some(value));
        }
        assert!(metadata.resource_version > before.0.metadata.as_ref().unwrap().resource_version);
        assert_eq!(
            crate::auth::sandbox_session::PersistedSandboxIdentity::read(&metadata.annotations)
                .unwrap(),
            identity_before,
            "ordinary metadata must preserve the entire token and replay identity"
        );
        let latest = fixture
            .state
            .store
            .get_latest_policy(&fixture.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.provenance, annotations);
        assert_eq!(latest.version, i64::from(response.version));
        assert_eq!((after.2, after.3), (before.2, before.3));
        fixture.assert_bearer_authority().await;
    }
}
