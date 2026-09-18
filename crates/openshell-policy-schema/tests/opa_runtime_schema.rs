// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_policy_schema::opa::{OpaSchemaErrorKind, normalize_opa_policy};
use serde_json::{Value, json};

fn policy_with_endpoint(endpoint: Value) -> Value {
    json!({"network_policies": {"example": {"endpoints": [endpoint]}}})
}

fn rejects(value: Value) {
    assert!(
        normalize_opa_policy(value.clone()).is_err(),
        "invalid input accepted: {value}"
    );
}

#[test]
fn versionless_runtime_input_preserves_application_data() {
    let application = json!({"allow": {"method": "GET"}, "opaque": [false, null, 7]});
    let input = json!({"deny_source": application, "runtime": {"require_binary_identity": false}});
    let normalized = normalize_opa_policy(input).unwrap();
    assert_eq!(normalized["deny_source"], application);
    assert_eq!(normalized["runtime"]["require_binary_identity"], false);
    assert!(normalized.get("version").is_none());
    assert_eq!(normalized["filesystem_policy"]["include_workdir"], true);
    for version in [json!(0), json!(2), json!("1"), Value::Null, json!(true)] {
        rejects(json!({"version": version}));
    }
}

#[test]
fn filesystem_presence_uses_canonical_defaults_without_rewriting_paths() {
    for (input, expected) in [
        (json!({}), true),
        (json!({"filesystem_policy": {}}), false),
        (
            json!({"filesystem_policy": {"read_only": ["/usr//./lib/"]}}),
            false,
        ),
        (
            json!({"filesystem_policy": {"include_workdir": true}}),
            true,
        ),
        (
            json!({"filesystem_policy": {"include_workdir": false}}),
            false,
        ),
    ] {
        let normalized = normalize_opa_policy(input.clone()).unwrap();
        assert_eq!(normalized["filesystem_policy"]["include_workdir"], expected);
        if let Some(paths) = input.pointer("/filesystem_policy/read_only") {
            assert_eq!(normalized["filesystem_policy"]["read_only"], *paths);
        }
        assert_eq!(
            normalize_opa_policy(normalized.clone()).unwrap(),
            normalized
        );
    }
}

#[test]
fn rejects_wrong_scalar_types_and_explicit_nulls() {
    for section in [
        "filesystem_policy",
        "landlock",
        "process",
        "network_policies",
        "network_middlewares",
    ] {
        for invalid in [
            Value::Null,
            json!(false),
            json!(1),
            json!("value"),
            json!([]),
        ] {
            rejects(json!({section: invalid}));
        }
    }
    for invalid in [Value::Null, json!("false"), json!(0), json!([]), json!({})] {
        rejects(json!({"filesystem_policy": {"include_workdir": invalid}}));
    }
    for field in ["read_only", "read_write"] {
        for invalid in [
            Value::Null,
            json!("/tmp"),
            json!(["/tmp", 7]),
            json!([false]),
            json!([null]),
        ] {
            rejects(json!({"filesystem_policy": {field: invalid}}));
        }
    }
    for identity in ["run_as_user", "run_as_group"] {
        for invalid in [Value::Null, json!(1000), json!(false), json!([]), json!({})] {
            rejects(json!({"process": {identity: invalid}}));
        }
    }
}

#[test]
fn landlock_uses_exact_canonical_vocabulary() {
    for compatibility in ["best_effort", "hard_requirement"] {
        let input = json!({"landlock": {"compatibility": compatibility}});
        let normalized = normalize_opa_policy(input).unwrap();
        assert_eq!(normalized["landlock"]["compatibility"], compatibility);
    }
    normalize_opa_policy(json!({"landlock": {}})).unwrap();
    for invalid in [
        json!(""),
        json!("BEST_EFFORT"),
        json!("best-effort"),
        json!("strict"),
        Value::Null,
        json!(false),
    ] {
        rejects(json!({"landlock": {"compatibility": invalid}}));
    }
}

#[test]
fn landlock_runtime_requires_a_string_representation() {
    for compatibility in ["best_effort", "hard_requirement"] {
        let input = json!({"landlock": {"compatibility": compatibility}});
        let normalized = normalize_opa_policy(input).unwrap();
        assert_eq!(normalized["landlock"]["compatibility"], compatibility);
        // A tagged unit enum is valid serde input, but raw OPA string readers
        // would treat it as absent and select best-effort enforcement.
        rejects(json!({"landlock": {"compatibility": {compatibility: null}}}));
    }
}

#[test]
fn governed_nested_objects_reject_unknown_fields() {
    let unknown = json!({"unexpected": "secret-payload"});
    for section in ["filesystem_policy", "landlock", "process"] {
        rejects(json!({section: unknown}));
    }
    for input in [
        json!({"network_policies": {"example": unknown}}),
        json!({"network_policies": {"example": {"binaries": [{"path": "/bin/app", "unexpected": true}]}}}),
        json!({"network_middlewares": {"audit": {"middleware": "logger", "unexpected": true}}}),
        json!({"network_middlewares": {"audit": {"middleware": "logger", "endpoints": unknown}}}),
        json!({"runtime": {"require_binary_identity": true, "unexpected": true}}),
    ] {
        rejects(input);
    }
    for endpoint in [
        unknown.clone(),
        json!({"credential_binding": {"provider": "example", "unexpected": true}}),
        json!({"json_rpc": unknown}),
        json!({"protocol": "mcp", "mcp": unknown}),
        json!({"graphql_persisted_queries": {"hash": unknown}}),
        json!({"rules": [{"allow": {}, "unexpected": true}]}),
        json!({"rules": [{"allow": unknown}]}),
        json!({"deny_rules": [unknown]}),
        json!({"rules": [{"allow": {"query": {"q": {"any": ["x"], "unexpected": true}}}}]}),
        json!({"rules": [{"allow": {"tool": {"glob": "read_*", "unexpected": true}}}]}),
        json!({"rules": [{"allow": {"params": {"nested": {"name": {"any": ["x"], "unexpected": true}}}}}]}),
        json!({"rules": [{"allow": {"review": unknown}}]}),
        json!({"review": unknown}),
    ] {
        rejects(policy_with_endpoint(endpoint));
    }
}

#[test]
fn runtime_profile_rejects_managed_metadata_and_review_annotations() {
    rejects(json!({"metadata": {}}));
    rejects(policy_with_endpoint(json!({"review": {}})));
    rejects(policy_with_endpoint(
        json!({"rules": [{"allow": {"review": {}}}]}),
    ));
    rejects(policy_with_endpoint(json!({"protocol": "rest", "mcp": {}})));
}

#[test]
fn endpoint_scalars_use_canonical_types() {
    for field in [
        "allow_encoded_slash",
        "websocket_credential_rewrite",
        "request_body_credential_rewrite",
        "allow_uninspected_credentials",
        "provider_credentialed",
        "advisor_proposed",
    ] {
        for invalid in [json!("false"), json!(0), Value::Null] {
            rejects(policy_with_endpoint(json!({field: invalid})));
        }
    }
    for field in [
        "host",
        "path",
        "protocol",
        "tls",
        "enforcement",
        "access",
        "persisted_queries",
        "credential_signing",
        "signing_service",
        "signing_region",
    ] {
        for invalid in [json!(false), json!(17), Value::Null] {
            rejects(policy_with_endpoint(json!({field: invalid})));
        }
    }
    for endpoint in [
        json!({"port": 65536}),
        json!({"port": -1}),
        json!({"ports": [443, "80"]}),
        json!({"allowed_ips": [false]}),
        json!({"graphql_max_body_bytes": 4_294_967_296_u64}),
        json!({"credential_binding": {"provider": 1}}),
        json!({"graphql_persisted_queries": {"hash": {"fields": [1]}}}),
        json!({"rules": [{"allow": {"method": false}}]}),
        json!({"deny_rules": [{"fields": [false]}]}),
    ] {
        rejects(policy_with_endpoint(endpoint));
    }
}

#[test]
fn positional_sequences_cannot_replace_named_policy_objects() {
    for input in [
        json!({"runtime": []}),
        json!({"network_policies": {"example": {"binaries": [["/bin/app"]]}}}),
        json!({"network_middlewares": {"audit": ["name", "logger"]}}),
        json!({"network_middlewares": {"audit": {"middleware": "logger", "endpoints": []}}}),
    ] {
        rejects(input);
    }
    for endpoint in [
        json!({"json_rpc": []}),
        json!({"protocol": "mcp", "mcp": []}),
        json!({"credential_binding": ["provider"]}),
        json!({"graphql_persisted_queries": {"hash": []}}),
        json!({"rules": [{"allow": {"query": {"q": []}}}]}),
        json!({"rules": [{"allow": {"params": {"q": []}}}]}),
    ] {
        rejects(policy_with_endpoint(endpoint));
    }
}

#[test]
fn lowered_fields_reuse_config_types_and_reject_nulls_conflicts_and_invalid_revisions() {
    for field in ["mcp_strict_tool_names", "mcp_allow_all_known_mcp_methods"] {
        for invalid in [json!("false"), json!(0), Value::Null] {
            rejects(policy_with_endpoint(
                json!({"protocol": "mcp", field: invalid}),
            ));
        }
        rejects(policy_with_endpoint(
            json!({"protocol": "rest", field: true}),
        ));
    }
    for invalid in [
        Value::Null,
        json!("2025-11-25"),
        json!([]),
        json!([false]),
        json!(["unknown"]),
        json!(["2025-11-25", "2025-11-25"]),
    ] {
        rejects(policy_with_endpoint(
            json!({"protocol": "mcp", "mcp_versions": invalid}),
        ));
    }
    for invalid in [
        Value::Null,
        json!("1024"),
        json!(-1),
        json!(4_294_967_296_u64),
        json!(false),
    ] {
        rejects(policy_with_endpoint(
            json!({"protocol": "json-rpc", "json_rpc_max_body_bytes": invalid}),
        ));
    }
    for endpoint in [
        json!({"json_rpc": {"max_body_bytes": 1024}, "json_rpc_max_body_bytes": 2048}),
        json!({"protocol": "mcp", "json_rpc": {"max_body_bytes": 1024}, "json_rpc_max_body_bytes": 2048}),
        json!({"protocol": "mcp", "mcp": {"max_body_bytes": 1024}, "json_rpc_max_body_bytes": 2048}),
        json!({"protocol": "mcp", "mcp": {"versions": ["2025-11-25"]}, "mcp_versions": ["2025-11-25"]}),
        json!({"protocol": "mcp", "mcp": {"strict_tool_names": true}, "mcp_strict_tool_names": false}),
    ] {
        let error = normalize_opa_policy(policy_with_endpoint(endpoint)).unwrap_err();
        assert_eq!(error.kind(), OpaSchemaErrorKind::ConflictingFields);
    }
}

#[test]
fn runtime_provenance_binary_entries_matchers_and_open_config_survive() {
    let input = json!({
        "network_policies": {"example": {
            "name": "example", "binaries": [{"path": "/usr/bin/python3"}, {"path": "/usr/bin/python3.11"}],
            "endpoints": [{"host": "mcp.example", "port": 443, "protocol": "mcp",
                "provider_credentialed": true, "advisor_proposed": true,
                "credential_binding": {"provider": "example"},
                "json_rpc_max_body_bytes": 1024, "mcp_versions": ["2025-03-26", "2025-11-25"],
                "mcp_strict_tool_names": true, "mcp_allow_all_known_mcp_methods": false,
                "rules": [{"allow": {"method": "tools/call", "tool": {"glob": "read_*"},
                    "query": {"empty": "", "explicit_empty": {"glob": ""}},
                    "params": {"arguments": {"nested": {"glob": "*"}}, "name": {"any": ["read_status"]}}}}],
                "deny_rules": [{"query": {"empty": ""}}]
            }]
        }},
        "network_middlewares": {"audit": {"middleware": "logger", "config": {
            "arbitrary": {"glob": {"not_a_matcher": [false, null]}}, "token": "fixture-secret"
        }}},
        "runtime": {"require_binary_identity": true}
    });
    let normalized = normalize_opa_policy(input.clone()).unwrap();
    for field in ["network_policies", "network_middlewares", "runtime"] {
        assert_eq!(
            normalized[field], input[field],
            "runtime data changed: {field}"
        );
    }
    assert_eq!(
        normalize_opa_policy(normalized.clone()).unwrap(),
        normalized
    );
}

#[test]
fn opa_bare_allow_rules_are_validated_without_rewriting_them() {
    let endpoint =
        json!({"rules": [{"method": "GET", "path": "/status", "query": {"q": {"glob": "*"}}}]});
    let input = policy_with_endpoint(endpoint);
    let normalized = normalize_opa_policy(input.clone()).unwrap();
    assert_eq!(normalized["network_policies"], input["network_policies"]);
    rejects(policy_with_endpoint(json!({"rules": [{"method": false}]})));
    rejects(policy_with_endpoint(
        json!({"rules": [{"unexpected": "value"}]}),
    ));
}

#[test]
fn errors_are_bounded_and_never_retain_policy_payloads() {
    let secret = "sensitive-credential-🦀".repeat(1000);
    for input in [
        json!({"filesystem_policy": {secret.clone(): secret}}),
        json!({"landlock": {"compatibility": secret}}),
        policy_with_endpoint(json!({"protocol": "mcp", "mcp_versions": [secret]})),
        policy_with_endpoint(
            json!({"rules": [{"allow": {"tool": {"glob": false, secret.clone(): secret}}}]}),
        ),
    ] {
        let error = normalize_opa_policy(input).unwrap_err();
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(rendered.len() <= 256, "schema error exceeded its bound");
            assert!(!rendered.contains("sensitive"));
            assert!(!rendered.contains('🦀'));
        }
        assert!(std::error::Error::source(&error).is_none());
    }
}
