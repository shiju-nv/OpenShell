// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Schema boundary for OPA runtime policy data.
//!
//! OPA data may omit `version`, contain application data at the root, and carry
//! lowered endpoint fields, explicit glob matchers, and runtime provenance.
//! Governed policy sections share the authored schema's types and closed-object
//! checks. A validation projection removes only the OPA-specific differences;
//! it never replaces the original data with an authored or protobuf round trip.

use std::fmt;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{POLICY_ROOT_FIELDS, ParseProfile, PolicyDocument};

/// Payload-free failure category for OPA schema validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaSchemaErrorKind {
    /// A governed policy value has an invalid type or required field.
    InvalidShape,
    /// A closed policy object contains an unsupported field.
    UnknownField,
    /// A value violates the canonical runtime profile.
    InvalidProfile,
    /// Authored and lowered spellings specify the same runtime setting.
    ConflictingFields,
}

/// Bounded schema failure containing only a fixed category and schema location.
///
/// Source values, user-defined map keys, and underlying serde diagnostics are
/// deliberately excluded because policy input can contain credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpaSchemaError {
    kind: OpaSchemaErrorKind,
    section: &'static str,
}

impl OpaSchemaError {
    /// Return the stable failure category.
    #[must_use]
    pub const fn kind(self) -> OpaSchemaErrorKind {
        self.kind
    }

    /// Return a fixed schema location without user-provided identifiers.
    #[must_use]
    pub const fn section(self) -> &'static str {
        self.section
    }

    const fn new(kind: OpaSchemaErrorKind, section: &'static str) -> Self {
        Self { kind, section }
    }

    const fn shape(section: &'static str) -> Self {
        Self::new(OpaSchemaErrorKind::InvalidShape, section)
    }
}

impl fmt::Display for OpaSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            OpaSchemaErrorKind::InvalidShape => "invalid value type or structure",
            OpaSchemaErrorKind::UnknownField => "unsupported field in closed object",
            OpaSchemaErrorKind::InvalidProfile => "value is not valid in a runtime policy",
            OpaSchemaErrorKind::ConflictingFields => "conflicting authored and lowered fields",
        };
        write!(formatter, "{}: {message}", self.section)
    }
}

impl std::error::Error for OpaSchemaError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeControls {
    #[serde(default)]
    require_binary_identity: bool,
}

/// Validate governed OPA data and materialize the canonical filesystem default.
///
/// The input should come from the bounded raw parser. Unrelated root data and
/// open middleware configuration remain unchanged. Omitted filesystem policy
/// enables workdir access; a present empty object disables it. Other lowering
/// and protocol-specific authorization checks remain the runtime owner's job.
/// Explicit matcher objects and empty scalar query matchers remain unchanged:
/// Rego distinguishes an empty scalar from an empty glob object.
///
/// The `runtime` section is shape-checked but grants no authority to choose the
/// binary-identity mode. The caller must inject its trusted runtime setting.
///
/// # Errors
///
/// Returns a bounded, payload-free error for malformed governed values, unknown
/// nested fields, unsupported runtime metadata, or ambiguous lowered settings.
pub fn normalize_opa_policy(mut value: Value) -> Result<Value, OpaSchemaError> {
    let root = value
        .as_object_mut()
        .ok_or_else(|| OpaSchemaError::shape("policy"))?;
    for section in ["filesystem_policy", "landlock", "process", "runtime"] {
        require_object_field(root, section)?;
    }
    if root
        .get("landlock")
        .and_then(|section| section.get("compatibility"))
        .is_some_and(|compatibility| !compatibility.is_string())
    {
        // Serde unit enums also accept tagged objects. The OPA consumer reads
        // this field as a string, so other representations cannot be retained.
        return Err(OpaSchemaError::shape("landlock.compatibility"));
    }
    if let Some(runtime) = root.get("runtime") {
        let controls: RuntimeControls = serde_json::from_value(runtime.clone())
            .map_err(|_| OpaSchemaError::shape("runtime"))?;
        // Validation must not make the caller-supplied mode authoritative.
        let _ = controls.require_binary_identity;
    }

    // Only the validation copy loses runtime-specific fields. This prevents a
    // typed authored conversion from resetting credential/advisor provenance.
    let mut projection: Map<String, Value> = root
        .iter()
        .filter(|(key, _)| POLICY_ROOT_FIELDS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    projection.entry("version").or_insert(Value::from(1));
    project_network_policies(&mut projection)?;
    validate_middleware_shapes(&projection)?;

    let projection = Value::Object(projection);
    let authored: PolicyDocument =
        serde_json::from_value(projection.clone()).map_err(|_| OpaSchemaError::shape("policy"))?;
    let yaml = serde_yml::to_value(&projection).map_err(|_| OpaSchemaError::shape("policy"))?;
    let extensions = crate::collect_extensions(&yaml);
    if !extensions.is_empty() {
        return Err(OpaSchemaError::new(
            OpaSchemaErrorKind::UnknownField,
            "policy",
        ));
    }
    crate::validate_profile(&authored, &extensions, ParseProfile::RuntimeStrict)
        .map_err(|_| OpaSchemaError::new(OpaSchemaErrorKind::InvalidProfile, "policy"))?;

    let filesystem = authored.effective_filesystem_policy();
    // Preserve supplied path lists verbatim. Only the presence-sensitive boolean
    // requires materialization before the runtime's optional-value readers run.
    let section = root
        .entry("filesystem_policy")
        .or_insert_with(|| Value::Object(Map::new()));
    let section = section
        .as_object_mut()
        .ok_or_else(|| OpaSchemaError::shape("filesystem_policy"))?;
    section.insert(
        "include_workdir".to_owned(),
        Value::Bool(filesystem.include_workdir),
    );
    Ok(value)
}

fn project_network_policies(root: &mut Map<String, Value>) -> Result<(), OpaSchemaError> {
    let Some(policies) = root.get_mut("network_policies") else {
        return Ok(());
    };
    let policies = policies
        .as_object_mut()
        .ok_or_else(|| OpaSchemaError::shape("network_policies"))?;
    for policy in policies.values_mut() {
        let policy = policy
            .as_object_mut()
            .ok_or_else(|| OpaSchemaError::shape("network_policies.*"))?;
        if let Some(binaries) = policy.get("binaries") {
            let binaries = binaries
                .as_array()
                .ok_or_else(|| OpaSchemaError::shape("network_policies.*.binaries"))?;
            for binary in binaries {
                require_object(binary, "network_policies.*.binaries[]")?;
            }
        }
        let Some(endpoints) = policy.get_mut("endpoints") else {
            continue;
        };
        let endpoints = endpoints
            .as_array_mut()
            .ok_or_else(|| OpaSchemaError::shape("network_policies.*.endpoints"))?;
        for endpoint in endpoints {
            let endpoint = endpoint
                .as_object_mut()
                .ok_or_else(|| OpaSchemaError::shape("network_policies.*.endpoints[]"))?;
            project_endpoint(endpoint)?;
        }
    }
    Ok(())
}

fn project_endpoint(endpoint: &mut Map<String, Value>) -> Result<(), OpaSchemaError> {
    for section in ["credential_binding", "json_rpc", "mcp"] {
        require_object_field(endpoint, section)?;
    }
    if endpoint.contains_key("json_rpc_max_body_bytes")
        && ["json_rpc", "mcp"].iter().any(|stanza| {
            endpoint
                .get(*stanza)
                .and_then(Value::as_object)
                .is_some_and(|config| config.contains_key("max_body_bytes"))
        })
    {
        // Both authored stanzas lower to the same runtime body limit. Reject a
        // second spelling before protocol selection can hide that overlap.
        return Err(OpaSchemaError::new(
            OpaSchemaErrorKind::ConflictingFields,
            "json_rpc_max_body_bytes",
        ));
    }
    if let Some(operations) = endpoint.get("graphql_persisted_queries") {
        for operation in require_object(operations, "graphql_persisted_queries")?.values() {
            require_object(operation, "graphql_persisted_queries.*")?;
        }
    }
    for field in ["provider_credentialed", "advisor_proposed"] {
        if let Some(value) = endpoint.remove(field)
            && !value.is_boolean()
        {
            return Err(OpaSchemaError::shape(field));
        }
    }
    let is_mcp = endpoint
        .get("protocol")
        .and_then(Value::as_str)
        .is_some_and(|protocol| protocol.eq_ignore_ascii_case("mcp"));
    for (lowered, authored) in [
        ("mcp_versions", "versions"),
        ("mcp_strict_tool_names", "strict_tool_names"),
        (
            "mcp_allow_all_known_mcp_methods",
            "allow_all_known_mcp_methods",
        ),
    ] {
        project_config_field(endpoint, lowered, "mcp", authored)?;
    }
    project_config_field(
        endpoint,
        "json_rpc_max_body_bytes",
        if is_mcp { "mcp" } else { "json_rpc" },
        "max_body_bytes",
    )?;

    if let Some(rules) = endpoint.get_mut("rules") {
        let rules = rules
            .as_array_mut()
            .ok_or_else(|| OpaSchemaError::shape("network_policies.*.endpoints[].rules"))?;
        for rule in rules {
            let object = rule
                .as_object_mut()
                .ok_or_else(|| OpaSchemaError::shape("network_policies.*.endpoints[].rules[]"))?;
            // OPA accepts a bare allow object as well as the authored wrapper.
            // Wrapping only this validation copy preserves the runtime shape.
            if !object.contains_key("allow") {
                let allow = Value::Object(std::mem::take(object));
                object.insert("allow".to_owned(), allow);
            }
            if let Some(allow) = object.get_mut("allow") {
                project_rule(allow)?;
            }
        }
    }
    if let Some(denies) = endpoint.get_mut("deny_rules") {
        let denies = denies
            .as_array_mut()
            .ok_or_else(|| OpaSchemaError::shape("network_policies.*.endpoints[].deny_rules"))?;
        for deny in denies {
            project_rule(deny)?;
        }
    }
    Ok(())
}

fn project_config_field(
    endpoint: &mut Map<String, Value>,
    lowered: &'static str,
    stanza: &'static str,
    field: &'static str,
) -> Result<(), OpaSchemaError> {
    let Some(value) = endpoint.remove(lowered) else {
        return Ok(());
    };
    let config = endpoint
        .entry(stanza)
        .or_insert_with(|| Value::Object(Map::new()));
    let config = config
        .as_object_mut()
        .ok_or_else(|| OpaSchemaError::shape(stanza))?;
    if config.contains_key(field) {
        return Err(OpaSchemaError::new(
            OpaSchemaErrorKind::ConflictingFields,
            lowered,
        ));
    }
    // Decode the lowered value through the canonical config type later; this
    // shares exact booleans, integer ranges, null rules, and MCP vocabulary.
    config.insert(field.to_owned(), value);
    Ok(())
}

fn project_rule(rule: &mut Value) -> Result<(), OpaSchemaError> {
    let rule = rule
        .as_object_mut()
        .ok_or_else(|| OpaSchemaError::shape("network_policies.*.endpoints[].rule"))?;
    if let Some(query) = rule.get_mut("query") {
        let query = query
            .as_object_mut()
            .ok_or_else(|| OpaSchemaError::shape("query"))?;
        for matcher in query.values_mut() {
            project_matcher(matcher, false)?;
        }
    }
    if let Some(tool) = rule.get_mut("tool") {
        project_matcher(tool, false)?;
    }
    if let Some(params) = rule.get_mut("params") {
        let params = params
            .as_object_mut()
            .ok_or_else(|| OpaSchemaError::shape("params"))?;
        for matcher in params.values_mut() {
            project_matcher(matcher, true)?;
        }
    }
    Ok(())
}

fn project_matcher(value: &mut Value, nested: bool) -> Result<(), OpaSchemaError> {
    if value.is_string() {
        return Ok(());
    }
    let Some(object) = value.as_object_mut() else {
        return Err(OpaSchemaError::shape("matcher"));
    };
    if object.contains_key("glob") {
        if object.len() != 1 {
            return Err(OpaSchemaError::new(
                OpaSchemaErrorKind::UnknownField,
                "matcher",
            ));
        }
        let glob = object
            .remove("glob")
            .filter(Value::is_string)
            .ok_or_else(|| OpaSchemaError::shape("matcher.glob"))?;
        *value = glob;
    } else if nested && !object.contains_key("any") {
        // Parameter names form an open recursive namespace; only leaf matcher
        // operators are closed. Never interpret middleware config as matchers.
        for child in object.values_mut() {
            project_matcher(child, true)?;
        }
    }
    Ok(())
}

fn require_object<'a>(
    value: &'a Value,
    section: &'static str,
) -> Result<&'a Map<String, Value>, OpaSchemaError> {
    // Serde struct visitors can also accept positional sequences. Policy
    // sections require named objects even when all their fields have defaults.
    value
        .as_object()
        .ok_or_else(|| OpaSchemaError::shape(section))
}

fn require_object_field(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<(), OpaSchemaError> {
    if let Some(value) = object.get(field) {
        require_object(value, field)?;
    }
    Ok(())
}

fn validate_middleware_shapes(root: &Map<String, Value>) -> Result<(), OpaSchemaError> {
    let Some(middlewares) = root.get("network_middlewares") else {
        return Ok(());
    };
    for middleware in require_object(middlewares, "network_middlewares")?.values() {
        let middleware = require_object(middleware, "network_middlewares.*")?;
        require_object_field(middleware, "endpoints")?;
    }
    Ok(())
}
