// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical representation of the `OpenShell` authored policy language.
//!
//! This dependency-light crate owns authored YAML/JSON serde, bounded parsing,
//! pure authored/OPA schema validation, and lexical policy-path normalization.
//! Runtime enforcement and protobuf adaptation live in their consuming crates.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Deserializer, Serialize};

/// Validation and normalization of OPA runtime policy data.
pub mod opa;

/// Fixed batch-member bound for the MCP 2025-03-26 wire profile.
pub const MAX_MCP_LEGACY_BATCH_MESSAGES: usize = 64;

/// Stable MCP protocol revisions accepted in authored policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum McpProtocolVersion {
    V2025_03_26,
    V2025_06_18,
    V2025_11_25,
}

/// Pinned revision used when authored policy omits MCP versions.
pub const DEFAULT_MCP_PROTOCOL_VERSION: McpProtocolVersion = McpProtocolVersion::V2025_11_25;

/// Shared remediation text for unsupported authored MCP protocol revisions.
pub const MCP_VERSION_REMEDIATION: &str = "omit mcp.versions to use the pinned default revision, use an exact supported revision, or omit protocol and mcp for deliberate uninspected L4 passthrough only when that weaker boundary is acceptable";

impl McpProtocolVersion {
    /// Every supported revision in chronological order.
    pub const ALL: &'static [Self] = &[Self::V2025_03_26, Self::V2025_06_18, Self::V2025_11_25];

    /// Return the exact revision spelling used in policy and protocol headers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2025_03_26 => "2025-03-26",
            Self::V2025_06_18 => "2025-06-18",
            Self::V2025_11_25 => "2025-11-25",
        }
    }

    /// Return the batch rules for this exact revision without selecting defaults.
    #[must_use]
    pub const fn wire_profile(self) -> McpWireProfile {
        match self {
            Self::V2025_03_26 => McpWireProfile {
                version: self,
                allows_json_rpc_batches: true,
                max_batch_messages: Some(MAX_MCP_LEGACY_BATCH_MESSAGES),
            },
            Self::V2025_06_18 | Self::V2025_11_25 => McpWireProfile {
                version: self,
                allows_json_rpc_batches: false,
                max_batch_messages: None,
            },
        }
    }
}

impl fmt::Display for McpProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for McpProtocolVersion {
    type Err = ParseMcpProtocolVersionError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "2025-03-26" => Ok(Self::V2025_03_26),
            "2025-06-18" => Ok(Self::V2025_06_18),
            "2025-11-25" => Ok(Self::V2025_11_25),
            _ => Err(ParseMcpProtocolVersionError {
                value: value.to_owned(),
            }),
        }
    }
}

/// Unsupported MCP revision retaining the original input for caller diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMcpProtocolVersionError {
    value: String,
}

impl ParseMcpProtocolVersionError {
    /// Return the rejected revision text without normalization or redaction.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for ParseMcpProtocolVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported MCP protocol version '{}'",
            self.value
        )
    }
}

impl std::error::Error for ParseMcpProtocolVersionError {}

/// Immutable batch-shape metadata for an exact MCP revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct McpWireProfile {
    version: McpProtocolVersion,
    allows_json_rpc_batches: bool,
    max_batch_messages: Option<usize>,
}

impl McpWireProfile {
    /// Return the exact revision whose wire rules this profile describes.
    #[must_use]
    pub const fn version(self) -> McpProtocolVersion {
        self.version
    }

    /// Whether this revision permits JSON-RPC batch messages.
    #[must_use]
    pub const fn allows_json_rpc_batches(self) -> bool {
        self.allows_json_rpc_batches
    }

    /// Return the batch-member limit, or `None` when this revision forbids batches.
    #[must_use]
    pub const fn max_batch_messages(self) -> Option<usize> {
        self.max_batch_messages
    }
}

/// Authored policy syntax preserving omitted sections for effective defaults.
///
/// Profile-aware parsing also enforces versions, closed objects, and runtime
/// applicability; deserializing this type alone does not apply those checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub version: u32,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub filesystem_policy: Option<FilesystemPolicy>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub landlock: Option<LandlockPolicy>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub process: Option<ProcessPolicy>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub network_policies: BTreeMap<String, NetworkPolicyRule>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub network_middlewares: BTreeMap<String, NetworkMiddleware>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata: Option<ManagedPolicyMetadata>,
}

/// Authored filesystem paths and workdir inclusion for a present policy section.
///
/// An omitted section has different defaults; use
/// [`PolicyDocument::effective_filesystem_policy`] to account for that absence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub include_workdir: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_write: Vec<String>,
}

/// Authored choice of best-effort or required Landlock policy enforcement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockCompatibility {
    /// Use the runtime's best-effort handling of unavailable policy controls.
    #[default]
    BestEffort,
    /// Require the runtime to satisfy its Landlock policy installation contract.
    HardRequirement,
}

/// Authored Landlock options, defaulting omitted compatibility to best effort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandlockPolicy {
    #[serde(default)]
    pub compatibility: LandlockCompatibility,
}

/// Authored process identities retained as strings for runtime resolution.
/// Empty fields leave identity selection to the consuming runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessPolicy {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_as_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_as_group: String,
}

/// Named network rule relating its binary selectors to its endpoint selectors.
/// An empty authored name resolves to the containing map key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicyRule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<NetworkEndpoint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binaries: Vec<NetworkBinary>,
}

/// Authored destination selectors and optional protocol inspection settings.
///
/// Runtime validation checks whether the selected options can be enforced
/// together; schema decoding alone does not establish endpoint admissibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Endpoint DTO mirrors independent policy schema toggles."
)]
pub struct NetworkEndpoint {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Single port used when `ports` is empty; zero means no scalar port.
    /// The integer type rejects values above 65535 during decoding.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub port: u16,
    /// Multiple ports. When non-empty, this endpoint covers all listed ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enforcement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<L7Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_rules: Vec<L7DenyRule>,
    /// When true, percent-encoded `/` (`%2F`) is preserved in path segments
    /// rather than rejected by the L7 path canonicalizer. Required for
    /// upstreams like GitLab that embed `%2F` in namespaced resource paths.
    /// Defaults to false (strict).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_encoded_slash: bool,
    /// When true, client-to-server WebSocket text messages on this REST
    /// endpoint rewrite credential placeholders after an allowed 101 upgrade.
    /// Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub websocket_credential_rewrite: bool,
    /// When true, supported textual REST request bodies rewrite credential
    /// placeholders before forwarding upstream. Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub request_body_credential_rewrite: bool,
    /// Explicitly permits credentials on traffic paths that `OpenShell` cannot
    /// inspect or rewrite. Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_uninspected_credentials: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub persisted_queries: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub graphql_persisted_queries: BTreeMap<String, GraphqlOperation>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub graphql_max_body_bytes: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential_signing: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_region: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_binding: Option<NetworkCredentialBinding>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub json_rpc: Option<JsonRpcConfig>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub mcp: Option<McpConfig>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub review: Option<ReviewAnnotation>,
}

/// Authored provider selector for binding an endpoint to attached credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCredentialBinding {
    pub provider: String,
}
/// Authored JSON-RPC limits; a zero body limit leaves the runtime default in use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcConfig {
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_body_bytes: u32,
}
/// Authored MCP revisions and optional protocol settings with presence retained.
///
/// Omitted revisions select the pinned default; validation rejects a present
/// empty revision list instead of treating it as omission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpConfig {
    // Presence is retained until authored-policy validation so an omitted
    // allowlist can select the pinned default while an explicit empty list is
    // rejected as an authoring mistake.
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub versions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_body_bytes: u32,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub strict_tool_names: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_all_known_mcp_methods: Option<bool>,
}
/// Authored operation metadata for a named persisted GraphQL query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlOperation {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

/// Authored allow-rule wrapper whose `allow` object must be present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L7Rule {
    pub allow: L7Allow,
}

/// Authored request selectors for an allow rule, interpreted by its protocol.
/// Optional review metadata describes workflow and grants no request authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L7Allow {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, QueryMatcher>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub tool: Option<QueryMatcher>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, ParameterMatcher>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub review: Option<ReviewAnnotation>,
}

/// Authored value matcher expressed as a scalar glob or an `any` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryMatcher {
    /// Match one glob, as in `query: { repo: "NVIDIA/*" }`.
    Glob(String),
    /// Match any listed glob, as in `query: { repo: { any: ["NVIDIA/*"] } }`.
    Any(AnyMatcher),
}

/// Authored MCP parameter matcher or recursive parameter-name map.
/// Runtime adapters flatten nested paths before protocol-specific validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParameterMatcher {
    /// Match the value at the current parameter path.
    #[serde(deserialize_with = "deserialize_parameter_value_matcher")]
    Matcher(QueryMatcher),
    /// Continue matching beneath each named child parameter in a nonempty map.
    #[serde(deserialize_with = "deserialize_parameter_object")]
    Object(BTreeMap<String, Self>),
}

fn deserialize_parameter_object<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, ParameterMatcher>, D::Error>
where
    D: Deserializer<'de>,
{
    let children = BTreeMap::deserialize(deserializer)?;
    // Every authored parameter path must reach a matcher when flattened.
    // An empty nested object would erase its selector and widen the rule.
    // The separate root params map may still be empty to omit all selectors.
    if children.is_empty() {
        Err(serde::de::Error::custom(
            "parameter object must contain a child matcher",
        ))
    } else {
        Ok(children)
    }
}

fn deserialize_parameter_value_matcher<'de, D>(
    deserializer: D,
) -> std::result::Result<QueryMatcher, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_yml::Value::deserialize(deserializer)?;
    // Parameter names are open, so only the exact disjunction shape selects a
    // matcher. Query/tool matchers permit containment annotations; reusing that
    // permissive decoder here would silently discard sibling parameter names.
    if value.is_string() || value.as_mapping().is_some_and(is_any_matcher) {
        serde_yml::from_value(&value).map_err(serde::de::Error::custom)
    } else {
        Err(serde::de::Error::custom(
            "expected a glob string or an exact any matcher",
        ))
    }
}

/// Authored disjunction of glob strings; runtime validation checks admissibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnyMatcher {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<String>,
}

/// Authored request selectors that deny matching traffic under their protocol.
/// Deny rules carry selectors directly, without an `allow` wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L7DenyRule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, QueryMatcher>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub tool: Option<QueryMatcher>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, ParameterMatcher>,
}

/// Authored executable-path selector for a network policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkBinary {
    pub path: String,
}
/// Authored middleware attachment with ordering, failure mode, and host scope.
///
/// Plugin configuration is an open data map; runtime consumers resolve the
/// middleware implementation and validate its configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMiddleware {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub middleware: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub order: i32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub on_error: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub endpoints: Option<MiddlewareEndpointSelector>,
}
/// Authored include and exclude host selectors for a middleware attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiddlewareEndpointSelector {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

/// Workflow metadata carried by a managed maximum policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedPolicyMetadata {
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub allowed_modes: Vec<String>,
    #[serde(default)]
    pub default_mode: String,
    #[serde(default)]
    pub audit_label: String,
}

/// Human-review workflow annotation. It never grants policy authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewAnnotation {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub reason: String,
}

// Signature dictated by serde's `skip_serializing_if`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u16) -> bool {
    *value == 0
}

// Signature dictated by serde's `skip_serializing_if`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
}

fn deserialize_non_null_optional_field<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Validation profile applied after parsing the shared document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseProfile {
    /// Authored runtime input: version 1 and only runtime-supported fields.
    RuntimeStrict,
    /// Input for maximum-policy containment analysis.
    ContainmentInput,
}

const MAX_UNKNOWN_FIELD_PATH_BYTES: usize = 1_024;

/// An unknown field retained from a closed authored-schema object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionField {
    pub path: String,
    pub value: serde_yml::Value,
}

/// A decoded policy plus unknown closed-object fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDocument {
    pub policy: PolicyDocument,
    pub extensions: Vec<ExtensionField>,
}

/// Resource budgets enforced before and while noyalib builds the YAML document.
///
/// Raw-value and authored-policy entrypoints share these limits. At most one
/// document is accepted, even if `max_documents` is larger; merge keys are
/// always forbidden, even if `max_merge_keys` is larger than zero.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ParseLimits {
    /// Maximum UTF-8 input bytes, including comments and whitespace.
    pub max_bytes: usize,
    /// Maximum nested mapping/sequence depth.
    pub max_depth: usize,
    /// Maximum parser events, including stream/document boundaries.
    pub max_events: usize,
    /// Maximum authored scalar, sequence, and mapping nodes.
    pub max_nodes: usize,
    /// Maximum aggregate authored scalar UTF-8 bytes, including mapping keys.
    pub max_scalar_bytes: usize,
    /// Maximum alias expansions; the parser also bounds expanded value bytes.
    pub max_alias_expansions: usize,
    /// Maximum keys in one mapping.
    pub max_mapping_keys: usize,
    /// Maximum elements in one sequence.
    pub max_sequence_elements: usize,
    /// Maximum parsed documents; raw-value APIs additionally cap this at one.
    pub max_documents: usize,
    /// Merge-key budget; the unconditional merge-key rejection takes precedence.
    pub max_merge_keys: usize,
    /// Optional maximum aliases per observed anchor.
    pub alias_anchor_ratio: Option<f64>,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_bytes: 4 * 1024 * 1024,
            max_depth: 64,
            max_events: 300_000,
            max_nodes: 100_000,
            max_scalar_bytes: 4 * 1024 * 1024,
            max_alias_expansions: 100,
            max_mapping_keys: 10_000,
            max_sequence_elements: 10_000,
            max_documents: 1,
            max_merge_keys: 0,
            alias_anchor_ratio: Some(5.0),
        }
    }
}

fn parser_config(limits: ParseLimits) -> serde_yml::ParserConfig {
    let mut config = serde_yml::ParserConfig::new();
    config.max_document_length = limits.max_bytes;
    config.max_depth = limits.max_depth;
    config.max_events = limits.max_events;
    config.max_nodes = limits.max_nodes;
    config.max_total_scalar_bytes = limits.max_scalar_bytes;
    config.max_alias_expansions = limits.max_alias_expansions;
    config.max_mapping_keys = limits.max_mapping_keys;
    config.max_sequence_length = limits.max_sequence_elements;
    // A Value decoder returns only one value. Cap while parsing so a relaxed
    // caller budget cannot silently discard additional YAML documents.
    config.max_documents = limits.max_documents.min(1);
    config.max_merge_keys = limits.max_merge_keys;
    config.alias_anchor_ratio = limits.alias_anchor_ratio;
    config.duplicate_key_policy = serde_yml::DuplicateKeyPolicy::Error;
    config.merge_key_policy = serde_yml::MergeKeyPolicy::Error;
    config
}

/// Payload-free classification of a raw YAML decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RawValueParseErrorKind {
    /// The complete encoded input exceeds the byte budget.
    #[error("policy exceeds the input byte limit")]
    InputBytes,
    /// Mapping or sequence nesting exceeds the depth budget.
    #[error("policy exceeds the nesting depth limit")]
    Depth,
    /// Parser events exceed the event budget.
    #[error("policy exceeds the parser event limit")]
    Events,
    /// Authored nodes exceed the node budget.
    #[error("policy exceeds the parser node limit")]
    Nodes,
    /// Aggregate authored scalar bytes exceed their budget.
    #[error("policy exceeds the scalar byte limit")]
    ScalarBytes,
    /// Alias count or expanded alias bytes exceed their budget.
    #[error("policy exceeds the alias expansion limit")]
    AliasExpansions,
    /// A mapping exceeds its key budget.
    #[error("policy exceeds the mapping key limit")]
    MappingKeys,
    /// A sequence exceeds its element budget.
    #[error("policy exceeds the sequence element limit")]
    SequenceElements,
    /// The document budget or single-document contract is violated.
    #[error("policy exceeds the single-document limit")]
    Documents,
    /// YAML merge keys are forbidden.
    #[error("policy YAML merge keys are forbidden")]
    MergeKeys,
    /// Alias-to-anchor ratio exceeds its configured budget.
    #[error("policy exceeds the alias-to-anchor ratio limit")]
    AliasAnchorRatio,
    /// A duplicate key or distinct-typed key collision was rejected.
    #[error("policy contains duplicate or colliding mapping keys")]
    DuplicateKey,
    /// The input is not UTF-8.
    #[error("policy is not valid UTF-8")]
    InvalidUtf8,
    /// Opening, inspecting, or reading the source failed.
    #[error("failed to read policy source")]
    Io,
    /// A file entrypoint received a non-regular file.
    #[error("policy source is not a regular file")]
    NotRegularFile,
    /// The bounded input buffer could not be allocated.
    #[error("failed to allocate the bounded policy input buffer")]
    Allocation,
    /// A parser resource limit without a more specific classification was hit.
    #[error("policy exceeds a parser resource limit")]
    ResourceLimit,
    /// YAML syntax or a YAML value is invalid.
    #[error("policy contains invalid YAML")]
    InvalidYaml,
}

/// Bounded raw parser diagnostic with no policy text, path, or source chain.
///
/// `Display` emits only a fixed message. `Debug` additionally exposes the typed
/// classification and optional numeric location; neither retains parser or I/O
/// error strings, which can contain policy values or caller-supplied secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{kind}")]
pub struct RawValueParseError {
    kind: RawValueParseErrorKind,
    location: Option<(usize, usize)>,
}

impl RawValueParseError {
    /// Return the payload-free failure classification.
    #[must_use]
    pub const fn kind(&self) -> RawValueParseErrorKind {
        self.kind
    }

    /// Return a one-based `(line, column)` when the parser supplied a location.
    #[must_use]
    pub const fn location(&self) -> Option<(usize, usize)> {
        self.location
    }

    fn new(kind: RawValueParseErrorKind) -> Self {
        Self {
            kind,
            location: None,
        }
    }

    fn from_yaml(error: serde_yml::Error) -> Self {
        use RawValueParseErrorKind as Kind;
        use serde_yml::{BudgetBreach, Error};

        // Classify by typed variants, never by rendering an untrusted parser
        // diagnostic. The merge rejection is a fixed library-owned string.
        let kind = match &error {
            Error::RecursionLimitExceeded { .. } => Kind::Depth,
            Error::RepetitionLimitExceeded => Kind::AliasExpansions,
            Error::DuplicateKey(_) | Error::KeyCollision(_) => Kind::DuplicateKey,
            Error::MoreThanOneDocument | Error::EndOfStream => Kind::Documents,
            Error::Budget(breach) => match breach {
                BudgetBreach::MaxEvents { .. } => Kind::Events,
                BudgetBreach::MaxNodes { .. } => Kind::Nodes,
                BudgetBreach::MaxTotalScalarBytes { .. } => Kind::ScalarBytes,
                BudgetBreach::MaxDocuments { .. } => Kind::Documents,
                BudgetBreach::MaxMergeKeys { .. } => Kind::MergeKeys,
                BudgetBreach::AliasAnchorRatio { .. } => Kind::AliasAnchorRatio,
                BudgetBreach::MaxSequenceLength { .. } => Kind::SequenceElements,
                BudgetBreach::MaxMappingKeys { .. } => Kind::MappingKeys,
                _ => Kind::ResourceLimit,
            },
            Error::Custom(message)
                if message == "merge key `<<` rejected by MergeKeyPolicy::Error" =>
            {
                Kind::MergeKeys
            }
            _ => Kind::InvalidYaml,
        };
        Self {
            kind,
            location: error
                .location()
                .map(|location| (location.line(), location.column())),
        }
    }
}

/// Decode one raw YAML value with the shared default resource budgets.
///
/// This validates YAML structure, not authored or OPA policy semantics.
///
/// # Errors
///
/// Returns a payload-free error for invalid YAML, duplicate/merge keys, or a
/// resource budget violation.
pub fn parse_raw_value(source: &str) -> std::result::Result<serde_yml::Value, RawValueParseError> {
    parse_raw_value_with_limits(source, ParseLimits::default())
}

/// Decode one raw YAML value after checking encoded bytes, using explicit budgets.
///
/// # Errors
///
/// Returns a payload-free error for invalid YAML, duplicate/merge keys, or a
/// resource budget violation. No authored-policy profile is applied.
pub fn parse_raw_value_with_limits(
    source: &str,
    limits: ParseLimits,
) -> std::result::Result<serde_yml::Value, RawValueParseError> {
    // Check before entering the parser, so comments and multibyte input count
    // toward the byte budget even when they produce few decoded value nodes.
    check_raw_input_length(source.len(), limits)?;
    serde_yml::from_str_with_config(source, &parser_config(limits))
        .map_err(RawValueParseError::from_yaml)
}

/// Decode one raw YAML value from UTF-8 bytes with the default budgets.
///
/// # Errors
///
/// Returns a payload-free error for invalid UTF-8 or any raw YAML parsing failure.
pub fn parse_raw_value_bytes(
    bytes: &[u8],
) -> std::result::Result<serde_yml::Value, RawValueParseError> {
    parse_raw_value_bytes_with_limits(bytes, ParseLimits::default())
}

/// Decode one raw YAML value from bytes, checking length before UTF-8 decoding.
///
/// # Errors
///
/// Returns a payload-free error for invalid UTF-8 or any raw YAML parsing failure.
pub fn parse_raw_value_bytes_with_limits(
    bytes: &[u8],
    limits: ParseLimits,
) -> std::result::Result<serde_yml::Value, RawValueParseError> {
    check_raw_input_length(bytes.len(), limits)?;
    let source = std::str::from_utf8(bytes)
        .map_err(|_| RawValueParseError::new(RawValueParseErrorKind::InvalidUtf8))?;
    parse_raw_value_with_limits(source, limits)
}

/// Read and decode one raw YAML value using a bounded input buffer.
///
/// At most `max_bytes + 1` bytes are consumed. The extra byte detects an
/// oversized stream and is never added to the input buffer or decoded.
///
/// # Errors
///
/// Returns a payload-free error for I/O, allocation, UTF-8, or raw YAML failures.
pub fn parse_raw_value_reader<R: Read>(
    reader: R,
    limits: ParseLimits,
) -> std::result::Result<serde_yml::Value, RawValueParseError> {
    let bytes = read_raw_bytes(reader, limits)?;
    parse_raw_value_bytes_with_limits(&bytes, limits)
}

/// Load one raw YAML value from a regular file with metadata and bounded reads.
///
/// # Errors
///
/// Returns a payload-free error for non-regular sources, I/O, allocation, UTF-8,
/// or raw YAML failures. Paths and underlying I/O diagnostics are omitted.
pub fn parse_raw_value_file(
    path: &Path,
    limits: ParseLimits,
) -> std::result::Result<serde_yml::Value, RawValueParseError> {
    let file = open_raw_file(path, limits)?;
    parse_raw_value_reader(file, limits)
}

fn check_raw_input_length(
    length: usize,
    limits: ParseLimits,
) -> std::result::Result<(), RawValueParseError> {
    if length > limits.max_bytes {
        return Err(RawValueParseError::new(RawValueParseErrorKind::InputBytes));
    }
    Ok(())
}

fn read_raw_bytes<R: Read>(
    mut reader: R,
    limits: ParseLimits,
) -> std::result::Result<Vec<u8>, RawValueParseError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let remaining = limits.max_bytes - bytes.len();
        // Read a single probe byte when full; never reserve or append it. A
        // growing file and a reader without metadata obey the same byte cap.
        let read_length = remaining.clamp(1, buffer.len());
        let count = match reader.read(&mut buffer[..read_length]) {
            Ok(0) => return Ok(bytes),
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(RawValueParseError::new(RawValueParseErrorKind::Io)),
        };
        // A faulty Read implementation must not turn its reported byte count
        // into an out-of-bounds slice or a misleading input-budget failure.
        if count > read_length {
            return Err(RawValueParseError::new(RawValueParseErrorKind::Io));
        }
        if count > remaining {
            return Err(RawValueParseError::new(RawValueParseErrorKind::InputBytes));
        }
        // Reserve only bytes already received within budget. A caller may set
        // a very large cap without causing an eager allocation of that size.
        bytes
            .try_reserve_exact(count)
            .map_err(|_| RawValueParseError::new(RawValueParseErrorKind::Allocation))?;
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn open_raw_file(
    path: &Path,
    limits: ParseLimits,
) -> std::result::Result<File, RawValueParseError> {
    let inspect = |metadata: &std::fs::Metadata| {
        if !metadata.is_file() {
            return Err(RawValueParseError::new(
                RawValueParseErrorKind::NotRegularFile,
            ));
        }
        if metadata.len() > u64::try_from(limits.max_bytes).unwrap_or(u64::MAX) {
            return Err(RawValueParseError::new(RawValueParseErrorKind::InputBytes));
        }
        Ok(())
    };
    let io_error = |_| RawValueParseError::new(RawValueParseErrorKind::Io);
    inspect(&path.metadata().map_err(io_error)?)?;
    let file = File::open(path).map_err(io_error)?;
    // Inspect the opened handle as well as the path; still bound the read
    // because regular files can grow after either metadata observation.
    inspect(&file.metadata().map_err(io_error)?)?;
    Ok(file)
}

/// Parse a UTF-8 authored policy with explicit profile and budgets.
pub fn parse_document_with_limits(
    source: &str,
    profile: ParseProfile,
    limits: ParseLimits,
) -> Result<ParsedDocument> {
    let value = parse_raw_value_with_limits(source, limits)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    decode_authored_document(value, profile)
}

fn decode_authored_document(
    value: serde_yml::Value,
    profile: ParseProfile,
) -> Result<ParsedDocument> {
    let extensions = collect_extensions(&value);
    let policy: PolicyDocument = serde_yml::from_value(&value)
        .into_diagnostic()
        .wrap_err("failed to decode sandbox policy fields")?;
    validate_profile(&policy, &extensions, profile)?;
    Ok(ParsedDocument { policy, extensions })
}

/// Parse a document while retaining unknown fields for containment auditing.
pub fn parse_document(source: &str, profile: ParseProfile) -> Result<ParsedDocument> {
    parse_document_with_limits(source, profile, ParseLimits::default())
}

/// Parse only the typed policy. Strict consumers should use this convenience
/// wrapper; containment consumers should use [`parse_document`].
pub fn parse_policy_with_limits(
    source: &str,
    profile: ParseProfile,
    limits: ParseLimits,
) -> Result<PolicyDocument> {
    Ok(parse_document_with_limits(source, profile, limits)?.policy)
}

/// Parse a UTF-8 authored policy with the shared default budgets.
pub fn parse_policy(source: &str, profile: ParseProfile) -> Result<PolicyDocument> {
    parse_policy_with_limits(source, profile, ParseLimits::default())
}

/// Parse an authored policy from a byte slice, rejecting invalid UTF-8.
pub fn parse_policy_bytes(bytes: &[u8], profile: ParseProfile) -> Result<PolicyDocument> {
    let value = parse_raw_value_bytes(bytes)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    Ok(decode_authored_document(value, profile)?.policy)
}

/// Read and parse an authored policy without an unbounded allocation.
pub fn parse_policy_reader<R: Read>(
    reader: R,
    profile: ParseProfile,
    limits: ParseLimits,
) -> Result<PolicyDocument> {
    Ok(parse_document_reader(reader, profile, limits)?.policy)
}

/// Read and parse a document while retaining unknown fields.
pub fn parse_document_reader<R: Read>(
    reader: R,
    profile: ParseProfile,
    limits: ParseLimits,
) -> Result<ParsedDocument> {
    let value = parse_raw_value_reader(reader, limits)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    decode_authored_document(value, profile)
}

/// Load a regular file with metadata and bounded-read checks.
pub fn parse_policy_file(
    path: &Path,
    profile: ParseProfile,
    limits: ParseLimits,
) -> Result<PolicyDocument> {
    Ok(parse_document_file(path, profile, limits)?.policy)
}

/// Load a regular file while retaining unknown fields for containment.
pub fn parse_document_file(
    path: &Path,
    profile: ParseProfile,
    limits: ParseLimits,
) -> Result<ParsedDocument> {
    let value = parse_raw_value_file(path, limits)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    decode_authored_document(value, profile)
}

fn validate_profile(
    document: &PolicyDocument,
    extensions: &[ExtensionField],
    profile: ParseProfile,
) -> Result<()> {
    if document.version != 1 {
        miette::bail!(
            "unsupported policy version {}; expected version 1",
            document.version
        );
    }
    for (key, rule) in &document.network_policies {
        let name = rule.effective_name(key);
        for endpoint in &rule.endpoints {
            if endpoint.protocol.eq_ignore_ascii_case("mcp") {
                if let Some(config) = &endpoint.mcp {
                    validate_mcp_config(config, &format!("network policy '{name}'"))?;
                }
            } else if endpoint.mcp.is_some() {
                miette::bail!(
                    "network policy '{name}': non-MCP endpoint '{}' cannot configure mcp options",
                    endpoint.host
                );
            }
        }
    }
    if profile == ParseProfile::RuntimeStrict {
        if let Some(extension) = extensions.first() {
            miette::bail!(
                "unknown field '{}' in authored policy",
                unknown_field_diagnostic_path(&extension.path)
            );
        }
        if document.metadata.is_some() {
            miette::bail!("managed maximum metadata is not valid in a runtime policy");
        }
        for (rule_name, rule) in &document.network_policies {
            for (endpoint_index, endpoint) in rule.endpoints.iter().enumerate() {
                if endpoint.review.is_some() {
                    miette::bail!(
                        "review annotation is not valid in runtime policy at network_policies.{rule_name}.endpoints[{endpoint_index}].review"
                    );
                }
                for (rule_index, rule) in endpoint.rules.iter().enumerate() {
                    if rule.allow.review.is_some() {
                        miette::bail!(
                            "review annotation is not valid in runtime policy at network_policies.{rule_name}.endpoints[{endpoint_index}].rules[{rule_index}].allow.review"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

// Authored root fields are shared with the OPA validation projection, whose
// original root also permits application data outside the authored schema.
const POLICY_ROOT_FIELDS: &[&str] = &[
    "version",
    "filesystem_policy",
    "landlock",
    "process",
    "network_policies",
    "network_middlewares",
    "metadata",
];

fn collect_extensions(root: &serde_yml::Value) -> Vec<ExtensionField> {
    let mut extensions = Vec::new();
    let Some(root) = inspect_closed(root, "", POLICY_ROOT_FIELDS, &mut extensions) else {
        return extensions;
    };

    inspect_named(
        root.get("filesystem_policy"),
        "filesystem_policy",
        &["include_workdir", "read_only", "read_write"],
        &mut extensions,
    );
    inspect_named(
        root.get("landlock"),
        "landlock",
        &["compatibility"],
        &mut extensions,
    );
    inspect_named(
        root.get("process"),
        "process",
        &["run_as_user", "run_as_group"],
        &mut extensions,
    );
    inspect_named(
        root.get("metadata"),
        "metadata",
        &[
            "policy_id",
            "version",
            "allowed_modes",
            "default_mode",
            "audit_label",
        ],
        &mut extensions,
    );

    for (name, rule) in open_map(root.get("network_policies")) {
        let path = join("network_policies", name);
        if let Some(rule) = inspect_closed(
            rule,
            &path,
            &["name", "endpoints", "binaries"],
            &mut extensions,
        ) {
            for (index, endpoint) in sequence(rule.get("endpoints")).iter().enumerate() {
                inspect_endpoint(
                    endpoint,
                    &format!("{path}.endpoints[{index}]"),
                    &mut extensions,
                );
            }
            for (index, binary) in sequence(rule.get("binaries")).iter().enumerate() {
                inspect_closed(
                    binary,
                    &format!("{path}.binaries[{index}]"),
                    &["path"],
                    &mut extensions,
                );
            }
        }
    }

    for (name, middleware) in open_map(root.get("network_middlewares")) {
        let path = join("network_middlewares", name);
        if let Some(middleware) = inspect_closed(
            middleware,
            &path,
            &[
                "name",
                "middleware",
                "order",
                "config",
                "on_error",
                "endpoints",
            ],
            &mut extensions,
        ) {
            inspect_named(
                middleware.get("endpoints"),
                &join(&path, "endpoints"),
                &["include", "exclude"],
                &mut extensions,
            );
            // `config` is deliberately an open user-data map.
        }
    }
    extensions
}

fn inspect_endpoint(value: &serde_yml::Value, path: &str, out: &mut Vec<ExtensionField>) {
    let Some(endpoint) = inspect_closed(
        value,
        path,
        &[
            "host",
            "path",
            "port",
            "ports",
            "protocol",
            "tls",
            "enforcement",
            "access",
            "rules",
            "allowed_ips",
            "deny_rules",
            "allow_encoded_slash",
            "websocket_credential_rewrite",
            "request_body_credential_rewrite",
            "allow_uninspected_credentials",
            "persisted_queries",
            "graphql_persisted_queries",
            "graphql_max_body_bytes",
            "credential_signing",
            "signing_service",
            "signing_region",
            "credential_binding",
            "json_rpc",
            "mcp",
            "review",
        ],
        out,
    ) else {
        return;
    };
    inspect_named(
        endpoint.get("credential_binding"),
        &join(path, "credential_binding"),
        &["provider"],
        out,
    );
    inspect_named(
        endpoint.get("json_rpc"),
        &join(path, "json_rpc"),
        &["max_body_bytes"],
        out,
    );
    inspect_named(
        endpoint.get("mcp"),
        &join(path, "mcp"),
        &[
            "versions",
            "max_body_bytes",
            "strict_tool_names",
            "allow_all_known_mcp_methods",
        ],
        out,
    );
    inspect_named(
        endpoint.get("review"),
        &join(path, "review"),
        &["required", "reason"],
        out,
    );
    for (name, operation) in open_map(endpoint.get("graphql_persisted_queries")) {
        inspect_closed(
            operation,
            &join(&join(path, "graphql_persisted_queries"), name),
            &["operation_type", "operation_name", "fields"],
            out,
        );
    }
    for (index, rule) in sequence(endpoint.get("rules")).iter().enumerate() {
        let rule_path = format!("{path}.rules[{index}]");
        if let Some(rule) = inspect_closed(rule, &rule_path, &["allow"], out) {
            inspect_allow(rule.get("allow"), &join(&rule_path, "allow"), true, out);
        }
    }
    for (index, deny) in sequence(endpoint.get("deny_rules")).iter().enumerate() {
        inspect_allow(
            Some(deny),
            &format!("{path}.deny_rules[{index}]"),
            false,
            out,
        );
    }
}

fn inspect_allow(
    value: Option<&serde_yml::Value>,
    path: &str,
    allow_review: bool,
    out: &mut Vec<ExtensionField>,
) {
    let mut allowed = vec![
        "method",
        "path",
        "command",
        "query",
        "operation_type",
        "operation_name",
        "fields",
        "tool",
        "params",
    ];
    if allow_review {
        allowed.push("review");
    }
    let Some(value) = value else { return };
    let Some(rule) = inspect_closed(value, path, &allowed, out) else {
        return;
    };
    if allow_review {
        inspect_named(
            rule.get("review"),
            &join(path, "review"),
            &["required", "reason"],
            out,
        );
    }
    for (name, matcher) in open_map(rule.get("query")) {
        inspect_matcher(matcher, &join(&join(path, "query"), name), out);
    }
    if let Some(matcher) = rule.get("tool") {
        inspect_matcher(matcher, &join(path, "tool"), out);
    }
    // MCP parameter names form an open namespace. The typed parameter
    // deserializers validate selector shape; there are no extension fields
    // to collect beneath params.
}

fn inspect_matcher(value: &serde_yml::Value, path: &str, out: &mut Vec<ExtensionField>) {
    if value.as_mapping().is_some() {
        inspect_closed(value, path, &["any"], out);
    }
}

fn is_any_matcher(mapping: &serde_yml::Mapping) -> bool {
    mapping.len() == 1
        && mapping.get("any").is_some_and(|value| {
            value
                .as_sequence()
                .is_some_and(|values| values.iter().all(serde_yml::Value::is_string))
        })
}

fn unknown_field_diagnostic_path(path: &str) -> std::borrow::Cow<'_, str> {
    if path.len() <= MAX_UNKNOWN_FIELD_PATH_BYTES {
        return std::borrow::Cow::Borrowed(path);
    }
    // Runtime diagnostics stay bounded without truncating the paths retained
    // for containment analysis, which must distinguish different extensions.
    let mut end = MAX_UNKNOWN_FIELD_PATH_BYTES - 3;
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!("{}...", &path[..end]))
}

fn inspect_named(
    value: Option<&serde_yml::Value>,
    path: &str,
    allowed: &[&str],
    out: &mut Vec<ExtensionField>,
) {
    if let Some(value) = value {
        inspect_closed(value, path, allowed, out);
    }
}

fn inspect_closed<'a>(
    value: &'a serde_yml::Value,
    path: &str,
    allowed: &[&str],
    out: &mut Vec<ExtensionField>,
) -> Option<&'a serde_yml::Mapping> {
    let mapping = value.as_mapping()?;
    for (name, value) in string_entries(mapping) {
        if !allowed.contains(&name) {
            out.push(ExtensionField {
                path: join(path, name),
                value: value.clone(),
            });
        }
    }
    Some(mapping)
}

fn string_entries(mapping: &serde_yml::Mapping) -> impl Iterator<Item = (&str, &serde_yml::Value)> {
    mapping.iter().map(|(key, value)| (key.as_str(), value))
}

fn open_map(value: Option<&serde_yml::Value>) -> Vec<(&str, &serde_yml::Value)> {
    value
        .and_then(serde_yml::Value::as_mapping)
        .map(|mapping| string_entries(mapping).collect())
        .unwrap_or_default()
}

fn sequence(value: Option<&serde_yml::Value>) -> &[serde_yml::Value] {
    value
        .and_then(serde_yml::Value::as_sequence)
        .map_or(&[], Vec::as_slice)
}

fn join(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}.{child}")
    }
}

/// Serialize the authored representation to YAML.
pub fn serialize_policy(document: &PolicyDocument) -> Result<String> {
    serde_yml::to_string(document)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to YAML")
}

/// Convert the authored representation to canonical JSON.
pub fn policy_to_json_value(document: &PolicyDocument) -> Result<serde_json::Value> {
    serde_json::to_value(document)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to JSON")
}

/// Deserialize a JSON-RPC fragment using the canonical authored schema.
pub fn parse_json_rpc_config(value: serde_json::Value) -> Result<JsonRpcConfig> {
    reject_json_unknown_fields(&value, &["max_body_bytes"], "json_rpc")?;
    serde_json::from_value(value)
        .into_diagnostic()
        .wrap_err("invalid json_rpc config")
}

/// Deserialize an MCP fragment using the canonical authored schema.
pub fn parse_mcp_config(value: serde_json::Value) -> Result<McpConfig> {
    reject_json_unknown_fields(
        &value,
        &[
            "versions",
            "max_body_bytes",
            "strict_tool_names",
            "allow_all_known_mcp_methods",
        ],
        "mcp",
    )?;
    let config = serde_json::from_value(value.clone())
        .map_err(|error| miette::miette!("invalid mcp config {value}: {error}"))?;
    validate_mcp_config(&config, "invalid mcp config")?;
    Ok(config)
}

/// Validate authored MCP revision presence, vocabulary, and uniqueness.
pub fn validate_mcp_config(config: &McpConfig, context: &str) -> Result<()> {
    let Some(versions) = config.versions.as_deref() else {
        return Ok(());
    };
    if versions.is_empty() {
        miette::bail!(
            "{context} has an empty mcp.versions list; omit it to use the pinned default revision"
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in versions {
        let version = value
            .parse::<McpProtocolVersion>()
            .map_err(|error| miette::miette!("{context}: {error}; {MCP_VERSION_REMEDIATION}"))?;
        if !seen.insert(version) {
            miette::bail!("{context} has duplicate protocol version '{value}'");
        }
    }
    Ok(())
}

fn reject_json_unknown_fields(
    value: &serde_json::Value,
    allowed: &[&str],
    stanza: &str,
) -> Result<()> {
    if let Some(object) = value.as_object()
        && let Some(field) = object
            .keys()
            .find(|field| !allowed.contains(&field.as_str()))
    {
        miette::bail!("invalid {stanza} config: unknown field '{field}'");
    }
    Ok(())
}

impl PolicyDocument {
    /// Effective filesystem policy. Absence enables the runtime workdir default;
    /// an explicitly present empty object retains `include_workdir: false`.
    #[must_use]
    pub fn effective_filesystem_policy(&self) -> FilesystemPolicy {
        self.filesystem_policy
            .clone()
            .unwrap_or_else(|| FilesystemPolicy {
                include_workdir: true,
                read_only: Vec::new(),
                read_write: Vec::new(),
            })
    }
}

impl NetworkPolicyRule {
    /// Effective rule name, falling back to the surrounding map key.
    #[must_use]
    pub fn effective_name<'a>(&'a self, key: &'a str) -> &'a str {
        if self.name.is_empty() {
            key
        } else {
            &self.name
        }
    }
}

impl NetworkEndpoint {
    /// Effective authored ports. A non-empty `ports` list takes precedence.
    #[must_use]
    pub fn effective_ports(&self) -> Vec<u16> {
        if self.ports.is_empty() {
            (self.port != 0).then_some(self.port).into_iter().collect()
        } else {
            self.ports.clone()
        }
    }

    /// Whether this endpoint is uninspected L4 traffic.
    #[must_use]
    pub fn is_l4(&self) -> bool {
        self.protocol.is_empty() || self.protocol.eq_ignore_ascii_case("tcp")
    }
}

/// Intrinsic access-preset vocabulary in the authored policy language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPreset {
    ReadOnly,
    ReadWrite,
    Full,
}

impl AccessPreset {
    /// Parse an exact authored preset spelling, returning `None` for other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read-only" => Some(Self::ReadOnly),
            "read-write" => Some(Self::ReadWrite),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    /// Expand a preset to the authored protocol methods it represents.
    #[must_use]
    pub fn methods(self, protocol: &str) -> &'static [&'static str] {
        match (protocol, self) {
            (_, Self::Full) => &["*"],
            ("websocket", Self::ReadOnly) => &["GET"],
            ("websocket", Self::ReadWrite) => &["GET", "WEBSOCKET_TEXT"],
            (_, Self::ReadOnly) => &["GET", "HEAD", "OPTIONS"],
            (_, Self::ReadWrite) => &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"],
        }
    }
}

/// Expand a recognized access preset for a protocol.
#[must_use]
pub fn expand_access_preset(protocol: &str, access: &str) -> Option<&'static [&'static str]> {
    AccessPreset::parse(access).map(|preset| preset.methods(protocol))
}

/// Normalize a policy path lexically without filesystem access.
#[must_use]
pub fn normalize_path(path: &str) -> String {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            #[allow(clippy::path_buf_push_overwrite)]
            Component::RootDir => normalized.push("/"),
            Component::CurDir => {}
            Component::ParentDir => normalized.push(".."),
            Component::Normal(component) => normalized.push(component),
        }
    }
    let normalized = normalized.to_string_lossy();
    #[cfg(target_os = "windows")]
    {
        normalized.replace('\\', "/")
    }
    #[cfg(not(target_os = "windows"))]
    {
        normalized.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn requires_version_one() {
        assert!(parse_policy("version: 2\n", ParseProfile::RuntimeStrict).is_err());
        assert!(parse_policy("network_policies: {}\n", ParseProfile::RuntimeStrict).is_err());
    }

    #[test]
    fn rejects_duplicate_keys() {
        let error = parse_policy("version: 1\nversion: 1\n", ParseProfile::RuntimeStrict)
            .expect_err("duplicate key must fail");
        assert!(error.to_string().contains("parse sandbox policy"));
    }

    #[test]
    fn distinguishes_absent_and_empty_filesystem() {
        let absent = parse_policy("version: 1\n", ParseProfile::RuntimeStrict).unwrap();
        let empty = parse_policy(
            "version: 1\nfilesystem_policy: {}\n",
            ParseProfile::RuntimeStrict,
        )
        .unwrap();
        assert!(absent.effective_filesystem_policy().include_workdir);
        assert!(!empty.effective_filesystem_policy().include_workdir);
    }

    #[test]
    fn rejects_oversized_port() {
        assert!(parse_policy(
            "version: 1\nnetwork_policies:\n  x:\n    endpoints:\n      - host: x\n        port: 65536\n",
            ParseProfile::RuntimeStrict,
        )
        .is_err());
    }

    #[test]
    fn explicit_null_does_not_collapse_to_omission() {
        for source in [
            "version: 1\nfilesystem_policy: null\n",
            "version: 1\nprocess: null\n",
            "version: 1\nmetadata: null\n",
            "version: 1\nnetwork_policies:\n  x:\n    endpoints:\n      - host: x\n        port: 443\n        mcp: null\n",
        ] {
            assert!(
                parse_document(source, ParseProfile::ContainmentInput).is_err(),
                "explicit null unexpectedly parsed: {source}"
            );
        }
    }

    #[test]
    fn truncation_paths_are_unicode_safe() {
        let oversized = "é".repeat(ParseLimits::default().max_bytes);
        let source = format!("version: 1\nunknown_{oversized}: true\n");
        assert!(parse_policy(&source, ParseProfile::RuntimeStrict).is_err());
    }

    #[test]
    fn path_normalization_is_lexical() {
        assert_eq!(normalize_path("/usr//./lib/"), "/usr/lib");
        assert_eq!(normalize_path("/usr/../etc"), "/usr/../etc");
    }

    #[test]
    fn containment_retains_nested_unknown_fields_with_paths() {
        let source = "version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - host: example.com\n        port: 443\n        future_authority: enabled\n";
        let parsed = parse_document(source, ParseProfile::ContainmentInput).unwrap();
        assert_eq!(parsed.extensions.len(), 1);
        assert_eq!(
            parsed.extensions[0].path,
            "network_policies.api.endpoints[0].future_authority"
        );
        assert!(parse_document(source, ParseProfile::RuntimeStrict).is_err());
    }

    #[test]
    fn containment_retains_unknown_matcher_fields() {
        let source = r#"
version: 1
network_policies:
  api:
    endpoints:
      - host: example.com
        port: 443
        rules:
          - allow:
              query:
                q:
                  any: ["one"]
                  future_constraint: true
"#;
        let parsed = parse_document(source, ParseProfile::ContainmentInput).unwrap();
        assert_eq!(parsed.extensions.len(), 1);
        assert_eq!(
            parsed.extensions[0].path,
            "network_policies.api.endpoints[0].rules[0].allow.query.q.future_constraint"
        );
        assert!(parse_document(source, ParseProfile::RuntimeStrict).is_err());
    }

    #[test]
    fn parameter_matchers_preserve_names_and_reject_ambiguous_disjunctions() {
        let source = r"
version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp: {}
        rules:
          - allow:
              method: tools/call
              params:
                arguments: { any: first, other: second }
                nested: { any: { any: [one, two] }, other: second }
                choice: { any: [one, two] }
";
        for profile in [ParseProfile::RuntimeStrict, ParseProfile::ContainmentInput] {
            let parsed = parse_document(source, profile).expect("valid open parameter maps");
            assert!(parsed.extensions.is_empty());
            let params = &parsed.policy.network_policies["mcp"].endpoints[0].rules[0]
                .allow
                .params;
            let ParameterMatcher::Object(arguments) = &params["arguments"] else {
                panic!("parameter names must remain an object");
            };
            assert_eq!(arguments.len(), 2);
            assert!(matches!(
                &arguments["any"],
                ParameterMatcher::Matcher(QueryMatcher::Glob(value)) if value == "first"
            ));
            let ParameterMatcher::Object(nested) = &params["nested"] else {
                panic!("nested any parameter must remain an object");
            };
            assert_eq!(nested.len(), 2);
            assert!(matches!(
                &nested["any"],
                ParameterMatcher::Matcher(QueryMatcher::Any(value)) if value.any == ["one", "two"]
            ));
            assert!(matches!(
                &params["choice"],
                ParameterMatcher::Matcher(QueryMatcher::Any(value)) if value.any == ["one", "two"]
            ));
            let yaml = serialize_policy(&parsed.policy).expect("canonical YAML");
            assert_eq!(
                parse_document(&yaml, profile).expect("round-trip parameter selectors"),
                parsed
            );

            // A sequence is matcher syntax only in the exact single-key map.
            // Additional fields cannot disappear through the query matcher
            // decoder, even when containment permits query annotations.
            for invalid in [
                "{ any: [one], other: second }",
                "{ any: [one], future_constraint: true }",
                "{ any: [one, 2] }",
            ] {
                let invalid_source = source.replace("{ any: [one, two] }", invalid);
                assert!(
                    parse_document(&invalid_source, profile).is_err(),
                    "ambiguous parameter matcher must fail: {invalid}"
                );
            }
        }
    }

    #[test]
    fn parameter_maps_reject_empty_nested_selectors_in_both_profiles() {
        let source = |params: &str| {
            format!(
                "version: 1\nnetwork_policies:\n  mcp:\n    endpoints:\n      - host: mcp.example.com\n        port: 443\n        protocol: mcp\n        mcp: {{}}\n        rules:\n          - allow:\n              method: tools/call\n              params: {params}\n"
            )
        };
        for profile in [ParseProfile::RuntimeStrict, ParseProfile::ContainmentInput] {
            let parsed = parse_document(&source("{}"), profile)
                .expect("an empty root params map intentionally omits selectors");
            assert!(parsed.extensions.is_empty());
            assert!(
                parsed.policy.network_policies["mcp"].endpoints[0].rules[0]
                    .allow
                    .params
                    .is_empty()
            );

            for params in [
                "{ name: {} }",
                "{ arguments: { file: {} } }",
                "{ arguments: { file: safe, missing: {} } }",
                "{ any: {} }",
            ] {
                assert!(
                    parse_document(&source(params), profile).is_err(),
                    "empty nested selectors must not disappear: {params}"
                );
            }
        }
    }

    #[test]
    fn diagnostic_path_bounds_preserve_full_containment_paths() {
        let field = "é".repeat(2_000);
        let source = format!("version: 1\n{field}: true\n");
        let parsed = parse_document(&source, ParseProfile::ContainmentInput)
            .expect("containment retains unsupported fields");
        assert_eq!(parsed.extensions.len(), 1);
        assert_eq!(parsed.extensions[0].path, field);
        let message = parse_document(&source, ParseProfile::RuntimeStrict)
            .expect_err("runtime rejects unsupported fields")
            .to_string();
        assert!(message.len() <= MAX_UNKNOWN_FIELD_PATH_BYTES + 50);
        assert!(message.contains("...' in authored policy"));
    }

    #[test]
    fn open_user_maps_do_not_become_extensions() {
        let source = r#"
version: 1
network_middlewares:
  audit:
    middleware: logger
    config:
      arbitrary_plugin_key: { nested: true }
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp: {}
        rules:
          - allow:
              method: tools/call
              query:
                arbitrary_name: { any: ["one", "two"] }
              params:
                arguments:
                  nested:
                    leaf: "value-*"
"#;
        let parsed = parse_document(source, ParseProfile::ContainmentInput).unwrap();
        assert!(parsed.extensions.is_empty(), "{:?}", parsed.extensions);
    }

    #[test]
    fn managed_metadata_and_review_are_containment_only() {
        let source = r"
version: 1
metadata:
  policy_id: managed/default
  version: 7
  allowed_modes: [audit, enforce]
  default_mode: enforce
  audit_label: production
network_policies:
  api:
    endpoints:
      - host: example.com
        port: 443
        review: { required: true, reason: human approval }
        rules:
          - allow:
              method: GET
              path: /v1/**
              review: { required: true, reason: broad path }
";
        let parsed = parse_document(source, ParseProfile::ContainmentInput).unwrap();
        assert_eq!(parsed.policy.metadata.unwrap().version, 7);
        assert!(parsed.extensions.is_empty());
        assert!(parse_document(source, ParseProfile::RuntimeStrict).is_err());
    }

    #[test]
    fn parser_budgets_are_enforced_during_decode() {
        let tiny = ParseLimits {
            max_bytes: 256,
            max_depth: 2,
            max_events: 8,
            max_nodes: 4,
            max_scalar_bytes: 32,
            max_alias_expansions: 0,
            max_mapping_keys: 2,
            max_sequence_elements: 2,
            max_documents: 1,
            max_merge_keys: 0,
            alias_anchor_ratio: Some(1.0),
        };
        assert!(
            parse_document_with_limits(
                "version: 1\nnetwork_policies: {a: {}, b: {}, c: {}}\n",
                ParseProfile::ContainmentInput,
                tiny,
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_reader_rejects_growth_past_limit_and_invalid_utf8() {
        let limits = ParseLimits {
            max_bytes: 12,
            ..ParseLimits::default()
        };
        assert!(
            parse_policy_reader(
                &b"version: 1\nextra"[..],
                ParseProfile::RuntimeStrict,
                limits,
            )
            .is_err()
        );
        assert!(parse_policy_bytes(&[0xff], ParseProfile::RuntimeStrict).is_err());
    }

    #[test]
    fn access_presets_expand_consistently() {
        assert_eq!(
            expand_access_preset("rest", "read-only"),
            Some(&["GET", "HEAD", "OPTIONS"][..])
        );
        assert_eq!(
            expand_access_preset("websocket", "read-write"),
            Some(&["GET", "WEBSOCKET_TEXT"][..])
        );
        assert_eq!(expand_access_preset("rest", "unknown"), None);
    }
    #[test]
    fn rejects_unknown_fields_at_every_closed_schema_level() {
        let cases = [
            ("version: 1\nfuture: true\n", "future"),
            (
                "version: 1\nfilesystem_policy: { future: true }\n",
                "filesystem_policy.future",
            ),
            (
                "version: 1\nlandlock: { future: true }\n",
                "landlock.future",
            ),
            ("version: 1\nprocess: { future: true }\n", "process.future"),
            (
                "version: 1\nnetwork_policies: { api: { future: true } }\n",
                "network_policies.api.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, future: true }] } }\n",
                "network_policies.api.endpoints[0].future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { binaries: [{ path: /bin/tool, future: true }] } }\n",
                "network_policies.api.binaries[0].future",
            ),
            (
                "version: 1\nnetwork_middlewares: { audit: { middleware: logger, future: true } }\n",
                "network_middlewares.audit.future",
            ),
            (
                "version: 1\nnetwork_middlewares: { audit: { middleware: logger, endpoints: { future: true } } }\n",
                "network_middlewares.audit.endpoints.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, credential_binding: { provider: p, future: true } }] } }\n",
                "network_policies.api.endpoints[0].credential_binding.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, json_rpc: { future: true } }] } }\n",
                "network_policies.api.endpoints[0].json_rpc.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, protocol: mcp, mcp: { future: true } }] } }\n",
                "network_policies.api.endpoints[0].mcp.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, graphql_persisted_queries: { op: { future: true } } }] } }\n",
                "network_policies.api.endpoints[0].graphql_persisted_queries.op.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, rules: [{ future: true, allow: {} }] }] } }\n",
                "network_policies.api.endpoints[0].rules[0].future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, rules: [{ allow: { future: true } }] }] } }\n",
                "network_policies.api.endpoints[0].rules[0].allow.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, deny_rules: [{ future: true }] }] } }\n",
                "network_policies.api.endpoints[0].deny_rules[0].future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, rules: [{ allow: { query: { q: { any: [one], future: true } } } }] }] } }\n",
                "network_policies.api.endpoints[0].rules[0].allow.query.q.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, rules: [{ allow: { tool: { any: [one], future: true } } }] }] } }\n",
                "network_policies.api.endpoints[0].rules[0].allow.tool.future",
            ),
        ];

        for (source, expected_path) in cases {
            let error = parse_policy(source, ParseProfile::RuntimeStrict)
                .expect_err("unknown field must fail closed");
            assert!(
                error.to_string().contains(expected_path),
                "missing path {expected_path} in {error:?}"
            );
        }
    }

    #[test]
    fn accepts_any_as_an_open_mcp_parameter_name() {
        let source = r#"
version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp: {}
        rules:
          - allow:
              method: tools/call
              params:
                arguments:
                  any: "first"
                  other: "second"
"#;

        let policy = parse_policy(source, ParseProfile::RuntimeStrict)
            .expect("open MCP parameter names must parse");
        let params = &policy.network_policies["mcp"].endpoints[0].rules[0]
            .allow
            .params;
        let ParameterMatcher::Object(arguments) = &params["arguments"] else {
            panic!("arguments must remain an open parameter object");
        };
        assert!(matches!(
            arguments["any"],
            ParameterMatcher::Matcher(QueryMatcher::Glob(ref value)) if value == "first"
        ));
        assert!(matches!(
            arguments["other"],
            ParameterMatcher::Matcher(QueryMatcher::Glob(ref value)) if value == "second"
        ));
    }

    #[test]
    fn bounds_unknown_field_diagnostics_for_wide_maps_under_long_keys() {
        let policy_name = "é".repeat(2_000);
        let mut unknown_fields = String::new();
        for index in 0..2_000 {
            writeln!(unknown_fields, "      unknown_{index}: true")
                .expect("writing to a string cannot fail");
        }
        let source = format!("version: 1\nnetwork_policies:\n  {policy_name}:\n{unknown_fields}");

        let error = parse_policy(&source, ParseProfile::RuntimeStrict)
            .expect_err("unknown fields must fail closed");
        let message = error.to_string();
        assert!(message.contains("unknown field 'network_policies."));
        assert!(message.contains("...' in authored policy"));
        assert!(message.len() <= MAX_UNKNOWN_FIELD_PATH_BYTES + 50);
    }
}
