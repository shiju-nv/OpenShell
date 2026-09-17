# Security Policy

OpenShell policy defines what a sandboxed agent can access. The workload boundary enforces kernel and process controls; the isolated supervisor enforces network policy and credential bindings. The gateway stores and delivers configuration, but it does not make per-request egress decisions.

For the field-by-field YAML reference, use
[Policy Schema Reference](../docs/reference/policy-schema.mdx).

## Policy Areas

| Area | Enforcement |
|---|---|
| Filesystem | Landlock restricts read-only and read-write paths. |
| Process | The boundary launches the agent with the admitted non-root identity and zero capabilities. |
| Network | The proxy evaluates destination, port, calling binary, and optional L7 rules. |
| Provider access | Attached provider profiles contribute endpoint and binary rules; credentials remain bound to profile-authorized endpoints. |
| Runtime settings | Typed settings are delivered with policy and can be global or sandbox scoped. |

Filesystem and process policy are startup controls. A rejected initial configuration may be repaired only while durable state proves that no workload release has been authorized. The first release authorization locks static policy before the workload may run. Network policy remains dynamic and is installed with the matching provider state.

### Authored policy boundary

`openshell-policy-schema` owns the authored YAML and JSON representation, bounded decoding, and pure language semantics such as access presets, MCP revision vocabulary, effective ports and rule names, protocol classification, and lexical path normalization. It preserves field presence, including the difference between an omitted filesystem section and a present empty object. `openshell-policy` owns protobuf conversion, composition, merge behavior, and validation that depends on runtime components.

The prover uses the schema's `RuntimeStrict` profile, which requires `version: 1` and rejects managed annotations and unknown fields in closed schema objects. Maximum-policy containment uses `ContainmentInput`, which retains managed metadata, review annotations, and unknown closed-object fields for its support audit. Both profiles require the known field types. Middleware configuration, query names, persisted-query names, and recursive MCP parameter names are open user-data namespaces. Recognizing a parameter shape in the schema does not imply that every protocol supports that matcher at runtime.

### OPA runtime data

The same schema crate supplies the bounded raw decoder used by OPA string, byte-reader, and file loading. Input budgets apply while the parser constructs the document; reader allocation is bounded before decoding, and regular-file loading also checks metadata. Duplicate and merge keys are rejected. The policy reference documents the byte, nesting, collection, scalar, and alias limits.

Raw OPA data has a separate runtime contract. It can omit `version`, retain unrelated application data at the root, and carry lowered protocol fields, explicit matcher objects, binary-resolution entries, and endpoint provenance. The loader validates governed policy sections through a separate canonical-schema projection while retaining the original runtime data. Closed governed objects reject unknown keys, malformed scalars, positional arrays, and explicit nulls. A missing filesystem section enables `include_workdir`; a present empty section disables it. Validation does not derive credential provenance or let input override the trusted runtime binary-identity setting. Custom Rego output has its own evaluation contract; these checks validate the supplied data document.

After L7 validation, the loader converts nonempty string query and MCP parameter matchers to explicit `glob` objects, including tool aliases and deny rules. Matchers supported by YAML and protobuf expose the same runtime representation. Existing `glob` and `any` matchers retain their values, and normalization preserves endpoint provenance. Empty scalar query matchers remain an OPA-only form because Rego gives them different behavior from empty `glob` objects.

Before applying Landlock, the supervisor enriches baseline filesystem paths that
the runtime needs. Missing baseline paths are skipped so one absent runtime path
does not weaken the whole ruleset. When GPU devices are present, GPU baseline
enrichment adds existing GPU device nodes as read-write paths and promotes
`/proc` to read-write because CUDA workloads write thread metadata under
`/proc/<pid>/task/<tid>/comm`.

Landlock rules are tailored to the inode type reported by the already-opened
path descriptor. Directories retain the requested directory and file rights;
regular files, device nodes, sockets, and other non-directories retain only
file-compatible rights. This avoids rejecting valid mixed-path policies without
weakening `hard_requirement`: genuine unsupported ABI capabilities and
preparation failures still fail sandbox startup.

## Network Decisions

Ordinary network traffic follows this order:

1. Force traffic through the sandbox proxy with namespace and seccomp controls.
2. Identify the calling binary and compare its trusted identity.
3. Reject hard-blocked destinations, including unsafe internal IP ranges unless
   explicitly allowed.
4. Match the destination and binary against network policy blocks.
5. Apply optional HTTP/L7 rules for endpoints that enable protocol inspection.
6. Allow, deny, audit, or log according to the matched policy.

Explicit deny and hardening checks win over allow rules. If no rule matches, the
request is denied.

## Host Wildcards

Network endpoint `host` patterns accept a `*` wildcard inside the first DNS
label and as an entire middle DNS label. The OPA runtime matches with a `.`
label boundary, so a wildcard never spans dots. The validator enforces the same
boundary so that policy load fails fast instead of silently mismatching at the
proxy.

| Pattern | Accepted | Example match | Notes |
|---|---|---|---|
| `*.example.com` | Yes | `api.example.com` | Single first label of any value. |
| `**.example.com` | Yes | `a.b.example.com` | Recursive wildcard as the entire first label. |
| `*-aiplatform.googleapis.com` | Yes | `us-central1-aiplatform.googleapis.com` | Intra-label wildcard inside the first DNS label. |
| `*.s3.*.amazonaws.com` | Yes | `bucket.s3.us-east-1.amazonaws.com` | Middle-label `*` matches exactly one DNS label. |
| `*` or `**` | No | — | Matches every host. |
| `*.com`, `**.com` | No | — | TLD wildcards (`labels <= 2`). |
| `foo.us-*.example.com` | No | — | Partial middle-label wildcards are not allowed. |
| `foo.**.example.com` | No | — | Recursive wildcard outside the first label is not allowed. |
| `foo**.example.com` | No | — | Recursive `**` mixed inside a label; allowed only as the entire first label. |

Validation rejects the disallowed patterns at policy load time. OPA load errors omit the supplied hostname. Exact hosts and IP addresses do not use this wildcard-validation path.

## TLS and L7 Inspection

For HTTP endpoints that need request-level controls, the proxy can terminate TLS
with the sandbox's ephemeral CA and inspect method/path or protocol-specific
metadata before forwarding. The proxy also supports credential injection on
terminated HTTP streams when policy allows the endpoint.

Static provider credentials have an independent endpoint-binding boundary.
Provider profile endpoints define that boundary by default. An endpointless
profile can delegate binding authority to sandbox policy through an endpoint
that names the concrete attached provider instance. The gateway rejects
unattached, profileless, endpointful, and gateway-global uses of that policy
binding. Policy endpoint changes rotate the provider-environment revision so
the supervisor installs policy and credential binding snapshots atomically.

Raw streams and long-lived response bodies are connection scoped. Policy
generation changes close relays pinned to the previous generation instead of
allowing them to continue under stale authorization. HTTP upgrades switch to
raw relay by default. A `protocol: rest` endpoint can opt in to
`websocket_credential_rewrite` for client-to-server WebSocket text messages
after an allowed `101` upgrade; server-to-client traffic and all other upgraded
protocols remain raw passthrough.

A `protocol: tcp` hostname is a connection-routing constraint, not an
application-authority boundary. Transparent capture validates the approved DNS
name, pinned destination address, port, and calling binary before opening the
stream, but it does not inspect TLS SNI, HTTP `Host`, or another protocol-level
destination. Compatible shared infrastructure can therefore let a client
select another tenant, virtual host, or service behind the approved front door.

## Credentialed Endpoints

OpenShell keeps provider credentials on paths it can inspect or rewrite by
default. The gateway derives credential provenance from the attached providers
and stamps it onto the effective policy at composition time. This provenance is
internal, contains no credential identifiers or values, and is never trusted
from user-authored policy.

Every evaluation clears provenance across the whole policy and re-derives it
from two sources:

- the endpoints of attached provider profiles that carry credentials, and
- the valid `credential_binding` entries of the sandbox policy that name an
  attached provider whose profile is endpointless.

A binding reduces to a host and port scope only. Dropping the path is
deliberate: a path is not observable on an L4 or `tls: skip` endpoint, so a
path-scoped derivation would omit the marker on exactly the surfaces the
uninspected-credential gate exists to catch. A malformed binding — empty
provider, missing host, or a port outside `1..=65535` — fails the evaluation
instead of contributing a scope. Bindings naming an endpointful profile or an
unattached provider contribute nothing; the gateway rejects those uses
separately.

Both sources merge into one deduplicated scope set, and each endpoint is
stamped once per evaluation from that set, so binding-derived scopes reach the
same gates as profile-derived ones. The stamp is an assignment, not an
accumulation, so an endpoint that stops matching a credentialed scope — or
whose binding was removed — loses its marker in the same pass. This must remain
a full recomputation: a delta-based derivation would let a series of
individually valid edits reach a state no single edit would have admitted.

Credentialed L4-only and `tls: skip` endpoints fail policy validation unless the
public `allow_uninspected_credentials` escape hatch is explicitly enabled. The
flag defaults to `false` and is security-flagged in policy approval flows.
Incremental merges only ever add the flag to a matching endpoint; clearing it
requires removing the endpoint or replacing the policy.

The network supervisor independently enforces the same boundary. Credentialed
WebSocket upgrades use the parsed relay, binary frames fail closed, and text
placeholders require rewrite. REST bodies continue streaming when body rewrite is disabled. The relay holds
complete placeholder candidates until a request-scoped metadata snapshot can
classify them. Authoritatively unknown keys and valid credentials with a current
binding pass unchanged, including references bound to the destination itself.
Revoked or invalid identities and unavailable classification state
fail closed. Classification never substitutes secret values and shares the request's
credential revision; stale credential or policy generations terminate forwarding.
Header rewriting scans only headers. Body bytes received in the initial proxy
read follow the same body classifier or explicit rewriter as later reads.
Candidates are limited to 4096 wire bytes, including percent encoding. Malformed
or oversized candidates fail closed; HTTP trailers retain prefix-based rejection. Explicitly opted-in
endpoints retain raw passthrough behavior.

Body denials return `credential_placeholder_in_request_body` in a local HTTP 403
response and discard any partially written upstream request. Safe preceding bytes
may already have reached upstream.

Denials emit both the relevant network activity and a detection finding. Events
identify only the destination, policy, traffic surface, and controlled denial reason; they never include
credential names, placeholders, body content, or secret values.

Credential provenance is gateway-derived and deliberately absent from the authored policy schema. The raw OPA loader preserves supplied runtime provenance but does not derive it for an unstamped policy. Gateway-delivered policy supplies the authoritative provenance for managed sandboxes. A policy without provenance applies neither the raw-tunnel refusal nor the WebSocket binary-frame refusal. The request-body backstop still applies because it keys off the presence of a secret resolver rather than endpoint provenance.

Two supervisor-local paths load a policy without provenance. A supervisor
booting from an explicitly provisioned policy file has a bounded window before
that policy is resynchronized to the gateway, which then serves a stamped
effective policy. An explicit supervisor Rego and data override is permanent,
because gateway revisions are observed for settings and providers but never
replace the local policy. Workload-image files and environment variables cannot
configure the separately isolated supervisor. When a supervisor override is
combined with injected provider credentials, the supervisor emits a
high-severity detection finding at startup naming the inactive controls.

## Policy Load Diagnostics

`OpaEngine` bounds returned load and reload errors from files, readers, strings, and protobuf. Each message contains at most eight error items and 512 UTF-8 bytes, including the heading, separators, and any `additional violations omitted` marker. The loader uses fixed categories and schema locations, omitting policy names, values, paths, source snippets, and nested error chains.

Typed categories identify process, filesystem, Landlock, endpoint, credential, MCP, and middleware validation failures. Shared raw-schema failures identify a fixed schema location and category. Opaque L7 errors identify the protocol-configuration or policy-validation stage; endpoint conflicts report ambiguous selectors. Parser errors retain a fixed category and numeric line and column when available. File I/O, Rego loading, and internal policy-data failures use fixed messages.

A rejected engine reload leaves that engine's installed policy, generation, and decisions unchanged. The supervisor then applies its configured rejection posture and workload hold rules described below. These bounds cover returned OPA load errors; accepted-policy warnings, runtime request diagnostics, and gateway-authored policy parser messages have separate reporting contracts.

## Live Updates

The gateway stores sandbox-authored policy revisions separately from effective configuration, which can include gateway-global overrides and provider-profile layers. An authenticated control poll issues an immutable delivered snapshot of the selected policy, settings, and provider revision. Later changes become desired at the next poll. Observer reads show desired policy and do not prove that the runtime installed it.

The OPA loader checks the object and list shapes of raw policy data before injecting runtime fields, normalizing values, or expanding access presets. It rejects the first malformed container with a fixed structural error that excludes authored keys and values. This check preserves valid versionless OPA data and runtime-only fields. A rejected OPA engine reload leaves that engine's installed policy, generation, and decisions unchanged; the supervisor separately applies its configured runtime rejection mode.

An explicitly supplied MCP rule `params` value must be a map in both allow and deny rules. Omit the field when using only the `tool` alias; `params: null` is rejected before alias lowering. A rejected raw policy reload preserves the active evaluator and its generation.

The supervisor validates complete effective policy generations before
activation. Overlapping endpoint selectors may contribute request allow and
deny rules only when their connection and request-processing metadata agree;
conflicting TLS, destination, credential, parser, or enforcement metadata
rejects the complete generation. Plain L4 endpoints do not contribute
request-processing metadata, so they may overlap an L7 endpoint when their
connection metadata agrees. When request paths overlap, a path endpoint with a
higher specificity rank deterministically overrides broader request-processing
metadata. Equally specific overlapping endpoints must agree.

Gateway mutation paths validate the complete effective candidate before
persistence when the affected sandbox scope is known. Direct replacements,
incremental merges and approvals, provider attachment, and profile fanout reject
ambiguity atomically, without creating an invalid revision or partially
activating an update. Supervisor validation remains the defense-in-depth
boundary for startup, concurrent changes, and sources outside those mutations.

The supervisor prepares policy, middleware and matching provider credentials before publication. It stages the boundary environment while the workload is frozen and new exec is blocked, publishes the matching control generation, and commits the boundary installation without resuming execution. Gateway acceptance authorizes release; only an exact release response and final activation report restore readiness and mark the policy loaded. Provider-only updates use the same path. Confirmation or reconnection alone cannot release a workload.

The `[openshell.gateway] policy_validation_failure_mode` setting controls rejected runtime candidates. Gateway preflight rejections leave the active configuration unchanged. The default `fail_closed` holds the workload and readiness, denies new egress, and invalidates old relays until a valid configuration activates. `retain_last_valid` can keep or restore only a previously accepted configuration whose installation is still known for the same boundary. It never authorizes mixed policy and credentials, uncertain commits, or an initial startup fallback. The gateway distributes this posture with effective snapshots; configuration and finding events identify the rejection and effective posture. After first release authorization, static controls require a new sandbox.

Gateway-global policy can override sandbox-scoped policy. Use it sparingly
because it changes the effective access model for every sandbox on the gateway.

## Policy Advisor

The policy advisor pipeline turns observed denials into draft policy
recommendations. There are two proposers (sandbox-side mechanistic mapper,
agent-authored via `policy.local`); the gateway is the single referee.
When enabled, L7 `policy_denied` responses include both structured
`next_steps` and a short `agent_guidance` string so generic agents can continue
through the proposal loop instead of treating the denial as terminal.

1. **Submit.** Both proposers POST through the same `SubmitPolicyAnalysis`
   path. Each chunk is persisted with its `analysis_mode` for audit provenance.
   Agent-authored chunks cannot request `protocol: tcp` or `tls: skip`; the
   sandbox-local API rejects those transport choices for immediate feedback,
   and the gateway repeats the check before persistence.
   Omitted-protocol endpoints remain available through the explicit proxy with
   default TLS termination and HTTP authority checks. Administrators can still
   author native TCP and raw TLS policy directly.
2. **Build and validate the candidate.** The gateway first canonicalizes a
   mechanistic proposal against the live effective policy. If an endpoint is
   already governed by an inspected or provider-owned contract, the candidate
   preserves that contract and adds only the proposed sandbox binary. Provider
   rules are immutable inputs; the sandbox contribution is stored as an
   overlay. The gateway then performs the same merge, policy validation,
   provider composition, credential preflight, and prover evaluation that the
   candidate would encounter when applied. Each chunk stores the resulting
   effective candidate, its hashes, any application error, and a review token
   derived from the candidate and its non-secret live inputs.
3. **Auto-approval gate (proposer-agnostic, opt-in).** Auto-approval fires
   only when *all three* conditions hold: (a) `proposal_approval_mode`
   resolves to `"auto"` — gateway scope wins, sandbox scope is the
   per-sandbox override, default is `"manual"`; (b) the prover delta is empty
   (`prover: no new findings`); and (c) the security notes recomputed from
   the chunk's current proposed rule are empty (see
   [Security-notes gate](#security-notes-gate)). Before merging, the gateway
   reloads the stored chunk and recomputes its candidate from live policy,
   provider, and credential inputs. If the review token is unchanged, the
   gateway reuses the persisted prover result. If it changed, the gateway
   persists the refreshed candidate and requires a fresh review instead of
   applying it. Decode, prover, merge, provider-composition, or credential
   failures leave the chunk pending with an application error. The audit event uses `CONFIG:APPROVED` and carries
   `auto=true`, `source=<mode>`, `prover_delta=empty`, and
   `resolved_from=<gateway|sandbox>` as unmapped fields, with message text
   `"auto-approved: no new prover findings"` — never `safe`. The opt-in gate
   preserves OpenShell's default-deny posture: with no setting at either
   scope, every proposal lands in `pending` for human review, even
   when the prover sees no findings.
4. **Implicit supersede.** On any successful submission, the gateway scans
   the sandbox's pending chunks for matches on `(host, port, binary)` and
   auto-rejects the older ones with reason `"superseded by chunk X"`. This
   gives the agent a refinement path (broad mechanistic L4 → narrow agent
   L7) without an explicit `supersedes_chunk_id` field.
5. **Mechanistic dedup and self-reject.** Mechanistic submissions dedup on
   `(host, port, binary)`: a repeat denial for an endpoint that already has a
   draft row folds into that row (bumping `hit_count`) instead of creating a
   new chunk. When the endpoint is already covered by a *different* approved
   chunk, the redundant mechanistic submission self-rejects on arrival with
   reason `"already covered by approved chunk X"`. This only ever acts on a
   genuinely fresh, still-`pending` submission; it never rewrites the status
   of an already-decided chunk. A dedup hit that resolves to an approved
   row's own id leaves that chunk `approved` and merged — the self-reject
   path does not un-merge a rule, so flipping an approved chunk to `rejected`
   would leave the governance ledger disagreeing with the still-enforced
   policy.
6. **Escalation.** Anything else lands in `pending` for human review.

After any successful policy write, pending chunks already covered by the new
live effective policy are rejected as redundant. This keeps the review inbox
aligned with what the sandbox currently enforces.

Endpoint advisor markers are provenance, not authorization or connection
metadata. Provider- or user-authored endpoints carry explicit provenance;
`policy.local` endpoints carry advisor provenance. A difference in endpoint
provenance alone is compatible during effective-policy ambiguity validation.
When identical endpoints merge, an explicit declaration dominates an advisor
declaration. Proposal coverage likewise ignores provenance so an approved
overlay converges when an existing explicit declaration already supplies the
same identity.

This compatibility does not weaken SSRF classification. Exact-host trust
requires one matching rule to contain both an exact explicit endpoint and a
matching binary identity. An advisor endpoint cannot assemble that trust from
an unrelated explicit endpoint. When the advisor observes a new binary for an
existing explicit endpoint contract, canonicalization keeps the observation in
a separate rule whose endpoint retains advisor provenance. A provider or user
rule may independently establish trust for its own explicit endpoint and binary
pair, but an advisor overlay does not broaden that pair to a different binary.

### Security-notes gate

Separately from the prover, each chunk carries advisory `security_notes`.
Reads, bulk approval, and auto-approval regenerate them from the current
stored proposed rule instead of trusting a persisted value that may be stale
after an edit. Non-empty notes block auto-approval and make
`ApproveAllDraftChunks` skip the chunk unless `include_security_flagged` is
set. The chunk stays `pending`; an explicit human approval can still merge a
flagged chunk.

Private/internal destinations are advisory, not blocking. A literal endpoint
IP, `allowed_ips` entry, or CIDR intersection in RFC 1918, CGNAT
`100.64.0.0/10`, IPv6 ULA `fc00::/7`, or another special-use range covered by
`openshell-core` `net::is_internal_net` produces a note. A hostless rule
carrying `allowed_ips` earns an extra note because it can match any hostname
resolving into the range.

Always-blocked destinations are separate from this advisory classification.
Loopback, link-local, and unspecified IPs/CIDRs, plus `localhost` and known
metadata endpoint hostnames, are excluded from security notes. Submit and edit
may store such a draft, but existing merge validation rejects it when an
approval attempts to add it to policy; runtime SSRF protections remain the
final enforcement boundary.

## What the prover decides

The prover answers four formal questions about each proposed policy
change. Each "yes" answer becomes its own categorical finding — there is
no severity grade. Any finding (of any category) blocks auto-approval.
The categories are intended to be (mostly) mutually exclusive per
underlying change: the gateway suppresses `capability_expansion` paths
whose `(binary, host, port)` is also in the `credential_reach_expansion`
delta, so a brand-new credentialed reach surfaces as one finding rather
than one reach + N method findings.

| Category | The prover detects… |
|---|---|
| `link_local_reach` | The proposal grants reach to a host in `169.254.0.0/16`, `fe80::/10`, or a known metadata hostname such as `metadata.google.internal`. Unconditional — cloud-metadata endpoints serve credentials regardless of sandbox state. |
| `l7_bypass_credentialed` | The proposal lets a binary using a non-HTTP wire protocol (`git-remote-https`, `ssh`, `nc`) reach a host where a sandbox credential is in scope. The L7 proxy cannot inspect the wire protocol; the reviewer decides whether to trust the binary with the credential. |
| `credential_reach_expansion` | A binary gained credentialed reach to a (host, port) it could not reach before. New authenticated reach is a stated intent change; the reviewer confirms the binary should authenticate to the host at all. |
| `capability_expansion` | On a (binary, host, port) that already had credentialed reach, the policy adds a new HTTP method. The reviewer sees exactly which method was added (e.g., PUT) and decides if it's part of the agent's task. |

"Credential in scope" is sandbox-coarse, not binary-fine: a credential is
considered in scope if the sandbox has a provider attached whose
`target_hosts` include the proposed endpoint's host, including runtime-like
first-label wildcard coverage such as `*.github.com` covering
`api.github.com`. v1 does not model credential scopes (read-only vs write);
presence is enough.

Proposals intentionally omit `allowed_ips`. If a proposed rule targets a host
that resolves to a private IP, the proxy's runtime SSRF classification blocks
the connection. The operator must then add an explicit `allowed_ips` entry to
permit it — a two-step flow that keeps SSRF protection on by default.

The advisor proposes narrow additions and preserves explicit-deny behavior.
Auto-approval is gated on prover determinism, not human judgment; an LLM-based
contextual reviewer is a deliberate future addition layered on top of the
deterministic prover gate.

## Security Logging

Sandbox events that represent observable behavior use OCSF structured logs:

| Event | OCSF class |
|---|---|
| Network and proxy decisions | Network or HTTP activity |
| SSH authentication and relay activity | SSH activity |
| Process lifecycle | Process activity |
| Policy and settings changes | Configuration state change |
| Security findings | Detection finding |

Use plain tracing for internal plumbing such as retries, debug state, and
intermediate steps where the final observable event is logged separately.
Forward-proxy success is a final observable event: emit it only after
middleware, token grants, credential rewriting, policy-generation checks, and
the HTTP relay have succeeded so a later denial cannot coexist with an allowed
record for the same request.

Never log secrets, credentials, bearer tokens, or query parameters in OCSF
messages. OCSF JSONL output may be shipped to external systems.
The gateway-local OCSF JSONL file sink is restricted to the Windows/MXC path
and requires an explicit `OPENSHELL_OCSF_JSON=1` opt-in. Other gateway
deployments do not initialize this gateway file sink; a cross-platform gateway
sink requires its own storage and configuration integration.
MXC ETW process events record executable identity but omit command-line
arguments from structured fields and messages. Raw ETW debug summaries replace
the `commandLine` value with `[REDACTED]`, including pending-buffer eviction
diagnostics.
MXC ETW attribution never treats command text as ownership evidence. It uses the
driver-owned `wxc-exec` PID plus its kernel process start key as the initial
anchor. ETW attaches that generation key to each record, and the driver queries
the same key from its child process handle. PID attribution requires both values
to match, so reuse cannot transfer ownership between process generations.
Retired PID evidence is discarded; established identity, activity, and
correlation-vector links remain eligible during the five-second late-event
window. Records without matching generation evidence fail closed.
