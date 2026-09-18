// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! Observe admission through the gateway and independent workload/upstream records.

// Keep the image/provider repair and restart regression independent of the
// controlled-upstream scenarios below.
#[path = "policy_activation/image_provider_repair.rs"]
mod image_provider_repair;

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::container::{ContainerEngine, ImageGuard};
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PROVIDER_A: &str = "service-a";
const PROVIDER_B: &str = "service-b";
const TOKEN_ENV: &str = "ACTIVATION_TOKEN";
const TOKEN_ENV_B: &str = "ACTIVATION_TOKEN_B";
const TOKEN_A: &str = "cred-A";
const TOKEN_B: &str = "cred-B";
const STARTS: &str = "/sandbox/activation-starts";
const HEARTBEAT: &str = "/sandbox/activation-heartbeat";
const WORKLOAD: &str = r"import json, os, pathlib, time
with open('/sandbox/activation-starts', 'a') as starts:
    identity = {'pid': os.getpid(), 'start_ticks': pathlib.Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]}
    starts.write(json.dumps(identity, sort_keys=True) + '\n')
while True:
    pathlib.Path('/sandbox/activation-heartbeat').write_text(str(time.monotonic_ns()))
    time.sleep(0.1)
";

struct Upstream {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

struct ProbeTask(tokio::task::JoinHandle<()>);

impl Drop for ProbeTask {
    fn drop(&mut self) {
        // A failed assertion must not leave a detached task issuing CLI execs
        // after the test's sandbox and provider guards have been dropped.
        self.0.abort();
    }
}

impl Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind upstream");
        let port = listener.local_addr().expect("upstream address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let captured = Arc::clone(&captured);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 2048];
                    while request.len() < 16_384 {
                        let read =
                            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                                .await;
                        let Ok(Ok(read)) = read else { return };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..read]);
                        if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            break;
                        }
                    }
                    captured
                        .lock()
                        .expect("upstream observations")
                        .push(String::from_utf8_lossy(&request).into_owned());
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .await;
                });
            }
        });
        Self {
            port,
            requests,
            task,
        }
    }

    fn captured(&self) -> Vec<String> {
        self.requests.lock().expect("upstream observations").clone()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ProviderGuard {
    name: String,
    profile: bool,
    provider: bool,
}

impl Drop for ProviderGuard {
    fn drop(&mut self) {
        // A sandbox deletion drains asynchronously. Retry only resources this
        // test created; an existing shared provider must never be deleted.
        for _ in 0..40 {
            let mut deleted = true;
            if self.provider {
                deleted = std::process::Command::new(openshell_bin())
                    .args(["provider", "delete", &self.name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success());
                if deleted {
                    self.provider = false;
                }
            }
            if deleted && self.profile {
                deleted = std::process::Command::new(openshell_bin())
                    .args(["provider", "profile", "delete", &self.name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success());
                if deleted {
                    self.profile = false;
                }
            }
            if deleted {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

async fn cli_ok(args: &[&str]) -> String {
    let (output, code) = tokio::time::timeout(Duration::from_secs(120), run_cli(args))
        .await
        .expect("CLI command timeout");
    assert_eq!(code, 0, "{} failed:\n{output}", args.join(" "));
    strip_ansi(&output)
}

fn fixture(name: &str) -> String {
    let directory = std::env::var_os("OPENSHELL_ACTIVATION_FIXTURES").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/configuration-activation"),
        PathBuf::from,
    );
    std::fs::read_to_string(directory.join(name)).expect("read activation policy fixture")
}

fn materialize_policy(directory: &Path, name: &str, port: u16) -> PathBuf {
    // Only endpoint locations change. Provider bindings and all policy behavior
    // remain the same as the fixture used by the independent acceptance runner.
    let policy = fixture(name)
        .replace("egress-a.invalid", &upstream_host().to_string())
        .replace("egress-b.invalid", &upstream_host().to_string())
        .replace("port: 18443", &format!("port: {port}"));
    let path = directory.join(name);
    std::fs::write(&path, &policy).expect("write rendered policy");
    record(name, json!({ "rendered_policy": policy }));
    path
}

/// Use the explicit host route proven by the runner's controlled upstream probe.
fn upstream_host() -> Ipv4Addr {
    std::env::var("OPENSHELL_ACCEPTANCE_UPSTREAM_HOST")
        .expect("runner must prove the controlled upstream host route")
        .parse()
        .expect("controlled upstream route must be an IPv4 address")
}

fn record(stage: &str, observation: Value) {
    let mut envelope = serde_json::Map::new();
    envelope.insert("stage".to_string(), Value::String(stage.to_string()));
    envelope.insert("observation".to_string(), observation);
    println!("ACTIVATION_OBSERVATION {}", Value::Object(envelope));
}

fn image(context: &Path, image_policy: Option<&Path>) -> ImageGuard {
    let copy = image_policy.map_or(String::new(), |path| {
        std::fs::copy(path, context.join("image-policy.yaml")).expect("copy image policy");
        "COPY image-policy.yaml /etc/openshell/policy.yaml\n".to_string()
    });
    // Image users and policy exist only in the boundary filesystem. Their
    // resolution must not depend on accounts installed with the control process.
    let dockerfile = format!(
        r#"FROM public.ecr.aws/docker/library/python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/* \
    && groupadd sandbox && useradd -m -g sandbox sandbox && mkdir -p /sandbox && chown sandbox:sandbox /sandbox
{copy}WORKDIR /sandbox
USER sandbox
CMD ["sleep", "infinity"]
"#
    );
    std::fs::write(context.join("Dockerfile"), dockerfile).expect("write Dockerfile");
    let image = ImageGuard::build(
        "configuration-activation",
        &context.join("Dockerfile"),
        context,
    )
    .expect("build workload image");
    let engine = ContainerEngine::from_env().expect("container engine");
    let inspect = engine
        .command()
        .args(["image", "inspect", "--format", "{{.Id}}", image.tag()])
        .output()
        .expect("inspect image identity");
    assert!(inspect.status.success());
    record(
        "image",
        json!({"tag": image.tag(), "id": String::from_utf8_lossy(&inspect.stdout).trim()}),
    );
    image
}

async fn install_provider(
    directory: &Path,
    name: &str,
    environment: &str,
    token: &str,
) -> ProviderGuard {
    let mut guard = ProviderGuard {
        name: name.to_string(),
        profile: false,
        provider: false,
    };
    let profile = directory.join(format!("{name}-provider.yaml"));
    // An endpointless profile makes the selected policy binding authoritative;
    // it cannot add a second implicit allow rule during policy composition.
    std::fs::write(
        &profile,
        format!(
            r"id: {name}
display_name: Configuration activation
category: other
credentials:
  - name: token
    env_vars: [{environment}]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints: []
binaries: []
"
        ),
    )
    .expect("write provider profile");
    let existing = cli_ok(&["provider", "list", "--output", "json"]).await;
    assert!(
        !existing.contains(&format!("\"{name}\"")),
        "activation test requires an isolated gateway; provider already exists"
    );
    let (_, existing_profile) = run_cli(&["provider", "profile", "export", name]).await;
    assert_ne!(
        existing_profile, 0,
        "activation test requires an isolated gateway; profile already exists"
    );
    cli_ok(&[
        "provider",
        "profile",
        "import",
        "--file",
        profile.to_str().expect("profile path"),
    ])
    .await;
    guard.profile = true;
    cli_ok(&[
        "provider",
        "create",
        "--name",
        name,
        "--type",
        name,
        "--credential",
        &format!("{environment}={token}"),
    ])
    .await;
    guard.provider = true;
    guard
}

fn container_id(engine: &ContainerEngine, name: &str) -> String {
    role_container_id(engine, name, "sandbox")
}

fn role_container_id(engine: &ContainerEngine, name: &str, role: &str) -> String {
    let output = engine
        .command()
        .args([
            "ps",
            "--quiet",
            "--filter",
            &format!("label=openshell.ai/sandbox-name={name}"),
            "--filter",
            &format!("label=openshell.ai/isolation-role={role}"),
        ])
        .output()
        .expect("find workload container");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("container IDs");
    let ids: Vec<_> = text.split_whitespace().collect();
    assert_eq!(
        ids.len(),
        1,
        "expected one running {role} container: {ids:?}"
    );
    ids[0].to_string()
}

fn boundary_read(engine: &ContainerEngine, container: &str, path: &str) -> String {
    let output = engine.command().args(["exec", container, "python3", "-c",
        "import pathlib,sys; p=pathlib.Path(sys.argv[1]); print(p.read_text() if p.exists() else '', end='')", path])
        .output().expect("read workload record independently of gateway exec");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("workload record")
}

async fn details(name: &str) -> Value {
    let output = cli_ok(&["sandbox", "get", name, "--output", "json"]).await;
    assert!(
        !output.contains(TOKEN_A),
        "gateway diagnostics leaked synthetic credential"
    );
    serde_json::from_str(&output).expect("sandbox detail JSON")
}

fn ready(detail: &Value) -> bool {
    detail["conditions"]
        .as_array()
        .expect("sandbox conditions")
        .iter()
        .any(|condition| condition["type"] == "Ready" && condition["status"] == "True")
}

async fn wait_accepted(name: &str) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let detail = details(name).await;
        assert_ne!(
            detail["phase"], "Error",
            "sandbox entered a terminal error before activation: {detail}"
        );
        if detail["configuration_admission"]["state"] == "accepted"
            && detail["configuration_admission"]["activation_confirmed"] == true
            && ready(&detail)
            && detail["phase"] == "Ready"
        {
            return detail;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "configuration did not activate: {detail}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn request(sandbox: &SandboxGuard, port: u16, authenticated: bool) -> String {
    request_with_environment(sandbox, port, authenticated.then_some(TOKEN_ENV)).await
}

async fn request_with_environment(
    sandbox: &SandboxGuard,
    port: u16,
    environment: Option<&str>,
) -> String {
    let script = format!(
        r"import os, urllib.error, urllib.request
request = urllib.request.Request('http://{host}:{port}/activation')
if {authenticated}:
    request.add_header('Authorization', 'Bearer ' + os.environ['{environment}'])
try:
    response = urllib.request.urlopen(request, timeout=5)
    print('STATUS', response.status)
except urllib.error.HTTPError as error:
    print('STATUS', error.code)
except (OSError, urllib.error.URLError) as error:
    print('DENIED', type(error).__name__, str(error))
",
        host = upstream_host(),
        authenticated = if environment.is_some() {
            "True"
        } else {
            "False"
        },
        environment = environment.unwrap_or("")
    );
    let output = sandbox
        .exec(&["python3", "-c", &script])
        .await
        .expect("run workload network probe");
    record(
        "network-probe",
        json!({"sandbox": sandbox.name, "port": port, "credential_env": environment, "output": output}),
    );
    output
}

#[tokio::test]
#[serial_test::serial(configuration_activation)]
async fn configuration_activation_live_updates_keep_endpoint_credentials_paired() {
    let upstream_a = Upstream::start().await;
    let upstream_b = Upstream::start().await;
    let context = tempfile::tempdir().expect("image context");
    let policy_a = materialize_policy(context.path(), "policy-a.yaml", upstream_a.port);
    let policy_b = materialize_policy(context.path(), "policy-b.yaml", upstream_b.port);
    let image = image(context.path(), None);
    let provider_a = install_provider(context.path(), PROVIDER_A, TOKEN_ENV, TOKEN_A).await;
    let provider_b = install_provider(context.path(), PROVIDER_B, TOKEN_ENV_B, TOKEN_B).await;
    let name = format!("atomic-{:012x}", rand::random::<u64>() & 0xffff_ffff_ffff);
    let mut sandbox = SandboxGuard::manage_existing(name.clone());
    cli_ok(&[
        "sandbox",
        "create",
        "--name",
        &name,
        "--detach",
        "--from",
        image.tag(),
        "--policy",
        policy_a.to_str().expect("policy A path"),
        "--provider",
        PROVIDER_A,
        "--",
        "python3",
        "-c",
        WORKLOAD,
    ])
    .await;
    let accepted_a = wait_accepted(&name).await;
    record("initial-live-generation", json!({"sandbox": accepted_a}));
    let engine = ContainerEngine::from_env().expect("container engine");
    let container = container_id(&engine, &name);
    let starts = boundary_read(&engine, &container, STARTS);
    assert_eq!(starts.lines().count(), 1);
    assert!(
        request(&sandbox, upstream_a.port, true)
            .await
            .contains("STATUS 200")
    );
    assert!(
        !request(&sandbox, upstream_b.port, true)
            .await
            .contains("STATUS 200")
    );

    // The candidate references a provider that exists but is not attached.
    // Rejection must leave the accepted endpoint and credential usable together.
    let (rejected, code) = run_cli(&[
        "policy",
        "set",
        &name,
        "--policy",
        policy_b.to_str().expect("policy B path"),
    ])
    .await;
    assert_ne!(
        code, 0,
        "unresolved candidate unexpectedly installed: {rejected}"
    );
    let after_rejection = details(&name).await;
    assert_eq!(
        after_rejection["configuration_admission"]["policy_hash"],
        accepted_a["configuration_admission"]["policy_hash"]
    );
    assert!(upstream_b.captured().is_empty());
    assert!(
        request(&sandbox, upstream_a.port, true)
            .await
            .contains("STATUS 200")
    );
    record(
        "rejected-live-binding",
        json!({"sandbox": after_rejection, "starts": starts, "upstream_a": upstream_a.captured(), "upstream_b": upstream_b.captured()}),
    );

    // New execs repeatedly cross the activation boundary while desired provider
    // and policy generations change. Failures while quiesced are expected; only
    // the controlled upstream proves which credential escaped the sandbox.
    let probe_name = name.clone();
    let port_a = upstream_a.port;
    let port_b = upstream_b.port;
    let probes = ProbeTask(tokio::spawn(async move {
        let script = format!(
            r"import os, urllib.request
for port in [{port_a}, {port_b}]:
    for variable in ['{TOKEN_ENV}', '{TOKEN_ENV_B}']:
        if variable not in os.environ:
            continue
        request = urllib.request.Request('http://{host}:' + str(port) + '/activation')
        request.add_header('Authorization', 'Bearer ' + os.environ[variable])
        try:
            urllib.request.urlopen(request, timeout=2).read()
        except (OSError, urllib.error.URLError):
            pass
",
            host = upstream_host(),
        );
        loop {
            let mut command = openshell_cmd();
            command
                .args([
                    "sandbox",
                    "exec",
                    "--name",
                    &probe_name,
                    "--no-tty",
                    "--",
                    "python3",
                    "-c",
                    &script,
                ])
                .kill_on_drop(true)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = tokio::time::timeout(Duration::from_secs(10), command.status()).await;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }));
    cli_ok(&["sandbox", "provider", "attach", &name, PROVIDER_B]).await;
    cli_ok(&[
        "policy",
        "set",
        &name,
        "--policy",
        policy_b.to_str().expect("policy B path"),
    ])
    .await;
    cli_ok(&["sandbox", "provider", "detach", &name, PROVIDER_A]).await;
    // Wait for an observable B-only environment, not merely for an earlier
    // successful acceptance that predates the provider detachment.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if sandbox.exec(&["python3", "-c", &format!("import os; assert '{TOKEN_ENV}' not in os.environ; assert '{TOKEN_ENV_B}' in os.environ")]).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "provider environment did not converge to B"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let accepted_b = wait_accepted(&name).await;
    assert_ne!(
        accepted_b["configuration_admission"]["policy_hash"],
        accepted_a["configuration_admission"]["policy_hash"]
    );
    assert!(
        request_with_environment(&sandbox, upstream_b.port, Some(TOKEN_ENV_B))
            .await
            .contains("STATUS 200")
    );
    assert!(
        !request_with_environment(&sandbox, upstream_a.port, Some(TOKEN_ENV_B))
            .await
            .contains("STATUS 200")
    );
    drop(probes);
    let requests_a = upstream_a.captured();
    let requests_b = upstream_b.captured();
    assert!(
        !requests_a.is_empty() && !requests_b.is_empty(),
        "both accepted endpoints need positive observations"
    );
    assert!(
        requests_a.iter().all(|request| request
            .to_ascii_lowercase()
            .contains("authorization: bearer cred-a")),
        "endpoint A received a credential from another generation: {requests_a:?}"
    );
    assert!(
        requests_b.iter().all(|request| request
            .to_ascii_lowercase()
            .contains("authorization: bearer cred-b")),
        "endpoint B received a credential from another generation: {requests_b:?}"
    );
    assert_eq!(
        boundary_read(&engine, &container, STARTS),
        starts,
        "live activation relaunched the main process"
    );
    record(
        "live-paired-publication",
        json!({"sandbox": accepted_b, "starts": starts, "upstream_a": requests_a, "upstream_b": requests_b}),
    );
    sandbox.cleanup().await;
    drop(provider_b);
    drop(provider_a);
    drop(image);
}

#[tokio::test]
#[serial_test::serial(configuration_activation)]
async fn configuration_activation_rejected_image_repair_starts_once() {
    let upstream = Upstream::start().await;
    let context = tempfile::tempdir().expect("image context");
    let invalid = materialize_policy(context.path(), "policy-invalid-binding.yaml", upstream.port);
    let repaired = materialize_policy(context.path(), "policy-a.yaml", upstream.port);
    let image = image(context.path(), Some(&invalid));
    let provider = install_provider(context.path(), PROVIDER_A, TOKEN_ENV, TOKEN_A).await;
    let name = format!("act-{:012x}", rand::random::<u64>() & 0xffff_ffff_ffff);
    let mut sandbox = SandboxGuard::manage_existing(name.clone());
    let mut create = openshell_cmd()
        .args([
            "sandbox",
            "create",
            "--name",
            &name,
            "--detach",
            "--from",
            image.tag(),
            "--provider",
            PROVIDER_A,
            "--",
            "python3",
            "-c",
            WORKLOAD,
        ])
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("create rejected sandbox");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let rejected = loop {
        let (output, code) = run_cli(&["sandbox", "get", &name, "--output", "json"]).await;
        if code == 0 {
            let detail: Value =
                serde_json::from_str(&strip_ansi(&output)).expect("sandbox detail JSON");
            if detail["configuration_admission"]["state"] == "rejected" {
                break detail;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "configuration did not reject: {output}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(!ready(&rejected));
    assert_ne!(
        rejected["phase"], "Error",
        "repair must retain runtime authentication"
    );
    assert_eq!(rejected["current_policy_version"], 0);
    let engine = ContainerEngine::from_env().expect("container engine");
    let container = container_id(&engine, &name);
    assert!(boundary_read(&engine, &container, STARTS).is_empty());
    assert!(boundary_read(&engine, &container, HEARTBEAT).is_empty());
    assert!(upstream.captured().is_empty());
    assert!(
        sandbox.exec(&["true"]).await.is_err(),
        "rejected configuration allowed exec"
    );
    record("rejected-initial", rejected);
    // Rejection must remain stable while the control process waits for repair.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(container_id(&engine, &name), container);
    assert!(boundary_read(&engine, &container, STARTS).is_empty());
    cli_ok(&[
        "policy",
        "set",
        &name,
        "--policy",
        repaired.to_str().expect("repair path"),
    ])
    .await;
    let accepted = wait_accepted(&name).await;
    let starts = boundary_read(&engine, &container, STARTS);
    assert_eq!(
        starts.lines().count(),
        1,
        "repair must start one main process: {starts}"
    );
    let heartbeat = boundary_read(&engine, &container, HEARTBEAT);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_ne!(boundary_read(&engine, &container, HEARTBEAT), heartbeat);
    assert!(
        request(&sandbox, upstream.port, true)
            .await
            .contains("STATUS 200")
    );
    assert!(upstream.captured().iter().any(|request| {
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer cred-a")
    }));
    record(
        "accepted-repair",
        json!({"sandbox": accepted, "starts": starts, "upstream": upstream.captured()}),
    );
    // Repeated desired-policy writes exercise the production polling replay path.
    for _ in 0..2 {
        cli_ok(&[
            "policy",
            "set",
            &name,
            "--policy",
            repaired.to_str().expect("repair path"),
        ])
        .await;
        let replayed = wait_accepted(&name).await;
        assert_eq!(
            replayed["configuration_admission"]["policy_hash"],
            accepted["configuration_admission"]["policy_hash"]
        );
        assert_eq!(boundary_read(&engine, &container, STARTS), starts);
    }
    record(
        "replayed-repair",
        json!({"sandbox": details(&name).await, "starts": starts}),
    );
    let _ = create.try_wait().expect("observe create process");
    sandbox.cleanup().await;
    drop(create);
    drop(provider);
    drop(image);
}

/// Require isolation from global policy before observing the default selection.
async fn assert_no_global_policy() {
    // An isolated gateway has no current global revision; the current-policy
    // command reports NotFound rather than a successful empty history listing.
    let (global, code) = tokio::time::timeout(
        Duration::from_secs(120),
        run_cli(&["policy", "get", "--global", "--output", "json"]),
    )
    .await
    .expect("global policy absence query timeout");
    assert!(
        code != 0
            && global.contains("Some requested entity was not found")
            && global.contains("no global policy")
            && global.contains("revision found"),
        "default-policy proof requires an isolated gateway without global policy: {global}"
    );
}

#[tokio::test]
async fn configuration_activation_no_image_policy_is_restrictive() {
    assert_no_global_policy().await;
    let upstream = Upstream::start().await;
    let context = tempfile::tempdir().expect("image context");
    let image = image(context.path(), None);
    let mut sandbox = SandboxGuard::create(&["--from", image.tag()])
        .await
        .expect("start image without policy");
    let accepted = wait_accepted(&sandbox.name).await;
    assert_eq!(
        accepted["policy_source"], "sandbox",
        "a global policy displaced default-policy selection"
    );
    let engine = ContainerEngine::from_env().expect("container engine");
    let boundary = container_id(&engine, &sandbox.name);
    let absence = engine
        .command()
        .args([
            "exec",
            &boundary,
            "test",
            "!",
            "-e",
            "/etc/openshell/policy.yaml",
        ])
        .output()
        .expect("inspect workload image policy absence");
    assert!(
        absence.status.success(),
        "image unexpectedly contains a policy"
    );
    let selected: Value = serde_json::from_str(
        &cli_ok(&["policy", "get", &sandbox.name, "--full", "--output", "json"]).await,
    )
    .expect("selected policy JSON");
    assert_eq!(
        selected["hash"],
        accepted["configuration_admission"]["policy_hash"]
    );
    assert!(
        selected["hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty())
    );
    assert!(
        accepted["policy"]["network_policies"].is_null()
            || accepted["policy"]["network_policies"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty),
        "default selected an allow rule: {accepted}"
    );
    let denied = request(&sandbox, upstream.port, false).await;
    assert!(
        !denied.contains("STATUS 200"),
        "restrictive default allowed endpoint: {denied}"
    );
    assert!(
        upstream.captured().is_empty(),
        "unauthorized request reached upstream"
    );
    record(
        "restrictive-default",
        json!({"sandbox": accepted, "request": denied, "upstream": upstream.captured(), "selected_policy": selected, "global_policy_absent": true, "image_policy_absent": true, "explicit_policy_supplied": false}),
    );
    // The same executable and reachable endpoint must work once explicitly
    // allowed, otherwise interpreter or transport failures could fake denial.
    let allowed = materialize_policy(context.path(), "policy-a.yaml", upstream.port);
    let without_binding = std::fs::read_to_string(&allowed)
        .expect("read positive control")
        .replace(
            "        credential_binding:\n          provider: service-a\n",
            "",
        );
    std::fs::write(&allowed, without_binding).expect("write positive control");
    sandbox.cleanup().await;
    let mut positive = SandboxGuard::create(&[
        "--from",
        image.tag(),
        "--policy",
        allowed.to_str().expect("positive control path"),
    ])
    .await
    .expect("start positive control with explicit policy");
    wait_accepted(&positive.name).await;
    let allowed_output = request(&positive, upstream.port, false).await;
    assert!(
        allowed_output.contains("STATUS 200"),
        "positive egress control failed: {allowed_output}"
    );
    assert_eq!(upstream.captured().len(), 1);
    positive.cleanup().await;
    drop(image);
}

fn durable_workload_record(engine: &ContainerEngine, container: &str, path: &str) -> String {
    let temporary = tempfile::tempdir().expect("workload evidence directory");
    let destination = temporary.path().join("record");
    // docker cp reads the stopped boundary filesystem without restarting it or
    // bypassing the gateway to launch a replacement workload process.
    let copied = engine
        .command()
        .args([
            "cp",
            &format!("{container}:{path}"),
            destination.to_str().expect("evidence path"),
        ])
        .output()
        .expect("copy retained workload evidence");
    assert!(
        copied.status.success(),
        "cannot preserve workload evidence: {}",
        String::from_utf8_lossy(&copied.stderr)
    );
    std::fs::read_to_string(destination).expect("read retained workload record")
}

/// Observe the driver's completed health gate before disrupting an active runtime.
async fn wait_control_healthy(engine: &ContainerEngine, name: &str) {
    let container = role_container_id(engine, name, "supervisor");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let output = engine
            .command()
            .args(["inspect", "--format", "{{json .State}}", &container])
            .output()
            .expect("inspect supervisor health before restart");
        assert!(
            output.status.success(),
            "supervisor disappeared before restart"
        );
        let state: Value = serde_json::from_slice(&output.stdout).expect("supervisor state");
        assert_eq!(
            state["Running"], true,
            "supervisor stopped before restart: {state}"
        );
        assert_ne!(
            state["Health"]["Status"], "unhealthy",
            "supervisor is unhealthy: {state}"
        );
        if state["Health"]["Status"] == "healthy" {
            record(
                "restart-health-baseline",
                json!({"sandbox":name,"control_container":container,"state":state}),
            );
            return;
        }
        // Session admission can precede Docker's first health observation. A
        // disruption during provisioning exercises startup cleanup instead of
        // the established-runtime restart contract.
        assert!(
            tokio::time::Instant::now() < deadline,
            "supervisor health did not settle: {state}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_restarted_sandbox(
    name: &str,
    role: &str,
    original: &Value,
    restarting: &tokio::task::JoinHandle<std::process::Output>,
) -> (Value, bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut observed_unready = false;
    loop {
        let detail = details(name).await;
        observed_unready |= !ready(&detail);
        let terminal = matches!(
            detail["phase"].as_str(),
            Some("Error" | "Completed" | "Stopped")
        );
        let replaced = detail["configuration_admission"]["instance_id"]
            != original["configuration_admission"]["instance_id"];
        if restarting.is_finished()
            && (terminal || (observed_unready && replaced && ready(&detail)))
        {
            assert!(
                observed_unready,
                "{role} replacement never withdrew readiness"
            );
            return (detail, observed_unready);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{role} restart did not settle behind admission: {detail}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Retire failed infrastructure explicitly before authorizing a fresh runtime.
async fn start_after_terminal_failure(name: &str, terminal: &Value) {
    if terminal["phase"] == "Error" {
        let (output, code) = run_cli(&["sandbox", "start", name]).await;
        assert_ne!(
            code, 0,
            "infrastructure Error allowed direct start: {output}"
        );
        cli_ok(&["sandbox", "stop", name]).await;
        let stopped = details(name).await;
        assert_eq!(stopped["phase"], "Stopped");
        assert!(!ready(&stopped));
        record(
            "authorized-stop-before-restart",
            json!({"sandbox":name,"stopped":stopped,"direct_start_exit_code":code}),
        );
    }
    cli_ok(&["sandbox", "start", name]).await;
}

#[tokio::test]
#[serial_test::serial(configuration_activation)]
async fn configuration_activation_independent_process_restarts_require_fresh_activation() {
    let upstream = Upstream::start().await;
    let context = tempfile::tempdir().expect("restart image context");
    let image = image(context.path(), None);
    let policy = materialize_policy(context.path(), "policy-a.yaml", upstream.port);
    let provider = install_provider(context.path(), PROVIDER_A, TOKEN_ENV, TOKEN_A).await;
    for role in ["supervisor", "sandbox"] {
        let name = format!("rst-{:012x}", rand::random::<u64>() & 0xffff_ffff_ffff);
        let mut sandbox = SandboxGuard::manage_existing(name.clone());
        cli_ok(&[
            "sandbox",
            "create",
            "--name",
            &name,
            "--detach",
            "--from",
            image.tag(),
            "--policy",
            policy.to_str().expect("restart policy path"),
            "--provider",
            PROVIDER_A,
            "--",
            "python3",
            "-c",
            WORKLOAD,
        ])
        .await;
        let original = wait_accepted(&name).await;
        let engine = ContainerEngine::from_env().expect("container engine");
        wait_control_healthy(&engine, &name).await;
        let boundary = container_id(&engine, &name);
        let target = role_container_id(&engine, &name, role);
        let starts = durable_workload_record(&engine, &boundary, STARTS);
        assert_eq!(starts.lines().count(), 1);
        let original_runtime = original["configuration_admission"]["runtime_generation"].clone();
        assert!(
            original_runtime
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        let restart_engine = engine.clone();
        let restarted_target = target.clone();
        let restarting = tokio::task::spawn_blocking(move || {
            restart_engine
                .command()
                .args(["restart", "--time", "0", &restarted_target])
                .output()
                .expect("restart independent runtime container")
        });
        let (settled, observed_unready) =
            wait_restarted_sandbox(&name, role, &original, &restarting).await;
        let restarted = restarting.await.expect("restart task");
        assert!(
            restarted.status.success(),
            "{role} restart failed: {}",
            String::from_utf8_lossy(&restarted.stderr)
        );
        let retained = durable_workload_record(&engine, &boundary, STARTS);
        assert_eq!(
            retained, starts,
            "independent restart launched an unauthorized main process"
        );
        if ready(&settled) {
            assert_eq!(
                role, "supervisor",
                "a new boundary incarnation cannot activate in the old runtime generation"
            );
            assert_eq!(
                settled["configuration_admission"]["runtime_generation"],
                original_runtime
            );
            assert_eq!(
                settled["configuration_admission"]["boundary_instance_id"],
                original["configuration_admission"]["boundary_instance_id"]
            );
            assert_ne!(
                settled["configuration_admission"]["instance_id"],
                original["configuration_admission"]["instance_id"]
            );
            let beat = boundary_read(&engine, &boundary, HEARTBEAT);
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_ne!(boundary_read(&engine, &boundary, HEARTBEAT), beat);
            record(
                "independent-process-restart",
                json!({"target": role, "before": original, "after": settled, "starts_before": starts, "starts_after": retained, "observed_unready": observed_unready, "workload_survived": true}),
            );
        } else {
            assert!(
                sandbox.exec(&["true"]).await.is_err(),
                "terminal runtime allowed exec"
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
            let terminal = details(&name).await;
            assert!(!ready(&terminal));
            assert!(matches!(
                terminal["phase"].as_str(),
                Some("Error" | "Completed" | "Stopped")
            ));
            assert_eq!(durable_workload_record(&engine, &boundary, STARTS), starts);
            // Only a gateway lifecycle start may mint a new runtime generation
            // and consume a new initial launch after boundary/control failure.
            start_after_terminal_failure(&name, &terminal).await;
            let fresh = wait_accepted(&name).await;
            assert_ne!(
                fresh["configuration_admission"]["runtime_generation"],
                original_runtime
            );
            let new_boundary = container_id(&engine, &name);
            let new_starts = durable_workload_record(&engine, &new_boundary, STARTS);
            let expected_count = if new_boundary == boundary { 2 } else { 1 };
            assert_eq!(
                new_starts.lines().count(),
                expected_count,
                "authorized start did not launch exactly one new main process"
            );
            record(
                "independent-process-restart",
                json!({"target": role, "before": original, "after": terminal, "fresh": fresh, "starts_before": starts, "starts_after": retained, "starts_after_authorized_start": new_starts, "new_boundary_container": new_boundary, "old_boundary_container": boundary, "observed_unready": observed_unready, "workload_survived": false}),
            );
        }
        sandbox.cleanup().await;
    }
    drop(provider);
    drop(image);
}
