// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! Exercise image/provider composition and management repair before workload launch.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::container::{ContainerEngine, ImageGuard};
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TOKEN: &str = "composition-synthetic-credential";
const WORKLOAD: &str = include_str!("../fixtures/configuration-composition/workload.py");
const OBSERVER: &str = include_str!("../fixtures/configuration-composition/observe_workload.py");
const DEADLINE: Duration = Duration::from_secs(120);

struct Upstream {
    port: u16,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Debug, PartialEq)]
struct UpstreamObservation {
    connections: usize,
    requests: Vec<Value>,
}

impl Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind controlled upstream");
        let port = listener.local_addr().expect("upstream address").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted_connections = Arc::clone(&connections);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        // A single owned task handles these sequential probes. Dropping the
        // fixture cancels an incomplete read without leaving detached workers.
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                accepted_connections.fetch_add(1, Ordering::SeqCst);
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2048];
                loop {
                    let read =
                        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                            .await;
                    let Ok(Ok(read)) = read else { break };
                    if read == 0 || request.len() > 16_384 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        let text = String::from_utf8_lossy(&request);
                        let authorization = text.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("authorization")
                                .then(|| value.trim().to_string())
                        });
                        captured.lock().expect("upstream observations").push(json!({
                            "request_line": text.lines().next(),
                            "authorization": authorization,
                        }));
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                            .await;
                        break;
                    }
                }
            }
        });
        Self {
            port,
            connections,
            requests,
            task,
        }
    }

    fn captured(&self) -> Vec<Value> {
        self.requests.lock().expect("upstream observations").clone()
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn observation(&self) -> UpstreamObservation {
        UpstreamObservation {
            connections: self.connection_count(),
            requests: self.captured(),
        }
    }

    async fn prove_listening(&self) {
        // Verify the denial listener itself responds before using an absence of
        // received connections as evidence. The allowed sandbox probe separately
        // proves that the same host is reachable from the runtime topology.
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port))
            .await
            .expect("connect listener positive control");
        stream
            .write_all(
                b"GET /listener-control HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write listener positive control");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .expect("listener response deadline")
            .expect("read listener positive control");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        record(
            "listener-positive-control",
            json!({"port":self.port,"response":String::from_utf8_lossy(&response),"requests":self.captured(),"connections":self.connection_count()}),
        );
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ProviderGuard {
    name: String,
    created: bool,
    profile_created: bool,
}

impl Drop for ProviderGuard {
    fn drop(&mut self) {
        // Sandbox deletion drains asynchronously. Only delete the uniquely
        // named provider/profile that this fixture successfully created. Every
        // child shares an overall deadline and is killed/reaped on its timeout.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.created {
                let mut command = Command::new(openshell_bin());
                command.args(["provider", "delete", &self.name]);
                self.created =
                    !bounded_status(command, deadline).is_ok_and(|status| status.success());
            }
            if !self.created && self.profile_created && Instant::now() < deadline {
                let mut command = Command::new(openshell_bin());
                command.args(["provider", "profile", "delete", &self.name]);
                self.profile_created =
                    !bounded_status(command, deadline).is_ok_and(|status| status.success());
            }
            if !self.created && !self.profile_created {
                break;
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(250)),
            );
        }
        if self.created || self.profile_created {
            eprintln!("provider cleanup deadline expired for {}", self.name);
        }
    }
}

fn bounded_status(mut command: Command, overall_deadline: Instant) -> std::io::Result<ExitStatus> {
    if Instant::now() >= overall_deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "cleanup overall deadline",
        ));
    }
    let deadline = overall_deadline.min(Instant::now() + Duration::from_secs(2));
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => {
                // This handle belongs exclusively to this cleanup invocation.
                // Reap it even on a polling error; never signal other CLI users.
                let _ = child.kill();
                let _ = child.wait();
                return Err(result.err().unwrap_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "cleanup command deadline")
                }));
            }
        }
    }
}

#[test]
fn configuration_composition_cleanup_deadline_reaps_sleeping_child() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exec /bin/sleep 10"]);
    let start = Instant::now();
    let error = bounded_status(command, start + Duration::from_millis(100))
        .expect_err("sleeping cleanup command must time out");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(3));
}

struct ManagedSandbox {
    create: tokio::process::Child,
    rejected_create_status: Option<ExitStatus>,
    guard: SandboxGuard,
    upstream_before_create: UpstreamObservation,
    workload_url: String,
}

async fn command(args: &[&str]) -> (String, i32) {
    let output = tokio::time::timeout(
        DEADLINE,
        openshell_cmd()
            .args(args)
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("CLI command deadline")
    .expect("execute CLI command");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (strip_ansi(&text), output.status.code().unwrap_or(-1))
}

async fn cli_ok(args: &[&str]) -> String {
    let (output, code) = command(args).await;
    assert_eq!(code, 0, "CLI operation failed: {output}");
    output
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
    println!("COMPOSITION_OBSERVATION {}", Value::Object(envelope));
}

fn materialize(directory: &Path, name: &str, port: u16, provider: &str) -> PathBuf {
    let fixtures = std::env::var_os("OPENSHELL_COMPOSITION_FIXTURES").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/configuration-composition"),
        PathBuf::from,
    );
    // The runner may freeze fixture bytes separately. Only endpoint locations
    // and the unique resource name change; inspection semantics remain fixed.
    let input = std::fs::read_to_string(fixtures.join(name)).expect("read composition fixture");
    let rendered = input
        .replace("composition.invalid", &upstream_host().to_string())
        .replace("port: 18443", &format!("port: {port}"))
        .replace("id: composition-provider", &format!("id: {provider}"));
    let output = directory.join(name);
    std::fs::write(&output, &rendered).expect("write rendered fixture");
    record("fixture", json!({"name": name, "rendered": rendered}));
    output
}

fn build_image(directory: &Path, policy: &Path) -> ImageGuard {
    std::fs::create_dir_all(directory).expect("create image context");
    std::fs::copy(policy, directory.join("policy.yaml")).expect("copy embedded policy");
    std::fs::write(
        directory.join("Dockerfile"),
        r#"FROM public.ecr.aws/docker/library/python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/* \
    && groupadd sandbox && useradd -m -g sandbox sandbox && mkdir -p /sandbox && chown sandbox:sandbox /sandbox
COPY policy.yaml /etc/openshell/policy.yaml
WORKDIR /sandbox
USER sandbox
CMD ["sleep", "infinity"]
"#,
    )
    .expect("write image definition");
    let image = ImageGuard::build(
        "configuration-composition",
        &directory.join("Dockerfile"),
        directory,
    )
    .expect("build workload image");
    let engine = ContainerEngine::from_env().expect("container engine");
    let output = engine
        .command()
        .args(["image", "inspect", "--format", "{{.Id}}", image.tag()])
        .output()
        .expect("inspect workload image");
    assert!(output.status.success());
    record(
        "image",
        json!({"tag": image.tag(), "id": String::from_utf8_lossy(&output.stdout).trim()}),
    );
    image
}

async fn install_provider(name: String, profile: &Path) -> ProviderGuard {
    let mut guard = ProviderGuard {
        name,
        created: false,
        profile_created: false,
    };
    cli_ok(&[
        "provider",
        "profile",
        "import",
        "--file",
        profile.to_str().expect("provider profile path"),
    ])
    .await;
    guard.profile_created = true;
    cli_ok(&[
        "provider",
        "create",
        "--name",
        &guard.name,
        "--type",
        &guard.name,
        "--credential",
        &format!("COMPOSITION_TOKEN={TOKEN}"),
    ])
    .await;
    guard.created = true;
    guard
}

fn create_sandbox(
    image: &ImageGuard,
    provider: Option<&str>,
    upstream: &Upstream,
) -> ManagedSandbox {
    let name = format!("cp-{:016x}", rand::random::<u64>());
    let guard = SandboxGuard::manage_existing(name.clone());
    let mut command = openshell_cmd();
    command.args([
        "sandbox",
        "create",
        "--name",
        &name,
        "--detach",
        "--from",
        image.tag(),
    ]);
    if let Some(provider) = provider {
        command.args(["--provider", provider]);
    }
    // Admission-time traffic must be compared with the state before creation,
    // including traffic preceding a later rejected-state or container observation.
    let upstream_before_create = upstream.observation();
    let port = upstream.port;
    let workload_url = format!("http://{}:{port}/{name}/workload", upstream_host());
    let create = command
        .args(["--", "python3", "-c", WORKLOAD, &workload_url])
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start sandbox creation");
    ManagedSandbox {
        create,
        rejected_create_status: None,
        guard,
        upstream_before_create,
        workload_url,
    }
}

async fn details(name: &str) -> Option<Value> {
    let (output, code) = command(&["sandbox", "get", name, "--output", "json"]).await;
    assert!(
        !output.contains(TOKEN),
        "diagnostics leaked fixture credential"
    );
    (code == 0).then(|| serde_json::from_str(&output).expect("sandbox detail JSON"))
}

fn ready(detail: &Value) -> bool {
    detail["conditions"]
        .as_array()
        .expect("sandbox conditions")
        .iter()
        .any(|condition| condition["type"] == "Ready" && condition["status"] == "True")
}

async fn wait_state(name: &str, state: &str) -> Value {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let detail = details(name).await;
        if let Some(detail) = &detail {
            let admission = &detail["configuration_admission"];
            if admission["state"] == state
                && (state != "accepted"
                    || (ready(detail) && admission["activation_confirmed"] == true))
            {
                return detail.clone();
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "sandbox did not reach {state}: {detail:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn container_state(engine: &ContainerEngine, name: &str, role: &str) -> Value {
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
        .expect("find container role");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("container identifiers");
    let ids: Vec<_> = text.split_whitespace().collect();
    assert_eq!(ids.len(), 1, "expected one {role} container");
    let output = engine.command().args([
        "inspect", "--format",
        r#"{"id":{{json .Id}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},"started_at":{{json .State.StartedAt}},"restarts":{{json .RestartCount}}}"#,
        ids[0],
    ]).output().expect("inspect actual container process");
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).expect("container process JSON")
}

fn workload(engine: &ContainerEngine, boundary: &Value, workload_url: &str) -> Value {
    process_observation(engine, boundary, WORKLOAD, workload_url, "composition")
}

fn process_observation(
    engine: &ContainerEngine,
    boundary: &Value,
    program: &str,
    workload_url: &str,
    record_prefix: &str,
) -> Value {
    // This read-only out-of-band observer remains available while gateway exec
    // is correctly denied. It never starts the main workload or changes policy.
    let output = engine
        .command()
        .args([
            "exec",
            boundary["id"].as_str().expect("boundary ID"),
            "python3",
            "-c",
            OBSERVER,
            program,
            workload_url,
            record_prefix,
        ])
        .output()
        .expect("read independent workload records");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("workload observation JSON")
}

async fn probe(name: &str, port: u16, stage: &str, authenticated: bool) -> (String, i32) {
    let script = format!(
        r"import os,urllib.error,urllib.request
request=urllib.request.Request('http://{host}:{port}/{name}/{stage}')
if {authenticated}:
    request.add_header('Authorization','Bearer '+os.environ['COMPOSITION_TOKEN'])
try:
    with urllib.request.urlopen(request,timeout=5) as response:
        print('STATUS',response.status)
except (OSError,urllib.error.URLError) as error:
    print('DENIED',type(error).__name__)",
        host = upstream_host(),
        authenticated = if authenticated { "True" } else { "False" },
    );
    command(&[
        "sandbox", "exec", "--name", name, "--no-tty", "--", "python3", "-c", &script,
    ])
    .await
}

async fn assert_blocked(sandbox: &mut ManagedSandbox, upstream: &Upstream) -> Value {
    let name = &sandbox.guard.name;
    let rejected = wait_state(name, "rejected").await;
    let status = tokio::time::timeout(DEADLINE, sandbox.create.wait())
        .await
        .expect("rejected create completion deadline")
        .expect("wait for rejected create completion");
    assert!(!status.success(), "create must report admission rejection");
    sandbox.rejected_create_status = Some(status);
    assert!(
        rejected["configuration_admission"]["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()),
        "composition rejection must expose a diagnostic"
    );
    let engine = ContainerEngine::from_env().expect("container engine");
    let boundary = container_state(&engine, name, "sandbox");
    let control = container_state(&engine, name, "supervisor");
    let requests = &sandbox.upstream_before_create.requests;
    let connections = sandbox.upstream_before_create.connections;
    assert_no_new_upstream(upstream, &sandbox.upstream_before_create);
    let mut samples = Vec::new();
    for _ in 0..3 {
        let detail = details(name)
            .await
            .expect("rejected sandbox remains visible");
        assert_eq!(detail["configuration_admission"]["state"], "rejected");
        assert!(!ready(&detail));
        assert_ne!(detail["phase"], "Error", "rejection must remain repairable");
        assert_eq!(detail["current_policy_version"], 0);
        let observed = workload(&engine, &boundary, &sandbox.workload_url);
        assert_no_workload(&observed);
        let current_boundary = container_state(&engine, name, "sandbox");
        let current_control = container_state(&engine, name, "supervisor");
        assert_eq!(
            current_boundary, boundary,
            "boundary restarted while rejected"
        );
        assert_eq!(current_control, control, "control restarted while rejected");
        assert_no_new_upstream(upstream, &sandbox.upstream_before_create);
        samples.push(json!({"detail":detail,"workload":observed,"boundary":current_boundary,"control":current_control}));
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let (exec_output, exec_code) = probe(name, upstream.port, "blocked-exec", false).await;
    assert_ne!(
        exec_code, 0,
        "gateway exec entered a rejected workload: {exec_output}"
    );
    assert_no_new_upstream(upstream, &sandbox.upstream_before_create);
    assert_no_workload(&workload(&engine, &boundary, &sandbox.workload_url));
    record(
        "composition-rejected",
        json!({"sandbox":name,"rejected":rejected,"create_exit_code":status.code(),"samples":samples,"upstream_before":requests,"upstream_after":upstream.captured(),"connections_before":connections,"connections_after":upstream.connection_count(),"exec_code":exec_code,"exec_output":exec_output}),
    );
    rejected
}

fn assert_no_new_upstream(upstream: &Upstream, before: &UpstreamObservation) {
    assert_eq!(
        upstream.observation(),
        *before,
        "rejected sandbox changed upstream observations"
    );
}

fn assert_no_workload(observed: &Value) {
    // A launched workload can be stopped before writing its first marker.
    // Process absence is therefore a separate gate from absent file records.
    assert!(
        no_workload_process(observed),
        "blocked workload exists before its startup marker"
    );
    for field in ["starts", "heartbeat", "first-request"] {
        assert!(observed[field].is_null(), "blocked workload wrote {field}");
    }
}

fn no_workload_process(observed: &Value) -> bool {
    observed["processes"]
        .as_array()
        .expect("workload process census")
        .is_empty()
}

struct StoppedObserverGuard {
    engine: ContainerEngine,
    boundary_id: String,
    pid: u64,
    start_ticks: u64,
    active: bool,
}

impl StoppedObserverGuard {
    fn terminate(&mut self) -> bool {
        if !self.active {
            return true;
        }
        let mut command = self.engine.command();
        // PID plus start ticks ensures cleanup cannot signal a reused PID.
        command.args([
            "exec",
            &self.boundary_id,
            "python3",
            "-c",
            r"import os,pathlib,signal,sys
pid=int(sys.argv[1])
try:
    ticks=int(pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19])
    if ticks==int(sys.argv[2]):
        os.kill(pid,signal.SIGKILL)
except (FileNotFoundError,ProcessLookupError):
    pass",
            &self.pid.to_string(),
            &self.start_ticks.to_string(),
        ]);
        let stopped = bounded_status(command, Instant::now() + Duration::from_secs(2))
            .is_ok_and(|status| status.success());
        self.active = !stopped;
        stopped
    }
}

impl Drop for StoppedObserverGuard {
    fn drop(&mut self) {
        if !self.terminate() {
            eprintln!("stopped observer cleanup failed for owned PID {}", self.pid);
        }
    }
}

async fn prove_stopped_process_observation(sandbox: &ManagedSandbox) {
    const STOPPED_PROGRAM: &str = "import os,signal; os.kill(os.getpid(),signal.SIGSTOP)";
    let engine = ContainerEngine::from_env().expect("container engine");
    let boundary = container_state(&engine, &sandbox.guard.name, "sandbox");
    let identifier = format!("observer-control-{:016x}", rand::random::<u64>());
    let mut command = engine.command();
    command.args([
        "exec",
        "--detach",
        boundary["id"].as_str().expect("boundary ID"),
        "python3",
        "-c",
        STOPPED_PROGRAM,
        &identifier,
    ]);
    assert!(
        bounded_status(command, Instant::now() + Duration::from_secs(2))
            .expect("launch stopped observer control")
            .success()
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let observed = loop {
        let observed = process_observation(
            &engine,
            &boundary,
            STOPPED_PROGRAM,
            &identifier,
            &identifier,
        );
        let processes = observed["processes"]
            .as_array()
            .expect("control process census");
        if processes.len() == 1 && processes[0]["state"] == "T" {
            break observed;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "stopped control not observed: {observed}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let process = &observed["processes"][0];
    let mut cleanup = StoppedObserverGuard {
        engine,
        boundary_id: boundary["id"].as_str().expect("boundary ID").to_string(),
        pid: process["pid"].as_u64().expect("stopped control PID"),
        start_ticks: process["start_ticks"]
            .as_u64()
            .expect("stopped control start ticks"),
        active: true,
    };
    for field in ["starts", "heartbeat", "first-request"] {
        assert!(observed[field].is_null());
    }
    // The same absence guard used for rejection must reject this actual stopped
    // process even though it has never written a workload marker.
    assert!(
        !no_workload_process(&observed),
        "process observer accepted the stopped control"
    );
    assert!(
        cleanup.terminate(),
        "could not remove owned stopped control"
    );
    record("observer-stopped-before-marker-control", observed);
}

#[tokio::test]
#[should_panic(expected = "rejected sandbox changed upstream observations")]
async fn configuration_composition_detects_pre_rejection_egress() {
    let upstream = Upstream::start().await;
    let before_creation = upstream.observation();
    assert_no_new_upstream(&upstream, &before_creation);
    // This successful real HTTP request occurs before rejection is observed.
    // A baseline captured after the request would incorrectly accept the escape.
    upstream.prove_listening().await;
    assert_no_new_upstream(&upstream, &before_creation);
}

// PID and start ticks identify one actual process; the startup request proves
// that the same main workload crossed the installed network policy.
fn assert_single_workload_start(observed: &Value) {
    let starts: Vec<Value> = observed["starts"]
        .as_str()
        .expect("workload starts")
        .lines()
        .map(|line| serde_json::from_str(line).expect("workload process identity"))
        .collect();
    assert_eq!(
        starts.len(),
        1,
        "configuration launched more than one workload"
    );
    assert!(starts[0]["pid"].as_u64().is_some_and(|pid| pid > 0));
    assert!(
        starts[0]["start_ticks"]
            .as_u64()
            .is_some_and(|ticks| ticks > 0)
    );
    let processes = observed["processes"]
        .as_array()
        .expect("actual workload process census");
    assert_eq!(processes.len(), 1, "expected one actual workload process");
    assert_eq!(processes[0]["pid"], starts[0]["pid"]);
    assert_eq!(processes[0]["start_ticks"], starts[0]["start_ticks"]);
    assert!(matches!(
        processes[0]["state"].as_str(),
        Some("R" | "S" | "D")
    ));
    let first_request: Value = serde_json::from_str(
        observed["first-request"]
            .as_str()
            .expect("first request outcome"),
    )
    .expect("first request JSON");
    assert_eq!(
        first_request["status"], 200,
        "main workload could not reach controlled upstream"
    );
}

/// Preserve the original CLI rejection outcome across later management repair.
async fn assert_create_outcome(sandbox: &mut ManagedSandbox) {
    if let Some(status) = sandbox.rejected_create_status {
        // Admission rejection completes create immediately; management repair
        // activates the retained sandbox without changing that past exit code.
        assert!(!status.success(), "recorded rejection must remain nonzero");
    } else {
        let status = tokio::time::timeout(DEADLINE, sandbox.create.wait())
            .await
            .expect("create completion deadline")
            .expect("wait for create completion");
        assert!(status.success(), "direct valid creation must succeed");
    }
}

async fn assert_active(
    sandbox: &mut ManagedSandbox,
    upstream: &Upstream,
    denied: &Upstream,
    authenticated: bool,
    stage: &str,
) -> Value {
    assert_create_outcome(sandbox).await;
    let name = &sandbox.guard.name;
    let accepted = wait_state(name, "accepted").await;
    assert_eq!(
        accepted["configuration_admission"]["policy_source"], "sandbox",
        "a global policy must not replace the embedded-policy control"
    );
    assert_eq!(
        accepted["current_policy_version"],
        accepted["configuration_admission"]["policy_version"]
    );
    let engine = ContainerEngine::from_env().expect("container engine");
    let boundary = container_state(&engine, name, "sandbox");
    let deadline = tokio::time::Instant::now() + DEADLINE;
    let before = loop {
        let observed = workload(&engine, &boundary, &sandbox.workload_url);
        if observed["heartbeat"].is_string() {
            break observed;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "accepted workload heartbeat absent: {observed}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_single_workload_start(&before);
    let (output, code) = probe(name, upstream.port, stage, authenticated).await;
    assert_eq!(code, 0, "active exec failed: {output}");
    assert!(
        output.contains("STATUS 200"),
        "allowed endpoint failed: {output}"
    );
    let captured = upstream.captured();
    let matching: Vec<_> = captured
        .iter()
        .filter(|request| {
            request["request_line"]
                .as_str()
                .is_some_and(|line| line.contains(&format!("/{name}/")))
        })
        .collect();
    assert!(
        matching.len() >= 2,
        "main and exec requests were not observed"
    );
    for request in &matching {
        if authenticated {
            assert_eq!(request["authorization"], format!("Bearer {TOKEN}"));
        } else {
            assert!(
                request["authorization"].is_null(),
                "detached provider still supplied credentials"
            );
        }
    }
    let denied_before = denied.captured();
    let denied_connections = denied.connection_count();
    let (denied_output, denied_code) = probe(name, denied.port, "unauthorized", false).await;
    assert_eq!(
        denied_code, 0,
        "denial probe could not run: {denied_output}"
    );
    assert!(
        denied_output.contains("DENIED") || denied_output.contains("STATUS 403"),
        "unauthorized endpoint did not produce a denial: {denied_output}"
    );
    assert_eq!(
        denied.captured(),
        denied_before,
        "unauthorized endpoint received a request"
    );
    assert_eq!(denied.connection_count(), denied_connections);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = workload(&engine, &boundary, &sandbox.workload_url);
    assert_eq!(
        before["starts"], after["starts"],
        "main workload relaunched"
    );
    assert_ne!(
        before["heartbeat"], after["heartbeat"],
        "main workload stopped advancing"
    );
    record(
        stage,
        json!({"sandbox":name,"accepted":accepted,"boundary":boundary,"workload_before":before,"workload_after":after,"matching_requests":matching,"probe_output":output,"denied_output":denied_output,"denied_requests_before":denied_before,"denied_requests_after":denied.captured(),"denied_connections_before":denied_connections,"denied_connections_after":denied.connection_count()}),
    );
    accepted
}

async fn verify_policy_repair(
    image: &ImageGuard,
    provider: &ProviderGuard,
    inspected: &Path,
    upstream: &Upstream,
    denied: &Upstream,
) {
    let mut replaced = create_sandbox(image, Some(&provider.name), upstream);
    let rejected = assert_blocked(&mut replaced, upstream).await;
    cli_ok(&[
        "policy",
        "set",
        &replaced.guard.name,
        "--policy",
        inspected.to_str().expect("replacement policy path"),
    ])
    .await;
    let repaired = assert_active(
        &mut replaced,
        upstream,
        denied,
        true,
        "complete-policy-repair",
    )
    .await;
    let engine = ContainerEngine::from_env().expect("container engine");
    let boundary_before = container_state(&engine, &replaced.guard.name, "sandbox");
    let workload_before = workload(&engine, &boundary_before, &replaced.workload_url);
    // Repeating a complete valid policy write must not replay the workload start.
    cli_ok(&[
        "policy",
        "set",
        &replaced.guard.name,
        "--policy",
        inspected.to_str().expect("replacement policy path"),
    ])
    .await;
    assert_active(
        &mut replaced,
        upstream,
        denied,
        true,
        "repeated-policy-repair",
    )
    .await;
    let boundary_after = container_state(&engine, &replaced.guard.name, "sandbox");
    let workload_after = workload(&engine, &boundary_after, &replaced.workload_url);
    assert_eq!(boundary_before, boundary_after);
    assert_eq!(workload_before["starts"], workload_after["starts"]);
    record(
        "repeat-repair-process-identity",
        json!({"boundary_before":boundary_before,"boundary_after":boundary_after,"workload_before":workload_before,"workload_after":workload_after}),
    );
    record(
        "policy-repair-transition",
        json!({"before":rejected,"after":repaired}),
    );
    drop(replaced);
}

#[tokio::test]
async fn configuration_composition_repair_preserves_prelaunch_gate() {
    let upstream = Upstream::start().await;
    let denied = Upstream::start().await;
    denied.prove_listening().await;
    let context = tempfile::tempdir().expect("composition fixture context");
    let provider_name = format!("composition-provider-{:016x}", rand::random::<u64>());
    let policy = materialize(
        context.path(),
        "image-policy.yaml",
        upstream.port,
        &provider_name,
    );
    let inspected = materialize(
        context.path(),
        "inspected-policy.yaml",
        upstream.port,
        &provider_name,
    );
    let profile = materialize(
        context.path(),
        "provider-profile.yaml",
        upstream.port,
        &provider_name,
    );
    let image = build_image(&context.path().join("uninspected-image"), &policy);
    let inspected_image = build_image(&context.path().join("inspected-image"), &inspected);
    let provider = install_provider(provider_name, &profile).await;

    // The exact same embedded image policy must activate without provider
    // composition, so malformed YAML or an invalid image cannot satisfy rejection.
    let mut standalone = create_sandbox(&image, None, &upstream);
    assert_active(&mut standalone, &upstream, &denied, false, "valid-alone").await;
    prove_stopped_process_observation(&standalone).await;
    drop(standalone);

    let mut detached = create_sandbox(&image, Some(&provider.name), &upstream);
    let rejected = assert_blocked(&mut detached, &upstream).await;
    cli_ok(&[
        "sandbox",
        "provider",
        "detach",
        &detached.guard.name,
        &provider.name,
    ])
    .await;
    let repaired = assert_active(
        &mut detached,
        &upstream,
        &denied,
        false,
        "provider-detach-repair",
    )
    .await;
    record(
        "provider-repair-transition",
        json!({"before":rejected,"after":repaired}),
    );
    drop(detached);

    verify_policy_repair(&image, &provider, &inspected, &upstream, &denied).await;

    // The matching inspected image and endpoint-bearing provider must work
    // directly; disabling every credentialed composition cannot pass this test.
    let mut matching = create_sandbox(&inspected_image, Some(&provider.name), &upstream);
    assert_active(
        &mut matching,
        &upstream,
        &denied,
        true,
        "valid-matching-bundle",
    )
    .await;
    drop(matching);
    drop(provider);
}
