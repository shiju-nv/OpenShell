// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox-local [`BoundaryLoopbackConnector`] implementation.

use async_trait::async_trait;
use openshell_isolation_interface::contract::{
    BackendError, BoundaryDuplexStream, BoundaryLoopbackConnector, BoundarySignal, LoopbackTarget,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

const RUNTIME_ACTIVE: u8 = 0;
const RUNTIME_FROZEN: u8 = 1;
const RUNTIME_TERMINATED: u8 = 2;
const RUNTIME_ENFORCEMENT_LOST: u8 = 3;

/// Shared liveness and child-process ownership for one active boundary.
pub struct BoundaryRuntimeState {
    state: AtomicU8,
    // Process control precedes registry or per-process signal ownership. Never
    // retain the registry while waiting for a signal/reap lock: child reaping
    // and launch registration also share the managed-children registry.
    process_control: Mutex<()>,
    process_groups: Mutex<HashMap<u32, RegisteredProcessGroup>>,
    exclusive_pid_namespace: bool,
}

impl BoundaryRuntimeState {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(RUNTIME_ACTIVE),
            process_control: Mutex::new(()),
            process_groups: Mutex::new(HashMap::new()),
            exclusive_pid_namespace: false,
        })
    }

    /// Construct state for a boundary that exclusively owns its PID namespace.
    #[must_use]
    pub fn new_exclusive_pid_namespace() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(RUNTIME_ACTIVE),
            process_control: Mutex::new(()),
            process_groups: Mutex::new(HashMap::new()),
            exclusive_pid_namespace: true,
        })
    }

    #[must_use]
    pub const fn requires_dedicated_process_group(&self) -> bool {
        self.exclusive_pid_namespace
    }

    pub fn ensure_active(&self) -> Result<(), BackendError> {
        match self.state.load(Ordering::Acquire) {
            RUNTIME_ACTIVE => Ok(()),
            RUNTIME_FROZEN => Err(BackendError::Unavailable(
                "boundary is frozen while supervisor control recovers".to_string(),
            )),
            _ => Err(BackendError::Terminated("boundary has ended".to_string())),
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.load(Ordering::Acquire) == RUNTIME_ACTIVE
    }

    #[must_use]
    pub fn enforcement_was_lost(&self) -> bool {
        self.state.load(Ordering::Acquire) == RUNTIME_ENFORCEMENT_LOST
    }

    pub fn register_process_group(
        &self,
        pid: u32,
        terminal: Arc<std::sync::atomic::AtomicBool>,
        signal_lock: Arc<Mutex<()>>,
    ) -> Result<(), BackendError> {
        let mut groups = self
            .process_groups
            .lock()
            .map_err(|_| BackendError::Process("boundary process registry poisoned".to_string()))?;
        self.ensure_active()?;
        groups.insert(
            pid,
            RegisteredProcessGroup {
                pid,
                terminal,
                signal_lock,
                pending_signals: Vec::new(),
            },
        );
        Ok(())
    }

    pub fn unregister_process_group(
        &self,
        pid: u32,
        terminal: &Arc<std::sync::atomic::AtomicBool>,
    ) {
        if let Ok(mut groups) = self.process_groups.lock()
            && groups
                .get(&pid)
                .is_some_and(|group| Arc::ptr_eq(&group.terminal, terminal))
        {
            groups.remove(&pid);
        }
    }

    #[cfg(test)]
    pub fn registered_process_group_count(&self) -> usize {
        self.process_groups.lock().map_or(0, |groups| groups.len())
    }

    /// Serialize process signals with the complete hold/release transition.
    /// Poisoning closes admission; only boundary-wide teardown may bypass it.
    fn process_control_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, BackendError> {
        self.process_control.lock().map_err(|_| {
            let _ = self.state.compare_exchange(
                RUNTIME_ACTIVE,
                RUNTIME_FROZEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            BackendError::Unavailable("boundary process control poisoned".to_string())
        })
    }

    /// Deliver an authenticated process signal, or retain it until a held
    /// configuration is released. Killing a stopped parent can make Linux
    /// continue an orphaned child group, so per-process signals cannot end a hold.
    pub(crate) fn signal_process_group(
        &self,
        pid: u32,
        terminal: &Arc<std::sync::atomic::AtomicBool>,
        signal: BoundarySignal,
    ) -> Result<(), BackendError> {
        let _control = self.process_control_guard()?;
        let mut groups = self
            .process_groups
            .lock()
            .map_err(|_| BackendError::Process("boundary process registry poisoned".to_string()))?;
        let group = groups
            .get_mut(&pid)
            .filter(|group| Arc::ptr_eq(&group.terminal, terminal))
            .ok_or_else(|| {
                BackendError::Terminated("process registration has ended".to_string())
            })?;
        if group.terminal.load(Ordering::Acquire) {
            return Err(BackendError::Terminated("process has exited".to_string()));
        }
        match self.state.load(Ordering::Acquire) {
            RUNTIME_ACTIVE => {
                let group = group.clone();
                drop(groups);
                group.deliver(signal)
            }
            RUNTIME_FROZEN => {
                // Standard signals coalesce. The typed interface has only four
                // variants, bounding storage even during a prolonged hold.
                if !group.pending_signals.contains(&signal) {
                    group.pending_signals.push(signal);
                }
                Ok(())
            }
            _ => Err(BackendError::Terminated("boundary has ended".to_string())),
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn pending_signal_count(
        &self,
        pid: u32,
        terminal: &Arc<std::sync::atomic::AtomicBool>,
    ) -> usize {
        self.process_groups.lock().map_or(0, |groups| {
            groups
                .get(&pid)
                .filter(|group| Arc::ptr_eq(&group.terminal, terminal))
                .map_or(0, |group| group.pending_signals.len())
        })
    }

    /// End the boundary and terminate every registered workload process group.
    pub fn deactivate(&self) {
        // Fatal teardown remains available even if an earlier operation panicked.
        let _control = self
            .process_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = self.state.swap(RUNTIME_TERMINATED, Ordering::AcqRel);
        if matches!(previous, RUNTIME_ACTIVE | RUNTIME_FROZEN) {
            self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
            self.signal_registered_processes(nix::sys::signal::Signal::SIGKILL);
        }
    }

    /// Stop every owned workload process while the supervisor reconnects.
    ///
    /// New process and loopback operations fail while frozen. The registered
    /// process groups include the canonical workload and every sandbox exec.
    #[must_use]
    pub fn freeze(&self) -> bool {
        let Ok(_control) = self.process_control_guard() else {
            return false;
        };
        if self
            .state
            .compare_exchange(
                RUNTIME_ACTIVE,
                RUNTIME_FROZEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            self.confirm_process_stop().is_ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.signal_registered_processes(nix::sys::signal::Signal::SIGSTOP);
            true
        }
    }

    /// Hold all owned processes and observe their stopped state before installation.
    /// A failed observation keeps execution closed; callers must not publish new
    /// credentials merely because delivery of SIGSTOP succeeded.
    #[cfg(target_os = "linux")]
    pub(crate) fn freeze_confirmed(&self) -> Result<(), BackendError> {
        let _control = self.process_control_guard()?;
        let _ = self.state.compare_exchange(
            RUNTIME_ACTIVE,
            RUNTIME_FROZEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if self.state.load(Ordering::Acquire) != RUNTIME_FROZEN {
            return Err(BackendError::Terminated(
                "boundary cannot be held".to_string(),
            ));
        }
        self.confirm_process_stop()
    }

    #[cfg(target_os = "linux")]
    fn confirm_process_stop(&self) -> Result<(), BackendError> {
        let result = self.stop_owned_processes();
        if result.is_err() {
            // Failed observation never reopens execution. Stop every reachable
            // descendant as a final best effort, without claiming a confirmed
            // hold or letting a failed ancestor wait leave its children running.
            self.signal_registered_processes(nix::sys::signal::Signal::SIGSTOP);
        }
        result
    }

    #[cfg(target_os = "linux")]
    fn stop_owned_processes(&self) -> Result<(), BackendError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            check_stop_deadline(deadline)?;
            let groups = self
                .process_groups
                .lock()
                .map_err(|_| {
                    BackendError::Process("boundary process registry poisoned".to_string())
                })?
                .values()
                .filter(|group| !group.terminal.load(Ordering::Acquire))
                .cloned()
                .collect::<Vec<_>>();
            let roots = groups.iter().map(|group| group.pid).collect::<Vec<_>>();
            let owned = owned_process_ids(&roots, self.exclusive_pid_namespace);
            // A vfork parent cannot stop until its child releases the shared
            // address space. Stop and observe ancestors first so their children
            // can finish exec/exit before receiving their own stop signal.
            for pid in &owned {
                check_stop_deadline(deadline)?;
                if let Some(group) = groups.iter().find(|group| group.pid == *pid) {
                    group.stop_process()?;
                } else {
                    stop_process(*pid)?;
                }
                while !process_is_stopped_or_exited(*pid) {
                    check_stop_deadline(deadline)?;
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            // Parents cannot create more children after every thread stops.
            // Rescan for children born during earlier ancestor waits, retaining
            // the same deadline across every scan and process observation.
            let current = owned_process_ids(&roots, self.exclusive_pid_namespace);
            if current == owned && current.into_iter().all(process_is_stopped_or_exited) {
                return Ok(());
            }
            check_stop_deadline(deadline)?;
        }
    }

    /// Resume only after the exact installed configuration has been released.
    /// Authentication and isolation confirmation alone never call this method.
    #[must_use]
    pub fn resume(&self) -> bool {
        let Ok(_control) = self.process_control_guard() else {
            return false;
        };
        let Ok(mut groups) = self.process_groups.lock() else {
            return false;
        };
        if self
            .state
            .compare_exchange(
                RUNTIME_FROZEN,
                RUNTIME_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let deferred = groups
            .values_mut()
            .map(|group| (group.clone(), std::mem::take(&mut group.pending_signals)))
            .collect::<Vec<_>>();
        drop(groups);
        self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
        // Release has authorized execution for the entire owned tree before a
        // queued termination can orphan a descendant. Reaped/replaced roots
        // retain their own terminal guard and cannot target a reused process.
        for (group, signals) in deferred {
            for signal in signals {
                let _ = group.deliver(signal);
            }
        }
        true
    }

    /// Begin fail-closed termination after authenticated recovery times out.
    /// Frozen tasks are continued before `SIGTERM` so they can run their
    /// ordinary shutdown handlers.
    #[must_use]
    pub fn begin_enforcement_loss_termination(&self) -> bool {
        let _control = self
            .process_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self
            .state
            .compare_exchange(
                RUNTIME_FROZEN,
                RUNTIME_ENFORCEMENT_LOST,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
        self.signal_registered_processes(nix::sys::signal::Signal::SIGTERM);
        true
    }

    /// Begin an authenticated, graceful boundary shutdown.
    #[must_use]
    pub fn begin_termination(&self) -> bool {
        let _control = self
            .process_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            let state = self.state.load(Ordering::Acquire);
            if !matches!(state, RUNTIME_ACTIVE | RUNTIME_FROZEN) {
                return false;
            }
            if self
                .state
                .compare_exchange(
                    state,
                    RUNTIME_TERMINATED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
                self.signal_registered_processes(nix::sys::signal::Signal::SIGTERM);
                return true;
            }
        }
    }

    /// Force all remaining owned process groups to exit.
    pub fn force_kill(&self) {
        let _control = self
            .process_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.force_kill_owned_processes();
    }

    fn force_kill_owned_processes(&self) {
        self.signal_registered_processes(nix::sys::signal::Signal::SIGCONT);
        self.signal_registered_processes(nix::sys::signal::Signal::SIGKILL);
    }

    #[must_use]
    pub fn has_registered_processes(&self) -> bool {
        self.process_groups
            .lock()
            .is_ok_and(|groups| !groups.is_empty())
    }

    /// End the boundary because required standing enforcement was lost.
    ///
    /// Returns `true` only to the caller that won the active-to-terminated
    /// transition. A concurrent normal teardown cannot later be reclassified
    /// as enforcement loss.
    pub fn deactivate_for_enforcement_loss(&self) -> bool {
        let _control = self
            .process_control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            let state = self.state.load(Ordering::Acquire);
            if !matches!(state, RUNTIME_ACTIVE | RUNTIME_FROZEN) {
                return false;
            }
            if self
                .state
                .compare_exchange(
                    state,
                    RUNTIME_ENFORCEMENT_LOST,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.force_kill_owned_processes();
                return true;
            }
        }
    }

    fn signal_registered_processes(&self, signal: nix::sys::signal::Signal) {
        let groups = self
            .process_groups
            .lock()
            .map(|groups| groups.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for group in &groups {
            group.signal(signal);
        }
        #[cfg(target_os = "linux")]
        {
            let roots = groups.iter().map(|group| group.pid).collect::<Vec<_>>();
            // A workload may create another process group or session. Once its
            // registered roots are stopped they cannot fork again, so bounded
            // repeated descendant scans close the signal-to-scan race without
            // requiring ptrace or a capability.
            let mut previous = Vec::new();
            for _ in 0..4 {
                let owned = owned_process_ids(&roots, self.exclusive_pid_namespace);
                for pid in &owned {
                    if roots.contains(pid) {
                        continue;
                    }
                    if let Ok(pid) = i32::try_from(*pid) {
                        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal);
                    }
                }
                if owned == previous {
                    break;
                }
                previous = owned;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn check_stop_deadline(deadline: std::time::Instant) -> Result<(), BackendError> {
    if std::time::Instant::now() >= deadline {
        return Err(BackendError::Unavailable(
            "workload stop could not be confirmed".to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn stop_process(pid: u32) -> Result<(), BackendError> {
    let pid = i32::try_from(pid)
        .map_err(|_| BackendError::Process("workload PID is out of range".to_string()))?;
    match nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGSTOP,
    ) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(BackendError::Unavailable(format!(
            "workload stop signal failed: {error}"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn process_is_stopped_or_exited(pid: u32) -> bool {
    let entries = match std::fs::read_dir(format!("/proc/{pid}/task")) {
        Ok(entries) => entries,
        Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return false,
        };
        if !stat
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.chars().next())
            .is_some_and(|state| matches!(state, 'T' | 't' | 'Z' | 'X'))
        {
            return false;
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn owned_process_ids(roots: &[u32], exclusive_pid_namespace: bool) -> Vec<u32> {
    let mut parents = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return roots.to_vec();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(after_name) = stat.rsplit_once(") ").map(|(_, fields)| fields) else {
            continue;
        };
        let Some(parent) = after_name
            .split_whitespace()
            .nth(1)
            .and_then(|field| field.parse::<u32>().ok())
        else {
            continue;
        };
        parents.insert(pid, parent);
    }

    // When openshell-sandbox is PID 1, every other process in its exclusive
    // namespace is workload-owned, including an orphan reparented during the
    // scan. Outside that deployment shape, restrict the walk to registered
    // roots so unit tests and development runs cannot affect sibling tasks.
    if exclusive_pid_namespace && std::process::id() == 1 {
        let mut owned = parents
            .keys()
            .copied()
            .filter(|pid| *pid != 1)
            .collect::<Vec<_>>();
        sort_parents_before_children(&mut owned, &parents);
        return owned;
    }

    let mut owned = roots.to_vec();
    loop {
        let mut changed = false;
        for (&pid, &parent) in &parents {
            if !owned.contains(&pid) && owned.contains(&parent) {
                owned.push(pid);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    sort_parents_before_children(&mut owned, &parents);
    owned
}

#[cfg(target_os = "linux")]
fn sort_parents_before_children(owned: &mut [u32], parents: &HashMap<u32, u32>) {
    owned.sort_unstable_by_key(|pid| {
        let mut parent = *pid;
        let mut depth = 0;
        // Bound traversal even if process exits/reparenting make a scan
        // inconsistent. PID order only breaks ties between unrelated tasks.
        while let Some(next) = parents.get(&parent) {
            depth += 1;
            if depth >= parents.len() || *next == parent {
                break;
            }
            parent = *next;
        }
        (depth, *pid)
    });
}

#[derive(Clone)]
struct RegisteredProcessGroup {
    pid: u32,
    terminal: Arc<std::sync::atomic::AtomicBool>,
    signal_lock: Arc<Mutex<()>>,
    pending_signals: Vec<BoundarySignal>,
}

impl RegisteredProcessGroup {
    fn deliver(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let _signal_guard = self
            .signal_lock
            .lock()
            .map_err(|_| BackendError::Process("process signal ownership poisoned".to_string()))?;
        if self.terminal.load(Ordering::Acquire) {
            return Err(BackendError::Terminated("process has exited".to_string()));
        }
        let pid = i32::try_from(self.pid)
            .map_err(|_| BackendError::Process("workload PID is out of range".to_string()))?;
        let signal = match signal {
            BoundarySignal::Term => nix::sys::signal::Signal::SIGTERM,
            BoundarySignal::Kill => nix::sys::signal::Signal::SIGKILL,
            BoundarySignal::Int => nix::sys::signal::Signal::SIGINT,
            BoundarySignal::Hup => nix::sys::signal::Signal::SIGHUP,
        };
        nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), signal)
            .map_err(|error| BackendError::Process(error.to_string()))
    }

    #[cfg(target_os = "linux")]
    fn stop_process(&self) -> Result<(), BackendError> {
        let _signal_guard = self
            .signal_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.terminal.load(Ordering::Acquire) {
            return Ok(());
        }
        stop_process(self.pid)
    }

    fn signal(&self, signal: nix::sys::signal::Signal) {
        let _signal_guard = self
            .signal_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.terminal.load(Ordering::Acquire) {
            return;
        }
        if let Ok(pid) = i32::try_from(self.pid) {
            let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), signal);
        }
    }
}

/// Loopback port-forward owned by the sandbox process.
pub struct LocalLoopbackConnector {
    runtime: Option<Arc<BoundaryRuntimeState>>,
}

impl LocalLoopbackConnector {
    #[must_use]
    pub fn new(runtime: Option<Arc<BoundaryRuntimeState>>) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl BoundaryLoopbackConnector for LocalLoopbackConnector {
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        if let Some(runtime) = &self.runtime {
            runtime.ensure_active()?;
        }
        let addr = std::net::SocketAddr::new(target.host(), target.port());
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&[addr])
            .await
            .map_err(|e| BackendError::Process(format!("port-forward connect to {addr}: {e}")))?;
        if let Some(runtime) = &self.runtime {
            runtime.ensure_active()?;
        }
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(target_os = "linux")]
    include!("boundary_io_vfork_tests.rs");

    /// Stands in for the SSH server's port-forward path: connect through the
    /// interface, write, and read the echo.
    #[tokio::test]
    async fn loopback_connector_connects_and_round_trips() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
        });

        let pf = LocalLoopbackConnector::new(None);
        let target =
            LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), addr.port()).expect("loopback target");
        let mut conn = pf.connect(target).await.expect("connect through interface");
        conn.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    /// Drive the port-forward interface through a generic `&dyn` consumer, proving a
    /// kernel-separated backend (tunneling into a guest) would use the same call.
    #[tokio::test]
    async fn loopback_connector_is_driven_via_dyn() {
        async fn forward_one(pf: &dyn BoundaryLoopbackConnector, target: LoopbackTarget) -> bool {
            pf.connect(target).await.is_ok()
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let pf = LocalLoopbackConnector::new(None);
        let target = LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), addr.port()).unwrap();
        assert!(forward_one(&pf, target).await);
    }

    #[tokio::test]
    async fn loopback_connector_rejects_after_boundary_end() {
        let runtime = BoundaryRuntimeState::new();
        let pf = LocalLoopbackConnector::new(Some(runtime.clone()));
        runtime.deactivate();
        let target = LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), 1).unwrap();
        assert!(matches!(
            pf.connect(target).await,
            Err(BackendError::Terminated(_))
        ));
    }

    #[tokio::test]
    async fn failed_loopback_connector_keeps_boundary_active() {
        let runtime = BoundaryRuntimeState::new();
        let pf = LocalLoopbackConnector::new(Some(runtime.clone()));
        // Port zero is never a connectable TCP destination. Reserving an ephemeral
        // port and dropping its listener races other parallel tests that may bind it.
        let target = LoopbackTarget::new(Ipv4Addr::LOCALHOST.into(), 0).unwrap();
        assert!(matches!(
            pf.connect(target).await,
            Err(BackendError::Process(_))
        ));
        runtime.ensure_active().expect("boundary remains active");
    }

    #[test]
    fn stale_unregister_preserves_reused_process_group_registration() {
        let runtime = BoundaryRuntimeState::new();
        let first_terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pid = 42;
        runtime
            .register_process_group(pid, first_terminal.clone(), Arc::new(Mutex::new(())))
            .expect("first registration");
        runtime
            .register_process_group(pid, second_terminal.clone(), Arc::new(Mutex::new(())))
            .expect("replacement registration");

        runtime.unregister_process_group(pid, &first_terminal);
        assert_eq!(runtime.registered_process_group_count(), 1);

        runtime.unregister_process_group(pid, &second_terminal);
        assert_eq!(runtime.registered_process_group_count(), 0);
    }

    #[test]
    fn canonical_process_completion_does_not_end_boundary_runtime() {
        let runtime = BoundaryRuntimeState::new_exclusive_pid_namespace();
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(true));
        runtime
            .register_process_group(42, terminal.clone(), Arc::new(Mutex::new(())))
            .expect("register canonical process");

        runtime.unregister_process_group(42, &terminal);

        runtime
            .ensure_active()
            .expect("canonical completion must preserve exec and forwarding");
        assert_eq!(runtime.registered_process_group_count(), 0);
        runtime.deactivate();
        assert!(matches!(
            runtime.ensure_active(),
            Err(BackendError::Terminated(_))
        ));
    }

    #[test]
    fn freeze_blocks_new_operations_until_explicit_resume() {
        let runtime = BoundaryRuntimeState::new_exclusive_pid_namespace();

        assert!(runtime.freeze());
        assert!(matches!(
            runtime.ensure_active(),
            Err(BackendError::Unavailable(_))
        ));
        assert!(!runtime.freeze());
        assert!(runtime.resume());
        runtime.ensure_active().expect("runtime resumed");
    }

    #[test]
    fn poisoned_process_control_rejects_signals_and_release() {
        let runtime = BoundaryRuntimeState::new();
        let poison_runtime = runtime.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = poison_runtime.process_control.lock().unwrap();
                panic!("poison process control for fail-closed assertion");
            })
            .join()
            .is_err()
        );
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert!(matches!(
            runtime.signal_process_group(42, &terminal, BoundarySignal::Kill),
            Err(BackendError::Unavailable(_))
        ));
        assert!(!runtime.is_active());
        assert!(!runtime.resume());
        runtime.deactivate();
        assert!(matches!(
            runtime.ensure_active(),
            Err(BackendError::Terminated(_))
        ));
    }

    #[test]
    fn process_signal_releases_registry_before_waiting_for_reaper() {
        let runtime = BoundaryRuntimeState::new();
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal_lock = Arc::new(Mutex::new(()));
        // This deliberately unrepresentable PID can never target an OS process,
        // even if an assertion or the terminal guard is changed incorrectly.
        let pid = u32::MAX;
        runtime
            .register_process_group(pid, terminal.clone(), signal_lock.clone())
            .expect("register signal ownership fixture");
        let signal_guard = signal_lock.lock().expect("retain reaper ownership");
        let baseline_owners = Arc::strong_count(&signal_lock);
        let signal_runtime = runtime.clone();
        let signal_terminal = terminal.clone();
        let delivery = std::thread::spawn(move || {
            signal_runtime.signal_process_group(pid, &signal_terminal, BoundarySignal::Kill)
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut registry_available = false;
        while std::time::Instant::now() < deadline {
            // The retained registration snapshot is a rendezvous: checking the
            // registry earlier could pass before delivery had acquired it.
            if Arc::strong_count(&signal_lock) > baseline_owners
                && runtime.process_groups.try_lock().is_ok()
            {
                registry_available = true;
                break;
            }
            std::thread::yield_now();
        }
        // Always release the blocked delivery before reporting a failed check.
        terminal.store(true, Ordering::Release);
        drop(signal_guard);
        let result = delivery.join().expect("signal delivery worker");
        runtime.unregister_process_group(pid, &terminal);
        assert!(
            registry_available,
            "signal delivery must release the process registry before waiting for the reaper"
        );
        assert!(matches!(result, Err(BackendError::Terminated(_))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn configuration_activation_freeze_confirms_real_child_stop() {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::{Pid, getpgid};
        use std::fs;
        use std::os::unix::process::CommandExt;
        use std::path::{Path, PathBuf};
        use std::process::{Child, Command, ExitStatus, Stdio};
        use std::time::{Duration, Instant};

        // The shell owns a private process group and reaps its descendant on
        // orderly exit. Keep cleanup active even when a heartbeat assertion fails.
        struct WorkloadChild {
            child: Child,
            stop_path: PathBuf,
            reaped: bool,
        }

        impl WorkloadChild {
            fn shutdown(&mut self) -> std::io::Result<ExitStatus> {
                fs::write(&self.stop_path, [])?;
                let group = Pid::from_raw(i32::try_from(self.child.id()).unwrap());
                let _ = killpg(group, Signal::SIGCONT);
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if let Some(status) = self.child.try_wait()? {
                        self.reaped = true;
                        return Ok(status);
                    }
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "heartbeat workload did not exit",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }

        impl Drop for WorkloadChild {
            fn drop(&mut self) {
                if self.reaped || self.shutdown().is_ok() {
                    return;
                }
                // This PID is the group leader created by process_group(0),
                // so emergency cleanup cannot signal the test runner's group.
                if let Ok(pid) = i32::try_from(self.child.id()) {
                    let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
                }
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }

        fn heartbeat_len(path: &Path) -> u64 {
            fs::metadata(path).expect("heartbeat file exists").len()
        }

        fn wait_for_heartbeats(parent: &Path, descendant: &Path, previous: (u64, u64)) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while heartbeat_len(parent) <= previous.0 || heartbeat_len(descendant) <= previous.1 {
                assert!(
                    Instant::now() < deadline,
                    "both workload heartbeats must advance"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        let dir = tempfile::tempdir().expect("heartbeat fixture directory");
        let stop_path = dir.path().join("stop");
        let parent_heartbeat = dir.path().join("parent-heartbeat");
        let descendant_heartbeat = dir.path().join("descendant-heartbeat");
        let descendant_pid_path = dir.path().join("descendant-pid");
        fs::write(&parent_heartbeat, []).expect("initialize parent heartbeat");
        fs::write(&descendant_heartbeat, []).expect("initialize descendant heartbeat");

        // /bin/sh supplies real workload processes without requiring another
        // compiled fixture. Both loops stop through the shared shutdown file.
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg(
                r#"
stop=$1
/bin/sh -c '
    printf "%s\n" "$$" > "$3"
    while [ ! -e "$1" ]; do
        printf x >> "$2"
        sleep 0.01
    done
' heartbeat-descendant "$1" "$3" "$4" &
descendant=$!
trap 'touch "$stop"; wait "$descendant"' EXIT
trap 'exit 1' TERM INT
while [ ! -e "$1" ]; do
    printf x >> "$2"
    sleep 0.01
done
wait "$descendant"
status=$?
trap - EXIT
exit "$status"
"#,
            )
            .arg("heartbeat-parent")
            .arg(&stop_path)
            .arg(&parent_heartbeat)
            .arg(&descendant_heartbeat)
            .arg(&descendant_pid_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn isolated heartbeat workload");
        let mut workload = WorkloadChild {
            child,
            stop_path,
            reaped: false,
        };
        let parent_pid = workload.child.id();
        let parent_group = Pid::from_raw(i32::try_from(parent_pid).unwrap());
        assert_eq!(getpgid(Some(parent_group)).unwrap(), parent_group);
        assert_ne!(parent_group, getpgid(None).unwrap());

        let runtime = BoundaryRuntimeState::new();
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime
            .register_process_group(parent_pid, terminal.clone(), Arc::new(Mutex::new(())))
            .expect("register isolated workload group");
        wait_for_heartbeats(&parent_heartbeat, &descendant_heartbeat, (0, 0));
        let descendant_pid = fs::read_to_string(&descendant_pid_path)
            .expect("descendant publishes its PID before its heartbeat")
            .trim()
            .parse::<u32>()
            .expect("numeric descendant PID");
        assert_ne!(parent_pid, descendant_pid);
        assert!(owned_process_ids(&[parent_pid], false).contains(&descendant_pid));

        runtime
            .freeze_confirmed()
            .expect("observe real workload stop");
        assert!(!runtime.is_active());
        assert!(process_is_stopped_or_exited(parent_pid));
        assert!(process_is_stopped_or_exited(descendant_pid));
        let stopped_heartbeats = (
            heartbeat_len(&parent_heartbeat),
            heartbeat_len(&descendant_heartbeat),
        );
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(heartbeat_len(&parent_heartbeat), stopped_heartbeats.0);
        assert_eq!(heartbeat_len(&descendant_heartbeat), stopped_heartbeats.1);

        assert!(runtime.resume());
        wait_for_heartbeats(&parent_heartbeat, &descendant_heartbeat, stopped_heartbeats);
        assert!(
            workload
                .shutdown()
                .expect("reap workload and descendant")
                .success()
        );
        terminal.store(true, Ordering::Release);
        runtime.unregister_process_group(parent_pid, &terminal);
        assert_eq!(runtime.registered_process_group_count(), 0);
        assert!(!Path::new(&format!("/proc/{parent_pid}")).exists());
        assert!(!Path::new(&format!("/proc/{descendant_pid}")).exists());
    }

    #[test]
    fn enforcement_loss_is_terminal_after_freeze() {
        let runtime = BoundaryRuntimeState::new_exclusive_pid_namespace();

        assert!(runtime.freeze());
        assert!(runtime.begin_enforcement_loss_termination());
        assert!(runtime.enforcement_was_lost());
        assert!(!runtime.resume());
        assert!(matches!(
            runtime.ensure_active(),
            Err(BackendError::Terminated(_))
        ));
    }
}
