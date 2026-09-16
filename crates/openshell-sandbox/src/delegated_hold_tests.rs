// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[allow(unsafe_code)]
mod held_process_fixture {
    use super::*;
    use crate::boundary_io::BoundaryRuntimeState;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Mutex, mpsc};
    use std::time::Instant;

    fn pipe() -> (File, File) {
        let mut fds = [-1; 2];
        // Successful descriptors each receive exactly one owning File.
        unsafe {
            assert_eq!(
                libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK),
                0
            );
            (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1]))
        }
    }

    fn state(pid: libc::pid_t) -> char {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat.rsplit_once(") ").unwrap().1.chars().next().unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 'X',
            Err(error) => panic!("read owned process state: {error}"),
        }
    }

    fn cleanup(pids: &Mutex<[libc::pid_t; 2]>) {
        // Signal and reap under one ownership lock so a concurrent wait cannot
        // release a PID for reuse between the ownership check and kill.
        let mut pids = pids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for &pid in pids.iter().rev().filter(|pid| **pid > 0) {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while pids.iter().any(|pid| *pid > 0) && Instant::now() < deadline {
            for index in 0..pids.len() {
                // The worker becomes our child only after the main exits; an
                // earlier ECHILD does not relinquish ownership of that worker.
                if pids[index] == 0 || (index == 1 && pids[0] != 0) {
                    continue;
                }
                let result =
                    unsafe { libc::waitpid(pids[index], std::ptr::null_mut(), libc::WNOHANG) };
                if result > 0
                    || (result < 0
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
                {
                    pids[index] = 0;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    struct Tree {
        main: libc::pid_t,
        worker: libc::pid_t,
        owned: Arc<Mutex<[libc::pid_t; 2]>>,
        heartbeat: File,
        acknowledge: Option<File>,
        cancel: Option<mpsc::Sender<()>>,
        watchdog: Option<std::thread::JoinHandle<()>>,
    }

    impl Tree {
        fn spawn() -> Self {
            let (mut identity, identity_writer) = pipe();
            let (heartbeat, heartbeat_writer) = pipe();
            let (acknowledged, acknowledge) = pipe();
            assert_eq!(
                unsafe { libc::fcntl(acknowledged.as_raw_fd(), libc::F_SETFL, 0) },
                0
            );
            // Raw children never enter Rust's allocator or inherited runtime.
            let main = unsafe {
                let main = libc::fork();
                if main == 0 {
                    libc::close(identity.as_raw_fd());
                    libc::close(heartbeat.as_raw_fd());
                    libc::close(acknowledge.as_raw_fd());
                    if libc::setsid() < 0 {
                        libc::_exit(91);
                    }
                    let worker = libc::fork();
                    if worker < 0 {
                        libc::_exit(92);
                    }
                    if worker == 0 {
                        if libc::setpgid(0, 0) != 0 {
                            libc::_exit(93);
                        }
                        libc::signal(libc::SIGHUP, libc::SIG_IGN);
                        let pid = libc::getpid();
                        if libc::write(
                            identity_writer.as_raw_fd(),
                            (&raw const pid).cast(),
                            size_of::<libc::pid_t>(),
                        ) != size_of::<libc::pid_t>().cast_signed()
                        {
                            libc::_exit(94);
                        }
                        // EOF ends an unacknowledged worker if startup fails
                        // before the controller can record ownership of its PID.
                        let mut byte = 0_u8;
                        if libc::read(acknowledged.as_raw_fd(), (&raw mut byte).cast(), 1) != 1 {
                            libc::_exit(96);
                        }
                        loop {
                            let byte = b'x';
                            if libc::write(
                                heartbeat_writer.as_raw_fd(),
                                (&raw const byte).cast(),
                                1,
                            ) != 1
                            {
                                libc::_exit(95);
                            }
                            libc::usleep(10_000);
                        }
                    }
                    loop {
                        libc::pause();
                    }
                }
                main
            };
            assert!(main > 0, "fork owned session leader");
            let mut tree = Self {
                main,
                worker: 0,
                owned: Arc::new(Mutex::new([main, 0])),
                heartbeat,
                acknowledge: Some(acknowledge),
                cancel: None,
                watchdog: None,
            };
            drop(identity_writer);
            drop(heartbeat_writer);
            let mut poll = libc::pollfd {
                fd: identity.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe { libc::poll(&raw mut poll, 1, 2000) },
                1,
                "worker publishes its PID"
            );
            let mut bytes = [0; size_of::<libc::pid_t>()];
            identity
                .read_exact(&mut bytes)
                .expect("read owned worker PID");
            tree.worker = libc::pid_t::from_ne_bytes(bytes);
            assert!(tree.worker > 0);
            tree.owned.lock().unwrap()[1] = tree.worker;
            tree.acknowledge.take().unwrap().write_all(b"x").unwrap();
            assert_eq!(unsafe { libc::getpgid(main) }, main);
            assert_eq!(unsafe { libc::getpgid(tree.worker) }, tree.worker);
            poll.fd = tree.heartbeat.as_raw_fd();
            assert_eq!(
                unsafe { libc::poll(&raw mut poll, 1, 2000) },
                1,
                "worker heartbeat runs before hold"
            );
            // The watchdog owns the same positive PID records as normal cleanup;
            // killing only the controller would leave the separate session alive.
            let owned = tree.owned.clone();
            let (cancel, receive) = mpsc::channel();
            tree.cancel = Some(cancel);
            tree.watchdog = Some(std::thread::spawn(move || {
                if matches!(
                    receive.recv_timeout(Duration::from_secs(8)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    cleanup(&owned);
                    unsafe {
                        libc::_exit(124);
                    }
                }
            }));
            tree
        }

        fn drain(&mut self) -> usize {
            let mut count = 0;
            let mut bytes = [0; 256];
            loop {
                match self.heartbeat.read(&mut bytes) {
                    Ok(0) => return count,
                    Ok(read) => count += read,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("read heartbeat: {error}"),
                }
            }
        }

        fn assert_stopped(&mut self) {
            assert_eq!(state(self.main), 'T', "session leader remains held");
            assert_eq!(
                state(self.worker),
                'T',
                "separate worker group remains held"
            );
            assert_eq!(
                self.drain(),
                0,
                "held worker cannot resume through orphan-group continuation"
            );
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            // Close before cleanup so an unpublished worker cannot stay blocked
            // waiting for its ownership acknowledgement after the main dies.
            drop(self.acknowledge.take());
            cleanup(&self.owned);
            if let Some(cancel) = self.cancel.take() {
                let _ = cancel.send(());
            }
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
        }
    }

    async fn wait_main(
        owned: Arc<Mutex<[libc::pid_t; 2]>>,
        terminal: Arc<AtomicBool>,
    ) -> std::io::Result<ProcessStatus> {
        loop {
            {
                let mut pids = owned.lock().unwrap();
                let mut status = 0;
                let result = unsafe { libc::waitpid(pids[0], &raw mut status, libc::WNOHANG) };
                if result < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if result > 0 {
                    pids[0] = 0;
                    terminal.store(true, Ordering::Release);
                    return Ok(std::process::ExitStatus::from_raw(status).into());
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Exercise held timeout, authenticated signals, and explicit fatal teardown.
    pub(super) fn run() {
        enum Action {
            Timeout,
            Signals,
            Fatal,
        }
        const ISOLATED: &str = "OPENSHELL_TEST_DELEGATED_HOLD_CONTROLLER";
        if std::env::var_os(ISOLATED).is_none() {
            struct Controller(std::process::Child);
            impl Drop for Controller {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let mut controller = Controller(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "delegated::tests::configuration_hold_defers_main_timeout_and_signals",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(ISOLATED, "1")
                    .spawn()
                    .expect("run isolated hold controller"),
            );
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(status) = controller.0.try_wait().unwrap() {
                    assert!(
                        status.success(),
                        "isolated hold regression failed: {status}"
                    );
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "hold controller exceeded deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        // Only this exact-test process adopts the fixture's orphan worker.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for action in [Action::Timeout, Action::Signals, Action::Fatal] {
            let mut tree = Tree::spawn();
            let runtime = BoundaryRuntimeState::new();
            let terminal = Arc::new(AtomicBool::new(false));
            runtime
                .register_process_group(
                    tree.main.cast_unsigned(),
                    terminal.clone(),
                    Arc::new(Mutex::new(())),
                )
                .unwrap();
            let worker_terminal = Arc::new(AtomicBool::new(false));
            if matches!(action, Action::Fatal) {
                // Explicit teardown owns both registered groups. The timeout
                // cases register only the main to expose orphan continuation.
                runtime
                    .register_process_group(
                        tree.worker.cast_unsigned(),
                        worker_terminal.clone(),
                        Arc::new(Mutex::new(())),
                    )
                    .unwrap();
            }
            let signaler = AgentSignaler {
                pid: tree.main.cast_unsigned(),
                terminal: terminal.clone(),
                boundary_runtime: runtime.clone(),
            };
            runtime
                .freeze_confirmed()
                .expect("confirm held process tree");
            assert!(
                tree.drain() > 0,
                "discard observed pre-hold heartbeat bytes"
            );
            executor.block_on(async {
                let waited = wait_main(tree.owned.clone(), terminal.clone());
                let wait = wait_with_timeout(waited, u64::from(matches!(action, Action::Timeout)), &signaler);
                tokio::pin!(wait);
                if matches!(action, Action::Timeout) {
                    // Poll the real timeout owner until both escalation requests
                    // exist, while proving neither request has completed the wait.
                    tokio::select! {
                        result = &mut wait => panic!("held timeout completed before release: {result:?}"),
                        () = async {
                            while runtime.pending_signal_count(signaler.pid, &terminal) != 2 {
                                tokio::time::sleep(Duration::from_millis(5)).await;
                            }
                        } => {}
                    }
                } else if matches!(action, Action::Signals) {
                    for _ in 0..2 {
                        signaler.term().unwrap();
                        signaler.kill().unwrap();
                        signaler.interrupt().unwrap();
                        signaler.hangup().unwrap();
                    }
                    assert_eq!(runtime.pending_signal_count(signaler.pid, &terminal), 4, "repeat signals coalesce while held");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                tree.assert_stopped();
                if matches!(action, Action::Fatal) {
                    runtime.deactivate();
                    assert!(!runtime.resume(), "explicit teardown remains terminal");
                } else {
                    assert!(runtime.resume(), "exact release reopens signal delivery");
                }
                let status = tokio::time::timeout(Duration::from_secs(2), &mut wait).await.expect("released timeout reaps its main process").expect("wait for main process");
                assert!(status.signal().is_some(), "queued termination reaches the workload after release");
                assert_eq!(runtime.pending_signal_count(signaler.pid, &terminal), 0);
                if matches!(action, Action::Fatal) {
                    tokio::time::timeout(Duration::from_secs(2), async {
                        while !matches!(state(tree.worker), 'Z' | 'X') {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }).await.expect("fatal teardown kills the held registered worker");
                }
            });
            runtime.unregister_process_group(signaler.pid, &terminal);
            cleanup(&tree.owned);
            assert_eq!(
                *tree.owned.lock().unwrap(),
                [0, 0],
                "owned main and adopted worker are reaped"
            );
            worker_terminal.store(true, Ordering::Release);
            runtime.unregister_process_group(tree.worker.cast_unsigned(), &worker_terminal);
        }
    }
}

#[test]
fn configuration_hold_defers_main_timeout_and_signals() {
    held_process_fixture::run();
}
