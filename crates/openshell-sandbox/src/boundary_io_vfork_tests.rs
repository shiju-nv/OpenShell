// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod configuration_vfork_fixture {
    use super::*;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    struct ChildArgs {
        ready: libc::c_int,
        gate: libc::c_int,
    }

    extern "C" fn vfork_child(opaque: *mut libc::c_void) -> libc::c_int {
        // The clone child shares its blocked parent's memory. Only direct libc
        // calls and stack locals are permitted until _exit releases the parent.
        unsafe {
            let args = &*opaque.cast::<ChildArgs>();
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            let pid = libc::getpid();
            let mut byte = 0_u8;
            if libc::write(
                args.ready,
                (&raw const pid).cast(),
                size_of::<libc::pid_t>(),
            ) != size_of::<libc::pid_t>() as isize
            {
                libc::_exit(91);
            }
            if libc::read(args.gate, (&raw mut byte).cast(), 1) != 1 {
                libc::_exit(92);
            }
            libc::_exit(0);
        }
    }

    fn pipe() -> (File, File) {
        let mut fds = [-1; 2];
        // Each successful pipe descriptor is transferred once to File ownership.
        unsafe {
            assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC), 0);
            (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1]))
        }
    }

    fn state(pid: libc::pid_t) -> char {
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat.rsplit_once(") ").unwrap().1.chars().next().unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 'X',
            Err(error) => panic!("read process {pid} state: {error}"),
        }
    }

    fn wait_until(mut ready: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ready() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        true
    }

    struct VforkTree {
        parent: libc::pid_t,
        child: libc::pid_t,
        gate: File,
        reaped: bool,
    }

    impl VforkTree {
        fn spawn() -> Self {
            let (mut ready, ready_writer) = pipe();
            let (gate_reader, gate) = pipe();
            // Allocate and align the clone stack before fork; neither child
            // enters the allocator inherited from the Rust test process.
            let mut stack = vec![0_u128; 4096];
            let mut args = ChildArgs {
                ready: ready_writer.as_raw_fd(),
                gate: gate_reader.as_raw_fd(),
            };
            let parent = unsafe {
                let parent = libc::fork();
                if parent == 0 {
                    if libc::setpgid(0, 0) != 0 {
                        libc::_exit(93);
                    }
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                    let child = libc::clone(
                        vfork_child,
                        stack.as_mut_ptr().add(stack.len()).cast(),
                        libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD,
                        (&raw mut args).cast(),
                    );
                    if child < 0 {
                        libc::_exit(94);
                    }
                    while libc::waitpid(child, std::ptr::null_mut(), 0) < 0 {
                        if *libc::__errno_location() != libc::EINTR {
                            libc::_exit(95);
                        }
                    }
                    loop {
                        libc::pause();
                    }
                }
                parent
            };
            assert!(parent > 0, "fork isolated vfork parent");
            let mut tree = Self {
                parent,
                child: 0,
                gate,
                reaped: false,
            };
            drop(ready_writer);
            drop(gate_reader);
            let mut poll = libc::pollfd {
                fd: ready.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe { libc::poll(&raw mut poll, 1, 2000) },
                1,
                "vfork child publishes PID"
            );
            let mut bytes = [0; size_of::<libc::pid_t>()];
            ready.read_exact(&mut bytes).expect("read vfork child PID");
            tree.child = libc::pid_t::from_ne_bytes(bytes);
            assert!(tree.child > 0);
            assert_eq!(unsafe { libc::getpgid(parent) }, parent);
            assert_ne!(unsafe { libc::getpgrp() }, parent);
            assert!(
                wait_until(|| state(parent) == 'D'),
                "parent waits for vfork completion"
            );
            tree
        }

        fn finish(&mut self) -> bool {
            if self.reaped {
                return true;
            }
            let _ = self.gate.write_all(b"x");
            // Resume the private group, then ensure the child exits so its
            // parent can reap it before the parent itself is killed/reaped.
            unsafe {
                libc::kill(-self.parent, libc::SIGCONT);
                if self.child > 0 {
                    libc::kill(self.child, libc::SIGKILL);
                }
            }
            let child_reaped = self.child > 0 && wait_until(|| state(self.child) == 'X');
            unsafe {
                libc::kill(-self.parent, libc::SIGKILL);
                while libc::waitpid(self.parent, std::ptr::null_mut(), 0) < 0 {
                    if *libc::__errno_location() != libc::EINTR {
                        break;
                    }
                }
            }
            self.reaped = true;
            child_reaped
        }
    }

    impl Drop for VforkTree {
        fn drop(&mut self) {
            let _ = self.finish();
        }
    }

    struct Controller(Child);

    impl Drop for Controller {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Run the vfork reproduction and both production freeze entrypoints.
    pub(super) fn run() {
        const ISOLATED: &str = "OPENSHELL_TEST_VFORK_CONTROLLER";
        if std::env::var_os(ISOLATED).is_none() {
            // An exact-test subprocess isolates raw child ownership from other
            // tests and their process reapers. Drop kills/reaps a stuck controller.
            let mut controller = Controller(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "boundary_io::tests::configuration_activation_freeze_orders_vfork_parent_before_child", "--nocapture", "--test-threads=1"])
                .env(ISOLATED, "1").process_group(0).spawn().expect("isolated vfork controller"));
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(status) = controller.0.try_wait().unwrap() {
                    assert!(
                        status.success(),
                        "isolated vfork regression failed: {status}"
                    );
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "vfork controller exceeded deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        let mut group_tree = VforkTree::spawn();
        assert_eq!(unsafe { libc::kill(-group_tree.parent, libc::SIGSTOP) }, 0);
        assert!(wait_until(|| state(group_tree.child) == 'T'));
        group_tree.gate.write_all(b"x").unwrap();
        assert_eq!(state(group_tree.parent), 'D');
        assert_eq!(state(group_tree.child), 'T');
        assert!(
            group_tree.finish(),
            "group-stop reproduction reaps its child"
        );

        for confirmed in [false, true] {
            let mut tree = VforkTree::spawn();
            let runtime = BoundaryRuntimeState::new();
            let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
            runtime
                .register_process_group(
                    tree.parent.cast_unsigned(),
                    terminal.clone(),
                    Arc::new(Mutex::new(())),
                )
                .unwrap();
            let parent = tree.parent;
            let mut gate = tree.gate.try_clone().unwrap();
            let feeder = std::thread::spawn(move || {
                let pending = wait_until(|| {
                    fs::read_to_string(format!("/proc/{parent}/status"))
                        .unwrap()
                        .lines()
                        .filter(|line| line.starts_with("SigPnd:") || line.starts_with("ShdPnd:"))
                        .any(|line| {
                            u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16)
                                .unwrap()
                                & (1_u64 << (libc::SIGSTOP - 1))
                                != 0
                        })
                });
                gate.write_all(b"x").unwrap();
                pending
            });
            let held = if confirmed {
                runtime.freeze_confirmed().is_ok()
            } else {
                runtime.freeze()
            };
            assert!(
                feeder.join().unwrap(),
                "gate opens only after the parent's pending STOP"
            );
            assert!(
                held,
                "ancestor-first freeze completes for entrypoint {confirmed}"
            );
            assert!(runtime.ensure_active().is_err());
            assert_eq!(state(tree.parent), 'T');
            assert!(
                owned_process_ids(&[tree.parent.cast_unsigned()], false)
                    .into_iter()
                    .all(process_is_stopped_or_exited)
            );
            assert!(runtime.resume());
            assert!(tree.finish(), "freeze regression reaps child and parent");
            terminal.store(true, Ordering::Release);
            runtime.unregister_process_group(tree.parent.cast_unsigned(), &terminal);
            assert_eq!(state(tree.parent), 'X');
        }
        println!(
            "configuration_activation_observation {{\"vfork_group_parent_d\":true,\"ancestor_first_parent_t\":true,\"freeze_entrypoints\":2}}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn configuration_activation_freeze_orders_vfork_parent_before_child() {
    configuration_vfork_fixture::run();
}
