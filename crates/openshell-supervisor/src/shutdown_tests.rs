// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shutdown exercises the production lifecycle owner through real boundary traits.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_isolation_interface::contract::{
    BackendError, BoundaryDuplexStream, BoundaryExec, BoundaryExitStatus,
    BoundaryLoopbackConnector, BoundaryProcess, BoundarySignal, ExecSession, ExecSpec,
    LoopbackTarget, RunningBoundary,
};
use tokio::sync::watch;

use super::shutdown_boundary;

enum WaitBehavior {
    Observe,
    Fail,
    Stall,
}

struct TestProcess {
    status: watch::Sender<Option<BoundaryExitStatus>>,
    signals: Mutex<Vec<BoundarySignal>>,
    held: bool,
    wait_behavior: WaitBehavior,
    stall_signal: bool,
    terminal: AtomicBool,
    cached_exit_status: Mutex<Option<BoundaryExitStatus>>,
}

#[tonic::async_trait]
impl BoundaryProcess for TestProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        if matches!(self.wait_behavior, WaitBehavior::Stall) {
            return std::future::pending().await;
        }
        let cached_status = *self.cached_exit_status.lock().expect("exit cache");
        if let Some(status) = cached_status {
            return Ok(status);
        }
        if self.terminal.load(Ordering::SeqCst) {
            return Err(BackendError::Denied("terminal session rejects Wait".into()));
        }
        if matches!(self.wait_behavior, WaitBehavior::Fail) {
            return Err(BackendError::Unavailable("status transport failed".into()));
        }
        let mut status = self.status.subscribe();
        loop {
            let observed_status = *status.borrow_and_update();
            if let Some(status) = observed_status {
                return Ok(status);
            }
            status
                .changed()
                .await
                .expect("fixture retains status owner");
        }
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        self.signals.lock().expect("signals").push(signal);
        if self.stall_signal {
            return std::future::pending().await;
        }
        // A held boundary acknowledges both TERM and KILL without delivering
        // either; only whole-boundary termination supplies a terminal status.
        if !self.held {
            self.status
                .send_replace(Some(BoundaryExitStatus::Exited(7)));
        }
        Ok(())
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.signal(BoundarySignal::Kill).await
    }
}

#[tonic::async_trait]
impl BoundaryExec for TestProcess {
    async fn exec(&self, _spec: ExecSpec) -> Result<ExecSession, BackendError> {
        Err(BackendError::Unsupported("fixture has no exec".into()))
    }
}

#[tonic::async_trait]
impl BoundaryLoopbackConnector for TestProcess {
    async fn connect(&self, _target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        Err(BackendError::Unsupported("fixture has no loopback".into()))
    }
}

enum TerminalResponse {
    Acknowledge,
    Fail,
    Stall,
}

struct TestBoundary {
    process: Arc<TestProcess>,
    terminal_requested: AtomicBool,
    terminal_response: TerminalResponse,
    publish_exit: bool,
}

impl TestBoundary {
    fn held() -> Self {
        Self {
            process: Arc::new(TestProcess {
                status: watch::channel(None).0,
                signals: Mutex::new(Vec::new()),
                held: true,
                wait_behavior: WaitBehavior::Observe,
                stall_signal: false,
                terminal: AtomicBool::new(false),
                cached_exit_status: Mutex::new(None),
            }),
            terminal_requested: AtomicBool::new(false),
            terminal_response: TerminalResponse::Acknowledge,
            publish_exit: true,
        }
    }
}

#[tonic::async_trait]
impl RunningBoundary for TestBoundary {
    fn agent(&self) -> Arc<dyn BoundaryProcess> {
        self.process.clone()
    }

    fn exec(&self) -> Arc<dyn BoundaryExec> {
        self.process.clone()
    }

    fn loopback_connector(&self) -> Arc<dyn BoundaryLoopbackConnector> {
        self.process.clone()
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.terminal_requested.store(true, Ordering::SeqCst);
        match self.terminal_response {
            TerminalResponse::Fail => {
                return Err(BackendError::Unavailable(
                    "terminal transport failed".into(),
                ));
            }
            TerminalResponse::Stall => return std::future::pending().await,
            TerminalResponse::Acknowledge => {}
        }
        if self.publish_exit && self.process.status.borrow().is_none() {
            self.process
                .status
                .send_replace(Some(BoundaryExitStatus::Signaled(9)));
        }
        // Model the real terminal acknowledgement: fresh remote waits are
        // revoked, while its main status is retained locally before success.
        self.process.terminal.store(true, Ordering::SeqCst);
        *self.process.cached_exit_status.lock().expect("exit cache") =
            *self.process.status.borrow();
        Ok(())
    }
}

#[tokio::test]
async fn shutdown_held_workload_reaches_terminal_teardown_without_release() {
    let boundary = TestBoundary::held();
    // Model an already-queued process kill, which must not break the hold.
    boundary.process.terminate().await.expect("queue kill");
    assert!(boundary.process.status.borrow().is_none());

    let code = tokio::time::timeout(
        Duration::from_secs(1),
        shutdown_boundary(&boundary, Duration::ZERO, Duration::from_secs(1)),
    )
    .await
    .expect("held signals must not prevent terminal teardown")
    .expect("whole-boundary shutdown");
    assert_eq!(code, 137);
    assert!(boundary.terminal_requested.load(Ordering::SeqCst));
    assert_eq!(
        *boundary.process.signals.lock().expect("signals"),
        [BoundarySignal::Kill, BoundarySignal::Term]
    );
}

#[tokio::test]
async fn shutdown_graceful_exit_keeps_status_and_terminates_boundary() {
    let mut boundary = TestBoundary::held();
    Arc::get_mut(&mut boundary.process)
        .expect("sole owner")
        .held = false;
    let code = tokio::time::timeout(
        Duration::from_secs(1),
        shutdown_boundary(&boundary, Duration::from_mins(1), Duration::from_secs(1)),
    )
    .await
    .expect("completed application must not wait out the grace period")
    .expect("graceful shutdown");
    assert_eq!(code, 7);
    assert!(boundary.terminal_requested.load(Ordering::SeqCst));
    assert_eq!(
        *boundary.process.signals.lock().expect("signals"),
        [BoundarySignal::Term]
    );
}

#[tokio::test]
async fn shutdown_wait_error_still_terminates_boundary() {
    let mut boundary = TestBoundary::held();
    Arc::get_mut(&mut boundary.process)
        .expect("sole owner")
        .wait_behavior = WaitBehavior::Fail;
    let error = shutdown_boundary(&boundary, Duration::from_secs(1), Duration::from_secs(1))
        .await
        .expect_err("status failure remains visible");
    assert!(error.to_string().contains("status transport failed"));
    assert!(boundary.terminal_requested.load(Ordering::SeqCst));
}

#[tokio::test]
async fn shutdown_terminal_acknowledgement_failure_is_reported() {
    let mut boundary = TestBoundary::held();
    Arc::get_mut(&mut boundary.process)
        .expect("sole owner")
        .held = false;
    boundary.terminal_response = TerminalResponse::Fail;
    let error = shutdown_boundary(&boundary, Duration::from_secs(1), Duration::from_secs(1))
        .await
        .expect_err("main exit cannot substitute for boundary acknowledgement");
    assert!(
        error
            .to_string()
            .contains("did not acknowledge terminal state")
    );
    assert!(error.to_string().contains("terminal transport failed"));
}

#[tokio::test]
async fn shutdown_stalled_term_delivery_still_terminates_boundary() {
    let mut boundary = TestBoundary::held();
    Arc::get_mut(&mut boundary.process)
        .expect("sole owner")
        .stall_signal = true;
    let code = tokio::time::timeout(
        Duration::from_secs(1),
        shutdown_boundary(&boundary, Duration::ZERO, Duration::from_secs(1)),
    )
    .await
    .expect("signal transport has a finite grace budget")
    .expect("terminal teardown bypasses stalled signal");
    assert_eq!(code, 137);
    assert!(boundary.terminal_requested.load(Ordering::SeqCst));
}

#[tokio::test]
async fn shutdown_terminal_acknowledgement_wait_is_bounded() {
    let mut boundary = TestBoundary::held();
    boundary.terminal_response = TerminalResponse::Stall;
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        shutdown_boundary(&boundary, Duration::ZERO, Duration::ZERO),
    )
    .await
    .expect("terminal acknowledgement has a finite request budget")
    .expect_err("unacknowledged teardown cannot succeed");
    assert!(
        error
            .to_string()
            .contains("terminal acknowledgement timed out")
    );
    assert!(boundary.terminal_requested.load(Ordering::SeqCst));
}

#[tokio::test]
async fn shutdown_final_process_status_wait_is_bounded() {
    let mut boundary = TestBoundary::held();
    // Deliberately violate the backend's retained-status contract to verify
    // that a stuck implementation cannot make supervisor shutdown unbounded.
    Arc::get_mut(&mut boundary.process)
        .expect("sole owner")
        .wait_behavior = WaitBehavior::Stall;
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        shutdown_boundary(&boundary, Duration::ZERO, Duration::ZERO),
    )
    .await
    .expect("acknowledgement must not make final status wait unbounded")
    .expect_err("missing exit status cannot succeed");
    assert!(
        error
            .to_string()
            .contains("exit status timed out after boundary termination")
    );
    assert!(boundary.terminal_requested.load(Ordering::SeqCst));
}

#[tokio::test]
async fn shutdown_cannot_query_status_after_terminal_without_retained_receipt() {
    let mut boundary = TestBoundary::held();
    boundary.publish_exit = false;
    let error = shutdown_boundary(&boundary, Duration::ZERO, Duration::from_secs(1))
        .await
        .expect_err("terminal authorization must reject a fresh uncached Wait");
    assert!(error.to_string().contains("terminal session rejects Wait"));
    assert!(boundary.terminal_requested.load(Ordering::SeqCst));
}
