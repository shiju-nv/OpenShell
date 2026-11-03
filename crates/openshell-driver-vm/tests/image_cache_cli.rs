// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn cache_commands_refuse_state_owned_by_another_user() {
    use std::os::unix::fs::MetadataExt as _;

    let root = std::path::Path::new("/");
    if std::fs::metadata(root).unwrap().uid() == nix::unistd::geteuid().as_raw() {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_openshell-driver-vm"))
        .args(["--state-dir", "/", "image-cache", "list"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("image-cache must run as state directory owner UID"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cache_commands_require_an_existing_explicit_state_dir() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing-state");
    let binary = env!("CARGO_BIN_EXE_openshell-driver-vm");

    let without_state_dir = Command::new(binary)
        .env_remove("OPENSHELL_VM_DRIVER_STATE_DIR")
        .current_dir(temp.path())
        .args(["image-cache", "list"])
        .output()
        .unwrap();
    assert!(!without_state_dir.status.success());
    assert!(!temp.path().join("target/openshell-vm-driver").exists());

    let missing_state_dir = Command::new(binary)
        .env_remove("OPENSHELL_VM_DRIVER_STATE_DIR")
        .arg("--state-dir")
        .arg(&missing)
        .args(["image-cache", "prune", "--unused", "--dry-run"])
        .output()
        .unwrap();
    assert!(!missing_state_dir.status.success());
    assert!(!missing.exists());

    let existing = temp.path().join("existing-state");
    std::fs::create_dir(&existing).unwrap();
    let valid_list = Command::new(binary)
        .env_remove("OPENSHELL_VM_DRIVER_STATE_DIR")
        .arg("--state-dir")
        .arg(&existing)
        .args(["image-cache", "list"])
        .output()
        .unwrap();
    assert!(
        valid_list.status.success(),
        "{}",
        String::from_utf8_lossy(&valid_list.stderr)
    );
    assert!(String::from_utf8_lossy(&valid_list.stdout).starts_with("ENTRY	IMAGE	"));
}
