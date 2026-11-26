// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod common;

#[test]
fn policy_lint_warns_for_statically_blocked_control_plane_ports() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policy.yaml");
    std::fs::write(
        &file,
        r#"
version: 1
network_policies:
  cluster-api:
    endpoints:
      - {host: api.cluster.example, port: 6443, protocol: tcp}
  node:
    endpoints:
      - {host: node.cluster.example, ports: [443, 10250, 2379, 10250]}
      - {host: '2001:db8::1', port: 6443}
  restricted:
    endpoints:
      - {host: '*.restricted.example', port: 2380, allowed_ips: [10.0.0.0/24]}
  hostless:
    endpoints:
      - {port: 10255, allowed_ips: [10.1.0.0/24]}
  ordinary:
    endpoints:
      - {host: web.example, port: 443}
      - {host: '*.public.example', port: 6443}
      - {host: 'bad name.example', port: 6443}
      - {host: '[2001:db8::1]', port: 6443}
      - {host: '*.invalid.example', port: 6443, allowed_ips: [not-an-ip]}
      - {host: '*.loopback.example', port: 6443, allowed_ips: [127.0.0.1]}
  special:
    endpoints:
      - {host: HOST.DOCKER.INTERNAL, port: 6443}
      - {host: policy.local, port: 6443}
      - {host: 198.18.0.1, port: 6443}
      - {host: '::ffff:198.18.0.1', port: 6443}
"#,
    )
    .unwrap();

    let output = common::run_isolated(&["policy", "lint", file.to_str().unwrap()]);
    assert_eq!(output.code, 0, "{}", output.combined);
    assert!(output.stdout.contains("Policy is valid (offline)"));
    assert!(!output.stdout.contains("blocked control-plane port"));
    let warnings: Vec<_> = output
        .combined
        .lines()
        .filter(|line| line.contains("blocked control-plane port"))
        .collect();
    assert_eq!(
        warnings,
        [
            r#"Warning: network policy "cluster-api" endpoint[0] ("api.cluster.example") lists blocked control-plane port 6443 for TCP egress"#,
            r#"Warning: network policy "hostless" endpoint[0] ("<any-host>") lists blocked control-plane port 10255 for TCP egress"#,
            r#"Warning: network policy "node" endpoint[0] ("node.cluster.example") lists blocked control-plane port 2379 for TCP egress"#,
            r#"Warning: network policy "node" endpoint[0] ("node.cluster.example") lists blocked control-plane port 10250 for TCP egress"#,
            r#"Warning: network policy "node" endpoint[1] ("2001:db8::1") lists blocked control-plane port 6443 for TCP egress"#,
            r#"Warning: network policy "restricted" endpoint[0] ("*.restricted.example") lists blocked control-plane port 2380 for TCP egress"#,
        ]
    );
}

#[test]
fn policy_lint_runs_offline_and_reports_file_errors() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policy.yaml");
    let path = file.to_str().unwrap();
    let cases = [
        (
            "version: 1\n",
            true,
            vec!["Policy is valid (offline)", "Gateway checks"],
        ),
        ("process: {}\n", false, vec!["version"]),
        ("version: 1\nunknown: true\n", false, vec!["unknown"]),
        (
            "version: 1\nprocess:\n  run_as_user: '0'\n  run_as_group: root\nfilesystem_policy:\n  read_write: [relative, /]\n",
            false,
            vec![
                "run_as_user",
                "run_as_group",
                "path must be absolute",
                "overly broad",
            ],
        ),
        (
            "version: 1\nnetwork_policies:\n  _provider_private:\n    endpoints: []\n",
            false,
            vec!["reserved '_provider_'", "--base"],
        ),
        (
            "version: 1\nnetwork_policies:\n  bound:\n    endpoints:\n      - host: example.com\n        port: 443\n        credential_binding: {provider: ' '}\n",
            false,
            vec!["credential_binding.provider"],
        ),
        (
            "version: 1\nprocess:\n  run_as_user: '0'\nnetwork_middlewares:\n  redact:\n    middleware: openshell/regex\n    order: 1\n    endpoints: {include: [example.com]}\n    config: {mode: allow}\n",
            false,
            vec!["mode: redact", "run_as_user"],
        ),
        (
            "version: 1\nnetwork_policies:\n  conflict:\n    endpoints:\n      - {host: example.com, port: 6443}\n      - {host: example.com, port: 6443, tls: skip}\n",
            false,
            vec!["overlap", "conflicting"],
        ),
    ];
    for (yaml, valid, messages) in cases {
        std::fs::write(&file, yaml).unwrap();
        for args in [
            vec!["policy", "lint", path],
            vec![
                "--gateway-endpoint",
                "http://127.0.0.1:1",
                "policy",
                "lint",
                path,
            ],
        ] {
            let output = common::run_isolated(&args);
            assert_eq!(output.code == 0, valid, "{yaml}\n{}", output.combined);
            assert!(
                !output.combined.contains("blocked control-plane port"),
                "{}",
                output.combined
            );
            assert!(
                !output.combined.contains("failed to connect"),
                "{}",
                output.combined
            );
            for message in &messages {
                assert!(
                    output.combined.contains(message),
                    "expected {message}: {}",
                    output.combined
                );
            }
        }
    }
    std::fs::write(
        &file,
        format!(
            "version: 1\nnetwork_policies:\n  large:\n    name: {}\n    endpoints:\n{}",
            "x".repeat(openshell_policy::MAX_AUTHORED_POLICY_SIZE),
            "      - {host: example.com, port: 443, tls: skip}\n      - {host: example.com, port: 443}\n".repeat(128)
        ),
    )
    .unwrap();
    let oversized = common::run_isolated(&["policy", "lint", path]);
    assert_ne!(oversized.code, 0);
    assert!(
        oversized
            .combined
            .contains("policy serialized size exceeds maximum"),
        "{}",
        oversized.combined
    );
    assert!(
        !oversized.combined.contains("overlap"),
        "oversized files must be rejected before collecting endpoint pairs: {}",
        oversized.combined
    );
    let missing = dir.path().join("missing.yaml");
    assert_ne!(
        common::run_isolated(&["policy", "lint", missing.to_str().unwrap()]).code,
        0
    );
}
