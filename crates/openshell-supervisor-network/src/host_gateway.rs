// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pin the host alias supplied by the driver to the trusted supervisor.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use miette::{IntoDiagnostic as _, Result, WrapErr as _};

const HOST_ALIAS: &str = "host.openshell.internal";
const CLOUD_METADATA_ADDRESS: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const CLOUD_METADATA_ADDRESS_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);

/// Retain a backend pin or discover it in the supervisor's own hosts file.
///
/// This runs before networking starts and never consults workload files or
/// DNS. The same result must feed DNS mappings and TCP destination checks.
/// Missing mappings stay unavailable; unsafe or ambiguous mappings fail closed.
///
/// # Errors
///
/// Returns an error if local discovery cannot read or safely select the mapping.
pub fn resolve(backend_address: Option<IpAddr>) -> Result<Option<IpAddr>> {
    resolve_from_hosts(backend_address, Path::new("/etc/hosts"))
}

fn resolve_from_hosts(backend_address: Option<IpAddr>, path: &Path) -> Result<Option<IpAddr>> {
    if backend_address.is_some() {
        // The authenticated backend's explicit address is authoritative. Do
        // not let an absent or conflicting local file replace that identity.
        return Ok(backend_address);
    }
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .into_diagnostic()
                .wrap_err("read supervisor host-gateway mapping");
        }
    };
    select_address(&contents)
}

fn select_address(contents: &str) -> Result<Option<IpAddr>> {
    let mut ipv4 = None;
    let mut ipv6 = None;
    for line in contents.lines() {
        let mut fields = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let Some(raw_address) = fields.next() else {
            continue;
        };
        if !fields.any(|alias| alias.trim_end_matches('.').eq_ignore_ascii_case(HOST_ALIAS)) {
            continue;
        }
        let address = raw_address
            .parse::<IpAddr>()
            .into_diagnostic()
            .wrap_err("supervisor host-gateway alias has an invalid address")?;
        // Normalize mapped addresses before both safety checks and duplicate
        // detection; their IPv4 target must not gain a second interpretation.
        let address = match address {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, IpAddr::V4),
            IpAddr::V4(_) => address,
        };
        if address.is_loopback()
            || address.is_unspecified()
            || address.is_multicast()
            || address == IpAddr::V6(CLOUD_METADATA_ADDRESS_V6)
            || matches!(address, IpAddr::V4(ip) if ip == CLOUD_METADATA_ADDRESS || ip.octets()[0] == 0 || ip.octets()[0] >= 240)
        {
            return Err(miette::miette!(
                "supervisor host-gateway alias has an unsafe address"
            ));
        }
        match address {
            IpAddr::V4(ip) => {
                if ipv4.is_some_and(|previous| previous != ip) {
                    return Err(miette::miette!(
                        "supervisor host-gateway alias has ambiguous IPv4 addresses"
                    ));
                }
                ipv4 = Some(ip);
            }
            IpAddr::V6(ip) => {
                if ipv6.is_some_and(|previous| previous != ip) {
                    return Err(miette::miette!(
                        "supervisor host-gateway alias has ambiguous IPv6 addresses"
                    ));
                }
                ipv6 = Some(ip);
            }
        }
    }
    // Docker can inject one address per family. Prefer IPv4 deterministically
    // rather than hosts-file order, while rejecting conflicts in either family.
    // This pin authorizes only the reserved alias, not the separate link-local
    // SSRF exemption or any destination omitted from the active policy.
    Ok(ipv4.map(IpAddr::V4).or_else(|| ipv6.map(IpAddr::V6)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_activation_host_gateway_backend_pin_is_authoritative() {
        let directory = tempfile::tempdir().unwrap();
        let pin = "192.168.65.254".parse().unwrap();
        // Reading a directory would fail. An explicit backend pin must not
        // read local hosts at all, including when the local mapping is broken.
        assert_eq!(
            resolve_from_hosts(Some(pin), directory.path()).unwrap(),
            Some(pin)
        );
    }

    #[test]
    fn configuration_activation_host_gateway_reads_trusted_hosts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hosts");
        std::fs::write(&path, "192.168.65.254 host.openshell.internal\n").unwrap();
        let pin = resolve_from_hosts(None, &path).unwrap();
        assert_eq!(pin, Some("192.168.65.254".parse().unwrap()));
    }

    #[test]
    fn configuration_activation_host_gateway_dual_stack_is_order_independent() {
        for hosts in [
            "192.168.65.254 host.openshell.internal\nfd00::254 host.openshell.internal\n",
            "fd00::254 host.openshell.internal\n192.168.65.254 host.openshell.internal\n",
        ] {
            assert_eq!(
                select_address(hosts).unwrap(),
                Some("192.168.65.254".parse().unwrap())
            );
        }
        assert_eq!(
            select_address("fd00::254 host.openshell.internal\n").unwrap(),
            Some("fd00::254".parse().unwrap())
        );
    }

    #[test]
    fn configuration_activation_host_gateway_parses_aliases_and_canonical_duplicates() {
        let hosts = "# 127.0.0.1 host.openshell.internal\n\
            127.0.0.1 localhost\n\
            192.168.65.254 another HOST.OPENSHELL.INTERNAL. # driver alias\n\
            ::ffff:192.168.65.254 host.openshell.internal\n";
        assert_eq!(
            select_address(hosts).unwrap(),
            Some("192.168.65.254".parse().unwrap())
        );
    }

    #[test]
    fn configuration_activation_host_gateway_missing_alias_remains_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_from_hosts(None, &directory.path().join("absent")).unwrap(),
            None
        );
        assert_eq!(
            select_address("127.0.0.1 localhost\n192.168.65.254 host.openshell.internal.example\n")
                .unwrap(),
            None
        );
    }

    #[test]
    fn configuration_activation_host_gateway_rejects_ambiguous_families() {
        for hosts in [
            "192.168.65.253 host.openshell.internal\n192.168.65.254 host.openshell.internal\n",
            "fd00::253 host.openshell.internal\nfd00::254 host.openshell.internal\n",
            "192.168.65.254 host.openshell.internal\nfd00::253 host.openshell.internal\nfd00::254 host.openshell.internal\n",
        ] {
            assert!(
                select_address(hosts)
                    .unwrap_err()
                    .to_string()
                    .contains("ambiguous")
            );
        }
    }

    #[test]
    fn configuration_activation_host_gateway_rejects_unsafe_and_mapped_addresses() {
        for address in [
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "fd00:ec2::254",
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "::",
            "::ffff:0.0.0.0",
            "224.0.0.1",
            "ff02::1",
            "::ffff:224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
        ] {
            let hosts = format!(
                "192.168.65.254 host.openshell.internal\n{address} host.openshell.internal\n"
            );
            assert!(
                select_address(&hosts)
                    .unwrap_err()
                    .to_string()
                    .contains("unsafe"),
                "{address}"
            );
        }
    }

    #[test]
    fn configuration_activation_host_gateway_rejects_invalid_or_unreadable_mapping() {
        assert!(
            select_address("invalid host.openshell.internal\n")
                .unwrap_err()
                .to_string()
                .contains("invalid address")
        );
        let directory = tempfile::tempdir().unwrap();
        assert!(resolve_from_hosts(None, directory.path()).is_err());
    }
}
