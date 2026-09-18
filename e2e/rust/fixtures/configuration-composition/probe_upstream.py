# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove an explicit Docker host IPv4 endpoint reaches a controlled local listener."""

import argparse
import http.server
import ipaddress
import json
import re
import socket
import subprocess
import threading
import uuid
from pathlib import Path


def eligible_ipv4(value):
    """Reject destinations that cannot be explicit controlled policy endpoints."""
    address = ipaddress.IPv4Address(value)
    if any(
        (
            address.is_loopback,
            address.is_link_local,
            address.is_unspecified,
            address.is_multicast,
            address.is_reserved,
        )
    ):
        raise ValueError(f"Not an eligible controlled upstream IPv4 address: {address}")
    return str(address)


def route_target(network, host_ip):
    """Use the test container's shared-network IP or Docker's native host route."""
    if host_ip is not None:
        return eligible_ipv4(host_ip)
    if network and Path("/.dockerenv").is_file():
        # The listener runs inside the CI job container, not on the daemon host.
        # The wrapper connects that container to its dedicated sandbox network.
        inspected = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .NetworkSettings.Networks}}",
                socket.gethostname(),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        networks = json.loads(inspected.stdout)
        if network not in networks:
            raise RuntimeError(
                "Test container must join the probe network; alternatively supply --host-ip"
            )
        return eligible_ipv4(networks[network]["IPAddress"])
    return "host-gateway"


def probe(image, output, *, network=None, host_ip=None):
    """Discover and test the route without changing gateway or DNS trust policy."""
    if output.exists():
        raise RuntimeError("Preserve previous upstream probe evidence")
    inspected = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    image_id = inspected.stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise RuntimeError("Expected one immutable locally cached probe image")
    host_route = route_target(network, host_ip)
    nonce = uuid.uuid4().hex
    name = f"openshell-acceptance-upstream-{nonce[:12]}"
    observations = []

    class Handler(http.server.BaseHTTPRequestHandler):
        """Record only this probe's synthetic request and return its nonce."""

        def do_GET(self):
            observations.append({"path": self.path, "client": self.client_address[0]})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(nonce.encode())

        def log_message(self, _format, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    script = """import http.client,json,socket,sys
addresses=sorted({item[4][0] for item in socket.getaddrinfo('acceptance-host',None,socket.AF_INET)})
assert len(addresses)==1, addresses
connection=http.client.HTTPConnection(addresses[0],int(sys.argv[1]),timeout=5)
connection.request('GET','/acceptance-probe/'+sys.argv[2])
response=connection.getresponse()
body=response.read().decode()
print(json.dumps({'host_ipv4':addresses[0],'status':response.status,'body':body}))
assert response.status==200 and body==sys.argv[2]
"""
    command = [
        "docker",
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        name,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--add-host",
        f"acceptance-host:{host_route}",
        *(["--network", network] if network else []),
        "--entrypoint",
        "python3",
        image_id,
        "-c",
        script,
        str(server.server_port),
        nonce,
    ]
    result = {
        "argv": command,
        "image": image_id,
        "image_reference": image,
        "network": network,
        "host_route": host_route,
        "listener_port": server.server_port,
        "container_name": name,
        "passed": False,
    }
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=30, check=False
        )
        result.update(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"Controlled upstream route probe failed: {completed.stderr}"
            )
        observed = json.loads(completed.stdout)
        address = eligible_ipv4(observed["host_ipv4"])
        if (
            observed["status"] != 200
            or observed["body"] != nonce
            or len(observations) != 1
        ):
            raise RuntimeError("Controlled upstream request/response evidence differs")
        if observations[0]["path"] != f"/acceptance-probe/{nonce}":
            raise RuntimeError("Unexpected request reached controlled listener")
        result.update(passed=True, response=observed, host_ipv4=str(address))
        return str(address)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        cleanup = subprocess.run(
            ["docker", "rm", "--force", name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        result.update(
            upstream_requests=observations,
            cleanup={
                "exit_code": cleanup.returncode,
                "stdout": cleanup.stdout,
                "stderr": cleanup.stderr,
            },
        )
        output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--network", help="Docker network shared with the test process")
    parser.add_argument("--host-ip", help="Explicit reachable IPv4 of the test process")
    arguments = parser.parse_args()
    print(
        probe(
            arguments.image,
            arguments.output,
            network=arguments.network,
            host_ip=arguments.host_ip,
        )
    )
