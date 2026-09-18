# Rust end-to-end tests

## Docker host aliases

The Docker suite includes tests that reach host-side fixtures through `host.openshell.internal` and verify credential separation from `host.docker.internal`. For a gateway started by `e2e/with-docker-gateway.sh`, `OPENSHELL_E2E_HOST_GATEWAY_IP` supplies the Docker driver's trusted host address. A nonempty explicit value takes precedence over CI network discovery; when unset or empty, the existing discovery behavior remains. This variable does not reconfigure an external `OPENSHELL_GATEWAY_ENDPOINT`.

On macOS, use the container-reachable Docker host address; the gateway keeps its host-side callback on loopback. On Linux, the address must also be locally bindable by the gateway, such as the CI job container's address on the shared Docker network. The driver validates the IP literal before starting workloads. A hostname is not accepted, and an address that fails the controlled probe below must not be used.

From the repository root on macOS, discover and verify Docker's route using a locally cached image containing `python3`, then run the default suite. The commands use fish; the probe does not pull images or install packages.

```fish
set -l route_dir (mktemp -d)
set -gx OPENSHELL_E2E_HOST_GATEWAY_IP (uv run --no-project --offline python \
    e2e/rust/fixtures/configuration-composition/probe_upstream.py \
    --image public.ecr.aws/docker/library/python:3.13-slim \
    --output "$route_dir/host-route.json")
or exit $status
set -gx OPENSHELL_ACCEPTANCE_UPSTREAM_HOST "$OPENSHELL_E2E_HOST_GATEWAY_IP"
printf "Controlled host route evidence: %s\n" "$route_dir/host-route.json"
mise run --jobs 1 e2e
```

For an explicit host address, add `--host-ip` to the probe. Containerized CI retains automatic network selection unless the override is supplied. Keep the route JSON with the test output so alias configuration and upstream reachability can be checked together.

## Configuration activation and composition

The `policy_activation` and `configuration_composition_acceptance` targets exercise the CLI, gateway, separate control and boundary containers, and a real workload. They use synthetic credentials and controlled HTTP listeners in the test process. The tests verify rejection before launch, policy/provider repair, restrictive defaults, credential pairing, process restarts, and exactly one authorized workload start.

Run these targets through `e2e/with-docker-gateway.sh`. The Bash wrapper starts an isolated gateway and exports its Docker network; the commands inside it below use fish. Use the repository's existing Rust tooling, Docker, Python 3, uv and fish. The upstream probe requires a locally cached image containing `python3`; `--image` accepts either its local tag or immutable image ID. It inspects and uses the immutable ID and never pulls an image or installs packages.

From the repository root:

```fish
bash e2e/with-docker-gateway.sh fish -c '
    set -gx UV_OFFLINE 1
    set -gx UV_PYTHON_DOWNLOADS never
    set -l route_dir (mktemp -d)
    set -gx OPENSHELL_ACCEPTANCE_UPSTREAM_HOST (uv run --no-project --offline python \
        e2e/rust/fixtures/configuration-composition/probe_upstream.py \
        --image public.ecr.aws/docker/library/python:3.13-slim \
        --network "$OPENSHELL_E2E_NETWORK_NAME" \
        --output "$route_dir/host-route.json")
    or exit $status
    printf "Controlled upstream evidence: %s\n" "$route_dir/host-route.json"
    mise exec -- cargo test --manifest-path e2e/rust/Cargo.toml \
        --features e2e-docker \
        --test policy_activation \
        --test configuration_composition_acceptance \
        -- --nocapture --test-threads=1
'
```

The probe starts a short-lived local listener and an owned temporary container. It resolves Docker's host route, requires an exact synthetic request and response, records the actual IPv4 address and image identity, and removes only its own container. When the test process runs inside a Docker container, `--network` lets it discover that container's address on the shared network. For another execution environment, `--host-ip` can specify the test process's reachable IPv4 address; the same round-trip check still applies.

`OPENSHELL_ACCEPTANCE_UPSTREAM_HOST` is required for these two targets. Every rendered policy/provider endpoint and workload request uses the proven literal IPv4 address. Reserved host aliases have separate DNS trust requirements and are not used as arbitrary upstream fixture names. Keep the route JSON with the test output; a failed probe stops execution before these tests start.

For one scenario, keep its corresponding `--test` target and add its exact Rust test name before `--`, followed by `--exact --nocapture --test-threads=1`. The composition target also contains host-side controls for detecting admission-time egress and bounding cleanup; those controls do not require the gateway or the upstream environment variable.
