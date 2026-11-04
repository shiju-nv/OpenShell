# Sandbox Policy Quickstart

See how OpenShell's network policy system works in under five minutes.
You'll create a sandbox, watch a request get blocked by the default-deny
policy, apply a fine-grained L7 rule, and verify that reads are allowed
while writes are blocked — all without restarting anything.

## Prerequisites

- A running OpenShell gateway with no global policy (`mise run gateway:docker` for local development)
- Docker daemon running
- A user-owned workload image with `curl` installed at `/usr/bin/curl` and no embedded OpenShell policy

## What's in this example

| File          | Description                                                          |
| ------------- | -------------------------------------------------------------------- |
| `policy.yaml` | Complete policy with the same rule, for `sandbox create --policy`    |

## Walkthrough

### 1. Create a sandbox

Replace `registry.example.com/team/agent-tools:1.0` with your workload image.

```shell
openshell sandbox create \
  --name demo \
  --from registry.example.com/team/agent-tools:1.0 \
  --no-auto-providers
```

`--no-auto-providers` skips the provider setup prompt since this
demo doesn't use an AI agent.

You'll land in an interactive shell inside the sandbox:

```text
sandbox@demo:~$
```

### 2. Try to reach the GitHub API — blocked

```shell
curl -sS https://api.github.com/zen
```

The command reports a connection error and exits with a nonzero status
because no network policy allows `curl` to reach `api.github.com:443`.

Keep this sandbox shell open for the rest of the walkthrough. Run the
following `openshell` commands in a second terminal on your host.

### 3. Check the deny log

```bash
openshell logs demo --since 5m --source sandbox
```

Look for a `NET:OPEN` entry showing `DENIED` for `/usr/bin/curl` to
`api.github.com:443`, with reason `transparent_tcp_policy_denied`.

### 4. Add a read-only GitHub API rule

```bash
openshell policy update demo \
  --rule-name github_api \
  --binary /usr/bin/curl \
  --add-endpoint api.github.com:443:read-only:rest:enforce \
  --wait
```

The endpoint specification lists the host, port, access preset, protocol,
and enforcement mode. **curl may make GET, HEAD, and OPTIONS requests to
`api.github.com` over HTTPS. Everything else is denied.** `rest` tells the
proxy to terminate TLS and inspect each HTTP request, `read-only` permits
`GET`, `HEAD`, and `OPTIONS`, and `enforce` blocks every other request.
`policy update` changes only the network rules and keeps the rest of the
sandbox's policy.

The command adds a rule equivalent to this YAML in the policy's
`network_policies` section:

```yaml
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/curl
```

`--wait` blocks until the sandbox reports a result for the new policy
revision. No restart required — network rules reload while the sandbox runs.

[`policy.yaml`](policy.yaml) contains the same rule in a complete policy. Use
it with `--policy examples/sandbox-policy-quickstart/policy.yaml` when
creating a new sandbox.
Do not apply it to a running sandbox with `openshell policy set`, which
replaces the entire policy and is rejected if the file drops a filesystem path
the sandbox already has.

### 5. Verify that GET works

Return to the sandbox shell in your first terminal and retry the request:

```bash
curl -s https://api.github.com/zen
```

```text
Anything added dilutes everything else.
```

It works. Try a more visual endpoint:

```bash
curl -s https://api.github.com/octocat
```

```text
               MMM.           .MMM
               MMMMMMMMMMMMMMMMMMM
               MMMMMMMMMMMMMMMMMMM      ____________________________
              MMMMMMMMMMMMMMMMMMMMM    |                            |
             MMMMMMMMMMMMMMMMMMMMMMM   | Speak like a human.       |
            MMMMMMMMMMMMMMMMMMMMMMMM   |_   ________________________|
            MMMM::- -:::::::- -::MMMM    |/
             MM~:~ 00~:::::~ 00~:~MM
        .. MMMMM::.00:::+:::.00teleMMM ..
              .MM::::: ._. :::::MM.
                 MMMM;:::::;MMMM
          -MM        MMMMMMM
          ^  M+     MMMMMMMMM
              MMMMMMM MM MM MM
                   MM MM MM MM
                   MM MM MM MM
                .~~MM~MM~MM~MM~~.
             ~~~~MM:~MM~~~MM~:MM~~~~
            ~~~~~~==googler======~~~~~~
             ~~~~~~==googler======
                 :MMMMMMMMMMM:
                 '=googler=='
```

### 6. Try a write — blocked by L7

In the same sandbox shell, send a POST request:

```bash
curl -s -X POST https://api.github.com/repos/octocat/hello-world/issues \
  -H "Content-Type: application/json" \
  -d '{"title":"oops"}'
```

The proxy returns a `403` response with a JSON body that includes fields
like these:

```text
{...,"error":"policy_denied",...,"policy":"github_api",...,"rule":"POST /repos/octocat/hello-world/issues",...}
```

The connection succeeds because `api.github.com` is allowed, but the L7
proxy inspects the HTTP method and returns `403`. `POST` is not in
the `read-only` preset. Your agent can read code from GitHub but cannot
create issues, push commits, or modify anything.

### 7. Check the L7 deny log

Run this in your second terminal on the host, leaving the sandbox shell open:

```bash
openshell logs demo --since 5m --source sandbox
```

```text
[1775014140.412] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST https://api.github.com/repos/octocat/hello-world/issues [policy:github_api engine:l7] [reason:L7_REQUEST deny POST api.github.com:443/repos/octocat/hello-world/issues reason=POST /repos/octocat/hello-world/issues not permitted by policy]
```

The log captures the exact HTTP method, path, and matching rule. Policy
events are INFO-level log records regardless of their severity, so do not
filter them out with `--level warn`. In production, export these events to
your SIEM for a complete audit trail of every request your agent makes.

### 8. Clean up

Delete the sandbox from your host terminal:

```bash
openshell sandbox delete demo
```

## What you just saw

| State              | What happens                                    |
| ------------------ | ----------------------------------------------- |
| **Default deny**   | All outbound traffic blocked — nothing gets out  |
| **L7 read-only**   | GET to `api.github.com` allowed, POST blocked    |
| **Audit trail**    | Every request logged with method, path, decision |

The policy hot-reloads in seconds and gives
you verifiable, fine-grained control over what your agent can access —
without `--dangerously-skip-permissions`.

## Next steps

- **Customize the policy**: Change `access: read-only` to `read-write`
  or add explicit `rules` for specific paths. See the
  [policy schema reference](../../docs/how-it-works/policies/schema.mdx).
- **Scope to an agent**: Replace the `binaries` section with your
  agent's binary (e.g., `/usr/local/bin/claude`) instead of `curl`.
- **Add more endpoints**: Stack multiple policies in the same file
  to allow PyPI, npm, or your internal APIs.
- **Try audit mode**: Set `enforcement: audit` to log violations
  without blocking, useful for building a policy iteratively.
