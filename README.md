# twohop

A Rust proof of concept for carrying WireGuard traffic through a QUIC entry
relay to an independently operated VPN exit, inspired by Obscura's two-party
design. The transport is still under development.

## How it works

```text
device → QUIC entry relay → WireGuard exit → internet
```

Your device encrypts traffic for the WireGuard exit, then sends those encrypted
packets to the entry relay using unreliable QUIC datagrams. The relay forwards
them over UDP. Only the exit can remove the WireGuard encryption; HTTPS remains
encrypted between your device and the website.

The entry sees your connecting IP but cannot read the inner traffic. The exit
sees destinations and the entry's IP instead of your original IP.

The [protocol document](docs/PROTOCOL.md) defines the control exchange and
packet forwarding rules.

## Development credentials

From the repository root, run `./scripts/dev/generate-credentials.sh` once. It
creates an ignored `local/` directory containing a test CA, a relay TLS
certificate and key for `relay.twohop.test`, and a random access token. The
script refuses to overwrite an existing `local/` directory. The paths in
`examples/client.toml` and `examples/relay.toml` assume commands are run from
the repository root.

Start the relay and client in separate terminals from the repository root:

```sh
cargo run -- relay --config examples/relay.toml
cargo run -- client --config examples/client.toml
```

The client forwards encrypted UDP payloads from its loopback listener through
the relay to the configured exit. The [native WireGuard demo](docs/MACOS_DEMO.md)
provides a dedicated Linux VM and split-tunnel Mac setup. Run the unprivileged loopback smoke test with
`cargo test --test transport`; it creates temporary credentials and uses
ephemeral ports.

## Reliable operation

The client retains its local UDP bind across relay outages and reconnects with
jittered exponential backoff, capped at 30 seconds. It discards local traffic
while connecting, authenticating, or waiting to retry. Authentication and TLS
identity failures exit with an error; relay overload is retryable.

The relay enforces the configured pending and active session caps, a single
setup deadline, and the transport idle timeout. Both commands handle Ctrl-C
and SIGTERM, close their sessions, and release sockets and tasks. The forwarding
path uses bounded QUIC buffers with no application packet queue.

Structured stderr logs report session lifecycle events and aggregate counters.
See [operations](docs/OPERATIONS.md) for limits, counter meanings, and failure
messages. Run the unprivileged lifecycle checks with:

```sh
cargo test --test lifecycle
```

They cover concurrent client isolation, hard and graceful relay restart,
capacity rejection, timeout/shutdown cleanup, connection churn, slow receivers,
and idle keepalive. Resource checks use `ps` and `lsof` on macOS, or `/proc` on
Linux. The suite uses temporary credentials and loopback UDP sockets; WireGuard
and elevated privileges are not required.

## Native WireGuard demo

With WireGuard CLI tools and Lima installed, prepare and verify the demo from
the repository root as your normal user:

```sh
./scripts/demo/demo.sh prepare
./scripts/demo/demo.sh verify
```

Verification needs interactive sudo for the Mac interface, routes, and packet
capture. It checks ping, DNS, HTTP, relay-restart recovery, and cleanup, leaving
results in ignored `local/demo/verification.txt`. See the
[runbook](docs/MACOS_DEMO.md) and [validation status](docs/M4_VALIDATION.md).
