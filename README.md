# twohop

A Rust proof of concept that carries WireGuard traffic through a QUIC entry
relay to an independently operated VPN exit. Inspired by Obscura's two-party
design and still under development.

## How it works

```text
device → QUIC entry relay → WireGuard exit → internet
```

Your device encrypts traffic for the WireGuard exit and sends it to the entry
relay over QUIC. The relay forwards the encrypted packets to the exit over UDP.
Only the exit can remove the WireGuard encryption; HTTPS remains encrypted
between your device and the website.

The entry sees your connecting IP but cannot read the inner traffic. The exit
sees destinations and the entry's IP instead of your original IP.
