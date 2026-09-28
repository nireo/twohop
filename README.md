# twohop

A Rust proof of concept for carrying WireGuard traffic through a QUIC entry
relay to an independently operated VPN exit, inspired by Obscura's two-party
design. Nothing really done at the moment

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
