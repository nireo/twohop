#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"
[ -f "$state/macos/interface" ] || die "Start the demo first."
interface=$(cat "$state/macos/interface")

# Retry for up to 90 seconds: QUIC reconnect backoff and WG handshake retries
# both apply after a relay restart. Each HTTP request is independently bounded.
attempts=30
until curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 \
    http://10.203.1.2:8080/blob -o "$state/download" 2> "$state/http-error.log"; do
    attempts=$((attempts - 1))
    [ "$attempts" -gt 0 ] || die "HTTP did not recover; inspect $state/client.log and $state/http-error.log"
    sleep 1
done
python3 - "$state/download" <<'PY'
from pathlib import Path
import sys
if Path(sys.argv[1]).read_bytes() != bytes(1024 * 1024):
    sys.exit("HTTP payload differs from the expected 1 MiB fixture.")
PY
ping -n -c 3 -W 1000 10.203.2.1
ping -n -c 3 -W 1000 10.203.1.2
answer=$(dig +time=2 +tries=1 +short @10.203.1.2 demo.twohop.test A)
[ "$answer" = 10.203.1.2 ] || die "Unexpected DNS answer: $answer"
sudo wg show "$interface"
handshake=$(sudo wg show "$interface" latest-handshakes | awk '{print $2}')
if [ -z "$handshake" ] || [ "$handshake" -eq 0 ]; then die "No WireGuard handshake recorded."; fi
endpoint=$(guest sudo ip netns exec twohop-exit wg show wg0 endpoints | awk '{print $2}')
case "$endpoint" in 10.203.0.1:*) ;; *) die "Exit observed unexpected endpoint: $endpoint" ;; esac
# The guest relay user must not be able to read the exit's private key.
guest test ! -r /var/lib/twohop-demo/exit.key
echo "PASS: handshake, exit/destination ping, DNS, exact 1 MiB HTTP payload, and entry source address."
