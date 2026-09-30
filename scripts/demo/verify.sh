#!/bin/sh
# An interactive native-Mac run, including capture, restart, and cleanup evidence.
# Remote shell snippets expand variables inside the guest.
# shellcheck disable=SC2016
set -eu
. "$(dirname "$0")/common.sh"
[ ! -d "$state/macos/active" ] || die "Run down before verify."
sudo -v

default_route() { route -n get default | awk '/gateway:|interface:/{print}'; }
default_route > "$state/default-route.before"
scutil --dns > "$state/dns.before"
netstat -rn -f inet > "$state/routes.before"
report="$state/verification.txt"
echo "Running native checks; output is written to $report"
exec 3>&1
exec > "$report" 2>&1
echo "Native macOS WireGuard demo: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
sw_vers
uname -m
cargo --version
wg --version
limactl --version
guest uname -srmo
guest sh -c '"$HOME/.cargo/bin/rustc" --version; wg --version'
git -C "$repo_root" rev-parse HEAD
git -C "$repo_root" status --short
echo "Command: ./scripts/demo/demo.sh verify"

cleanup() {
    result=$?
    "$script_dir/demo.sh" down
    echo "Verification exited with status $result; inspect $report" >&3
}
trap 'cleanup' EXIT
trap 'exit 1' HUP INT TERM
"$script_dir/demo.sh" up
tracked_interface=$(cat "$state/macos/interface")
"$script_dir/demo.sh" capture-start
"$script_dir/demo.sh" check
"$script_dir/demo.sh" restart-check
"$script_dir/demo.sh" capture-stop
tcpdump -n -r "$state/macos/quic.pcap" -c 6 'udp port 4433'
tcpdump -n -r "$state/wireguard.pcap" -c 6 'udp port 51820'
for capture in "$state/macos/quic.pcap" "$state/wireguard.pcap"; do
    [ "$(wc -c < "$capture")" -gt 24 ] || die "Empty capture: $capture"
done
"$script_dir/demo.sh" down
trap - EXIT HUP INT TERM
default_route > "$state/default-route.after"
scutil --dns > "$state/dns.after"
netstat -rn -f inet > "$state/routes.after"
diff -u "$state/default-route.before" "$state/default-route.after"
diff -u "$state/dns.before" "$state/dns.after"
if ifconfig "$tracked_interface" >/dev/null 2>&1; then die "Demo interface remains after cleanup."; fi
python3 "$script_dir/check-subnets.py"
guest test ! -e /run/twohop-demo
guest test ! -e /run/netns/twohop-exit
guest test ! -e /run/netns/twohop-dest
guest sh -c '! ip link show twh-entry >/dev/null 2>&1'
echo "PASS: native Mac demo, relay restart, populated captures, and cleanup."
echo "PASS. Results: $report" >&3
