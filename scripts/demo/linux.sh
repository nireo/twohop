#!/bin/sh
# Privileged topology only. The relay is launched separately as the guest user.
set -eu
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
repo_root=$(CDPATH='' cd "$script_dir/../.." && pwd)
runtime=/run/twohop-demo
keys=/var/lib/twohop-demo

die() { echo "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || die "This helper requires Linux."
[ "$(id -u)" -eq 0 ] || die "Run this helper with sudo."

stop_capture() {
    [ -f "$runtime/capture.pid" ] || return 0
    pid=$(cat "$runtime/capture.pid")
    command=$(ps -p "$pid" -o args= 2>/dev/null || true)
    case "$command" in
        *"tcpdump -U -n -i twh-entry"*) kill -INT "$pid" ;;
        '') ;;
        *) die "Capture PID belongs to another process." ;;
    esac
    # tcpdump flushes its pcap on SIGINT.
    sleep 1
    rm -f "$runtime/capture.pid"
}

down() {
    [ -d "$runtime" ] || return 0
    stop_capture
    for namespace in twohop-dest twohop-exit; do
        if [ -f "$runtime/$namespace" ]; then
            for pid in $(ip netns pids "$namespace"); do kill "$pid" 2>/dev/null || true; done
            ip netns del "$namespace"
            rm -f "$runtime/$namespace"
        fi
    done
    if [ -f "$runtime/entry-link" ]; then
        if ip link show twh-entry >/dev/null 2>&1; then ip link del twh-entry; fi
        rm -f "$runtime/entry-link"
    fi
    rm -rf "$runtime"
}

case "${1:-}" in
    key)
        mkdir -p "$keys"
        chmod 700 "$keys"
        if [ ! -f "$keys/exit.key" ]; then wg genkey > "$keys/exit.key"; fi
        wg pubkey < "$keys/exit.key"
        ;;
    up)
        [ ! -e "$runtime" ] || die "Demo is already set up; run down first."
        [ -f "$keys/exit.key" ] || die "Generate the exit key first."
        python3 "$script_dir/check-subnets.py"
        for namespace in twohop-exit twohop-dest; do
            [ ! -e "/run/netns/$namespace" ] || die "Namespace $namespace already exists."
        done
        for link in twh-entry twh-exit twh-lan twh-dest; do
            if ip link show "$link" >/dev/null 2>&1; then die "Interface $link already exists."; fi
        done
        mkdir "$runtime"
        trap 'down' EXIT
        trap 'exit 1' HUP INT TERM
        ip netns add twohop-exit
        touch "$runtime/twohop-exit"
        ip netns add twohop-dest
        touch "$runtime/twohop-dest"
        ip link add twh-entry type veth peer name twh-exit
        touch "$runtime/entry-link"
        ip link set twh-exit netns twohop-exit
        ip addr add 10.203.0.1/30 dev twh-entry
        ip link set twh-entry up
        ip -n twohop-exit addr add 10.203.0.2/30 dev twh-exit
        ip -n twohop-exit link set twh-exit up
        ip -n twohop-exit link set lo up
        ip -n twohop-dest link set lo up

        # Create the second pair inside the owned namespace so rollback owns both ends.
        ip -n twohop-exit link add twh-lan type veth peer name twh-dest
        ip -n twohop-exit link set twh-dest netns twohop-dest
        ip -n twohop-exit addr add 10.203.1.1/24 dev twh-lan
        ip -n twohop-exit link set twh-lan mtu 1000 up
        ip -n twohop-dest addr add 10.203.1.2/24 dev twh-dest
        ip -n twohop-dest link set twh-dest mtu 1000 up
        ip -n twohop-dest route add 10.203.2.2/32 via 10.203.1.1

        # The encrypted UDP socket belongs to the interface's birthplace namespace.
        ip -n twohop-exit link add wg0 type wireguard
        python3 - "$repo_root" "$keys" "$runtime" <<'PY'
from pathlib import Path
import sys
repo, keys, runtime = map(Path, sys.argv[1:])
config = (repo / "examples/wireguard/exit.conf.in").read_text()
config = config.replace("@EXIT_PRIVATE_KEY@", (keys / "exit.key").read_text().strip())
config = config.replace("@CLIENT_PUBLIC_KEY@", (repo / "client.pub").read_text().strip())
(runtime / "exit.conf").write_text(config)
PY
        ip netns exec twohop-exit wg setconf wg0 "$runtime/exit.conf"
        ip -n twohop-exit addr add 10.203.2.1/32 dev wg0
        ip -n twohop-exit link set wg0 mtu 1000 up
        ip -n twohop-exit route add 10.203.2.2/32 dev wg0
        ip netns exec twohop-exit sysctl -q -w net.ipv4.ip_forward=1

        mkdir "$runtime/www"
        dd if=/dev/zero of="$runtime/www/blob" bs=1024 count=1024 2>/dev/null
        # Only the controlled DNS answer is served; there is no external resolver.
        nohup ip netns exec twohop-dest dnsmasq --keep-in-foreground --no-resolv --no-hosts \
            --bind-interfaces --listen-address=10.203.1.2 \
            --address=/demo.twohop.test/10.203.1.2 --user=root --pid-file= \
            > "$runtime/dns.log" 2>&1 < /dev/null &
        nohup ip netns exec twohop-dest python3 -m http.server 8080 --bind 10.203.1.2 \
            --directory "$runtime/www" > "$runtime/http.log" 2>&1 < /dev/null &
        sleep 1
        ip netns exec twohop-dest ss -lnt | grep -q '10.203.1.2:8080'
        ip netns exec twohop-dest ss -lnu | grep -q '10.203.1.2:53'
        trap - EXIT HUP INT TERM
        echo "Linux demo topology ready."
        ;;
    down) down ;;
    capture-start)
        [ -d "$runtime" ] || die "Start the topology first."
        [ ! -e "$runtime/capture.pid" ] || die "Capture already started."
        tcpdump -U -n -i twh-entry -w "$runtime/wireguard.pcap" 'udp port 51820' \
            > "$runtime/capture.log" 2>&1 &
        echo "$!" > "$runtime/capture.pid"
        sleep 1
        kill -0 "$(cat "$runtime/capture.pid")"
        ;;
    capture-stop)
        stop_capture
        [ ! -f "$runtime/wireguard.pcap" ] || cat "$runtime/wireguard.pcap"
        ;;
    status) ip netns exec twohop-exit wg show wg0 ;;
    *) die "Usage: $0 key|up|down|capture-start|capture-stop|status" ;;
esac
