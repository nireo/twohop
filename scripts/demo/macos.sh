#!/bin/sh
# Privileged interface/route helper; Twohop itself runs as the invoking user.
set -eu
umask 077
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
. "$(dirname "$0")/common.sh"
mac="$state/macos"
[ "$(uname -s)" = Darwin ] || die "This helper requires macOS."
[ "$(id -u)" -eq 0 ] || die "Run this helper with sudo."

stop_capture() {
    [ -f "$mac/capture.pid" ] || return 0
    pid=$(cat "$mac/capture.pid")
    command=$(ps -p "$pid" -o command= 2>/dev/null || true)
    case "$command" in
        *"tcpdump -U -n -i "*"$mac/quic.pcap"*) kill -INT "$pid" ;;
        '') ;;
        *) die "Capture PID belongs to another process." ;;
    esac
    sleep 1
    rm -f "$mac/capture.pid"
}

down() {
    [ -d "$mac" ] || return 0
    stop_capture
    if [ -f "$mac/interface" ]; then
        interface=$(cat "$mac/interface")
        case "$interface" in utun[0-9]*) ;; *) die "Invalid tracked interface." ;; esac
        for destination in 10.203.1.0/24 10.203.2.1; do
            actual=$(route -n get "$destination" 2>/dev/null | awk '/interface:/{print $2}')
            if [ "$actual" = "$interface" ]; then
                route -n delete -inet "$destination" -interface "$interface"
            fi
        done
    fi
    stop_process "$mac/wireguard.pid" "wireguard-go -f utun"
    # Keep logs and captures readable by the invoking user after privileged setup.
    if [ -n "${SUDO_UID:-}" ]; then chown -R "$SUDO_UID:${SUDO_GID:-0}" "$mac"; fi
    rm -f "$mac/interface"
    rmdir "$mac/active"
}

case "${1:-}" in
    up)
        require wg; require wireguard-go; require python3
        [ -f "$state/mac.conf" ] || die "Run demo.sh prepare first."
        [ ! -e "$mac/active" ] || die "Demo interface already exists; run down first."
        python3 "$script_dir/check-subnets.py"
        if lsof -nP -iUDP:51820 -iUDP:51821 >/dev/null 2>&1; then
            die "UDP port 51820 or 51821 is already in use."
        fi
        mkdir -p "$mac"
        mkdir "$mac/active"
        trap 'down' EXIT
        trap 'exit 1' HUP INT TERM
        nohup env WG_TUN_NAME_FILE="$mac/interface" wireguard-go -f utun \
            > "$mac/wireguard.log" 2>&1 &
        echo "$!" > "$mac/wireguard.pid"
        attempts=50
        while :; do
            kill -0 "$(cat "$mac/wireguard.pid")"
            if [ -s "$mac/interface" ] && wg show "$(cat "$mac/interface")" >/dev/null 2>&1; then break; fi
            attempts=$((attempts - 1))
            [ "$attempts" -gt 0 ] || die "WireGuard did not create an interface."
            sleep 0.1
        done
        interface=$(cat "$mac/interface")
        wg setconf "$interface" "$state/mac.conf"
        ifconfig "$interface" inet 10.203.2.2/32 10.203.2.2 alias
        ifconfig "$interface" mtu 1000 up
        route -n add -inet 10.203.1.0/24 -interface "$interface"
        route -n add -inet 10.203.2.1 -interface "$interface"
        if [ -n "${SUDO_UID:-}" ]; then chown -R "$SUDO_UID:${SUDO_GID:-0}" "$mac"; fi
        trap - EXIT HUP INT TERM
        echo "Mac WireGuard interface ready: $interface"
        ;;
    down)
        [ ! -d "$mac/active" ] || down
        ;;
    status) wg show "$(cat "$mac/interface")" ;;
    capture-start)
        [ -d "$mac/active" ] || die "Start the Mac interface first."
        [ ! -e "$mac/capture.pid" ] || die "Capture already started."
        relay_ip=$(cat "$state/relay-ip")
        interface=$(route -n get "$relay_ip" | awk '/interface:/{print $2}')
        [ -n "$interface" ] || die "Cannot find the relay's route."
        tcpdump -U -n -i "$interface" -w "$mac/quic.pcap" "host $relay_ip and udp port 4433" \
            > "$mac/capture.log" 2>&1 &
        echo "$!" > "$mac/capture.pid"
        sleep 1
        kill -0 "$(cat "$mac/capture.pid")"
        ;;
    capture-stop)
        stop_capture
        chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$mac/quic.pcap"
        ;;
    *) die "Usage: $0 up|down|status|capture-start|capture-stop" ;;
esac
