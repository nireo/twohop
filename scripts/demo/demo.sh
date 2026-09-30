#!/bin/sh
# One fixed, split-tunnel demo. Run as your normal macOS user.
# Remote shell snippets expand variables inside the guest, not on the host.
# shellcheck disable=SC2016
set -eu
. "$(dirname "$0")/common.sh"
cd "$repo_root"

usage() {
    echo "Usage: $0 prepare|verify|up|check|restart-check|capture-start|capture-stop|down|vm-stop"
}

load_prepared() {
    [ -f "$state/prepared" ] || die "Run $0 prepare first."
    guest_dir=$(cat "$state/guest-dir")
}

relay_start() {
    guest sh -eu -c '
        cd "$1"
        [ ! -f relay/relay.pid ] || { echo "Relay PID file exists; run down first." >&2; exit 1; }
        nohup "$1/target/release/twohop" relay --config "$1/relay/relay.toml" \
            >> relay/relay.log 2>&1 < /dev/null &
        echo "$!" > relay/relay.pid
        sleep 1
        kill -0 "$(cat relay/relay.pid)"
    ' sh "$guest_dir"
}

relay_stop() {
    guest sh -eu -c '
        . "$1/scripts/demo/common.sh"
        stop_process "$1/relay/relay.pid" "$1/target/release/twohop relay --config $1/relay/relay.toml"
    ' sh "$guest_dir"
}

down() {
    # Try every cleanup step even if one fails; retain state needed for a retry.
    failed=0
    stop_process "$state/client.pid" "$repo_root/target/release/twohop client --config $state/client.toml" || failed=1
    sudo "$script_dir/macos.sh" down || failed=1
    if [ -f "$state/prepared" ]; then
        load_prepared
        relay_stop || failed=1
        guest sudo "$guest_dir/scripts/demo/linux.sh" down || failed=1
    fi
    return "$failed"
}

case "${1:-}" in
    prepare)
        [ "$(uname -s)" = Darwin ] || die "The host demo requires macOS."
        [ "$(id -u)" -ne 0 ] || die "Run demo.sh as your normal user."
        for tool in limactl cargo wg wireguard-go openssl python3 curl tcpdump dig; do require "$tool"; done
        if [ -d "$state/macos/active" ] || [ -f "$state/client.pid" ]; then die "Run down before prepare."; fi
        python3 "$script_dir/check-subnets.py"
        mkdir -p "$state"
        mkdir "$state/prepare-active" || die "Preparation already running."
        trap 'rmdir "$state/prepare-active"' EXIT
        trap 'exit 1' HUP INT TERM
        mkdir -p "$LIMA_HOME"
        if [ ! -d "$LIMA_HOME/$vm" ]; then
            limactl create -y --name="$vm" --vm-type=vz --network=vzNAT \
                --cpus=2 --memory=2 --disk=10 --containerd=none --mount-none template:ubuntu-24.04
        fi
        limactl start -y "$vm"
        guest test ! -e /run/twohop-demo || die "Run down before preparing the live Linux topology."
        guest_dir=$(guest sh -c 'printf "%s/twohop-demo" "$HOME"')
        printf '%s\n' "$guest_dir" > "$state/guest-dir"
        guest mkdir -p "$guest_dir/relay"
        guest sudo apt-get update
        guest sudo apt-get install -y --no-install-recommends \
            wireguard-tools iproute2 iputils-ping dnsutils dnsmasq-base python3 tcpdump \
            build-essential pkg-config curl ca-certificates
        tar -czf "$state/source.tar.gz" Cargo.toml Cargo.lock src tests scripts/dev scripts/demo examples/wireguard
        limactl copy "$state/source.tar.gz" "$vm:$guest_dir/source.tar.gz"
        guest tar -xzf "$guest_dir/source.tar.gz" -C "$guest_dir"
        guest sh -eu -c '
            if [ ! -x "$HOME/.cargo/bin/cargo" ]; then
                curl --proto "=https" --tlsv1.2 -fsS https://sh.rustup.rs -o "$1/rustup-init.sh"
                sh "$1/rustup-init.sh" -y --profile minimal --default-toolchain 1.95.0 --no-modify-path
            fi
            cd "$1"
            "$HOME/.cargo/bin/cargo" build --release --locked
        ' sh "$guest_dir"
        cargo build --release --locked

        if [ ! -d "$state/tls" ]; then "$repo_root/scripts/dev/generate-credentials.sh" "$state/tls"; fi
        if [ ! -f "$state/client.key" ]; then wg genkey > "$state/client.key"; fi
        wg pubkey < "$state/client.key" > "$state/client.pub"
        guest sudo "$guest_dir/scripts/demo/linux.sh" key > "$state/exit.pub"
        limactl copy "$state/client.pub" "$vm:$guest_dir/client.pub"
        # Transfer only relay TLS credentials and the access token; no CA or WG private key.
        limactl copy "$state/tls/relay.pem" "$state/tls/relay-key.pem" "$state/tls/token" \
            "$repo_root/examples/wireguard/relay.toml" "$vm:$guest_dir/relay/"
        guest chmod 700 "$guest_dir/relay"
        guest chmod 600 "$guest_dir/relay/relay-key.pem" "$guest_dir/relay/token"
        # Lima calls the explicitly configured vzNAT interface lima0.
        guest ip -4 -o addr show dev lima0 | awk '{split($4,a,"/"); print a[1]}' > "$state/relay-ip"
        [ -s "$state/relay-ip" ] || die "No vzNAT IPv4 address found on lima0."
        python3 - "$repo_root" "$state" <<'PY'
from pathlib import Path
import ipaddress
import sys
repo, state = map(Path, sys.argv[1:])
relay_ip = str(ipaddress.IPv4Address((state / "relay-ip").read_text().strip()))
config = (repo / "examples/wireguard/mac.conf.in").read_text()
config = config.replace("@CLIENT_PRIVATE_KEY@", (state / "client.key").read_text().strip())
config = config.replace("@EXIT_PUBLIC_KEY@", (state / "exit.pub").read_text().strip())
(state / "mac.conf").write_text(config)
config = (repo / "examples/wireguard/client.toml.in").read_text().replace("@RELAY_IP@", relay_ip)
(state / "client.toml").write_text(config)
PY
        touch "$state/prepared"
        echo "Prepared. Relay address: $(cat "$state/relay-ip"):4433"
        ;;
    up)
        load_prepared
        [ ! -f "$state/client.pid" ] || die "Client PID file exists; run down first."
        # Authenticate before changing networking, so an unattended invocation fails early.
        sudo -v
        trap 'down' EXIT
        trap 'exit 1' HUP INT TERM
        guest sudo "$guest_dir/scripts/demo/linux.sh" up
        relay_start
        sudo "$script_dir/macos.sh" up
        nohup "$repo_root/target/release/twohop" client --config "$state/client.toml" \
            >> "$state/client.log" 2>&1 < /dev/null &
        echo "$!" > "$state/client.pid"
        sleep 1
        kill -0 "$(cat "$state/client.pid")"
        "$script_dir/smoke.sh"
        trap - EXIT HUP INT TERM
        ;;
    verify) load_prepared; "$script_dir/verify.sh" ;;
    check) load_prepared; "$script_dir/smoke.sh" ;;
    restart-check)
        load_prepared
        "$script_dir/smoke.sh"
        before=$(cat "$state/macos/interface")
        client_pid=$(cat "$state/client.pid")
        sudo -v
        relay_stop
        trap 'relay_start' EXIT
        trap 'exit 1' HUP INT TERM
        # A new request during the outage must fail while the WG interface stays up.
        if curl --noproxy '*' -fsS --connect-timeout 2 --max-time 3 \
            http://10.203.1.2:8080/blob -o /dev/null 2> "$state/outage.log"; then
            die "HTTP unexpectedly succeeded while the relay was stopped."
        fi
        ifconfig "$before" >/dev/null
        kill -0 "$client_pid"
        echo "HTTP stalled during the relay outage; WireGuard and the client stayed up."
        relay_start
        trap - EXIT HUP INT TERM
        "$script_dir/smoke.sh"
        [ "$(cat "$state/macos/interface")" = "$before" ]
        [ "$(cat "$state/client.pid")" = "$client_pid" ]
        echo "Relay restart recovered without replacing the Mac interface or client."
        ;;
    capture-start)
        load_prepared
        sudo -v
        guest sudo "$guest_dir/scripts/demo/linux.sh" capture-start
        if ! sudo "$script_dir/macos.sh" capture-start; then
            guest sudo "$guest_dir/scripts/demo/linux.sh" capture-stop > "$state/wireguard.pcap"
            exit 1
        fi
        ;;
    capture-stop)
        load_prepared
        sudo "$script_dir/macos.sh" capture-stop
        guest sudo "$guest_dir/scripts/demo/linux.sh" capture-stop > "$state/wireguard.pcap"
        echo "Captures: $state/macos/quic.pcap and $state/wireguard.pcap"
        ;;
    down) down ;;
    vm-stop)
        down
        limactl stop "$vm"
        ;;
    -h|--help|'') usage ;;
    *) usage >&2; exit 2 ;;
esac
