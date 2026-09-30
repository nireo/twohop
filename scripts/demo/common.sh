#!/bin/sh
# Sourced by the host scripts; no side effects beyond locating the workspace.
set -eu
umask 077
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
repo_root=$(CDPATH='' cd "$script_dir/../.." && pwd)
# Used by the host scripts that source this file.
# shellcheck disable=SC2034
state="$repo_root/local/demo"
export LIMA_HOME="$repo_root/local/lima"
vm=twohop-demo

die() { echo "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || die "Required command missing: $1"; }
guest() { limactl shell "$vm" "$@"; }

# A stale PID file must never stop an unrelated process after PID reuse.
stop_process() {
    pid_file=$1
    expected=$2
    [ -f "$pid_file" ] || return 0
    pid=$(cat "$pid_file")
    case "$pid" in ''|*[!0-9]*) echo "Invalid PID file: $pid_file" >&2; return 1 ;; esac
    command=$(ps -p "$pid" -o command= 2>/dev/null || true)
    case "$command" in
        *"$expected"*)
            kill "$pid"
            remaining=10
            while kill -0 "$pid" 2>/dev/null && [ "$remaining" -gt 0 ]; do
                sleep 1
                remaining=$((remaining - 1))
            done
            if kill -0 "$pid" 2>/dev/null; then
                echo "Process $pid has not stopped; retaining $pid_file" >&2
                return 1
            fi
            ;;
        '') ;;
        *) echo "PID $pid belongs to another command; retaining $pid_file" >&2; return 1 ;;
    esac
    rm -f "$pid_file"
}
