#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
repo_root=$(CDPATH= cd "$script_dir/../.." && pwd)
if [ "$#" -gt 1 ]; then
    echo "Usage: $0 [OUTPUT_DIR]" >&2
    exit 2
fi
output_dir="${1:-$repo_root/local}"

if [ -e "$output_dir" ] || [ -L "$output_dir" ]; then
    echo "Refusing to overwrite $output_dir" >&2
    exit 1
fi

stage_dir=$(mktemp -d "${TMPDIR:-/tmp}/twohop-credentials.XXXXXXXX")
trap 'rm -rf "$stage_dir"' EXIT
trap 'exit 1' HUP INT TERM

openssl ecparam -name prime256v1 -genkey -noout -out "$stage_dir/ca-key.pem"
openssl req -new -x509 -sha256 -days 3650 \
    -key "$stage_dir/ca-key.pem" \
    -out "$stage_dir/ca.pem" \
    -config "$script_dir/ca.cnf" \
    -extensions v3_ca

openssl ecparam -name prime256v1 -genkey -noout -out "$stage_dir/relay-key.pem"
openssl req -new -sha256 \
    -key "$stage_dir/relay-key.pem" \
    -out "$stage_dir/relay.csr" \
    -config "$script_dir/relay.cnf"
openssl x509 -req -sha256 -days 365 \
    -in "$stage_dir/relay.csr" \
    -CA "$stage_dir/ca.pem" \
    -CAkey "$stage_dir/ca-key.pem" \
    -CAcreateserial \
    -out "$stage_dir/relay.pem" \
    -extfile "$script_dir/relay.cnf" \
    -extensions v3_server

openssl rand -hex 32 > "$stage_dir/token"
openssl verify -purpose sslserver -verify_hostname relay.twohop.test \
    -CAfile "$stage_dir/ca.pem" "$stage_dir/relay.pem"

rm -f "$stage_dir/relay.csr" "$stage_dir/ca.srl"

if [ -e "$output_dir" ] || [ -L "$output_dir" ]; then
    echo "Refusing to overwrite $output_dir" >&2
    exit 1
fi
mv "$stage_dir" "$output_dir"
trap - EXIT HUP INT TERM

echo "Development credentials created in $output_dir"
