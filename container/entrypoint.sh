#!/usr/bin/env sh
set -eu

STATE_DIR="${STATE_DIR:-/state}"
TCP_PORT="${TCP_PORT:-8080}"
export STATE_DIR TCP_PORT

mkdir -p "${STATE_DIR}/data" "${STATE_DIR}/secrets" "${STATE_DIR}/run"
chmod 0700 "${STATE_DIR}/data" "${STATE_DIR}/secrets" "${STATE_DIR}/run"

rm -f "${STATE_DIR}/run/admin.sock"

umask 0077
exec python3 -m app.main
