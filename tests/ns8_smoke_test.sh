#!/usr/bin/env bash
#
# End-to-End Live Smoke Test for ns8-vpn on NethServer 8 (Rocky Linux 9 / Debian 12)
#
# Run as root on a dedicated NS8 test node:
#   bash tests/ns8_smoke_test.sh [--cleanup] [--skip-build] [--node 1] [--endpoint vpn.example.test]
#
# Verifies:
#   1. Container & NS8 module image build (./build-images.sh)
#   2. Module installation (add-module) & pre-configuration safe fallbacks (get-configuration, list-audit-logs)
#   3. Module configuration (api-cli run module/<id>/configure-module) with WireGuard + OpenVPN fallback
#   4. Kernel interface wg-<id> UP while NS8 cluster wg0 remains untouched on 55820/udp
#   5. Atomic nftables isolation table (nft list table inet ns8_vpn_<id>)
#   6. Dedicated firewalld zone (firewall-cmd --info-zone=ns8vpn-<id>, never in 'trusted')
#   7. Admin peer creation with static VPN IP assignment (create-peer + wg show allowed-ips)
#   8. Security & administrative audit trail (list-audit-logs)
#   9. Online SQLite Restic pre-backup hook (module-dump-state + PRAGMA integrity_check)
#  10. Optional clean teardown (--cleanup -> remove-module --no-preserve <id>)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CLEANUP=false
SKIP_BUILD=false
NODE_ID="${NODE_ID:-1}"
REPOBASE="${REPOBASE:-localhost}"
IMAGETAG="${IMAGETAG:-smoke}"
ENDPOINT_HOST="${ENDPOINT_HOST:-vpn-smoke.nethserver.test}"
WG_SUBNET="${WG_SUBNET:-10.199.250.0/24}"
STATIC_PEER_IP="${STATIC_PEER_IP:-10.199.250.10}"
OVPN_SUBNET="${OVPN_SUBNET:-10.199.251.0/24}"
TEST_ALLOWED_CIDR="${TEST_ALLOWED_CIDR:-192.0.2.0/24}"

usage() {
    cat <<'EOF'
Usage: bash tests/ns8_smoke_test.sh [OPTIONS]

Options:
  --cleanup             Remove the test module instance (remove-module --no-preserve) after passing
  --skip-build          Skip ./build-images.sh and use existing ${REPOBASE}/vpnportal:${IMAGETAG} image
  --node <id>           Target NS8 cluster node ID (default: 1)
  --endpoint <host>     Public endpoint hostname/IP for test config (default: vpn-smoke.nethserver.test)
  -h, --help            Show this help message and exit

Environment overrides:
  REPOBASE              Container repository prefix (default: localhost)
  IMAGETAG              Container image tag (default: smoke)
  WG_SUBNET             Test WireGuard /24 pool (default: 10.199.250.0/24)
  STATIC_PEER_IP        Static IP tested with create-peer (default: 10.199.250.10)
  OVPN_SUBNET           Test OpenVPN /24 pool (default: 10.199.251.0/24)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cleanup)
            CLEANUP=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --node)
            NODE_ID="${2:?--node requires a node ID}"
            shift 2
            ;;
        --endpoint)
            ENDPOINT_HOST="${2:?--endpoint requires a hostname or IP}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

log_step() {
    printf '\n==> %s\n' "$*"
}

log_ok() {
    printf '  [OK] %s\n' "$*"
}

fail() {
    printf '  [FAIL] %s\n' "$*" >&2
    exit 1
}

if [[ "$(id -u)" -ne 0 ]]; then
    fail "This smoke test must be executed as root on an NS8 Linux node."
fi

for required_cmd in add-module api-cli podman wg ip nft python3 systemctl; do
    if ! command -v "${required_cmd}" >/dev/null 2>&1; then
        fail "Required NS8/Linux command '${required_cmd}' not found in PATH."
    fi
done

# Record pre-test NS8 cluster wg0 port (expected 55820/udp)
ip link show dev wg0 >/dev/null 2>&1 || fail "NS8 cluster interface 'wg0' is not present on this node."
CLUSTER_WG0_PORT_BEFORE="$(wg show wg0 listen-port | tr -d '[:space:]')"
[[ -n "${CLUSTER_WG0_PORT_BEFORE}" ]] || fail "Could not read wg0 listen-port."
log_ok "Detected active NS8 cluster wg0 on UDP port ${CLUSTER_WG0_PORT_BEFORE}"

# 1. Build container & module images
if [[ "${SKIP_BUILD}" == "false" ]]; then
    log_step "1/9 Building controller and NS8 module images (${REPOBASE}/vpnportal:${IMAGETAG})"
    (
        cd "${REPO_ROOT}"
        REPOBASE="${REPOBASE}" IMAGETAG="${IMAGETAG}" ./build-images.sh
    )
    log_ok "Built ${REPOBASE}/vpn-controller:${IMAGETAG} and ${REPOBASE}/vpnportal:${IMAGETAG}"
else
    log_step "1/9 Skipping image build (--skip-build); using ${REPOBASE}/vpnportal:${IMAGETAG}"
fi

# 2. Install module on NS8 node
log_step "2/9 Installing module via add-module on node ${NODE_ID}"
ADD_OUT="$(add-module "${REPOBASE}/vpnportal:${IMAGETAG}" "${NODE_ID}")"
MODULE_ID="$(printf '%s\n' "${ADD_OUT}" | python3 -c '
import json, sys
lines = [ln.strip() for ln in sys.stdin if ln.strip().startswith("{")]
if not lines:
    raise SystemExit("No JSON output returned by add-module")
print(json.loads(lines[-1])["module_id"])
')"
[[ -n "${MODULE_ID}" ]] || fail "Failed to parse module_id from add-module output."
log_ok "Installed module instance: ${MODULE_ID}"

WG_IFACE="wg-${MODULE_ID}"
TUN_IFACE="tun-${MODULE_ID}"
NFT_TABLE="ns8_vpn_$(printf '%s' "${MODULE_ID}" | tr -c 'a-zA-Z0-9_' '_')"
FW_ZONE="$(printf 'ns8vpn-%s' "${MODULE_ID}" | cut -c1-17)"
STATE_DIR="/var/lib/nethserver/${MODULE_ID}/state"

# 3. Verify pre-configuration safe fallbacks (before vpn-controller service is started)
log_step "3/9 Verifying pre-configuration get-configuration & list-audit-logs fallbacks"
PRE_CFG="$(api-cli run "module/${MODULE_ID}/get-configuration" --data '{}')"
SUGGESTED_WG_PORT="$(printf '%s' "${PRE_CFG}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert data.get("configured") is False, f"Expected configured=False, got {data.get(\"configured\")}"
print(int(data.get("wg_port", 51820)))
')"
PRE_AUDIT="$(api-cli run "module/${MODULE_ID}/list-audit-logs" --data '{"limit": 25}')"
printf '%s' "${PRE_AUDIT}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert data == {"entries": [], "total": 0}, f"Unexpected pre-config audit response: {data}"
'
log_ok "Pre-configuration actions succeeded cleanly (suggested wg_port=${SUGGESTED_WG_PORT})"

# 4. Configure module
log_step "4/9 Running module/${MODULE_ID}/configure-module"
CONFIGURE_PAYLOAD="$(python3 -c '
import json, sys
print(json.dumps({
    "endpoint_host": sys.argv[1],
    "wg_port": int(sys.argv[2]),
    "wg_network": sys.argv[3],
    "tunnel_mode": "split",
    "allowed_cidrs": [sys.argv[4]],
    "dns_servers": [],
    "dns_search_domain": "smoke.internal",
    "wg_mtu": 1380,
    "persistent_keepalive": 25,
    "nat_enabled": True,
    "user_domain": "",
    "vpn_group": "",
    "max_devices_per_user": 3,
    "sync_interval_minutes": 5,
    "portal_enabled": False,
    "portal_domain": "",
    "portal_lets_encrypt": False,
    "portal_http2https": True,
    "portal_totp_mode": "optional",
    "ovpn_enabled": True,
    "ovpn_proto": "tcp",
    "ovpn_port": 1194,
    "ovpn_public_port": 443,
    "ovpn_network": sys.argv[5],
    "ovpn_totp_required": False,
}))
' "${ENDPOINT_HOST}" "${SUGGESTED_WG_PORT}" "${WG_SUBNET}" "${TEST_ALLOWED_CIDR}" "${OVPN_SUBNET}")"

api-cli run "module/${MODULE_ID}/configure-module" --data "${CONFIGURE_PAYLOAD}" >/dev/null
systemctl is-active --quiet "${MODULE_ID}.service" || fail "Systemd unit ${MODULE_ID}.service is not active."
log_ok "Configured ${MODULE_ID} and verified ${MODULE_ID}.service is active"

# 5. Verify wg-<id> UP and NS8 cluster wg0 untouched on 55820/udp
log_step "5/9 Verifying WireGuard kernel interface (${WG_IFACE}) & NS8 cluster wg0 isolation"
ip link show dev "${WG_IFACE}" | grep -q "UP" || fail "Interface ${WG_IFACE} is not UP."
wg show "${WG_IFACE}" >/dev/null || fail "wg show ${WG_IFACE} failed."
ip link show dev "${TUN_IFACE}" >/dev/null 2>&1 && log_ok "OpenVPN interface ${TUN_IFACE} present"

ip link show dev wg0 >/dev/null 2>&1 || fail "NS8 cluster wg0 disappeared!"
CLUSTER_WG0_PORT_AFTER="$(wg show wg0 listen-port | tr -d '[:space:]')"
if [[ "${CLUSTER_WG0_PORT_AFTER}" != "${CLUSTER_WG0_PORT_BEFORE}" ]]; then
    fail "Cluster wg0 listen-port changed from ${CLUSTER_WG0_PORT_BEFORE} to ${CLUSTER_WG0_PORT_AFTER}!"
fi
if [[ "${CLUSTER_WG0_PORT_AFTER}" != "55820" ]]; then
    printf '  [WARN] Cluster wg0 uses custom non-default port %s (still untouched)\n' "${CLUSTER_WG0_PORT_AFTER}"
else
    log_ok "Cluster wg0 remains untouched on 55820/udp"
fi
log_ok "Dedicated interface ${WG_IFACE} is UP on UDP port ${SUGGESTED_WG_PORT}"

# 6. Verify nftables & firewalld isolation
log_step "6/9 Verifying nftables table (inet ${NFT_TABLE}) and firewalld zone (${FW_ZONE})"
NFT_DUMP="$(nft list table inet "${NFT_TABLE}")"
printf '%s' "${NFT_DUMP}" | grep -q "chain forward" || fail "Missing forward chain in inet ${NFT_TABLE}."
printf '%s' "${NFT_DUMP}" | grep -q "10.5.4.0/24" || fail "Missing cluster CIDR drop rule in inet ${NFT_TABLE}."
log_ok "Verified nftables table inet ${NFT_TABLE}"

if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    FW_INFO="$(firewall-cmd --info-zone="${FW_ZONE}")"
    printf '%s' "${FW_INFO}" | grep -q "${WG_IFACE}" || fail "${WG_IFACE} not assigned to zone ${FW_ZONE}."
    if firewall-cmd --zone=trusted --list-interfaces | tr ' ' '\n' | grep -qx "${WG_IFACE}"; then
        fail "Security violation: ${WG_IFACE} must NEVER be in firewalld 'trusted' zone!"
    fi
    log_ok "Verified firewalld zone ${FW_ZONE} (isolated from 'trusted')"
else
    printf '  [SKIP] firewalld not active on this host; skipped firewall-cmd zone check\n'
fi

# 7. Create peer with static VPN IP and verify kernel WireGuard peer programming
log_step "7/9 Testing create-peer with static VPN IP (${STATIC_PEER_IP})"
CREATE_PEER_PAYLOAD="$(python3 -c '
import json, sys
print(json.dumps({
    "username": "smoke.admin",
    "device_name": "SmokeTest-Laptop",
    "allow_unlisted": True,
    "assigned_ip": sys.argv[1],
}))
' "${STATIC_PEER_IP}")"

PEER_OUT="$(api-cli run "module/${MODULE_ID}/create-peer" --data "${CREATE_PEER_PAYLOAD}")"
PEER_ID="$(printf '%s' "${PEER_OUT}" | python3 -c '
import json, sys
expected_ip = sys.argv[1]
resp = json.load(sys.stdin)
peer = resp["peer"]
assert peer["assigned_ip"] == expected_ip, f"Expected {expected_ip}, got {peer[\"assigned_ip\"]}"
assert f"Address = {expected_ip}/32" in resp["config_text"], "Static IP missing from rendered .conf"
print(peer["id"])
' "${STATIC_PEER_IP}")"

wg show "${WG_IFACE}" allowed-ips | grep -q "${STATIC_PEER_IP}/32" \
    || fail "Kernel WireGuard interface ${WG_IFACE} missing allowed-ips ${STATIC_PEER_IP}/32."
log_ok "Created peer ${PEER_ID} with static IP ${STATIC_PEER_IP} and verified kernel allowed-ips"

# 8. Verify list-audit-logs action returns recorded events
log_step "8/9 Verifying module/${MODULE_ID}/list-audit-logs"
AUDIT_OUT="$(api-cli run "module/${MODULE_ID}/list-audit-logs" --data '{"limit": 50}')"
AUDIT_SUMMARY="$(printf '%s' "${AUDIT_OUT}" | python3 -c '
import json, sys
resp = json.load(sys.stdin)
entries = resp.get("entries", [])
total = int(resp.get("total", 0))
assert total >= 1 and len(entries) >= 1, f"Expected >=1 audit entries, got total={total}"
events = [e.get("event_type", "") for e in entries]
print(f"total={total}, latest_events={events[:3]}")
')"
log_ok "Audit log verified (${AUDIT_SUMMARY})"

# 9. Verify online SQLite Restic backup dump hook (module-dump-state)
log_step "9/9 Testing Restic pre-backup SQLite snapshot (module-dump-state)"
DUMP_SCRIPT="/var/lib/nethserver/${MODULE_ID}/bin/module-dump-state"
if [[ ! -x "${DUMP_SCRIPT}" ]]; then
    DUMP_SCRIPT="${REPO_ROOT}/imageroot/bin/module-dump-state"
fi
MODULE_ID="${MODULE_ID}" AGENT_STATE_DIR="${STATE_DIR}" "${DUMP_SCRIPT}"

BAK_FILE="${STATE_DIR}/backup/vpn.db.bak"
[[ -s "${BAK_FILE}" ]] || fail "Backup file ${BAK_FILE} was not created or is empty."
python3 -c '
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
res = conn.execute("PRAGMA integrity_check;").fetchone()[0]
peer_cnt = conn.execute("SELECT COUNT(*) FROM peers;").fetchone()[0]
conn.close()
assert res == "ok", f"SQLite integrity_check failed: {res}"
assert peer_cnt >= 1, f"Expected >=1 peer in backup snapshot, got {peer_cnt}"
' "${BAK_FILE}"
log_ok "Verified SQLite hot backup ${BAK_FILE} (PRAGMA integrity_check=ok)"

# Optional teardown
if [[ "${CLEANUP}" == "true" ]]; then
    log_step "Cleanup (--cleanup): Removing ${MODULE_ID} via remove-module --no-preserve"
    remove-module --no-preserve "${MODULE_ID}"
    if ip link show dev "${WG_IFACE}" >/dev/null 2>&1; then
        fail "Interface ${WG_IFACE} still exists after remove-module!"
    fi
    if nft list table inet "${NFT_TABLE}" >/dev/null 2>&1; then
        fail "nftables table inet ${NFT_TABLE} still exists after remove-module!"
    fi
    ip link show dev wg0 >/dev/null 2>&1 || fail "Cluster wg0 affected during cleanup!"
    log_ok "Removed ${MODULE_ID} cleanly; wg0 remains healthy"
else
    printf '\nNote: Instance %s was kept running for manual Cockpit/Portal inspection.\n' "${MODULE_ID}"
    printf '      Run `remove-module --no-preserve %s` when finished (or pass --cleanup).\n' "${MODULE_ID}"
fi

printf '\nSUCCESS: All ns8-vpn smoke tests passed on %s!\n' "$(hostname -f 2>/dev/null || hostname)"
