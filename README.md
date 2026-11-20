# ns8-vpn — Business Roadwarrior VPN, Self-Service Portal & Site-to-Site for NethServer 8

`ns8-vpn` is a production-grade **NethServer 8 (NS8)** rootful module providing high-performance **WireGuard** roadwarrior VPN, a **Traefik-integrated End-User Self-Service Portal with TOTP 2FA**, an **OpenVPN TCP/UDP Dual-Stack Hotel & Firewall Fallback Server** with live AD/LDAP + TOTP authentication, **WireGuard Site-to-Site Branch Office Tunnels**, and **Compliance Audit Logging** — tightly integrated with NS8's central user management (**Samba Active Directory** and **OpenLDAP** via `ldapproxy`).

## Architecture & Capabilities Across All 3 Phases

### Phase 1 — WireGuard Core, AD/LDAP Lifecycle & Cockpit Admin UI
- **Central NS8 User & Group Lifecycle Sync (`ldapproxy`)**:
  - Supports **Samba Active Directory (`ad`)** (nested groups via `LDAP_MATCHING_RULE_IN_CHAIN` `1.2.840.113556.1.4.1941`, `userAccountControl` disabled bitmask `0x0002`, and Windows FILETIME `accountExpires`) and **OpenLDAP (`rfc2307`)** (`posixGroup` & `groupOfNames`, `pwdAccountLockedTime`, `shadowExpire`).
  - **Instant Kernel & Session Eviction**: Deauthorized, disabled, or expired accounts have all active WireGuard peers (`wg set <iface> peer <pubkey> remove`) and active OpenVPN sessions (`kill <username>` over `openvpn-mgmt.sock`) terminated immediately.
  - **Fail-Safe Outage Handling**: Temporary LDAP/AD connectivity errors never drop existing authorized tunnels.
- **Automatic IPAM & Optional Static VPN IP Assignment**:
  - Peers automatically receive collision-free `/32` addresses from `wg_network` (`10.199.0.0/24` default).
  - Cockpit administrators can optionally assign a **static VPN IP address** (`assigned_ip`, e.g. `10.199.0.10`) when creating admin/workstation peers for IP-based internal firewall rules, validated against subnet bounds, gateway `.1`, active peers, and Site-to-Site tunnels. Self-Service Portal users always receive automatic pool IPs.
- **Strict NS8 Cluster Isolation & Host Safety**:
  - Dedicated interfaces `wg-<module_id>` (default `10.199.0.0/24`, UDP `51820`) and `tun-<module_id>` (default `10.199.1.0/24`, TCP/UDP `1194`) completely isolated from NS8's internal cluster WireGuard (`wg0`, UDP `55820`, `10.5.4.0/24`) and Redis (`6379/tcp`).
  - Automatic collision checks against `wg0`, `ns8-traefik` (`443/tcp`), host routing tables, and bound TCP/UDP sockets.
  - Dedicated `firewalld` zone (`ns8vpn-<module_id>`) & forwarding policy (`<module_id>-fwd`) paired with an atomic `nftables` table (`table inet ns8_vpn_<module_id>`) enforcing Split-Tunnel CIDRs server-side, TCP MSS clamping (`1380` MTU default for PPPoE/FritzBox links), and optional SNAT masquerading.

### Phase 2 — End-User Self-Service Web Portal, TOTP 2FA & Audit Trail
- **Privilege-Separated Architecture**:
  - Cockpit admin actions (`configure-module`, `create-peer`, `list-audit-logs`, etc.) communicate exclusively over a root-only Unix Domain Socket (`/var/lib/nethserver/<module_id>/state/run/admin.sock`, `0600`).
  - `127.0.0.1:${TCP_PORT}` behind `ns8-traefik` exposes **only** the hardened End-User Self-Service Portal (never `/api/v1/admin/*`), protected by strict CSP, `HttpOnly`/`SameSite=Lax` HMAC sessions, `X-Requested-With: NS8VPNPortal` CSRF protection, and login rate limiting.
- **Zero-Ticket Employee Onboarding**:
  - Employees sign in with their NS8 AD/OpenLDAP credentials, enroll **TOTP 2FA** (`disabled` / `optional` / `required` policy, with Cockpit helpdesk 2FA reset), manage their own WireGuard devices up to `max_devices_per_user`, scan mobile QR codes, download `.conf` / `.ovpn` profiles, and follow interactive OS setup guides (Windows, macOS, iOS, Android, Linux) in German or English.
- **Security & Administrative Audit Log (`list-audit-logs`)**:
  - Records authentication attempts, TOTP enrollments/resets, peer creation/suspension/revocation, AD/LDAP lifecycle evictions, OpenVPN sessions, and configuration changes in a bounded SQLite audit table.
  - Accessible in NS8 Cockpit (*Audit Log* / *Audit-Protokoll*) with search, category filters, and RFC-4180 UTF-8 CSV export for IT/GDPR compliance, or via CLI (`api-cli run module/<id>/list-audit-logs --data '{"limit": 100}'`).

### Phase 3 — OpenVPN Dual-Stack TCP/443 Fallback & WireGuard Site-to-Site
- **OpenVPN Compatibility, Restricted-Network & DS-Lite / IPv6 Transport**:
  - Built-in X.509 PKI + 2048-bit `tls-crypt` V1 static key encrypted at rest in SQLite (`AES-256-GCM`).
  - **DS-Lite & IPv6 Dual-Stack Ready**: Automatically detects Dual-Stack Linux hosts (`/proc/sys/net/ipv6/conf/all/disable_ipv6=0` and `bindv6only=0`) and binds OpenVPN with `proto tcp6-server` / `proto udp6` (gracefully falling back to `tcp-server` / `udp` on IPv4-only hosts), accepting both IPv4 and IPv6/DS-Lite connections while `.ovpn` profiles resolve both `AAAA` and `A` DNS records natively.
  - Supports external router port remapping (`ovpn_public_port`, e.g. forwarding WAN `443/tcp -> <host_lan_ip>:1194/tcp` on a FritzBox while NS8 Traefik occupies local `443/tcp`) to bypass hotel, clinic, and guest Wi-Fi UDP blocks.
  - Live AD/LDAP password verification (`via-file` — zero secrets in process argv) with optional trailing 6-digit TOTP verification on every connection.
- **Site-to-Site Branch Office Coupling**:
  - Connect branch routers (e.g. FritzBox, OPNsense, Linux WireGuard gateways) with bidirectional LAN CIDR routing, collision validation, and ready-to-import router `.conf` generation directly from NS8 Cockpit.
- **Full Restic Backup, Restore & Clone Support**:
  - Online SQLite `.backup` snapshot (`module-dump-state`) + `state/secrets/master.key` preserves all WireGuard keys, TOTP secrets, OpenVPN PKI certificates, audit history, and Site-to-Site tunnels across server migrations.

## Building Container Images

```bash
REPOBASE=ghcr.io/generablack IMAGETAG=latest ./build-images.sh
```

This builds:
1. `${REPOBASE}/vpn-controller:${IMAGETAG}` (from `container/Containerfile`)
2. `${REPOBASE}/vpn:${IMAGETAG}` (NS8 module image from `Containerfile`)

## Installing & Managing via NS8 CLI

```bash
# Install on node 1
add-module ghcr.io/generablack/vpn:latest 1

# Provision an admin peer with an optional static VPN IP
api-cli run module/vpn1/create-peer --data '{"username":"jdoe","device_name":"Admin-Workstation","assigned_ip":"10.199.0.10"}'

# Query recent security & administrative audit events
api-cli run module/vpn1/list-audit-logs --data '{"limit":100,"username":"jdoe"}'
```

## Running Unit Tests & NS8 Architecture Audit

```bash
# Run Python controller, portal, TOTP, OpenVPN, Site-to-Site & module action tests
pytest -v

# Run NS8 architectural, LF line-ending & i18n parity audit
python tests/verify_ns8_rules.py

# Validate Self-Service Portal JavaScript syntax
node --check container/app/portal_static/app.js

# Lint and build Cockpit Admin UI
cd ui && npm install && npm run lint && npm run build
```

## Live NS8 VM End-to-End Smoke Test (`tests/ns8_smoke_test.sh`)

To validate image builds, `add-module`, `configure-module`, `wg-<id>` kernel interface provisioning, `wg0` (`55820/udp`) cluster isolation, `nftables` & `firewalld` rules, static-IP `create-peer`, `list-audit-logs`, and `module-dump-state` on a dedicated **NethServer 8 (Rocky Linux 9 / Debian 12)** test VM, run as `root`:

```bash
# Build images locally, run all live NS8 smoke checks, and remove the test instance afterwards
bash tests/ns8_smoke_test.sh --cleanup

# Keep the test instance running for manual Cockpit UI / Self-Service Portal inspection
bash tests/ns8_smoke_test.sh --endpoint vpn.test.lan
```

## License

Released under the [GNU General Public License v3.0 or later](LICENSE) (`GPL-3.0-or-later`).
