"""Configuration and environment helpers for ns8-vpn controller."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping


CLUSTER_RESERVED_INTERFACE = "wg0"
DEFAULT_CLUSTER_WG_CIDR = "10.5.4.0/24"
DEFAULT_CLUSTER_WG_PORT = 55820
DEFAULT_WG_NETWORK = "10.199.0.0/24"
DEFAULT_WG_PORT = 51820
DEFAULT_WG_MTU = 1380
DEFAULT_PERSISTENT_KEEPALIVE = 25
DEFAULT_MAX_DEVICES_PER_USER = 3
DEFAULT_SYNC_INTERVAL_MINUTES = 5

DEFAULT_PORTAL_TOTP_MODE = "optional"
DEFAULT_OVPN_PROTO = "tcp"
DEFAULT_OVPN_PORT = 1194
DEFAULT_OVPN_PUBLIC_PORT = 1194
DEFAULT_OVPN_NETWORK = "10.199.1.0/24"


def _parse_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    norm = str(value).strip().lower()
    if norm in {"1", "true", "yes", "on"}:
        return True
    if norm in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_int(value: str | int | None, default: int) -> int:
    if value is None or str(value).strip() == "":
        return default
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def _parse_str_list(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    raw = str(value).strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass
    parts = re.split(r"[,\n;]+", raw)
    return [p.strip() for p in parts if p.strip()]


def _derive_prefixed_interface(module_id: str, prefix: str) -> str:
    """Derive a safe Linux network interface name (`<prefix>-<id>`, <=15 chars, never wg0)."""
    raw = (module_id or "").strip()
    if raw.lower() == CLUSTER_RESERVED_INTERFACE or raw == "0":
        raise ValueError("Interface 'wg0' is strictly reserved for NS8 cluster WireGuard")

    clean = re.sub(r"[^A-Za-z0-9_-]", "", raw)
    if not clean:
        clean = "vpn1"

    low_prefix = f"{prefix.lower()}-"
    if clean.lower().startswith(low_prefix):
        clean = clean[len(low_prefix) :] or "vpn1"
    elif clean.lower().startswith("wg-"):
        clean = clean[3:] or "vpn1"

    if clean == "0" or clean.lower() == CLUSTER_RESERVED_INTERFACE:
        raise ValueError("Interface 'wg0' is strictly reserved for NS8 cluster WireGuard")

    base_prefix = f"{prefix}-"
    candidate = f"{base_prefix}{clean}"
    if len(candidate) > 15:
        m = re.search(r"(\d+)$", clean)
        if m and len(m.group(1)) <= 6:
            suffix = m.group(1)
            prefix_len = 15 - len(base_prefix) - len(suffix)
            candidate = f"{base_prefix}{clean[:prefix_len]}{suffix}"
        else:
            candidate = candidate[:15]

    if candidate.lower() == CLUSTER_RESERVED_INTERFACE:
        raise ValueError("Interface 'wg0' is strictly reserved for NS8 cluster WireGuard")
    return candidate


def derive_interface_name(module_id: str) -> str:
    """Derive a safe Linux WireGuard interface name (`wg-${MODULE_ID}`, <=15 chars, NEVER wg0)."""
    return _derive_prefixed_interface(module_id, "wg")


def derive_ovpn_interface_name(module_id: str) -> str:
    """Derive a safe Linux OpenVPN TUN interface name (`tun-${MODULE_ID}`, <=15 chars)."""
    return _derive_prefixed_interface(module_id, "tun")


def derive_nft_table_name(module_id: str) -> str:
    """Derive an isolated nftables inet table identifier (`ns8_vpn_<safe_id>`)."""
    raw = (module_id or "vpn1").strip() or "vpn1"
    safe = re.sub(r"[^A-Za-z0-9_]", "_", raw)
    return f"ns8_vpn_{safe}"


@dataclass
class Settings:
    """Runtime settings for the VPN controller process."""

    module_id: str = "vpn1"
    state_dir: Path = field(default_factory=lambda: Path("/state"))
    tcp_port: int = 8080
    initial_wg_port: int = DEFAULT_WG_PORT
    initial_wg_network: str = DEFAULT_WG_NETWORK
    initial_endpoint_host: str = ""
    initial_tunnel_mode: str = "split"
    initial_allowed_cidrs: list[str] = field(default_factory=list)
    initial_dns_servers: list[str] = field(default_factory=list)
    initial_dns_search_domain: str = ""
    initial_wg_mtu: int = DEFAULT_WG_MTU
    initial_persistent_keepalive: int = DEFAULT_PERSISTENT_KEEPALIVE
    initial_nat_enabled: bool = True
    initial_user_domain: str = ""
    initial_vpn_group: str = ""
    initial_max_devices_per_user: int = DEFAULT_MAX_DEVICES_PER_USER
    initial_sync_interval_minutes: int = DEFAULT_SYNC_INTERVAL_MINUTES
    initial_portal_enabled: bool = False
    initial_portal_domain: str = ""
    initial_portal_lets_encrypt: bool = False
    initial_portal_http2https: bool = True
    initial_portal_totp_mode: str = DEFAULT_PORTAL_TOTP_MODE
    initial_ovpn_enabled: bool = False
    initial_ovpn_proto: str = DEFAULT_OVPN_PROTO
    initial_ovpn_port: int = DEFAULT_OVPN_PORT
    initial_ovpn_public_port: int = DEFAULT_OVPN_PUBLIC_PORT
    initial_ovpn_network: str = DEFAULT_OVPN_NETWORK
    initial_ovpn_totp_required: bool = False
    cluster_wg_cidr: str = DEFAULT_CLUSTER_WG_CIDR
    cluster_wg_port: int = DEFAULT_CLUSTER_WG_PORT
    cluster_wg_interface: str = CLUSTER_RESERVED_INTERFACE
    dry_run: bool = field(default_factory=lambda: sys.platform != "linux")

    def __post_init__(self) -> None:
        self.state_dir = Path(self.state_dir)

    @property
    def interface_name(self) -> str:
        return derive_interface_name(self.module_id)

    @property
    def ovpn_interface_name(self) -> str:
        return derive_ovpn_interface_name(self.module_id)

    @property
    def nft_table_name(self) -> str:
        return derive_nft_table_name(self.module_id)

    @property
    def data_dir(self) -> Path:
        return self.state_dir / "data"

    @property
    def secrets_dir(self) -> Path:
        return self.state_dir / "secrets"

    @property
    def run_dir(self) -> Path:
        return self.state_dir / "run"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "vpn.db"

    @property
    def master_key_path(self) -> Path:
        return self.secrets_dir / "master.key"

    @property
    def ldap_config_path(self) -> Path:
        return self.secrets_dir / "ldap.json"

    @property
    def admin_sock_path(self) -> Path:
        return self.run_dir / "admin.sock"

    @property
    def ovpn_server_conf_path(self) -> Path:
        return self.run_dir / "openvpn-server.conf"

    @property
    def ovpn_mgmt_sock_path(self) -> Path:
        return self.run_dir / "openvpn-mgmt.sock"

    @property
    def ovpn_status_log_path(self) -> Path:
        return self.run_dir / "openvpn-status.log"

    @property
    def ovpn_pid_path(self) -> Path:
        return self.run_dir / "openvpn.pid"

    def ensure_directories(self) -> None:
        for directory in (self.data_dir, self.secrets_dir, self.run_dir):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        source = env if env is not None else os.environ
        default_dry = sys.platform != "linux"
        dry_val = source.get("VPN_DRY_RUN", source.get("DRY_RUN"))
        totp_mode = source.get("PORTAL_TOTP_MODE", DEFAULT_PORTAL_TOTP_MODE).strip().lower()
        if totp_mode not in {"disabled", "optional", "required"}:
            totp_mode = DEFAULT_PORTAL_TOTP_MODE
        ovpn_proto = source.get("OVPN_PROTO", DEFAULT_OVPN_PROTO).strip().lower()
        if ovpn_proto not in {"tcp", "udp"}:
            ovpn_proto = DEFAULT_OVPN_PROTO
        ovpn_port = _parse_int(source.get("OVPN_PORT"), DEFAULT_OVPN_PORT)
        ovpn_pub_port = _parse_int(source.get("OVPN_PUBLIC_PORT"), ovpn_port)

        return cls(
            module_id=source.get("MODULE_ID", "vpn1").strip() or "vpn1",
            state_dir=Path(source.get("STATE_DIR", "/state")),
            tcp_port=_parse_int(source.get("TCP_PORT"), 8080),
            initial_wg_port=_parse_int(source.get("WG_PORT"), DEFAULT_WG_PORT),
            initial_wg_network=source.get("WG_NETWORK", DEFAULT_WG_NETWORK).strip() or DEFAULT_WG_NETWORK,
            initial_endpoint_host=source.get("ENDPOINT_HOST", "").strip(),
            initial_tunnel_mode=(source.get("TUNNEL_MODE", "split").strip().lower() or "split"),
            initial_allowed_cidrs=_parse_str_list(source.get("ALLOWED_CIDRS")),
            initial_dns_servers=_parse_str_list(source.get("DNS_SERVERS")),
            initial_dns_search_domain=source.get("DNS_SEARCH_DOMAIN", "").strip(),
            initial_wg_mtu=_parse_int(source.get("WG_MTU"), DEFAULT_WG_MTU),
            initial_persistent_keepalive=_parse_int(
                source.get("PERSISTENT_KEEPALIVE"), DEFAULT_PERSISTENT_KEEPALIVE
            ),
            initial_nat_enabled=_parse_bool(source.get("NAT_ENABLED"), True),
            initial_user_domain=source.get("USER_DOMAIN", "").strip(),
            initial_vpn_group=source.get("VPN_GROUP", "").strip(),
            initial_max_devices_per_user=_parse_int(
                source.get("MAX_DEVICES_PER_USER"), DEFAULT_MAX_DEVICES_PER_USER
            ),
            initial_sync_interval_minutes=_parse_int(
                source.get("SYNC_INTERVAL_MINUTES"), DEFAULT_SYNC_INTERVAL_MINUTES
            ),
            initial_portal_enabled=_parse_bool(source.get("PORTAL_ENABLED"), False),
            initial_portal_domain=source.get("PORTAL_DOMAIN", "").strip(),
            initial_portal_lets_encrypt=_parse_bool(source.get("PORTAL_LETS_ENCRYPT"), False),
            initial_portal_http2https=_parse_bool(source.get("PORTAL_HTTP2HTTPS"), True),
            initial_portal_totp_mode=totp_mode,
            initial_ovpn_enabled=_parse_bool(source.get("OVPN_ENABLED"), False),
            initial_ovpn_proto=ovpn_proto,
            initial_ovpn_port=ovpn_port,
            initial_ovpn_public_port=ovpn_pub_port,
            initial_ovpn_network=source.get("OVPN_NETWORK", DEFAULT_OVPN_NETWORK).strip()
            or DEFAULT_OVPN_NETWORK,
            initial_ovpn_totp_required=_parse_bool(source.get("OVPN_TOTP_REQUIRED"), False),
            cluster_wg_cidr=source.get("CLUSTER_WG_CIDR", DEFAULT_CLUSTER_WG_CIDR).strip()
            or DEFAULT_CLUSTER_WG_CIDR,
            cluster_wg_port=_parse_int(source.get("CLUSTER_WG_PORT"), DEFAULT_CLUSTER_WG_PORT),
            cluster_wg_interface=source.get("CLUSTER_WG_INTERFACE", CLUSTER_RESERVED_INTERFACE).strip()
            or CLUSTER_RESERVED_INTERFACE,
            dry_run=_parse_bool(dry_val, default_dry),
        )
