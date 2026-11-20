"""WireGuard Site-to-Site branch office tunnel manager (`s2s.py`)."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from .config import DEFAULT_CLUSTER_WG_CIDR
from .crypto import generate_wg_keypair, generate_wg_psk, is_valid_wg_key
from .ipam import (
    CLUSTER_HARDCODED_NET,
    LINK_LOCAL_NET,
    LOOPBACK_NET,
    IPAMValidationError,
    get_server_tunnel_ip,
    normalize_wg_network,
)
from .wireguard import CommandRunner, _guard_not_cluster_interface


S2S_NAME_RE = re.compile(r"^[\w\s.\-()'\u00C0-\u024F]{1,64}$")


def validate_s2s_name(name: str) -> str:
    clean = (name or "").strip()
    if not clean or len(clean) > 64 or not S2S_NAME_RE.match(clean):
        raise IPAMValidationError(
            "Tunnel name must be 1..64 characters using letters, numbers, spaces, '.', '-', '_', or '()'"
        )
    return clean


def validate_s2s_remote_endpoint(endpoint: str) -> str:
    clean = (endpoint or "").strip()
    if not clean:
        return ""
    if any(ch.isspace() for ch in clean) or len(clean) > 255:
        raise IPAMValidationError("Invalid remote_endpoint format (expected host:port or empty)")
    if ":" not in clean:
        raise IPAMValidationError("remote_endpoint must include port (e.g. branch.example.com:51820)")
    _, _, port_str = clean.rpartition(":")
    if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
        raise IPAMValidationError("remote_endpoint port must be between 1 and 65535")
    return clean


def normalize_s2s_remote_cidrs(
    remote_cidrs: Iterable[str],
    *,
    wg_network: str,
    ovpn_network: str = "",
    existing_s2s_cidrs: Iterable[str] = (),
    cluster_wg_cidr: str = DEFAULT_CLUSTER_WG_CIDR,
) -> list[str]:
    """Validate and deduplicate remote LAN CIDRs for a Site-to-Site WireGuard tunnel."""
    wg_net = normalize_wg_network(wg_network, cluster_wg_cidr=cluster_wg_cidr)
    ovpn_net = (
        normalize_wg_network(ovpn_network, cluster_wg_cidr=cluster_wg_cidr)
        if ovpn_network
        else None
    )
    try:
        cluster_net = ipaddress.ip_network(cluster_wg_cidr.strip(), strict=False)
    except ValueError:
        cluster_net = CLUSTER_HARDCODED_NET

    existing_nets = [ipaddress.IPv4Network(c, strict=False) for c in existing_s2s_cidrs if c]

    normalized: list[str] = []
    seen: set[str] = set()
    for raw in remote_cidrs:
        item = str(raw).strip()
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise IPAMValidationError(f"Invalid remote CIDR '{item}': {exc}") from exc

        if not isinstance(net, ipaddress.IPv4Network):
            raise IPAMValidationError(f"Remote CIDR '{item}' must be IPv4")
        if net.prefixlen == 0 or net.prefixlen < 8:
            raise IPAMValidationError(f"Remote CIDR '{net}' is too broad (0.0.0.0/0 is forbidden)")
        if net.overlaps(LOOPBACK_NET) or net.overlaps(LINK_LOCAL_NET) or net.is_multicast:
            raise IPAMValidationError(f"Remote CIDR '{net}' uses reserved address space")
        if net.overlaps(CLUSTER_HARDCODED_NET) or (
            isinstance(cluster_net, ipaddress.IPv4Network) and net.overlaps(cluster_net)
        ):
            raise IPAMValidationError(
                f"Remote CIDR '{net}' overlaps reserved NS8 cluster VPN ({cluster_net})"
            )
        if net.overlaps(wg_net):
            raise IPAMValidationError(
                f"Remote CIDR '{net}' overlaps WireGuard transfer network ({wg_net})"
            )
        if ovpn_net is not None and net.overlaps(ovpn_net):
            raise IPAMValidationError(
                f"Remote CIDR '{net}' overlaps OpenVPN transfer network ({ovpn_net})"
            )
        for other in existing_nets:
            if net.overlaps(other):
                raise IPAMValidationError(
                    f"Remote CIDR '{net}' overlaps another Site-to-Site tunnel's network ({other})"
                )

        canonical = str(net)
        if canonical not in seen:
            seen.add(canonical)
            normalized.append(canonical)

    if not normalized:
        raise IPAMValidationError("At least one valid IPv4 remote_cidr is required")
    return normalized


def prepare_s2s_keys(
    remote_public_key: str,
    server_public_key: str,
) -> tuple[str | None, str, str]:
    """Return `(remote_private_key_or_none, remote_public_key, preshared_key)`."""
    clean_pub = (remote_public_key or "").strip()
    if clean_pub:
        if not is_valid_wg_key(clean_pub):
            raise IPAMValidationError(
                "remote_public_key must be a valid 44-character base64 Curve25519 WireGuard public key"
            )
        if clean_pub == server_public_key:
            raise IPAMValidationError("remote_public_key cannot equal the NS8 server public key")
        priv = None
        pub = clean_pub
    else:
        priv, pub = generate_wg_keypair()

    psk = generate_wg_psk()
    return priv, pub, psk


def render_s2s_remote_config(
    *,
    tunnel_name: str,
    assigned_ip: str,
    remote_private_key: str | None,
    preshared_key: str | None,
    server_public_key: str,
    endpoint_host: str,
    wg_port: int,
    wg_network: str,
    local_allowed_cidrs: list[str],
    ovpn_enabled: bool = False,
    ovpn_network: str = "",
    wg_mtu: int = 1380,
    persistent_keepalive: int = 25,
) -> str:
    """Render ready-to-import WireGuard Site-to-Site `.conf` (FritzBox / router compatible)."""
    priv_line = remote_private_key if remote_private_key else "<INSERT_REMOTE_ROUTER_PRIVATE_KEY>"
    server_ip_cidr = f"{get_server_tunnel_ip(wg_network)}/32"

    allowed_list: list[str] = []
    seen: set[str] = set()
    for item in [server_ip_cidr, wg_network, *local_allowed_cidrs] + (
        [ovpn_network] if ovpn_enabled and ovpn_network else []
    ):
        clean = (item or "").strip()
        if clean and clean not in seen:
            seen.add(clean)
            allowed_list.append(clean)

    host = (endpoint_host or "").strip() or "vpn.example.com"
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        endpoint_str = f"[{host}]:{int(wg_port)}"
    else:
        endpoint_str = f"{host}:{int(wg_port)}"

    lines = [
        f"# Site-to-Site WireGuard Tunnel: {tunnel_name}",
        "[Interface]",
        f"PrivateKey = {priv_line}",
        f"Address = {assigned_ip}/32",
        f"MTU = {int(wg_mtu)}",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
    ]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.extend(
        [
            f"AllowedIPs = {', '.join(allowed_list)}",
            f"Endpoint = {endpoint_str}",
            f"PersistentKeepalive = {int(persistent_keepalive) if int(persistent_keepalive) > 0 else 25}",
        ]
    )
    return "\n".join(lines) + "\n"


class SiteToSiteRouter:
    """Synchronizes Linux kernel IPv4 routes for active Site-to-Site `remote_cidrs`."""

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner
        self._applied_cidrs: set[str] = set()

    def sync_routes(self, interface_name: str, active_cidrs: list[str]) -> None:
        _guard_not_cluster_interface(interface_name)
        desired = {c.strip() for c in active_cidrs if c.strip()}

        for stale in sorted(self._applied_cidrs - desired):
            self.runner.run(["ip", "route", "del", stale, "dev", interface_name], check=False)

        for cidr in sorted(desired):
            self.runner.run(["ip", "route", "replace", cidr, "dev", interface_name])

        self._applied_cidrs = desired

    def remove_routes(self, interface_name: str, cidrs: Iterable[str]) -> None:
        _guard_not_cluster_interface(interface_name)
        for cidr in cidrs:
            clean = str(cidr).strip()
            if clean:
                self.runner.run(["ip", "route", "del", clean, "dev", interface_name], check=False)
                self._applied_cidrs.discard(clean)
