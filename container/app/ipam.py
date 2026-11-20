"""IP Address Management (IPAM) and network collision checks for ns8-vpn."""

from __future__ import annotations

import ipaddress
from typing import Iterable

from .config import DEFAULT_CLUSTER_WG_CIDR, DEFAULT_CLUSTER_WG_PORT


CLUSTER_HARDCODED_NET = ipaddress.IPv4Network(DEFAULT_CLUSTER_WG_CIDR)
LOOPBACK_NET = ipaddress.IPv4Network("127.0.0.0/8")
LINK_LOCAL_NET = ipaddress.IPv4Network("169.254.0.0/16")


class IPAMValidationError(ValueError):
    """Raised when a subnet, IP, or port violates NS8 VPN safety rules."""


class IPPoolExhaustedError(RuntimeError):
    """Raised when no free client IP addresses remain in the VPN transfer subnet."""


def _parse_cluster_net(cluster_wg_cidr: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(cluster_wg_cidr.strip(), strict=False)
    except ValueError:
        return CLUSTER_HARDCODED_NET
    if not isinstance(net, ipaddress.IPv4Network):
        return CLUSTER_HARDCODED_NET
    return net


def validate_wg_port(port: int, cluster_wg_port: int = DEFAULT_CLUSTER_WG_PORT) -> int:
    """Validate WireGuard UDP listen port and reject NS8 cluster port 55820."""
    if isinstance(port, bool) or not isinstance(port, int):
        raise IPAMValidationError("wg_port must be an integer")
    if port < 1 or port > 65535:
        raise IPAMValidationError(f"wg_port {port} is out of valid UDP port range (1..65535)")
    if port == DEFAULT_CLUSTER_WG_PORT or port == cluster_wg_port:
        raise IPAMValidationError(
            f"wg_port {port}/udp is reserved for the NS8 cluster WireGuard mesh (wg0)"
        )
    return port


def normalize_wg_network(
    cidr: str,
    cluster_wg_cidr: str = DEFAULT_CLUSTER_WG_CIDR,
) -> ipaddress.IPv4Network:
    """Validate and normalize the WireGuard IPv4 transfer network."""
    if not cidr or not isinstance(cidr, str):
        raise IPAMValidationError("wg_network must be a non-empty IPv4 CIDR string")
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise IPAMValidationError(f"Invalid wg_network CIDR '{cidr}': {exc}") from exc

    if not isinstance(net, ipaddress.IPv4Network):
        raise IPAMValidationError("wg_network must be an IPv4 CIDR (e.g. 10.199.0.0/24)")

    if net.prefixlen < 16 or net.prefixlen > 30:
        raise IPAMValidationError(
            f"wg_network /{net.prefixlen} is unsupported; prefix length must be between /16 and /30"
        )

    if net.is_unspecified or net.is_multicast or net.overlaps(LOOPBACK_NET) or net.overlaps(LINK_LOCAL_NET):
        raise IPAMValidationError(f"wg_network {net} uses a reserved loopback/link-local/multicast range")

    cluster_net = _parse_cluster_net(cluster_wg_cidr)
    if net.overlaps(CLUSTER_HARDCODED_NET) or net.overlaps(cluster_net):
        raise IPAMValidationError(
            f"wg_network {net} overlaps reserved NS8 cluster WireGuard network ({cluster_net})"
        )

    return net


def normalize_allowed_cidrs(
    cidrs: Iterable[str],
    wg_network: str,
    cluster_wg_cidr: str = DEFAULT_CLUSTER_WG_CIDR,
) -> list[str]:
    """Validate and normalize Split-Tunnel target CIDRs."""
    transfer_net = normalize_wg_network(wg_network, cluster_wg_cidr=cluster_wg_cidr)
    cluster_net = _parse_cluster_net(cluster_wg_cidr)
    normalized: list[str] = []
    seen: set[str] = set()

    for raw in cidrs:
        item = str(raw).strip()
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise IPAMValidationError(f"Invalid allowed CIDR '{item}': {exc}") from exc

        if not isinstance(net, ipaddress.IPv4Network):
            raise IPAMValidationError(f"Allowed CIDR '{item}' must be IPv4")

        if net.prefixlen == 0:
            raise IPAMValidationError(
                "0.0.0.0/0 is not permitted in split-tunnel allowed_cidrs; select tunnel_mode='full' instead"
            )

        if net.overlaps(LOOPBACK_NET) or net.is_multicast:
            raise IPAMValidationError(f"Allowed CIDR {net} uses reserved loopback/multicast space")

        if net.overlaps(CLUSTER_HARDCODED_NET) or net.overlaps(cluster_net):
            raise IPAMValidationError(
                f"Allowed CIDR {net} overlaps reserved NS8 cluster VPN subnet ({cluster_net})"
            )

        if net.overlaps(transfer_net):
            raise IPAMValidationError(
                f"Allowed CIDR {net} overlaps the VPN transfer network ({transfer_net})"
            )

        canonical = str(net)
        if canonical not in seen:
            seen.add(canonical)
            normalized.append(canonical)

    return normalized


def normalize_dns_servers(
    servers: Iterable[str],
    cluster_wg_cidr: str = DEFAULT_CLUSTER_WG_CIDR,
) -> list[str]:
    """Validate and deduplicate IPv4 DNS server addresses."""
    cluster_net = _parse_cluster_net(cluster_wg_cidr)
    normalized: list[str] = []
    seen: set[str] = set()

    for raw in servers:
        item = str(raw).strip()
        if not item:
            continue
        try:
            ip = ipaddress.ip_address(item)
        except ValueError as exc:
            raise IPAMValidationError(f"Invalid DNS server IP '{item}': {exc}") from exc

        if not isinstance(ip, ipaddress.IPv4Address):
            raise IPAMValidationError(f"DNS server '{item}' must be an IPv4 address")

        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise IPAMValidationError(f"DNS server {ip} cannot be loopback, unspecified, or multicast")

        if ip in CLUSTER_HARDCODED_NET or ip in cluster_net:
            raise IPAMValidationError(
                f"DNS server {ip} belongs to the isolated NS8 cluster VPN ({cluster_net})"
            )

        canonical = str(ip)
        if canonical not in seen:
            seen.add(canonical)
            normalized.append(canonical)

    return normalized


def get_server_tunnel_ip(wg_network: str) -> str:
    """Return the server's tunnel IP (first usable host `.1` of `wg_network`)."""
    net = normalize_wg_network(wg_network)
    return str(next(net.hosts()))


def get_server_interface_cidr(wg_network: str) -> str:
    """Return `<server_ip>/<prefixlen>` for `ip addr replace` (e.g. `10.199.0.1/24`)."""
    net = normalize_wg_network(wg_network)
    first_host = next(net.hosts())
    return f"{first_host}/{net.prefixlen}"


def is_ip_valid_client_in_network(ip_str: str, wg_network: str) -> bool:
    """Return True if `ip_str` is a valid non-server usable host inside `wg_network`."""
    net = normalize_wg_network(wg_network)
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if not isinstance(ip, ipaddress.IPv4Address) or ip not in net:
        return False
    if ip == net.network_address or ip == net.broadcast_address:
        return False
    server_ip = next(net.hosts())
    return ip != server_ip


def validate_requested_peer_ip(
    requested_ip: str,
    wg_network: str,
    used_ips: set[str],
) -> str:
    """Validate an admin-requested static client IPv4 address inside `wg_network`."""
    net = normalize_wg_network(wg_network)
    raw = (requested_ip or "").strip()
    if not raw:
        raise IPAMValidationError("assigned_ip must be a valid IPv4 address")
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise IPAMValidationError(f"Invalid IPv4 address '{raw}': {exc}") from exc

    if not isinstance(ip, ipaddress.IPv4Address):
        raise IPAMValidationError(f"assigned_ip '{raw}' must be an IPv4 address")

    if ip not in net:
        raise IPAMValidationError(
            f"IP address '{ip}' is outside VPN transfer network {net}"
        )

    if ip == net.network_address:
        raise IPAMValidationError(
            f"IP address '{ip}' is the network address of {net} and cannot be assigned to a peer"
        )
    if ip == net.broadcast_address:
        raise IPAMValidationError(
            f"IP address '{ip}' is the broadcast address of {net} and cannot be assigned to a peer"
        )

    server_ip = next(net.hosts())
    if ip == server_ip:
        raise IPAMValidationError(
            f"IP address '{ip}' is reserved for the VPN server tunnel interface"
        )

    canonical = str(ip)
    taken = {str(existing).strip() for existing in used_ips if str(existing).strip()}
    if canonical in taken:
        raise IPPoolExhaustedError(f"IP address '{canonical}' is already assigned")

    return canonical


def allocate_peer_ip(wg_network: str, used_ips: Iterable[str]) -> str:
    """Allocate the lowest available peer IPv4 address (`.2`..`.254` for `/24`)."""
    net = normalize_wg_network(wg_network)
    hosts_iter = net.hosts()
    server_ip = str(next(hosts_iter))
    taken = {str(ip).strip() for ip in used_ips if str(ip).strip()} | {server_ip}

    for candidate in hosts_iter:
        candidate_str = str(candidate)
        if candidate_str not in taken:
            return candidate_str

    raise IPPoolExhaustedError(f"IP pool exhausted in transfer network {net}")
