"""nftables firewall and kernel IPv4 forwarding manager for ns8-vpn (WireGuard + OpenVPN + S2S)."""

from __future__ import annotations

import re

from .config import (
    CLUSTER_RESERVED_INTERFACE,
    DEFAULT_CLUSTER_WG_CIDR,
    DEFAULT_CLUSTER_WG_PORT,
    derive_nft_table_name,
)
from .ipam import (
    get_server_tunnel_ip,
    normalize_allowed_cidrs,
    normalize_dns_servers,
    normalize_wg_network,
)
from .wireguard import CommandRunner, _guard_not_cluster_interface


def _sanitize_chain_suffix(iface: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", iface)


def _append_source_guard_rule(
    lines: list[str],
    *,
    iface: str,
    allowed_src_cidrs: list[str],
    primary_net_str: str,
    src_guard_chain: str | None,
) -> None:
    if len(allowed_src_cidrs) == 1:
        lines.append(f'        iifname "{iface}" ip saddr != {primary_net_str} drop')
    elif src_guard_chain:
        lines.append(f'        iifname "{iface}" jump {src_guard_chain}')


def _append_tunnel_input_rules(
    lines: list[str],
    *,
    iface: str,
    allowed_src_cidrs: list[str],
    primary_net_str: str,
    src_guard_chain: str | None,
    server_ip: str,
    tunnel_mode: str,
    clean_cidrs: list[str],
    clean_dns: list[str],
    cluster_cidrs: list[str],
    cluster_wg_port: int,
) -> None:
    lines.append(f'        iifname "{iface}" ip daddr 127.0.0.0/8 drop')
    for c_cidr in cluster_cidrs:
        lines.append(f'        iifname "{iface}" ip daddr {c_cidr} drop')
    lines.append(f'        iifname "{iface}" tcp dport 6379 drop')
    lines.append(f'        iifname "{iface}" udp dport {int(cluster_wg_port)} drop')
    _append_source_guard_rule(
        lines,
        iface=iface,
        allowed_src_cidrs=allowed_src_cidrs,
        primary_net_str=primary_net_str,
        src_guard_chain=src_guard_chain,
    )
    lines.append(f'        iifname "{iface}" ct state established,related accept')
    lines.append(f'        iifname "{iface}" ip daddr {server_ip} accept')

    for dns_ip in clean_dns:
        lines.append(f'        iifname "{iface}" ip daddr {dns_ip} udp dport 53 accept')
        lines.append(f'        iifname "{iface}" ip daddr {dns_ip} tcp dport 53 accept')

    if tunnel_mode == "split":
        for dest_cidr in clean_cidrs:
            lines.append(f'        iifname "{iface}" ip daddr {dest_cidr} accept')
        lines.append(f'        iifname "{iface}" drop')
    else:
        lines.append(f'        iifname "{iface}" accept')


def _append_tunnel_forward_rules(
    lines: list[str],
    *,
    iface: str,
    allowed_src_cidrs: list[str],
    primary_net_str: str,
    src_guard_chain: str | None,
    server_ip: str,
    tunnel_mode: str,
    allowed_dest_cidrs: list[str],
    s2s_dest_cidrs: list[str],
    clean_dns: list[str],
    cluster_ifaces: list[str],
    cluster_cidrs: list[str],
) -> None:
    # TCP MSS clamping
    lines.append(f'        iifname "{iface}" tcp flags syn tcp option maxseg size set rt mtu')
    lines.append(f'        oifname "{iface}" tcp flags syn tcp option maxseg size set rt mtu')

    # Strict NS8 cluster (`wg0`, `10.5.4.0/24`, loopback, Redis 6379) isolation
    for c_iface in cluster_ifaces:
        lines.append(f'        iifname "{iface}" oifname "{c_iface}" drop')
        lines.append(f'        iifname "{c_iface}" oifname "{iface}" drop')
    for c_cidr in cluster_cidrs:
        lines.append(f'        iifname "{iface}" ip daddr {c_cidr} drop')
        lines.append(f'        oifname "{iface}" ip saddr {c_cidr} drop')
    lines.append(f'        iifname "{iface}" ip daddr 127.0.0.0/8 drop')
    lines.append(f'        iifname "{iface}" tcp dport 6379 drop')

    # Allow routing into active Site-to-Site remote CIDRs before roadwarrior peer-to-peer drop
    for s2s_cidr in s2s_dest_cidrs:
        lines.append(f'        oifname "{iface}" ip daddr {s2s_cidr} accept')

    # Isolate direct roadwarrior peer-to-peer traffic on same interface
    lines.append(f'        iifname "{iface}" oifname "{iface}" drop')

    _append_source_guard_rule(
        lines,
        iface=iface,
        allowed_src_cidrs=allowed_src_cidrs,
        primary_net_str=primary_net_str,
        src_guard_chain=src_guard_chain,
    )

    # Stateful return traffic
    lines.append(f'        oifname "{iface}" ct state established,related accept')
    lines.append(f'        iifname "{iface}" ct state established,related accept')

    if tunnel_mode == "split":
        lines.append(f'        iifname "{iface}" ip daddr {server_ip} accept')
        for dns_ip in clean_dns:
            lines.append(f'        iifname "{iface}" ip daddr {dns_ip} udp dport 53 accept')
            lines.append(f'        iifname "{iface}" ip daddr {dns_ip} tcp dport 53 accept')
        combined_dest = list(dict.fromkeys([*allowed_dest_cidrs, *s2s_dest_cidrs]))
        for dest_cidr in combined_dest:
            lines.append(f'        iifname "{iface}" ip daddr {dest_cidr} accept')
        # Drop any unauthorized destination (defeats client-side AllowedIPs/route tampering)
        lines.append(f'        iifname "{iface}" drop')
    else:
        lines.append(f'        iifname "{iface}" ip saddr {primary_net_str} accept')
        for s2s_cidr in s2s_dest_cidrs:
            lines.append(f'        iifname "{iface}" ip saddr {s2s_cidr} accept')
        lines.append(f'        iifname "{iface}" drop')


def build_nft_ruleset(
    *,
    module_id: str,
    interface_name: str,
    wg_network: str,
    tunnel_mode: str,
    allowed_cidrs: list[str],
    dns_servers: list[str],
    nat_enabled: bool = True,
    ovpn_enabled: bool = False,
    ovpn_interface_name: str = "",
    ovpn_network: str = "",
    s2s_remote_cidrs: list[str] | None = None,
    cluster_wg_cidr: str = DEFAULT_CLUSTER_WG_CIDR,
    cluster_wg_interface: str = CLUSTER_RESERVED_INTERFACE,
    cluster_wg_port: int = DEFAULT_CLUSTER_WG_PORT,
) -> str:
    """Build per-instance `table inet ns8_vpn_${MODULE_ID}` ruleset (validated by Linux `nft -c -f -`).

    NEVER emits `flush ruleset` and NEVER uses `iifname` in `postrouting` (which the
    Linux kernel `nf_tables` hook validator rejects with `EOPNOTSUPP`).
    """
    _guard_not_cluster_interface(interface_name)
    table_name = derive_nft_table_name(module_id)
    wg_net = normalize_wg_network(wg_network, cluster_wg_cidr=cluster_wg_cidr)
    wg_server_ip = get_server_tunnel_ip(str(wg_net))
    clean_cidrs = normalize_allowed_cidrs(
        allowed_cidrs, str(wg_net), cluster_wg_cidr=cluster_wg_cidr
    )
    clean_dns = normalize_dns_servers(dns_servers, cluster_wg_cidr=cluster_wg_cidr)
    clean_s2s: list[str] = []
    for raw_s2s in s2s_remote_cidrs or []:
        s_net = normalize_wg_network(raw_s2s, cluster_wg_cidr=cluster_wg_cidr)
        s_str = str(s_net)
        if s_str not in clean_s2s:
            clean_s2s.append(s_str)

    ovpn_net_str = ""
    ovpn_server_ip = ""
    if ovpn_enabled:
        _guard_not_cluster_interface(ovpn_interface_name)
        ovpn_net = normalize_wg_network(ovpn_network, cluster_wg_cidr=cluster_wg_cidr)
        ovpn_net_str = str(ovpn_net)
        ovpn_server_ip = get_server_tunnel_ip(ovpn_net_str)

    cluster_cidrs = [DEFAULT_CLUSTER_WG_CIDR]
    if cluster_wg_cidr and cluster_wg_cidr not in cluster_cidrs:
        cluster_cidrs.append(cluster_wg_cidr)
    cluster_ifaces = [CLUSTER_RESERVED_INTERFACE]
    if cluster_wg_interface and cluster_wg_interface not in cluster_ifaces:
        cluster_ifaces.append(cluster_wg_interface)

    wg_allowed_sources = [str(wg_net), *clean_s2s]
    wg_src_guard_chain = (
        f"src_guard_{_sanitize_chain_suffix(interface_name)}"
        if len(wg_allowed_sources) > 1
        else None
    )

    lines: list[str] = [
        f"table inet {table_name} {{",
    ]

    if wg_src_guard_chain:
        lines.append(f"    chain {wg_src_guard_chain} {{")
        for src_cidr in wg_allowed_sources:
            lines.append(f"        ip saddr {src_cidr} return")
        lines.append("        drop")
        lines.append("    }")
        lines.append("")

    lines.extend(
        [
            "    chain input {",
            "        type filter hook input priority -10; policy accept;",
        ]
    )

    _append_tunnel_input_rules(
        lines,
        iface=interface_name,
        allowed_src_cidrs=wg_allowed_sources,
        primary_net_str=str(wg_net),
        src_guard_chain=wg_src_guard_chain,
        server_ip=wg_server_ip,
        tunnel_mode=tunnel_mode,
        clean_cidrs=clean_cidrs,
        clean_dns=clean_dns,
        cluster_cidrs=cluster_cidrs,
        cluster_wg_port=cluster_wg_port,
    )
    if ovpn_enabled and ovpn_interface_name and ovpn_net_str:
        _append_tunnel_input_rules(
            lines,
            iface=ovpn_interface_name,
            allowed_src_cidrs=[ovpn_net_str],
            primary_net_str=ovpn_net_str,
            src_guard_chain=None,
            server_ip=ovpn_server_ip,
            tunnel_mode=tunnel_mode,
            clean_cidrs=clean_cidrs,
            clean_dns=clean_dns,
            cluster_cidrs=cluster_cidrs,
            cluster_wg_port=cluster_wg_port,
        )

    lines.extend(
        [
            "    }",
            "",
            "    chain forward {",
            "        type filter hook forward priority -10; policy accept;",
        ]
    )

    _append_tunnel_forward_rules(
        lines,
        iface=interface_name,
        allowed_src_cidrs=wg_allowed_sources,
        primary_net_str=str(wg_net),
        src_guard_chain=wg_src_guard_chain,
        server_ip=wg_server_ip,
        tunnel_mode=tunnel_mode,
        allowed_dest_cidrs=clean_cidrs,
        s2s_dest_cidrs=clean_s2s,
        clean_dns=clean_dns,
        cluster_ifaces=cluster_ifaces,
        cluster_cidrs=cluster_cidrs,
    )
    if ovpn_enabled and ovpn_interface_name and ovpn_net_str:
        _append_tunnel_forward_rules(
            lines,
            iface=ovpn_interface_name,
            allowed_src_cidrs=[ovpn_net_str],
            primary_net_str=ovpn_net_str,
            src_guard_chain=None,
            server_ip=ovpn_server_ip,
            tunnel_mode=tunnel_mode,
            allowed_dest_cidrs=clean_cidrs,
            s2s_dest_cidrs=clean_s2s,
            clean_dns=clean_dns,
            cluster_ifaces=cluster_ifaces,
            cluster_cidrs=cluster_cidrs,
        )

    lines.extend(
        [
            "    }",
            "",
            "    chain postrouting {",
            "        type nat hook postrouting priority srcnat; policy accept;",
        ]
    )
    if nat_enabled:
        lines.append(
            f'        oifname != "{interface_name}" oifname != "lo" ip saddr {wg_net} masquerade'
        )
        for s2s_cidr in clean_s2s:
            lines.append(
                f'        oifname != "{interface_name}" oifname != "lo" ip saddr {s2s_cidr} masquerade'
            )
        if ovpn_enabled and ovpn_interface_name and ovpn_net_str:
            lines.append(
                f'        oifname != "{ovpn_interface_name}" oifname != "lo" ip saddr {ovpn_net_str} masquerade'
            )

    lines.extend(
        [
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


class FirewallEngine:
    """Applies IPv4 forwarding sysctl and isolated per-instance nftables rules."""

    def __init__(
        self,
        runner: CommandRunner,
        module_id: str,
        cluster_wg_cidr: str = DEFAULT_CLUSTER_WG_CIDR,
        cluster_wg_interface: str = CLUSTER_RESERVED_INTERFACE,
        cluster_wg_port: int = DEFAULT_CLUSTER_WG_PORT,
    ) -> None:
        self.runner = runner
        self.module_id = module_id
        self.cluster_wg_cidr = cluster_wg_cidr
        self.cluster_wg_interface = cluster_wg_interface
        self.cluster_wg_port = cluster_wg_port

    def enable_ip_forwarding(self) -> None:
        """Enable `net.ipv4.ip_forward=1` in kernel."""
        self.runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)

    def apply_firewall(
        self,
        *,
        interface_name: str,
        wg_network: str,
        tunnel_mode: str,
        allowed_cidrs: list[str],
        dns_servers: list[str],
        nat_enabled: bool = True,
        ovpn_enabled: bool = False,
        ovpn_interface_name: str = "",
        ovpn_network: str = "",
        s2s_remote_cidrs: list[str] | None = None,
    ) -> str:
        """Enable forwarding and replace `table inet ns8_vpn_${MODULE_ID}` cleanly."""
        self.enable_ip_forwarding()
        table_name = derive_nft_table_name(self.module_id)
        ruleset = build_nft_ruleset(
            module_id=self.module_id,
            interface_name=interface_name,
            wg_network=wg_network,
            tunnel_mode=tunnel_mode,
            allowed_cidrs=allowed_cidrs,
            dns_servers=dns_servers,
            nat_enabled=nat_enabled,
            ovpn_enabled=ovpn_enabled,
            ovpn_interface_name=ovpn_interface_name,
            ovpn_network=ovpn_network,
            s2s_remote_cidrs=s2s_remote_cidrs,
            cluster_wg_cidr=self.cluster_wg_cidr,
            cluster_wg_interface=self.cluster_wg_interface,
            cluster_wg_port=self.cluster_wg_port,
        )
        self.runner.run(["nft", "delete", "table", "inet", table_name], check=False)
        self.runner.run(["nft", "-f", "-"], stdin=ruleset)
        return ruleset

    def cleanup_firewall(self) -> None:
        """Delete only this module's nftables table."""
        table_name = derive_nft_table_name(self.module_id)
        self.runner.run(["nft", "delete", "table", "inet", table_name], check=False)
