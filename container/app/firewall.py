"""nftables firewall and kernel IPv4 forwarding manager for ns8-vpn (WireGuard + OpenVPN + S2S)."""

from __future__ import annotations

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


def _format_nft_set(items: list[str]) -> str:
    return "{ " + ", ".join(items) + " }"


def _append_tunnel_input_rules(
    lines: list[str],
    *,
    iface: str,
    allowed_src_cidrs: list[str],
    primary_net_str: str,
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
    if len(allowed_src_cidrs) == 1:
        lines.append(f'        iifname "{iface}" ip saddr != {primary_net_str} drop')
    else:
        lines.append(
            f'        iifname "{iface}" ip saddr != {_format_nft_set(allowed_src_cidrs)} drop'
        )
    lines.append(f'        iifname "{iface}" ct state established,related accept')
    lines.append(f'        iifname "{iface}" ip daddr {server_ip} accept')

    if clean_dns:
        dns_set = _format_nft_set(clean_dns)
        lines.append(f'        iifname "{iface}" ip daddr {dns_set} udp dport 53 accept')
        lines.append(f'        iifname "{iface}" ip daddr {dns_set} tcp dport 53 accept')

    if tunnel_mode == "split":
        if clean_cidrs:
            cidr_set = _format_nft_set(clean_cidrs)
            lines.append(f'        iifname "{iface}" ip daddr {cidr_set} accept')
        lines.append(f'        iifname "{iface}" drop')
    else:
        lines.append(f'        iifname "{iface}" accept')


def _append_tunnel_forward_rules(
    lines: list[str],
    *,
    iface: str,
    allowed_src_cidrs: list[str],
    primary_net_str: str,
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

    # Allow Hairpin/Routing into active Site-to-Site remote CIDRs before peer-to-peer drop
    if s2s_dest_cidrs:
        s2s_set = _format_nft_set(s2s_dest_cidrs)
        lines.append(
            f'        oifname "{iface}" ip daddr {s2s_set} accept'
        )

    # Isolate direct roadwarrior peer-to-peer traffic on same interface
    lines.append(f'        iifname "{iface}" oifname "{iface}" drop')

    if len(allowed_src_cidrs) == 1:
        lines.append(f'        iifname "{iface}" ip saddr != {primary_net_str} drop')
    else:
        lines.append(
            f'        iifname "{iface}" ip saddr != {_format_nft_set(allowed_src_cidrs)} drop'
        )

    # Stateful return traffic
    lines.append(f'        oifname "{iface}" ct state established,related accept')
    lines.append(f'        iifname "{iface}" ct state established,related accept')

    if tunnel_mode == "split":
        lines.append(f'        iifname "{iface}" ip daddr {server_ip} accept')
        if clean_dns:
            dns_set = _format_nft_set(clean_dns)
            lines.append(f'        iifname "{iface}" ip daddr {dns_set} udp dport 53 accept')
            lines.append(f'        iifname "{iface}" ip daddr {dns_set} tcp dport 53 accept')
        combined_dest = list(dict.fromkeys([*allowed_dest_cidrs, *s2s_dest_cidrs]))
        if combined_dest:
            cidr_set = _format_nft_set(combined_dest)
            lines.append(f'        iifname "{iface}" ip daddr {cidr_set} accept')
        # Drop any unauthorized destination (defeats client-side AllowedIPs/route tampering)
        lines.append(f'        iifname "{iface}" drop')
    else:
        lines.append(f'        iifname "{iface}" ip saddr {primary_net_str} accept')
        if s2s_dest_cidrs:
            lines.append(
                f'        iifname "{iface}" ip saddr {_format_nft_set(s2s_dest_cidrs)} accept'
            )
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
    """Build atomic nftables ruleset managing ONLY `table inet ns8_vpn_${MODULE_ID}`.

    NEVER emits `flush ruleset`. Uses idempotent create-then-delete-then-recreate
    within a single atomic `nft -f -` transaction, covering WireGuard, OpenVPN, and S2S.
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

    lines: list[str] = [
        f"table inet {table_name} {{}}",
        f"delete table inet {table_name}",
        f"table inet {table_name} {{",
        "    chain input {",
        "        type filter hook input priority -10; policy accept;",
    ]

    _append_tunnel_input_rules(
        lines,
        iface=interface_name,
        allowed_src_cidrs=wg_allowed_sources,
        primary_net_str=str(wg_net),
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
            f'        iifname "{interface_name}" oifname != "{interface_name}" ip saddr {wg_net} masquerade'
        )
        if clean_s2s:
            lines.append(
                f'        iifname "{interface_name}" oifname != "{interface_name}" ip saddr {_format_nft_set(clean_s2s)} masquerade'
            )
        if ovpn_enabled and ovpn_interface_name and ovpn_net_str:
            lines.append(
                f'        iifname "{ovpn_interface_name}" oifname != "{ovpn_interface_name}" ip saddr {ovpn_net_str} masquerade'
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
        """Enable forwarding and atomically apply `table inet ns8_vpn_${MODULE_ID}`."""
        self.enable_ip_forwarding()
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
        self.runner.run(["nft", "-f", "-"], stdin=ruleset)
        return ruleset

    def cleanup_firewall(self) -> None:
        """Delete only this module's nftables table."""
        table_name = derive_nft_table_name(self.module_id)
        script = f"table inet {table_name} {{}}\ndelete table inet {table_name}\n"
        self.runner.run(["nft", "-f", "-"], stdin=script, check=False)
