"""Unit tests for isolated nftables ruleset generation and kernel IPv4 forwarding (`firewall.py`)."""

from __future__ import annotations

import pytest

from container.app.firewall import FirewallEngine, build_nft_ruleset
from container.app.wireguard import DryRunCommandRunner


def test_split_tunnel_nft_ruleset_isolation_mss_and_nat() -> None:
    runner = DryRunCommandRunner()
    fw = FirewallEngine(runner=runner, module_id="vpn-1&test")

    ruleset = fw.apply_firewall(
        interface_name="wg-vpn1",
        wg_network="10.199.0.0/24",
        tunnel_mode="split",
        allowed_cidrs=["192.168.10.0/24", "172.20.0.0/16"],
        dns_servers=["192.168.10.5"],
        nat_enabled=True,
    )

    assert runner.sysctls.get("net.ipv4.ip_forward") == "1"
    assert runner.last_nft_ruleset == ruleset

    # Strictly manages ONLY its own sanitized table, NEVER global `flush ruleset`
    assert "flush ruleset" not in ruleset
    assert "table inet ns8_vpn_vpn_1_test {}" in ruleset
    assert "delete table inet ns8_vpn_vpn_1_test" in ruleset
    assert "table inet ns8_vpn_vpn_1_test {" in ruleset

    # TCP MSS clamping
    assert 'iifname "wg-vpn1" tcp flags syn tcp option maxseg size set rt mtu' in ruleset
    assert 'oifname "wg-vpn1" tcp flags syn tcp option maxseg size set rt mtu' in ruleset

    # Strict NS8 cluster (`wg0`, `10.5.4.0/24`, loopback, Redis 6379) drops
    assert 'iifname "wg-vpn1" oifname "wg0" drop' in ruleset
    assert 'iifname "wg-vpn1" ip daddr 10.5.4.0/24 drop' in ruleset
    assert 'iifname "wg-vpn1" ip daddr 127.0.0.0/8 drop' in ruleset
    assert 'iifname "wg-vpn1" tcp dport 6379 drop' in ruleset

    # Server-side Split-Tunnel allowlist + final unauthorized destination drop
    assert 'iifname "wg-vpn1" ip daddr 10.199.0.1 accept' in ruleset
    assert 'iifname "wg-vpn1" ip daddr { 192.168.10.5 } udp dport 53 accept' in ruleset
    assert 'iifname "wg-vpn1" ip daddr { 192.168.10.5 } tcp dport 53 accept' in ruleset
    assert 'iifname "wg-vpn1" ip daddr { 192.168.10.0/24, 172.20.0.0/16 } accept' in ruleset
    assert 'iifname "wg-vpn1" drop' in ruleset
    assert 'iifname "wg-vpn1" ip saddr 10.199.0.0/24 accept' not in ruleset

    # Conditional SNAT / Masquerade enabled
    assert (
        'iifname "wg-vpn1" oifname != "wg-vpn1" ip saddr 10.199.0.0/24 masquerade'
        in ruleset
    )


def test_full_tunnel_and_nat_disabled() -> None:
    ruleset = build_nft_ruleset(
        module_id="vpn1",
        interface_name="wg-vpn1",
        wg_network="10.199.0.0/24",
        tunnel_mode="full",
        allowed_cidrs=[],
        dns_servers=["9.9.9.9"],
        nat_enabled=False,
        cluster_wg_cidr="10.5.99.0/24",
    )

    # Full tunnel allows general non-cluster forwarding from wg_network
    assert 'iifname "wg-vpn1" ip saddr 10.199.0.0/24 accept' in ruleset
    # Still strictly drops both default 10.5.4.0/24 AND custom cluster_wg_cidr + wg0 + Redis 6379
    assert 'iifname "wg-vpn1" oifname "wg0" drop' in ruleset
    assert 'iifname "wg-vpn1" ip daddr 10.5.4.0/24 drop' in ruleset
    assert 'iifname "wg-vpn1" ip daddr 10.5.99.0/24 drop' in ruleset
    assert 'iifname "wg-vpn1" tcp dport 6379 drop' in ruleset

    # Masquerade omitted when nat_enabled=False
    assert "masquerade" not in ruleset


def test_firewall_rejects_cluster_interface_wg0() -> None:
    with pytest.raises(ValueError, match="wg0"):
        build_nft_ruleset(
            module_id="vpn1",
            interface_name="wg0",
            wg_network="10.199.0.0/24",
            tunnel_mode="split",
            allowed_cidrs=[],
            dns_servers=[],
        )
