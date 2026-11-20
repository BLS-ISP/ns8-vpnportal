"""Unit tests for WireGuard interface engine, dump parser, `.conf` renderer, and QR SVG generator."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from container.app.crypto import generate_wg_keypair, generate_wg_psk
from container.app.wireguard import (
    DryRunCommandRunner,
    WireGuardEngine,
    parse_wg_dump,
    render_client_config,
    render_qr_svg_data_uri,
)


def test_wireguard_idempotent_reconcile_and_instant_remove(tmp_path: Path) -> None:
    runner = DryRunCommandRunner()
    engine = WireGuardEngine(runner, run_dir=tmp_path)
    srv_priv, _ = generate_wg_keypair()
    _, peer_pub = generate_wg_keypair()
    peer_psk = generate_wg_psk()

    # First run creates wg-vpn1, sets IP, applies setconf, brings link up
    engine.reconcile_interface(
        interface_name="wg-vpn1",
        server_private_key=srv_priv,
        wg_port=51820,
        wg_network="10.199.0.0/24",
        wg_mtu=1380,
        active_peers=[
            {
                "public_key": peer_pub,
                "preshared_key": peer_psk,
                "assigned_ip": "10.199.0.2",
            }
        ],
    )

    assert engine.is_interface_up("wg-vpn1") is True
    assert "wg-vpn1" in runner.last_setconf
    assert f"PublicKey = {peer_pub}" in runner.last_setconf["wg-vpn1"]
    assert f"PresharedKey = {peer_psk}" in runner.last_setconf["wg-vpn1"]
    assert "AllowedIPs = 10.199.0.2/32" in runner.last_setconf["wg-vpn1"]
    # Verify temporary setconf file was deleted after `wg setconf`
    assert list(tmp_path.glob("*.conf")) == []

    add_cmds_first = [c for c, _ in runner.commands if c[:3] == ["ip", "link", "add"]]
    assert len(add_cmds_first) == 1

    # Second run is idempotent: does NOT call `ip link add` again
    engine.reconcile_interface(
        interface_name="wg-vpn1",
        server_private_key=srv_priv,
        wg_port=51820,
        wg_network="10.199.0.0/24",
        wg_mtu=1380,
        active_peers=[
            {
                "public_key": peer_pub,
                "preshared_key": peer_psk,
                "assigned_ip": "10.199.0.2",
            }
        ],
    )
    add_cmds_second = [c for c, _ in runner.commands if c[:3] == ["ip", "link", "add"]]
    assert len(add_cmds_second) == 1

    # Instant removal via `wg set wg-vpn1 peer <pubkey> remove`
    engine.remove_peer_immediately("wg-vpn1", peer_pub)
    assert (["wg", "set", "wg-vpn1", "peer", peer_pub, "remove"], None) in runner.commands
    assert peer_pub not in runner.peers_by_iface["wg-vpn1"]


def test_wireguard_never_touches_cluster_wg0() -> None:
    runner = DryRunCommandRunner()
    engine = WireGuardEngine(runner)

    with pytest.raises(ValueError, match="wg0"):
        engine.is_interface_up("wg0")
    with pytest.raises(ValueError, match="wg0"):
        engine.remove_peer_immediately("wg0", "PUBKEY")
    with pytest.raises(ValueError, match="wg0"):
        engine.reconcile_interface(
            interface_name="wg0",
            server_private_key="PRIV",
            wg_port=51820,
            wg_network="10.199.0.0/24",
            wg_mtu=1380,
            active_peers=[],
        )


def test_parse_wg_dump_online_and_offline_calculation() -> None:
    now = 1_760_000_200
    recent_hs = now - 45    # < 180s -> online
    stale_hs = now - 300    # >= 180s -> offline

    dump_text = "\n".join(
        [
            "SRV_PRIV\tSRV_PUB\t51820\toff",
            f"PEER_ONLINE\t(none)\t198.51.100.12:61234\t10.199.0.2/32\t{recent_hs}\t123456\t654321\t25",
            f"PEER_STALE\t(none)\t198.51.100.99:50000\t10.199.0.3/32\t{stale_hs}\t500\t900\t25",
            "PEER_NEVER\t(none)\t(none)\t10.199.0.4/32\t0\t0\t0\toff",
        ]
    )

    parsed = parse_wg_dump(dump_text, now_epoch=now)
    assert set(parsed.keys()) == {"PEER_ONLINE", "PEER_STALE", "PEER_NEVER"}

    assert parsed["PEER_ONLINE"]["online"] is True
    assert parsed["PEER_ONLINE"]["rx_bytes"] == 123456
    assert parsed["PEER_ONLINE"]["tx_bytes"] == 654321
    assert parsed["PEER_ONLINE"]["endpoint"] == "198.51.100.12:61234"
    assert parsed["PEER_ONLINE"]["handshake_iso"] is not None

    assert parsed["PEER_STALE"]["online"] is False
    assert parsed["PEER_STALE"]["handshake_iso"] is not None

    assert parsed["PEER_NEVER"]["online"] is False
    assert parsed["PEER_NEVER"]["endpoint"] is None
    assert parsed["PEER_NEVER"]["handshake_iso"] is None


def test_render_client_config_split_vs_full_and_qr_svg() -> None:
    cli_priv, _ = generate_wg_keypair()
    _, srv_pub = generate_wg_keypair()
    psk = generate_wg_psk()

    split_conf = render_client_config(
        client_private_key=cli_priv,
        assigned_ip="10.199.0.5",
        server_public_key=srv_pub,
        preshared_key=psk,
        endpoint_host="vpn.firma.de",
        wg_port=51820,
        wg_network="10.199.0.0/24",
        tunnel_mode="split",
        allowed_cidrs=["192.168.178.0/24", "10.20.0.0/16"],
        dns_servers=["192.168.178.10"],
        dns_search_domain="ad.firma.de",
        wg_mtu=1380,
        persistent_keepalive=25,
    )
    assert "\r" not in split_conf
    assert f"PrivateKey = {cli_priv}" in split_conf
    assert "Address = 10.199.0.5/32" in split_conf
    assert "DNS = 192.168.178.10, ad.firma.de" in split_conf
    assert "MTU = 1380" in split_conf
    assert f"PublicKey = {srv_pub}" in split_conf
    assert f"PresharedKey = {psk}" in split_conf
    assert (
        "AllowedIPs = 192.168.178.0/24, 10.20.0.0/16, 10.199.0.1/32, 192.168.178.10/32"
        in split_conf
    )
    assert "Endpoint = vpn.firma.de:51820" in split_conf
    assert "PersistentKeepalive = 25" in split_conf

    full_conf = render_client_config(
        client_private_key=cli_priv,
        assigned_ip="10.199.0.5",
        server_public_key=srv_pub,
        preshared_key=psk,
        endpoint_host="2001:db8::1",
        wg_port=51820,
        wg_network="10.199.0.0/24",
        tunnel_mode="full",
        allowed_cidrs=["192.168.178.0/24"],
        dns_servers=["9.9.9.9"],
        dns_search_domain="",
        wg_mtu=1380,
        persistent_keepalive=25,
    )
    assert "AllowedIPs = 0.0.0.0/0" in full_conf
    assert "Endpoint = [2001:db8::1]:51820" in full_conf

    qr_data_uri = render_qr_svg_data_uri(split_conf)
    assert qr_data_uri.startswith("data:image/svg+xml;base64,")
    svg_bytes = base64.b64decode(qr_data_uri.split(",", 1)[1])
    assert b"<svg" in svg_bytes
