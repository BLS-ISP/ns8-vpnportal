"""Unit tests for Phase 3 WireGuard Site-to-Site branch office tunnels (`s2s.py` & `admin_api.py`)."""

from __future__ import annotations

import httpx
import pytest

from container.app.admin_api import VPNControllerService, create_admin_app
from container.app.crypto import generate_wg_keypair
from container.app.wireguard import DryRunCommandRunner


@pytest.mark.asyncio
async def test_site_to_site_lifecycle_routing_firewall_and_collision_guards(
    controller_service: VPNControllerService,
    dry_runner: DryRunCommandRunner,
) -> None:
    admin_app = create_admin_app(controller_service)
    transport = httpx.ASGITransport(app=admin_app)

    async with httpx.AsyncClient(transport=transport, base_url="http://admin.local") as client:
        # 1. Reject S2S remote_cidrs overlapping NS8 cluster (`10.5.4.0/24`) or `wg_network` (`10.199.0.0/24`)
        r_cluster_conflict = await client.post(
            "/api/v1/admin/s2s",
            json={"name": "Bad-Cluster", "remote_cidrs": ["10.5.4.0/24"]},
        )
        assert r_cluster_conflict.status_code == 400

        r_wg_conflict = await client.post(
            "/api/v1/admin/s2s",
            json={"name": "Bad-WG", "remote_cidrs": ["10.199.0.0/24"]},
        )
        assert r_wg_conflict.status_code == 400

        # 2. Create S2S tunnel with auto-generated FritzBox/router keypair
        r_create = await client.post(
            "/api/v1/admin/s2s",
            json={
                "name": "Filiale München",
                "remote_cidrs": ["192.168.90.0/24", "10.90.0.0/16"],
                "remote_endpoint": "muenchen.firma.example:51820",
            },
        )
        assert r_create.status_code == 200
        created = r_create.json()
        t1 = created["tunnel"]
        assert t1["name"] == "Filiale München"
        assert t1["assigned_ip"] == "10.199.0.2"
        assert t1["has_private_key"] is True
        assert t1["remote_cidrs"] == ["192.168.90.0/24", "10.90.0.0/16"]
        assert "PrivateKey =" in created["config_text"]
        assert "<INSERT_REMOTE_ROUTER_PRIVATE_KEY>" not in created["config_text"]
        assert "AllowedIPs = 10.199.0.1/32, 10.199.0.0/24, 192.168.10.0/24" in created["config_text"]

        # Verify `wg setconf`, kernel `ip route replace`, and `nftables` S2S forwarding rules
        setconf = dry_runner.last_setconf["wg-vpn1"]
        assert "AllowedIPs = 10.199.0.2/32, 192.168.90.0/24, 10.90.0.0/16" in setconf
        assert "Endpoint = muenchen.firma.example:51820" in setconf
        assert dry_runner.routes_by_iface["wg-vpn1"] == {"192.168.90.0/24", "10.90.0.0/16"}
        assert "192.168.90.0/24" in dry_runner.last_nft_ruleset
        assert 'iifname "wg-vpn1" oifname "wg0" drop' in dry_runner.last_nft_ruleset

        # 3. Reject overlapping CIDR on a second S2S tunnel, then create valid 2nd S2S with external public key
        r_dup_cidr = await client.post(
            "/api/v1/admin/s2s",
            json={"name": "Overlap-Branch", "remote_cidrs": ["192.168.90.128/25"]},
        )
        assert r_dup_cidr.status_code == 400

        _, ext_pub = generate_wg_keypair()
        r_t2 = await client.post(
            "/api/v1/admin/s2s",
            json={
                "name": "Standort Hamburg",
                "remote_cidrs": ["192.168.91.0/24"],
                "remote_public_key": ext_pub,
            },
        )
        assert r_t2.status_code == 200
        t2 = r_t2.json()["tunnel"]
        assert t2["has_private_key"] is False
        assert t2["assigned_ip"] == "10.199.0.3"

        r_t2_cfg = await client.get(f"/api/v1/admin/s2s/{t2['id']}/config")
        assert r_t2_cfg.status_code == 200
        assert r_t2_cfg.json()["has_private_key"] is False
        assert "<INSERT_REMOTE_ROUTER_PRIVATE_KEY>" in r_t2_cfg.json()["config_text"]

        # Verify summary counts in `GET /api/v1/admin/config` and `GET /api/v1/admin/s2s`
        r_cfg = await client.get("/api/v1/admin/config")
        assert r_cfg.json()["summary"]["s2s_tunnels"] == 2
        assert r_cfg.json()["summary"]["active_s2s_tunnels"] == 2

        r_list = await client.get("/api/v1/admin/s2s")
        assert len(r_list.json()["tunnels"]) == 2

        # 4. Toggle disable S2S tunnel 1 -> removes kernel peer & kernel routes immediately
        dry_runner.commands.clear()
        r_off = await client.post(
            f"/api/v1/admin/s2s/{t1['id']}/toggle",
            json={"enabled": False},
        )
        assert r_off.status_code == 200
        assert r_off.json()["tunnel"]["enabled"] is False
        assert (
            ["wg", "set", "wg-vpn1", "peer", t1["public_key"], "remove"],
            None,
        ) in dry_runner.commands
        assert dry_runner.routes_by_iface["wg-vpn1"] == {"192.168.91.0/24"}

        # Re-enable S2S tunnel 1 -> restores routes
        r_on = await client.post(
            f"/api/v1/admin/s2s/{t1['id']}/toggle",
            json={"enabled": True},
        )
        assert r_on.status_code == 200
        assert dry_runner.routes_by_iface["wg-vpn1"] == {
            "192.168.90.0/24",
            "10.90.0.0/16",
            "192.168.91.0/24",
        }

        # 5. Delete S2S tunnel 1 -> cleans up peer, routes, and frees IP 10.199.0.2
        r_del = await client.delete(f"/api/v1/admin/s2s/{t1['id']}")
        assert r_del.status_code == 200
        assert r_del.json() == {"deleted": True, "tunnel_id": t1["id"]}
        assert dry_runner.routes_by_iface["wg-vpn1"] == {"192.168.91.0/24"}
        assert "10.199.0.2" not in controller_service.db.get_used_ips()
