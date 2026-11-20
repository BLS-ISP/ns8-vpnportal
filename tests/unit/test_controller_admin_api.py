"""End-to-end unit tests for the FastAPI Unix-Socket `admin_api` and isolated `portal_api`."""

from __future__ import annotations

import time

import httpx
import pytest

from container.app.admin_api import VPNControllerService, create_admin_app
from container.app.portal_api import create_portal_app
from container.app.portal_auth import SESSION_COOKIE_NAME
from container.app.wireguard import DryRunCommandRunner


@pytest.mark.asyncio
async def test_admin_api_full_lifecycle_and_exact_contracts(
    controller_service: VPNControllerService,
    dry_runner: DryRunCommandRunner,
) -> None:
    admin_app = create_admin_app(controller_service)
    transport = httpx.ASGITransport(app=admin_app)

    async with httpx.AsyncClient(transport=transport, base_url="http://admin.local") as client:
        # 1. GET /api/v1/admin/health
        r_health = await client.get("/api/v1/admin/health")
        assert r_health.status_code == 200
        health = r_health.json()
        assert health == {
            "status": "ok",
            "module_id": "vpn1",
            "interface": "wg-vpn1",
            "interface_up": True,
        }

        # 2. GET /api/v1/admin/config
        r_cfg = await client.get("/api/v1/admin/config")
        assert r_cfg.status_code == 200
        cfg = r_cfg.json()
        expected_cfg_keys = {
            "configured",
            "endpoint_host",
            "wg_port",
            "wg_network",
            "tunnel_mode",
            "allowed_cidrs",
            "dns_servers",
            "dns_search_domain",
            "wg_mtu",
            "persistent_keepalive",
            "nat_enabled",
            "user_domain",
            "vpn_group",
            "max_devices_per_user",
            "sync_interval_minutes",
            "portal_enabled",
            "portal_domain",
            "portal_lets_encrypt",
            "portal_http2https",
            "portal_totp_mode",
            "ovpn_enabled",
            "ovpn_proto",
            "ovpn_port",
            "ovpn_public_port",
            "ovpn_network",
            "ovpn_totp_required",
            "ovpn_interface_name",
            "server_public_key",
            "interface_name",
            "summary",
        }
        assert set(cfg.keys()) == expected_cfg_keys
        assert set(cfg["summary"].keys()) == {
            "authorized_users",
            "total_peers",
            "active_peers",
            "online_peers",
            "online_ovpn_clients",
            "s2s_tunnels",
            "active_s2s_tunnels",
            "last_synced_at",
            "last_sync_status",
            "last_sync_error",
        }

        # 3. PUT /api/v1/admin/config rejects NS8 cluster port 55820 and subnet 10.5.4.0/24
        r_bad_port = await client.put("/api/v1/admin/config", json={"wg_port": 55820})
        assert r_bad_port.status_code == 400
        r_bad_net = await client.put("/api/v1/admin/config", json={"wg_network": "10.5.4.0/24"})
        assert r_bad_net.status_code == 400

        # Valid PUT /api/v1/admin/config
        r_upd = await client.put(
            "/api/v1/admin/config",
            json={
                "endpoint_host": "vpn.firma.example",
                "wg_port": 51821,
                "wg_network": "10.199.0.0/24",
                "tunnel_mode": "split",
                "allowed_cidrs": ["192.168.50.0/24"],
                "dns_servers": ["192.168.50.10"],
                "dns_search_domain": "firma.example",
                "max_devices_per_user": 2,
                "user_domain": "firma.example",
                "vpn_group": "vpn-users",
            },
        )
        assert r_upd.status_code == 200
        upd = r_upd.json()
        assert upd["configured"] is True
        assert upd["wg_port"] == 51821
        assert upd["allowed_cidrs"] == ["192.168.50.0/24"]
        assert "192.168.50.0/24" in dry_runner.last_nft_ruleset

        # 4. POST /api/v1/admin/reconcile (empty body AND JSON body) & POST /api/v1/admin/sync
        r_rec = await client.post("/api/v1/admin/reconcile")
        assert r_rec.status_code == 200
        assert r_rec.json()["status"] == "ok"
        assert r_rec.json()["config"]["wg_port"] == 51821

        r_sync = await client.post("/api/v1/admin/sync")
        assert r_sync.status_code == 200
        assert r_sync.json()["status"] == "skipped"

        # Seed synced users in DB (1 authorized, 1 unauthorized)
        controller_service.db.upsert_user(
            username="m.mueller",
            domain="firma.example",
            display_name="Max Müller",
            email="max@firma.example",
            ldap_active=True,
            in_vpn_group=True,
        )
        controller_service.db.upsert_user(
            username="disabled.user",
            domain="firma.example",
            display_name="Disabled User",
            email="disabled@firma.example",
            ldap_active=False,
            in_vpn_group=True,
        )

        # 5. POST /api/v1/admin/peers rejects unlisted, unauthorized, and malformed device_name
        r_unlisted = await client.post(
            "/api/v1/admin/peers",
            json={"username": "ghost", "device_name": "Laptop"},
        )
        assert r_unlisted.status_code == 403

        r_unauth = await client.post(
            "/api/v1/admin/peers",
            json={"username": "disabled.user", "device_name": "Laptop"},
        )
        assert r_unauth.status_code == 403

        r_bad_dev = await client.post(
            "/api/v1/admin/peers",
            json={"username": "m.mueller", "device_name": "<script>bad</script>"},
        )
        assert r_bad_dev.status_code == 400

        # Create valid peer 1 (German umlaut in device_name!)
        r_p1 = await client.post(
            "/api/v1/admin/peers",
            json={"username": "m.mueller", "device_name": "Büro-Laptop"},
        )
        assert r_p1.status_code == 200
        p1_body = r_p1.json()
        peer1 = p1_body["peer"]
        assert peer1["assigned_ip"] == "10.199.0.2"
        assert peer1["effective_active"] is True
        assert "Endpoint = vpn.firma.example:51821" in p1_body["config_text"]
        assert p1_body["qr_svg_data_uri"].startswith("data:image/svg+xml;base64,")

        # Create peer 2 and verify enforce_limit=True blocks 3rd device (max_devices_per_user == 2)
        r_p2 = await client.post(
            "/api/v1/admin/peers",
            json={"username": "m.mueller", "device_name": "iPhone 16", "enforce_limit": True},
        )
        assert r_p2.status_code == 200
        assert r_p2.json()["peer"]["assigned_ip"] == "10.199.0.3"

        r_p3_blocked = await client.post(
            "/api/v1/admin/peers",
            json={"username": "m.mueller", "device_name": "iPad", "enforce_limit": True},
        )
        assert r_p3_blocked.status_code == 400

        # Simulate live WireGuard handshake & traffic on peer 1
        now_ts = int(time.time())
        dry_runner.mock_dump_output["wg-vpn1"] = (
            f"SRV_PRIV\tSRV_PUB\t51821\toff\n"
            f"{peer1['public_key']}\tPSK\t80.150.10.20:51234\t10.199.0.2/32\t{now_ts - 15}\t4096\t8192\t25\n"
        )

        # 6. GET /api/v1/admin/peers
        r_list = await client.get("/api/v1/admin/peers")
        assert r_list.status_code == 200
        listed = r_list.json()
        assert listed["summary"] == {
            "authorized_users": 1,
            "total_peers": 2,
            "active_peers": 2,
            "online_peers": 1,
            "max_devices_per_user": 2,
        }
        p1_live = next(p for p in listed["peers"] if p["id"] == peer1["id"])
        assert p1_live["online"] is True
        assert p1_live["rx_bytes"] == 4096
        assert p1_live["tx_bytes"] == 8192
        assert p1_live["last_endpoint"] == "80.150.10.20:51234"

        # 7. GET /api/v1/admin/peers/{peer_id}/config
        r_p1_cfg = await client.get(f"/api/v1/admin/peers/{peer1['id']}/config")
        assert r_p1_cfg.status_code == 200
        assert r_p1_cfg.json()["config_text"] == p1_body["config_text"]

        # 8. POST /api/v1/admin/peers/{peer_id}/toggle (disable -> immediate kernel removal)
        dry_runner.commands.clear()
        r_toggle_off = await client.post(
            f"/api/v1/admin/peers/{peer1['id']}/toggle",
            json={"enabled": False},
        )
        assert r_toggle_off.status_code == 200
        toggled_off = r_toggle_off.json()["peer"]
        assert toggled_off["admin_enabled"] is False
        assert toggled_off["effective_active"] is False
        assert toggled_off["online"] is False
        assert (
            ["wg", "set", "wg-vpn1", "peer", peer1["public_key"], "remove"],
            None,
        ) in dry_runner.commands

        # Re-enable peer 1
        r_toggle_on = await client.post(
            f"/api/v1/admin/peers/{peer1['id']}/toggle",
            json={"enabled": True},
        )
        assert r_toggle_on.status_code == 200
        assert r_toggle_on.json()["peer"]["effective_active"] is True

        # 9. DELETE /api/v1/admin/peers/{peer_id} -> revokes peer & frees 10.199.0.2
        dry_runner.commands.clear()
        r_del = await client.delete(f"/api/v1/admin/peers/{peer1['id']}")
        assert r_del.status_code == 200
        assert r_del.json() == {"revoked": True, "peer_id": peer1["id"]}
        assert (
            ["wg", "set", "wg-vpn1", "peer", peer1["public_key"], "remove"],
            None,
        ) in dry_runner.commands

        r_gone = await client.get(f"/api/v1/admin/peers/{peer1['id']}/config")
        assert r_gone.status_code == 404

        # Next created peer reclaims freed 10.199.0.2!
        r_reclaim = await client.post(
            "/api/v1/admin/peers",
            json={"username": "m.mueller", "device_name": "New-Laptop"},
        )
        assert r_reclaim.status_code == 200
        assert r_reclaim.json()["peer"]["assigned_ip"] == "10.199.0.2"


@pytest.mark.asyncio
async def test_portal_tcp_app_strictly_exposes_no_admin_routes(
    controller_service: VPNControllerService,
) -> None:
    portal_app = create_portal_app(controller_service)
    transport = httpx.ASGITransport(app=portal_app)

    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as client:
        r_health = await client.get("/healthz")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "ok"

        # Every privileged admin route MUST return 404 on the TCP portal listener!
        for admin_path in (
            "/api/v1/admin/health",
            "/api/v1/admin/config",
            "/api/v1/admin/peers",
            "/api/v1/admin/sync",
            "/api/v1/admin/reconcile",
            "/api/v1/admin/audit-logs",
        ):
            resp_get = await client.get(admin_path)
            resp_post = await client.post(admin_path)
            assert resp_get.status_code == 404
            assert resp_post.status_code == 404


@pytest.mark.asyncio
async def test_admin_audit_logs_filtering_retention_and_static_peer_ip(
    controller_service: VPNControllerService,
) -> None:
    admin_app = create_admin_app(controller_service)
    portal_app = create_portal_app(controller_service)

    controller_service.db.upsert_user(
        username="s.schmidt",
        domain="firma.example",
        display_name="Sabine Schmidt",
        email="sabine@firma.example",
        ldap_active=True,
        in_vpn_group=True,
    )
    controller_service.db.upsert_user(
        username="t.weber",
        domain="firma.example",
        display_name="Thomas Weber",
        email="thomas@firma.example",
        ldap_active=True,
        in_vpn_group=True,
    )
    controller_service.db.update_server_config(
        {
            "configured": True,
            "endpoint_host": "vpn.firma.example",
            "wg_network": "10.199.0.0/24",
            "portal_enabled": True,
            "portal_totp_mode": "disabled",
            "max_devices_per_user": 5,
        }
    )

    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=admin_app),
            base_url="http://admin.local",
        ) as admin_client,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=portal_app),
            base_url="https://vpn.firma.example",
        ) as portal_client,
    ):
        # 1. Static VPN IP allocation via Admin API (`10.199.0.55`)
        r_static = await admin_client.post(
            "/api/v1/admin/peers",
            json={
                "username": "s.schmidt",
                "device_name": "Admin-Workstation",
                "assigned_ip": "10.199.0.55",
            },
        )
        assert r_static.status_code == 200
        assert r_static.json()["peer"]["assigned_ip"] == "10.199.0.55"
        assert "Address = 10.199.0.55/32" in r_static.json()["config_text"]

        # Empty/blank `assigned_ip` falls back to automatic lowest-free allocation (`10.199.0.2`)
        r_auto = await admin_client.post(
            "/api/v1/admin/peers",
            json={
                "username": "t.weber",
                "device_name": "Auto-Laptop",
                "assigned_ip": "   ",
            },
        )
        assert r_auto.status_code == 200
        assert r_auto.json()["peer"]["assigned_ip"] == "10.199.0.2"

        # 2. Collision with active peer IP -> 409 Conflict with clear message
        r_collision = await admin_client.post(
            "/api/v1/admin/peers",
            json={
                "username": "t.weber",
                "device_name": "Duplicate-IP",
                "assigned_ip": "10.199.0.55",
            },
        )
        assert r_collision.status_code == 409
        assert "IP address '10.199.0.55' is already assigned" in r_collision.json()["detail"]

        # Collision with Site-to-Site tunnel IP -> 409 Conflict
        r_s2s = await admin_client.post(
            "/api/v1/admin/s2s",
            json={"name": "Branch-Berlin", "remote_cidrs": ["192.168.77.0/24"]},
        )
        assert r_s2s.status_code == 200
        s2s_ip = r_s2s.json()["tunnel"]["assigned_ip"]

        r_s2s_collision = await admin_client.post(
            "/api/v1/admin/peers",
            json={
                "username": "s.schmidt",
                "device_name": "S2S-Collision",
                "assigned_ip": s2s_ip,
            },
        )
        assert r_s2s_collision.status_code == 409

        # Out-of-range, server `.1`, network `.0`, broadcast `.255`, or invalid IP -> 400 Bad Request
        for invalid_ip in ("10.199.9.10", "10.199.0.1", "10.199.0.0", "10.199.0.255", "invalid-ip"):
            r_bad_ip = await admin_client.post(
                "/api/v1/admin/peers",
                json={
                    "username": "s.schmidt",
                    "device_name": "Bad-IP-Peer",
                    "assigned_ip": invalid_ip,
                },
            )
            assert r_bad_ip.status_code == 400, f"Expected 400 for {invalid_ip}"

        # Confirm Portal self-service ignores any spoofed `assigned_ip` field in JSON payload
        token = controller_service.session_manager.create_token("s.schmidt")
        portal_client.cookies.set(SESSION_COOKIE_NAME, token)
        r_portal_dev = await portal_client.post(
            "/api/v1/portal/devices",
            headers={"X-Requested-With": "NS8VPNPortal"},
            json={"device_name": "Portal-Phone", "assigned_ip": "10.199.0.200"},
        )
        assert r_portal_dev.status_code == 200
        assert r_portal_dev.json()["device"]["assigned_ip"] != "10.199.0.200"

        # Confirm `/api/v1/admin/audit-logs` is strictly 404 on `portal_api` even with valid session!
        r_portal_audit = await portal_client.get("/api/v1/admin/audit-logs")
        assert r_portal_audit.status_code == 404

        # 3. GET /api/v1/admin/audit-logs + filtering (`limit`, `event_type`, `username`)
        r_audit_all = await admin_client.get("/api/v1/admin/audit-logs")
        assert r_audit_all.status_code == 200
        audit_body = r_audit_all.json()
        assert audit_body["total"] >= 4
        assert len(audit_body["entries"]) == audit_body["total"]
        # Descending order by ID
        ids = [entry["id"] for entry in audit_body["entries"]]
        assert ids == sorted(ids, reverse=True)

        # Filter by username (case-insensitive) + event_type
        r_audit_filtered = await admin_client.get(
            "/api/v1/admin/audit-logs",
            params={"event_type": "peer_created", "username": "S.SCHMIDT"},
        )
        assert r_audit_filtered.status_code == 200
        filtered_body = r_audit_filtered.json()
        assert filtered_body["total"] == 2
        assert all(e["event_type"] == "peer_created" for e in filtered_body["entries"])
        assert all(e["username"] == "s.schmidt" for e in filtered_body["entries"])

        # Limit parameter caps `entries` while keeping `total` accurate
        r_audit_limited = await admin_client.get(
            "/api/v1/admin/audit-logs",
            params={"limit": 2},
        )
        assert r_audit_limited.status_code == 200
        assert len(r_audit_limited.json()["entries"]) == 2
        assert r_audit_limited.json()["total"] == audit_body["total"]

        # Query validation rejects out-of-bounds `limit`
        assert (await admin_client.get("/api/v1/admin/audit-logs?limit=0")).status_code == 422
        assert (await admin_client.get("/api/v1/admin/audit-logs?limit=1001")).status_code == 422

        # 4. Verify bounded SQLite retention pruning in `db.log_audit`
        assert controller_service.db.audit_log_max_rows == 10_000
        controller_service.db.audit_log_max_rows = 5
        for idx in range(8):
            controller_service.db.log_audit(
                event_type="retention_probe",
                actor="system",
                details=f"probe-{idx}",
            )
        retained_entries, retained_total = controller_service.db.list_audit_logs(limit=50)
        assert retained_total == 5
        assert len(retained_entries) == 5
        assert [e["details"] for e in retained_entries] == [
            "probe-7",
            "probe-6",
            "probe-5",
            "probe-4",
            "probe-3",
        ]
