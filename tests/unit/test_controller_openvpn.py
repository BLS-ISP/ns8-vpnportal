"""Unit tests for Phase 3 OpenVPN PKI, TCP/UDP fallback server, live AD+TOTP auth, and instant session kill."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import httpx
import pyotp
import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from container.app.admin_api import create_admin_app
from container.app.config import Settings, derive_ovpn_interface_name
from container.app.openvpn import (
    DryRunOpenVPNController,
    OpenVPNEngine,
    detect_host_ipv6_dualstack,
    parse_openvpn_status_log,
    render_openvpn_server_conf,
)
from container.app.portal_api import create_portal_app
from container.app.totp import generate_totp_secret
from container.app.wireguard import DryRunCommandRunner
from container.openvpn_auth import verify_via_file
from tests.unit.test_controller_portal_totp import CSRF, _build_portal_test_service


def test_ovpn_interface_naming_and_status_log_parsers() -> None:
    assert derive_ovpn_interface_name("vpn1") == "tun-vpn1"
    long_tun = derive_ovpn_interface_name("vpn-enterprise-branch-99")
    assert len(long_tun) <= 15
    assert long_tun.endswith("99")

    v2_log = "\n".join(
        [
            "TITLE,OpenVPN 2.6.3 x86_64-pc-linux-gnu",
            "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent",
            "CLIENT_LIST,alice,198.51.100.7:52341,10.199.1.2,,15000,32000",
            "CLIENT_LIST,bob,203.0.113.9:60123,10.199.1.3,,8000,9000",
        ]
    )
    clients_v2 = parse_openvpn_status_log(v2_log)
    assert len(clients_v2) == 2
    assert clients_v2[0]["username"] == "alice"
    assert clients_v2[0]["virtual_address"] == "10.199.1.2"

    v1_log = "\n".join(
        [
            "OpenVPN CLIENT LIST",
            "Updated,2026-11-20 12:00:00",
            "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since",
            "alice,198.51.100.7:52341,15000,32000,2026-11-20 11:50:00",
            "ROUTING TABLE",
        ]
    )
    clients_v1 = parse_openvpn_status_log(v1_log)
    assert len(clients_v1) == 1
    assert clients_v1[0]["username"] == "alice"


@pytest.mark.asyncio
async def test_openvpn_pki_encryption_profiles_auth_and_instant_kill(
    controller_settings: Settings,
    dry_runner: DryRunCommandRunner,
    tmp_path: Path,
) -> None:
    svc, state = _build_portal_test_service(controller_settings, dry_runner)
    assert isinstance(svc.ovpn_controller, DryRunOpenVPNController)

    admin_app = create_admin_app(svc)
    portal_app = create_portal_app(svc)

    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=admin_app),
            base_url="http://admin.local",
        ) as admin_client,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=portal_app),
            base_url="https://vpn.corp.example.com",
        ) as portal_client,
    ):
        # 1. Reject OpenVPN subnet collisions with WireGuard (`10.199.0.0/24`) and NS8 cluster (`10.5.4.0/24`)
        r_bad1 = await admin_client.put(
            "/api/v1/admin/config",
            json={"ovpn_enabled": True, "ovpn_network": "10.5.4.0/24"},
        )
        assert r_bad1.status_code == 400

        r_bad2 = await admin_client.put(
            "/api/v1/admin/config",
            json={"ovpn_enabled": True, "ovpn_network": "10.199.0.0/24"},
        )
        assert r_bad2.status_code == 400

        r_bad_udp = await admin_client.put(
            "/api/v1/admin/config",
            json={"ovpn_enabled": True, "ovpn_proto": "udp", "ovpn_port": 55820},
        )
        assert r_bad_udp.status_code == 400

        # Seed a stale management socket file to verify cleanup before OpenVPN start
        controller_settings.ovpn_mgmt_sock_path.write_text("stale", encoding="utf-8")

        # 2. Enable OpenVPN TCP fallback (internal 1194/tcp, external WAN port 443/tcp)
        r_enable = await admin_client.put(
            "/api/v1/admin/config",
            json={
                "endpoint_host": "vpn.corp.example.com",
                "portal_enabled": True,
                "portal_totp_mode": "optional",
                "ovpn_enabled": True,
                "ovpn_proto": "tcp",
                "ovpn_port": 1194,
                "ovpn_public_port": 443,
                "ovpn_network": "10.199.1.0/24",
                "ovpn_totp_required": False,
                "allowed_cidrs": ["192.168.10.0/24"],
                "dns_servers": ["192.168.10.5"],
                "dns_search_domain": "corp.example.com",
            },
        )
        assert r_enable.status_code == 200
        assert svc.ovpn_controller.running is True
        assert not controller_settings.ovpn_mgmt_sock_path.exists()

        # Verify generated X.509 certificates and encrypted PKI at rest in SQLite
        pki = svc.db.ensure_openvpn_pki()
        ca_cert = x509.load_pem_x509_certificate(pki.ca_cert_pem.encode("ascii"))
        srv_cert = x509.load_pem_x509_certificate(pki.server_cert_pem.encode("ascii"))
        cli_cert = x509.load_pem_x509_certificate(pki.client_cert_pem.encode("ascii"))

        assert ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
        assert ExtendedKeyUsageOID.SERVER_AUTH in srv_cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in cli_cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert "-----BEGIN OpenVPN Static key V1-----" in pki.tls_crypt_key

        raw_conn = sqlite3.connect(str(controller_settings.db_path))
        try:
            pki_row = raw_conn.execute(
                "SELECT ca_key_enc, server_key_enc, client_key_enc, tls_crypt_key_enc FROM openvpn_pki WHERE id = 1"
            ).fetchone()
            for col in pki_row:
                assert col.startswith("v1:")
                assert "PRIVATE KEY" not in col
                assert "Static key" not in col
        finally:
            raw_conn.close()

        # Verify rendered `openvpn-server.conf` and `nftables` rules for `tun-vpn1`
        srv_conf = controller_settings.ovpn_server_conf_path.read_text(encoding="utf-8")
        assert "dev tun-vpn1" in srv_conf
        expected_proto = "proto tcp6-server" if detect_host_ipv6_dualstack() else "proto tcp-server"
        assert expected_proto in srv_conf
        assert "port 1194" in srv_conf
        assert "server 10.199.1.0 255.255.255.0" in srv_conf
        assert 'push "route 192.168.10.0 255.255.255.0"' in srv_conf
        assert "auth-user-pass-verify /app/openvpn_auth.py via-file" in srv_conf
        assert f"setenv ADMIN_SOCK_PATH {controller_settings.admin_sock_path.as_posix()}" in srv_conf
        assert "username-as-common-name" in srv_conf
        assert "duplicate-cn" in srv_conf

        nft_rules = dry_runner.last_nft_ruleset
        assert 'iifname "tun-vpn1" oifname "wg0" drop' in nft_rules
        assert 'iifname "tun-vpn1" ip daddr 10.5.4.0/24 drop' in nft_rules
        assert 'iifname "tun-vpn1" tcp dport 6379 drop' in nft_rules
        assert 'iifname "tun-vpn1" oifname != "tun-vpn1" ip saddr 10.199.1.0/24 masquerade' in nft_rules

        # Sync users so alice is in SQLite
        svc.ldap_sync.sync_now()

        # 3. Admin & Portal `.ovpn` profile download uses external `ovpn_public_port` (443)
        r_admin_ovpn = await admin_client.get("/api/v1/admin/users/alice/ovpn")
        assert r_admin_ovpn.status_code == 200
        ovpn_body = r_admin_ovpn.json()
        assert "proto tcp-client" in ovpn_body["ovpn_text"]
        assert "remote vpn.corp.example.com 443" in ovpn_body["ovpn_text"]
        assert "remote-cert-tls server" in ovpn_body["ovpn_text"]
        assert "<tls-crypt>" in ovpn_body["ovpn_text"]

        await portal_client.post(
            "/api/v1/portal/auth/login",
            headers=CSRF,
            json={"username": "alice", "password": "AlicePass!123"},
        )
        r_portal_ovpn = await portal_client.get("/api/v1/portal/openvpn/profile")
        assert r_portal_ovpn.status_code == 200
        assert r_portal_ovpn.json()["ovpn_text"] == ovpn_body["ovpn_text"]

        # 4. Live OpenVPN authentication (password-only, then password + 6-digit TOTP)
        r_auth_ok = await admin_client.post(
            "/api/v1/admin/openvpn/authenticate",
            json={"username": "alice", "password": "AlicePass!123"},
        )
        assert r_auth_ok.status_code == 200
        assert r_auth_ok.json()["allowed"] is True

        # Enable `ovpn_totp_required = True` and enroll TOTP for alice
        totp_secret = generate_totp_secret()
        svc.db.confirm_user_totp("alice", totp_secret, actor="test")
        await admin_client.put("/api/v1/admin/config", json={"ovpn_totp_required": True})

        # Plain password without 6-digit TOTP suffix is now rejected!
        r_missing_totp = await admin_client.post(
            "/api/v1/admin/openvpn/authenticate",
            json={"username": "alice", "password": "AlicePass!123"},
        )
        assert r_missing_totp.status_code == 401
        assert r_missing_totp.json()["allowed"] is False

        # Password + current 6-digit TOTP code succeeds!
        combined_pw = f"AlicePass!123{pyotp.TOTP(totp_secret).now()}"
        r_totp_ok = await admin_client.post(
            "/api/v1/admin/openvpn/authenticate",
            json={"username": "alice", "password": combined_pw},
        )
        assert r_totp_ok.status_code == 200
        assert r_totp_ok.json()["allowed"] is True

        # Also test `container/openvpn_auth.py` `verify_via_file` CLI helper
        via_file = tmp_path / "ovpn_creds.txt"
        via_file.write_text(f"alice\n{combined_pw}\n", encoding="utf-8", newline="\n")

        class _FakeResp:
            status = 200

            @staticmethod
            def read() -> bytes:
                return b'{"allowed": true, "username": "alice"}'

        with patch.dict(
            "os.environ", {"ADMIN_SOCK_PATH": str(tmp_path / "custom-admin.sock")}, clear=False
        ), patch("container.openvpn_auth._UnixHTTPConnection.__init__", return_value=None) as mock_init, patch(
            "container.openvpn_auth._UnixHTTPConnection.request"
        ), patch(
            "container.openvpn_auth._UnixHTTPConnection.getresponse", return_value=_FakeResp()
        ), patch("container.openvpn_auth._UnixHTTPConnection.close"):
            assert verify_via_file(via_file) == 0
            mock_init.assert_called_once_with(str(tmp_path / "custom-admin.sock"), timeout=12.0)

        # 5. Live OpenVPN status count in `GET /api/v1/admin/config` + instant management-socket kill on AD disable!
        controller_settings.ovpn_status_log_path.write_text(
            "TITLE,OpenVPN 2.6\nCLIENT_LIST,alice,198.51.100.1:44444,10.199.1.2,,100,200\n",
            encoding="utf-8",
            newline="\n",
        )
        r_cfg_live = await admin_client.get("/api/v1/admin/config")
        assert r_cfg_live.json()["summary"]["online_ovpn_clients"] == 1

        # Disable alice in AD (notice alice has ZERO WireGuard peers!) -> OpenVPN session MUST still be killed!
        state["users"]["alice"]["userAccountControl"] = 514
        svc.ldap_sync.sync_now()
        assert "alice" in svc.ovpn_controller.killed_users

        # Disabling OpenVPN stops the daemon cleanly and removes any stale management socket
        controller_settings.ovpn_mgmt_sock_path.write_text("active-sock", encoding="utf-8")
        await admin_client.put("/api/v1/admin/config", json={"ovpn_enabled": False})
        assert svc.ovpn_controller.running is False
        assert not controller_settings.ovpn_mgmt_sock_path.exists()


def test_openvpn_dslite_ipv6_dualstack_detection_and_server_conf(
    controller_settings: Settings,
    tmp_path: Path,
) -> None:
    # 1. `detect_host_ipv6_dualstack()` probes `/proc/sys/...` safely
    missing_disable = tmp_path / "missing_disable_ipv6"
    missing_v6only = tmp_path / "missing_bindv6only"
    assert (
        detect_host_ipv6_dualstack(
            disable_ipv6_path=missing_disable,
            bindv6only_path=missing_v6only,
        )
        is False
    )

    disable_file = tmp_path / "disable_ipv6"
    v6only_file = tmp_path / "bindv6only"
    disable_file.write_text("0\n", encoding="utf-8", newline="\n")
    v6only_file.write_text("0\n", encoding="utf-8", newline="\n")
    assert (
        detect_host_ipv6_dualstack(
            disable_ipv6_path=disable_file,
            bindv6only_path=v6only_file,
        )
        is True
    )

    # IPv6 disabled (`1`) OR `bindv6only=1` must fall back to IPv4-only (`False`)
    disable_file.write_text("1\n", encoding="utf-8", newline="\n")
    assert (
        detect_host_ipv6_dualstack(
            disable_ipv6_path=disable_file,
            bindv6only_path=v6only_file,
        )
        is False
    )
    disable_file.write_text("0\n", encoding="utf-8", newline="\n")
    v6only_file.write_text("1\n", encoding="utf-8", newline="\n")
    assert (
        detect_host_ipv6_dualstack(
            disable_ipv6_path=disable_file,
            bindv6only_path=v6only_file,
        )
        is False
    )

    # 2. Verify `render_openvpn_server_conf()` and `OpenVPNEngine` emit `tcp6-server`/`udp6` vs `tcp-server`/`udp`
    svc_db_settings = controller_settings
    from container.app.db import Database

    db = Database(svc_db_settings)
    db.initialize()
    pki = db.ensure_openvpn_pki()

    conf_tcp_v6 = render_openvpn_server_conf(
        interface_name="tun-vpn1",
        ovpn_proto="tcp",
        ovpn_port=1194,
        ovpn_network="10.199.1.0/24",
        tunnel_mode="split",
        allowed_cidrs=["192.168.1.0/24"],
        dns_servers=["192.168.1.1"],
        dns_search_domain="corp.local",
        pki=pki,
        mgmt_sock_path=tmp_path / "ovpn.sock",
        status_log_path=tmp_path / "status.log",
        ipv6_dualstack=True,
    )
    assert "\nproto tcp6-server\n" in conf_tcp_v6

    conf_udp_v6 = render_openvpn_server_conf(
        interface_name="tun-vpn1",
        ovpn_proto="udp",
        ovpn_port=1194,
        ovpn_network="10.199.1.0/24",
        tunnel_mode="split",
        allowed_cidrs=[],
        dns_servers=[],
        dns_search_domain="",
        pki=pki,
        mgmt_sock_path=tmp_path / "ovpn.sock",
        status_log_path=tmp_path / "status.log",
        ipv6_dualstack=True,
    )
    assert "\nproto udp6\n" in conf_udp_v6

    conf_tcp_v4 = render_openvpn_server_conf(
        interface_name="tun-vpn1",
        ovpn_proto="tcp",
        ovpn_port=1194,
        ovpn_network="10.199.1.0/24",
        tunnel_mode="split",
        allowed_cidrs=[],
        dns_servers=[],
        dns_search_domain="",
        pki=pki,
        mgmt_sock_path=tmp_path / "ovpn.sock",
        status_log_path=tmp_path / "status.log",
        ipv6_dualstack=False,
    )
    assert "\nproto tcp-server\n" in conf_tcp_v4

    conf_udp_v4 = render_openvpn_server_conf(
        interface_name="tun-vpn1",
        ovpn_proto="udp",
        ovpn_port=1194,
        ovpn_network="10.199.1.0/24",
        tunnel_mode="split",
        allowed_cidrs=[],
        dns_servers=[],
        dns_search_domain="",
        pki=pki,
        mgmt_sock_path=tmp_path / "ovpn.sock",
        status_log_path=tmp_path / "status.log",
        ipv6_dualstack=False,
    )
    assert "\nproto udp\n" in conf_udp_v4

    # 3. Verify `OpenVPNEngine` honors `ipv6_dualstack` on both `__init__` and `reconcile`
    ovpn_ctrl = DryRunOpenVPNController()
    engine = OpenVPNEngine(
        conf_path=tmp_path / "server.conf",
        mgmt_sock_path=tmp_path / "mgmt.sock",
        status_log_path=tmp_path / "ovpn-status.log",
        pid_path=tmp_path / "ovpn.pid",
        process_controller=ovpn_ctrl,
        ipv6_dualstack=True,
    )
    engine.reconcile(
        ovpn_enabled=True,
        interface_name="tun-vpn1",
        ovpn_proto="tcp",
        ovpn_port=1194,
        ovpn_network="10.199.1.0/24",
        tunnel_mode="full",
        allowed_cidrs=[],
        dns_servers=[],
        dns_search_domain="",
        pki=pki,
    )
    assert "\nproto tcp6-server\n" in (tmp_path / "server.conf").read_text(encoding="utf-8")

    engine.reconcile(
        ovpn_enabled=True,
        interface_name="tun-vpn1",
        ovpn_proto="udp",
        ovpn_port=1194,
        ovpn_network="10.199.1.0/24",
        tunnel_mode="full",
        allowed_cidrs=[],
        dns_servers=[],
        dns_search_domain="",
        pki=pki,
        ipv6_dualstack=False,
    )
    assert "\nproto udp\n" in (tmp_path / "server.conf").read_text(encoding="utf-8")
