"""Unit tests for Phase 2 Self-Service Portal API, live AD auth, CSRF, IDOR, rate limiting, and TOTP 2FA."""

from __future__ import annotations

from typing import Any

import httpx
import pyotp
import pytest

from container.app.admin_api import VPNControllerService, create_admin_app
from container.app.config import Settings
from container.app.portal_api import create_portal_app
from container.app.wireguard import DryRunCommandRunner
from tests.conftest import write_ldap_json
from tests.unit.test_controller_ldap_sync import FakeLDAPSession


CSRF = {"X-Requested-With": "NS8VPNPortal"}


def _build_portal_test_service(settings: Settings, runner: DryRunCommandRunner):
    write_ldap_json(
        settings,
        {
            "configured": True,
            "domain": "corp.example.com",
            "host": "127.0.0.1",
            "port": 4389,
            "schema": "ad",
            "base_dn": "DC=corp,DC=example,DC=com",
            "bind_dn": "CN=svc,CN=Users,DC=corp,DC=example,DC=com",
            "bind_password": "svc-secret",
            "vpn_group": "vpn-users",
            "hidden_users": ["administrator"],
        },
    )

    directory_state: dict[str, Any] = {
        "queries": [],
        "bind_calls": [],
        "passwords": {
            "CN=Alice,OU=Staff,DC=corp,DC=example,DC=com": "AlicePass!123",
            "CN=Bob,OU=Staff,DC=corp,DC=example,DC=com": "BobPass!456",
            "CN=Eve,OU=Staff,DC=corp,DC=example,DC=com": "EvePass!789",
        },
        "users": {
            "alice": {
                "dn": "CN=Alice,OU=Staff,DC=corp,DC=example,DC=com",
                "sAMAccountName": "alice",
                "displayName": "Alice Meyer",
                "mail": "alice@corp.example.com",
                "userAccountControl": 512,
                "accountExpires": "0",
                "in_group": True,
            },
            "bob": {
                "dn": "CN=Bob,OU=Staff,DC=corp,DC=example,DC=com",
                "sAMAccountName": "bob",
                "displayName": "Bob Weber",
                "mail": "bob@corp.example.com",
                "userAccountControl": 512,
                "accountExpires": "0",
                "in_group": True,
            },
            "eve": {
                "dn": "CN=Eve,OU=Staff,DC=corp,DC=example,DC=com",
                "sAMAccountName": "eve",
                "displayName": "Eve NoVPN",
                "mail": "eve@corp.example.com",
                "userAccountControl": 512,
                "accountExpires": "0",
                "in_group": False,
            },
        },
    }

    def conn_factory(_cfg: dict[str, Any]) -> FakeLDAPSession:
        def handle(_base: str, flt: str, _attrs: list[str]) -> list[dict[str, Any]]:
            directory_state["queries"].append(flt)
            flt_low = flt.lower()
            if "(objectclass=group)" in flt_low:
                members = [
                    u["dn"] for u in directory_state["users"].values() if u["in_group"]
                ]
                return [
                    {
                        "dn": "CN=vpn-users,CN=Users,DC=corp,DC=example,DC=com",
                        "member": members,
                    }
                ]
            if "samaccountname=" in flt_low:
                matched: list[dict[str, Any]] = []
                for uname, uobj in directory_state["users"].items():
                    if f"(samaccountname={uname})" in flt_low:
                        if "1.2.840.113556.1.4.1941" in flt_low and not uobj["in_group"]:
                            continue
                        matched.append(dict(uobj))
                return matched
            if "1.2.840.113556.1.4.1941" in flt_low:
                return [dict(u) for u in directory_state["users"].values() if u["in_group"]]
            return [dict(u) for u in directory_state["users"].values()]

        return FakeLDAPSession(handle)

    def bind_verifier(_cfg: dict[str, Any], user_dn: str, password: str) -> bool:
        directory_state["bind_calls"].append((user_dn, password))
        return directory_state["passwords"].get(user_dn) == password

    svc = VPNControllerService(
        settings=settings,
        runner=runner,
        ldap_connection_factory=conn_factory,
        ldap_user_bind_verifier=bind_verifier,
    )
    svc.db.update_server_config(
        {
            "configured": True,
            "portal_enabled": True,
            "portal_domain": "vpn.corp.example.com",
            "portal_totp_mode": "required",
            "user_domain": "corp.example.com",
            "vpn_group": "vpn-users",
            "max_devices_per_user": 2,
        }
    )
    svc.reconcile_dataplane()
    return svc, directory_state


@pytest.mark.asyncio
async def test_portal_security_headers_csrf_ldap_injection_and_rate_limit(
    controller_settings: Settings,
    dry_runner: DryRunCommandRunner,
) -> None:
    svc, state = _build_portal_test_service(controller_settings, dry_runner)
    portal_app = create_portal_app(svc)
    transport = httpx.ASGITransport(app=portal_app)

    async with httpx.AsyncClient(transport=transport, base_url="https://vpn.corp.example.com") as client:
        # 1. Static HTML & Security Headers + Path Traversal defense
        r_index = await client.get("/")
        assert r_index.status_code == 200
        assert r_index.headers["X-Frame-Options"] == "DENY"
        assert r_index.headers["X-Content-Type-Options"] == "nosniff"
        assert "script-src 'self'" in r_index.headers["Content-Security-Policy"]

        r_traversal = await client.get("/static/../../secrets/master.key")
        assert r_traversal.status_code == 404

        r_info = await client.get("/api/v1/portal/info")
        assert r_info.status_code == 200
        assert r_info.headers["Cache-Control"] == "no-store"
        assert r_info.json()["totp_mode"] == "required"

        # 2. Missing CSRF header is rejected on mutating endpoints
        r_no_csrf = await client.post(
            "/api/v1/portal/auth/login",
            json={"username": "alice", "password": "AlicePass!123"},
        )
        assert r_no_csrf.status_code == 403

        # 3. Empty password MUST be rejected before any LDAP bind call!
        r_empty_pw = await client.post(
            "/api/v1/portal/auth/login",
            headers=CSRF,
            json={"username": "alice", "password": ""},
        )
        assert r_empty_pw.status_code == 401
        assert state["bind_calls"] == []

        # 4. LDAP filter injection payload is escaped safely (`\2a`, `\28`, `\29`)
        svc.rate_limiter.reset("ip:127.0.0.1", "user:alice")
        r_inj = await client.post(
            "/api/v1/portal/auth/login",
            headers=CSRF,
            json={"username": "alice)(|(sAMAccountName=*", "password": "AlicePass!123"},
        )
        assert r_inj.status_code == 401
        assert any("\\29\\28|\\28sAMAccountName=\\2a" in q for q in state["queries"])

        # 5. Non-VPN-group user with valid AD password gets 403
        r_eve = await client.post(
            "/api/v1/portal/auth/login",
            headers=CSRF,
            json={"username": "eve", "password": "EvePass!789"},
        )
        assert r_eve.status_code == 403

        # 6. Brute-force rate limiter triggers 429 after 5 failed attempts
        svc.rate_limiter.reset("ip:127.0.0.1", "user:bob", "ip:203.0.113.99")
        for _ in range(5):
            r_fail = await client.post(
                "/api/v1/portal/auth/login",
                headers={**CSRF, "X-Forwarded-For": "203.0.113.99"},
                json={"username": "bob", "password": "wrong-password"},
            )
            assert r_fail.status_code == 401

        r_limited = await client.post(
            "/api/v1/portal/auth/login",
            headers={**CSRF, "X-Forwarded-For": "203.0.113.99"},
            json={"username": "bob", "password": "BobPass!456"},
        )
        assert r_limited.status_code == 429


@pytest.mark.asyncio
async def test_portal_mandatory_and_optional_totp_devices_quota_and_idor(
    controller_settings: Settings,
    dry_runner: DryRunCommandRunner,
) -> None:
    svc, state = _build_portal_test_service(controller_settings, dry_runner)
    portal_app = create_portal_app(svc)
    admin_app = create_admin_app(svc)

    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=portal_app),
            base_url="https://vpn.corp.example.com",
        ) as alice_client,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=portal_app),
            base_url="https://vpn.corp.example.com",
        ) as bob_client,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=admin_app),
            base_url="http://admin.local",
        ) as admin_client,
    ):
        # 1. Alice logs in under `portal_totp_mode == "required"` (not yet enrolled)
        r_login = await alice_client.post(
            "/api/v1/portal/auth/login",
            headers={**CSRF, "X-Forwarded-Proto": "https"},
            json={"username": "alice", "password": "AlicePass!123"},
        )
        assert r_login.status_code == 200
        assert "Secure" in r_login.headers.get("set-cookie", "")
        assert "HttpOnly" in r_login.headers.get("set-cookie", "")
        login_data = r_login.json()
        assert login_data["authenticated"] is True
        assert login_data["totp_setup_required"] is True

        # Device creation is strictly locked (`403`) until mandatory 2FA enrollment completes!
        r_locked = await alice_client.post(
            "/api/v1/portal/devices",
            headers=CSRF,
            json={"device_name": "Arbeits-Laptop"},
        )
        assert r_locked.status_code == 403

        # 2. Mandatory TOTP Setup + Confirm
        r_setup = await alice_client.post("/api/v1/portal/totp/setup", headers=CSRF, json={})
        assert r_setup.status_code == 200
        setup_data = r_setup.json()
        secret = setup_data["secret"]
        assert setup_data["otpauth_uri"].startswith("otpauth://totp/")
        assert setup_data["qr_svg_data_uri"].startswith("data:image/svg+xml;base64,")

        # Invalid 6-digit code fails confirmation
        r_bad_code = await alice_client.post(
            "/api/v1/portal/totp/confirm",
            headers=CSRF,
            json={"code": "000000" if pyotp.TOTP(secret).now() != "000000" else "111111"},
        )
        assert r_bad_code.status_code == 400

        # Valid TOTP code confirms and unlocks dashboard
        valid_code = pyotp.TOTP(secret).now()
        r_confirm = await alice_client.post(
            "/api/v1/portal/totp/confirm",
            headers=CSRF,
            json={"code": valid_code},
        )
        assert r_confirm.status_code == 200
        assert r_confirm.json()["totp_enrolled"] is True
        assert r_confirm.json()["totp_setup_required"] is False

        # Cannot disable TOTP while `portal_totp_mode == "required"`
        r_dis_forbidden = await alice_client.post(
            "/api/v1/portal/totp/disable",
            headers=CSRF,
            json={"password": "AlicePass!123", "code": pyotp.TOTP(secret).now()},
        )
        assert r_dis_forbidden.status_code == 403

        # 3. Re-login now requires 2-step TOTP verification!
        await alice_client.post("/api/v1/portal/auth/logout", headers=CSRF, json={})
        r_step1 = await alice_client.post(
            "/api/v1/portal/auth/login",
            headers=CSRF,
            json={"username": "alice", "password": "AlicePass!123"},
        )
        assert r_step1.status_code == 200
        assert r_step1.json()["authenticated"] is False
        assert r_step1.json()["totp_verify_required"] is True

        r_step2 = await alice_client.post(
            "/api/v1/portal/auth/login",
            headers=CSRF,
            json={
                "username": "alice",
                "password": "AlicePass!123",
                "totp_code": pyotp.TOTP(secret).now(),
            },
        )
        assert r_step2.status_code == 200
        assert r_step2.json()["authenticated"] is True

        # 4. Self-service WireGuard device creation + quota enforcement (max_devices_per_user=2)
        r_d1 = await alice_client.post(
            "/api/v1/portal/devices",
            headers=CSRF,
            json={"device_name": "Arbeits-Laptop"},
        )
        assert r_d1.status_code == 200
        d1_id = r_d1.json()["device"]["id"]
        assert "PrivateKey =" in r_d1.json()["config_text"]

        r_d2 = await alice_client.post(
            "/api/v1/portal/devices",
            headers=CSRF,
            json={"device_name": "iPhone"},
        )
        assert r_d2.status_code == 200

        r_d3_quota = await alice_client.post(
            "/api/v1/portal/devices",
            headers=CSRF,
            json={"device_name": "iPad"},
        )
        assert r_d3_quota.status_code == 400

        # 5. IDOR Protection: Switch to `optional` so Bob logs in, then Bob tries to read/delete Alice's device!
        svc.db.update_server_config({"portal_totp_mode": "optional"})
        r_bob_login = await bob_client.post(
            "/api/v1/portal/auth/login",
            headers=CSRF,
            json={"username": "bob", "password": "BobPass!456"},
        )
        assert r_bob_login.status_code == 200
        assert r_bob_login.json()["authenticated"] is True

        r_idor_get = await bob_client.get(f"/api/v1/portal/devices/{d1_id}/wireguard")
        assert r_idor_get.status_code == 403

        r_idor_del = await bob_client.delete(
            f"/api/v1/portal/devices/{d1_id}", headers=CSRF
        )
        assert r_idor_del.status_code == 403

        # Alice can fetch and delete her own device cleanly
        r_alice_get = await alice_client.get(f"/api/v1/portal/devices/{d1_id}/wireguard")
        assert r_alice_get.status_code == 200
        assert r_alice_get.json()["assigned_ip"] == "10.199.0.2"

        r_alice_del = await alice_client.delete(
            f"/api/v1/portal/devices/{d1_id}", headers=CSRF
        )
        assert r_alice_del.status_code == 200

        # 6. Optional TOTP disable works with password + valid code, and Admin reset-totp works
        r_opt_dis = await alice_client.post(
            "/api/v1/portal/totp/disable",
            headers=CSRF,
            json={"password": "AlicePass!123", "code": pyotp.TOTP(secret).now()},
        )
        assert r_opt_dis.status_code == 200
        assert r_opt_dis.json()["totp_enrolled"] is False

        # Re-enroll via DB helper and verify Admin Cockpit reset-totp endpoint
        svc.db.confirm_user_totp("alice", secret, actor="test")
        assert svc.db.is_user_totp_enrolled("alice") is True
        r_admin_reset = await admin_client.post("/api/v1/admin/users/alice/reset-totp")
        assert r_admin_reset.status_code == 200
        assert r_admin_reset.json() == {"reset": True, "username": "alice"}
        assert svc.db.is_user_totp_enrolled("alice") is False

        # 7. Deauthorizing Alice in AD immediately invalidates her active Portal session (`401`)!
        state["users"]["alice"]["userAccountControl"] = 514
        svc.ldap_sync.sync_now()
        r_me_revoked = await alice_client.get("/api/v1/portal/me")
        assert r_me_revoked.status_code == 401
