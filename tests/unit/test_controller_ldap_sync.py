"""Unit tests for Samba AD & OpenLDAP synchronization and fail-safe outage handling (`ldap_sync.py`)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import ldap3
from ldap3.core.exceptions import LDAPSocketOpenError

from container.app.config import Settings
from container.app.crypto import generate_wg_keypair, generate_wg_psk
from container.app.db import Database
from container.app.ldap_sync import (
    LDAP_MATCHING_RULE_IN_CHAIN,
    LDAPSyncService,
    WINDOWS_EPOCH_OFFSET_SECONDS,
)
from container.app.wireguard import DryRunCommandRunner, WireGuardEngine
from tests.conftest import write_ldap_json


def _to_filetime(dt: datetime) -> int:
    return int((dt.timestamp() + WINDOWS_EPOCH_OFFSET_SECONDS) * 10_000_000)


class FakeLDAPSession:
    """Deterministic fake `ldap3.Connection` routing queries by search filter."""

    def __init__(self, handler) -> None:
        self._handler = handler
        self.entries: list[dict[str, Any]] = []
        self.queries: list[tuple[str, str]] = []
        self.unbound = False

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: str = ldap3.SUBTREE,
        attributes: list[str] | None = None,
    ) -> bool:
        self.queries.append((search_base, search_filter))
        self.entries = self._handler(search_base, search_filter, attributes or [])
        return bool(self.entries)

    def unbind(self) -> bool:
        self.unbound = True
        return True


def test_ad_sync_nested_group_uac_disable_expiry_and_fail_safe(
    controller_settings: Settings,
) -> None:
    runner = DryRunCommandRunner()
    db = Database(controller_settings)
    db.initialize()
    db.update_server_config({"user_domain": "corp.example.com", "vpn_group": "vpn-users"})
    wg = WireGuardEngine(runner, run_dir=controller_settings.run_dir)

    write_ldap_json(
        controller_settings,
        {
            "configured": True,
            "domain": "corp.example.com",
            "host": "127.0.0.1",
            "port": 4389,
            "schema": "ad",
            "base_dn": "DC=corp,DC=example,DC=com",
            "bind_dn": "CN=svc,CN=Users,DC=corp,DC=example,DC=com",
            "bind_password": "secret",
            "vpn_group": "vpn-users",
            "hidden_users": ["administrator"],
        },
    )

    now = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
    past_ft = str(_to_filetime(now - timedelta(days=2)))
    future_ft = str(_to_filetime(now + timedelta(days=30)))

    # Mutable AD directory state
    ad_state = {
        "raise_error": False,
        "group_dn": "CN=vpn-users,CN=Users,DC=corp,DC=example,DC=com",
        "nested_members": [
            {
                "dn": "CN=Alice,OU=Staff,DC=corp,DC=example,DC=com",
                "sAMAccountName": "alice",
            },
            {
                "dn": "CN=Bob,OU=Staff,DC=corp,DC=example,DC=com",
                "sAMAccountName": "bob",
            },
            {
                "dn": "CN=Charlie,OU=Staff,DC=corp,DC=example,DC=com",
                "sAMAccountName": "charlie",
            },
        ],
        "users": [
            {
                "dn": "CN=Alice,OU=Staff,DC=corp,DC=example,DC=com",
                "sAMAccountName": "alice",
                "displayName": "Alice Active",
                "mail": "alice@corp.example.com",
                "userAccountControl": 512,  # active
                "accountExpires": "0",
            },
            {
                "dn": "CN=Bob,OU=Staff,DC=corp,DC=example,DC=com",
                "sAMAccountName": "bob",
                "displayName": "Bob FutureExp",
                "mail": "bob@corp.example.com",
                "userAccountControl": 512,
                "accountExpires": future_ft,
            },
            {
                "dn": "CN=Charlie,OU=Staff,DC=corp,DC=example,DC=com",
                "sAMAccountName": "charlie",
                "displayName": "Charlie Expired",
                "mail": "charlie@corp.example.com",
                "userAccountControl": 512,
                "accountExpires": past_ft,  # already expired!
            },
            {
                "dn": "CN=Administrator,CN=Users,DC=corp,DC=example,DC=com",
                "sAMAccountName": "administrator",  # hidden_users -> skipped
                "userAccountControl": 512,
                "accountExpires": "9223372036854775807",
            },
            {
                "dn": "CN=WS01,CN=Computers,DC=corp,DC=example,DC=com",
                "sAMAccountName": "WS01$",  # machine account -> skipped
                "userAccountControl": 4096,
                "accountExpires": "0",
            },
        ],
    }

    sessions: list[FakeLDAPSession] = []

    def factory(_cfg: dict[str, Any]) -> FakeLDAPSession:
        if ad_state["raise_error"]:
            raise LDAPSocketOpenError("Samba AD container temporarily restarting")

        def handle(_base: str, flt: str, _attrs: list[str]) -> list[dict[str, Any]]:
            if "(objectClass=group)" in flt:
                return [{"dn": ad_state["group_dn"], "member": []}]
            if LDAP_MATCHING_RULE_IN_CHAIN in flt:
                return list(ad_state["nested_members"])
            return list(ad_state["users"])

        sess = FakeLDAPSession(handle)
        sessions.append(sess)
        return sess

    sync_svc = LDAPSyncService(
        db=db,
        wg_engine=wg,
        ldap_config_path=controller_settings.ldap_config_path,
        connection_factory=factory,
    )

    # 1. Initial sync: alice & bob authorized, charlie unauthorized (expired), hidden/machine filtered
    res1 = sync_svc.sync_now(now_utc=now)
    assert res1["status"] == "ok"
    assert res1["total_users"] == 3
    assert res1["authorized_users"] == 2
    assert any(LDAP_MATCHING_RULE_IN_CHAIN in q[1] for q in sessions[-1].queries)

    assert db.get_user("alice")["authorized"] is True
    assert db.get_user("bob")["authorized"] is True
    assert db.get_user("charlie")["authorized"] is False
    assert db.get_user("administrator") is None

    # Provision active WireGuard peers for alice and bob
    a_priv, a_pub = generate_wg_keypair()
    b_priv, b_pub = generate_wg_keypair()
    alice_peer = db.create_peer_record(
        username="alice",
        device_name="Alice-Laptop",
        assigned_ip="10.199.0.2",
        public_key=a_pub,
        private_key=a_priv,
        preshared_key=generate_wg_psk(),
    )
    bob_peer = db.create_peer_record(
        username="bob",
        device_name="Bob-Phone",
        assigned_ip="10.199.0.3",
        public_key=b_pub,
        private_key=b_priv,
        preshared_key=generate_wg_psk(),
    )
    wg.reconcile_interface(
        interface_name="wg-vpn1",
        server_private_key=db.get_server_private_key(),
        wg_port=51820,
        wg_network="10.199.0.0/24",
        wg_mtu=1380,
        active_peers=db.list_active_wireguard_peers_with_psk(),
    )
    runner.commands.clear()

    # 2. CRITICAL FAIL-SAFE TEST: Samba AD unreachable -> MUST NOT disconnect alice or bob!
    ad_state["raise_error"] = True
    res_err = sync_svc.sync_now(now_utc=now)
    assert res_err["status"] == "ldap_error"
    assert res_err["suspended_peers"] == 0
    assert db.get_user("alice")["authorized"] is True
    assert db.get_user("bob")["authorized"] is True
    assert db.get_peer(alice_peer["id"])["effective_active"] is True
    assert db.get_peer(bob_peer["id"])["effective_active"] is True
    remove_cmds_during_outage = [
        cmd for cmd, _ in runner.commands if cmd[:2] == ["wg", "set"] and "remove" in cmd
    ]
    assert remove_cmds_during_outage == []

    # 3. AD comes back online: alice gets disabled (`0x0002` -> 514), bob removed from `vpn-users`
    ad_state["raise_error"] = False
    ad_state["users"][0]["userAccountControl"] = 514  # UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE
    ad_state["nested_members"] = [
        {"dn": "CN=Alice,OU=Staff,DC=corp,DC=example,DC=com", "sAMAccountName": "alice"}
    ]  # bob removed from vpn-users

    res2 = sync_svc.sync_now(now_utc=now)
    assert res2["status"] == "ok"
    assert res2["authorized_users"] == 0
    assert res2["suspended_peers"] == 2

    # Verify BOTH peers were immediately evicted from kernel WireGuard interface
    assert (["wg", "set", "wg-vpn1", "peer", a_pub, "remove"], None) in runner.commands
    assert (["wg", "set", "wg-vpn1", "peer", b_pub, "remove"], None) in runner.commands
    assert db.get_peer(alice_peer["id"])["effective_active"] is False
    assert db.get_peer(bob_peer["id"])["effective_active"] is False

    audit_rows, _audit_total = db.list_audit_logs()
    audit_events = [a["event_type"] for a in audit_rows]
    assert audit_events.count("peer_auto_suspended") == 2

    # 4. Alice is re-enabled in AD -> her peer is automatically restored into `wg-vpn1`!
    ad_state["users"][0]["userAccountControl"] = 512
    res3 = sync_svc.sync_now(now_utc=now)
    assert res3["status"] == "ok"
    assert res3["authorized_users"] == 1
    assert db.get_peer(alice_peer["id"])["effective_active"] is True
    assert a_pub in runner.peers_by_iface["wg-vpn1"]
    assert b_pub not in runner.peers_by_iface["wg-vpn1"]


def test_openldap_rfc2307_posix_and_group_of_names_and_locks(
    controller_settings: Settings,
) -> None:
    runner = DryRunCommandRunner()
    db = Database(controller_settings)
    db.initialize()
    db.update_server_config({"user_domain": "ldap.example.org", "vpn_group": "vpn-team"})
    wg = WireGuardEngine(runner, run_dir=controller_settings.run_dir)

    write_ldap_json(
        controller_settings,
        {
            "configured": True,
            "domain": "ldap.example.org",
            "host": "127.0.0.1",
            "port": 3389,
            "schema": "rfc2307",
            "base_dn": "dc=ldap,dc=example,dc=org",
            "bind_dn": "cn=ldapservice,dc=ldap,dc=example,dc=org",
            "bind_password": "secret",
            "vpn_group": "vpn-team",
            "hidden_users": [],
        },
    )

    now = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
    today_days = int(now.timestamp() // 86400)

    def handle(_base: str, flt: str, _attrs: list[str]) -> list[dict[str, Any]]:
        if "posixGroup" in flt:
            return [
                {
                    "dn": "cn=vpn-team,ou=Groups,dc=ldap,dc=example,dc=org",
                    "cn": "vpn-team",
                    "memberUid": ["anna", "locked_user"],
                    "member": [
                        "uid=ben,ou=People,dc=ldap,dc=example,dc=org",
                        "uid=expired_user,ou=People,dc=ldap,dc=example,dc=org",
                    ],
                }
            ]
        return [
            {
                "dn": "uid=anna,ou=People,dc=ldap,dc=example,dc=org",
                "uid": "anna",
                "cn": "Anna Posix",
                "mail": "anna@example.org",
                "shadowExpire": str(today_days + 90),
            },
            {
                "dn": "uid=ben,ou=People,dc=ldap,dc=example,dc=org",
                "uid": "ben",
                "cn": "Ben GroupOfNames",
                "mail": "ben@example.org",
            },
            {
                "dn": "uid=locked_user,ou=People,dc=ldap,dc=example,dc=org",
                "uid": "locked_user",
                "cn": "Locked Account",
                "pwdAccountLockedTime": "000001010000Z",
            },
            {
                "dn": "uid=expired_user,ou=People,dc=ldap,dc=example,dc=org",
                "uid": "expired_user",
                "cn": "Shadow Expired",
                "shadowExpire": str(today_days - 1),
            },
            {
                "dn": "uid=outsider,ou=People,dc=ldap,dc=example,dc=org",
                "uid": "outsider",
                "cn": "Not In Group",
            },
        ]

    sync_svc = LDAPSyncService(
        db=db,
        wg_engine=wg,
        ldap_config_path=controller_settings.ldap_config_path,
        connection_factory=lambda _cfg: FakeLDAPSession(handle),
    )

    res = sync_svc.sync_now(now_utc=now)
    assert res["status"] == "ok"
    assert res["total_users"] == 5
    assert res["authorized_users"] == 2

    assert db.get_user("anna")["authorized"] is True
    assert db.get_user("ben")["authorized"] is True
    assert db.get_user("locked_user")["ldap_active"] is False
    assert db.get_user("locked_user")["authorized"] is False
    assert db.get_user("expired_user")["ldap_active"] is False
    assert db.get_user("expired_user")["authorized"] is False
    assert db.get_user("outsider")["ldap_active"] is True
    assert db.get_user("outsider")["in_vpn_group"] is False
    assert db.get_user("outsider")["authorized"] is False
