"""NS8 Active Directory & OpenLDAP user/group lifecycle synchronization with fail-safe."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

import ldap3
from ldap3.utils.conv import escape_filter_chars

from .db import Database, utc_now_iso
from .wireguard import WireGuardEngine


logger = logging.getLogger("ns8_vpn.ldap_sync")

UF_ACCOUNTDISABLE = 0x0002
WINDOWS_EPOCH_OFFSET_SECONDS = 11644473600
AD_NEVER_EXPIRES_MAX = 9223372036854775807
LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

DEFAULT_HIDDEN_USERS = {"krbtgt", "guest", "nobody"}


@dataclass
class SyncedLDAPUser:
    username: str
    dn: str
    display_name: str
    email: str
    ldap_active: bool
    in_vpn_group: bool


class LDAPSessionProtocol(Protocol):
    """Minimal search/unbind interface implemented by `ldap3.Connection` and test doubles."""

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: str = ldap3.SUBTREE,
        attributes: list[str] | None = None,
    ) -> bool: ...

    @property
    def entries(self) -> list[Any]: ...

    def unbind(self) -> Any: ...


LDAPConnectionFactory = Callable[[dict[str, Any]], LDAPSessionProtocol]


def default_ldap_connection_factory(ldap_cfg: dict[str, Any]) -> LDAPSessionProtocol:
    """Create and bind a live `ldap3.Connection` to NS8 `ldapproxy`."""
    host = str(ldap_cfg.get("host") or "127.0.0.1").strip()
    port = int(ldap_cfg.get("port") or 389)
    use_ssl = bool(ldap_cfg.get("use_ssl") or ldap_cfg.get("tls") or port == 636)
    bind_dn = str(ldap_cfg.get("bind_dn") or "").strip() or None
    bind_password = ldap_cfg.get("bind_password") or None

    server = ldap3.Server(
        host=host,
        port=port,
        use_ssl=use_ssl,
        get_info=ldap3.NONE,
        connect_timeout=10,
    )
    conn = ldap3.Connection(
        server,
        user=bind_dn,
        password=bind_password,
        auto_bind=True,
        receive_timeout=15,
        raise_exceptions=True,
    )
    return conn


def is_ad_account_expired(account_expires: Any, now_utc: datetime | None = None) -> bool:
    """Evaluate Windows AD `accountExpires` (FILETIME 100ns ticks or datetime)."""
    if account_expires is None:
        return False
    now = now_utc or datetime.now(timezone.utc)

    if isinstance(account_expires, list):
        if not account_expires:
            return False
        account_expires = account_expires[0]

    if isinstance(account_expires, datetime):
        dt = (
            account_expires.replace(tzinfo=timezone.utc)
            if account_expires.tzinfo is None
            else account_expires.astimezone(timezone.utc)
        )
        if dt.year <= 1601 or dt.year >= 9999:
            return False
        return dt <= now

    raw_str = str(account_expires).strip()
    if not raw_str:
        return False
    try:
        filetime = int(raw_str)
    except ValueError:
        return False

    if filetime <= 0 or filetime >= AD_NEVER_EXPIRES_MAX:
        return False

    now_filetime = int((now.timestamp() + WINDOWS_EPOCH_OFFSET_SECONDS) * 10_000_000)
    return filetime <= now_filetime


def is_ad_uac_disabled(uac_value: Any) -> bool:
    """Return True if AD `userAccountControl` has `UF_ACCOUNTDISABLE` (`0x0002`) set."""
    if uac_value is None:
        return False
    if isinstance(uac_value, list):
        uac_value = uac_value[0] if uac_value else 0
    try:
        bitmask = int(str(uac_value).strip())
    except ValueError:
        return False
    return (bitmask & UF_ACCOUNTDISABLE) != 0


def is_rfc2307_account_active(
    pwd_locked_time: Any,
    shadow_expire: Any,
    ns_account_lock: Any = None,
    now_utc: datetime | None = None,
) -> bool:
    """Evaluate OpenLDAP `pwdAccountLockedTime`, `shadowExpire`, and `nsAccountLock`."""
    now = now_utc or datetime.now(timezone.utc)

    if isinstance(pwd_locked_time, list):
        pwd_locked_time = pwd_locked_time[0] if pwd_locked_time else None
    if pwd_locked_time is not None and str(pwd_locked_time).strip() != "":
        return False

    if isinstance(ns_account_lock, list):
        ns_account_lock = ns_account_lock[0] if ns_account_lock else None
    if ns_account_lock is not None and str(ns_account_lock).strip().lower() == "true":
        return False

    if isinstance(shadow_expire, list):
        shadow_expire = shadow_expire[0] if shadow_expire else None
    if shadow_expire is not None and str(shadow_expire).strip() != "":
        try:
            expire_days = int(str(shadow_expire).strip())
        except ValueError:
            expire_days = -1
        if expire_days >= 0:
            today_days = int(now.timestamp() // 86400)
            if expire_days <= today_days:
                return False

    return True


def _entry_attr(entry: Any, attr_name: str) -> Any:
    """Extract an attribute value from either an `ldap3.Entry` or dict-like mock entry."""
    if isinstance(entry, dict):
        attrs = entry.get("attributes", entry)
        for k, v in attrs.items():
            if k.lower() == attr_name.lower():
                return v
        return None

    if hasattr(entry, "entry_attributes_as_dict"):
        attr_dict = entry.entry_attributes_as_dict
        for k, v in attr_dict.items():
            if k.lower() == attr_name.lower():
                if isinstance(v, list):
                    return v[0] if len(v) == 1 else (v if v else None)
                return v

    if hasattr(entry, attr_name):
        attr_obj = getattr(entry, attr_name)
        return getattr(attr_obj, "value", attr_obj)

    return None


def _entry_attr_list(entry: Any, attr_name: str) -> list[str]:
    val = _entry_attr(entry, attr_name)
    if val is None:
        return []
    if isinstance(val, (list, tuple, set)):
        return [str(x).strip() for x in val if str(x).strip()]
    s = str(val).strip()
    return [s] if s else []


def _entry_dn(entry: Any) -> str:
    if isinstance(entry, dict):
        dn = entry.get("dn") or _entry_attr(entry, "distinguishedName") or ""
        return str(dn).strip()
    if hasattr(entry, "entry_dn"):
        return str(entry.entry_dn).strip()
    dn_attr = _entry_attr(entry, "distinguishedName")
    return str(dn_attr or "").strip()


def _scalar_str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        return str(val[0]).strip() if val else ""
    return str(val).strip()


def load_ldap_config_file(path: Path) -> dict[str, Any] | None:
    """Load `${STATE_DIR}/secrets/ldap.json` if present."""
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    data = json.loads(raw)
    return data if isinstance(data, dict) else None


class LDAPSyncService:
    """Synchronizes NS8 AD / OpenLDAP users & VPN group authorization with fail-safe."""

    def __init__(
        self,
        db: Database,
        wg_engine: WireGuardEngine,
        ldap_config_path: Path,
        connection_factory: LDAPConnectionFactory | None = None,
        on_user_deauthorized: Callable[[str], Any] | None = None,
    ) -> None:
        self.db = db
        self.wg_engine = wg_engine
        self.ldap_config_path = ldap_config_path
        self.connection_factory = connection_factory or default_ldap_connection_factory
        self.on_user_deauthorized = on_user_deauthorized
        self._sync_lock = asyncio.Lock()

    def is_ldap_configured(self) -> bool:
        try:
            cfg = load_ldap_config_file(self.ldap_config_path)
        except Exception:
            return False
        if not cfg:
            return False
        return bool(cfg.get("configured")) and bool(cfg.get("host")) and bool(cfg.get("base_dn"))

    def sync_now(self, now_utc: datetime | None = None) -> dict[str, Any]:
        """Run synchronous AD/LDAP sync, updating SQLite and kernel WireGuard peers."""
        server_cfg = self.db.get_server_config()
        try:
            ldap_cfg = load_ldap_config_file(self.ldap_config_path)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", self.ldap_config_path, exc)
            return self._record_ldap_error(f"Invalid ldap.json configuration: {exc}")

        if not ldap_cfg or not ldap_cfg.get("configured") or not ldap_cfg.get("base_dn"):
            users = self.db.list_users()
            peers = self.db.list_peers()
            return {
                "status": "skipped",
                "synced_at": server_cfg.get("last_synced_at"),
                "total_users": len(users),
                "authorized_users": sum(1 for u in users if u["authorized"]),
                "active_peers": sum(1 for p in peers if p["effective_active"]),
                "suspended_peers": 0,
                "message": "LDAP user domain is not configured yet",
            }

        vpn_group = (
            server_cfg.get("vpn_group")
            if server_cfg.get("vpn_group")
            else str(ldap_cfg.get("vpn_group") or "")
        ).strip()
        domain = str(ldap_cfg.get("domain") or server_cfg.get("user_domain") or "").strip()
        schema = str(ldap_cfg.get("schema") or "ad").strip().lower()
        base_dn = str(ldap_cfg.get("base_dn") or "").strip()
        hidden_raw = ldap_cfg.get("hidden_users") or []
        hidden_users = {str(u).strip().lower() for u in hidden_raw if str(u).strip()} | DEFAULT_HIDDEN_USERS

        now = now_utc or datetime.now(timezone.utc)

        # CRITICAL FAIL-SAFE: Any socket, bind, timeout, or LDAP protocol failure MUST NOT
        # alter user authorization or disconnect active VPN peers!
        try:
            synced_users = self._query_directory(
                ldap_cfg=ldap_cfg,
                schema=schema,
                base_dn=base_dn,
                vpn_group=vpn_group,
                hidden_users=hidden_users,
                now_utc=now,
            )
        except Exception as exc:
            logger.warning(
                "LDAP sync failed for domain '%s' (fail-safe active, keeping peers intact): %s",
                domain,
                exc,
            )
            return self._record_ldap_error(
                f"LDAP directory unreachable/error (fail-safe preserved active tunnels): {exc}"
            )

        return self._apply_directory_snapshot(
            domain=domain,
            synced_users=synced_users,
            now_utc=now,
        )

    def _record_ldap_error(self, error_message: str) -> dict[str, Any]:
        cfg = self.db.update_server_config(
            {
                "last_sync_status": "ldap_error",
                "last_sync_error": error_message,
            }
        )
        users = self.db.list_users()
        peers = self.db.list_peers()
        return {
            "status": "ldap_error",
            "synced_at": cfg.get("last_synced_at"),
            "total_users": len(users),
            "authorized_users": sum(1 for u in users if u["authorized"]),
            "active_peers": sum(1 for p in peers if p["effective_active"]),
            "suspended_peers": 0,
            "message": error_message,
        }

    def _query_directory(
        self,
        *,
        ldap_cfg: dict[str, Any],
        schema: str,
        base_dn: str,
        vpn_group: str,
        hidden_users: set[str],
        now_utc: datetime,
    ) -> list[SyncedLDAPUser]:
        conn = self.connection_factory(ldap_cfg)
        try:
            if schema == "ad":
                return self._query_ad(
                    conn=conn,
                    base_dn=base_dn,
                    vpn_group=vpn_group,
                    hidden_users=hidden_users,
                    now_utc=now_utc,
                )
            if schema in {"rfc2307", "ldap", "openldap"}:
                return self._query_rfc2307(
                    conn=conn,
                    base_dn=base_dn,
                    vpn_group=vpn_group,
                    hidden_users=hidden_users,
                    now_utc=now_utc,
                )
            raise ValueError(f"Unsupported LDAP schema '{schema}'")
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    def _query_ad(
        self,
        *,
        conn: LDAPSessionProtocol,
        base_dn: str,
        vpn_group: str,
        hidden_users: set[str],
        now_utc: datetime,
    ) -> list[SyncedLDAPUser]:
        group_member_dns: set[str] = set()
        group_member_usernames: set[str] = set()

        if vpn_group:
            esc_group = escape_filter_chars(vpn_group)
            group_filter = f"(&(objectClass=group)(sAMAccountName={esc_group}))"
            conn.search(
                search_base=base_dn,
                search_filter=group_filter,
                search_scope=ldap3.SUBTREE,
                attributes=["distinguishedName", "member", "sAMAccountName", "cn"],
            )
            group_entries = list(conn.entries)
            if not group_entries:
                conn.search(
                    search_base=base_dn,
                    search_filter=f"(&(objectClass=group)(cn={esc_group}))",
                    search_scope=ldap3.SUBTREE,
                    attributes=["distinguishedName", "member", "sAMAccountName", "cn"],
                )
                group_entries = list(conn.entries)

            if group_entries:
                grp = group_entries[0]
                group_dn = _entry_dn(grp)
                for m_dn in _entry_attr_list(grp, "member"):
                    group_member_dns.add(m_dn.lower())

                if group_dn:
                    chain_filter = (
                        f"(&(objectClass=user)(!(objectClass=computer))"
                        f"(memberOf:{LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(group_dn)}))"
                    )
                    conn.search(
                        search_base=base_dn,
                        search_filter=chain_filter,
                        search_scope=ldap3.SUBTREE,
                        attributes=["sAMAccountName", "distinguishedName"],
                    )
                    for member_entry in conn.entries:
                        m_dn = _entry_dn(member_entry)
                        if m_dn:
                            group_member_dns.add(m_dn.lower())
                        m_sam = _scalar_str(_entry_attr(member_entry, "sAMAccountName"))
                        if m_sam:
                            group_member_usernames.add(m_sam.lower())

        user_filter = "(&(objectClass=user)(!(objectClass=computer)))"
        conn.search(
            search_base=base_dn,
            search_filter=user_filter,
            search_scope=ldap3.SUBTREE,
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "displayName",
                "cn",
                "mail",
                "userAccountControl",
                "accountExpires",
                "memberOf",
            ],
        )

        results: list[SyncedLDAPUser] = []
        for entry in conn.entries:
            username = _scalar_str(_entry_attr(entry, "sAMAccountName"))
            if not username or username.endswith("$"):
                continue
            if username.lower() in hidden_users:
                continue

            dn = _entry_dn(entry)
            display_name = (
                _scalar_str(_entry_attr(entry, "displayName"))
                or _scalar_str(_entry_attr(entry, "cn"))
                or username
            )
            email = _scalar_str(_entry_attr(entry, "mail"))
            uac = _entry_attr(entry, "userAccountControl")
            expires = _entry_attr(entry, "accountExpires")

            ldap_active = (not is_ad_uac_disabled(uac)) and (
                not is_ad_account_expired(expires, now_utc=now_utc)
            )

            if not vpn_group:
                in_group = True
            else:
                in_group = (dn.lower() in group_member_dns) or (
                    username.lower() in group_member_usernames
                )

            results.append(
                SyncedLDAPUser(
                    username=username,
                    dn=dn,
                    display_name=display_name,
                    email=email,
                    ldap_active=ldap_active,
                    in_vpn_group=in_group,
                )
            )
        return results

    def _query_rfc2307(
        self,
        *,
        conn: LDAPSessionProtocol,
        base_dn: str,
        vpn_group: str,
        hidden_users: set[str],
        now_utc: datetime,
    ) -> list[SyncedLDAPUser]:
        member_uids: set[str] = set()
        member_dns: set[str] = set()

        if vpn_group:
            esc_group = escape_filter_chars(vpn_group)
            group_filter = (
                f"(&(|(objectClass=posixGroup)(objectClass=groupOfNames)"
                f"(objectClass=groupOfUniqueNames))(cn={esc_group}))"
            )
            conn.search(
                search_base=base_dn,
                search_filter=group_filter,
                search_scope=ldap3.SUBTREE,
                attributes=["cn", "memberUid", "member", "uniqueMember"],
            )
            for grp in conn.entries:
                for uid_val in _entry_attr_list(grp, "memberUid"):
                    member_uids.add(uid_val.lower())
                for dn_val in _entry_attr_list(grp, "member"):
                    member_dns.add(dn_val.lower())
                for udn_val in _entry_attr_list(grp, "uniqueMember"):
                    member_dns.add(udn_val.lower())

        user_filter = "(&(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))(uid=*))"
        conn.search(
            search_base=base_dn,
            search_filter=user_filter,
            search_scope=ldap3.SUBTREE,
            attributes=[
                "uid",
                "cn",
                "displayName",
                "mail",
                "pwdAccountLockedTime",
                "shadowExpire",
                "nsAccountLock",
            ],
        )

        results: list[SyncedLDAPUser] = []
        for entry in conn.entries:
            username = _scalar_str(_entry_attr(entry, "uid"))
            if not username or username.lower() in hidden_users:
                continue

            dn = _entry_dn(entry)
            display_name = (
                _scalar_str(_entry_attr(entry, "displayName"))
                or _scalar_str(_entry_attr(entry, "cn"))
                or username
            )
            email = _scalar_str(_entry_attr(entry, "mail"))
            pwd_locked = _entry_attr(entry, "pwdAccountLockedTime")
            shadow_exp = _entry_attr(entry, "shadowExpire")
            ns_lock = _entry_attr(entry, "nsAccountLock")

            ldap_active = is_rfc2307_account_active(
                pwd_locked_time=pwd_locked,
                shadow_expire=shadow_exp,
                ns_account_lock=ns_lock,
                now_utc=now_utc,
            )

            if not vpn_group:
                in_group = True
            else:
                in_group = (username.lower() in member_uids) or (dn.lower() in member_dns)

            results.append(
                SyncedLDAPUser(
                    username=username,
                    dn=dn,
                    display_name=display_name,
                    email=email,
                    ldap_active=ldap_active,
                    in_vpn_group=in_group,
                )
            )
        return results

    def _apply_directory_snapshot(
        self,
        *,
        domain: str,
        synced_users: list[SyncedLDAPUser],
        now_utc: datetime,
    ) -> dict[str, Any]:
        now_iso = now_utc.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        cfg = self.db.get_server_config()
        iface = cfg["interface_name"]

        # Snapshot pre-sync user and peer authorization so we detect transitions accurately
        users_before = {u["username"].lower(): u for u in self.db.list_users()}
        peers_before = {p["id"]: p for p in self.db.list_peers(include_revoked=False)}
        live_dump = self.wg_engine.read_dump(iface)
        if live_dump:
            self.db.update_peers_telemetry(live_dump)

        seen_lower: set[str] = set()
        for item in synced_users:
            seen_lower.add(item.username.lower())
            self.db.upsert_user(
                username=item.username,
                domain=domain,
                dn=item.dn,
                display_name=item.display_name,
                email=item.email,
                ldap_active=item.ldap_active,
                in_vpn_group=item.in_vpn_group,
                last_synced_at=now_iso,
            )

        # Mark previously known users or peer owners missing from LDAP as inactive/removed
        existing_users_by_lower = {u["username"].lower(): u for u in self.db.list_users()}
        all_known_usernames = set(existing_users_by_lower.keys()) | {
            p["username"].lower() for p in peers_before.values()
        }
        for uname_lower in all_known_usernames:
            if uname_lower in seen_lower:
                continue
            prev_user = existing_users_by_lower.get(uname_lower)
            canonical_name = prev_user["username"] if prev_user else uname_lower
            self.db.upsert_user(
                username=canonical_name,
                domain=domain,
                dn=prev_user["dn"] if prev_user else "",
                display_name=prev_user["display_name"] if prev_user else canonical_name,
                email=prev_user["email"] if prev_user else "",
                ldap_active=False,
                in_vpn_group=False,
                last_synced_at=now_iso,
            )

        # Immediately terminate OpenVPN sessions for any user who lost AD/LDAP authorization
        if self.on_user_deauthorized is not None:
            for user_after in self.db.list_users():
                if not user_after["authorized"]:
                    prev_u = users_before.get(user_after["username"].lower())
                    if prev_u is None or prev_u["authorized"]:
                        try:
                            self.on_user_deauthorized(user_after["username"])
                        except Exception as exc:
                            logger.warning(
                                "OpenVPN session kill hook failed for '%s': %s",
                                user_after["username"],
                                exc,
                            )

        # Enforce immediate kernel peer eviction or restoration
        peers_after = self.db.list_peers(include_revoked=False)
        suspended_peers = 0
        restored_peers = 0

        for peer in peers_after:
            if peer["protocol"] != "wireguard":
                continue
            pid = peer["id"]
            prev = peers_before.get(pid)
            was_effective = bool(prev and prev["effective_active"])
            in_kernel = peer["public_key"] in live_dump

            if not peer["user_authorized"]:
                if was_effective or in_kernel:
                    self.db.fold_peer_kernel_counters(pid)
                    self.wg_engine.remove_peer_immediately(iface, peer["public_key"])
                    suspended_peers += 1
                    self.db.log_audit(
                        event_type="peer_auto_suspended",
                        actor="ldap_sync",
                        username=peer["username"],
                        peer_id=pid,
                        details=(
                            f"Automatically removed peer '{peer['device_name']}' ({peer['assigned_ip']}) "
                            f"from {iface}: user lost AD/LDAP VPN authorization"
                        ),
                    )
            elif peer["effective_active"] and not was_effective:
                restored_peers += 1
                self.db.log_audit(
                    event_type="peer_auto_restored",
                    actor="ldap_sync",
                    username=peer["username"],
                    peer_id=pid,
                    details=(
                        f"Restored peer '{peer['device_name']}' ({peer['assigned_ip']}) "
                        f"on {iface}: user regained AD/LDAP VPN authorization"
                    ),
                )

        if restored_peers > 0:
            server_priv = self.db.get_server_private_key()
            active_wg_peers = self.db.list_active_wireguard_peers_with_psk()
            self.wg_engine.reconcile_interface(
                interface_name=iface,
                server_private_key=server_priv,
                wg_port=cfg["wg_port"],
                wg_network=cfg["wg_network"],
                wg_mtu=cfg["wg_mtu"],
                active_peers=active_wg_peers,
            )

        self.db.update_server_config(
            {
                "last_synced_at": now_iso,
                "last_sync_status": "ok",
                "last_sync_error": None,
            }
        )

        final_users = self.db.list_users()
        final_peers = self.db.list_peers(include_revoked=False)
        authorized_count = sum(1 for u in final_users if u["authorized"])
        active_peer_count = sum(1 for p in final_peers if p["effective_active"])

        return {
            "status": "ok",
            "synced_at": now_iso,
            "total_users": len(final_users),
            "authorized_users": authorized_count,
            "active_peers": active_peer_count,
            "suspended_peers": suspended_peers,
            "message": (
                f"Synchronized {len(final_users)} users ({authorized_count} authorized, "
                f"{suspended_peers} peer(s) suspended)"
            ),
        }

    async def sync_async(self) -> dict[str, Any]:
        """Thread-offloaded async wrapper around `sync_now()` serialized by lock."""
        async with self._sync_lock:
            return await asyncio.to_thread(self.sync_now)
