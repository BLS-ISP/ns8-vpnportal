"""Live AD/OpenLDAP user authentication, sliding-window rate limiting, and HMAC session cookies."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPInvalidCredentialsResult
from ldap3.utils.conv import escape_filter_chars

from .db import Database, utc_now_iso
from .ldap_sync import (
    DEFAULT_HIDDEN_USERS,
    LDAP_MATCHING_RULE_IN_CHAIN,
    LDAPConnectionFactory,
    _entry_attr,
    _entry_attr_list,
    _entry_dn,
    _scalar_str,
    default_ldap_connection_factory,
    is_ad_account_expired,
    is_ad_uac_disabled,
    is_rfc2307_account_active,
    load_ldap_config_file,
)


logger = logging.getLogger("ns8_vpn.portal_auth")

SESSION_COOKIE_NAME = "ns8_vpn_session"
CSRF_HEADER_NAME = "X-Requested-With"
CSRF_HEADER_VALUE = "NS8VPNPortal"
DEFAULT_SESSION_TTL_SECONDS = 8 * 3600


UserBindVerifier = Callable[[dict[str, Any], str, str], bool]


def default_user_bind_verifier(ldap_cfg: dict[str, Any], user_dn: str, password: str) -> bool:
    """Verify non-empty user password via direct `ldap3.Connection` bind as `user_dn`."""
    if not user_dn or not password:
        return False
    host = str(ldap_cfg.get("host") or "127.0.0.1").strip()
    port = int(ldap_cfg.get("port") or 389)
    use_ssl = bool(ldap_cfg.get("use_ssl") or ldap_cfg.get("tls") or port == 636)

    server = ldap3.Server(
        host=host,
        port=port,
        use_ssl=use_ssl,
        get_info=ldap3.NONE,
        connect_timeout=8,
    )
    try:
        conn = ldap3.Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=True,
            receive_timeout=10,
            raise_exceptions=True,
            authentication=ldap3.SIMPLE,
        )
        try:
            return bool(conn.bound)
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
    except (LDAPBindError, LDAPInvalidCredentialsResult):
        return False


@dataclass
class AuthResult:
    ok: bool
    status_code: int
    error_code: str = ""
    message: str = ""
    user: dict[str, Any] | None = None


class LoginRateLimiter:
    """Thread-safe sliding-window brute-force rate limiter."""

    def __init__(self, max_failures: int = 5, window_seconds: int = 300) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        recent = [ts for ts in self._failures.get(key, []) if ts > cutoff]
        if recent:
            self._failures[key] = recent
        else:
            self._failures.pop(key, None)
        return recent

    def is_limited(self, *keys: str, now: float | None = None) -> bool:
        ts = time.monotonic() if now is None else now
        with self._lock:
            for raw_key in keys:
                key = (raw_key or "").strip().lower()
                if not key:
                    continue
                if len(self._prune(key, ts)) >= self.max_failures:
                    return True
        return False

    def record_failure(self, *keys: str, now: float | None = None) -> None:
        ts = time.monotonic() if now is None else now
        with self._lock:
            for raw_key in keys:
                key = (raw_key or "").strip().lower()
                if not key:
                    continue
                recent = self._prune(key, ts)
                recent.append(ts)
                self._failures[key] = recent

    def reset(self, *keys: str) -> None:
        with self._lock:
            for raw_key in keys:
                key = (raw_key or "").strip().lower()
                if key:
                    self._failures.pop(key, None)


class SessionManager:
    """Stateless HMAC-SHA256 signed session tokens with domain-separated key derivation."""

    def __init__(self, master_key: bytes, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> None:
        self._signing_key = hmac.new(
            bytes(master_key),
            b"ns8-vpn-portal-session-hmac-v1",
            hashlib.sha256,
        ).digest()
        self.ttl_seconds = ttl_seconds

    def create_token(self, username: str, now_epoch: int | None = None) -> str:
        now = int(time.time()) if now_epoch is None else int(now_epoch)
        payload = {
            "u": username,
            "iat": now,
            "exp": now + self.ttl_seconds,
        }
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
        sig = hmac.new(self._signing_key, payload_b64.encode("ascii"), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
        return f"{payload_b64}.{sig_b64}"

    def verify_token(self, token: str | None, now_epoch: int | None = None) -> dict[str, Any] | None:
        if not token or not isinstance(token, str) or "." not in token:
            return None
        payload_b64, _, sig_b64 = token.partition(".")
        if not payload_b64 or not sig_b64:
            return None

        expected_sig = hmac.new(
            self._signing_key, payload_b64.encode("ascii"), hashlib.sha256
        ).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            return None

        try:
            pad = "=" * (-len(payload_b64) % 4)
            raw = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
            data = json.loads(raw.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None

        if not isinstance(data, dict) or not data.get("u"):
            return None

        now = int(time.time()) if now_epoch is None else int(now_epoch)
        exp = int(data.get("exp") or 0)
        if exp <= now:
            return None
        return data


class PortalAuthenticator:
    """Authenticates end users live against NS8 Active Directory / OpenLDAP."""

    def __init__(
        self,
        db: Database,
        ldap_config_path: Path,
        connection_factory: LDAPConnectionFactory | None = None,
        user_bind_verifier: UserBindVerifier | None = None,
    ) -> None:
        self.db = db
        self.ldap_config_path = ldap_config_path
        self.connection_factory = connection_factory or default_ldap_connection_factory
        self.user_bind_verifier = user_bind_verifier or default_user_bind_verifier

    def authenticate_user(
        self,
        username: str,
        password: str,
        *,
        now_utc: datetime | None = None,
    ) -> AuthResult:
        """Bind service account, resolve user safely, verify password bind, and enforce group/active status."""
        clean_user = (username or "").strip()
        # SECURITY: Strictly reject empty username or empty password before any LDAP bind!
        if not clean_user or not password:
            return AuthResult(
                ok=False,
                status_code=401,
                error_code="invalid_credentials",
                message="Invalid username or password",
            )

        if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean_user) or len(clean_user) > 128:
            return AuthResult(
                ok=False,
                status_code=401,
                error_code="invalid_credentials",
                message="Invalid username or password",
            )

        try:
            ldap_cfg = load_ldap_config_file(self.ldap_config_path)
        except Exception as exc:
            logger.warning("Failed reading ldap.json during auth: %s", exc)
            return AuthResult(
                ok=False,
                status_code=503,
                error_code="ldap_unavailable",
                message="Authentication directory configuration error",
            )

        if not ldap_cfg or not ldap_cfg.get("configured") or not ldap_cfg.get("base_dn"):
            return AuthResult(
                ok=False,
                status_code=503,
                error_code="ldap_not_configured",
                message="User authentication directory is not configured",
            )

        server_cfg = self.db.get_server_config()
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

        if clean_user.lower() in hidden_users or clean_user.endswith("$"):
            return AuthResult(
                ok=False,
                status_code=401,
                error_code="invalid_credentials",
                message="Invalid username or password",
            )

        now = now_utc or datetime.now(timezone.utc)

        try:
            resolved = self._lookup_user_and_status(
                ldap_cfg=ldap_cfg,
                schema=schema,
                base_dn=base_dn,
                vpn_group=vpn_group,
                username=clean_user,
                now_utc=now,
            )
        except Exception as exc:
            logger.warning("LDAP directory error during user lookup: %s", exc)
            return AuthResult(
                ok=False,
                status_code=503,
                error_code="ldap_unavailable",
                message="Authentication service temporarily unavailable",
            )

        if resolved is None:
            return AuthResult(
                ok=False,
                status_code=401,
                error_code="invalid_credentials",
                message="Invalid username or password",
            )

        user_dn = resolved["dn"]
        try:
            bound_ok = self.user_bind_verifier(ldap_cfg, user_dn, password)
        except Exception as exc:
            logger.warning("LDAP error during user bind verification: %s", exc)
            return AuthResult(
                ok=False,
                status_code=503,
                error_code="ldap_unavailable",
                message="Authentication service temporarily unavailable",
            )

        if not bound_ok:
            return AuthResult(
                ok=False,
                status_code=401,
                error_code="invalid_credentials",
                message="Invalid username or password",
            )

        updated_user = self.db.upsert_user(
            username=resolved["username"],
            domain=domain,
            dn=user_dn,
            display_name=resolved["display_name"],
            email=resolved["email"],
            ldap_active=resolved["ldap_active"],
            in_vpn_group=resolved["in_vpn_group"],
            last_synced_at=utc_now_iso(),
        )

        if not updated_user["authorized"]:
            return AuthResult(
                ok=False,
                status_code=403,
                error_code="user_not_authorized",
                message="Your account is disabled or not a member of the authorized VPN group",
                user=updated_user,
            )

        return AuthResult(
            ok=True,
            status_code=200,
            user=updated_user,
        )

    def _lookup_user_and_status(
        self,
        *,
        ldap_cfg: dict[str, Any],
        schema: str,
        base_dn: str,
        vpn_group: str,
        username: str,
        now_utc: datetime,
    ) -> dict[str, Any] | None:
        escaped_username = escape_filter_chars(username)
        conn = self.connection_factory(ldap_cfg)
        try:
            if schema == "ad":
                user_filter = (
                    f"(&(objectClass=user)(!(objectClass=computer))"
                    f"(sAMAccountName={escaped_username}))"
                )
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
                    ],
                )
                if not conn.entries:
                    return None
                entry = conn.entries[0]
                dn = _entry_dn(entry)
                canonical = _scalar_str(_entry_attr(entry, "sAMAccountName")) or username
                if not dn or canonical.endswith("$"):
                    return None

                display_name = (
                    _scalar_str(_entry_attr(entry, "displayName"))
                    or _scalar_str(_entry_attr(entry, "cn"))
                    or canonical
                )
                email = _scalar_str(_entry_attr(entry, "mail"))
                uac = _entry_attr(entry, "userAccountControl")
                expires = _entry_attr(entry, "accountExpires")
                ldap_active = (not is_ad_uac_disabled(uac)) and (
                    not is_ad_account_expired(expires, now_utc=now_utc)
                )

                in_group = True
                if vpn_group:
                    in_group = self._check_ad_group_membership(
                        conn=conn,
                        base_dn=base_dn,
                        vpn_group=vpn_group,
                        user_dn=dn,
                        canonical_username=canonical,
                    )

                return {
                    "username": canonical,
                    "dn": dn,
                    "display_name": display_name,
                    "email": email,
                    "ldap_active": ldap_active,
                    "in_vpn_group": in_group,
                }

            # OpenLDAP / RFC2307
            user_filter = (
                f"(&(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))"
                f"(uid={escaped_username}))"
            )
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
            if not conn.entries:
                return None
            entry = conn.entries[0]
            dn = _entry_dn(entry)
            canonical = _scalar_str(_entry_attr(entry, "uid")) or username
            if not dn:
                return None

            display_name = (
                _scalar_str(_entry_attr(entry, "displayName"))
                or _scalar_str(_entry_attr(entry, "cn"))
                or canonical
            )
            email = _scalar_str(_entry_attr(entry, "mail"))
            ldap_active = is_rfc2307_account_active(
                pwd_locked_time=_entry_attr(entry, "pwdAccountLockedTime"),
                shadow_expire=_entry_attr(entry, "shadowExpire"),
                ns_account_lock=_entry_attr(entry, "nsAccountLock"),
                now_utc=now_utc,
            )

            in_group = True
            if vpn_group:
                in_group = self._check_rfc2307_group_membership(
                    conn=conn,
                    base_dn=base_dn,
                    vpn_group=vpn_group,
                    user_dn=dn,
                    canonical_uid=canonical,
                )

            return {
                "username": canonical,
                "dn": dn,
                "display_name": display_name,
                "email": email,
                "ldap_active": ldap_active,
                "in_vpn_group": in_group,
            }
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    @staticmethod
    def _check_ad_group_membership(
        *,
        conn: Any,
        base_dn: str,
        vpn_group: str,
        user_dn: str,
        canonical_username: str,
    ) -> bool:
        esc_group = escape_filter_chars(vpn_group)
        conn.search(
            search_base=base_dn,
            search_filter=f"(&(objectClass=group)(sAMAccountName={esc_group}))",
            search_scope=ldap3.SUBTREE,
            attributes=["distinguishedName", "member"],
        )
        group_entries = list(conn.entries)
        if not group_entries:
            conn.search(
                search_base=base_dn,
                search_filter=f"(&(objectClass=group)(cn={esc_group}))",
                search_scope=ldap3.SUBTREE,
                attributes=["distinguishedName", "member"],
            )
            group_entries = list(conn.entries)
        if not group_entries:
            return False

        grp = group_entries[0]
        direct_members = {m.lower() for m in _entry_attr_list(grp, "member")}
        if user_dn.lower() in direct_members:
            return True

        group_dn = _entry_dn(grp)
        if not group_dn:
            return False

        chain_filter = (
            f"(&(objectClass=user)(!(objectClass=computer))"
            f"(sAMAccountName={escape_filter_chars(canonical_username)})"
            f"(memberOf:{LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(group_dn)}))"
        )
        conn.search(
            search_base=base_dn,
            search_filter=chain_filter,
            search_scope=ldap3.SUBTREE,
            attributes=["sAMAccountName", "distinguishedName"],
        )
        for m_entry in conn.entries:
            m_dn = _entry_dn(m_entry)
            m_sam = _scalar_str(_entry_attr(m_entry, "sAMAccountName"))
            if m_dn.lower() == user_dn.lower() or m_sam.lower() == canonical_username.lower():
                return True
        return False

    @staticmethod
    def _check_rfc2307_group_membership(
        *,
        conn: Any,
        base_dn: str,
        vpn_group: str,
        user_dn: str,
        canonical_uid: str,
    ) -> bool:
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
            uids = {u.lower() for u in _entry_attr_list(grp, "memberUid")}
            dns = {d.lower() for d in _entry_attr_list(grp, "member")} | {
                d.lower() for d in _entry_attr_list(grp, "uniqueMember")
            }
            if canonical_uid.lower() in uids or user_dn.lower() in dns:
                return True
        return False
