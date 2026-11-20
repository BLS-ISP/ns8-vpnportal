"""SQLite WAL persistence layer for ns8-vpn controller (Phases 1-3)."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import Settings
from .crypto import (
    decrypt_optional,
    decrypt_secret,
    encrypt_optional,
    encrypt_secret,
    ensure_master_key,
    generate_wg_keypair,
)
from .openvpn_pki import OpenVPNPKIBundle, generate_openvpn_pki


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format (`...Z`)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS server_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    configured INTEGER NOT NULL DEFAULT 0,
    interface_name TEXT NOT NULL,
    endpoint_host TEXT NOT NULL DEFAULT '',
    wg_port INTEGER NOT NULL DEFAULT 51820,
    wg_network TEXT NOT NULL DEFAULT '10.199.0.0/24',
    tunnel_mode TEXT NOT NULL DEFAULT 'split',
    allowed_cidrs TEXT NOT NULL DEFAULT '[]',
    dns_servers TEXT NOT NULL DEFAULT '[]',
    dns_search_domain TEXT NOT NULL DEFAULT '',
    wg_mtu INTEGER NOT NULL DEFAULT 1380,
    persistent_keepalive INTEGER NOT NULL DEFAULT 25,
    nat_enabled INTEGER NOT NULL DEFAULT 1,
    user_domain TEXT NOT NULL DEFAULT '',
    vpn_group TEXT NOT NULL DEFAULT '',
    max_devices_per_user INTEGER NOT NULL DEFAULT 3,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 5,
    portal_enabled INTEGER NOT NULL DEFAULT 0,
    portal_domain TEXT NOT NULL DEFAULT '',
    portal_lets_encrypt INTEGER NOT NULL DEFAULT 0,
    portal_http2https INTEGER NOT NULL DEFAULT 1,
    portal_totp_mode TEXT NOT NULL DEFAULT 'optional',
    ovpn_enabled INTEGER NOT NULL DEFAULT 0,
    ovpn_proto TEXT NOT NULL DEFAULT 'tcp',
    ovpn_port INTEGER NOT NULL DEFAULT 1194,
    ovpn_public_port INTEGER NOT NULL DEFAULT 1194,
    ovpn_network TEXT NOT NULL DEFAULT '10.199.1.0/24',
    ovpn_totp_required INTEGER NOT NULL DEFAULT 0,
    ovpn_interface_name TEXT NOT NULL DEFAULT 'tun-vpn1',
    server_private_key_enc TEXT NOT NULL,
    server_public_key TEXT NOT NULL,
    last_synced_at TEXT,
    last_sync_status TEXT NOT NULL DEFAULT 'never',
    last_sync_error TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY COLLATE NOCASE,
    domain TEXT NOT NULL DEFAULT '',
    dn TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    ldap_active INTEGER NOT NULL DEFAULT 1,
    in_vpn_group INTEGER NOT NULL DEFAULT 1,
    totp_secret_enc TEXT,
    totp_pending_enc TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    last_synced_at TEXT
);

CREATE TABLE IF NOT EXISTS peers (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE,
    protocol TEXT NOT NULL DEFAULT 'wireguard',
    device_name TEXT NOT NULL,
    assigned_ip TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    private_key_enc TEXT NOT NULL,
    preshared_key_enc TEXT,
    admin_enabled INTEGER NOT NULL DEFAULT 1,
    rx_bytes_offset INTEGER NOT NULL DEFAULT 0,
    tx_bytes_offset INTEGER NOT NULL DEFAULT 0,
    last_rx_kernel INTEGER NOT NULL DEFAULT 0,
    last_tx_kernel INTEGER NOT NULL DEFAULT 0,
    last_handshake_at TEXT,
    last_endpoint TEXT,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_active_ip
    ON peers(assigned_ip)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_peers_username
    ON peers(username);

CREATE TABLE IF NOT EXISTS openvpn_pki (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ca_cert_pem TEXT NOT NULL,
    ca_key_enc TEXT NOT NULL,
    server_cert_pem TEXT NOT NULL,
    server_key_enc TEXT NOT NULL,
    client_cert_pem TEXT NOT NULL,
    client_key_enc TEXT NOT NULL,
    tls_crypt_key_enc TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS site_to_site_tunnels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    assigned_ip TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL UNIQUE,
    private_key_enc TEXT,
    preshared_key_enc TEXT,
    remote_endpoint TEXT NOT NULL DEFAULT '',
    remote_cidrs_json TEXT NOT NULL DEFAULT '[]',
    rx_bytes_offset INTEGER NOT NULL DEFAULT 0,
    tx_bytes_offset INTEGER NOT NULL DEFAULT 0,
    last_rx_kernel INTEGER NOT NULL DEFAULT 0,
    last_tx_kernel INTEGER NOT NULL DEFAULT 0,
    last_handshake_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    username TEXT,
    peer_id TEXT,
    details TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type
    ON audit_log(event_type);

CREATE INDEX IF NOT EXISTS idx_audit_log_username
    ON audit_log(username COLLATE NOCASE);
"""

AUDIT_LOG_MAX_ROWS = 10_000


class Database:
    """Thread-safe SQLite WAL persistence manager with AES-256-GCM secret handling."""

    def __init__(self, settings: Settings, master_key: bytes | None = None) -> None:
        self.settings = settings
        self.settings.ensure_directories()
        self.db_path: Path = self.settings.db_path
        self.master_key: bytes = (
            master_key if master_key is not None else ensure_master_key(self.settings.master_key_path)
        )
        self.audit_log_max_rows: int = AUDIT_LOG_MAX_ROWS
        self._lock = threading.RLock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = self._connect()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        existing_cols = {
            row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in existing_cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def initialize(self) -> None:
        """Create/migrate schema in WAL mode and ensure singleton server_config row exists."""
        with self.connection() as conn:
            conn.executescript(SCHEMA_SQL)

            # Idempotent forward migrations for existing Phase 1 databases / restored backups
            self._ensure_column(
                conn, "server_config", "portal_totp_mode", "TEXT NOT NULL DEFAULT 'optional'"
            )
            self._ensure_column(
                conn, "server_config", "ovpn_enabled", "INTEGER NOT NULL DEFAULT 0"
            )
            self._ensure_column(
                conn, "server_config", "ovpn_proto", "TEXT NOT NULL DEFAULT 'tcp'"
            )
            self._ensure_column(
                conn, "server_config", "ovpn_port", "INTEGER NOT NULL DEFAULT 1194"
            )
            self._ensure_column(
                conn, "server_config", "ovpn_public_port", "INTEGER NOT NULL DEFAULT 1194"
            )
            self._ensure_column(
                conn, "server_config", "ovpn_network", "TEXT NOT NULL DEFAULT '10.199.1.0/24'"
            )
            self._ensure_column(
                conn, "server_config", "ovpn_totp_required", "INTEGER NOT NULL DEFAULT 0"
            )
            self._ensure_column(
                conn, "server_config", "ovpn_interface_name", "TEXT NOT NULL DEFAULT 'tun-vpn1'"
            )
            self._ensure_column(conn, "users", "totp_pending_enc", "TEXT")
            self._ensure_column(conn, "users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0")

            row = conn.execute(
                "SELECT id, interface_name, ovpn_interface_name FROM server_config WHERE id = 1"
            ).fetchone()
            if row is None:
                priv_key, pub_key = generate_wg_keypair()
                priv_enc = encrypt_secret(priv_key, self.master_key)
                now = utc_now_iso()
                tunnel_mode = (
                    self.settings.initial_tunnel_mode
                    if self.settings.initial_tunnel_mode in {"split", "full"}
                    else "split"
                )
                totp_mode = (
                    self.settings.initial_portal_totp_mode
                    if self.settings.initial_portal_totp_mode in {"disabled", "optional", "required"}
                    else "optional"
                )
                ovpn_proto = (
                    self.settings.initial_ovpn_proto
                    if self.settings.initial_ovpn_proto in {"tcp", "udp"}
                    else "tcp"
                )
                configured = 1 if self.settings.initial_endpoint_host else 0
                conn.execute(
                    """
                    INSERT INTO server_config (
                        id, configured, interface_name, endpoint_host, wg_port, wg_network,
                        tunnel_mode, allowed_cidrs, dns_servers, dns_search_domain,
                        wg_mtu, persistent_keepalive, nat_enabled, user_domain, vpn_group,
                        max_devices_per_user, sync_interval_minutes,
                        portal_enabled, portal_domain, portal_lets_encrypt, portal_http2https, portal_totp_mode,
                        ovpn_enabled, ovpn_proto, ovpn_port, ovpn_public_port, ovpn_network, ovpn_totp_required, ovpn_interface_name,
                        server_private_key_enc, server_public_key, updated_at
                    ) VALUES (
                        1, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?
                    )
                    """,
                    (
                        configured,
                        self.settings.interface_name,
                        self.settings.initial_endpoint_host,
                        self.settings.initial_wg_port,
                        self.settings.initial_wg_network,
                        tunnel_mode,
                        json.dumps(self.settings.initial_allowed_cidrs),
                        json.dumps(self.settings.initial_dns_servers),
                        self.settings.initial_dns_search_domain,
                        self.settings.initial_wg_mtu,
                        self.settings.initial_persistent_keepalive,
                        1 if self.settings.initial_nat_enabled else 0,
                        self.settings.initial_user_domain,
                        self.settings.initial_vpn_group,
                        self.settings.initial_max_devices_per_user,
                        self.settings.initial_sync_interval_minutes,
                        1 if self.settings.initial_portal_enabled else 0,
                        self.settings.initial_portal_domain,
                        1 if self.settings.initial_portal_lets_encrypt else 0,
                        1 if self.settings.initial_portal_http2https else 0,
                        totp_mode,
                        1 if self.settings.initial_ovpn_enabled else 0,
                        ovpn_proto,
                        self.settings.initial_ovpn_port,
                        self.settings.initial_ovpn_public_port,
                        self.settings.initial_ovpn_network,
                        1 if self.settings.initial_ovpn_totp_required else 0,
                        self.settings.ovpn_interface_name,
                        priv_enc,
                        pub_key,
                        now,
                    ),
                )
            elif (
                row["interface_name"] != self.settings.interface_name
                or row["ovpn_interface_name"] != self.settings.ovpn_interface_name
            ):
                conn.execute(
                    """
                    UPDATE server_config
                    SET interface_name = ?, ovpn_interface_name = ?, updated_at = ?
                    WHERE id = 1
                    """,
                    (
                        self.settings.interface_name,
                        self.settings.ovpn_interface_name,
                        utc_now_iso(),
                    ),
                )

    def rotate_server_keys(self) -> tuple[str, str]:
        """Generate and store a fresh server WireGuard keypair (used e.g. on clone)."""
        priv_key, pub_key = generate_wg_keypair()
        priv_enc = encrypt_secret(priv_key, self.master_key)
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE server_config
                SET server_private_key_enc = ?, server_public_key = ?, updated_at = ?
                WHERE id = 1
                """,
                (priv_enc, pub_key, utc_now_iso()),
            )
        return priv_key, pub_key

    def get_server_config(self) -> dict[str, Any]:
        """Return parsed server_config dictionary (without decrypting private key)."""
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM server_config WHERE id = 1").fetchone()
            if row is None:
                raise RuntimeError("server_config singleton row missing; call initialize() first")
            return self._row_to_server_config(row)

    def get_server_private_key(self) -> str:
        """Decrypt and return the server's WireGuard private key."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT server_private_key_enc FROM server_config WHERE id = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("server_config singleton row missing")
            return decrypt_secret(row["server_private_key_enc"], self.master_key)

    @staticmethod
    def _row_to_server_config(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "configured": bool(row["configured"]),
            "interface_name": row["interface_name"],
            "endpoint_host": row["endpoint_host"],
            "wg_port": int(row["wg_port"]),
            "wg_network": row["wg_network"],
            "tunnel_mode": row["tunnel_mode"],
            "allowed_cidrs": json.loads(row["allowed_cidrs"] or "[]"),
            "dns_servers": json.loads(row["dns_servers"] or "[]"),
            "dns_search_domain": row["dns_search_domain"] or "",
            "wg_mtu": int(row["wg_mtu"]),
            "persistent_keepalive": int(row["persistent_keepalive"]),
            "nat_enabled": bool(row["nat_enabled"]),
            "user_domain": row["user_domain"] or "",
            "vpn_group": row["vpn_group"] or "",
            "max_devices_per_user": int(row["max_devices_per_user"]),
            "sync_interval_minutes": int(row["sync_interval_minutes"]),
            "portal_enabled": bool(row["portal_enabled"]),
            "portal_domain": row["portal_domain"] or "",
            "portal_lets_encrypt": bool(row["portal_lets_encrypt"]),
            "portal_http2https": bool(row["portal_http2https"]),
            "portal_totp_mode": row["portal_totp_mode"] or "optional",
            "ovpn_enabled": bool(row["ovpn_enabled"]),
            "ovpn_proto": row["ovpn_proto"] or "tcp",
            "ovpn_port": int(row["ovpn_port"]),
            "ovpn_public_port": int(row["ovpn_public_port"]),
            "ovpn_network": row["ovpn_network"] or "10.199.1.0/24",
            "ovpn_totp_required": bool(row["ovpn_totp_required"]),
            "ovpn_interface_name": row["ovpn_interface_name"] or "tun-vpn1",
            "server_public_key": row["server_public_key"],
            "last_synced_at": row["last_synced_at"],
            "last_sync_status": row["last_sync_status"] or "never",
            "last_sync_error": row["last_sync_error"],
            "updated_at": row["updated_at"],
        }

    def update_server_config(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Update server_config fields and return the updated configuration dict."""
        allowed_columns = {
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
            "last_synced_at",
            "last_sync_status",
            "last_sync_error",
        }
        bool_cols = {
            "configured",
            "nat_enabled",
            "portal_enabled",
            "portal_lets_encrypt",
            "portal_http2https",
            "ovpn_enabled",
            "ovpn_totp_required",
        }
        json_cols = {"allowed_cidrs", "dns_servers"}

        assignments: list[str] = []
        params: list[Any] = []
        for key, val in updates.items():
            if key not in allowed_columns:
                continue
            assignments.append(f"{key} = ?")
            if key in bool_cols:
                params.append(1 if val else 0)
            elif key in json_cols:
                params.append(json.dumps(list(val)))
            else:
                params.append(val)

        if assignments:
            assignments.append("updated_at = ?")
            params.append(utc_now_iso())
            sql = f"UPDATE server_config SET {', '.join(assignments)} WHERE id = 1"
            with self.connection() as conn:
                conn.execute(sql, params)

        return self.get_server_config()

    def _insert_audit_row(
        self,
        conn: sqlite3.Connection,
        *,
        timestamp: str,
        event_type: str,
        actor: str,
        username: str | None,
        peer_id: str | None,
        details: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO audit_log (timestamp, event_type, actor, username, peer_id, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (timestamp, event_type, actor, username, peer_id, details),
        )
        max_rows = max(1, int(self.audit_log_max_rows))
        cutoff_row = conn.execute(
            "SELECT id FROM audit_log ORDER BY id DESC LIMIT 1 OFFSET ?",
            (max_rows,),
        ).fetchone()
        if cutoff_row is not None:
            conn.execute("DELETE FROM audit_log WHERE id <= ?", (int(cutoff_row["id"]),))

    def log_audit(
        self,
        event_type: str,
        details: str = "",
        actor: str = "system",
        username: str | None = None,
        peer_id: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        """Record an audit trail entry and cap retention to `self.audit_log_max_rows`."""
        now = utc_now_iso()
        if conn is not None:
            self._insert_audit_row(
                conn,
                timestamp=now,
                event_type=event_type,
                actor=actor,
                username=username,
                peer_id=peer_id,
                details=details,
            )
            return
        with self.connection() as own_conn:
            self._insert_audit_row(
                own_conn,
                timestamp=now,
                event_type=event_type,
                actor=actor,
                username=username,
                peer_id=peer_id,
                details=details,
            )

    def list_audit_logs(
        self,
        limit: int = 200,
        event_type: str = "",
        username: str = "",
    ) -> tuple[list[dict[str, Any]], int]:
        """Return `(entries_desc, total_matching_count)` from `audit_log`."""
        safe_limit = max(1, int(limit))
        clauses: list[str] = []
        params: list[Any] = []

        clean_event = (event_type or "").strip()
        if clean_event:
            clauses.append("event_type = ? COLLATE NOCASE")
            params.append(clean_event)

        clean_user = (username or "").strip()
        if clean_user:
            clauses.append("username = ? COLLATE NOCASE")
            params.append(clean_user)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self.connection() as conn:
            total_row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM audit_log {where_sql}",
                params,
            ).fetchone()
            total = int(total_row["cnt"]) if total_row is not None else 0

            rows = conn.execute(
                f"""
                SELECT id, timestamp, event_type, actor, username, peer_id, details
                FROM audit_log
                {where_sql}
                ORDER BY id DESC
                LIMIT ?
                """,
                [*params, safe_limit],
            ).fetchall()

            entries = [
                {
                    "id": int(r["id"]),
                    "timestamp": str(r["timestamp"]),
                    "event_type": str(r["event_type"]),
                    "actor": str(r["actor"] or "system"),
                    "username": str(r["username"]) if r["username"] is not None else None,
                    "peer_id": str(r["peer_id"]) if r["peer_id"] is not None else None,
                    "details": str(r["details"] or ""),
                }
                for r in rows
            ]
            return entries, total

    # --- Users & TOTP ---

    def upsert_user(
        self,
        username: str,
        domain: str = "",
        dn: str = "",
        display_name: str = "",
        email: str = "",
        ldap_active: bool = True,
        in_vpn_group: bool = True,
        totp_secret: str | None = None,
        last_synced_at: str | None = None,
    ) -> dict[str, Any]:
        totp_enc = encrypt_optional(totp_secret, self.master_key) if totp_secret else None
        with self.connection() as conn:
            existing = conn.execute(
                "SELECT username, totp_secret_enc, totp_pending_enc, totp_enabled FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if existing is not None:
                preserved_totp = totp_enc if totp_enc is not None else existing["totp_secret_enc"]
                preserved_enabled = 1 if totp_enc is not None else int(existing["totp_enabled"])
                conn.execute(
                    """
                    UPDATE users
                    SET domain = ?, dn = ?, display_name = ?, email = ?,
                        ldap_active = ?, in_vpn_group = ?,
                        totp_secret_enc = ?, totp_pending_enc = ?, totp_enabled = ?,
                        last_synced_at = ?
                    WHERE username = ?
                    """,
                    (
                        domain,
                        dn,
                        display_name,
                        email,
                        1 if ldap_active else 0,
                        1 if in_vpn_group else 0,
                        preserved_totp,
                        existing["totp_pending_enc"],
                        preserved_enabled,
                        last_synced_at,
                        existing["username"],
                    ),
                )
                target_username = existing["username"]
            else:
                conn.execute(
                    """
                    INSERT INTO users (
                        username, domain, dn, display_name, email,
                        ldap_active, in_vpn_group,
                        totp_secret_enc, totp_pending_enc, totp_enabled,
                        last_synced_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        username,
                        domain,
                        dn,
                        display_name,
                        email,
                        1 if ldap_active else 0,
                        1 if in_vpn_group else 0,
                        totp_enc,
                        1 if totp_enc else 0,
                        last_synced_at,
                    ),
                )
                target_username = username
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (target_username,)
            ).fetchone()
            return self._row_to_user(row)

    def get_user(self, username: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            return self._row_to_user(row) if row is not None else None

    def get_user_totp_secret(self, username: str) -> str | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT totp_secret_enc FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row is None or not row["totp_secret_enc"]:
                return None
            return decrypt_optional(row["totp_secret_enc"], self.master_key)

    def is_user_totp_enrolled(self, username: str) -> bool:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT totp_enabled, totp_secret_enc FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return False
            return bool(row["totp_enabled"]) and bool(row["totp_secret_enc"])

    def set_user_totp_pending(self, username: str, pending_secret: str) -> None:
        enc = encrypt_secret(pending_secret, self.master_key)
        with self.connection() as conn:
            res = conn.execute(
                "UPDATE users SET totp_pending_enc = ? WHERE username = ?",
                (enc, username),
            )
            if res.rowcount == 0:
                raise KeyError(f"User '{username}' not found")

    def get_user_totp_pending(self, username: str) -> str | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT totp_pending_enc FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None or not row["totp_pending_enc"]:
                return None
            return decrypt_optional(row["totp_pending_enc"], self.master_key)

    def confirm_user_totp(self, username: str, confirmed_secret: str, actor: str = "portal") -> None:
        enc = encrypt_secret(confirmed_secret, self.master_key)
        with self.connection() as conn:
            res = conn.execute(
                """
                UPDATE users
                SET totp_secret_enc = ?, totp_pending_enc = NULL, totp_enabled = 1
                WHERE username = ?
                """,
                (enc, username),
            )
            if res.rowcount == 0:
                raise KeyError(f"User '{username}' not found")
            self.log_audit(
                event_type="totp_enrolled",
                actor=actor,
                username=username,
                details=f"User '{username}' activated TOTP 2FA",
                conn=conn,
            )

    def reset_user_totp(self, username: str, actor: str = "admin") -> str | None:
        """Clear enrolled and pending TOTP secrets for `username`; returns canonical username."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT username FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row is None:
                return None
            canonical = str(row["username"])
            conn.execute(
                """
                UPDATE users
                SET totp_secret_enc = NULL, totp_pending_enc = NULL, totp_enabled = 0
                WHERE username = ?
                """,
                (canonical,),
            )
            self.log_audit(
                event_type="totp_reset",
                actor=actor,
                username=canonical,
                details=f"Reset TOTP 2FA secret for '{canonical}'",
                conn=conn,
            )
            return canonical

    def list_users(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM users ORDER BY username COLLATE NOCASE ASC"
            ).fetchall()
            return [self._row_to_user(r) for r in rows]

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> dict[str, Any]:
        ldap_active = bool(row["ldap_active"])
        in_vpn_group = bool(row["in_vpn_group"])
        totp_enrolled = bool(row["totp_enabled"]) and bool(row["totp_secret_enc"])
        return {
            "username": row["username"],
            "domain": row["domain"] or "",
            "dn": row["dn"] or "",
            "display_name": row["display_name"] or row["username"],
            "email": row["email"] or "",
            "ldap_active": ldap_active,
            "in_vpn_group": in_vpn_group,
            "authorized": ldap_active and in_vpn_group,
            "has_totp": totp_enrolled,
            "totp_enrolled": totp_enrolled,
            "last_synced_at": row["last_synced_at"],
        }

    # --- OpenVPN PKI (AES-256-GCM encrypted in SQLite -> Restic-safe) ---

    def ensure_openvpn_pki(self) -> OpenVPNPKIBundle:
        """Load or generate and encrypt the singleton OpenVPN PKI bundle."""
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM openvpn_pki WHERE id = 1").fetchone()
            if row is not None:
                return OpenVPNPKIBundle(
                    ca_cert_pem=row["ca_cert_pem"],
                    ca_key_pem=decrypt_secret(row["ca_key_enc"], self.master_key),
                    server_cert_pem=row["server_cert_pem"],
                    server_key_pem=decrypt_secret(row["server_key_enc"], self.master_key),
                    client_cert_pem=row["client_cert_pem"],
                    client_key_pem=decrypt_secret(row["client_key_enc"], self.master_key),
                    tls_crypt_key=decrypt_secret(row["tls_crypt_key_enc"], self.master_key),
                )

            bundle = generate_openvpn_pki(module_id=self.settings.module_id)
            conn.execute(
                """
                INSERT INTO openvpn_pki (
                    id, ca_cert_pem, ca_key_enc, server_cert_pem, server_key_enc,
                    client_cert_pem, client_key_enc, tls_crypt_key_enc, created_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bundle.ca_cert_pem,
                    encrypt_secret(bundle.ca_key_pem, self.master_key),
                    bundle.server_cert_pem,
                    encrypt_secret(bundle.server_key_pem, self.master_key),
                    bundle.client_cert_pem,
                    encrypt_secret(bundle.client_key_pem, self.master_key),
                    encrypt_secret(bundle.tls_crypt_key, self.master_key),
                    utc_now_iso(),
                ),
            )
            return bundle

    # --- Roadwarrior Peers ---

    def create_peer_record(
        self,
        username: str,
        device_name: str,
        assigned_ip: str,
        public_key: str,
        private_key: str,
        preshared_key: str | None = None,
        protocol: str = "wireguard",
        admin_enabled: bool = True,
        actor: str = "admin",
    ) -> dict[str, Any]:
        peer_id = str(uuid.uuid4())
        priv_enc = encrypt_secret(private_key, self.master_key)
        psk_enc = encrypt_optional(preshared_key, self.master_key)
        now = utc_now_iso()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO peers (
                    id, username, protocol, device_name, assigned_ip,
                    public_key, private_key_enc, preshared_key_enc,
                    admin_enabled, rx_bytes_offset, tx_bytes_offset,
                    last_rx_kernel, last_tx_kernel, last_handshake_at,
                    last_endpoint, created_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, NULL, NULL, ?, NULL)
                """,
                (
                    peer_id,
                    username,
                    protocol,
                    device_name,
                    assigned_ip,
                    public_key,
                    priv_enc,
                    psk_enc,
                    1 if admin_enabled else 0,
                    now,
                ),
            )
            self.log_audit(
                event_type="peer_created",
                actor=actor,
                username=username,
                peer_id=peer_id,
                details=f"Created {protocol} peer '{device_name}' ({assigned_ip})",
                conn=conn,
            )
        peer = self.get_peer(peer_id)
        if peer is None:
            raise RuntimeError("Failed to retrieve created peer")
        return peer

    def get_peer(self, peer_id: str, include_revoked: bool = False) -> dict[str, Any] | None:
        with self.connection() as conn:
            sql = """
                SELECT p.*, u.display_name AS user_display_name,
                       u.ldap_active AS user_ldap_active,
                       u.in_vpn_group AS user_in_vpn_group,
                       c.user_domain AS cfg_user_domain
                FROM peers p
                LEFT JOIN users u ON u.username = p.username
                CROSS JOIN server_config c ON c.id = 1
                WHERE p.id = ?
            """
            if not include_revoked:
                sql += " AND p.revoked_at IS NULL"
            row = conn.execute(sql, (peer_id,)).fetchone()
            return self._row_to_peer(row) if row is not None else None

    def get_peer_secrets(self, peer_id: str) -> tuple[str, str | None]:
        """Decrypt and return `(private_key, preshared_key)` for a non-revoked peer."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT private_key_enc, preshared_key_enc FROM peers WHERE id = ? AND revoked_at IS NULL",
                (peer_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"Active peer {peer_id} not found")
            priv = decrypt_secret(row["private_key_enc"], self.master_key)
            psk = decrypt_optional(row["preshared_key_enc"], self.master_key)
            return priv, psk

    def list_peers(self, include_revoked: bool = False) -> list[dict[str, Any]]:
        with self.connection() as conn:
            sql = """
                SELECT p.*, u.display_name AS user_display_name,
                       u.ldap_active AS user_ldap_active,
                       u.in_vpn_group AS user_in_vpn_group,
                       c.user_domain AS cfg_user_domain
                FROM peers p
                LEFT JOIN users u ON u.username = p.username
                CROSS JOIN server_config c ON c.id = 1
            """
            if not include_revoked:
                sql += " WHERE p.revoked_at IS NULL"
            sql += " ORDER BY p.created_at ASC, p.id ASC"
            rows = conn.execute(sql).fetchall()
            return [self._row_to_peer(r) for r in rows]

    def list_active_wireguard_peers_with_psk(self) -> list[dict[str, Any]]:
        """Return all active WireGuard roadwarrior peers AND enabled S2S tunnels for `wg setconf`."""
        peers = self.list_peers(include_revoked=False)
        active: list[dict[str, Any]] = []
        with self.connection() as conn:
            for peer in peers:
                if peer["protocol"] != "wireguard" or not peer["effective_active"]:
                    continue
                row = conn.execute(
                    "SELECT preshared_key_enc FROM peers WHERE id = ?", (peer["id"],)
                ).fetchone()
                psk = (
                    decrypt_optional(row["preshared_key_enc"], self.master_key)
                    if row is not None
                    else None
                )
                active.append(
                    {
                        "public_key": peer["public_key"],
                        "preshared_key": psk,
                        "assigned_ip": peer["assigned_ip"],
                        "allowed_ips": [f"{peer['assigned_ip']}/32"],
                    }
                )

            s2s_rows = conn.execute(
                "SELECT * FROM site_to_site_tunnels WHERE enabled = 1 ORDER BY created_at ASC"
            ).fetchall()
            for s_row in s2s_rows:
                psk = decrypt_optional(s_row["preshared_key_enc"], self.master_key)
                remote_cidrs = json.loads(s_row["remote_cidrs_json"] or "[]")
                allowed_ips = [f"{s_row['assigned_ip']}/32", *remote_cidrs]
                active.append(
                    {
                        "public_key": s_row["public_key"],
                        "preshared_key": psk,
                        "assigned_ip": s_row["assigned_ip"],
                        "allowed_ips": allowed_ips,
                        "endpoint": s_row["remote_endpoint"] or None,
                    }
                )
        return active

    def get_used_ips(self) -> set[str]:
        with self.connection() as conn:
            peer_rows = conn.execute(
                "SELECT assigned_ip FROM peers WHERE revoked_at IS NULL"
            ).fetchall()
            s2s_rows = conn.execute(
                "SELECT assigned_ip FROM site_to_site_tunnels"
            ).fetchall()
            return {r["assigned_ip"] for r in peer_rows} | {r["assigned_ip"] for r in s2s_rows}

    def update_peer_ip(self, peer_id: str, new_ip: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE peers SET assigned_ip = ? WHERE id = ? AND revoked_at IS NULL",
                (new_ip, peer_id),
            )

    def set_peer_admin_enabled(
        self, peer_id: str, enabled: bool, actor: str = "admin"
    ) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT id, username, device_name, last_rx_kernel, last_tx_kernel FROM peers WHERE id = ? AND revoked_at IS NULL",
                (peer_id,),
            ).fetchone()
            if row is None:
                return None
            if not enabled:
                conn.execute(
                    """
                    UPDATE peers
                    SET admin_enabled = 0,
                        rx_bytes_offset = rx_bytes_offset + last_rx_kernel,
                        tx_bytes_offset = tx_bytes_offset + last_tx_kernel,
                        last_rx_kernel = 0,
                        last_tx_kernel = 0
                    WHERE id = ?
                    """,
                    (peer_id,),
                )
            else:
                conn.execute(
                    "UPDATE peers SET admin_enabled = 1 WHERE id = ?",
                    (peer_id,),
                )
            state_label = "enabled" if enabled else "disabled"
            self.log_audit(
                event_type="peer_toggled",
                actor=actor,
                username=row["username"],
                peer_id=peer_id,
                details=f"Peer '{row['device_name']}' manually {state_label}",
                conn=conn,
            )
        return self.get_peer(peer_id)

    def revoke_peer(self, peer_id: str, actor: str = "admin") -> dict[str, Any] | None:
        now = utc_now_iso()
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM peers WHERE id = ? AND revoked_at IS NULL", (peer_id,)
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                """
                UPDATE peers
                SET admin_enabled = 0,
                    revoked_at = ?,
                    rx_bytes_offset = rx_bytes_offset + last_rx_kernel,
                    tx_bytes_offset = tx_bytes_offset + last_tx_kernel,
                    last_rx_kernel = 0,
                    last_tx_kernel = 0
                WHERE id = ?
                """,
                (now, peer_id),
            )
            self.log_audit(
                event_type="peer_revoked",
                actor=actor,
                username=row["username"],
                peer_id=peer_id,
                details=f"Revoked peer '{row['device_name']}' ({row['assigned_ip']})",
                conn=conn,
            )
            return dict(row)

    def fold_peer_kernel_counters(self, peer_id: str) -> None:
        """Fold live kernel RX/TX counters into offsets before/after removing peer from kernel."""
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE peers
                SET rx_bytes_offset = rx_bytes_offset + last_rx_kernel,
                    tx_bytes_offset = tx_bytes_offset + last_tx_kernel,
                    last_rx_kernel = 0,
                    last_tx_kernel = 0
                WHERE id = ?
                """,
                (peer_id,),
            )

    def update_peers_telemetry(self, dump_by_pubkey: dict[str, dict[str, Any]]) -> None:
        """Merge `wg show <iface> dump` counters into SQLite for both peers and S2S tunnels."""
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, public_key, rx_bytes_offset, tx_bytes_offset,
                       last_rx_kernel, last_tx_kernel, last_handshake_at, last_endpoint
                FROM peers
                WHERE revoked_at IS NULL AND protocol = 'wireguard'
                """
            ).fetchall()
            for row in rows:
                pubkey = row["public_key"]
                rx_offset = int(row["rx_bytes_offset"])
                tx_offset = int(row["tx_bytes_offset"])
                prev_rx = int(row["last_rx_kernel"])
                prev_tx = int(row["last_tx_kernel"])

                live = dump_by_pubkey.get(pubkey)
                if live is None:
                    if prev_rx > 0 or prev_tx > 0:
                        conn.execute(
                            """
                            UPDATE peers
                            SET rx_bytes_offset = ?, tx_bytes_offset = ?,
                                last_rx_kernel = 0, last_tx_kernel = 0
                            WHERE id = ?
                            """,
                            (rx_offset + prev_rx, tx_offset + prev_tx, row["id"]),
                        )
                    continue

                kernel_rx = int(live["rx_bytes"])
                kernel_tx = int(live["tx_bytes"])
                if kernel_rx < prev_rx:
                    rx_offset += prev_rx
                if kernel_tx < prev_tx:
                    tx_offset += prev_tx

                handshake_iso = live.get("handshake_iso") or row["last_handshake_at"]
                endpoint = live.get("endpoint") or row["last_endpoint"]

                conn.execute(
                    """
                    UPDATE peers
                    SET rx_bytes_offset = ?,
                        tx_bytes_offset = ?,
                        last_rx_kernel = ?,
                        last_tx_kernel = ?,
                        last_handshake_at = ?,
                        last_endpoint = ?
                    WHERE id = ?
                    """,
                    (
                        rx_offset,
                        tx_offset,
                        kernel_rx,
                        kernel_tx,
                        handshake_iso,
                        endpoint,
                        row["id"],
                    ),
                )

            s2s_rows = conn.execute(
                """
                SELECT id, public_key, rx_bytes_offset, tx_bytes_offset,
                       last_rx_kernel, last_tx_kernel, last_handshake_at
                FROM site_to_site_tunnels
                """
            ).fetchall()
            for srow in s2s_rows:
                pubkey = srow["public_key"]
                rx_offset = int(srow["rx_bytes_offset"])
                tx_offset = int(srow["tx_bytes_offset"])
                prev_rx = int(srow["last_rx_kernel"])
                prev_tx = int(srow["last_tx_kernel"])

                live = dump_by_pubkey.get(pubkey)
                if live is None:
                    if prev_rx > 0 or prev_tx > 0:
                        conn.execute(
                            """
                            UPDATE site_to_site_tunnels
                            SET rx_bytes_offset = ?, tx_bytes_offset = ?,
                                last_rx_kernel = 0, last_tx_kernel = 0
                            WHERE id = ?
                            """,
                            (rx_offset + prev_rx, tx_offset + prev_tx, srow["id"]),
                        )
                    continue

                kernel_rx = int(live["rx_bytes"])
                kernel_tx = int(live["tx_bytes"])
                if kernel_rx < prev_rx:
                    rx_offset += prev_rx
                if kernel_tx < prev_tx:
                    tx_offset += prev_tx
                handshake_iso = live.get("handshake_iso") or srow["last_handshake_at"]
                conn.execute(
                    """
                    UPDATE site_to_site_tunnels
                    SET rx_bytes_offset = ?, tx_bytes_offset = ?,
                        last_rx_kernel = ?, last_tx_kernel = ?,
                        last_handshake_at = ?
                    WHERE id = ?
                    """,
                    (rx_offset, tx_offset, kernel_rx, kernel_tx, handshake_iso, srow["id"]),
                )

    @staticmethod
    def _row_to_peer(row: sqlite3.Row) -> dict[str, Any]:
        admin_enabled = bool(row["admin_enabled"])
        revoked_at = row["revoked_at"]
        if row["user_ldap_active"] is None:
            user_authorized = not bool(row["cfg_user_domain"])
        else:
            user_authorized = bool(row["user_ldap_active"]) and bool(row["user_in_vpn_group"])
        effective_active = admin_enabled and user_authorized and (revoked_at is None)
        rx_total = int(row["rx_bytes_offset"]) + int(row["last_rx_kernel"])
        tx_total = int(row["tx_bytes_offset"]) + int(row["last_tx_kernel"])
        return {
            "id": row["id"],
            "username": row["username"],
            "display_name": row["user_display_name"] or row["username"],
            "protocol": row["protocol"],
            "device_name": row["device_name"],
            "assigned_ip": row["assigned_ip"],
            "public_key": row["public_key"],
            "admin_enabled": admin_enabled,
            "user_authorized": user_authorized,
            "effective_active": effective_active,
            "online": False,
            "rx_bytes": rx_total,
            "tx_bytes": tx_total,
            "last_handshake_at": row["last_handshake_at"],
            "last_endpoint": row["last_endpoint"],
            "created_at": row["created_at"],
            "revoked_at": revoked_at,
        }

    # --- Site-to-Site Tunnels ---

    def create_s2s_tunnel(
        self,
        *,
        name: str,
        assigned_ip: str,
        public_key: str,
        private_key: str | None,
        preshared_key: str,
        remote_endpoint: str,
        remote_cidrs: list[str],
        enabled: bool = True,
    ) -> dict[str, Any]:
        tunnel_id = str(uuid.uuid4())
        priv_enc = encrypt_optional(private_key, self.master_key)
        psk_enc = encrypt_secret(preshared_key, self.master_key)
        now = utc_now_iso()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO site_to_site_tunnels (
                    id, name, enabled, assigned_ip, public_key,
                    private_key_enc, preshared_key_enc,
                    remote_endpoint, remote_cidrs_json,
                    rx_bytes_offset, tx_bytes_offset, last_rx_kernel, last_tx_kernel,
                    last_handshake_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, NULL, ?)
                """,
                (
                    tunnel_id,
                    name,
                    1 if enabled else 0,
                    assigned_ip,
                    public_key,
                    priv_enc,
                    psk_enc,
                    remote_endpoint,
                    json.dumps(remote_cidrs),
                    now,
                ),
            )
            self.log_audit(
                event_type="s2s_created",
                actor="admin",
                peer_id=tunnel_id,
                details=f"Created Site-to-Site tunnel '{name}' ({assigned_ip} -> {', '.join(remote_cidrs)})",
                conn=conn,
            )
        tunnel = self.get_s2s_tunnel(tunnel_id)
        if tunnel is None:
            raise RuntimeError("Failed to retrieve created S2S tunnel")
        return tunnel

    def get_s2s_tunnel(self, tunnel_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM site_to_site_tunnels WHERE id = ?", (tunnel_id,)
            ).fetchone()
            return self._row_to_s2s(row) if row is not None else None

    def get_s2s_secrets(self, tunnel_id: str) -> tuple[str | None, str | None]:
        """Return `(private_key_or_none, preshared_key)` for a Site-to-Site tunnel."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT private_key_enc, preshared_key_enc FROM site_to_site_tunnels WHERE id = ?",
                (tunnel_id,),
            ).fetchone()
            if row is None:
                raise KeyError(tunnel_id)
            priv = decrypt_optional(row["private_key_enc"], self.master_key)
            psk = decrypt_optional(row["preshared_key_enc"], self.master_key)
            return priv, psk

    def list_s2s_tunnels(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM site_to_site_tunnels ORDER BY created_at ASC, id ASC"
            ).fetchall()
            return [self._row_to_s2s(r) for r in rows]

    def update_s2s_ip(self, tunnel_id: str, new_ip: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE site_to_site_tunnels SET assigned_ip = ? WHERE id = ?",
                (new_ip, tunnel_id),
            )

    def set_s2s_enabled(self, tunnel_id: str, enabled: bool) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT id, name FROM site_to_site_tunnels WHERE id = ?", (tunnel_id,)
            ).fetchone()
            if row is None:
                return None
            if not enabled:
                conn.execute(
                    """
                    UPDATE site_to_site_tunnels
                    SET enabled = 0,
                        rx_bytes_offset = rx_bytes_offset + last_rx_kernel,
                        tx_bytes_offset = tx_bytes_offset + last_tx_kernel,
                        last_rx_kernel = 0,
                        last_tx_kernel = 0
                    WHERE id = ?
                    """,
                    (tunnel_id,),
                )
            else:
                conn.execute(
                    "UPDATE site_to_site_tunnels SET enabled = 1 WHERE id = ?",
                    (tunnel_id,),
                )
            self.log_audit(
                event_type="s2s_toggled",
                actor="admin",
                peer_id=tunnel_id,
                details=f"Site-to-Site tunnel '{row['name']}' {'enabled' if enabled else 'disabled'}",
                conn=conn,
            )
        return self.get_s2s_tunnel(tunnel_id)

    def delete_s2s_tunnel(self, tunnel_id: str) -> dict[str, Any] | None:
        existing = self.get_s2s_tunnel(tunnel_id)
        if existing is None:
            return None
        with self.connection() as conn:
            conn.execute("DELETE FROM site_to_site_tunnels WHERE id = ?", (tunnel_id,))
            self.log_audit(
                event_type="s2s_deleted",
                actor="admin",
                peer_id=tunnel_id,
                details=f"Deleted Site-to-Site tunnel '{existing['name']}'",
                conn=conn,
            )
        return existing

    @staticmethod
    def _row_to_s2s(row: sqlite3.Row) -> dict[str, Any]:
        rx_total = int(row["rx_bytes_offset"]) + int(row["last_rx_kernel"])
        tx_total = int(row["tx_bytes_offset"]) + int(row["last_tx_kernel"])
        return {
            "id": row["id"],
            "name": row["name"],
            "enabled": bool(row["enabled"]),
            "assigned_ip": row["assigned_ip"],
            "public_key": row["public_key"],
            "has_private_key": bool(row["private_key_enc"]),
            "remote_endpoint": row["remote_endpoint"] or "",
            "remote_cidrs": json.loads(row["remote_cidrs_json"] or "[]"),
            "online": False,
            "rx_bytes": rx_total,
            "tx_bytes": tx_total,
            "last_handshake_at": row["last_handshake_at"],
            "created_at": row["created_at"],
        }
