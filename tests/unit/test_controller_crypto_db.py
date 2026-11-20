"""Unit tests for AES-256-GCM encryption, WireGuard key generation, config naming, and SQLite WAL persistence."""

from __future__ import annotations

import base64
import os
import sqlite3
from pathlib import Path

import pytest

from container.app.config import Settings, derive_interface_name, derive_nft_table_name
from container.app.crypto import (
    CryptoError,
    decrypt_optional,
    decrypt_secret,
    derive_wg_public_key,
    encrypt_optional,
    encrypt_secret,
    ensure_master_key,
    generate_wg_keypair,
    generate_wg_psk,
    is_valid_wg_key,
)
from container.app.db import Database


def test_master_key_auto_generation_and_reload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_path = tmp_path / "secrets" / "master.key"
    # Include 0x0a (\n), 0x0d (\r), and 0x1a (EOF on Windows text mode) to verify binary-safe O_BINARY write
    tricky_key = b"\x00\x0a\x0d\x1a" + (b"\xab" * 28)
    monkeypatch.setattr("container.app.crypto.os.urandom", lambda n: tricky_key[:n])

    key1 = ensure_master_key(key_path)
    assert len(key1) == 32
    assert key1 == tricky_key
    assert key_path.exists()
    assert key_path.read_bytes() == tricky_key

    key2 = ensure_master_key(key_path)
    assert key2 == tricky_key


def test_master_key_rejects_corrupt_length(tmp_path: Path) -> None:
    key_path = tmp_path / "secrets" / "master.key"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(b"too-short")
    with pytest.raises(CryptoError):
        ensure_master_key(key_path)


def test_aes_256_gcm_roundtrip_and_tamper_detection() -> None:
    key = os.urandom(32)
    secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY="

    token1 = encrypt_secret(secret, key)
    token2 = encrypt_secret(secret, key)
    assert token1.startswith("v1:")
    assert token1 != token2  # fresh 96-bit random nonce per encryption
    assert secret not in token1
    assert decrypt_secret(token1, key) == secret
    assert decrypt_secret(token2, key) == secret

    # Wrong master key fails authentication
    wrong_key = os.urandom(32)
    with pytest.raises(CryptoError):
        decrypt_secret(token1, wrong_key)

    # Bit flip in ciphertext fails GCM authentication tag
    raw = bytearray(base64.b64decode(token1[3:]))
    raw[-1] ^= 0xFF
    tampered = "v1:" + base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(CryptoError):
        decrypt_secret(tampered, key)

    assert encrypt_optional(None, key) is None
    assert encrypt_optional("", key) is None
    assert decrypt_optional(None, key) is None
    opt_tok = encrypt_optional("JBSWY3DPEHPK3PXP", key)
    assert opt_tok is not None
    assert decrypt_optional(opt_tok, key) == "JBSWY3DPEHPK3PXP"


def test_wireguard_keypair_generation_and_clamping() -> None:
    priv, pub = generate_wg_keypair()
    psk = generate_wg_psk()

    assert is_valid_wg_key(priv)
    assert is_valid_wg_key(pub)
    assert is_valid_wg_key(psk)
    assert priv != pub
    assert derive_wg_public_key(priv) == pub

    raw_priv = base64.b64decode(priv)
    assert (raw_priv[0] & 7) == 0
    assert (raw_priv[31] & 128) == 0
    assert (raw_priv[31] & 64) == 64

    assert not is_valid_wg_key("not-a-valid-key")


def test_interface_and_nft_table_naming_safety() -> None:
    assert derive_interface_name("vpn1") == "wg-vpn1"
    long_iface = derive_interface_name("vpn-enterprise-branch-42")
    assert len(long_iface) <= 15
    assert long_iface.endswith("42")
    assert long_iface != "wg0"

    with pytest.raises(ValueError, match="wg0"):
        derive_interface_name("wg0")
    with pytest.raises(ValueError, match="wg0"):
        derive_interface_name("0")

    assert derive_nft_table_name("vpn1") == "ns8_vpn_vpn1"
    assert derive_nft_table_name("vpn-prod&1") == "ns8_vpn_vpn_prod_1"


def test_sqlite_wal_at_rest_encryption_and_counter_folding(controller_settings: Settings) -> None:
    db = Database(controller_settings)
    db.initialize()

    # Verify WAL journal mode and encrypted secrets at rest in raw SQLite
    raw_conn = sqlite3.connect(str(controller_settings.db_path))
    try:
        mode = raw_conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert mode.lower() == "wal"
        srv_row = raw_conn.execute(
            "SELECT server_private_key_enc, server_public_key FROM server_config WHERE id = 1"
        ).fetchone()
        assert srv_row[0].startswith("v1:")
    finally:
        raw_conn.close()

    decrypted_srv_priv = db.get_server_private_key()
    assert derive_wg_public_key(decrypted_srv_priv) == db.get_server_config()["server_public_key"]

    # Upsert user with future Phase-2 totp_secret encrypted at rest
    db.upsert_user(
        username="Alice",
        domain="corp.example.com",
        display_name="Alice Admin",
        email="alice@corp.example.com",
        ldap_active=True,
        in_vpn_group=True,
        totp_secret="BASE32SECRET3232",
    )
    assert db.get_user("alice") is not None  # case-insensitive NOCASE lookup
    assert db.get_user_totp_secret("ALICE") == "BASE32SECRET3232"

    client_priv, client_pub = generate_wg_keypair()
    client_psk = generate_wg_psk()
    peer = db.create_peer_record(
        username="Alice",
        device_name="ThinkPad",
        assigned_ip="10.199.0.2",
        public_key=client_pub,
        private_key=client_priv,
        preshared_key=client_psk,
    )

    # Confirm raw SQLite table never stores plaintext keys or TOTP secrets
    raw_conn = sqlite3.connect(str(controller_settings.db_path))
    try:
        peer_raw = raw_conn.execute(
            "SELECT private_key_enc, preshared_key_enc FROM peers WHERE id = ?",
            (peer["id"],),
        ).fetchone()
        user_raw = raw_conn.execute(
            "SELECT totp_secret_enc FROM users WHERE username = 'Alice'"
        ).fetchone()
        assert client_priv not in peer_raw[0]
        assert client_psk not in peer_raw[1]
        assert "BASE32SECRET3232" not in user_raw[0]
    finally:
        raw_conn.close()

    # Verify cumulative RX/TX byte counters survive kernel resets & restarts
    db.update_peers_telemetry(
        {
            client_pub: {
                "rx_bytes": 10_000,
                "tx_bytes": 25_000,
                "handshake_iso": "2026-11-20T12:00:00Z",
                "endpoint": "203.0.113.50:54321",
            }
        }
    )
    p1 = db.get_peer(peer["id"])
    assert p1 is not None
    assert p1["rx_bytes"] == 10_000
    assert p1["tx_bytes"] == 25_000

    # Simulate kernel restart where counter resets to a smaller number (3,000 / 4,000)
    db.update_peers_telemetry(
        {
            client_pub: {
                "rx_bytes": 3_000,
                "tx_bytes": 4_000,
                "handshake_iso": "2026-11-20T12:05:00Z",
                "endpoint": "203.0.113.50:54321",
            }
        }
    )
    p2 = db.get_peer(peer["id"])
    assert p2 is not None
    assert p2["rx_bytes"] == 13_000
    assert p2["tx_bytes"] == 29_000

    # Revoking frees 10.199.0.2 via partial unique index so a new peer can claim 10.199.0.2
    db.revoke_peer(peer["id"])
    assert "10.199.0.2" not in db.get_used_ips()

    priv2, pub2 = generate_wg_keypair()
    peer2 = db.create_peer_record(
        username="Alice",
        device_name="Replacement-Laptop",
        assigned_ip="10.199.0.2",
        public_key=pub2,
        private_key=priv2,
    )
    assert peer2["assigned_ip"] == "10.199.0.2"
