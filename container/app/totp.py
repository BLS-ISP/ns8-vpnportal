"""RFC 6238 TOTP two-factor authentication helpers (`pyotp` + SVG QR Data-URI)."""

from __future__ import annotations

import re
from datetime import datetime

import pyotp

from .wireguard import render_qr_svg_data_uri


TOTP_CODE_RE = re.compile(r"^\d{6}$")


def generate_totp_secret() -> str:
    """Generate a 160-bit RFC 4648 Base32 secret for Authenticator apps."""
    return pyotp.random_base32(length=32)


def build_totp_provisioning_bundle(
    *,
    secret: str,
    username: str,
    portal_domain: str = "",
    endpoint_host: str = "",
) -> dict[str, str]:
    """Return `(secret, issuer, otpauth_uri, qr_svg_data_uri)` for Authenticator enrollment."""
    label_host = (portal_domain or endpoint_host or "Portal").strip()
    issuer = f"NS8 VPN ({label_host})"
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    qr_uri = render_qr_svg_data_uri(uri)
    return {
        "secret": secret,
        "issuer": issuer,
        "otpauth_uri": uri,
        "qr_svg_data_uri": qr_uri,
    }


def normalize_totp_code(raw_code: str | None) -> str:
    """Strip spaces/dashes and return normalized code string."""
    if not raw_code:
        return ""
    return re.sub(r"[\s\-]", "", str(raw_code))


def verify_totp_code(
    secret: str,
    code: str | None,
    *,
    valid_window: int = 1,
    for_time: datetime | int | None = None,
) -> bool:
    """Verify a 6-digit RFC 6238 TOTP code with +/-1 30s clock-skew tolerance."""
    if not secret:
        return False
    clean_code = normalize_totp_code(code)
    if not TOTP_CODE_RE.match(clean_code):
        return False
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(clean_code, for_time=for_time, valid_window=valid_window))


def split_password_and_totp(combined_password: str) -> tuple[str, str] | None:
    """Split `<ad_password><6_digit_totp>` for OpenVPN password+2FA login.

    Returns `(ad_password, totp_code)` when valid, or `None` if input is too short
    or does not end with a 6-digit numeric TOTP code.
    """
    if not combined_password or len(combined_password) <= 6:
        return None
    ad_pw = combined_password[:-6]
    totp_suffix = combined_password[-6:]
    if not ad_pw or not TOTP_CODE_RE.match(totp_suffix):
        return None
    return ad_pw, totp_suffix
