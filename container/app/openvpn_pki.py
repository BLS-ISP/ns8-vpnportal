"""X.509 PKI and 2048-bit `tls-crypt` static key generator for OpenVPN (`cryptography.x509`)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass
class OpenVPNPKIBundle:
    ca_cert_pem: str
    ca_key_pem: str
    server_cert_pem: str
    server_key_pem: str
    client_cert_pem: str
    client_key_pem: str
    tls_crypt_key: str


def generate_openvpn_static_key_v1() -> str:
    """Generate a 2048-bit (256-byte) OpenVPN Static key V1 for `tls-crypt`."""
    raw_hex = os.urandom(256).hex()
    chunks = [raw_hex[i : i + 32] for i in range(0, len(raw_hex), 32)]
    lines = [
        "#",
        "# 2048 bit OpenVPN static key",
        "#",
        "-----BEGIN OpenVPN Static key V1-----",
        *chunks,
        "-----END OpenVPN Static key V1-----",
    ]
    return "\n".join(lines) + "\n"


def _serialize_private_key(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _serialize_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def generate_openvpn_pki(module_id: str = "vpn1") -> OpenVPNPKIBundle:
    """Generate Root CA, Server (`serverAuth`), Client (`clientAuth`), and `tls-crypt` key."""
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=1)
    not_after = now + timedelta(days=3650)

    # 1. Root CA (ECDSA P-256 / prime256v1)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NethServer 8 VPN"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"ns8-vpn-{module_id}-ca"),
        ]
    )
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 2. Server Certificate (`ExtendedKeyUsageOID.SERVER_AUTH` required for `remote-cert-tls server`)
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NethServer 8 VPN"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"ns8-vpn-{module_id}-server"),
        ]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 3. Shared Client Certificate (`ExtendedKeyUsageOID.CLIENT_AUTH` + per-user AD/TOTP auth)
    client_key = ec.generate_private_key(ec.SECP256R1())
    client_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NethServer 8 VPN"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"ns8-vpn-{module_id}-roadwarrior"),
        ]
    )
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(ca_subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    return OpenVPNPKIBundle(
        ca_cert_pem=_serialize_cert(ca_cert),
        ca_key_pem=_serialize_private_key(ca_key),
        server_cert_pem=_serialize_cert(server_cert),
        server_key_pem=_serialize_private_key(server_key),
        client_cert_pem=_serialize_cert(client_cert),
        client_key_pem=_serialize_private_key(client_key),
        tls_crypt_key=generate_openvpn_static_key_v1(),
    )
