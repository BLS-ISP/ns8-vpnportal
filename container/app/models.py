"""Pydantic API schemas shared between vpn-controller, NS8 module actions, Cockpit UI, and Self-Service Portal."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    module_id: str
    interface: str
    interface_up: bool


class ConfigSummary(BaseModel):
    authorized_users: int = 0
    total_peers: int = 0
    active_peers: int = 0
    online_peers: int = 0
    online_ovpn_clients: int = 0
    s2s_tunnels: int = 0
    active_s2s_tunnels: int = 0
    last_synced_at: str | None = None
    last_sync_status: str = "never"
    last_sync_error: str | None = None


class ServerConfigResponse(BaseModel):
    configured: bool
    endpoint_host: str
    wg_port: int
    wg_network: str
    tunnel_mode: Literal["split", "full"]
    allowed_cidrs: list[str]
    dns_servers: list[str]
    dns_search_domain: str
    wg_mtu: int
    persistent_keepalive: int
    nat_enabled: bool
    user_domain: str
    vpn_group: str
    max_devices_per_user: int
    sync_interval_minutes: int
    portal_enabled: bool
    portal_domain: str
    portal_lets_encrypt: bool
    portal_http2https: bool
    portal_totp_mode: Literal["disabled", "optional", "required"] = "optional"
    ovpn_enabled: bool = False
    ovpn_proto: Literal["tcp", "udp"] = "tcp"
    ovpn_port: int = 1194
    ovpn_public_port: int = 1194
    ovpn_network: str = "10.199.1.0/24"
    ovpn_totp_required: bool = False
    ovpn_interface_name: str = "tun-vpn1"
    server_public_key: str
    interface_name: str
    summary: ConfigSummary


class ServerConfigUpdateRequest(BaseModel):
    configured: bool | None = None
    endpoint_host: str | None = None
    wg_port: int | None = None
    wg_network: str | None = None
    tunnel_mode: Literal["split", "full"] | None = None
    allowed_cidrs: list[str] | None = None
    dns_servers: list[str] | None = None
    dns_search_domain: str | None = None
    wg_mtu: int | None = None
    persistent_keepalive: int | None = None
    nat_enabled: bool | None = None
    user_domain: str | None = None
    vpn_group: str | None = None
    max_devices_per_user: int | None = None
    sync_interval_minutes: int | None = None
    portal_enabled: bool | None = None
    portal_domain: str | None = None
    portal_lets_encrypt: bool | None = None
    portal_http2https: bool | None = None
    portal_totp_mode: Literal["disabled", "optional", "required"] | None = None
    ovpn_enabled: bool | None = None
    ovpn_proto: Literal["tcp", "udp"] | None = None
    ovpn_port: int | None = None
    ovpn_public_port: int | None = None
    ovpn_network: str | None = None
    ovpn_totp_required: bool | None = None


class ReconcileResponse(BaseModel):
    status: Literal["ok"] = "ok"
    config: ServerConfigResponse


class SyncResponse(BaseModel):
    status: Literal["ok", "skipped", "ldap_error"]
    synced_at: str | None = None
    total_users: int = 0
    authorized_users: int = 0
    active_peers: int = 0
    suspended_peers: int = 0
    message: str


class UserItem(BaseModel):
    username: str
    domain: str
    display_name: str
    email: str
    ldap_active: bool
    in_vpn_group: bool
    authorized: bool
    totp_enrolled: bool = False
    peer_count: int
    last_synced_at: str | None = None


class PeerItem(BaseModel):
    id: str
    username: str
    display_name: str
    protocol: str = "wireguard"
    device_name: str
    assigned_ip: str
    public_key: str
    admin_enabled: bool
    user_authorized: bool
    effective_active: bool
    online: bool
    rx_bytes: int
    tx_bytes: int
    last_handshake_at: str | None = None
    last_endpoint: str | None = None
    created_at: str


class PeersSummary(BaseModel):
    authorized_users: int = 0
    total_peers: int = 0
    active_peers: int = 0
    online_peers: int = 0
    max_devices_per_user: int = 3


class PeersListResponse(BaseModel):
    users: list[UserItem] = Field(default_factory=list)
    peers: list[PeerItem] = Field(default_factory=list)
    summary: PeersSummary


class CreatePeerRequest(BaseModel):
    username: str
    device_name: str
    enforce_limit: bool = False
    allow_unlisted: bool = False
    assigned_ip: str | None = None


class CreatePeerResponse(BaseModel):
    peer: PeerItem
    config_text: str
    qr_svg_data_uri: str


class PeerConfigResponse(BaseModel):
    peer_id: str
    username: str
    device_name: str
    config_text: str
    qr_svg_data_uri: str


class TogglePeerRequest(BaseModel):
    enabled: bool | None = None


class TogglePeerResponse(BaseModel):
    peer: PeerItem


class RevokePeerResponse(BaseModel):
    revoked: bool = True
    peer_id: str


# --- Phase 2 & 3 Admin User / OpenVPN / Site-to-Site Models ---


class ResetUserTotpResponse(BaseModel):
    reset: bool = True
    username: str


class UserOvpnResponse(BaseModel):
    username: str
    filename: str
    ovpn_text: str
    totp_required_on_connect: bool


class OpenVPNAuthRequest(BaseModel):
    username: str
    password: str


class OpenVPNAuthResponse(BaseModel):
    allowed: bool
    username: str = ""
    reason: str | None = None


class S2STunnelItem(BaseModel):
    id: str
    name: str
    enabled: bool
    assigned_ip: str
    public_key: str
    has_private_key: bool = True
    remote_endpoint: str = ""
    remote_cidrs: list[str] = Field(default_factory=list)
    online: bool = False
    rx_bytes: int = 0
    tx_bytes: int = 0
    last_handshake_at: str | None = None
    created_at: str


class S2SListResponse(BaseModel):
    tunnels: list[S2STunnelItem] = Field(default_factory=list)


class CreateS2SRequest(BaseModel):
    name: str
    remote_cidrs: list[str]
    remote_endpoint: str = ""
    remote_public_key: str = ""


class CreateS2SResponse(BaseModel):
    tunnel: S2STunnelItem
    config_text: str


class S2SConfigResponse(BaseModel):
    tunnel_id: str
    name: str
    config_text: str
    has_private_key: bool


class ToggleS2SRequest(BaseModel):
    enabled: bool | None = None


class ToggleS2SResponse(BaseModel):
    tunnel: S2STunnelItem


class DeleteS2SResponse(BaseModel):
    deleted: bool = True
    tunnel_id: str


class AuditLogItem(BaseModel):
    id: int
    timestamp: str
    event_type: str
    actor: str
    username: str | None = None
    peer_id: str | None = None
    details: str


class AuditLogListResponse(BaseModel):
    entries: list[AuditLogItem] = Field(default_factory=list)
    total: int = 0


# --- Phase 2 Self-Service Portal Models ---


class PortalInfoResponse(BaseModel):
    portal_enabled: bool
    portal_domain: str
    totp_mode: Literal["disabled", "optional", "required"]
    openvpn_enabled: bool
    ovpn_totp_required: bool
    max_devices_per_user: int


class PortalLoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str | None = None


class PortalUserSummary(BaseModel):
    username: str
    display_name: str
    email: str
    domain: str
    totp_enrolled: bool


class PortalQuota(BaseModel):
    used_devices: int
    max_devices: int


class PortalDeviceItem(BaseModel):
    id: str
    device_name: str
    protocol: str = "wireguard"
    assigned_ip: str
    effective_active: bool
    admin_enabled: bool
    online: bool
    rx_bytes: int
    tx_bytes: int
    last_handshake_at: str | None = None
    created_at: str


class PortalMeResponse(BaseModel):
    authenticated: Literal[True] = True
    totp_setup_required: bool
    totp_mode: Literal["disabled", "optional", "required"]
    openvpn_enabled: bool
    ovpn_totp_required: bool
    endpoint_host: str
    tunnel_mode: Literal["split", "full"]
    user: PortalUserSummary
    quota: PortalQuota
    devices: list[PortalDeviceItem] = Field(default_factory=list)


class PortalTotpSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_svg_data_uri: str
    issuer: str


class PortalTotpConfirmRequest(BaseModel):
    code: str


class PortalTotpDisableRequest(BaseModel):
    password: str
    code: str


class PortalCreateDeviceRequest(BaseModel):
    device_name: str
