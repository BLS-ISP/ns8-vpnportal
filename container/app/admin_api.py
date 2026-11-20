"""Privileged Admin Unix-Socket FastAPI application and controller orchestration service."""

from __future__ import annotations

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .config import Settings
from .crypto import generate_wg_keypair, generate_wg_psk
from .db import Database
from .firewall import FirewallEngine
from .ipam import (
    IPAMValidationError,
    IPPoolExhaustedError,
    allocate_peer_ip,
    is_ip_valid_client_in_network,
    normalize_allowed_cidrs,
    normalize_dns_servers,
    normalize_wg_network,
    validate_requested_peer_ip,
    validate_wg_port,
)
from .ldap_sync import LDAPConnectionFactory, LDAPSyncService, load_ldap_config_file
from .models import (
    AuditLogItem,
    AuditLogListResponse,
    ConfigSummary,
    CreatePeerRequest,
    CreatePeerResponse,
    CreateS2SRequest,
    CreateS2SResponse,
    DeleteS2SResponse,
    HealthResponse,
    OpenVPNAuthRequest,
    OpenVPNAuthResponse,
    PeerConfigResponse,
    PeerItem,
    PeersListResponse,
    PeersSummary,
    ReconcileResponse,
    ResetUserTotpResponse,
    RevokePeerResponse,
    S2SConfigResponse,
    S2SListResponse,
    S2STunnelItem,
    ServerConfigResponse,
    ServerConfigUpdateRequest,
    SyncResponse,
    TogglePeerRequest,
    TogglePeerResponse,
    ToggleS2SRequest,
    ToggleS2SResponse,
    UserItem,
    UserOvpnResponse,
)
from .openvpn import (
    DryRunOpenVPNController,
    OpenVPNEngine,
    OpenVPNProcessController,
    SubprocessOpenVPNController,
    render_openvpn_client_profile,
    sanitize_profile_filename,
    validate_openvpn_settings,
)
from .portal_auth import (
    LoginRateLimiter,
    PortalAuthenticator,
    SessionManager,
    UserBindVerifier,
)
from .s2s import (
    SiteToSiteRouter,
    normalize_s2s_remote_cidrs,
    prepare_s2s_keys,
    render_s2s_remote_config,
    validate_s2s_name,
    validate_s2s_remote_endpoint,
)
from .totp import split_password_and_totp, verify_totp_code
from .wireguard import (
    CommandExecutionError,
    CommandRunner,
    DryRunCommandRunner,
    SubprocessCommandRunner,
    WireGuardEngine,
    render_client_config,
    render_qr_svg_data_uri,
)


logger = logging.getLogger("ns8_vpn.controller")

DEVICE_NAME_PATTERN = re.compile(r"^[\w\s.\-()'\u00C0-\u024F]{1,64}$")
USERNAME_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")


def validate_device_name(name: str) -> str:
    cleaned = (name or "").strip()
    if not cleaned or len(cleaned) > 64 or not DEVICE_NAME_PATTERN.match(cleaned):
        raise ValueError(
            "device_name must be 1..64 characters using letters, numbers, spaces, '.', '-', '_', or '()'"
        )
    return cleaned


def validate_username_input(username: str) -> str:
    cleaned = (username or "").strip()
    if not cleaned or len(cleaned) > 128 or not USERNAME_PATTERN.match(cleaned):
        raise ValueError("username must be a non-empty valid identifier (1..128 characters)")
    return cleaned


class VPNControllerService:
    """Core state, reconciliation, IPAM, WireGuard, OpenVPN, S2S, firewall, Portal, and LDAP coordinator."""

    def __init__(
        self,
        settings: Settings,
        runner: CommandRunner | None = None,
        ovpn_controller: OpenVPNProcessController | None = None,
        ldap_connection_factory: LDAPConnectionFactory | None = None,
        ldap_user_bind_verifier: UserBindVerifier | None = None,
    ) -> None:
        self.settings = settings
        self.runner: CommandRunner = runner or (
            DryRunCommandRunner() if settings.dry_run else SubprocessCommandRunner()
        )
        self.ovpn_controller: OpenVPNProcessController = ovpn_controller or (
            DryRunOpenVPNController() if settings.dry_run else SubprocessOpenVPNController()
        )
        self.db = Database(settings)
        self.db.initialize()
        self.wg_engine = WireGuardEngine(self.runner, run_dir=self.settings.run_dir)
        self.s2s_router = SiteToSiteRouter(self.runner)
        self.ovpn_engine = OpenVPNEngine(
            conf_path=self.settings.ovpn_server_conf_path,
            mgmt_sock_path=self.settings.ovpn_mgmt_sock_path,
            status_log_path=self.settings.ovpn_status_log_path,
            pid_path=self.settings.ovpn_pid_path,
            process_controller=self.ovpn_controller,
            admin_sock_path=self.settings.admin_sock_path,
        )
        self.firewall = FirewallEngine(
            runner=self.runner,
            module_id=self.settings.module_id,
            cluster_wg_cidr=self.settings.cluster_wg_cidr,
            cluster_wg_interface=self.settings.cluster_wg_interface,
            cluster_wg_port=self.settings.cluster_wg_port,
        )
        self.ldap_sync = LDAPSyncService(
            db=self.db,
            wg_engine=self.wg_engine,
            ldap_config_path=self.settings.ldap_config_path,
            connection_factory=ldap_connection_factory,
            on_user_deauthorized=self.ovpn_engine.kill_user_sessions,
        )
        self.portal_auth = PortalAuthenticator(
            db=self.db,
            ldap_config_path=self.settings.ldap_config_path,
            connection_factory=ldap_connection_factory,
            user_bind_verifier=ldap_user_bind_verifier,
        )
        self.rate_limiter = LoginRateLimiter(max_failures=5, window_seconds=300)
        self.session_manager = SessionManager(master_key=self.db.master_key)
        self._scheduler_wakeup = asyncio.Event()
        self._scheduler_task: asyncio.Task[None] | None = None

    def reconcile_dataplane(self) -> None:
        """Synchronize WireGuard, Site-to-Site kernel routes, OpenVPN daemon, and nftables."""
        cfg = self.db.get_server_config()
        server_priv = self.db.get_server_private_key()
        active_peers = self.db.list_active_wireguard_peers_with_psk()

        self.wg_engine.reconcile_interface(
            interface_name=cfg["interface_name"],
            server_private_key=server_priv,
            wg_port=cfg["wg_port"],
            wg_network=cfg["wg_network"],
            wg_mtu=cfg["wg_mtu"],
            active_peers=active_peers,
        )

        s2s_tunnels = self.db.list_s2s_tunnels()
        active_s2s_cidrs = [
            cidr
            for tunnel in s2s_tunnels
            if tunnel["enabled"]
            for cidr in tunnel["remote_cidrs"]
        ]
        self.s2s_router.sync_routes(cfg["interface_name"], active_s2s_cidrs)

        pki = self.db.ensure_openvpn_pki() if cfg["ovpn_enabled"] else None
        self.ovpn_engine.reconcile(
            ovpn_enabled=cfg["ovpn_enabled"],
            interface_name=cfg["ovpn_interface_name"],
            ovpn_proto=cfg["ovpn_proto"],
            ovpn_port=cfg["ovpn_port"],
            ovpn_network=cfg["ovpn_network"],
            tunnel_mode=cfg["tunnel_mode"],
            allowed_cidrs=cfg["allowed_cidrs"],
            dns_servers=cfg["dns_servers"],
            dns_search_domain=cfg["dns_search_domain"],
            pki=pki,
        )

        self.firewall.apply_firewall(
            interface_name=cfg["interface_name"],
            wg_network=cfg["wg_network"],
            tunnel_mode=cfg["tunnel_mode"],
            allowed_cidrs=cfg["allowed_cidrs"],
            dns_servers=cfg["dns_servers"],
            nat_enabled=cfg["nat_enabled"],
            ovpn_enabled=cfg["ovpn_enabled"],
            ovpn_interface_name=cfg["ovpn_interface_name"],
            ovpn_network=cfg["ovpn_network"],
            s2s_remote_cidrs=active_s2s_cidrs,
        )

    async def startup_reconcile(self) -> None:
        """Run full boot sequence: dataplane reconcile + initial LDAP sync."""
        self._sync_domain_metadata_from_ldap_file()
        await asyncio.to_thread(self.reconcile_dataplane)
        if self.ldap_sync.is_ldap_configured():
            await self.ldap_sync.sync_async()

    def _sync_domain_metadata_from_ldap_file(self) -> None:
        try:
            ldap_cfg = load_ldap_config_file(self.settings.ldap_config_path)
        except Exception:
            return
        if not ldap_cfg or not ldap_cfg.get("configured"):
            return
        cfg = self.db.get_server_config()
        updates: dict[str, Any] = {}
        file_domain = str(ldap_cfg.get("domain") or "").strip()
        file_group = str(ldap_cfg.get("vpn_group") or "").strip()
        if file_domain and not cfg["user_domain"]:
            updates["user_domain"] = file_domain
        if file_group and not cfg["vpn_group"]:
            updates["vpn_group"] = file_group
        if updates:
            self.db.update_server_config(updates)

    def start_background_scheduler(self) -> None:
        if self._scheduler_task is None or self._scheduler_task.done():
            self._scheduler_task = asyncio.create_task(
                self._periodic_sync_loop(), name="ns8-vpn-ldap-sync-scheduler"
            )

    async def stop_background_scheduler(self) -> None:
        if self._scheduler_task is not None and not self._scheduler_task.done():
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        self._scheduler_task = None

    async def _periodic_sync_loop(self) -> None:
        while True:
            cfg = self.db.get_server_config()
            interval_sec = max(60, int(cfg.get("sync_interval_minutes", 5)) * 60)
            self._scheduler_wakeup.clear()
            try:
                await asyncio.wait_for(self._scheduler_wakeup.wait(), timeout=interval_sec)
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                raise

            if self.ldap_sync.is_ldap_configured():
                try:
                    await self.ldap_sync.sync_async()
                except Exception as exc:
                    logger.warning("Background LDAP sync error: %s", exc)

    def _collect_live_wg_state(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, Any]]]:
        cfg = self.db.get_server_config()
        live_dump = self.wg_engine.read_dump(cfg["interface_name"])
        if live_dump is not None:
            self.db.update_peers_telemetry(live_dump)
        peers = self.db.list_peers(include_revoked=False)
        for p in peers:
            dump_entry = live_dump.get(p["public_key"])
            p["online"] = bool(
                p["effective_active"] and dump_entry is not None and dump_entry.get("online", False)
            )

        s2s_list = self.db.list_s2s_tunnels()
        for t in s2s_list:
            dump_entry = live_dump.get(t["public_key"])
            t["online"] = bool(
                t["enabled"] and dump_entry is not None and dump_entry.get("online", False)
            )
        return peers, s2s_list, live_dump

    def get_config_response(self) -> ServerConfigResponse:
        cfg = self.db.get_server_config()
        users = self.db.list_users()
        peers, s2s_tunnels, _ = self._collect_live_wg_state()
        online_ovpn = self.ovpn_engine.count_online_clients() if cfg["ovpn_enabled"] else 0

        summary = ConfigSummary(
            authorized_users=sum(1 for u in users if u["authorized"]),
            total_peers=len(peers),
            active_peers=sum(1 for p in peers if p["effective_active"]),
            online_peers=sum(1 for p in peers if p["online"]),
            online_ovpn_clients=online_ovpn,
            s2s_tunnels=len(s2s_tunnels),
            active_s2s_tunnels=sum(1 for t in s2s_tunnels if t["enabled"]),
            last_synced_at=cfg["last_synced_at"],
            last_sync_status=cfg["last_sync_status"],
            last_sync_error=cfg["last_sync_error"],
        )
        return ServerConfigResponse(
            configured=cfg["configured"],
            endpoint_host=cfg["endpoint_host"],
            wg_port=cfg["wg_port"],
            wg_network=cfg["wg_network"],
            tunnel_mode=cfg["tunnel_mode"],
            allowed_cidrs=cfg["allowed_cidrs"],
            dns_servers=cfg["dns_servers"],
            dns_search_domain=cfg["dns_search_domain"],
            wg_mtu=cfg["wg_mtu"],
            persistent_keepalive=cfg["persistent_keepalive"],
            nat_enabled=cfg["nat_enabled"],
            user_domain=cfg["user_domain"],
            vpn_group=cfg["vpn_group"],
            max_devices_per_user=cfg["max_devices_per_user"],
            sync_interval_minutes=cfg["sync_interval_minutes"],
            portal_enabled=cfg["portal_enabled"],
            portal_domain=cfg["portal_domain"],
            portal_lets_encrypt=cfg["portal_lets_encrypt"],
            portal_http2https=cfg["portal_http2https"],
            portal_totp_mode=cfg["portal_totp_mode"],
            ovpn_enabled=cfg["ovpn_enabled"],
            ovpn_proto=cfg["ovpn_proto"],
            ovpn_port=cfg["ovpn_port"],
            ovpn_public_port=cfg["ovpn_public_port"],
            ovpn_network=cfg["ovpn_network"],
            ovpn_totp_required=cfg["ovpn_totp_required"],
            ovpn_interface_name=cfg["ovpn_interface_name"],
            server_public_key=cfg["server_public_key"],
            interface_name=cfg["interface_name"],
            summary=summary,
        )

    async def update_config(self, req: ServerConfigUpdateRequest) -> ServerConfigResponse:
        current = self.db.get_server_config()
        raw_updates = req.model_dump(exclude_unset=True)

        target_port = int(raw_updates.get("wg_port", current["wg_port"]))
        target_net_str = str(raw_updates.get("wg_network", current["wg_network"]))
        target_mode = str(raw_updates.get("tunnel_mode", current["tunnel_mode"]))
        target_cidrs = raw_updates.get("allowed_cidrs", current["allowed_cidrs"])
        target_dns = raw_updates.get("dns_servers", current["dns_servers"])
        target_mtu = int(raw_updates.get("wg_mtu", current["wg_mtu"]))
        target_keepalive = int(raw_updates.get("persistent_keepalive", current["persistent_keepalive"]))
        target_max_dev = int(raw_updates.get("max_devices_per_user", current["max_devices_per_user"]))
        target_sync_min = int(raw_updates.get("sync_interval_minutes", current["sync_interval_minutes"]))
        target_totp_mode = str(raw_updates.get("portal_totp_mode", current["portal_totp_mode"])).lower()

        target_ovpn_enabled = bool(raw_updates.get("ovpn_enabled", current["ovpn_enabled"]))
        target_ovpn_proto = str(raw_updates.get("ovpn_proto", current["ovpn_proto"]))
        target_ovpn_port = int(raw_updates.get("ovpn_port", current["ovpn_port"]))
        target_ovpn_pub_port = int(
            raw_updates.get(
                "ovpn_public_port",
                target_ovpn_port if "ovpn_port" in raw_updates and "ovpn_public_port" not in raw_updates else current["ovpn_public_port"],
            )
        )
        target_ovpn_net = str(raw_updates.get("ovpn_network", current["ovpn_network"]))

        validate_wg_port(target_port, cluster_wg_port=self.settings.cluster_wg_port)
        normalized_net = normalize_wg_network(
            target_net_str, cluster_wg_cidr=self.settings.cluster_wg_cidr
        )
        normalized_cidrs = normalize_allowed_cidrs(
            target_cidrs, str(normalized_net), cluster_wg_cidr=self.settings.cluster_wg_cidr
        )
        normalized_dns = normalize_dns_servers(
            target_dns, cluster_wg_cidr=self.settings.cluster_wg_cidr
        )

        ovpn_proto_clean, ovpn_port_clean, ovpn_pub_clean, ovpn_net_clean = validate_openvpn_settings(
            ovpn_enabled=target_ovpn_enabled,
            ovpn_proto=target_ovpn_proto,
            ovpn_port=target_ovpn_port,
            ovpn_public_port=target_ovpn_pub_port,
            ovpn_network=target_ovpn_net,
            wg_port=target_port,
            wg_network=str(normalized_net),
            allowed_cidrs=normalized_cidrs,
            cluster_wg_cidr=self.settings.cluster_wg_cidr,
            cluster_wg_port=self.settings.cluster_wg_port,
        )

        if target_mtu < 1280 or target_mtu > 1500:
            raise IPAMValidationError("wg_mtu must be between 1280 and 1500")
        if target_keepalive < 0 or target_keepalive > 600:
            raise IPAMValidationError("persistent_keepalive must be between 0 and 600 seconds")
        if target_max_dev < 1 or target_max_dev > 100:
            raise IPAMValidationError("max_devices_per_user must be between 1 and 100")
        if target_sync_min < 1 or target_sync_min > 1440:
            raise IPAMValidationError("sync_interval_minutes must be between 1 and 1440")
        if target_mode not in {"split", "full"}:
            raise IPAMValidationError("tunnel_mode must be 'split' or 'full'")
        if target_totp_mode not in {"disabled", "optional", "required"}:
            raise IPAMValidationError("portal_totp_mode must be 'disabled', 'optional', or 'required'")

        updates: dict[str, Any] = dict(raw_updates)
        updates["wg_port"] = target_port
        updates["wg_network"] = str(normalized_net)
        updates["tunnel_mode"] = target_mode
        updates["allowed_cidrs"] = normalized_cidrs
        updates["dns_servers"] = normalized_dns
        updates["wg_mtu"] = target_mtu
        updates["persistent_keepalive"] = target_keepalive
        updates["max_devices_per_user"] = target_max_dev
        updates["sync_interval_minutes"] = target_sync_min
        updates["portal_totp_mode"] = target_totp_mode
        updates["ovpn_enabled"] = target_ovpn_enabled
        updates["ovpn_proto"] = ovpn_proto_clean
        updates["ovpn_port"] = ovpn_port_clean
        updates["ovpn_public_port"] = ovpn_pub_clean
        updates["ovpn_network"] = ovpn_net_clean

        for str_key in ("endpoint_host", "dns_search_domain", "user_domain", "vpn_group", "portal_domain"):
            if str_key in updates and updates[str_key] is not None:
                updates[str_key] = str(updates[str_key]).strip()

        if "configured" not in updates or updates["configured"] is None:
            updates["configured"] = True

        # Re-IP existing roadwarrior peers & S2S tunnels if WireGuard transfer subnet changed
        if str(normalized_net) != current["wg_network"]:
            existing_peers = self.db.list_peers(include_revoked=False)
            existing_s2s = self.db.list_s2s_tunnels()
            used_in_new: set[str] = {
                p["assigned_ip"]
                for p in [*existing_peers, *existing_s2s]
                if is_ip_valid_client_in_network(p["assigned_ip"], str(normalized_net))
            }
            for peer in existing_peers:
                if not is_ip_valid_client_in_network(peer["assigned_ip"], str(normalized_net)):
                    new_ip = allocate_peer_ip(str(normalized_net), used_in_new)
                    used_in_new.add(new_ip)
                    self.db.update_peer_ip(peer["id"], new_ip)
            for s2s in existing_s2s:
                if not is_ip_valid_client_in_network(s2s["assigned_ip"], str(normalized_net)):
                    new_ip = allocate_peer_ip(str(normalized_net), used_in_new)
                    used_in_new.add(new_ip)
                    self.db.update_s2s_ip(s2s["id"], new_ip)

        self.db.update_server_config(updates)
        self.db.log_audit(
            event_type="config_updated",
            actor="admin",
            details=(
                f"Updated VPN config: wg={normalized_net}:{target_port}/udp, mode={target_mode}, "
                f"portal={updates.get('portal_enabled', current['portal_enabled'])} ({target_totp_mode}), "
                f"ovpn={target_ovpn_enabled} ({ovpn_net_clean}:{ovpn_port_clean}/{ovpn_proto_clean})"
            ),
        )

        await asyncio.to_thread(self.reconcile_dataplane)
        if self.ldap_sync.is_ldap_configured():
            await self.ldap_sync.sync_async()
        self._scheduler_wakeup.set()

        return self.get_config_response()

    async def reconcile_all(self) -> ReconcileResponse:
        self._sync_domain_metadata_from_ldap_file()
        await asyncio.to_thread(self.reconcile_dataplane)
        if self.ldap_sync.is_ldap_configured():
            await self.ldap_sync.sync_async()
        self._scheduler_wakeup.set()
        return ReconcileResponse(status="ok", config=self.get_config_response())

    def list_peers_response(self) -> PeersListResponse:
        cfg = self.db.get_server_config()
        users_raw = self.db.list_users()
        peers_raw, _, _ = self._collect_live_wg_state()

        peer_counts: dict[str, int] = {}
        for p in peers_raw:
            key = p["username"].lower()
            peer_counts[key] = peer_counts.get(key, 0) + 1

        user_items = [
            UserItem(
                username=u["username"],
                domain=u["domain"],
                display_name=u["display_name"],
                email=u["email"],
                ldap_active=u["ldap_active"],
                in_vpn_group=u["in_vpn_group"],
                authorized=u["authorized"],
                totp_enrolled=bool(u.get("totp_enrolled", False)),
                peer_count=peer_counts.get(u["username"].lower(), 0),
                last_synced_at=u["last_synced_at"],
            )
            for u in users_raw
        ]
        peer_items = [self._to_peer_item(p) for p in peers_raw]
        summary = PeersSummary(
            authorized_users=sum(1 for u in user_items if u.authorized),
            total_peers=len(peer_items),
            active_peers=sum(1 for p in peer_items if p.effective_active),
            online_peers=sum(1 for p in peer_items if p.online),
            max_devices_per_user=cfg["max_devices_per_user"],
        )
        return PeersListResponse(users=user_items, peers=peer_items, summary=summary)

    def render_peer_bundle(self, peer_id: str) -> tuple[dict[str, Any], str, str]:
        peer = self.db.get_peer(peer_id)
        if peer is None:
            raise KeyError(peer_id)
        cfg = self.db.get_server_config()
        priv_key, psk = self.db.get_peer_secrets(peer_id)
        config_text = render_client_config(
            client_private_key=priv_key,
            assigned_ip=peer["assigned_ip"],
            server_public_key=cfg["server_public_key"],
            preshared_key=psk,
            endpoint_host=cfg["endpoint_host"],
            wg_port=cfg["wg_port"],
            wg_network=cfg["wg_network"],
            tunnel_mode=cfg["tunnel_mode"],
            allowed_cidrs=cfg["allowed_cidrs"],
            dns_servers=cfg["dns_servers"],
            dns_search_domain=cfg["dns_search_domain"],
            wg_mtu=cfg["wg_mtu"],
            persistent_keepalive=cfg["persistent_keepalive"],
        )
        qr_uri = render_qr_svg_data_uri(config_text)
        return peer, config_text, qr_uri

    async def create_peer(self, req: CreatePeerRequest, actor: str = "admin") -> CreatePeerResponse:
        username = validate_username_input(req.username)
        device_name = validate_device_name(req.device_name)
        cfg = self.db.get_server_config()

        user = self.db.get_user(username)
        if user is None:
            if not req.allow_unlisted:
                raise PermissionError(
                    f"User '{username}' does not exist in synchronized AD/LDAP directory"
                )
            user = self.db.upsert_user(
                username=username,
                domain=cfg["user_domain"],
                display_name=username,
                ldap_active=True,
                in_vpn_group=True,
            )
        elif not user["authorized"]:
            raise PermissionError(
                f"User '{user['username']}' is disabled or not in authorized VPN group"
            )

        canonical_username = user["username"]
        existing_peers = self.db.list_peers(include_revoked=False)
        user_peer_count = sum(
            1 for p in existing_peers if p["username"].lower() == canonical_username.lower()
        )
        if req.enforce_limit and user_peer_count >= cfg["max_devices_per_user"]:
            raise ValueError(
                f"User '{canonical_username}' has reached max_devices_per_user ({cfg['max_devices_per_user']})"
            )

        used_ips = self.db.get_used_ips()
        requested_ip = (req.assigned_ip or "").strip()
        if requested_ip:
            assigned_ip = validate_requested_peer_ip(
                requested_ip,
                cfg["wg_network"],
                used_ips,
            )
        else:
            assigned_ip = allocate_peer_ip(cfg["wg_network"], used_ips)
        priv_key, pub_key = generate_wg_keypair()
        psk = generate_wg_psk()

        peer = self.db.create_peer_record(
            username=canonical_username,
            device_name=device_name,
            assigned_ip=assigned_ip,
            public_key=pub_key,
            private_key=priv_key,
            preshared_key=psk,
            protocol="wireguard",
            admin_enabled=True,
            actor=actor,
        )

        await asyncio.to_thread(self.reconcile_dataplane)
        _, config_text, qr_uri = self.render_peer_bundle(peer["id"])
        return CreatePeerResponse(
            peer=self._to_peer_item(peer),
            config_text=config_text,
            qr_svg_data_uri=qr_uri,
        )

    async def toggle_peer(self, peer_id: str, enabled: bool | None) -> TogglePeerResponse:
        existing = self.db.get_peer(peer_id)
        if existing is None:
            raise KeyError(peer_id)

        cfg = self.db.get_server_config()
        iface = cfg["interface_name"]
        target_enabled = (not existing["admin_enabled"]) if enabled is None else bool(enabled)

        live_dump = await asyncio.to_thread(self.wg_engine.read_dump, iface)
        if live_dump:
            self.db.update_peers_telemetry(live_dump)

        updated = self.db.set_peer_admin_enabled(peer_id, target_enabled, actor="admin")
        if updated is None:
            raise KeyError(peer_id)

        if not updated["effective_active"]:
            await asyncio.to_thread(
                self.wg_engine.remove_peer_immediately, iface, updated["public_key"]
            )
            updated["online"] = False
        else:
            await asyncio.to_thread(self.reconcile_dataplane)
            dump_after = await asyncio.to_thread(self.wg_engine.read_dump, iface)
            entry = dump_after.get(updated["public_key"])
            updated["online"] = bool(entry and entry.get("online", False))

        return TogglePeerResponse(peer=self._to_peer_item(updated))

    async def revoke_peer(self, peer_id: str, actor: str = "admin") -> RevokePeerResponse:
        existing = self.db.get_peer(peer_id)
        if existing is None:
            raise KeyError(peer_id)

        cfg = self.db.get_server_config()
        iface = cfg["interface_name"]
        live_dump = await asyncio.to_thread(self.wg_engine.read_dump, iface)
        if live_dump:
            self.db.update_peers_telemetry(live_dump)

        await asyncio.to_thread(
            self.wg_engine.remove_peer_immediately, iface, existing["public_key"]
        )
        revoked = self.db.revoke_peer(peer_id, actor=actor)
        if revoked is None:
            raise KeyError(peer_id)
        return RevokePeerResponse(revoked=True, peer_id=peer_id)

    # --- Phase 2 & 3 User TOTP Reset & OpenVPN Profile / Auth ---

    def reset_user_totp(self, username: str) -> ResetUserTotpResponse:
        clean_user = validate_username_input(username)
        canonical = self.db.reset_user_totp(clean_user, actor="admin")
        if canonical is None:
            raise KeyError(clean_user)
        return ResetUserTotpResponse(reset=True, username=canonical)

    def get_user_openvpn_profile(self, username: str) -> UserOvpnResponse:
        clean_user = validate_username_input(username)
        cfg = self.db.get_server_config()
        if not cfg["ovpn_enabled"]:
            raise ValueError("OpenVPN fallback server is disabled")

        user = self.db.get_user(clean_user)
        if user is None:
            raise KeyError(clean_user)
        if not user["authorized"]:
            raise PermissionError(
                f"User '{user['username']}' is disabled or not in authorized VPN group"
            )

        pki = self.db.ensure_openvpn_pki()
        ovpn_text = render_openvpn_client_profile(
            endpoint_host=cfg["endpoint_host"],
            ovpn_public_port=cfg["ovpn_public_port"],
            ovpn_proto=cfg["ovpn_proto"],
            pki=pki,
        )
        fname = (
            f"{sanitize_profile_filename(user['username'])}-"
            f"{sanitize_profile_filename(self.settings.module_id)}.ovpn"
        )
        return UserOvpnResponse(
            username=user["username"],
            filename=fname,
            ovpn_text=ovpn_text,
            totp_required_on_connect=bool(cfg["ovpn_totp_required"]),
        )

    def authenticate_openvpn_connect(
        self, username: str, password: str
    ) -> tuple[int, OpenVPNAuthResponse]:
        """Validate live OpenVPN client login (`AD password` or `AD password + 6-digit TOTP`)."""
        clean_user = (username or "").strip()
        rate_key = f"ovpn:{clean_user.lower()}"
        if self.rate_limiter.is_limited(rate_key):
            return 429, OpenVPNAuthResponse(
                allowed=False,
                username=clean_user,
                reason="rate_limited",
            )

        cfg = self.db.get_server_config()
        if not cfg["ovpn_enabled"]:
            return 403, OpenVPNAuthResponse(
                allowed=False,
                username=clean_user,
                reason="openvpn_disabled",
            )

        if not clean_user or not password:
            self.rate_limiter.record_failure(rate_key)
            return 401, OpenVPNAuthResponse(
                allowed=False,
                username=clean_user,
                reason="invalid_credentials",
            )

        if cfg["ovpn_totp_required"]:
            split_pair = split_password_and_totp(password)
            if split_pair is None:
                self.rate_limiter.record_failure(rate_key)
                return 401, OpenVPNAuthResponse(
                    allowed=False,
                    username=clean_user,
                    reason="totp_code_required",
                )
            ad_password, totp_code = split_pair
        else:
            ad_password, totp_code = password, ""

        auth_res = self.portal_auth.authenticate_user(clean_user, ad_password)
        if not auth_res.ok or auth_res.user is None:
            if auth_res.status_code == 401:
                self.rate_limiter.record_failure(rate_key)
            self.db.log_audit(
                event_type="openvpn_auth_denied",
                actor="openvpn",
                username=clean_user,
                details=f"OpenVPN auth denied ({auth_res.error_code})",
            )
            return auth_res.status_code, OpenVPNAuthResponse(
                allowed=False,
                username=clean_user,
                reason=auth_res.error_code or "auth_failed",
            )

        canonical_user = auth_res.user["username"]
        if cfg["ovpn_totp_required"]:
            if not self.db.is_user_totp_enrolled(canonical_user):
                self.db.log_audit(
                    event_type="openvpn_auth_denied",
                    actor="openvpn",
                    username=canonical_user,
                    details="OpenVPN auth denied: 2FA required on connect, user has no TOTP enrolled",
                )
                return 403, OpenVPNAuthResponse(
                    allowed=False,
                    username=canonical_user,
                    reason="totp_not_enrolled",
                )
            secret = self.db.get_user_totp_secret(canonical_user) or ""
            if not verify_totp_code(secret, totp_code):
                self.rate_limiter.record_failure(rate_key)
                self.db.log_audit(
                    event_type="openvpn_auth_denied",
                    actor="openvpn",
                    username=canonical_user,
                    details="OpenVPN auth denied: invalid 6-digit TOTP code",
                )
                return 401, OpenVPNAuthResponse(
                    allowed=False,
                    username=canonical_user,
                    reason="invalid_totp",
                )

        self.rate_limiter.reset(rate_key)
        self.db.log_audit(
            event_type="openvpn_auth_ok",
            actor="openvpn",
            username=canonical_user,
            details="OpenVPN live authentication succeeded",
        )
        return 200, OpenVPNAuthResponse(allowed=True, username=canonical_user)

    # --- Phase 3 Site-to-Site Tunnels ---

    def list_s2s_response(self) -> S2SListResponse:
        _, s2s_raw, _ = self._collect_live_wg_state()
        return S2SListResponse(tunnels=[self._to_s2s_item(t) for t in s2s_raw])

    def render_s2s_config_bundle(self, tunnel_id: str) -> S2SConfigResponse:
        tunnel = self.db.get_s2s_tunnel(tunnel_id)
        if tunnel is None:
            raise KeyError(tunnel_id)
        cfg = self.db.get_server_config()
        priv_key, psk = self.db.get_s2s_secrets(tunnel_id)
        config_text = render_s2s_remote_config(
            tunnel_name=tunnel["name"],
            assigned_ip=tunnel["assigned_ip"],
            remote_private_key=priv_key,
            preshared_key=psk,
            server_public_key=cfg["server_public_key"],
            endpoint_host=cfg["endpoint_host"],
            wg_port=cfg["wg_port"],
            wg_network=cfg["wg_network"],
            local_allowed_cidrs=cfg["allowed_cidrs"],
            ovpn_enabled=cfg["ovpn_enabled"],
            ovpn_network=cfg["ovpn_network"],
            wg_mtu=cfg["wg_mtu"],
            persistent_keepalive=cfg["persistent_keepalive"],
        )
        return S2SConfigResponse(
            tunnel_id=tunnel["id"],
            name=tunnel["name"],
            config_text=config_text,
            has_private_key=priv_key is not None,
        )

    async def create_s2s(self, req: CreateS2SRequest) -> CreateS2SResponse:
        cfg = self.db.get_server_config()
        name = validate_s2s_name(req.name)
        remote_ep = validate_s2s_remote_endpoint(req.remote_endpoint)
        existing_cidrs = [
            cidr for t in self.db.list_s2s_tunnels() for cidr in t["remote_cidrs"]
        ]
        clean_cidrs = normalize_s2s_remote_cidrs(
            req.remote_cidrs,
            wg_network=cfg["wg_network"],
            ovpn_network=cfg["ovpn_network"] if cfg["ovpn_enabled"] else "",
            existing_s2s_cidrs=existing_cidrs,
            cluster_wg_cidr=self.settings.cluster_wg_cidr,
        )
        priv_key, pub_key, psk = prepare_s2s_keys(
            remote_public_key=req.remote_public_key,
            server_public_key=cfg["server_public_key"],
        )
        if any(t["public_key"] == pub_key for t in self.db.list_s2s_tunnels()):
            raise IPAMValidationError("A Site-to-Site tunnel with this public key already exists")

        assigned_ip = allocate_peer_ip(cfg["wg_network"], self.db.get_used_ips())
        tunnel = self.db.create_s2s_tunnel(
            name=name,
            assigned_ip=assigned_ip,
            public_key=pub_key,
            private_key=priv_key,
            preshared_key=psk,
            remote_endpoint=remote_ep,
            remote_cidrs=clean_cidrs,
            enabled=True,
        )

        await asyncio.to_thread(self.reconcile_dataplane)
        cfg_bundle = self.render_s2s_config_bundle(tunnel["id"])
        return CreateS2SResponse(
            tunnel=self._to_s2s_item(tunnel),
            config_text=cfg_bundle.config_text,
        )

    async def toggle_s2s(self, tunnel_id: str, enabled: bool | None) -> ToggleS2SResponse:
        existing = self.db.get_s2s_tunnel(tunnel_id)
        if existing is None:
            raise KeyError(tunnel_id)

        cfg = self.db.get_server_config()
        iface = cfg["interface_name"]
        target_enabled = (not existing["enabled"]) if enabled is None else bool(enabled)

        live_dump = await asyncio.to_thread(self.wg_engine.read_dump, iface)
        if live_dump:
            self.db.update_peers_telemetry(live_dump)

        updated = self.db.set_s2s_enabled(tunnel_id, target_enabled)
        if updated is None:
            raise KeyError(tunnel_id)

        if not target_enabled:
            await asyncio.to_thread(
                self.wg_engine.remove_peer_immediately, iface, updated["public_key"]
            )
            await asyncio.to_thread(
                self.s2s_router.remove_routes, iface, updated["remote_cidrs"]
            )
        await asyncio.to_thread(self.reconcile_dataplane)
        return ToggleS2SResponse(tunnel=self._to_s2s_item(updated))

    async def delete_s2s(self, tunnel_id: str) -> DeleteS2SResponse:
        existing = self.db.get_s2s_tunnel(tunnel_id)
        if existing is None:
            raise KeyError(tunnel_id)

        cfg = self.db.get_server_config()
        iface = cfg["interface_name"]
        await asyncio.to_thread(
            self.wg_engine.remove_peer_immediately, iface, existing["public_key"]
        )
        await asyncio.to_thread(
            self.s2s_router.remove_routes, iface, existing["remote_cidrs"]
        )
        self.db.delete_s2s_tunnel(tunnel_id)
        await asyncio.to_thread(self.reconcile_dataplane)
        return DeleteS2SResponse(deleted=True, tunnel_id=tunnel_id)

    def list_audit_logs_response(
        self,
        limit: int = 200,
        event_type: str = "",
        username: str = "",
    ) -> AuditLogListResponse:
        entries_raw, total = self.db.list_audit_logs(
            limit=limit,
            event_type=event_type,
            username=username,
        )
        return AuditLogListResponse(
            entries=[AuditLogItem(**entry) for entry in entries_raw],
            total=total,
        )

    @staticmethod
    def _to_peer_item(peer: dict[str, Any]) -> PeerItem:
        return PeerItem(
            id=peer["id"],
            username=peer["username"],
            display_name=peer["display_name"],
            protocol=peer["protocol"],
            device_name=peer["device_name"],
            assigned_ip=peer["assigned_ip"],
            public_key=peer["public_key"],
            admin_enabled=peer["admin_enabled"],
            user_authorized=peer["user_authorized"],
            effective_active=peer["effective_active"],
            online=bool(peer.get("online", False)),
            rx_bytes=int(peer["rx_bytes"]),
            tx_bytes=int(peer["tx_bytes"]),
            last_handshake_at=peer["last_handshake_at"],
            last_endpoint=peer["last_endpoint"],
            created_at=peer["created_at"],
        )

    @staticmethod
    def _to_s2s_item(tunnel: dict[str, Any]) -> S2STunnelItem:
        return S2STunnelItem(
            id=tunnel["id"],
            name=tunnel["name"],
            enabled=tunnel["enabled"],
            assigned_ip=tunnel["assigned_ip"],
            public_key=tunnel["public_key"],
            has_private_key=bool(tunnel.get("has_private_key", True)),
            remote_endpoint=tunnel["remote_endpoint"],
            remote_cidrs=list(tunnel["remote_cidrs"]),
            online=bool(tunnel.get("online", False)),
            rx_bytes=int(tunnel["rx_bytes"]),
            tx_bytes=int(tunnel["tx_bytes"]),
            last_handshake_at=tunnel["last_handshake_at"],
            created_at=tunnel["created_at"],
        )


def create_admin_app(
    service: VPNControllerService,
    run_lifecycle: bool = False,
) -> FastAPI:
    """Create the Admin Unix-Domain-Socket FastAPI app (`/api/v1/admin/*`)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if run_lifecycle:
            await service.startup_reconcile()
            service.start_background_scheduler()
        try:
            yield
        finally:
            if run_lifecycle:
                await service.stop_background_scheduler()

    app = FastAPI(
        title="ns8-vpn Admin Socket API",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.service = service

    @app.get("/api/v1/admin/health", response_model=HealthResponse)
    async def admin_health(request: Request) -> HealthResponse:
        svc: VPNControllerService = request.app.state.service
        cfg = svc.db.get_server_config()
        iface = cfg["interface_name"]
        up = await asyncio.to_thread(svc.wg_engine.is_interface_up, iface)
        return HealthResponse(
            status="ok",
            module_id=svc.settings.module_id,
            interface=iface,
            interface_up=up,
        )

    @app.get("/api/v1/admin/config", response_model=ServerConfigResponse)
    async def admin_get_config(request: Request) -> ServerConfigResponse:
        svc: VPNControllerService = request.app.state.service
        return await asyncio.to_thread(svc.get_config_response)

    @app.put("/api/v1/admin/config", response_model=ServerConfigResponse)
    async def admin_put_config(
        payload: ServerConfigUpdateRequest,
        request: Request,
    ) -> ServerConfigResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            return await svc.update_config(payload)
        except IPAMValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except IPPoolExhaustedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except CommandExecutionError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/api/v1/admin/reconcile", response_model=ReconcileResponse)
    async def admin_reconcile(
        request: Request,
        _body: dict[str, Any] | None = Body(default=None),
    ) -> ReconcileResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            return await svc.reconcile_all()
        except CommandExecutionError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/api/v1/admin/sync", response_model=SyncResponse)
    async def admin_sync(
        request: Request,
        _body: dict[str, Any] | None = Body(default=None),
    ) -> SyncResponse:
        svc: VPNControllerService = request.app.state.service
        result = await svc.ldap_sync.sync_async()
        return SyncResponse(**result)

    @app.get("/api/v1/admin/peers", response_model=PeersListResponse)
    async def admin_list_peers(request: Request) -> PeersListResponse:
        svc: VPNControllerService = request.app.state.service
        return await asyncio.to_thread(svc.list_peers_response)

    @app.post("/api/v1/admin/peers", response_model=CreatePeerResponse)
    async def admin_create_peer(
        payload: CreatePeerRequest,
        request: Request,
    ) -> CreatePeerResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            return await svc.create_peer(payload, actor="admin")
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except IPPoolExhaustedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (ValueError, IPAMValidationError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/admin/peers/{peer_id}/config", response_model=PeerConfigResponse)
    async def admin_get_peer_config(peer_id: str, request: Request) -> PeerConfigResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            peer, config_text, qr_uri = await asyncio.to_thread(
                svc.render_peer_bundle, peer_id
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Peer '{peer_id}' not found") from exc
        return PeerConfigResponse(
            peer_id=peer["id"],
            username=peer["username"],
            device_name=peer["device_name"],
            config_text=config_text,
            qr_svg_data_uri=qr_uri,
        )

    @app.post("/api/v1/admin/peers/{peer_id}/toggle", response_model=TogglePeerResponse)
    async def admin_toggle_peer(
        peer_id: str,
        request: Request,
        payload: TogglePeerRequest | None = Body(default=None),
    ) -> TogglePeerResponse:
        svc: VPNControllerService = request.app.state.service
        enabled = payload.enabled if payload is not None else None
        try:
            return await svc.toggle_peer(peer_id, enabled)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Peer '{peer_id}' not found") from exc

    @app.delete("/api/v1/admin/peers/{peer_id}", response_model=RevokePeerResponse)
    async def admin_delete_peer(peer_id: str, request: Request) -> RevokePeerResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            return await svc.revoke_peer(peer_id, actor="admin")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Peer '{peer_id}' not found") from exc

    # --- Phase 2 & 3 Admin User / OpenVPN / Site-to-Site Routes ---

    @app.post("/api/v1/admin/users/{username}/reset-totp", response_model=ResetUserTotpResponse)
    async def admin_reset_user_totp(
        username: str,
        request: Request,
        _body: dict[str, Any] | None = Body(default=None),
    ) -> ResetUserTotpResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            return await asyncio.to_thread(svc.reset_user_totp, username)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"User '{username}' not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/admin/users/{username}/ovpn", response_model=UserOvpnResponse)
    async def admin_get_user_ovpn(username: str, request: Request) -> UserOvpnResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            return await asyncio.to_thread(svc.get_user_openvpn_profile, username)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"User '{username}' not found") from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/admin/openvpn/authenticate")
    async def admin_openvpn_authenticate(
        payload: OpenVPNAuthRequest,
        request: Request,
    ) -> JSONResponse:
        svc: VPNControllerService = request.app.state.service
        status_code, result = await asyncio.to_thread(
            svc.authenticate_openvpn_connect, payload.username, payload.password
        )
        return JSONResponse(status_code=status_code, content=result.model_dump())

    @app.get("/api/v1/admin/s2s", response_model=S2SListResponse)
    async def admin_list_s2s(request: Request) -> S2SListResponse:
        svc: VPNControllerService = request.app.state.service
        return await asyncio.to_thread(svc.list_s2s_response)

    @app.post("/api/v1/admin/s2s", response_model=CreateS2SResponse)
    async def admin_create_s2s(
        payload: CreateS2SRequest,
        request: Request,
    ) -> CreateS2SResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            return await svc.create_s2s(payload)
        except IPPoolExhaustedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (ValueError, IPAMValidationError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/admin/s2s/{tunnel_id}/config", response_model=S2SConfigResponse)
    async def admin_get_s2s_config(tunnel_id: str, request: Request) -> S2SConfigResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            return await asyncio.to_thread(svc.render_s2s_config_bundle, tunnel_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404, detail=f"Site-to-Site tunnel '{tunnel_id}' not found"
            ) from exc

    @app.post("/api/v1/admin/s2s/{tunnel_id}/toggle", response_model=ToggleS2SResponse)
    async def admin_toggle_s2s(
        tunnel_id: str,
        request: Request,
        payload: ToggleS2SRequest | None = Body(default=None),
    ) -> ToggleS2SResponse:
        svc: VPNControllerService = request.app.state.service
        enabled = payload.enabled if payload is not None else None
        try:
            return await svc.toggle_s2s(tunnel_id, enabled)
        except KeyError as exc:
            raise HTTPException(
                status_code=404, detail=f"Site-to-Site tunnel '{tunnel_id}' not found"
            ) from exc

    @app.delete("/api/v1/admin/s2s/{tunnel_id}", response_model=DeleteS2SResponse)
    async def admin_delete_s2s(tunnel_id: str, request: Request) -> DeleteS2SResponse:
        svc: VPNControllerService = request.app.state.service
        try:
            return await svc.delete_s2s(tunnel_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404, detail=f"Site-to-Site tunnel '{tunnel_id}' not found"
            ) from exc

    @app.get("/api/v1/admin/audit-logs", response_model=AuditLogListResponse)
    async def admin_list_audit_logs(
        request: Request,
        limit: int = Query(default=200, ge=1, le=1000),
        event_type: str = Query(default=""),
        username: str = Query(default=""),
    ) -> AuditLogListResponse:
        svc: VPNControllerService = request.app.state.service
        return await asyncio.to_thread(
            svc.list_audit_logs_response,
            limit,
            event_type,
            username,
        )

    return app
