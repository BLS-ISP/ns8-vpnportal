"""End-User Self-Service Portal FastAPI server (`127.0.0.1:${TCP_PORT}`).

SECURITY INVARIANT:
This FastAPI application MUST NEVER mount `/api/v1/admin/*` routes.
All privileged NS8 administration runs exclusively over the `0600` Unix Domain Socket.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse

from .admin_api import VPNControllerService
from .ipam import IPAMValidationError, IPPoolExhaustedError
from .models import (
    CreatePeerRequest,
    PortalCreateDeviceRequest,
    PortalDeviceItem,
    PortalInfoResponse,
    PortalLoginRequest,
    PortalMeResponse,
    PortalQuota,
    PortalTotpConfirmRequest,
    PortalTotpDisableRequest,
    PortalTotpSetupResponse,
    PortalUserSummary,
)
from .openvpn import sanitize_profile_filename
from .portal_auth import CSRF_HEADER_NAME, CSRF_HEADER_VALUE, SESSION_COOKIE_NAME
from .totp import build_totp_provisioning_bundle, generate_totp_secret, verify_totp_code


PORTAL_STATIC_DIR = Path(__file__).resolve().parent / "portal_static"

PORTAL_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)

STATIC_MEDIA_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
}


def _client_ip_from_request(request: Request) -> str:
    xff = (request.headers.get("x-forwarded-for") or "").strip()
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _is_secure_request(request: Request) -> bool:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").strip().lower()
    return proto == "https"


def _require_csrf(request: Request) -> None:
    if request.headers.get(CSRF_HEADER_NAME) != CSRF_HEADER_VALUE:
        raise HTTPException(
            status_code=403,
            detail=f"CSRF protection requires header {CSRF_HEADER_NAME}: {CSRF_HEADER_VALUE}",
        )


def _require_portal_enabled(svc: VPNControllerService) -> dict[str, Any]:
    cfg = svc.db.get_server_config()
    if not cfg["portal_enabled"]:
        raise HTTPException(status_code=404, detail="Self-service portal is disabled")
    return cfg


def _set_session_cookie(
    response: Response,
    request: Request,
    token: str,
    max_age: int,
) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=_is_secure_request(request),
        path="/",
    )


def _clear_session_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
        secure=_is_secure_request(request),
    )


def _require_authenticated_user(
    request: Request,
    response: Response,
    svc: VPNControllerService,
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Validate session cookie, ensure user is still active/authorized in DB, and return `(cfg, user, totp_setup_required)`."""
    cfg = _require_portal_enabled(svc)
    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    claims = svc.session_manager.verify_token(raw_cookie)
    if claims is None:
        _clear_session_cookie(response, request)
        raise HTTPException(status_code=401, detail="Authentication required")

    user = svc.db.get_user(str(claims["u"]))
    if user is None or not user["authorized"]:
        _clear_session_cookie(response, request)
        raise HTTPException(
            status_code=401,
            detail="Session expired or VPN authorization revoked",
        )

    totp_enrolled = svc.db.is_user_totp_enrolled(user["username"])
    user["totp_enrolled"] = totp_enrolled
    totp_setup_required = cfg["portal_totp_mode"] == "required" and not totp_enrolled
    return cfg, user, totp_setup_required


def _require_totp_compliant(totp_setup_required: bool) -> None:
    if totp_setup_required:
        raise HTTPException(
            status_code=403,
            detail="Two-factor authentication enrollment must be completed before accessing VPN profiles",
        )


def _serve_static_file(filename: str) -> Response:
    safe_root = PORTAL_STATIC_DIR.resolve()
    candidate = (safe_root / filename).resolve()
    if not candidate.is_relative_to(safe_root) or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Asset not found")
    media_type = STATIC_MEDIA_TYPES.get(candidate.suffix.lower(), "application/octet-stream")
    return FileResponse(candidate, media_type=media_type)


def create_portal_app(service: VPNControllerService) -> FastAPI:
    """Create the Self-Service User Portal & Health FastAPI server (strictly NO admin routes)."""
    app = FastAPI(
        title="ns8-vpn Self-Service Portal",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.service = service

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", PORTAL_CSP)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    # --- Health & Public Portal Metadata ---

    @app.get("/healthz")
    @app.get("/api/v1/portal/health")
    async def portal_health(request: Request) -> dict[str, Any]:
        svc: VPNControllerService = request.app.state.service
        cfg = svc.db.get_server_config()
        return {
            "status": "ok",
            "service": "ns8-vpn-portal",
            "portal_enabled": bool(cfg["portal_enabled"]),
        }

    @app.get("/api/v1/portal/status")
    async def portal_status(request: Request) -> dict[str, Any]:
        svc: VPNControllerService = request.app.state.service
        cfg = _require_portal_enabled(svc)
        return {
            "portal_enabled": True,
            "portal_domain": cfg["portal_domain"],
            "totp_mode": cfg["portal_totp_mode"],
            "openvpn_enabled": cfg["ovpn_enabled"],
        }

    @app.get("/api/v1/portal/info", response_model=PortalInfoResponse)
    async def portal_info(request: Request) -> PortalInfoResponse:
        svc: VPNControllerService = request.app.state.service
        cfg = svc.db.get_server_config()
        return PortalInfoResponse(
            portal_enabled=bool(cfg["portal_enabled"]),
            portal_domain=cfg["portal_domain"],
            totp_mode=cfg["portal_totp_mode"],
            openvpn_enabled=bool(cfg["ovpn_enabled"]),
            ovpn_totp_required=bool(cfg["ovpn_totp_required"]),
            max_devices_per_user=int(cfg["max_devices_per_user"]),
        )

    # --- Static Frontend Routes (only when `portal_enabled == True`) ---

    @app.get("/", response_model=None)
    async def portal_index(request: Request) -> Response:
        svc: VPNControllerService = request.app.state.service
        _require_portal_enabled(svc)
        index_path = PORTAL_STATIC_DIR / "index.html"
        if index_path.is_file():
            return FileResponse(index_path, media_type="text/html; charset=utf-8")
        return HTMLResponse(
            "<!doctype html><html><head><meta charset='utf-8'><title>VPN Portal</title></head>"
            "<body><h1>NS8 VPN Portal</h1></body></html>"
        )

    @app.get("/static/{asset_path:path}", response_model=None)
    async def portal_static_asset(asset_path: str, request: Request) -> Response:
        svc: VPNControllerService = request.app.state.service
        _require_portal_enabled(svc)
        return _serve_static_file(asset_path)

    # --- Authentication & Session Lifecycle ---

    @app.post("/api/v1/portal/auth/login")
    async def portal_login(
        payload: PortalLoginRequest,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        _require_csrf(request)
        svc: VPNControllerService = request.app.state.service
        cfg = _require_portal_enabled(svc)

        client_ip = _client_ip_from_request(request)
        ip_key = f"ip:{client_ip}"
        user_key = f"user:{(payload.username or '').strip().lower()}"

        if svc.rate_limiter.is_limited(ip_key, user_key):
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Please try again in 5 minutes.",
            )

        auth_res = await asyncio.to_thread(
            svc.portal_auth.authenticate_user, payload.username, payload.password
        )
        if not auth_res.ok or auth_res.user is None:
            if auth_res.status_code == 401:
                svc.rate_limiter.record_failure(ip_key, user_key)
            svc.db.log_audit(
                event_type="portal_login_failed",
                actor="portal",
                username=(payload.username or "").strip() or None,
                details=f"Portal login rejected from {client_ip} ({auth_res.error_code})",
            )
            raise HTTPException(
                status_code=auth_res.status_code,
                detail=auth_res.message or "Authentication failed",
            )

        user = auth_res.user
        canonical = user["username"]
        totp_enrolled = svc.db.is_user_totp_enrolled(canonical)
        totp_mode = cfg["portal_totp_mode"]

        if totp_mode != "disabled" and totp_enrolled:
            if not payload.totp_code or not str(payload.totp_code).strip():
                return {
                    "authenticated": False,
                    "totp_verify_required": True,
                    "totp_setup_required": False,
                    "message": "Enter your 6-digit Authenticator code",
                }
            secret = svc.db.get_user_totp_secret(canonical) or ""
            if not verify_totp_code(secret, payload.totp_code):
                svc.rate_limiter.record_failure(ip_key, user_key)
                svc.db.log_audit(
                    event_type="portal_totp_failed",
                    actor="portal",
                    username=canonical,
                    details=f"Invalid TOTP code from {client_ip}",
                )
                raise HTTPException(
                    status_code=401,
                    detail="Invalid two-factor authentication code",
                )

        svc.rate_limiter.reset(ip_key, user_key)
        token = svc.session_manager.create_token(canonical)
        _set_session_cookie(response, request, token, svc.session_manager.ttl_seconds)

        totp_setup_required = totp_mode == "required" and not totp_enrolled
        svc.db.log_audit(
            event_type="portal_login_ok",
            actor="portal",
            username=canonical,
            details=f"Portal login succeeded from {client_ip}",
        )
        return {
            "authenticated": True,
            "totp_verify_required": False,
            "totp_setup_required": totp_setup_required,
            "user": {
                "username": canonical,
                "display_name": user["display_name"],
                "email": user["email"],
                "domain": user["domain"],
                "totp_enrolled": totp_enrolled,
            },
        }

    @app.post("/api/v1/portal/auth/logout")
    async def portal_logout(request: Request, response: Response) -> dict[str, Any]:
        _require_csrf(request)
        _clear_session_cookie(response, request)
        return {"authenticated": False, "logged_out": True}

    @app.get("/api/v1/portal/me", response_model=PortalMeResponse)
    async def portal_me(request: Request, response: Response) -> PortalMeResponse:
        svc: VPNControllerService = request.app.state.service
        cfg, user, totp_setup_required = _require_authenticated_user(request, response, svc)

        peers_all, _, _ = await asyncio.to_thread(svc._collect_live_wg_state)
        my_peers = [
            PortalDeviceItem(
                id=p["id"],
                device_name=p["device_name"],
                protocol=p["protocol"],
                assigned_ip=p["assigned_ip"],
                effective_active=p["effective_active"],
                admin_enabled=p["admin_enabled"],
                online=bool(p.get("online", False)),
                rx_bytes=int(p["rx_bytes"]),
                tx_bytes=int(p["tx_bytes"]),
                last_handshake_at=p["last_handshake_at"],
                created_at=p["created_at"],
            )
            for p in peers_all
            if p["username"].lower() == user["username"].lower()
        ]

        return PortalMeResponse(
            authenticated=True,
            totp_setup_required=totp_setup_required,
            totp_mode=cfg["portal_totp_mode"],
            openvpn_enabled=bool(cfg["ovpn_enabled"]),
            ovpn_totp_required=bool(cfg["ovpn_totp_required"]),
            endpoint_host=cfg["endpoint_host"],
            tunnel_mode=cfg["tunnel_mode"],
            user=PortalUserSummary(
                username=user["username"],
                display_name=user["display_name"],
                email=user["email"],
                domain=user["domain"],
                totp_enrolled=bool(user["totp_enrolled"]),
            ),
            quota=PortalQuota(
                used_devices=len(my_peers),
                max_devices=int(cfg["max_devices_per_user"]),
            ),
            devices=my_peers,
        )

    # --- TOTP 2FA Self-Service Enrollment & Management ---

    @app.post("/api/v1/portal/totp/setup", response_model=PortalTotpSetupResponse)
    async def portal_totp_setup(request: Request, response: Response) -> PortalTotpSetupResponse:
        _require_csrf(request)
        svc: VPNControllerService = request.app.state.service
        cfg, user, _ = _require_authenticated_user(request, response, svc)

        if cfg["portal_totp_mode"] == "disabled":
            raise HTTPException(status_code=400, detail="Two-factor authentication is disabled")
        if user["totp_enrolled"]:
            raise HTTPException(
                status_code=409,
                detail="Two-factor authentication is already active on this account",
            )

        secret = generate_totp_secret()
        await asyncio.to_thread(svc.db.set_user_totp_pending, user["username"], secret)
        bundle = await asyncio.to_thread(
            build_totp_provisioning_bundle,
            secret=secret,
            username=user["username"],
            portal_domain=cfg["portal_domain"],
            endpoint_host=cfg["endpoint_host"],
        )
        return PortalTotpSetupResponse(**bundle)

    @app.post("/api/v1/portal/totp/confirm")
    async def portal_totp_confirm(
        payload: PortalTotpConfirmRequest,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        _require_csrf(request)
        svc: VPNControllerService = request.app.state.service
        _, user, _ = _require_authenticated_user(request, response, svc)

        pending_secret = await asyncio.to_thread(svc.db.get_user_totp_pending, user["username"])
        if not pending_secret:
            raise HTTPException(
                status_code=400,
                detail="No pending 2FA setup found; initiate /api/v1/portal/totp/setup first",
            )

        if not verify_totp_code(pending_secret, payload.code):
            raise HTTPException(status_code=400, detail="Invalid 6-digit verification code")

        await asyncio.to_thread(
            svc.db.confirm_user_totp, user["username"], pending_secret, "portal"
        )
        return {
            "totp_enrolled": True,
            "totp_setup_required": False,
        }

    @app.post("/api/v1/portal/totp/disable")
    async def portal_totp_disable(
        payload: PortalTotpDisableRequest,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        _require_csrf(request)
        svc: VPNControllerService = request.app.state.service
        cfg, user, _ = _require_authenticated_user(request, response, svc)

        if cfg["portal_totp_mode"] == "required":
            raise HTTPException(
                status_code=403,
                detail="Two-factor authentication is mandatory by administrator policy",
            )
        if not user["totp_enrolled"]:
            raise HTTPException(status_code=400, detail="Two-factor authentication is not enabled")

        client_ip = _client_ip_from_request(request)
        rate_key = f"totp_disable:{user['username'].lower()}:{client_ip}"
        if svc.rate_limiter.is_limited(rate_key):
            raise HTTPException(status_code=429, detail="Too many failed verification attempts")

        secret = await asyncio.to_thread(svc.db.get_user_totp_secret, user["username"]) or ""
        if not verify_totp_code(secret, payload.code):
            svc.rate_limiter.record_failure(rate_key)
            raise HTTPException(status_code=401, detail="Invalid 6-digit Authenticator code")

        auth_res = await asyncio.to_thread(
            svc.portal_auth.authenticate_user, user["username"], payload.password
        )
        if not auth_res.ok:
            svc.rate_limiter.record_failure(rate_key)
            raise HTTPException(status_code=401, detail="Invalid account password")

        svc.rate_limiter.reset(rate_key)
        await asyncio.to_thread(svc.db.reset_user_totp, user["username"], "portal")
        return {"totp_enrolled": False}

    # --- WireGuard Self-Service Device Provisioning (with Quota & IDOR Protection) ---

    @app.post("/api/v1/portal/devices")
    async def portal_create_device(
        payload: PortalCreateDeviceRequest,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        _require_csrf(request)
        svc: VPNControllerService = request.app.state.service
        _, user, totp_setup_required = _require_authenticated_user(request, response, svc)
        _require_totp_compliant(totp_setup_required)

        try:
            created = await svc.create_peer(
                CreatePeerRequest(
                    username=user["username"],
                    device_name=payload.device_name,
                    enforce_limit=True,
                    allow_unlisted=False,
                    assigned_ip=None,
                ),
                actor="portal",
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except IPPoolExhaustedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (ValueError, IPAMValidationError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        peer_obj = created.peer
        dev_dict = {
            "id": peer_obj.id,
            "device_name": peer_obj.device_name,
            "protocol": peer_obj.protocol,
            "assigned_ip": peer_obj.assigned_ip,
            "effective_active": peer_obj.effective_active,
            "admin_enabled": peer_obj.admin_enabled,
            "online": peer_obj.online,
            "rx_bytes": peer_obj.rx_bytes,
            "tx_bytes": peer_obj.tx_bytes,
            "last_handshake_at": peer_obj.last_handshake_at,
            "created_at": peer_obj.created_at,
        }
        filename = (
            f"{sanitize_profile_filename(user['username'])}-"
            f"{sanitize_profile_filename(peer_obj.device_name)}.conf"
        )
        return {
            "device": dev_dict,
            "peer": dev_dict,
            "filename": filename,
            "config_text": created.config_text,
            "qr_svg_data_uri": created.qr_svg_data_uri,
        }

    @app.get("/api/v1/portal/devices/{peer_id}/wireguard")
    async def portal_get_device_wireguard(
        peer_id: str,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        svc: VPNControllerService = request.app.state.service
        _, user, totp_setup_required = _require_authenticated_user(request, response, svc)
        _require_totp_compliant(totp_setup_required)

        peer = await asyncio.to_thread(svc.db.get_peer, peer_id)
        if peer is None:
            raise HTTPException(status_code=404, detail="Device not found")
        if peer["username"].lower() != user["username"].lower():
            raise HTTPException(status_code=403, detail="Access denied")

        _, config_text, qr_uri = await asyncio.to_thread(svc.render_peer_bundle, peer_id)
        filename = (
            f"{sanitize_profile_filename(user['username'])}-"
            f"{sanitize_profile_filename(peer['device_name'])}.conf"
        )
        return {
            "id": peer["id"],
            "peer_id": peer["id"],
            "username": user["username"],
            "device_name": peer["device_name"],
            "assigned_ip": peer["assigned_ip"],
            "filename": filename,
            "config_text": config_text,
            "qr_svg_data_uri": qr_uri,
        }

    @app.delete("/api/v1/portal/devices/{peer_id}")
    async def portal_delete_device(
        peer_id: str,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        _require_csrf(request)
        svc: VPNControllerService = request.app.state.service
        _, user, totp_setup_required = _require_authenticated_user(request, response, svc)
        _require_totp_compliant(totp_setup_required)

        peer = await asyncio.to_thread(svc.db.get_peer, peer_id)
        if peer is None:
            raise HTTPException(status_code=404, detail="Device not found")
        if peer["username"].lower() != user["username"].lower():
            raise HTTPException(status_code=403, detail="Access denied")

        await svc.revoke_peer(peer_id, actor="portal")
        return {
            "revoked": True,
            "deleted": True,
            "id": peer_id,
            "peer_id": peer_id,
        }

    # --- OpenVPN Fallback Profile Download ---

    @app.get("/api/v1/portal/openvpn/profile")
    async def portal_get_openvpn_profile(
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        svc: VPNControllerService = request.app.state.service
        _, user, totp_setup_required = _require_authenticated_user(request, response, svc)
        _require_totp_compliant(totp_setup_required)

        try:
            ovpn_res = await asyncio.to_thread(
                svc.get_user_openvpn_profile, user["username"]
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return ovpn_res.model_dump()

    return app
