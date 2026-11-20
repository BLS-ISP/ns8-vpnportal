"""Main entrypoint running Uvicorn concurrently on Unix Admin Socket and localhost TCP."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
from pathlib import Path

import uvicorn

from .admin_api import VPNControllerService, create_admin_app
from .config import Settings
from .portal_api import create_portal_app


def configure_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


async def _chmod_socket_when_ready(sock_path: Path, stop_event: asyncio.Event) -> None:
    """Ensure `${STATE_DIR}/run/admin.sock` strictly carries mode `0600` once bound."""
    for _ in range(200):
        if stop_event.is_set():
            return
        if sock_path.exists():
            try:
                os.chmod(sock_path, 0o600)
            except OSError:
                pass
            return
        await asyncio.sleep(0.05)


async def serve_async(settings: Settings | None = None) -> None:
    configure_logging()
    logger = logging.getLogger("ns8_vpn.main")

    cfg_settings = settings or Settings.from_env()
    cfg_settings.ensure_directories()

    sock_path = cfg_settings.admin_sock_path
    if sock_path.exists():
        sock_path.unlink()

    service = VPNControllerService(cfg_settings)
    try:
        await service.startup_reconcile()
    except Exception as exc:
        logger.error(
            "Initial startup_reconcile encountered an error (continuing to bind admin.sock): %s",
            exc,
            exc_info=True,
        )
    service.start_background_scheduler()

    admin_app = create_admin_app(service, run_lifecycle=False)
    portal_app = create_portal_app(service)

    stop_event = asyncio.Event()
    servers: list[uvicorn.Server] = []

    if hasattr(socket, "AF_UNIX"):
        admin_config = uvicorn.Config(
            app=admin_app,
            uds=str(sock_path),
            log_level="info",
            access_log=False,
        )
        servers.append(uvicorn.Server(admin_config))
    else:
        logger.warning("AF_UNIX not supported on this platform; skipping UDS listener")

    portal_config = uvicorn.Config(
        app=portal_app,
        host="127.0.0.1",
        port=cfg_settings.tcp_port,
        log_level="info",
        access_log=False,
    )
    servers.append(uvicorn.Server(portal_config))

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: _shutdown_servers(servers, stop_event))
        except (NotImplementedError, RuntimeError):
            pass

    logger.info(
        "Starting ns8-vpn controller (module_id=%s, iface=%s, uds=%s, portal=127.0.0.1:%d)",
        cfg_settings.module_id,
        cfg_settings.interface_name,
        sock_path,
        cfg_settings.tcp_port,
    )

    chmod_task = asyncio.create_task(_chmod_socket_when_ready(sock_path, stop_event))
    try:
        await asyncio.gather(*(srv.serve() for srv in servers))
    finally:
        stop_event.set()
        chmod_task.cancel()
        await service.stop_background_scheduler()
        if sock_path.exists():
            try:
                sock_path.unlink()
            except OSError:
                pass


def _shutdown_servers(servers: list[uvicorn.Server], stop_event: asyncio.Event) -> None:
    stop_event.set()
    for srv in servers:
        srv.should_exit = True


def main() -> None:
    asyncio.run(serve_async())


if __name__ == "__main__":
    main()
