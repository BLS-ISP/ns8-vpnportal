#!/usr/bin/env python3
"""OpenVPN `--auth-user-pass-verify <script> via-file` helper for ns8-vpn.

Reads the 2-line temporary credentials file provided by OpenVPN in `sys.argv[1]`
and validates live AD/OpenLDAP + optional 6-digit TOTP credentials against the
privileged local Unix socket `${STATE_DIR}/run/admin.sock`.

Never logs passwords or TOTP codes. Exits 0 only on explicit authorization.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import sys
from pathlib import Path


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 10.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        af_unix = getattr(socket, "AF_UNIX", None)
        if af_unix is None:
            raise OSError("AF_UNIX not supported")
        sock = socket.socket(af_unix, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


def verify_via_file(
    via_file_path: str | Path,
    socket_path: str | Path | None = None,
) -> int:
    """Return 0 when credentials in `via_file_path` are authorized, 1 otherwise."""
    cred_path = Path(via_file_path)
    if not cred_path.is_file():
        return 1

    try:
        raw_lines = cred_path.read_text(encoding="utf-8", errors="strict").splitlines()
    except Exception:
        return 1

    if len(raw_lines) < 2:
        return 1

    username = raw_lines[0].strip()
    password = raw_lines[1]
    if not username or not password:
        return 1

    if socket_path is not None:
        sock_file = Path(socket_path)
    else:
        env_admin_sock = os.environ.get("ADMIN_SOCK_PATH", "").strip()
        if env_admin_sock:
            sock_file = Path(env_admin_sock)
        else:
            state_dir = Path(os.environ.get("STATE_DIR", "/state"))
            sock_file = state_dir / "run" / "admin.sock"

    payload = json.dumps({"username": username, "password": password}).encode("utf-8")
    conn = _UnixHTTPConnection(str(sock_file), timeout=12.0)
    try:
        conn.request(
            "POST",
            "/api/v1/admin/openvpn/authenticate",
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            return 1
        parsed = json.loads(body.decode("utf-8"))
        return 0 if bool(parsed.get("allowed")) else 1
    except Exception:
        return 1
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        return 1
    return verify_via_file(args[0])


if __name__ == "__main__":
    sys.exit(main())
