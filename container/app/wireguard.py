"""WireGuard interface lifecycle, peer synchronization, dump parser, and profile/QR generator."""

from __future__ import annotations

import base64
import io
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import segno

from .config import CLUSTER_RESERVED_INTERFACE
from .ipam import get_server_interface_cidr, get_server_tunnel_ip


ONLINE_HANDSHAKE_WINDOW_SECONDS = 180


@dataclass
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandExecutionError(RuntimeError):
    """Raised when a privileged network command fails."""


class CommandRunner(Protocol):
    """Injectable command execution interface for Linux production and CI/Windows tests."""

    def run(
        self,
        cmd: list[str],
        stdin: str | None = None,
        check: bool = True,
        timeout: float = 15.0,
    ) -> CommandResult: ...


class SubprocessCommandRunner:
    """Executes real `ip`, `wg`, `nft`, and `sysctl` binaries in the container."""

    def run(
        self,
        cmd: list[str],
        stdin: str | None = None,
        check: bool = True,
        timeout: float = 15.0,
    ) -> CommandResult:
        proc = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        result = CommandResult(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
        if check and result.returncode != 0:
            raise CommandExecutionError(
                f"Command {' '.join(cmd)} failed with exit code {result.returncode}: {result.stderr.strip()}"
            )
        return result


@dataclass
class DryRunCommandRunner:
    """In-memory command runner for Windows/CI unit tests without Linux kernel netlink."""

    commands: list[tuple[list[str], str | None]] = field(default_factory=list)
    interfaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    peers_by_iface: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    routes_by_iface: dict[str, set[str]] = field(default_factory=dict)
    last_setconf: dict[str, str] = field(default_factory=dict)
    last_nft_ruleset: str = ""
    sysctls: dict[str, str] = field(default_factory=dict)
    mock_dump_output: dict[str, str] = field(default_factory=dict)

    def run(
        self,
        cmd: list[str],
        stdin: str | None = None,
        check: bool = True,
        timeout: float = 15.0,
    ) -> CommandResult:
        cmd_copy = [str(part) for part in cmd]
        self.commands.append((cmd_copy, stdin))

        if len(cmd_copy) >= 4 and cmd_copy[:3] == ["ip", "link", "show"]:
            iface = cmd_copy[-1]
            if iface in self.interfaces:
                mtu = self.interfaces[iface].get("mtu", 1380)
                state = "UP" if self.interfaces[iface].get("up", False) else "DOWN"
                return CommandResult(
                    0,
                    f"10: {iface}: <POINTOPOINT,NOARP,{state}> mtu {mtu} state UNKNOWN\n",
                )
            res = CommandResult(1, "", f"Device \"{iface}\" does not exist.\n")
            if check:
                raise CommandExecutionError(res.stderr)
            return res

        if len(cmd_copy) >= 6 and cmd_copy[:3] == ["ip", "link", "add"] and "wireguard" in cmd_copy:
            dev_idx = cmd_copy.index("dev") + 1 if "dev" in cmd_copy else 3
            iface = cmd_copy[dev_idx]
            self.interfaces.setdefault(iface, {"up": False, "cidr": "", "mtu": 1380})
            self.peers_by_iface.setdefault(iface, {})
            return CommandResult(0, "")

        if len(cmd_copy) >= 6 and cmd_copy[:4] == ["ip", "-4", "-o", "addr"]:
            iface = cmd_copy[-1]
            cidr = self.interfaces.get(iface, {}).get("cidr", "")
            out = f"10: {iface}    inet {cidr} scope global {iface}\n" if cidr else ""
            return CommandResult(0, out)

        if len(cmd_copy) >= 5 and cmd_copy[:3] == ["ip", "addr", "replace"]:
            cidr = cmd_copy[3]
            iface = cmd_copy[-1]
            self.interfaces.setdefault(iface, {"up": False, "mtu": 1380})["cidr"] = cidr
            return CommandResult(0, "")

        if len(cmd_copy) >= 6 and cmd_copy[:3] == ["ip", "link", "set"]:
            iface = cmd_copy[-1]
            info = self.interfaces.setdefault(iface, {"cidr": ""})
            if "mtu" in cmd_copy:
                mtu_idx = cmd_copy.index("mtu") + 1
                info["mtu"] = int(cmd_copy[mtu_idx])
            if "up" in cmd_copy:
                info["up"] = True
            return CommandResult(0, "")

        if len(cmd_copy) >= 6 and cmd_copy[:3] == ["ip", "route", "replace"]:
            cidr = cmd_copy[3]
            iface = cmd_copy[-1]
            self.routes_by_iface.setdefault(iface, set()).add(cidr)
            return CommandResult(0, "")

        if len(cmd_copy) >= 6 and cmd_copy[:3] == ["ip", "route", "del"]:
            cidr = cmd_copy[3]
            iface = cmd_copy[-1]
            self.routes_by_iface.setdefault(iface, set()).discard(cidr)
            return CommandResult(0, "")

        if len(cmd_copy) == 4 and cmd_copy[:2] == ["wg", "setconf"]:
            iface, conf_path = cmd_copy[2], cmd_copy[3]
            content = Path(conf_path).read_text(encoding="utf-8")
            self.last_setconf[iface] = content
            parsed_peers = _parse_setconf_peers(content)
            existing = self.peers_by_iface.get(iface, {})
            updated: dict[str, dict[str, Any]] = {}
            for pubkey, pinfo in parsed_peers.items():
                prev = existing.get(pubkey, {})
                updated[pubkey] = {
                    "public_key": pubkey,
                    "preshared_key": pinfo.get("preshared_key", "(none)"),
                    "allowed_ips": pinfo.get("allowed_ips", ""),
                    "endpoint": prev.get("endpoint", "(none)"),
                    "handshake": prev.get("handshake", 0),
                    "rx_bytes": prev.get("rx_bytes", 0),
                    "tx_bytes": prev.get("tx_bytes", 0),
                }
            self.peers_by_iface[iface] = updated
            return CommandResult(0, "")

        if (
            len(cmd_copy) == 6
            and cmd_copy[:2] == ["wg", "set"]
            and cmd_copy[3] == "peer"
            and cmd_copy[5] == "remove"
        ):
            iface = cmd_copy[2]
            pubkey = cmd_copy[4]
            self.peers_by_iface.setdefault(iface, {}).pop(pubkey, None)
            return CommandResult(0, "")

        if len(cmd_copy) == 4 and cmd_copy[:2] == ["wg", "show"] and cmd_copy[3] == "dump":
            iface = cmd_copy[2]
            if iface in self.mock_dump_output:
                return CommandResult(0, self.mock_dump_output[iface])
            lines = ["SERVER_PRIV\tSERVER_PUB\t51820\toff"]
            for pubkey, pinfo in self.peers_by_iface.get(iface, {}).items():
                psk = pinfo.get("preshared_key") or "(none)"
                ep = pinfo.get("endpoint") or "(none)"
                aips = pinfo.get("allowed_ips") or "(none)"
                hs = pinfo.get("handshake", 0)
                rx = pinfo.get("rx_bytes", 0)
                tx = pinfo.get("tx_bytes", 0)
                lines.append(f"{pubkey}\t{psk}\t{ep}\t{aips}\t{hs}\t{rx}\t{tx}\toff")
            return CommandResult(0, "\n".join(lines) + "\n")

        if cmd_copy[:2] == ["nft", "-f"]:
            self.last_nft_ruleset = stdin or ""
            return CommandResult(0, "")

        if cmd_copy and cmd_copy[0] == "sysctl":
            for arg in cmd_copy[1:]:
                if "=" in arg:
                    k, v = arg.split("=", 1)
                    self.sysctls[k] = v
            return CommandResult(0, "")

        return CommandResult(0, "")


def _parse_setconf_peers(content: str) -> dict[str, dict[str, str]]:
    peers: dict[str, dict[str, str]] = {}
    section = ""
    current: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            if section == "peer" and "public_key" in current:
                peers[current["public_key"]] = current
            section = line[1:-1].strip().lower()
            current = {}
            continue
        if "=" in line and section == "peer":
            k, v = [part.strip() for part in line.split("=", 1)]
            key_norm = k.lower()
            if key_norm == "publickey":
                current["public_key"] = v
            elif key_norm == "presharedkey":
                current["preshared_key"] = v
            elif key_norm == "allowedips":
                current["allowed_ips"] = v
    if section == "peer" and "public_key" in current:
        peers[current["public_key"]] = current
    return peers


def _guard_not_cluster_interface(interface_name: str) -> None:
    if not interface_name or interface_name.strip().lower() == CLUSTER_RESERVED_INTERFACE:
        raise ValueError("Refusing to operate on reserved NS8 cluster WireGuard interface 'wg0'")


def build_wg_setconf(
    server_private_key: str,
    wg_port: int,
    active_peers: list[dict[str, Any]],
) -> str:
    """Build atomic `wg setconf` configuration containing only authorized active peers."""
    lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"ListenPort = {int(wg_port)}",
    ]
    for peer in active_peers:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer['public_key']}")
        psk = peer.get("preshared_key")
        if psk:
            lines.append(f"PresharedKey = {psk}")
        allowed_ips = peer.get("allowed_ips")
        if allowed_ips and isinstance(allowed_ips, list):
            lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")
        else:
            lines.append(f"AllowedIPs = {peer['assigned_ip']}/32")
        remote_ep = (peer.get("endpoint") or "").strip()
        if remote_ep:
            lines.append(f"Endpoint = {remote_ep}")
    return "\n".join(lines) + "\n"


def parse_wg_dump(
    dump_output: str,
    now_epoch: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Parse `wg show <iface> dump` output keyed by peer public key."""
    now_ts = int(time.time()) if now_epoch is None else int(now_epoch)
    peers: dict[str, dict[str, Any]] = {}
    for raw_line in (dump_output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        # Interface header line has 4 fields; peer lines have 8 fields.
        if len(parts) < 8:
            continue
        pubkey = parts[0].strip()
        endpoint_raw = parts[2].strip()
        allowed_ips = parts[3].strip()
        try:
            handshake_epoch = int(parts[4].strip())
        except ValueError:
            handshake_epoch = 0
        try:
            rx_bytes = int(parts[5].strip())
        except ValueError:
            rx_bytes = 0
        try:
            tx_bytes = int(parts[6].strip())
        except ValueError:
            tx_bytes = 0

        endpoint = None if endpoint_raw in {"", "(none)"} else endpoint_raw
        if handshake_epoch > 0:
            handshake_iso = (
                datetime.fromtimestamp(handshake_epoch, tz=timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
            age = now_ts - handshake_epoch
            online = -30 <= age < ONLINE_HANDSHAKE_WINDOW_SECONDS
        else:
            handshake_iso = None
            online = False

        peers[pubkey] = {
            "public_key": pubkey,
            "endpoint": endpoint,
            "allowed_ips": allowed_ips,
            "handshake_epoch": handshake_epoch,
            "handshake_iso": handshake_iso,
            "rx_bytes": max(0, rx_bytes),
            "tx_bytes": max(0, tx_bytes),
            "online": online,
        }
    return peers


def render_client_config(
    *,
    client_private_key: str,
    assigned_ip: str,
    server_public_key: str,
    preshared_key: str | None,
    endpoint_host: str,
    wg_port: int,
    wg_network: str,
    tunnel_mode: str,
    allowed_cidrs: list[str],
    dns_servers: list[str],
    dns_search_domain: str = "",
    wg_mtu: int = 1380,
    persistent_keepalive: int = 25,
) -> str:
    """Render a standard WireGuard client `.conf` file with LF line endings."""
    dns_items: list[str] = [ip.strip() for ip in dns_servers if ip.strip()]
    search_dom = (dns_search_domain or "").strip()
    if search_dom:
        dns_items.append(search_dom)

    if tunnel_mode == "full":
        allowed_ips_str = "0.0.0.0/0"
    else:
        server_ip_cidr = f"{get_server_tunnel_ip(wg_network)}/32"
        split_items: list[str] = []
        seen: set[str] = set()
        for cidr in allowed_cidrs:
            c = cidr.strip()
            if c and c not in seen:
                seen.add(c)
                split_items.append(c)
        if server_ip_cidr not in seen:
            seen.add(server_ip_cidr)
            split_items.append(server_ip_cidr)
        for dns_ip in dns_servers:
            d = dns_ip.strip()
            if d:
                dns_cidr = f"{d}/32"
                if dns_cidr not in seen:
                    seen.add(dns_cidr)
                    split_items.append(dns_cidr)
        allowed_ips_str = ", ".join(split_items)

    host = (endpoint_host or "").strip() or "vpn.example.com"
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        endpoint_str = f"[{host}]:{int(wg_port)}"
    else:
        endpoint_str = f"{host}:{int(wg_port)}"

    lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key}",
        f"Address = {assigned_ip}/32",
    ]
    if dns_items:
        lines.append(f"DNS = {', '.join(dns_items)}")
    lines.append(f"MTU = {int(wg_mtu)}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_public_key}")
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.append(f"AllowedIPs = {allowed_ips_str}")
    lines.append(f"Endpoint = {endpoint_str}")
    if int(persistent_keepalive) > 0:
        lines.append(f"PersistentKeepalive = {int(persistent_keepalive)}")

    return "\n".join(lines) + "\n"


def render_qr_svg_data_uri(config_text: str) -> str:
    """Render a WireGuard `.conf` string into a `data:image/svg+xml;base64,...` URI."""
    qr = segno.make(config_text, micro=False)
    buffer = io.BytesIO()
    qr.save(buffer, kind="svg", xmldecl=False, scale=4, border=2)
    svg_b64 = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{svg_b64}"


class WireGuardEngine:
    """Manages the `wg-${MODULE_ID}` kernel interface without dropping active handshakes."""

    def __init__(self, runner: CommandRunner, run_dir: Path | None = None) -> None:
        self.runner = runner
        self.run_dir = run_dir

    def is_interface_up(self, interface_name: str) -> bool:
        _guard_not_cluster_interface(interface_name)
        res = self.runner.run(["ip", "link", "show", "dev", interface_name], check=False)
        if res.returncode != 0:
            return False
        if not res.stdout:
            return True
        return "UP" in res.stdout

    def reconcile_interface(
        self,
        *,
        interface_name: str,
        server_private_key: str,
        wg_port: int,
        wg_network: str,
        wg_mtu: int,
        active_peers: list[dict[str, Any]],
    ) -> None:
        """Idempotently configure WireGuard interface and synchronize authorized peers."""
        _guard_not_cluster_interface(interface_name)
        server_cidr = get_server_interface_cidr(wg_network)

        exists = self.runner.run(["ip", "link", "show", "dev", interface_name], check=False)
        if exists.returncode != 0:
            self.runner.run(["ip", "link", "add", "dev", interface_name, "type", "wireguard"])

        addr_info = self.runner.run(
            ["ip", "-4", "-o", "addr", "show", "dev", interface_name], check=False
        )
        if addr_info.returncode == 0 and addr_info.stdout and server_cidr not in addr_info.stdout:
            self.runner.run(["ip", "-4", "addr", "flush", "dev", interface_name], check=False)

        self.runner.run(["ip", "addr", "replace", server_cidr, "dev", interface_name])

        setconf_text = build_wg_setconf(
            server_private_key=server_private_key,
            wg_port=wg_port,
            active_peers=active_peers,
        )

        temp_dir = str(self.run_dir) if self.run_dir and self.run_dir.exists() else None
        fd, tmp_path = tempfile.mkstemp(prefix=f"{interface_name}-", suffix=".conf", dir=temp_dir)
        try:
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(setconf_text)
            self.runner.run(["wg", "setconf", interface_name, tmp_path])
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        self.runner.run(
            ["ip", "link", "set", "mtu", str(int(wg_mtu)), "up", "dev", interface_name]
        )

    def remove_peer_immediately(self, interface_name: str, public_key: str) -> None:
        """Immediately evict a single peer session from the kernel WireGuard interface."""
        _guard_not_cluster_interface(interface_name)
        if not public_key:
            return
        self.runner.run(
            ["wg", "set", interface_name, "peer", public_key, "remove"],
            check=False,
        )

    def read_dump(
        self, interface_name: str, now_epoch: int | None = None
    ) -> dict[str, dict[str, Any]]:
        """Query `wg show <iface> dump` and return live peer telemetry."""
        _guard_not_cluster_interface(interface_name)
        res = self.runner.run(["wg", "show", interface_name, "dump"], check=False)
        if res.returncode != 0:
            return {}
        return parse_wg_dump(res.stdout, now_epoch=now_epoch)
