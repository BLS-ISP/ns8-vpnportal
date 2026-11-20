"""Shared helper utilities for NethServer 8 Business Roadwarrior VPN actions."""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Collection, Sequence

DEFAULT_WG_PORT = 51820
DEFAULT_WG_NETWORK = "10.199.0.0/24"
DEFAULT_WG_MTU = 1380
DEFAULT_PERSISTENT_KEEPALIVE = 25
DEFAULT_MAX_DEVICES_PER_USER = 3
DEFAULT_SYNC_INTERVAL_MINUTES = 5

DEFAULT_PORTAL_TOTP_MODE = "optional"
DEFAULT_OVPN_PROTO = "tcp"
DEFAULT_OVPN_PORT = 1194
DEFAULT_OVPN_PUBLIC_PORT = 1194
DEFAULT_OVPN_NETWORK = "10.199.1.0/24"

DEFAULT_CLUSTER_WG_PORT = 55820
DEFAULT_CLUSTER_WG_CIDR = "10.5.4.0/24"

_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def get_module_id() -> str:
    """Return the active NS8 MODULE_ID (e.g. 'vpn1')."""
    return os.environ.get("MODULE_ID", "vpn1").strip() or "vpn1"


def get_state_dir(module_id: str | None = None) -> Path:
    """Return the rootful module state directory (/var/lib/nethserver/<MODULE_ID>/state)."""
    env_state = os.environ.get("AGENT_STATE_DIR", "").strip()
    if env_state:
        return Path(env_state)
    mid = module_id or get_module_id()
    return Path(f"/var/lib/nethserver/{mid}/state")


def get_admin_socket_path(module_id: str | None = None, state_dir: Path | None = None) -> Path:
    """Return the Unix Domain Socket path used by privileged NS8 actions."""
    base = state_dir or get_state_dir(module_id)
    return base / "run" / "admin.sock"


def get_wg_interface_name(module_id: str | None = None) -> str:
    """Return the dedicated WireGuard kernel interface name (<=15 chars, never wg0)."""
    raw = (module_id if module_id is not None else get_module_id()).strip()
    if raw.lower() == "wg0" or raw == "0":
        raise ValueError("Interface 'wg0' is strictly reserved for NS8 cluster WireGuard")

    clean = re.sub(r"[^A-Za-z0-9_-]", "", raw)
    if not clean:
        clean = "vpn1"

    if clean.lower().startswith("wg-"):
        clean = clean[3:] or "vpn1"
    if clean == "0" or clean.lower() == "wg0":
        raise ValueError("Interface 'wg0' is strictly reserved for NS8 cluster WireGuard")

    candidate = f"wg-{clean}"
    if len(candidate) > 15:
        m = re.search(r"(\d+)$", clean)
        if m and len(m.group(1)) <= 6:
            suffix = m.group(1)
            prefix_len = 15 - 3 - len(suffix)
            candidate = f"wg-{clean[:prefix_len]}{suffix}"
        else:
            candidate = candidate[:15]

    if candidate.lower() == "wg0":
        raise ValueError("Interface 'wg0' is strictly reserved for NS8 cluster WireGuard")
    return candidate


def get_ovpn_interface_name(module_id: str | None = None) -> str:
    """Return the dedicated OpenVPN tun interface name (<=15 chars, e.g. tun-vpn1)."""
    raw = (module_id if module_id is not None else get_module_id()).strip()
    clean = re.sub(r"[^A-Za-z0-9_-]", "", raw)
    if not clean:
        clean = "vpn1"

    if clean.lower().startswith("tun-"):
        clean = clean[4:] or "vpn1"

    candidate = f"tun-{clean}"
    if len(candidate) > 15:
        m = re.search(r"(\d+)$", clean)
        if m and len(m.group(1)) <= 6:
            suffix = m.group(1)
            prefix_len = 15 - 4 - len(suffix)
            candidate = f"tun-{clean[:prefix_len]}{suffix}"
        else:
            candidate = candidate[:15]
    return candidate


def get_nft_table_name(module_id: str | None = None) -> str:
    """Return the isolated nftables inet table identifier for this module."""
    mid = module_id or get_module_id()
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", mid)
    return f"ns8_vpn_{sanitized}"


def get_firewalld_zone_name(module_id: str | None = None) -> str:
    """Return the dedicated firewalld zone name (max 17 chars on RHEL/Rocky 9)."""
    mid = module_id or get_module_id()
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", mid) or "vpnportal1"
    candidate = f"ns8vpn-{sanitized}"
    if len(candidate) > 17:
        m = re.search(r"(\d+)$", sanitized)
        if m and len(m.group(1)) <= 6:
            suffix = m.group(1)
            prefix_len = 17 - len("ns8vpn-") - len(suffix)
            candidate = f"ns8vpn-{sanitized[:prefix_len]}{suffix}"
        else:
            candidate = candidate[:17]
    return candidate


def get_firewalld_policy_name(module_id: str | None = None) -> str:
    """Return the dedicated firewalld forwarding policy name."""
    mid = module_id or get_module_id()
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", mid)
    return f"{sanitized}-fwd"[:31]


def atomic_write_json(target_path: Path, data: Any, mode: int = 0o600) -> None:
    """Write JSON atomically with restrictive file permissions."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target_path.name}.",
        dir=str(target_path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        try:
            os.chmod(tmp_path, mode)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, target_path)
        try:
            os.chmod(target_path, mode)
        except OSError:
            pass
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def run_cmd(
    args: Sequence[str],
    *,
    check: bool = False,
    input_text: str | None = None,
    timeout: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    """Execute a system command safely, returning returncode=127 when missing."""
    try:
        return subprocess.run(
            list(args),
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )
    except FileNotFoundError as exc:
        if check:
            raise
        return subprocess.CompletedProcess(
            args=list(args),
            returncode=127,
            stdout="",
            stderr=str(exc),
        )


# ---------------------------------------------------------------------------
# Host Network Inspection & Collision Checks
# ---------------------------------------------------------------------------


def detect_cluster_wg() -> tuple[str, int]:
    """Detect NS8 cluster wg0 subnet and UDP listen port (defaults: 10.5.4.0/24, 55820)."""
    cluster_cidr = os.environ.get("CLUSTER_WG_CIDR", "").strip() or DEFAULT_CLUSTER_WG_CIDR
    try:
        cluster_port = int(os.environ.get("CLUSTER_WG_PORT", "") or DEFAULT_CLUSTER_WG_PORT)
    except ValueError:
        cluster_port = DEFAULT_CLUSTER_WG_PORT

    addr_res = run_cmd(["ip", "-j", "-4", "addr", "show", "dev", "wg0"])
    if addr_res.returncode == 0 and addr_res.stdout.strip():
        try:
            items = json.loads(addr_res.stdout)
            for item in items:
                for addr_info in item.get("addr_info", []):
                    local = addr_info.get("local")
                    prefixlen = addr_info.get("prefixlen")
                    if local and prefixlen is not None:
                        net = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
                        if isinstance(net, ipaddress.IPv4Network):
                            cluster_cidr = str(net)
                            break
        except (ValueError, TypeError, KeyError):
            pass

    wg_res = run_cmd(["wg", "show", "wg0", "listen-port"])
    if wg_res.returncode == 0 and wg_res.stdout.strip().isdigit():
        port_val = int(wg_res.stdout.strip())
        if 1 <= port_val <= 65535:
            cluster_port = port_val
    else:
        wg0_conf = Path("/etc/wireguard/wg0.conf")
        try:
            if wg0_conf.is_file():
                for line in wg0_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
                    stripped = line.strip()
                    if stripped.lower().startswith("listenport"):
                        _, _, rhs = stripped.partition("=")
                        if rhs.strip().isdigit():
                            cluster_port = int(rhs.strip())
        except OSError:
            pass

    return cluster_cidr, cluster_port


def detect_host_lan(module_id: str | None = None) -> tuple[str, str]:
    """Detect primary host IPv4 address and LAN CIDR for router-forwarding hints & split-tunnel suggestion."""
    own_wg_iface = get_wg_interface_name(module_id)
    own_tun_iface = get_ovpn_interface_name(module_id)
    ignored_prefixes = ("lo", "wg0", "wg-", "tun-", "tun", "tap", "podman", "cni", "veth", "docker", "virbr")

    primary_dev = ""
    primary_ip = ""

    route_res = run_cmd(["ip", "-j", "-4", "route", "get", "1.1.1.1"])
    if route_res.returncode == 0 and route_res.stdout.strip():
        try:
            routes = json.loads(route_res.stdout)
            if isinstance(routes, list) and routes:
                primary_dev = str(routes[0].get("dev") or "")
                primary_ip = str(routes[0].get("prefsrc") or "")
        except (ValueError, TypeError, KeyError):
            pass

    if not primary_dev:
        def_res = run_cmd(["ip", "-j", "-4", "route", "show", "default"])
        if def_res.returncode == 0 and def_res.stdout.strip():
            try:
                routes = json.loads(def_res.stdout)
                if isinstance(routes, list) and routes:
                    primary_dev = str(routes[0].get("dev") or "")
                    primary_ip = str(routes[0].get("prefsrc") or primary_ip)
            except (ValueError, TypeError, KeyError):
                pass

    own_ifaces = {own_wg_iface, own_tun_iface}
    addr_cmd = ["ip", "-j", "-4", "addr", "show"]
    if primary_dev and primary_dev not in own_ifaces and not primary_dev.startswith(ignored_prefixes):
        dev_res = run_cmd(["ip", "-j", "-4", "addr", "show", "dev", primary_dev])
        if dev_res.returncode == 0 and dev_res.stdout.strip():
            ip_str, cidr_str = _extract_lan_from_ip_json(dev_res.stdout, primary_ip, own_ifaces, ignored_prefixes)
            if ip_str:
                return ip_str, cidr_str

    all_res = run_cmd(addr_cmd)
    if all_res.returncode == 0 and all_res.stdout.strip():
        ip_str, cidr_str = _extract_lan_from_ip_json(all_res.stdout, primary_ip, own_ifaces, ignored_prefixes)
        if ip_str:
            return ip_str, cidr_str

    return primary_ip, ""


def _extract_lan_from_ip_json(
    raw_json: str,
    preferred_ip: str,
    own_ifaces: set[str],
    ignored_prefixes: tuple[str, ...],
) -> tuple[str, str]:
    try:
        ifaces = json.loads(raw_json)
    except ValueError:
        return "", ""

    fallback_ip = ""
    fallback_cidr = ""

    for iface in ifaces if isinstance(ifaces, list) else []:
        ifname = str(iface.get("ifname") or "")
        if ifname in own_ifaces or ifname.startswith(ignored_prefixes):
            continue
        for addr_info in iface.get("addr_info", []):
            local = str(addr_info.get("local") or "")
            prefixlen = addr_info.get("prefixlen")
            if not local or prefixlen is None:
                continue
            try:
                ip_obj = ipaddress.ip_address(local)
                if not isinstance(ip_obj, ipaddress.IPv4Address):
                    continue
                if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
                    continue
                net = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
                cidr = str(net) if net.prefixlen < 32 else ""
            except ValueError:
                continue

            if preferred_ip and local == preferred_ip:
                return local, cidr
            if not fallback_ip:
                fallback_ip, fallback_cidr = local, cidr

    return fallback_ip, fallback_cidr


def parse_ss_udp_ports(ss_output: str) -> set[int]:
    """Parse bound local port numbers from `ss -H -uln` or `ss -H -tln` output."""
    ports: set[int] = set()
    for line in ss_output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local_col = parts[3] if parts[0].isupper() and len(parts) >= 5 else parts[2] if len(parts) == 4 else parts[3]
        if ":" not in local_col:
            continue
        _, _, port_part = local_col.rpartition(":")
        if port_part.isdigit():
            port = int(port_part)
            if 1 <= port <= 65535:
                ports.add(port)
    return ports


def get_bound_udp_ports() -> set[int]:
    """Return the set of currently bound local UDP ports on the host."""
    res = run_cmd(["ss", "-H", "-uln"])
    if res.returncode != 0:
        return set()
    return parse_ss_udp_ports(res.stdout)


def get_bound_tcp_ports() -> set[int]:
    """Return the set of currently listening local TCP ports on the host."""
    res = run_cmd(["ss", "-H", "-tln"])
    if res.returncode != 0:
        return set()
    return parse_ss_udp_ports(res.stdout)


def get_own_active_wg_port(module_id: str | None = None) -> int | None:
    """Return this module's own active WireGuard listen port if already running."""
    iface = get_wg_interface_name(module_id)
    res = run_cmd(["wg", "show", iface, "listen-port"])
    if res.returncode == 0 and res.stdout.strip().isdigit():
        return int(res.stdout.strip())
    link_res = run_cmd(["ip", "link", "show", "dev", iface])
    if link_res.returncode == 0:
        env_port = os.environ.get("WG_PORT", "").strip()
        if env_port.isdigit():
            return int(env_port)
    return None


def get_own_active_ovpn_binding(module_id: str | None = None) -> tuple[str, int] | None:
    """Return `(proto, port)` if this module's OpenVPN daemon is already active."""
    mid = module_id or get_module_id()
    tun_iface = get_ovpn_interface_name(mid)
    was_enabled = os.environ.get("OVPN_ENABLED", "").strip().lower() == "true"
    env_port = os.environ.get("OVPN_PORT", "").strip()
    env_proto = (os.environ.get("OVPN_PROTO", "") or DEFAULT_OVPN_PROTO).strip().lower()
    if not env_port.isdigit() or env_proto not in ("tcp", "udp"):
        return None

    link_res = run_cmd(["ip", "link", "show", "dev", tun_iface])
    if link_res.returncode == 0:
        return env_proto, int(env_port)

    if was_enabled:
        svc_res = run_cmd(["systemctl", "is-active", "--quiet", f"{mid}.service"])
        if svc_res.returncode == 0:
            return env_proto, int(env_port)
    return None


def parse_ip_routes_json(raw_json: str, module_id: str | None = None) -> list[ipaddress.IPv4Network]:
    """Parse host IPv4 routes from `ip -j route show`, ignoring default, lo, wg0, wg-<MID>, and tun-<MID>."""
    own_wg = get_wg_interface_name(module_id)
    own_tun = get_ovpn_interface_name(module_id)
    networks: list[ipaddress.IPv4Network] = []
    try:
        routes = json.loads(raw_json)
    except ValueError:
        return networks

    if not isinstance(routes, list):
        return networks

    for entry in routes:
        if not isinstance(entry, dict):
            continue
        dst = str(entry.get("dst") or "").strip()
        dev = str(entry.get("dev") or "").strip()
        if not dst or dst in ("default", "0.0.0.0/0"):
            continue
        if dev in (own_wg, own_tun, "wg0", "lo"):
            continue
        try:
            net = ipaddress.ip_network(dst, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network) and not net.is_loopback:
            networks.append(net)
    return networks


def get_host_route_networks(module_id: str | None = None) -> list[ipaddress.IPv4Network]:
    """Return active non-default IPv4 host route networks (excluding wg0, wg-<MID>, tun-<MID>)."""
    res = run_cmd(["ip", "-j", "-4", "route", "show"])
    if res.returncode != 0 or not res.stdout.strip():
        return []
    return parse_ip_routes_json(res.stdout, module_id=module_id)


def pick_free_wg_port(
    preferred: int = DEFAULT_WG_PORT,
    cluster_wg_port: int = DEFAULT_CLUSTER_WG_PORT,
    bound_ports: set[int] | None = None,
) -> int:
    """Choose the first free UDP port starting at `preferred`, avoiding cluster wg0."""
    used = set(bound_ports) if bound_ports is not None else get_bound_udp_ports()
    reserved = {DEFAULT_CLUSTER_WG_PORT, cluster_wg_port}
    for candidate in range(preferred, 65535):
        if candidate not in reserved and candidate not in used:
            return candidate
    for candidate in range(10000, preferred):
        if candidate not in reserved and candidate not in used:
            return candidate
    raise RuntimeError("No free UDP port available for WireGuard")


def pick_free_ovpn_port(
    preferred: int = DEFAULT_OVPN_PORT,
    proto: str = DEFAULT_OVPN_PROTO,
    *,
    wg_port: int = DEFAULT_WG_PORT,
    cluster_wg_port: int = DEFAULT_CLUSTER_WG_PORT,
    bound_tcp_ports: set[int] | None = None,
    bound_udp_ports: set[int] | None = None,
) -> int:
    """Choose a collision-free OpenVPN listen port."""
    norm_proto = (proto or DEFAULT_OVPN_PROTO).strip().lower()
    if norm_proto == "udp":
        used = set(bound_udp_ports) if bound_udp_ports is not None else get_bound_udp_ports()
        reserved = {DEFAULT_CLUSTER_WG_PORT, cluster_wg_port, wg_port}
    else:
        used = set(bound_tcp_ports) if bound_tcp_ports is not None else get_bound_tcp_ports()
        reserved = {80, 443}

    for candidate in [preferred] + list(range(1194, 1300)) + list(range(11940, 12100)):
        if candidate not in reserved and candidate not in used:
            return candidate
    raise RuntimeError("No free port available for OpenVPN")


def pick_free_wg_network(
    preferred: str = DEFAULT_WG_NETWORK,
    cluster_wg_cidr: str = DEFAULT_CLUSTER_WG_CIDR,
    host_routes: Sequence[ipaddress.IPv4Network] | None = None,
    extra_forbidden: Sequence[str | ipaddress.IPv4Network] | None = None,
) -> str:
    """Choose a collision-free /24 IPv4 transfer network."""
    routes = list(host_routes) if host_routes is not None else get_host_route_networks()
    forbidden: list[ipaddress.IPv4Network] = [
        ipaddress.ip_network(DEFAULT_CLUSTER_WG_CIDR, strict=False),
        ipaddress.ip_network(cluster_wg_cidr, strict=False),
        *routes,
    ]
    for item in extra_forbidden or ():
        if isinstance(item, ipaddress.IPv4Network):
            forbidden.append(item)
        elif str(item).strip():
            try:
                net = ipaddress.ip_network(str(item).strip(), strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    forbidden.append(net)
            except ValueError:
                pass

    candidates = [preferred] + [f"10.199.{octet}.0/24" for octet in range(1, 255)] + [
        f"10.198.{octet}.0/24" for octet in range(0, 255)
    ]
    for cand_str in candidates:
        cand = ipaddress.ip_network(cand_str, strict=False)
        if isinstance(cand, ipaddress.IPv4Network) and not any(cand.overlaps(f) for f in forbidden):
            return str(cand)
    raise RuntimeError("No collision-free IPv4 /24 transfer subnet available")


# ---------------------------------------------------------------------------
# Configuration Validation & Normalization
# ---------------------------------------------------------------------------


def is_valid_hostname_or_ip(value: str, *, require_fqdn: bool = False) -> bool:
    """Return True if value is a valid hostname/FQDN or IP address (unless require_fqdn=True)."""
    val = value.strip()
    if not val or len(val) > 253 or " " in val or "/" in val or ":" in val and not _is_ipv6(val):
        return False

    if not require_fqdn:
        try:
            ip_obj = ipaddress.ip_address(val)
            return not (ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_loopback)
        except ValueError:
            pass

    host = val[:-1] if val.endswith(".") else val
    labels = host.split(".")
    if require_fqdn and len(labels) < 2:
        return False
    if labels[-1].isdigit():
        return False
    return all(bool(_HOSTNAME_LABEL_RE.match(lbl)) for lbl in labels)


def _is_ipv6(val: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(val), ipaddress.IPv6Address)
    except ValueError:
        return False


def normalize_config_input(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a configure-module input payload with safe defaults."""
    allowed_raw = raw.get("allowed_cidrs") or []
    if isinstance(allowed_raw, str):
        allowed_list = [item.strip() for item in re.split(r"[,\n]+", allowed_raw) if item.strip()]
    else:
        allowed_list = [str(item).strip() for item in allowed_raw if str(item).strip()]

    dns_raw = raw.get("dns_servers") or []
    if isinstance(dns_raw, str):
        dns_list = [item.strip() for item in re.split(r"[,\n]+", dns_raw) if item.strip()]
    else:
        dns_list = [str(item).strip() for item in dns_raw if str(item).strip()]

    normalized_cidrs: list[str] = []
    for cidr in allowed_list:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            normalized_cidrs.append(str(net))
        except ValueError:
            normalized_cidrs.append(cidr)

    wg_net_raw = str(raw.get("wg_network") or os.environ.get("WG_NETWORK") or DEFAULT_WG_NETWORK).strip()
    ovpn_enabled = bool(raw.get("ovpn_enabled", _env_bool("OVPN_ENABLED", False)))
    ovpn_net_raw = str(raw.get("ovpn_network") or os.environ.get("OVPN_NETWORK") or DEFAULT_OVPN_NETWORK).strip()

    # If OpenVPN is disabled and default ovpn_network collides with wg_network or allowed_cidrs, shift it safely
    if not ovpn_enabled and "ovpn_network" not in raw:
        try:
            ovpn_net_obj = ipaddress.ip_network(ovpn_net_raw, strict=False)
            wg_net_obj = ipaddress.ip_network(wg_net_raw, strict=False)
            if ovpn_net_obj.overlaps(wg_net_obj) or any(
                ovpn_net_obj.overlaps(ipaddress.ip_network(c, strict=False))
                for c in normalized_cidrs
                if _is_valid_cidr(c)
            ):
                ovpn_net_raw = pick_free_wg_network(
                    preferred="10.199.2.0/24",
                    host_routes=[],
                    extra_forbidden=[wg_net_raw, *normalized_cidrs],
                )
        except ValueError:
            pass

    ovpn_port = int(raw.get("ovpn_port", os.environ.get("OVPN_PORT") or DEFAULT_OVPN_PORT))
    ovpn_pub_port = int(raw.get("ovpn_public_port", os.environ.get("OVPN_PUBLIC_PORT") or ovpn_port))

    return {
        "endpoint_host": str(raw.get("endpoint_host") or "").strip(),
        "wg_port": int(raw.get("wg_port", os.environ.get("WG_PORT") or DEFAULT_WG_PORT)),
        "wg_network": wg_net_raw,
        "tunnel_mode": str(raw.get("tunnel_mode") or "split").strip().lower(),
        "allowed_cidrs": normalized_cidrs,
        "dns_servers": dns_list,
        "dns_search_domain": str(raw.get("dns_search_domain") or "").strip(),
        "wg_mtu": int(raw.get("wg_mtu", DEFAULT_WG_MTU)),
        "persistent_keepalive": int(raw.get("persistent_keepalive", DEFAULT_PERSISTENT_KEEPALIVE)),
        "nat_enabled": bool(raw.get("nat_enabled", True)),
        "user_domain": str(raw.get("user_domain") or "").strip(),
        "vpn_group": str(raw.get("vpn_group") or "").strip(),
        "max_devices_per_user": int(raw.get("max_devices_per_user", DEFAULT_MAX_DEVICES_PER_USER)),
        "sync_interval_minutes": int(raw.get("sync_interval_minutes", DEFAULT_SYNC_INTERVAL_MINUTES)),
        "portal_enabled": bool(raw.get("portal_enabled", False)),
        "portal_domain": str(raw.get("portal_domain") or "").strip().lower(),
        "portal_lets_encrypt": bool(raw.get("portal_lets_encrypt", False)),
        "portal_http2https": bool(raw.get("portal_http2https", True)),
        "portal_totp_mode": str(
            raw.get("portal_totp_mode") or os.environ.get("PORTAL_TOTP_MODE") or DEFAULT_PORTAL_TOTP_MODE
        )
        .strip()
        .lower(),
        "ovpn_enabled": ovpn_enabled,
        "ovpn_proto": str(raw.get("ovpn_proto") or os.environ.get("OVPN_PROTO") or DEFAULT_OVPN_PROTO).strip().lower(),
        "ovpn_port": ovpn_port,
        "ovpn_public_port": ovpn_pub_port,
        "ovpn_network": ovpn_net_raw,
        "ovpn_totp_required": bool(raw.get("ovpn_totp_required", _env_bool("OVPN_TOTP_REQUIRED", False))),
    }


def _is_valid_cidr(val: str) -> bool:
    try:
        ipaddress.ip_network(val, strict=False)
        return True
    except ValueError:
        return False


def _validation_error(field: str, value: Any, error: str) -> dict[str, Any]:
    return {
        "field": field,
        "parameter": field,
        "value": value,
        "error": error,
    }


def validate_module_config(
    raw_config: dict[str, Any],
    *,
    module_id: str | None = None,
    known_domains: Collection[str] | None = None,
    bound_udp_ports: set[int] | None = None,
    bound_tcp_ports: set[int] | None = None,
    own_wg_port: int | None = None,
    own_ovpn_binding: tuple[str, int] | None = None,
    host_routes: Sequence[ipaddress.IPv4Network] | None = None,
    cluster_wg: tuple[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Validate configure-module input against NS8 cluster, host route, and port constraints."""
    errors: list[dict[str, Any]] = []
    mid = module_id or get_module_id()
    cluster_cidr, cluster_port = cluster_wg if cluster_wg is not None else detect_cluster_wg()
    cluster_default_net = ipaddress.ip_network(DEFAULT_CLUSTER_WG_CIDR, strict=False)
    cluster_actual_net = ipaddress.ip_network(cluster_cidr, strict=False)

    # 1. Endpoint host
    endpoint_host = str(raw_config.get("endpoint_host") or "").strip()
    if not is_valid_hostname_or_ip(endpoint_host):
        errors.append(_validation_error("endpoint_host", endpoint_host, "invalid_endpoint_host"))

    # 2. WireGuard UDP port
    raw_port = raw_config.get("wg_port", DEFAULT_WG_PORT)
    try:
        wg_port = int(raw_port)
    except (TypeError, ValueError):
        wg_port = -1

    used_udp = bound_udp_ports if bound_udp_ports is not None else get_bound_udp_ports()
    if not (1 <= wg_port <= 65535):
        errors.append(_validation_error("wg_port", raw_port, "invalid_port"))
    elif wg_port in (DEFAULT_CLUSTER_WG_PORT, cluster_port):
        errors.append(_validation_error("wg_port", wg_port, "port_reserved_cluster_vpn"))
    else:
        active_own = own_wg_port if own_wg_port is not None else get_own_active_wg_port(mid)
        if wg_port != active_own and wg_port in used_udp:
            errors.append(_validation_error("wg_port", wg_port, "port_already_in_use"))

    # 3. Tunnel mode
    tunnel_mode = str(raw_config.get("tunnel_mode") or "split").strip().lower()
    if tunnel_mode not in ("split", "full"):
        errors.append(_validation_error("tunnel_mode", tunnel_mode, "invalid_tunnel_mode"))

    # 4. Allowed CIDRs
    raw_allowed = raw_config.get("allowed_cidrs") or []
    if isinstance(raw_allowed, str):
        allowed_strs = [c.strip() for c in re.split(r"[,\n]+", raw_allowed) if c.strip()]
    else:
        allowed_strs = [str(c).strip() for c in raw_allowed if str(c).strip()]

    parsed_allowed: list[ipaddress.IPv4Network] = []
    if tunnel_mode == "split" and not allowed_strs:
        errors.append(_validation_error("allowed_cidrs", raw_allowed, "allowed_cidrs_required"))
    else:
        for item in allowed_strs:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                errors.append(_validation_error("allowed_cidrs", item, "invalid_allowed_cidr"))
                break
            if not isinstance(net, ipaddress.IPv4Network) or net.prefixlen == 0 or net.is_loopback or net.is_multicast:
                errors.append(_validation_error("allowed_cidrs", item, "invalid_allowed_cidr"))
                break
            if net.overlaps(cluster_default_net) or net.overlaps(cluster_actual_net):
                errors.append(_validation_error("allowed_cidrs", item, "allowed_cidr_overlaps_cluster_vpn"))
                break
            parsed_allowed.append(net)

    # 5. WireGuard transfer subnet
    routes = list(host_routes) if host_routes is not None else get_host_route_networks(mid)
    wg_net_str = str(raw_config.get("wg_network") or DEFAULT_WG_NETWORK).strip()
    wg_net: ipaddress.IPv4Network | None = None
    try:
        parsed_net = ipaddress.ip_network(wg_net_str, strict=True)
        if not isinstance(parsed_net, ipaddress.IPv4Network):
            errors.append(_validation_error("wg_network", wg_net_str, "invalid_cidr"))
        elif (
            not (16 <= parsed_net.prefixlen <= 30)
            or parsed_net.is_loopback
            or parsed_net.is_multicast
            or parsed_net.is_link_local
            or parsed_net.is_unspecified
        ):
            errors.append(_validation_error("wg_network", wg_net_str, "invalid_cidr"))
        else:
            wg_net = parsed_net
    except ValueError:
        errors.append(_validation_error("wg_network", wg_net_str, "invalid_cidr"))

    if wg_net is not None:
        if wg_net.overlaps(cluster_default_net) or wg_net.overlaps(cluster_actual_net):
            errors.append(_validation_error("wg_network", wg_net_str, "subnet_overlaps_cluster_vpn"))
        elif any(wg_net.overlaps(route_net) for route_net in routes):
            errors.append(_validation_error("wg_network", wg_net_str, "subnet_overlaps_host_route"))
        elif any(wg_net.overlaps(allowed_net) for allowed_net in parsed_allowed):
            errors.append(_validation_error("wg_network", wg_net_str, "subnet_overlaps_allowed_cidrs"))

    # 6. DNS servers
    raw_dns = raw_config.get("dns_servers") or []
    dns_strs = (
        [d.strip() for d in re.split(r"[,\n]+", raw_dns) if d.strip()]
        if isinstance(raw_dns, str)
        else [str(d).strip() for d in raw_dns if str(d).strip()]
    )
    for dns_ip in dns_strs:
        try:
            ip_obj = ipaddress.ip_address(dns_ip)
            if (
                not isinstance(ip_obj, ipaddress.IPv4Address)
                or ip_obj.is_loopback
                or ip_obj.is_unspecified
                or ip_obj.is_multicast
                or ip_obj in cluster_default_net
                or ip_obj in cluster_actual_net
            ):
                errors.append(_validation_error("dns_servers", dns_ip, "invalid_dns_server"))
                break
        except ValueError:
            errors.append(_validation_error("dns_servers", dns_ip, "invalid_dns_server"))
            break

    # 7. Numeric bounds
    try:
        mtu = int(raw_config.get("wg_mtu", DEFAULT_WG_MTU))
        if not (1280 <= mtu <= 1500):
            errors.append(_validation_error("wg_mtu", mtu, "invalid_mtu"))
    except (TypeError, ValueError):
        errors.append(_validation_error("wg_mtu", raw_config.get("wg_mtu"), "invalid_mtu"))

    try:
        keepalive = int(raw_config.get("persistent_keepalive", DEFAULT_PERSISTENT_KEEPALIVE))
        if not (0 <= keepalive <= 300):
            errors.append(_validation_error("persistent_keepalive", keepalive, "invalid_keepalive"))
    except (TypeError, ValueError):
        errors.append(
            _validation_error("persistent_keepalive", raw_config.get("persistent_keepalive"), "invalid_keepalive")
        )

    try:
        max_dev = int(raw_config.get("max_devices_per_user", DEFAULT_MAX_DEVICES_PER_USER))
        if not (1 <= max_dev <= 50):
            errors.append(_validation_error("max_devices_per_user", max_dev, "invalid_max_devices"))
    except (TypeError, ValueError):
        errors.append(
            _validation_error("max_devices_per_user", raw_config.get("max_devices_per_user"), "invalid_max_devices")
        )

    try:
        sync_int = int(raw_config.get("sync_interval_minutes", DEFAULT_SYNC_INTERVAL_MINUTES))
        if not (1 <= sync_int <= 1440):
            errors.append(_validation_error("sync_interval_minutes", sync_int, "invalid_sync_interval"))
    except (TypeError, ValueError):
        errors.append(
            _validation_error("sync_interval_minutes", raw_config.get("sync_interval_minutes"), "invalid_sync_interval")
        )

    # 8. User domain existence
    user_domain = str(raw_config.get("user_domain") or "").strip()
    if user_domain and known_domains is not None and user_domain not in known_domains:
        errors.append(_validation_error("user_domain", user_domain, "unknown_user_domain"))

    # 9. Portal & TOTP mode
    portal_enabled = bool(raw_config.get("portal_enabled", False))
    portal_domain = str(raw_config.get("portal_domain") or "").strip()
    if portal_enabled and not is_valid_hostname_or_ip(portal_domain, require_fqdn=True):
        errors.append(_validation_error("portal_domain", portal_domain, "invalid_portal_domain"))

    totp_mode = str(raw_config.get("portal_totp_mode") or DEFAULT_PORTAL_TOTP_MODE).strip().lower()
    if totp_mode not in ("disabled", "optional", "required"):
        errors.append(_validation_error("portal_totp_mode", totp_mode, "invalid_totp_mode"))

    # 10. OpenVPN Fallback Server (Phase 3)
    ovpn_enabled = bool(raw_config.get("ovpn_enabled", False))
    if ovpn_enabled:
        ovpn_proto = str(raw_config.get("ovpn_proto") or DEFAULT_OVPN_PROTO).strip().lower()
        if ovpn_proto not in ("tcp", "udp"):
            errors.append(_validation_error("ovpn_proto", ovpn_proto, "invalid_ovpn_proto"))

        raw_ovpn_port = raw_config.get("ovpn_port", DEFAULT_OVPN_PORT)
        try:
            ovpn_port = int(raw_ovpn_port)
        except (TypeError, ValueError):
            ovpn_port = -1

        raw_ovpn_pub = raw_config.get("ovpn_public_port", raw_ovpn_port)
        try:
            ovpn_pub_port = int(raw_ovpn_pub)
        except (TypeError, ValueError):
            ovpn_pub_port = -1

        if not (1 <= ovpn_pub_port <= 65535):
            errors.append(_validation_error("ovpn_public_port", raw_ovpn_pub, "invalid_ovpn_public_port"))

        if not (1 <= ovpn_port <= 65535):
            errors.append(_validation_error("ovpn_port", raw_ovpn_port, "invalid_ovpn_port"))
        elif ovpn_proto == "udp" and ovpn_port in (DEFAULT_CLUSTER_WG_PORT, cluster_port):
            errors.append(_validation_error("ovpn_port", ovpn_port, "port_reserved_cluster_vpn"))
        elif ovpn_proto == "udp" and ovpn_port == wg_port:
            errors.append(_validation_error("ovpn_port", ovpn_port, "ovpn_port_conflicts_wireguard"))
        elif ovpn_proto in ("tcp", "udp"):
            active_ovpn = own_ovpn_binding if own_ovpn_binding is not None else get_own_active_ovpn_binding(mid)
            if active_ovpn != (ovpn_proto, ovpn_port):
                if ovpn_proto == "tcp":
                    used_tcp = bound_tcp_ports if bound_tcp_ports is not None else get_bound_tcp_ports()
                    if ovpn_port in used_tcp:
                        err_code = "port_in_use_by_traefik" if ovpn_port == 443 else "port_already_in_use"
                        errors.append(_validation_error("ovpn_port", ovpn_port, err_code))
                else:
                    if ovpn_port in used_udp:
                        errors.append(_validation_error("ovpn_port", ovpn_port, "port_already_in_use"))

        ovpn_net_str = str(raw_config.get("ovpn_network") or DEFAULT_OVPN_NETWORK).strip()
        ovpn_net: ipaddress.IPv4Network | None = None
        try:
            parsed_ovpn = ipaddress.ip_network(ovpn_net_str, strict=True)
            if not isinstance(parsed_ovpn, ipaddress.IPv4Network):
                errors.append(_validation_error("ovpn_network", ovpn_net_str, "invalid_ovpn_network"))
            elif (
                not (16 <= parsed_ovpn.prefixlen <= 30)
                or parsed_ovpn.is_loopback
                or parsed_ovpn.is_multicast
                or parsed_ovpn.is_link_local
                or parsed_ovpn.is_unspecified
            ):
                errors.append(_validation_error("ovpn_network", ovpn_net_str, "invalid_ovpn_network"))
            else:
                ovpn_net = parsed_ovpn
        except ValueError:
            errors.append(_validation_error("ovpn_network", ovpn_net_str, "invalid_ovpn_network"))

        if ovpn_net is not None:
            if ovpn_net.overlaps(cluster_default_net) or ovpn_net.overlaps(cluster_actual_net):
                errors.append(_validation_error("ovpn_network", ovpn_net_str, "subnet_overlaps_cluster_vpn"))
            elif wg_net is not None and ovpn_net.overlaps(wg_net):
                errors.append(_validation_error("ovpn_network", ovpn_net_str, "ovpn_subnet_overlaps_wg_network"))
            elif any(ovpn_net.overlaps(route_net) for route_net in routes):
                errors.append(_validation_error("ovpn_network", ovpn_net_str, "subnet_overlaps_host_route"))
            elif any(ovpn_net.overlaps(allowed_net) for allowed_net in parsed_allowed):
                errors.append(_validation_error("ovpn_network", ovpn_net_str, "subnet_overlaps_allowed_cidrs"))

    return errors


def validate_s2s_tunnel_input(
    raw_data: dict[str, Any],
    *,
    module_id: str | None = None,
    host_routes: Sequence[ipaddress.IPv4Network] | None = None,
    cluster_wg_cidr: str | None = None,
) -> list[dict[str, Any]]:
    """Validate Site-to-Site tunnel creation input against NS8 cluster wg0 and host routes."""
    errors: list[dict[str, Any]] = []
    mid = module_id or get_module_id()
    c_cidr = cluster_wg_cidr if cluster_wg_cidr is not None else detect_cluster_wg()[0]
    cluster_default_net = ipaddress.ip_network(DEFAULT_CLUSTER_WG_CIDR, strict=False)
    cluster_actual_net = ipaddress.ip_network(c_cidr, strict=False)
    routes = list(host_routes) if host_routes is not None else get_host_route_networks(mid)

    name = str(raw_data.get("name") or "").strip()
    if not name or len(name) > 64:
        errors.append(_validation_error("name", name, "invalid_s2s_name"))

    raw_cidrs = raw_data.get("remote_cidrs") or []
    cidr_strs = (
        [c.strip() for c in re.split(r"[,\n]+", raw_cidrs) if c.strip()]
        if isinstance(raw_cidrs, str)
        else [str(c).strip() for c in raw_cidrs if str(c).strip()]
    )
    if not cidr_strs:
        errors.append(_validation_error("remote_cidrs", raw_cidrs, "remote_cidrs_required"))
        return errors

    wg_net_env = os.environ.get("WG_NETWORK") or DEFAULT_WG_NETWORK
    ovpn_net_env = os.environ.get("OVPN_NETWORK") or DEFAULT_OVPN_NETWORK
    own_subnets: list[ipaddress.IPv4Network] = []
    for sub in (wg_net_env, ovpn_net_env):
        try:
            net_obj = ipaddress.ip_network(sub, strict=False)
            if isinstance(net_obj, ipaddress.IPv4Network):
                own_subnets.append(net_obj)
        except ValueError:
            pass

    for item in cidr_strs:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            errors.append(_validation_error("remote_cidrs", item, "invalid_remote_cidr"))
            break
        if (
            not isinstance(net, ipaddress.IPv4Network)
            or net.prefixlen == 0
            or net.is_loopback
            or net.is_multicast
            or net.is_link_local
        ):
            errors.append(_validation_error("remote_cidrs", item, "invalid_remote_cidr"))
            break
        if net.overlaps(cluster_default_net) or net.overlaps(cluster_actual_net):
            errors.append(_validation_error("remote_cidrs", item, "remote_cidr_overlaps_cluster_vpn"))
            break
        if any(net.overlaps(own_net) for own_net in own_subnets):
            errors.append(_validation_error("remote_cidrs", item, "remote_cidr_overlaps_vpn_subnet"))
            break
        if any(net.overlaps(r_net) for r_net in routes):
            errors.append(_validation_error("remote_cidrs", item, "remote_cidr_overlaps_host_route"))
            break

    return errors


# ---------------------------------------------------------------------------
# NS8 Ldapproxy Integration & Group Discovery
# ---------------------------------------------------------------------------


def _get_ldapproxy(ldapproxy_instance: Any = None) -> Any:
    if ldapproxy_instance is not None:
        return ldapproxy_instance
    from agent.ldapproxy import Ldapproxy

    return Ldapproxy()


def derive_suggested_dns_search(domain_name: str, base_dn: str) -> str:
    """Derive a sensible DNS search domain from NS8 user domain name or base_dn."""
    name = (domain_name or "").strip().lower()
    if "." in name:
        return name

    dc_parts: list[str] = []
    for rdn in (base_dn or "").split(","):
        rdn_stripped = rdn.strip()
        if rdn_stripped.lower().startswith("dc="):
            dc_val = rdn_stripped[3:].strip().lower()
            if dc_val:
                dc_parts.append(dc_val)

    derived = ".".join(dc_parts)
    if derived and derived != "directory.nh":
        return derived
    return name


def build_ldap_config(
    user_domain: str,
    vpn_group: str,
    ldapproxy_instance: Any = None,
) -> dict[str, Any]:
    """Build the `state/secrets/ldap.json` payload from NS8 `Ldapproxy`."""
    domain = (user_domain or "").strip()
    group = (vpn_group or "").strip()

    if not domain:
        return {
            "configured": False,
            "domain": "",
            "host": "127.0.0.1",
            "port": 389,
            "schema": "ad",
            "base_dn": "",
            "bind_dn": "",
            "bind_password": "",
            "vpn_group": group,
            "hidden_users": [],
        }

    lp = _get_ldapproxy(ldapproxy_instance)
    dom_info = lp.get_domain(domain)

    return {
        "configured": True,
        "domain": domain,
        "host": str(dom_info.get("host") or "127.0.0.1"),
        "port": int(dom_info.get("port") or 389),
        "schema": str(dom_info.get("schema") or "ad"),
        "base_dn": str(dom_info.get("base_dn") or ""),
        "bind_dn": str(dom_info.get("bind_dn") or ""),
        "bind_password": str(dom_info.get("bind_password") or ""),
        "vpn_group": group,
        "hidden_users": [str(u) for u in (dom_info.get("hidden_users") or [])],
    }


def write_ldap_secret(
    user_domain: str,
    vpn_group: str,
    *,
    state_dir: Path | None = None,
    ldapproxy_instance: Any = None,
) -> dict[str, Any]:
    """Query `Ldapproxy` and write `state/secrets/ldap.json` with 0600 permissions."""
    sdir = state_dir or get_state_dir()
    payload = build_ldap_config(user_domain, vpn_group, ldapproxy_instance=ldapproxy_instance)
    atomic_write_json(sdir / "secrets" / "ldap.json", payload, mode=0o600)
    return payload


def list_user_domains_info(ldapproxy_instance: Any = None) -> list[dict[str, str]]:
    """Return all configured NS8 user domains with metadata and DNS search suggestion."""
    lp = _get_ldapproxy(ldapproxy_instance)
    names = sorted(lp.get_domains_list() or [])
    domains: list[dict[str, str]] = []
    for name in names:
        info = lp.get_domain(name) or {}
        base_dn = str(info.get("base_dn") or "")
        if "location" in info and info["location"]:
            location = str(info["location"])
        elif "is_internal" in info:
            location = "internal" if info["is_internal"] else "external"
        else:
            location = "internal"
        domains.append(
            {
                "name": str(name),
                "schema": str(info.get("schema") or "ad"),
                "location": location,
                "base_dn": base_dn,
                "suggested_dns_search": derive_suggested_dns_search(str(name), base_dn),
            }
        )
    return domains


def query_domain_groups(
    user_domain: str,
    *,
    ldapproxy_instance: Any = None,
    module_id: str | None = None,
) -> list[dict[str, str]]:
    """Query groups in `user_domain` via ldap3, falling back to ldapsearch or container python."""
    domain = (user_domain or "").strip()
    if not domain:
        return []

    lp = _get_ldapproxy(ldapproxy_instance)
    domains_list = lp.get_domains_list() or []
    if domain not in domains_list:
        return []

    dom_info = lp.get_domain(domain) or {}
    host = str(dom_info.get("host") or "127.0.0.1")
    port = int(dom_info.get("port") or 389)
    schema = str(dom_info.get("schema") or "ad").lower()
    base_dn = str(dom_info.get("base_dn") or "")
    bind_dn = str(dom_info.get("bind_dn") or "")
    bind_password = str(dom_info.get("bind_password") or "")

    if not base_dn:
        return []

    groups = _query_groups_via_ldap3(host, port, schema, base_dn, bind_dn, bind_password)
    if groups is not None:
        return groups

    groups = _query_groups_via_ldapsearch(host, port, schema, base_dn, bind_dn, bind_password)
    if groups is not None:
        return groups

    mid = module_id or get_module_id()
    groups = _query_groups_via_container(mid, host, port, schema, base_dn, bind_dn, bind_password)
    if groups is not None:
        return groups

    return []


def _query_groups_via_ldap3(
    host: str,
    port: int,
    schema: str,
    base_dn: str,
    bind_dn: str,
    bind_password: str,
) -> list[dict[str, str]] | None:
    try:
        import ldap3  # type: ignore[import-not-found]
    except ImportError:
        return None

    search_filter = (
        "(objectClass=group)"
        if schema == "ad"
        else "(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
    )
    attrs = ["sAMAccountName", "cn", "description"] if schema == "ad" else ["cn", "description"]

    try:
        server = ldap3.Server(host, port=port, use_ssl=False, get_info=ldap3.NONE, connect_timeout=5)
        conn_kwargs: dict[str, Any] = {
            "auto_bind": True,
            "receive_timeout": 10,
            "read_only": True,
        }
        if bind_dn:
            conn_kwargs["user"] = bind_dn
            conn_kwargs["password"] = bind_password
        conn = ldap3.Connection(server, **conn_kwargs)
        try:
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attrs,
            )
            results: list[dict[str, str]] = []
            for entry in conn.entries:
                dn_str = str(entry.entry_dn)
                raw_attrs = entry.entry_attributes_as_dict
                name = ""
                if schema == "ad" and raw_attrs.get("sAMAccountName"):
                    name = str(raw_attrs["sAMAccountName"][0]).strip()
                if not name and raw_attrs.get("cn"):
                    name = str(raw_attrs["cn"][0]).strip()
                if not name:
                    continue
                desc = ""
                if raw_attrs.get("description"):
                    desc = str(raw_attrs["description"][0]).strip()
                results.append({"name": name, "dn": dn_str, "description": desc})
            return sorted(results, key=lambda g: g["name"].lower())
        finally:
            conn.unbind()
    except Exception:
        return []


def parse_ldif_groups(ldif_text: str, schema: str) -> list[dict[str, str]]:
    """Parse group entries from `ldapsearch -LLL -o ldif-wrap=no` output."""
    entries: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}

    for line in ldif_text.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("#"):
            continue
        if "::" in line:
            key, _, b64_val = line.partition("::")
            try:
                val = base64.b64decode(b64_val.strip()).decode("utf-8", errors="replace")
            except ValueError:
                val = b64_val.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            val = val.strip()
        else:
            continue
        current.setdefault(key.strip().lower(), []).append(val)

    if current:
        entries.append(current)

    groups: list[dict[str, str]] = []
    for ent in entries:
        dn_list = ent.get("dn")
        if not dn_list:
            continue
        name = ""
        if schema == "ad" and ent.get("samaccountname"):
            name = ent["samaccountname"][0].strip()
        if not name and ent.get("cn"):
            name = ent["cn"][0].strip()
        if not name:
            continue
        desc = ent["description"][0].strip() if ent.get("description") else ""
        groups.append({"name": name, "dn": dn_list[0], "description": desc})

    return sorted(groups, key=lambda g: g["name"].lower())


def _query_groups_via_ldapsearch(
    host: str,
    port: int,
    schema: str,
    base_dn: str,
    bind_dn: str,
    bind_password: str,
) -> list[dict[str, str]] | None:
    if shutil.which("ldapsearch") is None:
        return None

    search_filter = (
        "(objectClass=group)"
        if schema == "ad"
        else "(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
    )
    attrs = ["sAMAccountName", "cn", "description"] if schema == "ad" else ["cn", "description"]

    pw_file: Path | None = None
    try:
        cmd = [
            "ldapsearch",
            "-LLL",
            "-o",
            "ldif-wrap=no",
            "-o",
            "nettimeout=5",
            "-x",
            "-H",
            f"ldap://{host}:{port}",
            "-b",
            base_dn,
        ]
        if bind_dn:
            fd, tmp_pw = tempfile.mkstemp(prefix=".ldappw.")
            pw_file = Path(tmp_pw)
            os.chmod(pw_file, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(bind_password)
            cmd.extend(["-D", bind_dn, "-y", str(pw_file)])

        cmd.append(search_filter)
        cmd.extend(attrs)
        res = run_cmd(cmd, timeout=15.0)
        if res.returncode != 0:
            return []
        return parse_ldif_groups(res.stdout, schema=schema)
    finally:
        if pw_file is not None:
            pw_file.unlink(missing_ok=True)


def _query_groups_via_container(
    module_id: str,
    host: str,
    port: int,
    schema: str,
    base_dn: str,
    bind_dn: str,
    bind_password: str,
) -> list[dict[str, str]] | None:
    if shutil.which("podman") is None:
        return None

    helper_code = (
        "import json, sys, ldap3\n"
        "cfg = json.load(sys.stdin)\n"
        "flt = '(objectClass=group)' if cfg['schema'] == 'ad' else "
        "'(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))'\n"
        "attrs = ['sAMAccountName', 'cn', 'description'] if cfg['schema'] == 'ad' else ['cn', 'description']\n"
        "srv = ldap3.Server(cfg['host'], port=cfg['port'], get_info=ldap3.NONE, connect_timeout=5)\n"
        "kw = {'auto_bind': True, 'receive_timeout': 10, 'read_only': True}\n"
        "if cfg['bind_dn']:\n"
        "    kw['user'] = cfg['bind_dn']; kw['password'] = cfg['bind_password']\n"
        "conn = ldap3.Connection(srv, **kw)\n"
        "conn.search(cfg['base_dn'], flt, attributes=attrs)\n"
        "out = []\n"
        "for e in conn.entries:\n"
        "    d = e.entry_attributes_as_dict\n"
        "    n = (d.get('sAMAccountName') or d.get('cn') or [''])[0]\n"
        "    if n:\n"
        "        out.append({'name': str(n), 'dn': str(e.entry_dn), 'description': str((d.get('description') or [''])[0])})\n"
        "conn.unbind()\n"
        "out.sort(key=lambda x: x['name'].lower())\n"
        "json.dump(out, sys.stdout)\n"
    )
    payload = json.dumps(
        {
            "host": host,
            "port": port,
            "schema": schema,
            "base_dn": base_dn,
            "bind_dn": bind_dn,
            "bind_password": bind_password,
        }
    )
    res = run_cmd(["podman", "exec", "-i", module_id, "python3", "-c", helper_code], input_text=payload, timeout=15.0)
    if res.returncode != 0 or not res.stdout.strip():
        return None
    try:
        return json.loads(res.stdout)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Host Firewall (firewalld + NS8 node:fwadm) & Traefik Route Helpers
# ---------------------------------------------------------------------------


def configure_host_firewall(
    agent_mod: Any,
    module_id: str,
    wg_port: int,
    *,
    ovpn_enabled: bool = False,
    ovpn_port: int = DEFAULT_OVPN_PORT,
    ovpn_proto: str = DEFAULT_OVPN_PROTO,
    cluster_wg_cidr: str = DEFAULT_CLUSTER_WG_CIDR,
) -> None:
    """Open WireGuard (and optional OpenVPN) public port(s) and configure isolated firewalld zone + policy."""
    ports = [f"{int(wg_port)}/udp"]
    norm_proto = (ovpn_proto or DEFAULT_OVPN_PROTO).strip().lower()
    if ovpn_enabled and norm_proto in ("tcp", "udp"):
        ovpn_entry = f"{int(ovpn_port)}/{norm_proto}"
        if ovpn_entry not in ports:
            ports.append(ovpn_entry)

    agent_mod.add_public_service(module_id, ports, replace_ports=True)

    if shutil.which("firewall-cmd") is None:
        return

    zone = get_firewalld_zone_name(module_id)
    policy = get_firewalld_policy_name(module_id)
    wg_iface = get_wg_interface_name(module_id)
    tun_iface = get_ovpn_interface_name(module_id)

    zones_res = run_cmd(["firewall-cmd", "--permanent", "--get-zones"])
    existing_zones = set(zones_res.stdout.split()) if zones_res.returncode == 0 else set()
    if zone not in existing_zones:
        run_cmd(["firewall-cmd", "--permanent", f"--new-zone={zone}"])

    # NEVER place wg-<MODULE_ID> or tun-<MODULE_ID> into NS8's `trusted` zone!
    for iface in (wg_iface, tun_iface):
        run_cmd(["firewall-cmd", "--permanent", "--zone=trusted", f"--remove-interface={iface}"])

    run_cmd(["firewall-cmd", "--permanent", f"--zone={zone}", "--set-target=DEFAULT"])
    for iface in (wg_iface, tun_iface):
        run_cmd(["firewall-cmd", "--permanent", f"--zone={zone}", f"--add-interface={iface}"])
    run_cmd(["firewall-cmd", "--permanent", f"--zone={zone}", "--add-service=dns"])

    for drop_cidr in {DEFAULT_CLUSTER_WG_CIDR, cluster_wg_cidr}:
        run_cmd(
            [
                "firewall-cmd",
                "--permanent",
                f"--zone={zone}",
                f'--add-rich-rule=rule family="ipv4" destination address="{drop_cidr}" drop',
            ]
        )
    run_cmd(
        [
            "firewall-cmd",
            "--permanent",
            f"--zone={zone}",
            '--add-rich-rule=rule port port="6379" protocol="tcp" drop',
        ]
    )

    pol_res = run_cmd(["firewall-cmd", "--permanent", "--get-policies"])
    existing_policies = set(pol_res.stdout.split()) if pol_res.returncode == 0 else set()
    if policy not in existing_policies:
        run_cmd(["firewall-cmd", "--permanent", f"--new-policy={policy}"])

    run_cmd(["firewall-cmd", "--permanent", f"--policy={policy}", f"--add-ingress-zone={zone}"])
    run_cmd(["firewall-cmd", "--permanent", f"--policy={policy}", "--add-egress-zone=ANY"])
    run_cmd(["firewall-cmd", "--permanent", f"--policy={policy}", "--set-target=ACCEPT"])
    for drop_cidr in {DEFAULT_CLUSTER_WG_CIDR, cluster_wg_cidr}:
        run_cmd(
            [
                "firewall-cmd",
                "--permanent",
                f"--policy={policy}",
                f'--add-rich-rule=rule family="ipv4" destination address="{drop_cidr}" drop',
            ]
        )

    run_cmd(["firewall-cmd", "--reload"])


def cleanup_host_firewall(agent_mod: Any, module_id: str) -> None:
    """Remove public service ports and clean up dedicated firewalld zone, policy, wg/tun links, and nft table."""
    try:
        agent_mod.remove_public_service(module_id)
    except Exception:
        pass

    wg_iface = get_wg_interface_name(module_id)
    tun_iface = get_ovpn_interface_name(module_id)
    nft_tbl = get_nft_table_name(module_id)
    zone = get_firewalld_zone_name(module_id)
    policy = get_firewalld_policy_name(module_id)

    if shutil.which("firewall-cmd") is not None:
        run_cmd(["firewall-cmd", "--permanent", f"--delete-policy={policy}"])
        run_cmd(["firewall-cmd", "--permanent", f"--delete-zone={zone}"])
        run_cmd(["firewall-cmd", "--reload"])

    run_cmd(["ip", "link", "delete", "dev", wg_iface])
    run_cmd(["ip", "link", "delete", "dev", tun_iface])
    run_cmd(["nft", "delete", "table", "inet", nft_tbl])


def configure_traefik_route(
    agent_mod: Any,
    *,
    module_id: str,
    tcp_port: str | int,
    portal_enabled: bool,
    portal_domain: str,
    lets_encrypt: bool = False,
    http2https: bool = True,
    previously_enabled: bool = False,
) -> None:
    """Register or delete the Traefik HTTP route pointing strictly to http://127.0.0.1:${TCP_PORT}."""
    if not portal_enabled and not previously_enabled:
        return

    traefik_id = agent_mod.resolve_agent_id("traefik@node")
    if not traefik_id:
        return

    if portal_enabled and portal_domain:
        response = agent_mod.tasks.run(
            agent_id=traefik_id,
            action="set-route",
            data={
                "instance": module_id,
                "url": f"http://127.0.0.1:{int(tcp_port)}",
                "host": portal_domain,
                "lets_encrypt": bool(lets_encrypt),
                "http2https": bool(http2https),
            },
        )
        agent_mod.assert_exp(response["exit_code"] == 0, "Failed to configure Traefik route")
    else:
        agent_mod.tasks.run(
            agent_id=traefik_id,
            action="delete-route",
            data={"instance": module_id},
        )


# ---------------------------------------------------------------------------
# Unix Domain Socket Client to vpn-controller (state/run/admin.sock)
# ---------------------------------------------------------------------------


class AdminApiError(RuntimeError):
    """Raised when vpn-controller returns a non-2xx response or cannot be reached."""

    def __init__(self, message: str, status_code: int = 500, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTP/1.1 connection over a local AF_UNIX socket."""

    def __init__(self, socket_path: str | Path, timeout: float = 15.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = str(socket_path)

    def connect(self) -> None:
        af_unix = getattr(socket, "AF_UNIX", None)
        if af_unix is None:
            raise OSError("AF_UNIX sockets are not supported on this platform")
        sock = socket.socket(af_unix, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


def _try_recover_controller_socket(sock_file: Path) -> bool:
    """Attempt to start `${MODULE_ID}.service` on Linux if `admin.sock` is not listening yet."""
    if getattr(socket, "AF_UNIX", None) is None or shutil.which("systemctl") is None:
        return False
    # Only auto-start when targeting the default module admin socket path
    if sock_file != get_admin_socket_path():
        return False
    mid = get_module_id()
    service_name = f"{mid}.service"
    unit_file = Path(f"/etc/systemd/system/{service_name}")
    if not unit_file.is_file():
        return False
    run_cmd(["systemctl", "start", service_name], check=False, timeout=25.0)
    return wait_for_admin_socket(socket_path=sock_file, timeout=15.0, interval=0.4)


def _read_service_journal_tail(lines: int = 12) -> str:
    if shutil.which("journalctl") is None:
        return ""
    mid = get_module_id()
    res = run_cmd(
        ["journalctl", "-u", f"{mid}.service", "-n", str(lines), "--no-pager", "-o", "cat"],
        check=False,
        timeout=5.0,
    )
    return res.stdout.strip() if res.returncode == 0 and res.stdout.strip() else ""


def admin_api_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    socket_path: Path | None = None,
    timeout: float = 15.0,
    auto_recover: bool = True,
) -> Any:
    """Perform a JSON HTTP request over `state/run/admin.sock` and return parsed JSON."""
    sock_file = socket_path or get_admin_socket_path()
    headers = {"Accept": "application/json"}
    body: bytes | None = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    for attempt in range(2):
        conn = UnixSocketHTTPConnection(sock_file, timeout=timeout)
        try:
            conn.request(method.upper(), path, body=body, headers=headers)
            resp = conn.getresponse()
            raw_bytes = resp.read()
            status = resp.status
            break
        except OSError as exc:
            if attempt == 0 and auto_recover and _try_recover_controller_socket(sock_file):
                continue
            journal_tail = _read_service_journal_tail() if auto_recover else ""
            suffix = f" | Service logs: {journal_tail}" if journal_tail else ""
            raise AdminApiError(
                f"Cannot connect to vpn-controller socket {sock_file}: {exc}{suffix}",
                status_code=503,
            ) from exc
        finally:
            conn.close()

    parsed: Any = {}
    if raw_bytes:
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except ValueError:
            parsed = {"detail": raw_bytes.decode("utf-8", errors="replace")}

    if not (200 <= status < 300):
        detail = parsed.get("detail") if isinstance(parsed, dict) else str(parsed)
        raise AdminApiError(f"vpn-controller returned HTTP {status}: {detail}", status_code=status, payload=parsed)

    return parsed


def wait_for_admin_socket(
    *,
    socket_path: Path | None = None,
    timeout: float = 30.0,
    interval: float = 0.5,
) -> bool:
    """Wait until vpn-controller responds 200 OK on GET /api/v1/admin/health."""
    sock_file = socket_path or get_admin_socket_path()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = admin_api_request(
                "GET",
                "/api/v1/admin/health",
                socket_path=sock_file,
                timeout=3.0,
                auto_recover=False,
            )
            if isinstance(resp, dict) and resp.get("status") == "ok":
                return True
        except AdminApiError:
            pass
        time.sleep(interval)
    return False


# ---------------------------------------------------------------------------
# Fallback Configuration Builder (before service starts)
# ---------------------------------------------------------------------------


def _env_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key)
    if val is None or val == "":
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_csv(key: str) -> list[str]:
    val = os.environ.get(key, "").strip()
    if not val:
        return []
    return [item.strip() for item in val.split(",") if item.strip()]


def build_fallback_configuration(module_id: str | None = None) -> dict[str, Any]:
    """Return full get-configuration schema from environment variables if admin.sock is offline."""
    mid = module_id or get_module_id()
    ovpn_port = int(os.environ.get("OVPN_PORT") or DEFAULT_OVPN_PORT)
    ovpn_pub_port = int(os.environ.get("OVPN_PUBLIC_PORT") or ovpn_port)
    return {
        "configured": _env_bool("CONFIGURED", False),
        "endpoint_host": os.environ.get("ENDPOINT_HOST", ""),
        "wg_port": int(os.environ.get("WG_PORT") or DEFAULT_WG_PORT),
        "wg_network": os.environ.get("WG_NETWORK") or DEFAULT_WG_NETWORK,
        "tunnel_mode": os.environ.get("TUNNEL_MODE") or "split",
        "allowed_cidrs": _env_csv("ALLOWED_CIDRS"),
        "dns_servers": _env_csv("DNS_SERVERS"),
        "dns_search_domain": os.environ.get("DNS_SEARCH_DOMAIN", ""),
        "wg_mtu": int(os.environ.get("WG_MTU") or DEFAULT_WG_MTU),
        "persistent_keepalive": int(os.environ.get("PERSISTENT_KEEPALIVE") or DEFAULT_PERSISTENT_KEEPALIVE),
        "nat_enabled": _env_bool("NAT_ENABLED", True),
        "user_domain": os.environ.get("USER_DOMAIN", ""),
        "vpn_group": os.environ.get("VPN_GROUP", ""),
        "max_devices_per_user": int(os.environ.get("MAX_DEVICES_PER_USER") or DEFAULT_MAX_DEVICES_PER_USER),
        "sync_interval_minutes": int(os.environ.get("SYNC_INTERVAL_MINUTES") or DEFAULT_SYNC_INTERVAL_MINUTES),
        "portal_enabled": _env_bool("PORTAL_ENABLED", False),
        "portal_domain": os.environ.get("PORTAL_DOMAIN", ""),
        "portal_lets_encrypt": _env_bool("PORTAL_LETS_ENCRYPT", False),
        "portal_http2https": _env_bool("PORTAL_HTTP2HTTPS", True),
        "portal_totp_mode": (os.environ.get("PORTAL_TOTP_MODE") or DEFAULT_PORTAL_TOTP_MODE).strip().lower(),
        "ovpn_enabled": _env_bool("OVPN_ENABLED", False),
        "ovpn_proto": (os.environ.get("OVPN_PROTO") or DEFAULT_OVPN_PROTO).strip().lower(),
        "ovpn_port": ovpn_port,
        "ovpn_public_port": ovpn_pub_port,
        "ovpn_network": os.environ.get("OVPN_NETWORK") or DEFAULT_OVPN_NETWORK,
        "ovpn_totp_required": _env_bool("OVPN_TOTP_REQUIRED", False),
        "server_public_key": "",
        "interface_name": get_wg_interface_name(mid),
        "ovpn_interface_name": get_ovpn_interface_name(mid),
        "summary": {
            "authorized_users": 0,
            "total_peers": 0,
            "active_peers": 0,
            "online_peers": 0,
            "online_ovpn_clients": 0,
            "s2s_tunnels": 0,
            "active_s2s_tunnels": 0,
            "last_synced_at": None,
            "last_sync_status": "never",
            "last_sync_error": None,
        },
    }
