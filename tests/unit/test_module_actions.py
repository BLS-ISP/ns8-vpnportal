"""Comprehensive unit tests for NS8 rootful module helpers, actions, events, and JSON schemas (Phases 1-3)."""

from __future__ import annotations

import base64
import io
import ipaddress
import json
import runpy
import sqlite3
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

try:
    import jsonschema as _jsonschema
except ImportError:  # pragma: no cover
    _jsonschema = None


def validate_json_schema(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Validate `instance` against a JSON Schema Draft-07 dict (uses jsonschema if installed)."""
    if _jsonschema is not None:
        _jsonschema.validate(instance=instance, schema=schema)
        return

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed_types = expected_type if isinstance(expected_type, list) else [expected_type]
        type_map = {
            "object": lambda v: isinstance(v, dict),
            "array": lambda v: isinstance(v, list),
            "string": lambda v: isinstance(v, str),
            "boolean": lambda v: isinstance(v, bool),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "null": lambda v: v is None,
        }
        assert any(type_map[t](instance) for t in allowed_types), (
            f"Schema type mismatch at {path}: expected {allowed_types}, got {type(instance).__name__}"
        )

    if "enum" in schema:
        assert instance in schema["enum"], f"Value {instance!r} at {path} not in enum {schema['enum']}"

    if isinstance(instance, str):
        if "minLength" in schema:
            assert len(instance) >= schema["minLength"], f"{path} shorter than minLength"
        if "maxLength" in schema:
            assert len(instance) <= schema["maxLength"], f"{path} longer than maxLength"

    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema:
            assert instance >= schema["minimum"], f"{path}={instance} < minimum {schema['minimum']}"
        if "maximum" in schema:
            assert instance <= schema["maximum"], f"{path}={instance} > maximum {schema['maximum']}"

    if isinstance(instance, dict):
        for req_key in schema.get("required", []):
            assert req_key in instance, f"Missing required key {req_key!r} at {path}"
        props = schema.get("properties", {})
        for key, sub_schema in props.items():
            if key in instance:
                validate_json_schema(instance[key], sub_schema, f"{path}.{key}")

    if isinstance(instance, list) and "items" in schema:
        item_schema = schema["items"]
        if isinstance(item_schema, dict):
            for idx, elem in enumerate(instance):
                validate_json_schema(elem, item_schema, f"{path}[{idx}]")


REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGEROOOT = REPO_ROOT / "imageroot"
PYPKG = IMAGEROOOT / "pypkg"

if str(PYPKG) not in sys.path:
    sys.path.insert(0, str(PYPKG))

import vpn_helpers  # noqa: E402


class MockAgentTasks:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, agent_id: str, action: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append({"agent_id": agent_id, "action": action, "data": data})
        return {"exit_code": 0, "output": {}}


class MockLdapproxy:
    def __init__(self, domains: dict[str, dict[str, Any]] | None = None) -> None:
        self._domains = domains if domains is not None else {
            "ad.firma.de": {
                "name": "ad.firma.de",
                "host": "127.0.0.1",
                "port": 20011,
                "schema": "ad",
                "base_dn": "DC=ad,DC=firma,DC=de",
                "bind_dn": "CN=ldapservice,CN=Users,DC=ad,DC=firma,DC=de",
                "bind_password": "s3cr3t-ad-password",
                "location": "internal",
                "hidden_users": ["administrator", "krbtgt", "guest"],
            },
            "ldap.local": {
                "name": "ldap.local",
                "host": "127.0.0.1",
                "port": 20012,
                "schema": "rfc2307",
                "base_dn": "dc=directory,dc=nh",
                "bind_dn": "cn=ldapservice,dc=directory,dc=nh",
                "bind_password": "s3cr3t-ldap-password",
                "is_internal": True,
                "hidden_users": [],
            },
        }

    def get_domains_list(self) -> list[str]:
        return list(self._domains.keys())

    def get_domain(self, name: str) -> dict[str, Any]:
        return dict(self._domains[name])


class MockAgentState:
    """Simulated NS8 `agent` + `agent.ldapproxy` Python environment."""

    def __init__(self, domains: dict[str, dict[str, Any]] | None = None) -> None:
        self.env_updates: list[tuple[str, str]] = []
        self.env_store: dict[str, str] = {}
        self.dump_env_count: int = 0
        self.dump_env_snapshots: list[dict[str, str]] = []
        self.bound_domains: list[list[str]] = []
        self.public_services: list[tuple[str, list[str], bool]] = []
        self.removed_public_services: list[str] = []
        self.statuses: list[str] = []
        self.route_in_use_domains: set[str] = set()
        self.traefik_agent_id: str = "module/traefik1"
        self.tasks = MockAgentTasks()
        self.ldapproxy_data = domains

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        state = self

        agent_mod = types.ModuleType("agent")
        agent_mod.tasks = state.tasks  # type: ignore[attr-defined]

        def set_env(key: str, val: str) -> None:
            state.env_updates.append((key, val))
            state.env_store[key] = val

        def dump_env() -> None:
            state.dump_env_count += 1
            state.dump_env_snapshots.append(dict(state.env_store))

        def bind_user_domains(domains: list[str]) -> None:
            state.bound_domains.append(list(domains))

        def add_public_service(service_name: str, ports: list[str], replace_ports: bool = False) -> None:
            state.public_services.append((service_name, list(ports), replace_ports))

        def remove_public_service(service_name: str) -> None:
            state.removed_public_services.append(service_name)

        def set_status(status: str) -> None:
            state.statuses.append(status)

        def http_route_in_use(domain: str) -> bool:
            return domain.lower() in state.route_in_use_domains

        def resolve_agent_id(role: str) -> str:
            if role == "traefik@node":
                return state.traefik_agent_id
            return ""

        def assert_exp(cond: bool, msg: str = "Assertion failed") -> None:
            if not cond:
                raise AssertionError(msg)

        agent_mod.set_env = set_env  # type: ignore[attr-defined]
        agent_mod.dump_env = dump_env  # type: ignore[attr-defined]
        agent_mod.bind_user_domains = bind_user_domains  # type: ignore[attr-defined]
        agent_mod.add_public_service = add_public_service  # type: ignore[attr-defined]
        agent_mod.remove_public_service = remove_public_service  # type: ignore[attr-defined]
        agent_mod.set_status = set_status  # type: ignore[attr-defined]
        agent_mod.http_route_in_use = http_route_in_use  # type: ignore[attr-defined]
        agent_mod.resolve_agent_id = resolve_agent_id  # type: ignore[attr-defined]
        agent_mod.assert_exp = assert_exp  # type: ignore[attr-defined]

        lp_mod = types.ModuleType("agent.ldapproxy")
        lp_mod.Ldapproxy = lambda: MockLdapproxy(state.ldapproxy_data)  # type: ignore[attr-defined]
        agent_mod.ldapproxy = lp_mod  # type: ignore[attr-defined]

        monkeypatch.setitem(sys.modules, "agent", agent_mod)
        monkeypatch.setitem(sys.modules, "agent.ldapproxy", lp_mod)


def execute_action_script(
    rel_script: str,
    monkeypatch: pytest.MonkeyPatch,
    stdin_payload: dict[str, Any] | None = None,
) -> tuple[int, str, str]:
    """Run an imageroot Python script in-process and capture exit code, stdout, and stderr."""
    script_path = IMAGEROOOT / rel_script
    stdin_str = json.dumps(stdin_payload) if stdin_payload is not None else ""
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_str))
    monkeypatch.setattr(sys, "stdout", stdout_buf)
    monkeypatch.setattr(sys, "stderr", stderr_buf)

    exit_code = 0
    try:
        runpy.run_path(str(script_path), run_name="__main__")
    except SystemExit as exc:
        exit_code = int(exc.code) if isinstance(exc.code, int) else (0 if exc.code is None else 1)

    return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()


# ---------------------------------------------------------------------------
# 1. Port, Subnet, OpenVPN & Site-to-Site Collision Validation Tests
# ---------------------------------------------------------------------------


def test_port_collision_rejects_cluster_wg0_and_bound_udp() -> None:
    base_cfg = {
        "endpoint_host": "vpn.firma.de",
        "wg_port": 55820,
        "wg_network": "10.199.0.0/24",
        "tunnel_mode": "split",
        "allowed_cidrs": ["192.168.178.0/24"],
    }
    errs = vpn_helpers.validate_module_config(
        base_cfg,
        module_id="vpn1",
        bound_udp_ports={53, 55820},
        own_wg_port=None,
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(e["field"] == "wg_port" and e["error"] == "port_reserved_cluster_vpn" for e in errs)

    errs_custom = vpn_helpers.validate_module_config(
        {**base_cfg, "wg_port": 55900},
        module_id="vpn1",
        bound_udp_ports=set(),
        own_wg_port=None,
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55900),
    )
    assert any(e["field"] == "wg_port" and e["error"] == "port_reserved_cluster_vpn" for e in errs_custom)

    errs_used = vpn_helpers.validate_module_config(
        {**base_cfg, "wg_port": 51820},
        module_id="vpn1",
        bound_udp_ports={53, 51820},
        own_wg_port=None,
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(e["field"] == "wg_port" and e["error"] == "port_already_in_use" for e in errs_used)

    errs_own = vpn_helpers.validate_module_config(
        {**base_cfg, "wg_port": 51820},
        module_id="vpn1",
        bound_udp_ports={53, 51820},
        own_wg_port=51820,
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert errs_own == []


def test_subnet_collision_checks_cluster_routes_and_allowed_cidrs() -> None:
    host_routes = [ipaddress.ip_network("192.168.178.0/24"), ipaddress.ip_network("172.16.10.0/24")]
    base_cfg = {
        "endpoint_host": "vpn.firma.de",
        "wg_port": 51820,
        "wg_network": "10.5.4.0/24",
        "tunnel_mode": "split",
        "allowed_cidrs": ["192.168.178.0/24"],
    }

    errs_cluster = vpn_helpers.validate_module_config(
        base_cfg,
        module_id="vpn1",
        bound_udp_ports=set(),
        own_wg_port=None,
        host_routes=host_routes,
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(e["field"] == "wg_network" and e["error"] == "subnet_overlaps_cluster_vpn" for e in errs_cluster)

    errs_super = vpn_helpers.validate_module_config(
        {**base_cfg, "wg_network": "10.5.0.0/16"},
        module_id="vpn1",
        bound_udp_ports=set(),
        own_wg_port=None,
        host_routes=host_routes,
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(e["field"] == "wg_network" and e["error"] == "subnet_overlaps_cluster_vpn" for e in errs_super)

    errs_route = vpn_helpers.validate_module_config(
        {**base_cfg, "wg_network": "172.16.10.0/24"},
        module_id="vpn1",
        bound_udp_ports=set(),
        own_wg_port=None,
        host_routes=host_routes,
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(e["field"] == "wg_network" and e["error"] == "subnet_overlaps_host_route" for e in errs_route)

    errs_allowed_overlap = vpn_helpers.validate_module_config(
        {**base_cfg, "wg_network": "10.199.0.0/24", "allowed_cidrs": ["10.199.0.0/24"]},
        module_id="vpn1",
        bound_udp_ports=set(),
        own_wg_port=None,
        host_routes=host_routes,
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(
        e["field"] == "wg_network" and e["error"] == "subnet_overlaps_allowed_cidrs" for e in errs_allowed_overlap
    )

    errs_expose_cluster = vpn_helpers.validate_module_config(
        {**base_cfg, "wg_network": "10.199.0.0/24", "allowed_cidrs": ["10.5.4.0/24"]},
        module_id="vpn1",
        bound_udp_ports=set(),
        own_wg_port=None,
        host_routes=host_routes,
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(
        e["field"] == "allowed_cidrs" and e["error"] == "allowed_cidr_overlaps_cluster_vpn"
        for e in errs_expose_cluster
    )


def test_openvpn_and_totp_validation_rules() -> None:
    base_ovpn = {
        "endpoint_host": "vpn.firma.de",
        "wg_port": 51820,
        "wg_network": "10.199.0.0/24",
        "tunnel_mode": "split",
        "allowed_cidrs": ["192.168.178.0/24"],
        "portal_totp_mode": "required",
        "ovpn_enabled": True,
        "ovpn_proto": "tcp",
        "ovpn_port": 443,
        "ovpn_public_port": 443,
        "ovpn_network": "10.199.1.0/24",
        "ovpn_totp_required": True,
    }

    # 1. TCP 443 bound on host by ns8-traefik -> port_in_use_by_traefik
    errs_traefik = vpn_helpers.validate_module_config(
        base_ovpn,
        module_id="vpn1",
        bound_udp_ports=set(),
        bound_tcp_ports={80, 443},
        own_wg_port=None,
        own_ovpn_binding=None,
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(e["field"] == "ovpn_port" and e["error"] == "port_in_use_by_traefik" for e in errs_traefik)

    # 2. Local port 1194 with external WAN public port 443 succeeds cleanly!
    errs_remapped = vpn_helpers.validate_module_config(
        {**base_ovpn, "ovpn_port": 1194, "ovpn_public_port": 443},
        module_id="vpn1",
        bound_udp_ports=set(),
        bound_tcp_ports={80, 443},
        own_wg_port=None,
        own_ovpn_binding=None,
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert errs_remapped == []

    # 3. Re-saving when OpenVPN is already bound on tcp/1194 by our own instance succeeds
    errs_own_ovpn = vpn_helpers.validate_module_config(
        {**base_ovpn, "ovpn_port": 1194},
        module_id="vpn1",
        bound_udp_ports=set(),
        bound_tcp_ports={80, 443, 1194},
        own_wg_port=51820,
        own_ovpn_binding=("tcp", 1194),
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert errs_own_ovpn == []

    # 4. UDP OpenVPN colliding with wg_port or 55820 or wg_network
    errs_udp_wg = vpn_helpers.validate_module_config(
        {**base_ovpn, "ovpn_proto": "udp", "ovpn_port": 51820},
        module_id="vpn1",
        bound_udp_ports=set(),
        bound_tcp_ports=set(),
        own_wg_port=None,
        own_ovpn_binding=None,
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(e["field"] == "ovpn_port" and e["error"] == "ovpn_port_conflicts_wireguard" for e in errs_udp_wg)

    errs_ovpn_net = vpn_helpers.validate_module_config(
        {**base_ovpn, "ovpn_port": 1194, "ovpn_network": "10.199.0.0/24"},
        module_id="vpn1",
        bound_udp_ports=set(),
        bound_tcp_ports=set(),
        own_wg_port=None,
        own_ovpn_binding=None,
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(
        e["field"] == "ovpn_network" and e["error"] == "ovpn_subnet_overlaps_wg_network" for e in errs_ovpn_net
    )

    errs_totp = vpn_helpers.validate_module_config(
        {**base_ovpn, "ovpn_port": 1194, "portal_totp_mode": "invalid"},
        module_id="vpn1",
        bound_udp_ports=set(),
        bound_tcp_ports=set(),
        own_wg_port=None,
        own_ovpn_binding=None,
        host_routes=[],
        cluster_wg=("10.5.4.0/24", 55820),
    )
    assert any(e["field"] == "portal_totp_mode" and e["error"] == "invalid_totp_mode" for e in errs_totp)


def test_ss_and_ip_route_parsers_and_allocators() -> None:
    ss_sample = (
        "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n"
        "UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
        "UNCONN 0 0 [::]:55820 [::]:*\n"
    )
    ports = vpn_helpers.parse_ss_udp_ports(ss_sample)
    assert ports == {53, 51820, 55820}

    assert vpn_helpers.pick_free_wg_port(preferred=51820, bound_ports=ports) == 51821
    assert vpn_helpers.pick_free_wg_port(preferred=55820, bound_ports=set()) == 55821

    routes_json = json.dumps(
        [
            {"dst": "default", "gateway": "192.168.178.1", "dev": "eth0"},
            {"dst": "192.168.178.0/24", "dev": "eth0"},
            {"dst": "10.5.4.0/24", "dev": "wg0"},
            {"dst": "10.199.0.0/24", "dev": "wg-vpn1"},
            {"dst": "10.199.1.0/24", "dev": "tun-vpn1"},
            {"dst": "10.199.2.0/24", "dev": "eth1"},
        ]
    )
    nets = vpn_helpers.parse_ip_routes_json(routes_json, module_id="vpn1")
    # wg0, wg-vpn1, tun-vpn1, and default are ignored; eth0 and eth1 routes are returned
    assert nets == [ipaddress.ip_network("192.168.178.0/24"), ipaddress.ip_network("10.199.2.0/24")]

    nets_with_0 = nets + [ipaddress.ip_network("10.199.0.0/24")]
    assert vpn_helpers.pick_free_wg_network("10.199.0.0/24", host_routes=nets_with_0) == "10.199.1.0/24"


def test_detect_host_lan_extracts_primary_ip_and_cidr(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run_cmd(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:5] == ["ip", "-j", "-4", "route", "get"]:
            return subprocess.CompletedProcess(
                args, 0, json.dumps([{"dst": "1.1.1.1", "dev": "ens18", "prefsrc": "192.168.178.25"}]), ""
            )
        if args[:6] == ["ip", "-j", "-4", "addr", "show"]:
            return subprocess.CompletedProcess(
                args,
                0,
                json.dumps(
                    [
                        {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]},
                        {"ifname": "wg0", "addr_info": [{"local": "10.5.4.1", "prefixlen": 24}]},
                        {"ifname": "tun-vpn1", "addr_info": [{"local": "10.199.1.1", "prefixlen": 24}]},
                        {"ifname": "ens18", "addr_info": [{"local": "192.168.178.25", "prefixlen": 24}]},
                    ]
                ),
                "",
            )
        return subprocess.CompletedProcess(args, 1, "", "")

    monkeypatch.setattr(vpn_helpers, "run_cmd", fake_run_cmd)
    ip_addr, cidr = vpn_helpers.detect_host_lan("vpn1")
    assert ip_addr == "192.168.178.25"
    assert cidr == "192.168.178.0/24"


# ---------------------------------------------------------------------------
# 2. Ldapproxy Integration & LDIF Group Parsing Tests
# ---------------------------------------------------------------------------


def test_write_ldap_secret_and_ldif_parsing(tmp_path: Path) -> None:
    lp = MockLdapproxy()
    secret = vpn_helpers.write_ldap_secret(
        "ad.firma.de",
        "vpn-users",
        state_dir=tmp_path,
        ldapproxy_instance=lp,
    )
    ldap_file = tmp_path / "secrets" / "ldap.json"
    assert ldap_file.is_file()
    stored = json.loads(ldap_file.read_text(encoding="utf-8"))
    assert stored == secret
    assert stored == {
        "configured": True,
        "domain": "ad.firma.de",
        "host": "127.0.0.1",
        "port": 20011,
        "schema": "ad",
        "base_dn": "DC=ad,DC=firma,DC=de",
        "bind_dn": "CN=ldapservice,CN=Users,DC=ad,DC=firma,DC=de",
        "bind_password": "s3cr3t-ad-password",
        "vpn_group": "vpn-users",
        "hidden_users": ["administrator", "krbtgt", "guest"],
    }

    disabled = vpn_helpers.write_ldap_secret("", "", state_dir=tmp_path, ldapproxy_instance=lp)
    assert disabled["configured"] is False
    assert disabled["domain"] == ""

    b64_desc = base64.b64encode("Außendienst & Homeoffice".encode("utf-8")).decode("ascii")
    ldif = (
        "dn: CN=vpn-users,CN=Users,DC=ad,DC=firma,DC=de\n"
        "sAMAccountName: vpn-users\n"
        f"description:: {b64_desc}\n"
        "\n"
        "dn: CN=Domain Admins,CN=Users,DC=ad,DC=firma,DC=de\n"
        "sAMAccountName: Domain Admins\n"
        "description: Designated administrators\n"
    )
    groups = vpn_helpers.parse_ldif_groups(ldif, schema="ad")
    assert len(groups) == 2
    assert groups[0]["name"] == "Domain Admins"
    assert groups[1] == {
        "name": "vpn-users",
        "dn": "CN=vpn-users,CN=Users,DC=ad,DC=firma,DC=de",
        "description": "Außendienst & Homeoffice",
    }


# ---------------------------------------------------------------------------
# 3. End-to-End Action & Event Script Execution Tests (Phases 1-3)
# ---------------------------------------------------------------------------


def test_create_module_20initialize_calls_dump_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    mock_agent = MockAgentState()
    mock_agent.install(monkeypatch)
    monkeypatch.setenv("MODULE_ID", "vpn1")
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(vpn_helpers, "detect_cluster_wg", lambda: ("10.5.4.0/24", 55820))
    monkeypatch.setattr(vpn_helpers, "get_bound_udp_ports", lambda: set())
    monkeypatch.setattr(vpn_helpers, "get_bound_tcp_ports", lambda: set())
    monkeypatch.setattr(vpn_helpers, "get_host_route_networks", lambda mid=None: [])
    monkeypatch.setattr(vpn_helpers, "detect_host_lan", lambda mid=None: ("192.168.178.10", "192.168.178.0/24"))

    code, _, _ = execute_action_script("actions/create-module/20initialize", monkeypatch)
    assert code == 0
    assert mock_agent.dump_env_count == 1
    snap = mock_agent.dump_env_snapshots[-1]
    assert snap["WG_PORT"] == "51820"
    assert snap["WG_NETWORK"] == "10.199.0.0/24"
    assert snap["OVPN_INTERFACE"] == "tun-vpn1"
    assert snap["OVPN_NETWORK"] == "10.199.1.0/24"
    assert snap["PORTAL_TOTP_MODE"] == "optional"
    assert snap["ALLOWED_CIDRS"] == "192.168.178.0/24"
    assert (tmp_path / "secrets" / "ldap.json").is_file()


def test_configure_module_validation_and_20configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    mock_agent = MockAgentState()
    mock_agent.route_in_use_domains.add("taken.firma.de")
    mock_agent.install(monkeypatch)

    monkeypatch.setenv("MODULE_ID", "vpn1")
    monkeypatch.setenv("TCP_PORT", "20088")
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path))

    recorded_cmds: list[list[str]] = []

    def fake_run_cmd(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        recorded_cmds.append(list(args))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(vpn_helpers, "run_cmd", fake_run_cmd)
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")

    # 1. Hostname validation rejects taken Traefik route
    code_taken, out_taken, _ = execute_action_script(
        "actions/configure-module/01hostname-validation",
        monkeypatch,
        {"portal_enabled": True, "portal_domain": "taken.firma.de"},
    )
    assert code_taken == 2
    assert "validation-failed" in mock_agent.statuses
    assert json.loads(out_taken)[0]["error"] == "route_already_in_use"

    # 2. 10validate rejects unknown domain & cluster port 55820
    bad_payload = {
        "endpoint_host": "vpn.firma.de",
        "wg_port": 55820,
        "wg_network": "10.199.0.0/24",
        "tunnel_mode": "split",
        "allowed_cidrs": ["192.168.178.0/24"],
        "user_domain": "nonexistent.lan",
    }
    code_bad, out_bad, _ = execute_action_script("actions/configure-module/10validate", monkeypatch, bad_payload)
    assert code_bad == 2
    err_fields = {item["field"]: item["error"] for item in json.loads(out_bad)}
    assert err_fields["wg_port"] == "port_reserved_cluster_vpn"
    assert err_fields["user_domain"] == "unknown_user_domain"

    # 3. Valid Phase 1-3 configure-module payload passes schema, 10validate, and 20configure
    valid_payload = {
        "endpoint_host": "vpn.firma.de",
        "wg_port": 51820,
        "wg_network": "10.199.0.0/24",
        "tunnel_mode": "split",
        "allowed_cidrs": ["192.168.178.0/24"],
        "dns_servers": ["192.168.178.10"],
        "dns_search_domain": "ad.firma.de",
        "wg_mtu": 1380,
        "persistent_keepalive": 25,
        "nat_enabled": True,
        "user_domain": "ad.firma.de",
        "vpn_group": "vpn-users",
        "max_devices_per_user": 3,
        "sync_interval_minutes": 5,
        "portal_enabled": True,
        "portal_domain": "portal.firma.de",
        "portal_lets_encrypt": True,
        "portal_http2https": True,
        "portal_totp_mode": "required",
        "ovpn_enabled": True,
        "ovpn_proto": "tcp",
        "ovpn_port": 1194,
        "ovpn_public_port": 443,
        "ovpn_network": "10.199.1.0/24",
        "ovpn_totp_required": True,
    }
    in_schema = json.loads((IMAGEROOOT / "actions" / "configure-module" / "validate-input.json").read_text("utf-8"))
    validate_json_schema(instance=valid_payload, schema=in_schema)

    code_val, _, _ = execute_action_script("actions/configure-module/10validate", monkeypatch, valid_payload)
    assert code_val == 0

    code_cfg, _, _ = execute_action_script("actions/configure-module/20configure", monkeypatch, valid_payload)
    assert code_cfg == 0

    # Verify dump_env() flushed ALL set_env() calls including Phase 2/3 fields
    assert mock_agent.dump_env_count == 1
    dumped = mock_agent.dump_env_snapshots[-1]
    assert dumped["CONFIGURED"] == "true"
    assert dumped["ENDPOINT_HOST"] == "vpn.firma.de"
    assert dumped["PORTAL_TOTP_MODE"] == "required"
    assert dumped["OVPN_ENABLED"] == "true"
    assert dumped["OVPN_PORT"] == "1194"
    assert dumped["OVPN_PUBLIC_PORT"] == "443"
    assert dumped["OVPN_NETWORK"] == "10.199.1.0/24"
    assert dumped["OVPN_TOTP_REQUIRED"] == "true"

    # Verify domain binding, multi-port firewall, both wg-vpn1 & tun-vpn1 in ns8vpn-vpn1 (never trusted), and Traefik
    assert mock_agent.bound_domains == [["ad.firma.de"]]
    assert mock_agent.public_services == [("vpn1", ["51820/udp", "1194/tcp"], True)]
    assert any("--zone=ns8vpn-vpn1" in cmd and "--add-interface=wg-vpn1" in cmd for cmd in recorded_cmds)
    assert any("--zone=ns8vpn-vpn1" in cmd and "--add-interface=tun-vpn1" in cmd for cmd in recorded_cmds)
    assert not any("--zone=trusted" in cmd and "--add-interface=wg-vpn1" in cmd for cmd in recorded_cmds)
    assert not any("--zone=trusted" in cmd and "--add-interface=tun-vpn1" in cmd for cmd in recorded_cmds)

    assert len(mock_agent.tasks.calls) == 1
    route_call = mock_agent.tasks.calls[0]
    assert route_call["action"] == "set-route"
    assert route_call["data"]["url"] == "http://127.0.0.1:20088"
    assert route_call["data"]["host"] == "portal.firma.de"

    # 4. 80start_services pushes desired_config.json over admin.sock
    api_calls: list[tuple[str, str, Any]] = []
    monkeypatch.setattr(vpn_helpers, "wait_for_admin_socket", lambda **kw: True)
    monkeypatch.setattr(
        vpn_helpers,
        "admin_api_request",
        lambda method, path, payload=None, **kw: (api_calls.append((method, path, payload)) or {"status": "ok"}),
    )
    code_start, _, _ = execute_action_script("actions/configure-module/80start_services", monkeypatch, valid_payload)
    assert code_start == 0
    assert [c[:2] for c in api_calls] == [
        ("PUT", "/api/v1/admin/config"),
        ("POST", "/api/v1/admin/reconcile"),
    ]
    assert api_calls[0][2]["ovpn_public_port"] == 443


def test_get_configuration_merges_host_and_validates_schema(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MODULE_ID", "vpn1")
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(vpn_helpers, "detect_host_lan", lambda mid=None: ("192.168.178.10", "192.168.178.0/24"))
    monkeypatch.setattr(vpn_helpers, "detect_cluster_wg", lambda: ("10.5.4.0/24", 55820))

    out_schema = json.loads((IMAGEROOOT / "actions" / "get-configuration" / "validate-output.json").read_text("utf-8"))

    # Case A: Fallback before service starts
    code_fb, out_fb, _ = execute_action_script("actions/get-configuration/10get", monkeypatch)
    assert code_fb == 0
    fb_data = json.loads(out_fb)
    validate_json_schema(instance=fb_data, schema=out_schema)
    assert fb_data["configured"] is False
    assert fb_data["ovpn_interface_name"] == "tun-vpn1"
    assert fb_data["portal_totp_mode"] == "optional"
    assert fb_data["summary"]["online_ovpn_clients"] == 0
    assert fb_data["summary"]["s2s_tunnels"] == 0

    # Case B: Live controller response via admin.sock
    sock_file = tmp_path / "run" / "admin.sock"
    sock_file.parent.mkdir(parents=True, exist_ok=True)
    sock_file.write_text("", encoding="utf-8")

    live_cfg = {
        **vpn_helpers.build_fallback_configuration("vpn1"),
        "configured": True,
        "endpoint_host": "vpn.firma.de",
        "ovpn_enabled": True,
        "ovpn_public_port": 443,
        "server_public_key": "dGVzdC1zZXJ2ZXItcHVibGljLWtleS0xMjM0NTY3ODk=",
        "summary": {
            "authorized_users": 8,
            "total_peers": 5,
            "active_peers": 5,
            "online_peers": 2,
            "online_ovpn_clients": 1,
            "s2s_tunnels": 2,
            "active_s2s_tunnels": 2,
            "last_synced_at": "2026-11-20T12:00:00Z",
            "last_sync_status": "ok",
            "last_sync_error": None,
        },
    }
    monkeypatch.setattr(vpn_helpers, "admin_api_request", lambda *a, **kw: live_cfg)

    code_live, out_live, _ = execute_action_script("actions/get-configuration/10get", monkeypatch)
    assert code_live == 0
    live_data = json.loads(out_live)
    validate_json_schema(instance=live_data, schema=out_schema)
    assert live_data["summary"]["online_ovpn_clients"] == 1
    assert live_data["summary"]["active_s2s_tunnels"] == 2


def test_domain_peer_totp_ovpn_and_s2s_actions_match_json_schemas(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mock_agent = MockAgentState()
    mock_agent.install(monkeypatch)
    monkeypatch.setenv("MODULE_ID", "vpn1")
    monkeypatch.setenv("CONFIGURED", "true")
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(vpn_helpers, "detect_cluster_wg", lambda: ("10.5.4.0/24", 55820))
    monkeypatch.setattr(
        vpn_helpers,
        "get_host_route_networks",
        lambda mid=None: [ipaddress.ip_network("192.168.178.0/24")],
    )

    # list-user-domains
    code, out, _ = execute_action_script("actions/list-user-domains/10list", monkeypatch)
    assert code == 0
    dom_out = json.loads(out)
    dom_schema = json.loads((IMAGEROOOT / "actions" / "list-user-domains" / "validate-output.json").read_text("utf-8"))
    validate_json_schema(instance=dom_out, schema=dom_schema)

    # list-domain-groups
    monkeypatch.setattr(
        vpn_helpers,
        "query_domain_groups",
        lambda dom, **kw: [{"name": "vpn-users", "dn": "CN=vpn-users,DC=ad,DC=firma,DC=de", "description": "VPN"}],
    )
    grp_in = {"user_domain": "ad.firma.de"}
    validate_json_schema(
        instance=grp_in,
        schema=json.loads((IMAGEROOOT / "actions" / "list-domain-groups" / "validate-input.json").read_text("utf-8")),
    )
    code, out, _ = execute_action_script("actions/list-domain-groups/10list", monkeypatch, grp_in)
    assert code == 0
    validate_json_schema(
        instance=json.loads(out),
        schema=json.loads((IMAGEROOOT / "actions" / "list-domain-groups" / "validate-output.json").read_text("utf-8")),
    )

    # create-s2s-tunnel rejects remote_cidrs overlapping wg0 10.5.4.0/24 or host route 192.168.178.0/24
    code_s2s_bad, out_s2s_bad, _ = execute_action_script(
        "actions/create-s2s-tunnel/20create",
        monkeypatch,
        {"name": "Bad-Branch", "remote_cidrs": ["10.5.4.0/24"]},
    )
    assert code_s2s_bad == 2
    assert json.loads(out_s2s_bad)[0]["error"] == "remote_cidr_overlaps_cluster_vpn"

    code_s2s_route, out_s2s_route, _ = execute_action_script(
        "actions/create-s2s-tunnel/20create",
        monkeypatch,
        {"name": "Route-Collision", "remote_cidrs": ["192.168.178.0/24"]},
    )
    assert code_s2s_route == 2
    assert json.loads(out_s2s_route)[0]["error"] == "remote_cidr_overlaps_host_route"

    mock_peer = {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "username": "jdoe",
        "display_name": "Jane Doe",
        "protocol": "wireguard",
        "device_name": "Work-Laptop",
        "assigned_ip": "10.199.0.2",
        "public_key": "cGVlci1wdWJsaWMta2V5LTEyMzQ1Njc4OTA=",
        "admin_enabled": True,
        "user_authorized": True,
        "effective_active": True,
        "online": False,
        "rx_bytes": 0,
        "tx_bytes": 0,
        "last_handshake_at": None,
        "last_endpoint": None,
        "created_at": "2026-11-20T12:00:00Z",
    }
    mock_tunnel = {
        "id": "990e8400-e29b-41d4-a716-446655440099",
        "name": "Branch-Munich",
        "enabled": True,
        "assigned_ip": "10.199.0.250",
        "public_key": "czJzLXB1YmxpYy1rZXktMTIzNDU2Nzg5MDEyMzQ1Ng==",
        "remote_endpoint": "munich.firma.de:51820",
        "remote_cidrs": ["192.168.20.0/24"],
        "online": True,
        "rx_bytes": 4096,
        "tx_bytes": 8192,
        "last_handshake_at": "2026-11-20T12:01:00Z",
        "created_at": "2026-11-20T11:00:00Z",
    }

    def fake_admin_api(method: str, path: str, payload: Any = None, **kw: Any) -> Any:
        if (method, path) == ("GET", "/api/v1/admin/peers"):
            return {
                "users": [
                    {
                        "username": "jdoe",
                        "domain": "ad.firma.de",
                        "display_name": "Jane Doe",
                        "email": None,
                        "ldap_active": True,
                        "in_vpn_group": True,
                        "authorized": True,
                        "peer_count": 1,
                        "totp_enrolled": True,
                        "last_synced_at": "2026-11-20T12:00:00Z",
                    }
                ],
                "peers": [mock_peer],
                "summary": {
                    "authorized_users": 1,
                    "total_peers": 1,
                    "active_peers": 1,
                    "online_peers": 0,
                    "max_devices_per_user": 3,
                },
            }
        if (method, path) == ("POST", "/api/v1/admin/peers"):
            return {
                "peer": mock_peer,
                "config_text": "[Interface]\nAddress = 10.199.0.2/32\n",
                "qr_svg_data_uri": "data:image/svg+xml;base64,PHN2Zy8+",
            }
        if (method, path) == ("GET", f"/api/v1/admin/peers/{mock_peer['id']}/config"):
            return {
                "peer_id": mock_peer["id"],
                "username": "jdoe",
                "device_name": "Work-Laptop",
                "config_text": "[Interface]\nAddress = 10.199.0.2/32\n",
                "qr_svg_data_uri": "data:image/svg+xml;base64,PHN2Zy8+",
            }
        if (method, path) == ("POST", f"/api/v1/admin/peers/{mock_peer['id']}/toggle"):
            return {"peer": {**mock_peer, "admin_enabled": payload["enabled"], "effective_active": payload["enabled"]}}
        if (method, path) == ("DELETE", f"/api/v1/admin/peers/{mock_peer['id']}"):
            return {"revoked": True, "peer_id": mock_peer["id"]}
        if (method, path) == ("POST", "/api/v1/admin/sync"):
            return {
                "status": "ok",
                "synced_at": "2026-11-20T12:05:00Z",
                "total_users": 10,
                "authorized_users": 4,
                "active_peers": 3,
                "suspended_peers": 0,
                "message": "Synchronized 4 authorized users",
            }
        if (method, path) == ("POST", "/api/v1/admin/users/jdoe/reset-totp"):
            return {"reset": True, "username": "jdoe"}
        if (method, path) == ("GET", "/api/v1/admin/users/jdoe/ovpn"):
            return {
                "username": "jdoe",
                "filename": "jdoe-ns8vpn.ovpn",
                "ovpn_text": "client\ndev tun\nproto tcp-client\nremote vpn.firma.de 443\n",
                "totp_required_on_connect": True,
            }
        if (method, path) == ("GET", "/api/v1/admin/s2s"):
            return {"tunnels": [mock_tunnel]}
        if (method, path) == ("POST", "/api/v1/admin/s2s"):
            return {"tunnel": mock_tunnel, "config_text": "[Interface]\nAddress = 10.199.0.250/32\n"}
        if (method, path) == ("GET", f"/api/v1/admin/s2s/{mock_tunnel['id']}/config"):
            return {
                "tunnel_id": mock_tunnel["id"],
                "name": mock_tunnel["name"],
                "config_text": "[Interface]\nAddress = 10.199.0.250/32\n",
                "has_private_key": True,
            }
        if (method, path) == ("POST", f"/api/v1/admin/s2s/{mock_tunnel['id']}/toggle"):
            return {"tunnel": {**mock_tunnel, "enabled": False, "online": False}}
        if (method, path) == ("DELETE", f"/api/v1/admin/s2s/{mock_tunnel['id']}"):
            return {"deleted": True, "tunnel_id": mock_tunnel["id"]}
        if (method, path) == ("GET", "/api/v1/admin/audit-logs?limit=250"):
            return {
                "entries": [
                    {
                        "id": 1,
                        "timestamp": "2026-11-20T12:10:00Z",
                        "event_type": "peer_created",
                        "actor": "admin",
                        "username": "jdoe",
                        "peer_id": mock_peer["id"],
                        "details": "Created WireGuard peer Work-Laptop (10.199.0.2)",
                    }
                ],
                "total": 1,
            }
        raise AssertionError(f"Unexpected call {method} {path}")

    monkeypatch.setattr(vpn_helpers, "admin_api_request", fake_admin_api)

    action_matrix = [
        ("list-peers", "actions/list-peers/10list", None),
        ("create-peer", "actions/create-peer/20create", {"username": "jdoe", "device_name": "Work-Laptop"}),
        ("get-peer-config", "actions/get-peer-config/10get", {"peer_id": mock_peer["id"]}),
        ("toggle-peer", "actions/toggle-peer/20toggle", {"peer_id": mock_peer["id"], "enabled": False}),
        ("revoke-peer", "actions/revoke-peer/20revoke", {"peer_id": mock_peer["id"]}),
        ("sync-users", "actions/sync-users/20sync", None),
        ("reset-user-totp", "actions/reset-user-totp/20reset", {"username": "jdoe"}),
        ("get-user-ovpn", "actions/get-user-ovpn/10get", {"username": "jdoe"}),
        ("list-s2s-tunnels", "actions/list-s2s-tunnels/10list", None),
        (
            "create-s2s-tunnel",
            "actions/create-s2s-tunnel/20create",
            {"name": "Branch-Munich", "remote_cidrs": ["192.168.20.0/24"], "remote_endpoint": "munich.firma.de:51820"},
        ),
        ("get-s2s-config", "actions/get-s2s-config/10get", {"tunnel_id": mock_tunnel["id"]}),
        ("toggle-s2s-tunnel", "actions/toggle-s2s-tunnel/20toggle", {"tunnel_id": mock_tunnel["id"], "enabled": False}),
        ("delete-s2s-tunnel", "actions/delete-s2s-tunnel/20delete", {"tunnel_id": mock_tunnel["id"]}),
        ("list-audit-logs", "actions/list-audit-logs/10list", {"limit": 250}),
    ]

    for action_name, rel_script, req_payload in action_matrix:
        in_schema_path = IMAGEROOOT / "actions" / action_name / "validate-input.json"
        if in_schema_path.is_file():
            validate_json_schema(instance=req_payload, schema=json.loads(in_schema_path.read_text("utf-8")))
        code, out, err = execute_action_script(rel_script, monkeypatch, req_payload)
        assert code == 0, f"{action_name} failed: {err}"
        resp_obj = json.loads(out)
        out_schema_path = IMAGEROOOT / "actions" / action_name / "validate-output.json"
        validate_json_schema(instance=resp_obj, schema=json.loads(out_schema_path.read_text("utf-8")))


def test_restore_clone_destroy_and_ldap_events(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    mock_agent = MockAgentState()
    mock_agent.install(monkeypatch)
    monkeypatch.setenv("MODULE_ID", "vpn2")
    monkeypatch.setenv("TCP_PORT", "20099")
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(vpn_helpers, "run_cmd", lambda args, **kw: subprocess.CompletedProcess(args, 0, "", ""))
    monkeypatch.setattr(vpn_helpers, "wait_for_admin_socket", lambda **kw: True)

    reconcile_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        vpn_helpers,
        "admin_api_request",
        lambda method, path, **kw: (reconcile_calls.append((method, path)) or {"status": "ok"}),
    )

    restore_req = {
        "environment": {
            "MODULE_ID": "vpn1",
            "TCP_PORT": "20001",
            "CONFIGURED": "true",
            "ENDPOINT_HOST": "vpn.firma.de",
            "WG_PORT": "51820",
            "USER_DOMAIN": "ad.firma.de",
            "VPN_GROUP": "vpn-users",
            "PORTAL_TOTP_MODE": "required",
            "OVPN_ENABLED": "true",
            "OVPN_PORT": "1194",
            "OVPN_PUBLIC_PORT": "443",
        }
    }
    code, _, _ = execute_action_script("actions/restore-module/06copyenv", monkeypatch, restore_req)
    assert code == 0
    assert mock_agent.dump_env_count == 1
    assert "MODULE_ID" not in mock_agent.env_store
    assert mock_agent.env_store["PORTAL_TOTP_MODE"] == "required"
    assert mock_agent.env_store["OVPN_PUBLIC_PORT"] == "443"

    bak_dir = tmp_path / "backup"
    bak_dir.mkdir(parents=True, exist_ok=True)
    bak_db = bak_dir / "vpn.db.bak"
    conn = sqlite3.connect(str(bak_db))
    conn.execute("CREATE TABLE server_config (id INTEGER PRIMARY KEY, interface_name TEXT, ovpn_interface_name TEXT)")
    conn.execute("INSERT INTO server_config (id, interface_name, ovpn_interface_name) VALUES (1, 'wg-vpn1', 'tun-vpn1')")
    conn.commit()
    conn.close()

    monkeypatch.setenv("CONFIGURED", "true")
    monkeypatch.setenv("USER_DOMAIN", "ad.firma.de")
    monkeypatch.setenv("VPN_GROUP", "vpn-users")
    code, _, _ = execute_action_script("actions/restore-module/50configure", monkeypatch)
    assert code == 0
    restored_db = tmp_path / "data" / "vpn.db"
    assert restored_db.is_file()
    conn2 = sqlite3.connect(str(restored_db))
    row = conn2.execute("SELECT interface_name, ovpn_interface_name FROM server_config WHERE id = 1").fetchone()
    conn2.close()
    assert row == ("wg-vpn2", "tun-vpn2")
    assert ("POST", "/api/v1/admin/reconcile") in reconcile_calls

    reconcile_calls.clear()
    sock_file = tmp_path / "run" / "admin.sock"
    sock_file.parent.mkdir(parents=True, exist_ok=True)
    sock_file.write_text("", encoding="utf-8")
    code, _, _ = execute_action_script("events/service-ldap-changed/10reload", monkeypatch)
    assert code == 0
    assert reconcile_calls == [("POST", "/api/v1/admin/reconcile")]

    (tmp_path / "secrets" / "master.key").write_bytes(b"0" * 32)
    prev_dumps = mock_agent.dump_env_count
    code, _, _ = execute_action_script("actions/clone-module/50configure", monkeypatch)
    assert code == 0
    assert mock_agent.dump_env_count == prev_dumps + 1
    assert not (tmp_path / "secrets" / "master.key").exists()
    assert not restored_db.exists()
    assert mock_agent.env_store["PORTAL_ENABLED"] == "false"
    assert mock_agent.env_store["OVPN_NETWORK"] != mock_agent.env_store["WG_NETWORK"]

    code, _, _ = execute_action_script("actions/destroy-module/20destroy", monkeypatch)
    assert code == 0
    assert mock_agent.bound_domains[-1] == []
    assert "vpn2" in mock_agent.removed_public_services


def test_interface_naming_parity_with_controller() -> None:
    from container.app.config import derive_interface_name

    samples = [
        "vpn1",
        "vpn2",
        "vpn-office1",
        "roadwarriorvpn12",
        "enterprise-roadwarrior-gateway999",
        "wg-vpn7",
    ]
    for sample in samples:
        expected = derive_interface_name(sample)
        actual = vpn_helpers.get_wg_interface_name(sample)
        assert actual == expected
        assert len(actual) <= 15
        assert actual != "wg0"

        tun_name = vpn_helpers.get_ovpn_interface_name(sample)
        assert tun_name.startswith("tun-")
        assert len(tun_name) <= 15

    for reserved in ("wg0", "0", "wg-0"):
        with pytest.raises(ValueError):
            vpn_helpers.get_wg_interface_name(reserved)


def test_list_audit_logs_live_query_params_and_offline_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MODULE_ID", "vpn1")
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path))

    in_schema = json.loads((IMAGEROOOT / "actions" / "list-audit-logs" / "validate-input.json").read_text("utf-8"))
    out_schema = json.loads((IMAGEROOOT / "actions" / "list-audit-logs" / "validate-output.json").read_text("utf-8"))

    # Validate input schema bounds
    validate_json_schema(instance={}, schema=in_schema)
    validate_json_schema(
        instance={"limit": 100, "event_type": "peer_created", "username": "jdoe"},
        schema=in_schema,
    )
    with pytest.raises(Exception):
        validate_json_schema(instance={"limit": 0}, schema=in_schema)
    with pytest.raises(Exception):
        validate_json_schema(instance={"limit": 1001}, schema=in_schema)

    # Case A: Offline fallback when service/socket is not yet started (AdminApiError 503)
    monkeypatch.setenv("CONFIGURED", "false")
    monkeypatch.setattr(
        vpn_helpers,
        "admin_api_request",
        lambda *a, **kw: (_ for _ in ()).throw(
            vpn_helpers.AdminApiError("Cannot connect to admin.sock", status_code=503)
        ),
    )
    code_fb, out_fb, err_fb = execute_action_script("actions/list-audit-logs/10list", monkeypatch, {"limit": 250})
    assert code_fb == 0, err_fb
    fb_obj = json.loads(out_fb)
    assert fb_obj == {"entries": [], "total": 0}
    validate_json_schema(instance=fb_obj, schema=out_schema)

    # Case B: Non-503 controller HTTP error surfaces exit code 1
    monkeypatch.setattr(
        vpn_helpers,
        "admin_api_request",
        lambda *a, **kw: (_ for _ in ()).throw(
            vpn_helpers.AdminApiError("vpn-controller returned HTTP 500: db failure", status_code=500)
        ),
    )
    code_err, _, err_msg = execute_action_script("actions/list-audit-logs/10list", monkeypatch, {})
    assert code_err == 1
    assert "HTTP 500" in err_msg

    # Case C: Live controller response with query string encoding and nullable fields
    recorded_paths: list[str] = []
    live_payload = {
        "entries": [
            {
                "id": 42,
                "timestamp": "2026-11-20T14:00:00Z",
                "event_type": "peer_created",
                "actor": "admin",
                "username": "jdoe",
                "peer_id": "550e8400-e29b-41d4-a716-446655440000",
                "details": "Created peer with static IP 10.199.0.10",
            },
            {
                "id": 41,
                "timestamp": "2026-11-20T13:55:00Z",
                "event_type": "config_updated",
                "actor": "system",
                "username": None,
                "peer_id": None,
                "details": "Applied desired_config.json",
            },
        ],
        "total": 2,
    }

    def fake_audit_api(method: str, path: str, **kw: Any) -> Any:
        assert method == "GET"
        recorded_paths.append(path)
        return live_payload

    monkeypatch.setattr(vpn_helpers, "admin_api_request", fake_audit_api)

    code_no_qs, out_no_qs, _ = execute_action_script("actions/list-audit-logs/10list", monkeypatch, {})
    assert code_no_qs == 0
    assert recorded_paths[-1] == "/api/v1/admin/audit-logs"
    validate_json_schema(instance=json.loads(out_no_qs), schema=out_schema)

    req_filtered = {"limit": 50, "event_type": "peer_created", "username": "jdoe@firma.de"}
    validate_json_schema(instance=req_filtered, schema=in_schema)
    code_qs, out_qs, _ = execute_action_script("actions/list-audit-logs/10list", monkeypatch, req_filtered)
    assert code_qs == 0
    assert recorded_paths[-1] == "/api/v1/admin/audit-logs?limit=50&event_type=peer_created&username=jdoe%40firma.de"
    parsed_live = json.loads(out_qs)
    assert parsed_live["total"] == 2
    assert len(parsed_live["entries"]) == 2
    validate_json_schema(instance=parsed_live, schema=out_schema)


def test_create_peer_optional_static_assigned_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    in_schema = json.loads((IMAGEROOOT / "actions" / "create-peer" / "validate-input.json").read_text("utf-8"))
    out_schema = json.loads((IMAGEROOOT / "actions" / "create-peer" / "validate-output.json").read_text("utf-8"))

    sent_payloads: list[dict[str, Any]] = []

    def fake_post_peer(method: str, path: str, payload: dict[str, Any] | None = None, **kw: Any) -> Any:
        assert (method, path) == ("POST", "/api/v1/admin/peers")
        assert payload is not None
        sent_payloads.append(dict(payload))
        assigned = str(payload.get("assigned_ip") or "10.199.0.2")
        return {
            "peer": {
                "id": "111e8400-e29b-41d4-a716-446655440011",
                "username": payload["username"],
                "device_name": payload["device_name"],
                "assigned_ip": assigned,
                "public_key": "c3RhdGljLWlwLXBlZXItcHVibGljLWtleS0xMjM0NTY=",
                "admin_enabled": True,
                "effective_active": True,
            },
            "config_text": f"[Interface]\nAddress = {assigned}/32\n",
            "qr_svg_data_uri": "data:image/svg+xml;base64,PHN2Zy8+",
        }

    monkeypatch.setattr(vpn_helpers, "admin_api_request", fake_post_peer)

    # 1. Blank/whitespace assigned_ip is omitted so controller auto-allocates from pool
    auto_req = {"username": "jdoe", "device_name": "Auto-Laptop", "assigned_ip": "   "}
    validate_json_schema(instance=auto_req, schema=in_schema)
    code_auto, out_auto, _ = execute_action_script("actions/create-peer/20create", monkeypatch, auto_req)
    assert code_auto == 0
    assert "assigned_ip" not in sent_payloads[-1]
    validate_json_schema(instance=json.loads(out_auto), schema=out_schema)

    # 2. Explicit static assigned_ip is stripped and forwarded to POST /api/v1/admin/peers
    static_req = {"username": "jdoe", "device_name": "Admin-PC", "assigned_ip": " 10.199.0.10 "}
    validate_json_schema(instance=static_req, schema=in_schema)
    code_static, out_static, _ = execute_action_script("actions/create-peer/20create", monkeypatch, static_req)
    assert code_static == 0
    assert sent_payloads[-1]["assigned_ip"] == "10.199.0.10"
    resp_static = json.loads(out_static)
    assert resp_static["peer"]["assigned_ip"] == "10.199.0.10"
    validate_json_schema(instance=resp_static, schema=out_schema)

    # 3. Collision (409) from controller surfaces error message on stderr with exit code 1
    monkeypatch.setattr(
        vpn_helpers,
        "admin_api_request",
        lambda *a, **kw: (_ for _ in ()).throw(
            vpn_helpers.AdminApiError(
                "vpn-controller returned HTTP 409: IP address '10.199.0.10' is already assigned",
                status_code=409,
            )
        ),
    )
    code_409, _, err_409 = execute_action_script("actions/create-peer/20create", monkeypatch, static_req)
    assert code_409 == 1
    assert "409" in err_409 and "10.199.0.10" in err_409


def test_ldapproxy_unbound_domain_fallback_and_async_port_allocation(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnboundThenBoundLdapproxy:
        calls = 0

        def __init__(self) -> None:
            self.domains = {
                "ldap.test.local": {
                    "schema": "rfc2307",
                    "location": "internal",
                    "base_dn": "dc=ldap,dc=test,dc=local",
                    "bind_dn": "cn=ldapservice,dc=ldap,dc=test,dc=local",
                    "bind_password": "secret",
                }
            }

        def get_domains_list(self) -> list[str]:
            return list(self.domains.keys())

        def get_domain(self, domain: str) -> dict[str, Any] | None:
            UnboundThenBoundLdapproxy.calls += 1
            if UnboundThenBoundLdapproxy.calls < 2:
                return None
            return {
                "host": "127.0.0.1",
                "port": 20012,
                **self.domains[domain],
                "hidden_users": [],
            }

    # 1. list_user_domains_info reads schema & base_dn from lp.domains even when get_domain() returns None
    unbound_lp = UnboundThenBoundLdapproxy()
    UnboundThenBoundLdapproxy.calls = -10
    listed = vpn_helpers.list_user_domains_info(ldapproxy_instance=unbound_lp)
    assert len(listed) == 1
    assert listed[0]["name"] == "ldap.test.local"
    assert listed[0]["schema"] == "rfc2307"
    assert listed[0]["base_dn"] == "dc=ldap,dc=test,dc=local"

    # 2. build_ldap_config retries until ns8-ldapproxy allocates listen_port asynchronously
    UnboundThenBoundLdapproxy.calls = 0
    monkeypatch.setattr(vpn_helpers, "_get_ldapproxy", lambda inst=None: inst or UnboundThenBoundLdapproxy())
    monkeypatch.setattr(vpn_helpers.time, "sleep", lambda _s: None)
    built = vpn_helpers.build_ldap_config("ldap.test.local", "vpn-users", max_wait_seconds=2.0)
    assert built["configured"] is True
    assert built["port"] == 20012
    assert built["schema"] == "rfc2307"
    assert built["base_dn"] == "dc=ldap,dc=test,dc=local"

