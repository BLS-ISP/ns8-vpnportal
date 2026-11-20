"""Shared pytest fixtures for ns8-vpn controller unit tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from container.app.admin_api import VPNControllerService
from container.app.config import Settings
from container.app.wireguard import DryRunCommandRunner


@pytest.fixture
def controller_settings(tmp_path: Path) -> Settings:
    state_dir = tmp_path / "state"
    settings = Settings(
        module_id="vpn1",
        state_dir=state_dir,
        tcp_port=18080,
        initial_wg_port=51820,
        initial_wg_network="10.199.0.0/24",
        initial_endpoint_host="vpn.corp.example.com",
        initial_tunnel_mode="split",
        initial_allowed_cidrs=["192.168.10.0/24"],
        initial_dns_servers=["192.168.10.5"],
        initial_dns_search_domain="corp.example.com",
        dry_run=True,
    )
    settings.ensure_directories()
    return settings


@pytest.fixture
def dry_runner() -> DryRunCommandRunner:
    return DryRunCommandRunner()


@pytest.fixture
def controller_service(
    controller_settings: Settings,
    dry_runner: DryRunCommandRunner,
) -> VPNControllerService:
    svc = VPNControllerService(settings=controller_settings, runner=dry_runner)
    svc.reconcile_dataplane()
    return svc


def write_ldap_json(settings: Settings, data: dict[str, Any]) -> Path:
    path = settings.ldap_config_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8", newline="\n")
    return path
