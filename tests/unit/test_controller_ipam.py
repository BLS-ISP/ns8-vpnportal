"""Unit tests for IPAM allocation and NS8 cluster collision safeguards (`ipam.py`)."""

from __future__ import annotations

import pytest

from container.app.ipam import (
    IPAMValidationError,
    IPPoolExhaustedError,
    allocate_peer_ip,
    get_server_interface_cidr,
    get_server_tunnel_ip,
    normalize_allowed_cidrs,
    normalize_dns_servers,
    normalize_wg_network,
    validate_requested_peer_ip,
    validate_wg_port,
)


def test_default_subnet_server_and_peer_allocation() -> None:
    net = normalize_wg_network("10.199.0.0/24")
    assert str(net) == "10.199.0.0/24"
    assert get_server_tunnel_ip("10.199.0.0/24") == "10.199.0.1"
    assert get_server_interface_cidr("10.199.0.0/24") == "10.199.0.1/24"

    first_ip = allocate_peer_ip("10.199.0.0/24", used_ips=set())
    assert first_ip == "10.199.0.2"

    second_ip = allocate_peer_ip("10.199.0.0/24", used_ips={"10.199.0.2", "10.199.0.3"})
    assert second_ip == "10.199.0.4"


def test_ip_pool_exhaustion_on_small_subnet() -> None:
    # 10.199.10.0/30 has hosts .1 (server) and .2 (single client)
    ip1 = allocate_peer_ip("10.199.10.0/30", used_ips=set())
    assert ip1 == "10.199.10.2"

    with pytest.raises(IPPoolExhaustedError):
        allocate_peer_ip("10.199.10.0/30", used_ips={"10.199.10.2"})


@pytest.mark.parametrize(
    "bad_cidr",
    [
        "10.5.4.0/24",      # Exact NS8 cluster VPN subnet
        "10.5.4.128/25",    # Subnet inside NS8 cluster VPN
        "10.5.0.0/16",      # Supernet overlapping NS8 cluster VPN
        "127.0.0.0/24",     # Loopback
        "169.254.1.0/24",   # Link-local
        "224.0.0.0/24",     # Multicast
        "0.0.0.0/0",        # Unspecified
        "10.199.0.0/31",    # Too small for server + client
        "10.0.0.0/8",       # Too large (> /16)
        "fd00::/64",        # IPv6 not valid for IPv4 transfer net
        "not-a-cidr",
    ],
)
def test_reject_reserved_and_overlapping_wg_networks(bad_cidr: str) -> None:
    with pytest.raises(IPAMValidationError):
        normalize_wg_network(bad_cidr)


def test_reject_ns8_cluster_wg_port() -> None:
    assert validate_wg_port(51820) == 51820
    with pytest.raises(IPAMValidationError, match="55820"):
        validate_wg_port(55820)
    with pytest.raises(IPAMValidationError):
        validate_wg_port(0)
    with pytest.raises(IPAMValidationError):
        validate_wg_port(70000)


def test_allowed_cidrs_and_dns_validation() -> None:
    cidrs = normalize_allowed_cidrs(
        ["192.168.10.5/24", "172.16.0.0/16", "192.168.10.0/24"],
        wg_network="10.199.0.0/24",
    )
    assert cidrs == ["192.168.10.0/24", "172.16.0.0/16"]

    # Reject NS8 cluster subnet in Split-Tunnel allowed_cidrs
    with pytest.raises(IPAMValidationError, match="cluster"):
        normalize_allowed_cidrs(["10.5.4.0/24"], wg_network="10.199.0.0/24")

    # Reject overlap with transfer subnet
    with pytest.raises(IPAMValidationError, match="transfer"):
        normalize_allowed_cidrs(["10.199.0.0/24"], wg_network="10.199.0.0/24")

    # Reject 0.0.0.0/0 in split-tunnel list
    with pytest.raises(IPAMValidationError, match="full"):
        normalize_allowed_cidrs(["0.0.0.0/0"], wg_network="10.199.0.0/24")

    dns = normalize_dns_servers(["192.168.10.5", "192.168.10.5", "9.9.9.9"])
    assert dns == ["192.168.10.5", "9.9.9.9"]

    with pytest.raises(IPAMValidationError):
        normalize_dns_servers(["10.5.4.1"])
    with pytest.raises(IPAMValidationError):
        normalize_dns_servers(["127.0.0.1"])


def test_validate_requested_peer_ip_static_assignment_and_collisions() -> None:
    assert (
        validate_requested_peer_ip(" 10.199.0.50 ", "10.199.0.0/24", used_ips={"10.199.0.2"})
        == "10.199.0.50"
    )

    # Reject invalid IPv4, network (.0), broadcast (.255), server (.1), and out-of-range IPs -> 400
    for bad_ip in (
        "",
        "not-an-ip",
        "fd00::10",
        "10.199.0.0",
        "10.199.0.1",
        "10.199.0.255",
        "10.199.5.10",
        "10.5.4.10",
    ):
        with pytest.raises(IPAMValidationError):
            validate_requested_peer_ip(bad_ip, "10.199.0.0/24", used_ips=set())

    # Reject already assigned IP -> 409 IPPoolExhaustedError with exact message
    with pytest.raises(
        IPPoolExhaustedError,
        match="IP address '10.199.0.10' is already assigned",
    ):
        validate_requested_peer_ip(
            "10.199.0.10",
            "10.199.0.0/24",
            used_ips={"10.199.0.2", "10.199.0.10"},
        )
