"""Tests for network share discovery and enumeration."""

from unittest.mock import patch

import pytest

from treasure_hunter.network import (
    enumerate_network_targets,
    _expand_cidr,
    _is_port_open,
)


class TestEnumerateNetworkTargets:
    def test_single_ip(self):
        targets = enumerate_network_targets("10.0.0.1")
        assert targets == ["10.0.0.1"]

    def test_hostname(self):
        targets = enumerate_network_targets("dc01.corp.local")
        assert targets == ["dc01.corp.local"]

    def test_comma_separated(self):
        targets = enumerate_network_targets("10.0.0.1,10.0.0.2,10.0.0.3")
        assert len(targets) == 3
        assert "10.0.0.1" in targets
        assert "10.0.0.3" in targets

    def test_cidr_subnet(self):
        targets = enumerate_network_targets("10.0.0.0/30")
        # /30 = 4 addresses, 2 usable hosts (skip network + broadcast)
        assert len(targets) == 2
        assert "10.0.0.1" in targets
        assert "10.0.0.2" in targets

    @patch("treasure_hunter.network._auto_discover_hosts", return_value=["dc01", "fileserver"])
    def test_auto_mode(self, mock_discover):
        targets = enumerate_network_targets("auto")
        assert "dc01" in targets
        assert "fileserver" in targets


class TestExpandCIDR:
    def test_slash_24(self):
        hosts = _expand_cidr("192.168.1.0/24")
        assert len(hosts) == 254  # .1 through .254
        assert "192.168.1.1" in hosts
        assert "192.168.1.254" in hosts
        assert "192.168.1.0" not in hosts    # network address
        assert "192.168.1.255" not in hosts  # broadcast

    def test_slash_30(self):
        hosts = _expand_cidr("10.0.0.0/30")
        assert len(hosts) == 2
        assert "10.0.0.1" in hosts
        assert "10.0.0.2" in hosts

    def test_slash_32_empty(self):
        # /32 = single host, no usable range
        hosts = _expand_cidr("10.0.0.1/32")
        assert hosts == []

    def test_too_large_prefix_rejected(self):
        # /8 would be millions of hosts -- safety check
        hosts = _expand_cidr("10.0.0.0/8")
        assert hosts == []  # Below min prefix of 16

    def test_slash_16(self):
        hosts = _expand_cidr("172.16.0.0/16")
        assert len(hosts) == 65534  # 2^16 - 2

    def test_invalid_cidr(self):
        hosts = _expand_cidr("not-a-cidr")
        assert isinstance(hosts, list)


class TestIsPortOpen:
    def test_closed_port(self):
        # Port 1 on localhost is almost certainly closed
        assert not _is_port_open("127.0.0.1", 1, timeout=0.5)

    def test_invalid_host(self):
        assert not _is_port_open("999.999.999.999", 445, timeout=0.5)

    def test_timeout_works(self):
        # Should return quickly with short timeout
        import time
        start = time.monotonic()
        _is_port_open("192.0.2.1", 445, timeout=0.5)  # RFC 5737 TEST-NET
        elapsed = time.monotonic() - start
        assert elapsed < 2.0  # Should respect timeout
