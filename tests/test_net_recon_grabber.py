"""Tests for network reconnaissance grabber."""

import platform
from unittest.mock import patch

import pytest

from treasure_hunter.grabbers.net_recon import NetReconGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


class TestNetReconAttributes:
    def test_name(self):
        g = NetReconGrabber()
        assert g.name == "net_recon"
        assert g.default_enabled is True

    def test_preflight_always_true(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx)
        assert NetReconGrabber().preflight_check(gctx)


class TestARPTable:
    def test_returns_list(self):
        entries = NetReconGrabber._get_arp_table()
        assert isinstance(entries, list)
        for entry in entries:
            assert "ip" in entry
            assert "mac" in entry

    def test_entries_have_valid_ips(self):
        entries = NetReconGrabber._get_arp_table()
        for entry in entries:
            parts = entry["ip"].split(".")
            # Should be valid IPv4
            assert len(parts) == 4


class TestTCPConnections:
    def test_returns_list(self):
        conns = NetReconGrabber._get_tcp_connections()
        assert isinstance(conns, list)

    def test_entries_have_required_fields(self):
        conns = NetReconGrabber._get_tcp_connections()
        for conn in conns:
            assert "local_ip" in conn
            assert "local_port" in conn
            assert "remote_ip" in conn
            assert "remote_port" in conn
            assert "state" in conn


class TestListeningPorts:
    def test_returns_list(self):
        listeners = NetReconGrabber._get_listening_ports()
        assert isinstance(listeners, list)


class TestNetReconExecution:
    def test_executes_without_crash(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx)
        g = NetReconGrabber()
        result = g.execute(gctx)
        assert result.status == GrabberStatus.COMPLETED

    @patch.object(NetReconGrabber, '_get_arp_table')
    @patch.object(NetReconGrabber, '_get_tcp_connections')
    def test_reports_arp_and_connections(self, mock_tcp, mock_arp):
        mock_arp.return_value = [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "iface": "eth0"},
            {"ip": "10.0.0.5", "mac": "11:22:33:44:55:66", "iface": "eth0"},
        ]
        mock_tcp.return_value = [
            {"local_ip": "10.0.0.100", "local_port": 49152,
             "remote_ip": "10.0.0.5", "remote_port": 445,
             "state": "ESTABLISHED", "pid": "1234"},
        ]

        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx)
        g = NetReconGrabber()
        result = g.execute(gctx)

        assert result.status == GrabberStatus.COMPLETED
        arp_creds = [c for c in result.credentials if c.target_application == "ARP Table"]
        tcp_creds = [c for c in result.credentials if c.target_application == "TCP Connection"]
        assert len(arp_creds) == 2
        assert len(tcp_creds) == 1
