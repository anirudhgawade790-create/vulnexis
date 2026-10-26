"""
Tests for NetworkScanner: mocks nmap.PortScanner so no actual nmap is needed.
"""

import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── nmap mock setup ────────────────────────────────────────────────────────────

def _make_nmap_mock():
    """Create a minimal nmap module mock."""
    nmap_mod = ModuleType("nmap")

    class FakePortScanner:
        def __init__(self):
            self._hosts = {}

        def scan(self, hosts="", arguments=""):
            pass  # no-op by default; tests override via instance methods

        def all_hosts(self):
            return list(self._hosts.keys())

        def __getitem__(self, host):
            return self._hosts[host]

    nmap_mod.PortScanner = FakePortScanner
    return nmap_mod


# Inject fake nmap before importing the scanner
_nmap_mod = _make_nmap_mock()
sys.modules.setdefault("nmap", _nmap_mod)


from app.scanners.base import ScanConfig, ScanProgressEvent  # noqa: E402
from app.scanners.network_scanner import NetworkScanner  # noqa: E402


# ── _parse_nmap_host ───────────────────────────────────────────────────────────

class FakeHostData:
    """Simulates an nmap PortScanner host result object."""

    _SENTINEL = object()

    def __init__(self, ip="192.168.1.1", hostnames=_SENTINEL, ports=None, os_match=None):
        self._ip = ip
        self._hostnames = [{"name": "test.local"}] if hostnames is FakeHostData._SENTINEL else hostnames
        self._ports = ports or {}  # {proto: {port: {state, name, version, product, extrainfo}}}
        self._os = os_match or []

    def get(self, key, default=None):
        mapping = {
            "addresses": {"ipv4": self._ip},
            "hostnames": self._hostnames,
            "osmatch": self._os,
        }
        return mapping.get(key, default)

    def state(self):
        return "up"

    def all_protocols(self):
        return list(self._ports.keys())

    def __getitem__(self, proto):
        return self._ports[proto]


def test_parse_nmap_host_basic():
    scanner = NetworkScanner()
    host = FakeHostData(
        ip="10.0.0.1",
        hostnames=[{"name": "myhost.local"}],
        ports={
            "tcp": {
                80: {"state": "open", "name": "http", "version": "Apache 2.4", "product": "Apache", "extrainfo": ""},
                443: {"state": "open", "name": "https", "version": "", "product": "", "extrainfo": ""},
            }
        },
        os_match=[{"name": "Linux 4.x"}],
    )
    result = scanner._parse_nmap_host(host)

    assert result["ip"] == "10.0.0.1"
    assert result["hostname"] == "myhost.local"
    assert result["os_guess"] == "Linux 4.x"
    assert len(result["open_ports"]) == 2

    ports_by_num = {p["port"]: p for p in result["open_ports"]}
    assert 80 in ports_by_num
    assert ports_by_num[80]["service"] == "http"
    assert ports_by_num[80]["version"] == "Apache 2.4"
    assert 443 in ports_by_num


def test_parse_nmap_host_no_ports():
    scanner = NetworkScanner()
    host = FakeHostData(ip="10.0.0.2", ports={})
    result = scanner._parse_nmap_host(host)

    assert result["ip"] == "10.0.0.2"
    assert result["open_ports"] == []


def test_parse_nmap_host_no_hostname():
    scanner = NetworkScanner()
    host = FakeHostData(ip="10.0.0.3", hostnames=[])
    result = scanner._parse_nmap_host(host)

    assert result["hostname"] == ""


def test_parse_nmap_host_closed_ports_excluded():
    """Closed/filtered ports must not appear in open_ports."""
    scanner = NetworkScanner()
    host = FakeHostData(
        ip="10.0.0.4",
        ports={
            "tcp": {
                22: {"state": "open", "name": "ssh", "version": "OpenSSH 8.0", "product": "", "extrainfo": ""},
                8080: {"state": "closed", "name": "http-alt", "version": "", "product": "", "extrainfo": ""},
                9090: {"state": "filtered", "name": "", "version": "", "product": "", "extrainfo": ""},
            }
        },
    )
    result = scanner._parse_nmap_host(host)
    port_numbers = [p["port"] for p in result["open_ports"]]
    assert 22 in port_numbers
    assert 8080 not in port_numbers
    assert 9090 not in port_numbers


# ── _detect_risky_services ─────────────────────────────────────────────────────

def test_detect_risky_services_rdp():
    scanner = NetworkScanner()
    ports = [{"port": 3389, "protocol": "tcp", "service": "", "version": "", "banner": ""}]
    risky = scanner._detect_risky_services(ports)
    assert len(risky) == 1
    assert risky[0]["port"] == 3389
    assert risky[0]["service"] == "rdp"
    assert risky[0]["severity"] == "high"


def test_detect_risky_services_smb():
    scanner = NetworkScanner()
    ports = [{"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": "", "banner": ""}]
    risky = scanner._detect_risky_services(ports)
    assert len(risky) == 1
    assert risky[0]["port"] == 445
    assert risky[0]["severity"] == "high"


def test_detect_risky_services_telnet():
    scanner = NetworkScanner()
    ports = [{"port": 23, "protocol": "tcp", "service": "telnet", "version": "", "banner": ""}]
    risky = scanner._detect_risky_services(ports)
    assert len(risky) == 1
    assert risky[0]["port"] == 23
    assert risky[0]["severity"] == "high"


def test_detect_risky_services_multiple():
    scanner = NetworkScanner()
    ports = [
        {"port": 21, "protocol": "tcp", "service": "ftp", "version": "", "banner": ""},
        {"port": 23, "protocol": "tcp", "service": "telnet", "version": "", "banner": ""},
        {"port": 3389, "protocol": "tcp", "service": "rdp", "version": "", "banner": ""},
        {"port": 80, "protocol": "tcp", "service": "http", "version": "", "banner": ""},  # not risky
    ]
    risky = scanner._detect_risky_services(ports)
    risky_ports = [r["port"] for r in risky]
    assert 21 in risky_ports
    assert 23 in risky_ports
    assert 3389 in risky_ports
    assert 80 not in risky_ports


def test_detect_risky_services_none():
    scanner = NetworkScanner()
    ports = [{"port": 80, "protocol": "tcp", "service": "http", "version": "", "banner": ""}]
    risky = scanner._detect_risky_services(ports)
    assert risky == []


# ── validate_scope ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_validate_scope_valid_ip():
    scanner = NetworkScanner()
    config = ScanConfig(target_ips=["192.168.1.1"])
    assert await scanner.validate_scope(config) is True


@pytest.mark.asyncio
async def test_validate_scope_valid_cidr():
    scanner = NetworkScanner()
    config = ScanConfig(target_ips=["10.0.0.0/24"])
    assert await scanner.validate_scope(config) is True


@pytest.mark.asyncio
async def test_validate_scope_invalid():
    scanner = NetworkScanner()
    config = ScanConfig(target_ips=["not-an-ip"])
    assert await scanner.validate_scope(config) is False


@pytest.mark.asyncio
async def test_validate_scope_empty():
    scanner = NetworkScanner()
    config = ScanConfig(target_ips=[])
    assert await scanner.validate_scope(config) is False


# ── scan progress events ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_emits_progress_events():
    """Scan should yield ScanProgressEvent objects with progress 0–100."""
    scanner = NetworkScanner()

    # Create a controlled nmap mock that returns no hosts (simplest path)
    mock_nm = _make_nmap_mock()
    # Override scan to do nothing, all_hosts returns []
    mock_nm.PortScanner.return_value = MagicMock(
        scan=MagicMock(return_value=None),
        all_hosts=MagicMock(return_value=[]),
    ) if False else None  # won't use this path

    # Use the existing module-level _nmap_mod but make PortScanner return empty results
    class EmptyScanner:
        def scan(self, hosts="", arguments=""):
            pass
        def all_hosts(self):
            return []
        def __getitem__(self, host):
            raise KeyError(host)

    import sys
    orig_nmap = sys.modules.get("nmap")
    test_nmap = ModuleType("nmap")
    test_nmap.PortScanner = lambda: EmptyScanner()
    sys.modules["nmap"] = test_nmap

    try:
        config = ScanConfig(
            target_ips=["192.168.1.1"],
            options={"scan_job_id": "test-scan-001", "timeout": 1},
        )

        events = []
        async for evt in scanner.scan(config):
            events.append(evt)
    finally:
        if orig_nmap is not None:
            sys.modules["nmap"] = orig_nmap
        else:
            sys.modules["nmap"] = _nmap_mod  # restore module-level mock

    assert len(events) >= 2
    assert all(isinstance(e, ScanProgressEvent) for e in events)
    assert events[0].progress >= 0
    assert events[-1].progress == 100 or events[-1].phase == "completed"


@pytest.mark.asyncio
async def test_scan_progress_events_have_scan_job_id():
    """All emitted events must carry the scan_job_id from config.options."""
    scanner = NetworkScanner()

    class EmptyScanner:
        def scan(self, hosts="", arguments=""):
            pass
        def all_hosts(self):
            return []

    import sys
    orig_nmap = sys.modules.get("nmap")
    test_nmap = ModuleType("nmap")
    test_nmap.PortScanner = lambda: EmptyScanner()
    sys.modules["nmap"] = test_nmap

    try:
        config = ScanConfig(
            target_ips=["10.10.10.1"],
            options={"scan_job_id": "my-job-xyz"},
        )
        events = []
        async for evt in scanner.scan(config):
            events.append(evt)
    finally:
        if orig_nmap is not None:
            sys.modules["nmap"] = orig_nmap
        else:
            sys.modules["nmap"] = _nmap_mod

    for evt in events:
        assert evt.scan_job_id == "my-job-xyz"


@pytest.mark.asyncio
async def test_get_results_empty():
    scanner = NetworkScanner()
    result = await scanner.get_results()
    assert result.assets == []
    assert result.findings == []
    assert result.errors == []
