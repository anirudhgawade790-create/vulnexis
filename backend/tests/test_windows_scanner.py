"""
Tests for WindowsScanner: mocks winrm.Protocol/Session so no real WinRM needed.
"""

import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


# ── winrm mock setup ───────────────────────────────────────────────────────────

def _make_winrm_mock():
    winrm_mod = ModuleType("winrm")

    class FakeResponse:
        def __init__(self, stdout=b"", stderr=b"", status_code=0):
            self.std_out = stdout
            self.std_err = stderr
            self.status_code = status_code

    class FakeSession:
        def __init__(self, *args, **kwargs):
            self._responses: dict[str, bytes] = {}

        def set_response(self, command: str, stdout: bytes):
            self._responses[command] = stdout

        def run_ps(self, command: str) -> FakeResponse:
            return FakeResponse(stdout=self._responses.get(command, b"{}"))

    class FakeProtocol:
        def __init__(self, *args, **kwargs):
            pass

    winrm_mod.Session = FakeSession
    winrm_mod.Protocol = FakeProtocol
    winrm_mod.Response = FakeResponse
    return winrm_mod


_winrm_mod = _make_winrm_mock()
sys.modules.setdefault("winrm", _winrm_mod)

from app.scanners.base import ScanConfig, ScanProgressEvent  # noqa: E402
from app.scanners.windows_scanner import WindowsScanner  # noqa: E402


# ── helpers ────────────────────────────────────────────────────────────────────

def _make_session(responses: dict[str, bytes] | None = None):
    """Create a FakeSession with optional pre-configured responses."""
    session = _winrm_mod.Session("192.168.1.1", auth=("user", "pass"))
    for cmd, resp in (responses or {}).items():
        session.set_response(cmd, resp)
    return session


# ── check_os_version ───────────────────────────────────────────────────────────

def test_check_os_version_success():
    scanner = WindowsScanner()
    output = b'{"Caption": "Windows Server 2022", "Version": "10.0.20348", "BuildNumber": "20348"}'
    cmd = "Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Json"
    session = _make_session({cmd: output})
    result = scanner.check_os_version(session)

    assert result["check_name"] == "os_version"
    assert result["result"] == "collected"
    assert result["confidence"] == "confirmed"
    assert result["error"] is None
    assert "Windows Server 2022" in result["evidence"]


def test_check_os_version_error():
    scanner = WindowsScanner()
    session = MagicMock()
    session.run_ps.side_effect = ConnectionError("refused")
    result = scanner.check_os_version(session)

    assert result["result"] == "error"
    assert result["confidence"] == "low"
    assert result["error"] is not None


# ── check_missing_patches ─────────────────────────────────────────────────────

def test_check_missing_patches_success():
    scanner = WindowsScanner()
    output = b'[{"HotFixID": "KB5021234", "InstalledOn": "2024-01-15"}]'
    cmd = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID, InstalledOn | ConvertTo-Json"
    session = _make_session({cmd: output})
    results = scanner.check_missing_patches(session)

    assert isinstance(results, list)
    assert len(results) >= 1
    assert results[0]["check_name"] == "missing_patches"
    assert results[0]["result"] == "collected"


def test_check_missing_patches_error():
    scanner = WindowsScanner()
    session = MagicMock()
    session.run_ps.side_effect = OSError("timeout")
    results = scanner.check_missing_patches(session)

    assert isinstance(results, list)
    assert results[0]["result"] == "error"
    assert results[0]["confidence"] == "low"


# ── check_defender_status ─────────────────────────────────────────────────────

def test_check_defender_status_enabled():
    scanner = WindowsScanner()
    output = b'{"AMServiceEnabled": true, "AntispywareEnabled": true, "AntivirusEnabled": true, "RealTimeProtectionEnabled": true}'
    cmd = "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json"
    session = _make_session({cmd: output})
    result = scanner.check_defender_status(session)

    assert result["check_name"] == "defender_status"
    assert result["result"] == "enabled"
    assert result["is_vulnerable"] is False


def test_check_defender_status_disabled():
    scanner = WindowsScanner()
    output = b'{"AMServiceEnabled": false, "AntispywareEnabled": false, "AntivirusEnabled": false, "RealTimeProtectionEnabled": false}'
    cmd = "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json"
    session = _make_session({cmd: output})
    result = scanner.check_defender_status(session)

    assert result["is_vulnerable"] is True
    assert result["severity"] == "high"


# ── check_firewall_config ─────────────────────────────────────────────────────

def test_check_firewall_config_all_enabled():
    scanner = WindowsScanner()
    output = b'[{"Name": "Domain", "Enabled": true}, {"Name": "Private", "Enabled": true}, {"Name": "Public", "Enabled": true}]'
    cmd = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    session = _make_session({cmd: output})
    result = scanner.check_firewall_config(session)

    assert result["result"] == "enabled"
    assert result["is_vulnerable"] is False


def test_check_firewall_config_partially_disabled():
    scanner = WindowsScanner()
    output = b'[{"Name": "Domain", "Enabled": true}, {"Name": "Public", "Enabled": false}]'
    cmd = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    session = _make_session({cmd: output})
    result = scanner.check_firewall_config(session)

    assert result["is_vulnerable"] is True
    assert result["severity"] == "high"


# ── check_smb_config ──────────────────────────────────────────────────────────

def test_check_smb_config_smb1_enabled():
    scanner = WindowsScanner()
    output = b'{"EnableSMB1Protocol": true, "EnableSMB2Protocol": true, "RequireSecuritySignature": false}'
    cmd = "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature | ConvertTo-Json"
    session = _make_session({cmd: output})
    result = scanner.check_smb_config(session)

    assert result["is_vulnerable"] is True
    assert result["severity"] == "critical"


def test_check_smb_config_smb1_disabled():
    scanner = WindowsScanner()
    output = b'{"EnableSMB1Protocol": false, "EnableSMB2Protocol": true, "RequireSecuritySignature": true}'
    cmd = "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature | ConvertTo-Json"
    session = _make_session({cmd: output})
    result = scanner.check_smb_config(session)

    assert result["is_vulnerable"] is False
    assert result["result"] == "ok"


# ── check_rdp_config ──────────────────────────────────────────────────────────

def test_check_rdp_config_enabled():
    scanner = WindowsScanner()
    output = b'{"fDenyTSConnections": 0}'
    cmd = r"Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections | Select-Object fDenyTSConnections | ConvertTo-Json"
    session = _make_session({cmd: output})
    result = scanner.check_rdp_config(session)

    assert result["result"] == "enabled"
    assert result["is_vulnerable"] is True


def test_check_rdp_config_disabled():
    scanner = WindowsScanner()
    output = b'{"fDenyTSConnections": 1}'
    cmd = r"Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections | Select-Object fDenyTSConnections | ConvertTo-Json"
    session = _make_session({cmd: output})
    result = scanner.check_rdp_config(session)

    assert result["result"] == "disabled"
    assert result["is_vulnerable"] is False


# ── check_risky_services ──────────────────────────────────────────────────────

def test_check_risky_services_none_found():
    scanner = WindowsScanner()
    output = b'[{"Name": "Spooler", "DisplayName": "Print Spooler", "Status": "Running"}]'
    cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status | ConvertTo-Json"
    session = _make_session({cmd: output})
    results = scanner.check_risky_services(session)

    assert all(not r.get("is_vulnerable") for r in results)


def test_check_risky_services_telnet_found():
    scanner = WindowsScanner()
    # Include "telnet" in the output to trigger detection
    output = b'[{"Name": "telnet", "DisplayName": "Telnet", "Status": "Running"}]'
    cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status | ConvertTo-Json"
    session = _make_session({cmd: output})
    results = scanner.check_risky_services(session)

    found = [r for r in results if r.get("is_vulnerable")]
    assert len(found) >= 1
    assert found[0]["severity"] == "high"


# ── WinRM graceful failure ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_winrm_connection_refused_creates_error_finding():
    """When WinRM refuses connection, scanner records error finding and continues."""
    scanner = WindowsScanner()

    # Patch the winrm module in sys.modules directly since it's imported lazily inside scan()
    mock_winrm = MagicMock()
    mock_winrm.Protocol.side_effect = ConnectionRefusedError("Connection refused")
    mock_winrm.Session.side_effect = ConnectionRefusedError("Connection refused")

    import sys
    orig = sys.modules.get("winrm")
    sys.modules["winrm"] = mock_winrm
    try:
        config = ScanConfig(
            target_ips=["192.168.1.99"],
            options={"username": "admin", "password": "pass", "scan_job_id": "test-job-001"},
        )
        events = []
        async for evt in scanner.scan(config):
            events.append(evt)
    finally:
        if orig is not None:
            sys.modules["winrm"] = orig
        else:
            del sys.modules["winrm"]

    result = await scanner.get_results()
    # Should have an error finding, not crash
    assert len(result.errors) >= 1 or len(result.findings) >= 1
    error_findings = [f for f in result.findings if f.get("check_name") == "winrm_connect"]
    assert len(error_findings) >= 1
    assert error_findings[0]["confidence"] == "low"


@pytest.mark.asyncio
async def test_winrm_does_not_mark_host_secure_on_failure():
    """A WinRM failure must NOT produce a 'secure' or positive finding."""
    scanner = WindowsScanner()

    mock_winrm = MagicMock()
    mock_winrm.Protocol.side_effect = Exception("Timeout")
    mock_winrm.Session.side_effect = Exception("Timeout")

    import sys
    orig = sys.modules.get("winrm")
    sys.modules["winrm"] = mock_winrm
    try:
        config = ScanConfig(
            target_ips=["192.168.1.50"],
            options={"username": "u", "password": "p", "scan_job_id": "test-job-002"},
        )
        async for _ in scanner.scan(config):
            pass
    finally:
        if orig is not None:
            sys.modules["winrm"] = orig
        else:
            del sys.modules["winrm"]

    result = await scanner.get_results()
    # All findings should reflect failure/inaccessible, not a clean bill of health
    for finding in result.findings:
        assert finding.get("confidence") != "confirmed"
        assert finding.get("result") != "secure"


@pytest.mark.asyncio
async def test_scan_emits_start_and_completion_events():
    """Scan must yield at least a start event and a completed event."""
    # Uses the module-level _winrm_mod mock (FakeSession returns {} for any command)
    scanner = WindowsScanner()

    config = ScanConfig(
        target_ips=["10.0.0.1"],
        options={"username": "admin", "password": "pass", "scan_job_id": "test-win-001"},
    )
    events = []
    async for evt in scanner.scan(config):
        events.append(evt)

    phases = [e.phase for e in events]
    assert "windows_assessment" in phases
    assert "completed" in phases
    assert events[-1].progress == 100


@pytest.mark.asyncio
async def test_validate_scope_requires_credentials():
    scanner = WindowsScanner()
    config_no_creds = ScanConfig(target_ips=["10.0.0.1"], options={})
    assert await scanner.validate_scope(config_no_creds) is False

    config_with_creds = ScanConfig(
        target_ips=["10.0.0.1"], options={"username": "u", "password": "p"}
    )
    assert await scanner.validate_scope(config_with_creds) is True
