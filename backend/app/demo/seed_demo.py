"""
Demo data seeder — creates deterministic sample data using fixed UUIDs.
Running this script twice produces the same result (idempotent).

Usage:
    cd backend && python -m app.demo.seed_demo
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, async_engine, Base
from app.models.user import User
from app.models.target import Target
from app.models.scan_job import ScanJob
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.finding import Finding
from app.models.baseline_policy import BaselinePolicy
from app.models.audit_log import AuditLog
from app.services.auth_service import hash_password

logger = logging.getLogger(__name__)

# ── Fixed UUIDs (deterministic) ────────────────────────────────────────────
ADMIN_ID    = "00000000-0000-0000-0000-000000000001"
ANALYST_ID  = "00000000-0000-0000-0000-000000000002"
VIEWER_ID   = "00000000-0000-0000-0000-000000000003"

TARGET_CORP_ID = "00000000-0000-0001-0000-000000000001"
TARGET_DMZ_ID  = "00000000-0000-0001-0000-000000000002"

SCAN1_ID = "00000000-0000-0002-0000-000000000001"
SCAN2_ID = "00000000-0000-0002-0000-000000000002"
SCAN3_ID = "00000000-0000-0002-0000-000000000003"

ASSET_DC01_ID     = "00000000-0000-0003-0000-000000000001"
ASSET_FILE01_ID   = "00000000-0000-0003-0000-000000000002"
ASSET_WEB01_ID    = "00000000-0000-0003-0000-000000000003"
ASSET_SQL01_ID    = "00000000-0000-0003-0000-000000000004"
ASSET_ADMIN01_ID  = "00000000-0000-0003-0000-000000000005"
ASSET_WS001_ID    = "00000000-0000-0003-0000-000000000006"
ASSET_WS002_ID    = "00000000-0000-0003-0000-000000000007"
ASSET_WS003_ID    = "00000000-0000-0003-0000-000000000008"
ASSET_NGINX_ID    = "00000000-0000-0003-0000-000000000009"
ASSET_MON_ID      = "00000000-0000-0003-0000-000000000010"
ASSET_ROUTER_ID   = "00000000-0000-0003-0000-000000000011"
ASSET_UNKNOWN_ID  = "00000000-0000-0003-0000-000000000012"

VULN_LOG4SHELL_ID     = "00000000-0000-0004-0000-000000000001"
VULN_PRINTNIGHTMARE_ID = "00000000-0000-0004-0000-000000000002"
VULN_ZEROLOGON_ID     = "00000000-0000-0004-0000-000000000003"
VULN_ETERNALBLUE_ID   = "00000000-0000-0004-0000-000000000004"
VULN_PROXYLOGON_ID    = "00000000-0000-0004-0000-000000000005"

POLICY_ID = "00000000-0000-0005-0000-000000000001"

# ── Helpers ─────────────────────────────────────────────────────────────────
now = datetime.now(timezone.utc)


def dt(days_ago: int = 0) -> datetime:
    return now - timedelta(days=days_ago)


async def _upsert(db: AsyncSession, model_cls, pk_val: str, **kwargs):
    """Insert if not exists, skip if already present."""
    result = await db.execute(
        select(model_cls).where(model_cls.id == pk_val)
    )
    obj = result.scalar_one_or_none()
    if obj is None:
        obj = model_cls(id=pk_val, **kwargs)
        db.add(obj)
    return obj


async def seed(db: AsyncSession) -> None:
    logger.info("Seeding demo data…")

    # ── Users ────────────────────────────────────────────────────────────────
    await _upsert(db, User, ADMIN_ID,
        username="admin", email="admin@demo.local",
        hashed_password=hash_password("Admin@1234"),
        role="admin", full_name="Demo Admin", is_active=True,
        created_at=dt(30), updated_at=dt(1))
    await _upsert(db, User, ANALYST_ID,
        username="analyst", email="analyst@demo.local",
        hashed_password=hash_password("Analyst@1234"),
        role="analyst", full_name="Demo Analyst", is_active=True,
        created_at=dt(30), updated_at=dt(1))
    await _upsert(db, User, VIEWER_ID,
        username="viewer", email="viewer@demo.local",
        hashed_password=hash_password("Viewer@1234"),
        role="viewer", full_name="Demo Viewer", is_active=True,
        created_at=dt(30), updated_at=dt(1))

    # ── Targets ──────────────────────────────────────────────────────────────
    await _upsert(db, Target, TARGET_CORP_ID,
        name="Corporate LAN", scope_type="cidr", scope_value="192.168.1.0/24",
        business_criticality="high", is_active=True, created_by=ADMIN_ID,
        created_at=dt(30), updated_at=dt(1))
    await _upsert(db, Target, TARGET_DMZ_ID,
        name="DMZ Segment", scope_type="cidr", scope_value="10.10.10.0/24",
        business_criticality="critical", is_active=True, created_by=ADMIN_ID,
        created_at=dt(30), updated_at=dt(1))

    # ── Scan Jobs ─────────────────────────────────────────────────────────────
    await _upsert(db, ScanJob, SCAN1_ID,
        target_id=TARGET_CORP_ID, scan_type="full", status="completed",
        progress=100, started_by=ADMIN_ID,
        started_at=dt(7), completed_at=dt(7), created_at=dt(7))
    await _upsert(db, ScanJob, SCAN2_ID,
        target_id=TARGET_CORP_ID, scan_type="full", status="completed",
        progress=100, started_by=ANALYST_ID,
        started_at=dt(1), completed_at=dt(1), created_at=dt(1))
    await _upsert(db, ScanJob, SCAN3_ID,
        target_id=TARGET_DMZ_ID, scan_type="network", status="completed",
        progress=100, started_by=ADMIN_ID,
        started_at=dt(3), completed_at=dt(3), created_at=dt(3))

    # ── Vulnerabilities (5 KEV + high-profile) ──────────────────────────────
    await _upsert(db, Vulnerability, VULN_LOG4SHELL_ID,
        cve_id="CVE-2021-44228", title="Log4Shell Remote Code Execution",
        description="Apache Log4j2 JNDI lookup RCE vulnerability (CVSS 10.0).",
        cvss_v3_score=10.0, severity="critical", is_kev=True,
        patch_available=True, source="NVD", fetched_at=now)
    await _upsert(db, Vulnerability, VULN_PRINTNIGHTMARE_ID,
        cve_id="CVE-2021-34527", title="PrintNightmare Windows Print Spooler RCE",
        description="Windows Print Spooler allows remote code execution (CVSS 8.8).",
        cvss_v3_score=8.8, severity="high", is_kev=True,
        patch_available=True, source="NVD", fetched_at=now)
    await _upsert(db, Vulnerability, VULN_ZEROLOGON_ID,
        cve_id="CVE-2020-1472", title="Zerologon Netlogon Privilege Escalation",
        description="Netlogon allows privilege escalation to domain admin (CVSS 10.0).",
        cvss_v3_score=10.0, severity="critical", is_kev=True,
        patch_available=True, source="NVD", fetched_at=now)
    await _upsert(db, Vulnerability, VULN_ETERNALBLUE_ID,
        cve_id="CVE-2017-0144", title="EternalBlue SMBv1 Remote Code Execution",
        description="SMBv1 MS17-010 allows remote code execution without authentication (CVSS 9.3).",
        cvss_v3_score=9.3, severity="critical", is_kev=True,
        patch_available=True, source="NVD", fetched_at=now)
    await _upsert(db, Vulnerability, VULN_PROXYLOGON_ID,
        cve_id="CVE-2021-26855", title="Exchange ProxyLogon SSRF",
        description="Microsoft Exchange Server SSRF leading to RCE (CVSS 9.8).",
        cvss_v3_score=9.8, severity="critical", is_kev=True,
        patch_available=True, source="NVD", fetched_at=now)

    # ── Assets ──────────────────────────────────────────────────────────────
    win_ports = [{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}, {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server"}]

    await _upsert(db, Asset, ASSET_DC01_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.10",
        hostname="DC01.corp.local", is_windows=True, asset_type="server",
        business_criticality="critical", os_name="Windows Server 2019",
        open_ports=win_ports + [{"port": 88, "protocol": "tcp", "service": "kerberos"}],
        windows_details={"patch_count": 3, "defender_status": "enabled", "smb_version": "SMBv2", "rdp_enabled": True},
        risk_score=9.2, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_FILE01_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.11",
        hostname="FILE01.corp.local", is_windows=True, asset_type="server",
        business_criticality="high", os_name="Windows Server 2016",
        open_ports=win_ports,
        windows_details={"patch_count": 0, "defender_status": "disabled", "smb_version": "SMBv1", "rdp_enabled": True},
        risk_score=9.8, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_WEB01_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.20",
        hostname="WEB01.corp.local", is_windows=True, asset_type="server",
        business_criticality="high", os_name="Windows Server 2022",
        open_ports=[{"port": 80, "protocol": "tcp", "service": "http"}, {"port": 443, "protocol": "tcp", "service": "https"}],
        windows_details={"patch_count": 10, "defender_status": "enabled", "smb_version": "SMBv3", "rdp_enabled": False},
        risk_score=5.5, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_SQL01_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.30",
        hostname="SQL01.corp.local", is_windows=True, asset_type="server",
        business_criticality="critical", os_name="Windows Server 2019",
        open_ports=[{"port": 1433, "protocol": "tcp", "service": "ms-sql-s"}, {"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
        windows_details={"patch_count": 5, "defender_status": "enabled", "smb_version": "SMBv2", "rdp_enabled": False},
        risk_score=7.1, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_ADMIN01_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.50",
        hostname="ADMIN01.corp.local", is_windows=True, asset_type="workstation",
        business_criticality="high", os_name="Windows 10 Pro",
        open_ports=win_ports,
        windows_details={"patch_count": 2, "defender_status": "enabled", "smb_version": "SMBv2", "rdp_enabled": True},
        risk_score=6.8, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_WS001_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.100",
        hostname="WS001.corp.local", is_windows=True, asset_type="workstation",
        business_criticality="low", os_name="Windows 10",
        open_ports=[{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
        windows_details={"patch_count": 1, "defender_status": "enabled", "smb_version": "SMBv2", "rdp_enabled": False},
        risk_score=4.0, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_WS002_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.101",
        hostname="WS002.corp.local", is_windows=True, asset_type="workstation",
        business_criticality="low", os_name="Windows 11",
        open_ports=[{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
        windows_details={"patch_count": 8, "defender_status": "enabled", "smb_version": "SMBv3", "rdp_enabled": False},
        risk_score=2.5, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_WS003_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.102",
        hostname="WS003.corp.local", is_windows=True, asset_type="workstation",
        business_criticality="medium", os_name="Windows 10",
        open_ports=[{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
        windows_details={"patch_count": 0, "defender_status": "disabled", "smb_version": "SMBv1", "rdp_enabled": True},
        risk_score=7.5, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_NGINX_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.200",
        hostname="nginx.corp.local", is_windows=False, asset_type="server",
        business_criticality="medium", os_name="Ubuntu 22.04",
        open_ports=[{"port": 80, "protocol": "tcp", "service": "http"}, {"port": 443, "protocol": "tcp", "service": "https"}],
        risk_score=3.0, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_MON_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.201",
        hostname="monitoring.corp.local", is_windows=False, asset_type="server",
        business_criticality="medium", os_name="Ubuntu 22.04",
        open_ports=[{"port": 9090, "protocol": "tcp", "service": "prometheus"}],
        risk_score=2.0, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_ROUTER_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.1",
        hostname=None, is_windows=False, asset_type="network_device",
        business_criticality="critical",
        open_ports=[{"port": 80, "protocol": "tcp", "service": "http"}, {"port": 22, "protocol": "tcp", "service": "ssh"}],
        risk_score=6.0, last_seen_at=dt(1), created_at=dt(7), updated_at=dt(1))
    await _upsert(db, Asset, ASSET_UNKNOWN_ID,
        scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID, ip_address="192.168.1.250",
        hostname=None, is_windows=False, asset_type="unknown",
        business_criticality="low", open_ports=[],
        risk_score=1.0, last_seen_at=dt(7), created_at=dt(7), updated_at=dt(7))

    # ── Findings (sample set) ─────────────────────────────────────────────────
    findings_data = [
        dict(id="00000000-0000-0006-0000-000000000001",
             scan_job_id=SCAN1_ID, asset_id=ASSET_FILE01_ID,
             vulnerability_id=VULN_ETERNALBLUE_ID,
             title="SMBv1 Enabled — EternalBlue Risk",
             finding_type="confirmed_vulnerability", severity="critical", status="open",
             check_name="smb_version_check", evidence="SMBv1 detected via service banner on port 445.",
             detection_method="network_scan", confidence="confirmed", risk_score=9.5),
        dict(id="00000000-0000-0006-0000-000000000002",
             scan_job_id=SCAN1_ID, asset_id=ASSET_DC01_ID,
             vulnerability_id=VULN_ZEROLOGON_ID,
             title="Domain Controller potentially vulnerable to Zerologon",
             finding_type="potential_vulnerability", severity="critical", status="open",
             check_name="zerologon_check", evidence="Windows Server 2019 with patch_count=3. Patch status unverified.",
             detection_method="version_check", confidence="medium", risk_score=9.0),
        dict(id="00000000-0000-0006-0000-000000000003",
             scan_job_id=SCAN1_ID, asset_id=ASSET_FILE01_ID,
             vulnerability_id=None,
             title="Windows Defender disabled on file server",
             finding_type="misconfiguration", severity="high", status="open",
             check_name="defender_status_check", evidence="defender_status=disabled in Windows configuration.",
             detection_method="winrm_check", confidence="confirmed", risk_score=8.5),
        dict(id="00000000-0000-0006-0000-000000000004",
             scan_job_id=SCAN1_ID, asset_id=ASSET_WS003_ID,
             vulnerability_id=None,
             title="RDP exposed with no patch history",
             finding_type="network_exposure", severity="high", status="open",
             check_name="rdp_exposure_check", evidence="RDP port 3389 open; patch_count=0.",
             detection_method="network_scan", confidence="confirmed", risk_score=8.0),
        dict(id="00000000-0000-0006-0000-000000000005",
             scan_job_id=SCAN1_ID, asset_id=ASSET_ROUTER_ID,
             vulnerability_id=None,
             title="Router HTTP management interface exposed",
             finding_type="network_exposure", severity="medium", status="open",
             check_name="admin_interface_check", evidence="HTTP port 80 open on network device 192.168.1.1.",
             detection_method="network_scan", confidence="high", risk_score=6.0),
    ]

    for fd in findings_data:
        await _upsert(db, Finding, fd.pop("id"),
                      first_seen_at=dt(7), last_seen_at=dt(1), **fd)

    # ── Baseline Policy ──────────────────────────────────────────────────────
    controls = [
        {"id": f"CIS-{i:02d}", "title": f"CIS Control {i}", "severity": "high",
         "description": f"CIS Windows Server 2019 control {i}", "check_command": "", "expected_result": ""}
        for i in range(1, 21)
    ]
    await _upsert(db, BaselinePolicy, POLICY_ID,
        name="CIS Windows Server 2019 Benchmark v1.0",
        description="Center for Internet Security Windows Server 2019 benchmark.",
        framework="cis_windows", version="1.0", controls=controls,
        is_active=True, created_by=ADMIN_ID, created_at=dt(30), updated_at=dt(1))

    await db.flush()
    logger.info("Demo data seed complete.")


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    # Ensure tables exist (demo mode convenience)
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        await seed(db)
        await db.commit()
    print("Demo seed complete.")


if __name__ == "__main__":
    asyncio.run(main())
