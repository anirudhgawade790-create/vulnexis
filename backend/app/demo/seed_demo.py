"""
Demo data seeder — creates deterministic sample data using fixed UUIDs.
Running this script twice produces the same result (idempotent).

Usage:
    cd backend && python -m app.demo.seed_demo

Idempotency: an ``is_demo_seeded`` guard queries the user count before doing
any work. If users already exist the seeder skips everything and prints
"already seeded". Individual inserts additionally use a select-then-skip
``_upsert`` helper so re-running never raises a constraint violation.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, async_engine, Base
from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.baseline_policy import BaselinePolicy
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.models.target import Target
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services.auth_service import hash_password

logger = logging.getLogger(__name__)

# ── Deterministic UUID namespace (uuid5) ───────────────────────────────────
DEMO_NAMESPACE = uuid.UUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")


def uuid5(name: str) -> str:
    """Return a deterministic UUID string derived from a fixed name."""
    return str(uuid.uuid5(DEMO_NAMESPACE, name))


# ── Fixed UUIDs for top-level entities ──────────────────────────────────────
ADMIN_ID = "00000000-0000-0000-0000-000000000001"
ANALYST_ID = "00000000-0000-0000-0000-000000000002"
VIEWER_ID = "00000000-0000-0000-0000-000000000003"

TARGET_CORP_ID = "00000000-0000-0001-0000-000000000001"
TARGET_DMZ_ID = "00000000-0000-0001-0000-000000000002"

SCAN1_ID = "00000000-0000-0002-0000-000000000001"
SCAN2_ID = "00000000-0000-0002-0000-000000000002"
SCAN3_ID = "00000000-0000-0002-0000-000000000003"

# 12 corporate hosts — all created in scan_1, re-scanned in scan_2 (per-scan
# asset model; UNIQUE constraint is on scan_job_id + ip_address).
ASSET_DC01_ID = uuid5("asset:dc01")
ASSET_FILE01_ID = uuid5("asset:file01")
ASSET_WEB01_ID = uuid5("asset:web01")
ASSET_SQL01_ID = uuid5("asset:sql01")
ASSET_ADMIN01_ID = uuid5("asset:admin01")
ASSET_WS001_ID = uuid5("asset:ws001")
ASSET_WS002_ID = uuid5("asset:ws002")
ASSET_WS003_ID = uuid5("asset:ws003")
ASSET_NGINX_ID = uuid5("asset:nginx")
ASSET_MON_ID = uuid5("asset:monitor")
ASSET_ROUTER_ID = uuid5("asset:router")
ASSET_UNKNOWN_ID = uuid5("asset:unknown")

# scan_2 re-scan copies (same IPs, distinct records)
ASSET_DC01_S2_ID = uuid5("asset:dc01:scan2")
ASSET_FILE01_S2_ID = uuid5("asset:file01:scan2")
ASSET_WEB01_S2_ID = uuid5("asset:web01:scan2")
ASSET_SQL01_S2_ID = uuid5("asset:sql01:scan2")
ASSET_ADMIN01_S2_ID = uuid5("asset:admin01:scan2")
ASSET_WS001_S2_ID = uuid5("asset:ws001:scan2")
ASSET_WS002_S2_ID = uuid5("asset:ws002:scan2")
ASSET_WS003_S2_ID = uuid5("asset:ws003:scan2")
ASSET_NGINX_S2_ID = uuid5("asset:nginx:scan2")
ASSET_MON_S2_ID = uuid5("asset:monitor:scan2")
ASSET_ROUTER_S2_ID = uuid5("asset:router:scan2")
ASSET_UNKNOWN_S2_ID = uuid5("asset:unknown:scan2")

VULN_LOG4SHELL_ID = uuid5("vuln:cve-2021-44228")
VULN_PRINTNIGHTMARE_ID = uuid5("vuln:cve-2021-34527")
VULN_ZEROLOGON_ID = uuid5("vuln:cve-2020-1472")
VULN_ETERNALBLUE_ID = uuid5("vuln:cve-2017-0144")
VULN_PROXYLOGON_ID = uuid5("vuln:cve-2021-26855")

POLICY_ID = uuid5("policy:cis-win2019")

# ── Helpers ─────────────────────────────────────────────────────────────────
_now = datetime.now(timezone.utc)


def dt(days_ago: int = 0, hours_ago: int = 0) -> datetime:
    return _now - timedelta(days=days_ago, hours=hours_ago)


async def _upsert(db: AsyncSession, model_cls, pk_val: str, **kwargs):
    """Insert if absent, skip if already present (idempotent)."""
    result = await db.execute(select(model_cls).where(model_cls.id == pk_val))
    obj = result.scalar_one_or_none()
    if obj is None:
        obj = model_cls(id=pk_val, **kwargs)
        db.add(obj)
    return obj


async def is_demo_seeded(db: AsyncSession) -> bool:
    """Return True when demo data is already present (user count > 0)."""
    count = (await db.execute(select(func.count(User.id)))).scalar_one()
    return count > 0


# ── Vulnerability catalogue (20: 5 KEV + 15 medium/low) ─────────────────────
VULNERABILITIES = [
    # 5 high-profile KEV CVEs
    dict(id=VULN_LOG4SHELL_ID, cve_id="CVE-2021-44228",
         title="Log4Shell Remote Code Execution",
         description="Apache Log4j2 JNDI lookup remote code execution (CVSS 10.0).",
         cvss_v3_score=10.0, cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
         severity="critical", is_kev=True, kev_date_added=dt(900).date(),
         kev_due_date=dt(870).date(), patch_available=True,
         patch_urls=["https://logging.apache.org/log4j/2.x/security.html"],
         affected_products=[{"vendor": "Apache", "product": "Log4j", "versions": "2.0-2.14.1"}],
         references=[{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
         published_at=dt(900), source="NVD"),
    dict(id=VULN_PRINTNIGHTMARE_ID, cve_id="CVE-2021-34527",
         title="PrintNightmare Windows Print Spooler RCE",
         description="Windows Print Spooler service allows remote code execution (CVSS 8.8).",
         cvss_v3_score=8.8, cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
         severity="high", is_kev=True, kev_date_added=dt(850).date(),
         kev_due_date=dt(820).date(), patch_available=True,
         patch_urls=["https://msrc.microsoft.com/update-guide/"],
         affected_products=[{"vendor": "Microsoft", "product": "Windows Print Spooler"}],
         references=[{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527"}],
         published_at=dt(850), source="NVD"),
    dict(id=VULN_ZEROLOGON_ID, cve_id="CVE-2020-1472",
         title="Zerologon Netlogon Privilege Escalation",
         description="Netlogon allows privilege escalation to domain admin (CVSS 10.0).",
         cvss_v3_score=10.0, cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
         severity="critical", is_kev=True, kev_date_added=dt(950).date(),
         kev_due_date=dt(920).date(), patch_available=True,
         patch_urls=["https://msrc.microsoft.com/update-guide/"],
         affected_products=[{"vendor": "Microsoft", "product": "Windows Server"}],
         references=[{"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"}],
         published_at=dt(950), source="NVD"),
    dict(id=VULN_ETERNALBLUE_ID, cve_id="CVE-2017-0144",
         title="EternalBlue SMBv1 Remote Code Execution",
         description="SMBv1 (MS17-010) allows remote code execution without authentication (CVSS 9.3).",
         cvss_v3_score=9.3, cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         severity="critical", is_kev=True, kev_date_added=dt(1500).date(),
         kev_due_date=dt(1470).date(), patch_available=True,
         patch_urls=["https://msrc.microsoft.com/update-guide/"],
         affected_products=[{"vendor": "Microsoft", "product": "Windows SMBv1"}],
         references=[{"url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"}],
         published_at=dt(1500), source="NVD"),
    dict(id=VULN_PROXYLOGON_ID, cve_id="CVE-2021-26855",
         title="Exchange ProxyLogon SSRF",
         description="Microsoft Exchange Server SSRF leading to RCE (CVSS 9.8).",
         cvss_v3_score=9.8, cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         severity="critical", is_kev=True, kev_date_added=dt(800).date(),
         kev_due_date=dt(770).date(), patch_available=True,
         patch_urls=["https://msrc.microsoft.com/update-guide/"],
         affected_products=[{"vendor": "Microsoft", "product": "Exchange Server"}],
         references=[{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"}],
         published_at=dt(800), source="NVD"),
]

# 15 medium/low CVEs appended with deterministic uuid5 ids
_MEDIUM_LOW_CVES = [
    ("CVE-2022-30190", "Follina MSDT RCE", 6.8, "high",
     "Microsoft Support Diagnostic Tool remote code execution."),
    ("CVE-2021-36934", "SeriousSAM Privilege Escalation", 7.8, "high",
     "Windows SAM database readable by non-admin users."),
    ("CVE-2022-37969", "Windows CLFS Privilege Escalation", 6.6, "medium",
     "Common Log File System driver elevation of privilege."),
    ("CVE-2023-21716", "Microsoft Word RTF RCE", 6.5, "medium",
     "Remote code execution via crafted RTF content."),
    ("CVE-2022-30134", "Windows LSA Spoofing", 5.9, "medium",
     "Local Security Authority spoofing vulnerability."),
    ("CVE-2020-1048", "Windows Print Spooler EoP", 6.5, "medium",
     "Print spooler elevation of privilege."),
    ("CVE-2022-41040", "Exchange OWASSRF EoP", 6.8, "medium",
     "Exchange Server elevation of privilege."),
    ("CVE-2022-41099", "Windows Kerberos EoP", 5.5, "medium",
     "Kerberos security feature bypass."),
    ("CVE-2023-21554", "Windows Message Queuing RCE", 6.3, "medium",
     "Message Queuing remote code execution."),
    ("CVE-2022-24521", "Windows Event Tracing EoP", 4.4, "low",
     "Event Tracing for Windows elevation of privilege."),
    ("CVE-2021-31195", "Windows GDI+ Info Disclosure", 4.3, "low",
     "Graphics device interface information disclosure."),
    ("CVE-2020-0754", "Windows File Server EoP", 4.3, "low",
     "Windows File Server elevation of privilege."),
    ("CVE-2021-28455", "Exchange SSRF", 4.0, "low",
     "Exchange Server server-side request forgery."),
    ("CVE-2022-21919", "Windows LUAFV EoP", 3.5, "low",
     "Windows User Mode Driver Frame elevation of privilege."),
    ("CVE-2023-28231", "Windows DHCP Server RCE", 4.9, "low",
     "Dynamic Host Configuration Protocol server RCE."),
]
for cve, title, cvss, sev, desc in _MEDIUM_LOW_CVES:
    VULNERABILITIES.append(
        dict(id=uuid5(f"vuln:{cve.lower()}"), cve_id=cve, title=title,
             description=desc, cvss_v3_score=cvss,
             cvss_v3_vector=f"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
             severity=sev, is_kev=False, patch_available=True,
             patch_urls=["https://msrc.microsoft.com/update-guide/"],
             affected_products=[{"vendor": "Microsoft", "product": "Windows"}],
             references=[{"url": f"https://nvd.nist.gov/vuln/detail/{cve}"}],
             published_at=dt(400), source="NVD")
    )

# Quick lookup: CVE -> vulnerability id
_VULN_BY_CVE = {v["cve_id"]: v["id"] for v in VULNERABILITIES}


# ── Asset definitions (scan_1 = 12 hosts) ───────────────────────────────────
_WIN_PORTS = [
    {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": ""},
    {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "version": ""},
]

SCAN1_ASSETS = [
    dict(id=ASSET_DC01_ID, ip="192.168.1.10", hostname="DC01.corp.local",
         is_windows=True, asset_type="server", criticality="critical",
         os_name="Windows Server 2019", os_version="10.0.17763", os_build="17763.1",
         ports=_WIN_PORTS + [{"port": 88, "protocol": "tcp", "service": "kerberos"}],
         win={"patch_count": 3, "defender_status": "enabled", "smb_version": "SMBv2",
              "rdp_enabled": True, "is_supported_os": True, "firewall_enabled": True},
         risk=9.2),
    dict(id=ASSET_FILE01_ID, ip="192.168.1.11", hostname="FILE01.corp.local",
         is_windows=True, asset_type="server", criticality="high",
         os_name="Windows Server 2016", os_version="10.0.14393", os_build="14393.0",
         ports=_WIN_PORTS,
         win={"patch_count": 0, "defender_status": "disabled", "smb_version": "SMBv1",
              "rdp_enabled": True, "is_supported_os": True, "firewall_enabled": False},
         risk=9.8),
    dict(id=ASSET_WEB01_ID, ip="192.168.1.12", hostname="WEB01.corp.local",
         is_windows=True, asset_type="server", criticality="high",
         os_name="Windows Server 2022", os_version="10.0.20348", os_build="20348.1",
         ports=[{"port": 80, "protocol": "tcp", "service": "http", "version": "IIS 10.0"},
                {"port": 443, "protocol": "tcp", "service": "https", "version": "IIS 10.0"}],
         win={"patch_count": 10, "defender_status": "enabled", "smb_version": "SMBv3",
              "rdp_enabled": False, "is_supported_os": True, "firewall_enabled": True},
         risk=5.5),
    dict(id=ASSET_SQL01_ID, ip="192.168.1.13", hostname="SQL01.corp.local",
         is_windows=True, asset_type="server", criticality="critical",
         os_name="Windows Server 2019", os_version="10.0.17763", os_build="17763.1",
         ports=[{"port": 1433, "protocol": "tcp", "service": "ms-sql-s", "version": "SQL Server 2019"},
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
         win={"patch_count": 5, "defender_status": "enabled", "smb_version": "SMBv2",
              "rdp_enabled": False, "is_supported_os": True, "firewall_enabled": True},
         risk=7.1),
    dict(id=ASSET_ADMIN01_ID, ip="192.168.1.14", hostname="ADMIN01.corp.local",
         is_windows=True, asset_type="workstation", criticality="high",
         os_name="Windows 10 Pro", os_version="10.0.19045", os_build="19045.1",
         ports=_WIN_PORTS,
         win={"patch_count": 2, "defender_status": "enabled", "smb_version": "SMBv2",
              "rdp_enabled": True, "is_supported_os": True, "firewall_enabled": True},
         risk=6.8),
    dict(id=ASSET_WS001_ID, ip="192.168.1.20", hostname="WS001.corp.local",
         is_windows=True, asset_type="workstation", criticality="low",
         os_name="Windows 10", os_version="10.0.19044", os_build="19044.1",
         ports=[{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
         win={"patch_count": 1, "defender_status": "enabled", "smb_version": "SMBv2",
              "rdp_enabled": False, "is_supported_os": True, "firewall_enabled": True},
         risk=4.0),
    dict(id=ASSET_WS002_ID, ip="192.168.1.21", hostname="WS002.corp.local",
         is_windows=True, asset_type="workstation", criticality="low",
         os_name="Windows 11", os_version="10.0.22621", os_build="22621.1",
         ports=[{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
         win={"patch_count": 8, "defender_status": "enabled", "smb_version": "SMBv3",
              "rdp_enabled": False, "is_supported_os": True, "firewall_enabled": True},
         risk=2.5),
    dict(id=ASSET_WS003_ID, ip="192.168.1.22", hostname="WS003.corp.local",
         is_windows=True, asset_type="workstation", criticality="medium",
         os_name="Windows 10", os_version="10.0.19042", os_build="19042.1",
         ports=[{"port": 445, "protocol": "tcp", "service": "microsoft-ds"},
                {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server"}],
         win={"patch_count": 0, "defender_status": "disabled", "smb_version": "SMBv1",
              "rdp_enabled": True, "is_supported_os": True, "firewall_enabled": False},
         risk=8.0),
    dict(id=ASSET_NGINX_ID, ip="192.168.1.30", hostname="nginx.corp.local",
         is_windows=False, asset_type="server", criticality="medium",
         os_name="Ubuntu 22.04", os_version="22.04",
         ports=[{"port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.22.1"},
                {"port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.22.1"}],
         win=None, risk=3.0),
    dict(id=ASSET_MON_ID, ip="192.168.1.31", hostname="monitor.corp.local",
         is_windows=False, asset_type="server", criticality="medium",
         os_name="Ubuntu 22.04", os_version="22.04",
         ports=[{"port": 9090, "protocol": "tcp", "service": "prometheus", "version": "2.40"}],
         win=None, risk=2.0),
    dict(id=ASSET_ROUTER_ID, ip="192.168.1.1", hostname=None,
         is_windows=False, asset_type="network_device", criticality="critical",
         os_name=None,
         ports=[{"port": 80, "protocol": "tcp", "service": "http", "version": ""},
                {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 7.4"}],
         win=None, risk=6.0),
    dict(id=ASSET_UNKNOWN_ID, ip="192.168.1.99", hostname=None,
         is_windows=False, asset_type="unknown", criticality="low",
         os_name=None, ports=[], win=None, risk=1.0),
]

# scan_2 re-scan: same 12 IPs; FILE01 + WS003 ports hardened (port changes).
SCAN2_ASSETS = [
    dict(id=ASSET_DC01_S2_ID, base=ASSET_DC01_ID, risk=8.5,
         dict_patch_count=4),
    dict(id=ASSET_FILE01_S2_ID, base=ASSET_FILE01_ID, risk=5.2,
         ports=[{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
         dict_smb_version="SMBv3", dict_rdp_enabled=False, dict_defender="enabled",
         dict_firewall=True),
    dict(id=ASSET_WEB01_S2_ID, base=ASSET_WEB01_ID, risk=5.0),
    dict(id=ASSET_SQL01_S2_ID, base=ASSET_SQL01_ID, risk=6.8),
    dict(id=ASSET_ADMIN01_S2_ID, base=ASSET_ADMIN01_ID, risk=6.5, win_patch=5),
    dict(id=ASSET_WS001_S2_ID, base=ASSET_WS001_ID, risk=3.8),
    dict(id=ASSET_WS002_S2_ID, base=ASSET_WS002_ID, risk=2.4),
    dict(id=ASSET_WS003_S2_ID, base=ASSET_WS003_ID, risk=3.0,
         ports=[{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
         dict_defender="enabled", dict_smb_version="SMBv3",
         dict_rdp_enabled=False, dict_firewall=True),
    dict(id=ASSET_NGINX_S2_ID, base=ASSET_NGINX_ID, risk=3.0),
    dict(id=ASSET_MON_S2_ID, base=ASSET_MON_ID, risk=2.0),
    dict(id=ASSET_ROUTER_S2_ID, base=ASSET_ROUTER_ID, risk=6.0),
    dict(id=ASSET_UNKNOWN_S2_ID, base=ASSET_UNKNOWN_ID, risk=1.0),
]


def _build_scan2_asset(spec: dict, base: dict) -> dict:
    """Merge a scan_2 asset spec onto its scan_1 base (same IP/host)."""
    out = {
        "id": spec["id"],
        "scan_job_id": SCAN2_ID,
        "target_id": TARGET_CORP_ID,
        "ip_address": base["ip"],
        "hostname": base["hostname"],
        "is_windows": base["is_windows"],
        "asset_type": base["asset_type"],
        "business_criticality": base["criticality"],
        "os_name": base["os_name"],
        "os_version": base.get("os_version"),
        "os_build": base.get("os_build"),
        "open_ports": spec.get("ports", base["ports"]),
        "windows_details": base["win"],
        "risk_score": spec.get("risk", base["risk"]),
        "last_seen_at": dt(1),
        "created_at": dt(1),
        "updated_at": dt(1),
    }
    # Apply optional windows_details overrides
    win = dict(base["win"]) if base["win"] else None
    if win is not None:
        if "dict_patch_count" in spec:
            win["patch_count"] = spec["dict_patch_count"]
        if "win_patch" in spec:
            win["patch_count"] = spec["win_patch"]
        if "dict_smb_version" in spec:
            win["smb_version"] = spec["dict_smb_version"]
        if "dict_rdp_enabled" in spec:
            win["rdp_enabled"] = spec["dict_rdp_enabled"]
        if "dict_defender" in spec:
            win["defender_status"] = spec["dict_defender"]
        if "dict_firewall" in spec:
            win["firewall_enabled"] = spec["dict_firewall"]
    out["windows_details"] = win
    return out


# ── Findings (45 total: 5 critical / 12 high / 18 medium / 10 low) ───────────
# scan_1 = 28, scan_2 = 12, scan_3 = 5.
# Several scan_1 findings are marked remediated (resolved_at set) to surface
# remediation progress; scan_2 omits their (asset, check_name) so change
# detection also reports them as resolved.
F = dict  # alias for readability


def _f(name, scan, asset, vuln_cve, title, ftype, sev, status, check, evidence,
       method, conf, risk, impact=None, action=None, remediated=False,
       risk_expl=None):
    return dict(
        name=name, scan_job_id=scan, asset_id=asset,
        vulnerability_id=_VULN_BY_CVE.get(vuln_cve) if vuln_cve else None,
        title=title, finding_type=ftype, severity=sev, status=status,
        check_name=check, evidence=evidence, detection_method=method,
        confidence=conf, risk_score=risk, business_impact=impact,
        recommended_action=action, risk_explanation=risk_expl,
        remediated=remediated,
    )


SCAN1_FINDINGS = [
    # ── 4 critical ──
    _f("s1-c1", SCAN1_ID, ASSET_DC01_ID, "CVE-2020-1472",
       "Zerologon: Domain Controller Netlogon vulnerability",
       "potential_vulnerability", "critical", "open", "zerologon_check",
       "Windows Server 2019 DC01 build 17763 with patch_count=3; patch status unverified.",
       "version_check", "medium", 9.0,
       "A compromised DC grants full domain control.",
       "Apply August 2020 cumulative update and enforce SMB signing.",
       risk_expl="Critical CVE on a criticality=critical asset; KEV active exploitation."),
    _f("s1-c2", SCAN1_ID, ASSET_FILE01_ID, "CVE-2017-0144",
       "EternalBlue: SMBv1 enabled allows remote code execution",
       "confirmed_vulnerability", "critical", "open", "smb_v1_enabled_check",
       "SMBv1 service banner observed on port 445; MS17-010 not installed.",
       "network_scan", "confirmed", 9.8,
       "Unauthenticated remote code execution possible.",
       "Disable SMBv1 and install MS17-010.",
       risk_expl="Confirmed SMBv1 + KEV CVE on high-criticality host."),
    _f("s1-c3", SCAN1_ID, ASSET_SQL01_ID, None,
       "Microsoft SQL Server exposed on default port 1433",
       "network_exposure", "critical", "open", "sql_exposed_check",
       "Port 1433 open and reachable on SQL01 (192.168.1.13).",
       "network_scan", "confirmed", 9.0,
       "Database port reachable exposes data to attack.",
       "Restrict port 1433 via firewall to known hosts only.",
       risk_expl="Critical service exposed on a criticality=critical asset."),
    _f("s1-c4", SCAN1_ID, ASSET_ADMIN01_ID, None,
       "Administrative workstation missing critical patches",
       "potential_vulnerability", "critical", "open", "missing_patch_check",
       "ADMIN01 patch_count=2; expected >10 for current build 19045.",
       "winrm_check", "medium", 8.8,
       "Admin workstation compromise yields privileged access.",
       "Install outstanding cumulative updates.",
       risk_expl="High-criticality host below patch baseline."),
    # ── 8 high ──
    _f("s1-h1", SCAN1_ID, ASSET_FILE01_ID, None,
       "Windows Defender disabled on file server",
       "misconfiguration", "high", "open", "defender_status_check",
       "defender_status=disabled reported via WinRM.",
       "winrm_check", "confirmed", 8.5,
       "No real-time anti-malware on a shared file server.",
       "Enable Windows Defender real-time protection."),
    _f("s1-h2", SCAN1_ID, ASSET_WS003_ID, None,
       "RDP exposed with no patch history",
       "network_exposure", "high", "open", "rdp_exposure_check",
       "Port 3389 open and patch_count=0 on WS003.",
       "network_scan", "confirmed", 8.0,
       "Exposed RDP is a common ransomware entry point.",
       "Disable RDP or restrict via firewall; patch the host."),
    _f("s1-h3", SCAN1_ID, ASSET_FILE01_ID, "CVE-2021-34527",
       "PrintNightmare: Print Spooler service running",
       "potential_vulnerability", "high", "open", "print_spooler_check",
       "Spooler service running on FILE01; patch status unverified.",
       "winrm_check", "medium", 7.8,
       "Print spooler RCE risk on a file server.",
       "Stop and disable the Print Spooler service or patch."),
    _f("s1-h4", SCAN1_ID, ASSET_DC01_ID, None,
       "Password policy does not meet complexity baseline",
       "misconfiguration", "high", "open", "password_policy_check",
       "net accounts: minimum password length = 6 (expected >= 12).",
       "winrm_check", "high", 7.2,
       "Weak passwords ease credential compromise.",
       "Raise minimum length to 12 and enable complexity."),
    _f("s1-h5", SCAN1_ID, ASSET_FILE01_ID, None,
       "Host firewall disabled",
       "misconfiguration", "high", "open", "firewall_check",
       "Get-NetFirewallProfile: all profiles Disabled on FILE01.",
       "winrm_check", "confirmed", 7.0,
       "No host firewall leaves services fully exposed.",
       "Enable all firewall profiles."),
    _f("s1-h6", SCAN1_ID, ASSET_ADMIN01_ID, "CVE-2022-30190",
       "Follina MSDT vulnerability present",
       "potential_vulnerability", "high", "open", "follina_check",
       "MSDT handler enabled; patch for CVE-2022-30190 not confirmed.",
       "version_check", "medium", 6.9,
       "Phishing-driven RCE risk on admin workstation.",
       "Apply the Follina mitigations and patches."),
    _f("s1-h7", SCAN1_ID, ASSET_WS003_ID, "CVE-2021-36934",
       "SeriousSAM: SAM database readable by non-admins",
       "potential_vulnerability", "high", "open", "serioussam_check",
       "SAM file ACLs overly permissive on WS003.",
       "winrm_check", "high", 6.8,
       "Credential theft enabling lateral movement.",
       "Apply the SAM ACL fix and rotate credentials."),
    _f("s1-h8", SCAN1_ID, ASSET_SQL01_ID, None,
       "SQL Server Browser service exposed",
       "network_exposure", "high", "open", "sql_browser_check",
       "UDP 1434 responding on SQL01.",
       "network_scan", "high", 6.5,
       "Enumerates instances for targeted attacks.",
       "Disable the SQL Browser service or block UDP 1434."),
    # ── 11 medium ──
    _f("s1-m1", SCAN1_ID, ASSET_DC01_ID, "CVE-2022-37969",
       "CLFS privilege escalation risk",
       "potential_vulnerability", "medium", "open", "clfs_check",
       "CLFS driver present; patch unverified.",
       "version_check", "medium", 5.8),
    _f("s1-m2", SCAN1_ID, ASSET_WEB01_ID, "CVE-2023-21716",
       "RTF parsing RCE risk on web server",
       "potential_vulnerability", "medium", "open", "rtf_check",
       "Office RTF components enabled on WEB01.",
       "version_check", "medium", 5.5),
    _f("s1-m3", SCAN1_ID, ASSET_DC01_ID, "CVE-2022-30134",
       "LSA spoofing risk on domain controller",
       "potential_vulnerability", "medium", "open", "lsa_check",
       "LSA protection not enabled.",
       "winrm_check", "medium", 5.4),
    _f("s1-m4", SCAN1_ID, ASSET_WS001_ID, "CVE-2020-1048",
       "Print spooler elevation of privilege",
       "potential_vulnerability", "medium", "open", "print_spooler_eop_check",
       "Spooler running; patch unverified.",
       "winrm_check", "medium", 5.2),
    _f("s1-m5", SCAN1_ID, ASSET_WEB01_ID, "CVE-2022-41040",
       "Exchange OWASSRF elevation of privilege",
       "potential_vulnerability", "medium", "open", "owassrf_check",
       "OWASSRF mitigations not confirmed.",
       "version_check", "medium", 5.0),
    _f("s1-m6", SCAN1_ID, ASSET_WS002_ID, "CVE-2022-41099",
       "Kerberos elevation of privilege risk",
       "potential_vulnerability", "medium", "open", "kerberos_check",
       "Kerberos patch level unverified.",
       "version_check", "low", 4.8),
    _f("s1-m7", SCAN1_ID, ASSET_SQL01_ID, "CVE-2023-21554",
       "Message queuing RCE risk",
       "potential_vulnerability", "medium", "open", "msmq_check",
       "MSMQ service running on SQL01.",
       "winrm_check", "medium", 4.6),
    _f("s1-m8", SCAN1_ID, ASSET_ROUTER_ID, None,
       "Router HTTP management interface exposed",
       "network_exposure", "medium", "open", "admin_interface_check",
       "HTTP port 80 open on network device 192.168.1.1.",
       "network_scan", "high", 6.0),
    _f("s1-m9", SCAN1_ID, ASSET_ROUTER_ID, None,
       "SSH service running an outdated OpenSSH version",
       "network_exposure", "medium", "open", "ssh_version_check",
       "OpenSSH 7.4 banner on port 22.",
       "network_scan", "high", 5.0),
    _f("s1-m10", SCAN1_ID, ASSET_NGINX_ID, None,
       "HTTP strict transport security not configured",
       "misconfiguration", "medium", "open", "hsts_check",
       "HSTS header absent on nginx HTTPS response.",
       "network_scan", "medium", 4.5),
    _f("s1-m11", SCAN1_ID, ASSET_MON_ID, None,
       "Monitoring service exposed without authentication",
       "network_exposure", "medium", "open", "prometheus_exposure_check",
       "Prometheus 9090 reachable without auth.",
       "network_scan", "high", 5.2),
    # ── 5 low ──
    _f("s1-l1", SCAN1_ID, ASSET_DC01_ID, "CVE-2022-24521",
       "Event Tracing elevation of privilege risk",
       "potential_vulnerability", "low", "open", "etw_check",
       "ETW patch unverified.",
       "version_check", "low", 3.5),
    _f("s1-l2", SCAN1_ID, ASSET_WS001_ID, "CVE-2021-31195",
       "GDI+ information disclosure",
       "informational", "low", "open", "gdi_check",
       "GDI+ patch unverified; minor info disclosure.",
       "version_check", "low", 3.0),
    _f("s1-l3", SCAN1_ID, ASSET_FILE01_ID, "CVE-2020-0754",
       "File server elevation of privilege",
       "potential_vulnerability", "low", "open", "fileserver_eop_check",
       "File server service EoP patch unverified.",
       "version_check", "low", 3.2),
    _f("s1-l4", SCAN1_ID, ASSET_WEB01_ID, "CVE-2021-28455",
       "Exchange SSRF low-severity exposure",
       "informational", "low", "open", "exchange_ssrf_check",
       "SSRF residual risk noted on web host.",
       "version_check", "low", 2.8),
    _f("s1-l5", SCAN1_ID, ASSET_WS002_ID, "CVE-2022-21919",
       "LUAFV elevation of privilege risk",
       "potential_vulnerability", "low", "open", "luafv_check",
       "LUAFV driver present; patch unverified.",
       "version_check", "low", 2.5),
]

# Mark 8 scan_1 findings as remediated (resolved between scan_1 and scan_2).
# These are removed from scan_2 so change detection reports them as resolved.
_REMEDIATED_NAMES = {
    "s1-c2", "s1-c4", "s1-h1", "s1-h2", "s1-h3", "s1-h5", "s1-m8", "s1-l3",
}
for fd in SCAN1_FINDINGS:
    if fd["name"] in _REMEDIATED_NAMES:
        fd["status"] = "remediated"
        fd["remediated"] = True

# scan_2 findings: 12 (1 critical, 3 high, 5 medium, 3 low). Persistent findings
# reuse the same check_name as scan_1 (against the scan_2 asset copy) so they
# are not flagged as new; new findings use fresh check_names.
SCAN2_FINDINGS = [
    _f("s2-c1", SCAN2_ID, ASSET_DC01_S2_ID, "CVE-2020-1472",
       "Zerologon: Domain Controller Netlogon vulnerability (persisting)",
       "potential_vulnerability", "critical", "open", "zerologon_check",
       "DC01 still on build 17763 with patch_count=4; full patch unverified.",
       "version_check", "medium", 8.5),
    _f("s2-h1", SCAN2_ID, ASSET_DC01_S2_ID, None,
       "Password policy does not meet complexity baseline (persisting)",
       "misconfiguration", "high", "open", "password_policy_check",
       "net accounts: minimum password length = 6 (expected >= 12).",
       "winrm_check", "high", 7.2),
    _f("s2-h2", SCAN2_ID, ASSET_SQL01_S2_ID, None,
       "SQL Server Browser service exposed (persisting)",
       "network_exposure", "high", "open", "sql_browser_check",
       "UDP 1434 responding on SQL01.",
       "network_scan", "high", 6.5),
    _f("s2-h3", SCAN2_ID, ASSET_FILE01_S2_ID, "CVE-2021-34527",
       "Print spooler residual risk on remediated host",
       "potential_vulnerability", "high", "open", "print_spooler_residual_check",
       "Spooler service stopped but binary still present on FILE01.",
       "winrm_check", "low", 5.8),
    _f("s2-m1", SCAN2_ID, ASSET_DC01_S2_ID, "CVE-2022-37969",
       "CLFS privilege escalation risk (persisting)",
       "potential_vulnerability", "medium", "open", "clfs_check",
       "CLFS driver present; patch unverified.",
       "version_check", "medium", 5.6),
    _f("s2-m2", SCAN2_ID, ASSET_WEB01_S2_ID, "CVE-2023-21716",
       "RTF parsing RCE risk (persisting)",
       "potential_vulnerability", "medium", "open", "rtf_check",
       "Office RTF components enabled on WEB01.",
       "version_check", "medium", 5.4),
    _f("s2-m3", SCAN2_ID, ASSET_WEB01_S2_ID, "CVE-2022-41040",
       "Exchange OWASSRF elevation of privilege (persisting)",
       "potential_vulnerability", "medium", "open", "owassrf_check",
       "OWASSRF mitigations not confirmed.",
       "version_check", "medium", 5.0),
    _f("s2-m4", SCAN2_ID, ASSET_MON_S2_ID, None,
       "Monitoring service exposed without authentication (persisting)",
       "network_exposure", "medium", "open", "prometheus_exposure_check",
       "Prometheus 9090 reachable without auth.",
       "network_scan", "high", 5.0),
    _f("s2-m5", SCAN2_ID, ASSET_NGINX_S2_ID, None,
       "TLS cipher suite includes weak algorithms",
       "misconfiguration", "medium", "open", "tls_cipher_check",
       "nmap ssl-enum-ciphers reported CBC ciphers on nginx.",
       "network_scan", "medium", 4.2),
    _f("s2-l1", SCAN2_ID, ASSET_DC01_S2_ID, "CVE-2022-24521",
       "Event Tracing elevation of privilege risk (persisting)",
       "potential_vulnerability", "low", "open", "etw_check",
       "ETW patch unverified.",
       "version_check", "low", 3.4),
    _f("s2-l2", SCAN2_ID, ASSET_WS002_S2_ID, "CVE-2022-41099",
       "Kerberos elevation of privilege risk (persisting)",
       "potential_vulnerability", "low", "open", "kerberos_check",
       "Kerberos patch level unverified.",
       "version_check", "low", 4.6),
    _f("s2-l3", SCAN2_ID, ASSET_WEB01_S2_ID, "CVE-2021-28455",
       "Exchange SSRF low-severity exposure (persisting)",
       "informational", "low", "open", "exchange_ssrf_check",
       "SSRF residual risk noted on web host.",
       "version_check", "low", 2.8),
]

# scan_3 (dmz network scan): 5 findings (1 high, 2 medium, 2 low) referencing
# scan_1 network-exposed hosts as network_exposure observations.
SCAN3_FINDINGS = [
    _f("s3-h1", SCAN3_ID, ASSET_ROUTER_ID, None,
       "DMZ scan: router management interface reachable from DMZ",
       "network_exposure", "high", "open", "dmz_router_mgmt_check",
       "Router 192.168.1.1 HTTP admin reachable during DMZ scan.",
       "network_scan", "confirmed", 6.8),
    _f("s3-m1", SCAN3_ID, ASSET_NGINX_ID, None,
       "DMZ scan: nginx HTTP service reachable",
       "network_exposure", "medium", "open", "dmz_nginx_http_check",
       "nginx 192.168.1.30 port 80 reachable from DMZ.",
       "network_scan", "confirmed", 5.0),
    _f("s3-m2", SCAN3_ID, ASSET_WEB01_ID, None,
       "DMZ scan: web server HTTP reachable",
       "network_exposure", "medium", "open", "dmz_web01_http_check",
       "WEB01 192.168.1.12 port 80 reachable from DMZ.",
       "network_scan", "high", 4.8),
    _f("s3-l1", SCAN3_ID, ASSET_MON_ID, None,
       "DMZ scan: monitoring port reachable",
       "network_exposure", "low", "open", "dmz_monitor_check",
       "monitor 192.168.1.31 port 9090 reachable from DMZ.",
       "network_scan", "medium", 3.0),
    _f("s3-l2", SCAN3_ID, ASSET_UNKNOWN_ID, None,
       "DMZ scan: unidentifiable host responded to discovery",
       "informational", "low", "open", "dmz_unknown_check",
       "Host 192.168.1.99 responded but no services identified.",
       "network_scan", "low", 1.5),
]

ALL_FINDINGS = SCAN1_FINDINGS + SCAN2_FINDINGS + SCAN3_FINDINGS
assert len(ALL_FINDINGS) == 45, len(ALL_FINDINGS)


# ── Baseline policy: 20 controls (8 pass, 7 fail, 5 unknown) ────────────────
def _build_controls():
    defs = [
        ("CIS-01", "Account lockout policy configured", "high", "account_policy", "pass",
         "net accounts: lockout threshold = 5 attempts."),
        ("CIS-02", "Minimum password length >= 12", "high", "account_policy", "fail",
         "net accounts: minimum password length = 6."),
        ("CIS-03", "Password complexity enabled", "high", "account_policy", "fail",
         "Complexity flag not set on DC01."),
        ("CIS-04", "Windows Defender real-time protection enabled", "high", "defender", "fail",
         "Defender disabled on FILE01."),
        ("CIS-05", "Windows Firewall enabled on all profiles", "high", "firewall", "fail",
         "All profiles disabled on FILE01."),
        ("CIS-06", "SMBv1 disabled", "critical", "smb", "fail",
         "SMBv1 enabled on FILE01 and WS003."),
        ("CIS-07", "RDP restricted via firewall", "high", "rdp", "fail",
         "RDP open on WS003 without restriction."),
        ("CIS-08", "Automatic updates enabled", "medium", "patching", "pass",
         "AUOptions=4 on DC01, WEB01, WS002."),
        ("CIS-09", "BitLocker enabled on fixed drives", "medium", "encryption", "unknown",
         "Requires remote disk query not completed."),
        ("CIS-10", "Guest account disabled", "medium", "account_policy", "pass",
         "Guest account disabled on all assessed hosts."),
        ("CIS-11", "Anonymous SAM access restricted", "high", "registry", "pass",
         "RestrictAnonymousSAM = 1 on DC01."),
        ("CIS-12", "NTLMv1 disabled", "high", "smb", "fail",
         "LANMAN auth level below 3 on FILE01."),
        ("CIS-13", "Remote Desktop NLA required", "high", "rdp", "unknown",
         "NLA setting not retrieved for ADMIN01."),
        ("CIS-14", "Audit policy: logon events", "medium", "audit", "pass",
         "Audit Logon success+failure enabled on DC01."),
        ("CIS-15", "Audit policy: object access", "medium", "audit", "pass",
         "Object access auditing enabled on SQL01."),
        ("CIS-16", "Unnecessary services removed (Telnet)", "low", "services", "pass",
         "Telnet service not present on assessed hosts."),
        ("CIS-17", "Unnecessary services removed (FTP)", "low", "services", "pass",
         "FTP service not present on assessed hosts."),
        ("CIS-18", "Windows Remote Management restricted", "medium", "winrm", "unknown",
         "WinRM listener scope not determined."),
        ("CIS-19", "Local admin accounts reviewed", "medium", "account_policy", "unknown",
         "Local admin membership not enumerated."),
        ("CIS-20", "Screen saver lockout timeout <= 15 min", "low", "config", "unknown",
         "Screen saver timeout not retrieved for assessed hosts."),
    ]
    controls = []
    for cid, title, sev, cat, result, evidence in defs:
        controls.append({
            "id": cid, "title": title, "severity": sev, "category": cat,
            "description": title,
            "check_command": f"# PowerShell check for {cid}",
            "expected_result": "compliant",
            "result": result,
            "evidence": evidence,
            "last_checked": dt(1).isoformat(),
        })
    return controls


# ── Audit log catalogue (50 entries) ───────────────────────────────────────
_AUDIT_ACTIONS = [
    ("login", "auth", None),
    ("logout", "auth", None),
    ("scan_create", "scan_job", "scan"),
    ("scan_complete", "scan_job", "scan"),
    ("scan_cancel", "scan_job", "scan"),
    ("finding_status_update", "finding", "finding"),
    ("finding_assign", "finding", "finding"),
    ("target_create", "target", "target"),
    ("target_update", "target", "target"),
    ("user_create", "user", "user"),
    ("baseline_assess", "baseline_policy", "policy"),
    ("vuln_sync", "vulnerability", "vuln"),
    ("remediation_verify", "finding", "finding"),
]


def _build_audit_logs() -> list:
    logs = []
    user_cycle = [ADMIN_ID, ANALYST_ID, VIEWER_ID]
    for i in range(50):
        action, rtype, _ = _AUDIT_ACTIONS[i % len(_AUDIT_ACTIONS)]
        uid = user_cycle[i % 3]
        days_ago = (i * 0.6) % 30  # spread over ~30 days
        logs.append(dict(
            id=uuid5(f"audit-{i:03d}"),
            user_id=uid,
            action=action,
            resource_type=rtype,
            resource_id=uuid5(f"audit-res-{i:03d}"),
            details={"index": i, "description": f"Demo {action} event #{i}"},
            ip_address=f"192.168.1.{100 + (i % 50)}",
            user_agent="Mozilla/5.0 (demo-seeder)",
            created_at=dt(0, hours_ago=int(days_ago * 24)),
        ))
    return logs


# ── Seed orchestration ──────────────────────────────────────────────────────
async def seed(db: AsyncSession) -> None:
    """Populate the database with deterministic demo data (idempotent)."""
    if await is_demo_seeded(db):
        print("Demo data already seeded — skipping.")
        logger.info("Demo data already seeded — skipping.")
        return

    logger.info("Seeding demo data…")

    # ── Users ───────────────────────────────────────────────────────────────
    await _upsert(db, User, ADMIN_ID,
                 username="admin", email="admin@demo.local",
                 hashed_password=hash_password("Admin@1234"),
                 role="admin", full_name="Demo Admin", is_active=True,
                 last_login=dt(0, hours_ago=2),
                 created_at=dt(30), updated_at=dt(1))
    await _upsert(db, User, ANALYST_ID,
                 username="analyst", email="analyst@demo.local",
                 hashed_password=hash_password("Analyst@1234"),
                 role="analyst", full_name="Demo Analyst", is_active=True,
                 last_login=dt(0, hours_ago=5),
                 created_at=dt(30), updated_at=dt(1))
    await _upsert(db, User, VIEWER_ID,
                 username="viewer", email="viewer@demo.local",
                 hashed_password=hash_password("Viewer@1234"),
                 role="viewer", full_name="Demo Viewer", is_active=True,
                 last_login=dt(2),
                 created_at=dt(30), updated_at=dt(1))

    # ── Targets ─────────────────────────────────────────────────────────────
    await _upsert(db, Target, TARGET_CORP_ID,
                 name="Corporate LAN", scope_type="cidr", scope_value="192.168.1.0/24",
                 business_criticality="high", is_active=True, created_by=ADMIN_ID,
                 created_at=dt(30), updated_at=dt(1))
    await _upsert(db, Target, TARGET_DMZ_ID,
                 name="DMZ Segment", scope_type="cidr", scope_value="10.10.10.0/24",
                 business_criticality="critical", is_active=True, created_by=ADMIN_ID,
                 created_at=dt(30), updated_at=dt(1))

    # ── Scan jobs ───────────────────────────────────────────────────────────
    await _upsert(db, ScanJob, SCAN1_ID,
                 target_id=TARGET_CORP_ID, scan_type="full", status="completed",
                 progress=100, started_by=ADMIN_ID, started_at=dt(7),
                 completed_at=dt(7), created_at=dt(7))
    await _upsert(db, ScanJob, SCAN2_ID,
                 target_id=TARGET_CORP_ID, scan_type="full", status="completed",
                 progress=100, started_by=ANALYST_ID, started_at=dt(1),
                 completed_at=dt(1), created_at=dt(1))
    await _upsert(db, ScanJob, SCAN3_ID,
                 target_id=TARGET_DMZ_ID, scan_type="network", status="completed",
                 progress=100, started_by=ADMIN_ID, started_at=dt(3),
                 completed_at=dt(3), created_at=dt(3))

    # ── Vulnerabilities (20) ────────────────────────────────────────────────
    for v in VULNERABILITIES:
        await _upsert(db, Vulnerability, v.pop("id"), fetched_at=_now, **v)

    # ── Assets: scan_1 (12) ─────────────────────────────────────────────────
    for a in SCAN1_ASSETS:
        await _upsert(db, Asset, a["id"],
                      scan_job_id=SCAN1_ID, target_id=TARGET_CORP_ID,
                      ip_address=a["ip"], hostname=a["hostname"],
                      is_windows=a["is_windows"], asset_type=a["asset_type"],
                      business_criticality=a["criticality"],
                      os_name=a["os_name"], os_version=a.get("os_version"),
                      os_build=a.get("os_build"),
                      is_supported_os=True if a["is_windows"] else None,
                      open_ports=a["ports"], windows_details=a["win"],
                      risk_score=a["risk"], last_seen_at=dt(1),
                      created_at=dt(7), updated_at=dt(1))

    # ── Assets: scan_2 re-scan (12, same IPs) ────────────────────────────────
    for spec in SCAN2_ASSETS:
        base = next(a for a in SCAN1_ASSETS if a["id"] == spec["base"])
        rec = _build_scan2_asset(spec, base)
        await _upsert(db, Asset, rec["id"], **{k: v for k, v in rec.items() if k != "id"})

    # ── Findings (45) ───────────────────────────────────────────────────────
    for fd in ALL_FINDINGS:
        first_seen = dt(7) if fd["scan_job_id"] == SCAN1_ID else (
            dt(1) if fd["scan_job_id"] == SCAN2_ID else dt(3))
        last_seen = dt(1) if fd["scan_job_id"] == SCAN2_ID else (
            dt(7) if fd["scan_job_id"] == SCAN1_ID else dt(3))
        resolved_at = dt(2) if fd.get("remediated") else None
        steps = None
        if fd.get("remediated") or fd["status"] == "open":
            steps = [
                {"step": "Review the finding evidence and confirm scope.",
                 "command": "# PowerShell: review command (display only)"},
                {"step": "Apply the vendor patch or configuration change.",
                 "command": "# PowerShell: apply change (requires administrator)"},
            ]
        await _upsert(db, Finding, uuid5(fd["name"]),
                      scan_job_id=fd["scan_job_id"], asset_id=fd["asset_id"],
                      vulnerability_id=fd["vulnerability_id"], title=fd["title"],
                      finding_type=fd["finding_type"], severity=fd["severity"],
                      status=fd["status"], check_name=fd["check_name"],
                      evidence=fd["evidence"], detection_method=fd["detection_method"],
                      confidence=fd["confidence"], risk_score=fd["risk_score"],
                      risk_explanation=fd.get("risk_expl"),
                      business_impact=fd.get("business_impact"),
                      recommended_action=fd.get("recommended_action"),
                      remediation_steps=steps,
                      first_seen_at=first_seen, last_seen_at=last_seen,
                      resolved_at=resolved_at)

    # ── Baseline policy (20 controls) ──────────────────────────────────────
    await _upsert(db, BaselinePolicy, POLICY_ID,
                 name="CIS Windows Server 2019 Benchmark v1.0",
                 description="Center for Internet Security Windows Server 2019 baseline.",
                 framework="cis_windows", version="1.0",
                 controls=_build_controls(), is_active=True,
                 created_by=ADMIN_ID, created_at=dt(30), updated_at=dt(1))

    # ── Audit logs (50) ─────────────────────────────────────────────────────
    for log in _build_audit_logs():
        await _upsert(db, AuditLog, log["id"], **{k: v for k, v in log.items() if k != "id"})

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
    await async_engine.dispose()
    print("Demo seed complete.")


if __name__ == "__main__":
    asyncio.run(main())
