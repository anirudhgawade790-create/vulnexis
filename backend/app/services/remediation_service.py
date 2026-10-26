"""
Remediation service: converts findings into actionable remediation plans.
PowerShell examples are display-only and never auto-executed.
"""

import logging

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Pre-defined remediation templates keyed by check_name
_REMEDIATION_TEMPLATES: dict[str, dict] = {
    "defender_status": {
        "plain_explanation": "Windows Defender is disabled or partially disabled on this system.",
        "technical_explanation": "AMServiceEnabled, AntivirusEnabled, or RealTimeProtectionEnabled returned False via Get-MpComputerStatus.",
        "potential_impact": "The host has reduced or no antivirus protection, making it vulnerable to malware infections.",
        "recommended_fix": "Enable all Windows Defender components via Group Policy or PowerShell.",
        "required_permissions": "Local Administrator or Domain Admin",
        "estimated_effort": "low",
        "verification_steps": [
            "Run: Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled",
            "Confirm all values are True",
        ],
        "documentation_links": [
            "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows"
        ],
        "rollback_considerations": "Enabling Defender may impact performance on legacy systems. Test in non-production first.",
        "powershell_examples": [
            "# Enable Windows Defender real-time protection (requires Administrator)\nSet-MpPreference -DisableRealtimeMonitoring $false",
            "# Verify Defender status\nGet-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled",
        ],
    },
    "firewall_config": {
        "plain_explanation": "One or more Windows Firewall profiles are disabled.",
        "technical_explanation": "Get-NetFirewallProfile returned Enabled=False for one or more profiles (Domain, Private, or Public).",
        "potential_impact": "Without the firewall, the host is directly exposed to network-based attacks.",
        "recommended_fix": "Enable all Windows Firewall profiles.",
        "required_permissions": "Local Administrator",
        "estimated_effort": "low",
        "verification_steps": [
            "Run: Get-NetFirewallProfile | Select-Object Name, Enabled",
            "Confirm all profiles show Enabled = True",
        ],
        "documentation_links": [
            "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security"
        ],
        "rollback_considerations": "Enabling the firewall may block legitimate traffic. Review existing rules before enabling.",
        "powershell_examples": [
            "# Enable all firewall profiles (requires Administrator)\nSet-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        ],
    },
    "smb_config": {
        "plain_explanation": "SMBv1 is enabled on this system, which is vulnerable to EternalBlue (MS17-010).",
        "technical_explanation": "Get-SmbServerConfiguration returned EnableSMB1Protocol = True.",
        "potential_impact": "SMBv1 is exploited by WannaCry, NotPetya, and similar ransomware. It should be disabled on all modern systems.",
        "recommended_fix": "Disable SMBv1 via PowerShell or Group Policy.",
        "required_permissions": "Local Administrator",
        "estimated_effort": "low",
        "verification_steps": [
            "Run: Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol",
            "Confirm EnableSMB1Protocol = False",
        ],
        "documentation_links": [
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
        ],
        "rollback_considerations": "Some legacy applications may require SMBv1. Verify no dependencies before disabling.",
        "powershell_examples": [
            "# Disable SMBv1 (requires Administrator, reboot may be needed)\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            "# Verify\nGet-SmbServerConfiguration | Select-Object EnableSMB1Protocol",
        ],
    },
    "rdp_config": {
        "plain_explanation": "Remote Desktop Protocol is enabled on this system.",
        "technical_explanation": "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server fDenyTSConnections = 0 indicates RDP is enabled.",
        "potential_impact": "Exposed RDP is a common attack vector for brute force attacks and exploitation of RDP vulnerabilities.",
        "recommended_fix": "If RDP is not required, disable it. If required, restrict access via firewall rules and enable Network Level Authentication.",
        "required_permissions": "Local Administrator",
        "estimated_effort": "medium",
        "verification_steps": [
            "Confirm RDP is needed for this host",
            "If disabled: Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections should return 1",
            "If kept: verify NLA is enabled and RDP port is firewall-restricted",
        ],
        "documentation_links": [
            "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
        ],
        "rollback_considerations": "Disabling RDP will terminate all remote desktop sessions.",
        "powershell_examples": [
            "# Disable RDP (requires Administrator)\nSet-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
            "# Enable NLA (if keeping RDP enabled)\nSet-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
        ],
    },
    "missing_patches": {
        "plain_explanation": "This system may be missing security updates.",
        "technical_explanation": "The installed hotfix list retrieved via Get-HotFix does not include recent security updates.",
        "potential_impact": "Missing patches leave known vulnerabilities unmitigated and may allow exploitation.",
        "recommended_fix": "Run Windows Update or deploy patches via WSUS/SCCM.",
        "required_permissions": "Local Administrator",
        "estimated_effort": "medium",
        "verification_steps": [
            "Run Windows Update manually or check WSUS compliance report",
            "Re-run Get-HotFix after patching to verify",
        ],
        "documentation_links": [
            "https://support.microsoft.com/en-us/windows/update-windows-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a"
        ],
        "rollback_considerations": "Some patches may require a reboot. Test in non-production when possible.",
        "powershell_examples": [
            "# Check for available updates (requires PSWindowsUpdate module)\nGet-WindowsUpdate",
            "# Install all available updates\nInstall-WindowsUpdate -AcceptAll -AutoReboot",
        ],
    },
    "winrm_connect": {
        "plain_explanation": "This host could not be assessed because the WinRM connection failed.",
        "technical_explanation": "The WinRM Protocol connection to this host was refused or timed out.",
        "potential_impact": "The security posture of this host is unknown — it cannot be confirmed as secure.",
        "recommended_fix": "Verify WinRM is enabled on the target and that network connectivity and credentials are correct.",
        "required_permissions": "Local Administrator on target",
        "estimated_effort": "medium",
        "verification_steps": [
            "Test-WSMan <target_hostname>",
            "Verify firewall allows port 5985 (WinRM HTTP) or 5986 (HTTPS)",
        ],
        "documentation_links": [
            "https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management"
        ],
        "rollback_considerations": "Enabling WinRM expands the attack surface. Restrict access using firewall rules.",
        "powershell_examples": [
            "# Enable WinRM (run on target, requires Administrator)\nEnable-PSRemoting -Force",
        ],
    },
}

_DEFAULT_TEMPLATE = {
    "plain_explanation": "A security finding was detected on this host.",
    "technical_explanation": "Refer to the finding evidence for technical details.",
    "potential_impact": "This finding may increase the risk profile of the affected asset.",
    "recommended_fix": "Review the finding evidence and apply the appropriate remediation.",
    "required_permissions": "Administrator",
    "estimated_effort": "medium",
    "verification_steps": ["Re-run the scan after remediation to verify the finding is resolved."],
    "documentation_links": [],
    "rollback_considerations": "Test changes in a non-production environment first.",
    "powershell_examples": [],
}


class RemediationService:
    """Assembles remediation details and plans."""

    async def get_remediation_detail(self, finding_id: str, db: AsyncSession) -> dict:
        """Return a RemediationDetail dict for a given finding."""
        from app.models.finding import Finding

        result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            return {}

        template = _REMEDIATION_TEMPLATES.get(finding.check_name, _DEFAULT_TEMPLATE)

        # Merge any powershell_examples stored in the finding itself
        stored_steps = finding.remediation_steps or []
        ps_from_finding = [
            step.get("command", "")
            for step in stored_steps
            if isinstance(step, dict) and step.get("type") == "powershell"
        ]
        ps_examples = ps_from_finding or template.get("powershell_examples", [])

        return {
            "finding_id": finding_id,
            "title": finding.title,
            "plain_explanation": template["plain_explanation"],
            "technical_explanation": template["technical_explanation"],
            "potential_impact": template["potential_impact"],
            "recommended_fix": template["recommended_fix"],
            "required_permissions": template["required_permissions"],
            "estimated_effort": template["estimated_effort"],
            "verification_steps": template["verification_steps"],
            "documentation_links": template["documentation_links"],
            "rollback_considerations": template["rollback_considerations"],
            "powershell_examples": ps_examples,
        }

    async def get_remediation_plan(self, db: AsyncSession) -> list[dict]:
        """Return all open findings ordered by risk_score desc."""
        from app.models.finding import Finding

        result = await db.execute(
            select(Finding)
            .where(Finding.status == "open")
            .order_by(desc(Finding.risk_score))
        )
        findings = result.scalars().all()
        return [
            {
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "check_name": f.check_name,
                "asset_id": f.asset_id,
            }
            for f in findings
        ]
