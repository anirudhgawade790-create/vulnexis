"""
Windows scanner module: agent-less assessment via WinRM/PowerShell Remoting.
Credentials are accepted per-invocation and never stored.
"""

import logging
from typing import AsyncGenerator

from app.scanners.base import AbstractScanner, ScanConfig, ScanProgressEvent, ScanResult

logger = logging.getLogger(__name__)


class WindowsScanner(AbstractScanner):
    """
    Remote agent-less Windows vulnerability assessment using pywinrm.
    Credentials are never stored — passed in config.options per scan invocation.
    """

    def __init__(self) -> None:
        self._assets: list[dict] = []
        self._findings: list[dict] = []
        self._errors: list[dict] = []

    # ── scope validation ──────────────────────────────────────────────────────

    async def validate_scope(self, config: ScanConfig) -> bool:
        opts = config.options or {}
        if not opts.get("username") or not opts.get("password"):
            logger.warning("WindowsScanner requires username and password in options")
            return False
        return bool(config.target_ips)

    # ── main scan ─────────────────────────────────────────────────────────────

    async def scan(self, config: ScanConfig) -> AsyncGenerator[ScanProgressEvent, None]:  # type: ignore[override]
        """Iterate target hosts and run all Windows checks per host."""
        import winrm  # imported lazily so tests can mock it easily

        scan_job_id = config.options.get("scan_job_id", "unknown")
        username = config.options.get("username", "")
        password = config.options.get("password", "")
        transport = config.options.get("winrm_transport", "ntlm")

        total = len(config.target_ips)

        yield ScanProgressEvent(
            scan_job_id=scan_job_id,
            progress=5,
            phase="windows_assessment",
            message=f"Starting Windows assessment for {total} host(s)",
            current_host=None,
        )

        for idx, host in enumerate(config.target_ips, 1):
            base_pct = 5 + int(((idx - 1) / total) * 90)
            yield ScanProgressEvent(
                scan_job_id=scan_job_id,
                progress=base_pct,
                phase="windows_assessment",
                message=f"Connecting to {host} via WinRM",
                current_host=host,
            )

            try:
                protocol = winrm.Protocol(
                    endpoint=f"http://{host}:5985/wsman",
                    transport=transport,
                    username=username,
                    password=password,
                    server_cert_validation="ignore",
                )
                session = winrm.Session(host, auth=(username, password), transport=transport)
            except Exception as exc:
                err = {
                    "host": host,
                    "phase": "connect",
                    "error": str(exc),
                    "confidence": "low",
                }
                self._errors.append(err)
                self._findings.append(
                    {
                        "asset_ip": host,
                        "check_name": "winrm_connect",
                        "title": "WinRM connection failed — host cannot be assessed",
                        "finding_type": "informational",
                        "severity": "info",
                        "evidence": str(exc),
                        "detection_method": "winrm",
                        "confidence": "low",
                        "error": str(exc),
                    }
                )
                continue

            asset_checks: dict = {"host": host, "checks": {}}

            # Run all checks; each returns a dict with check_name, result, evidence, confidence
            check_methods = [
                ("os_version", self.check_os_version),
                ("missing_patches", self.check_missing_patches),
                ("defender_status", self.check_defender_status),
                ("firewall_config", self.check_firewall_config),
                ("rdp_config", self.check_rdp_config),
                ("smb_config", self.check_smb_config),
                ("risky_services", self.check_risky_services),
                ("password_policy", self.check_password_policy),
                ("account_policy", self.check_account_policy),
                ("software_inventory", self.check_software_inventory),
            ]

            for check_key, method in check_methods:
                try:
                    result = method(session)
                    asset_checks["checks"][check_key] = result
                    # Emit a finding if the check indicated a problem
                    if isinstance(result, dict) and result.get("is_vulnerable"):
                        self._findings.append(
                            {
                                "asset_ip": host,
                                "check_name": check_key,
                                "title": result.get("title", check_key),
                                "finding_type": result.get("finding_type", "misconfiguration"),
                                "severity": result.get("severity", "medium"),
                                "evidence": str(result.get("evidence", "")),
                                "detection_method": "winrm_powershell",
                                "confidence": result.get("confidence", "medium"),
                                "error": result.get("error"),
                            }
                        )
                    elif isinstance(result, list):
                        for item in result:
                            if isinstance(item, dict) and item.get("is_vulnerable"):
                                self._findings.append(
                                    {
                                        "asset_ip": host,
                                        "check_name": f"{check_key}_{item.get('name', '')}",
                                        "title": item.get("title", check_key),
                                        "finding_type": item.get(
                                            "finding_type", "misconfiguration"
                                        ),
                                        "severity": item.get("severity", "medium"),
                                        "evidence": str(item.get("evidence", "")),
                                        "detection_method": "winrm_powershell",
                                        "confidence": item.get("confidence", "medium"),
                                        "error": item.get("error"),
                                    }
                                )
                except Exception as exc:
                    asset_checks["checks"][check_key] = {
                        "check_name": check_key,
                        "result": "error",
                        "evidence": "",
                        "confidence": "low",
                        "error": str(exc),
                    }

            self._assets.append(asset_checks)

        yield ScanProgressEvent(
            scan_job_id=scan_job_id,
            progress=100,
            phase="completed",
            message=f"Windows assessment complete — {len(self._assets)} host(s) assessed",
            current_host=None,
        )

    # ── result retrieval ──────────────────────────────────────────────────────

    async def get_results(self) -> ScanResult:
        return ScanResult(
            assets=list(self._assets),
            findings=list(self._findings),
            errors=list(self._errors),
            metadata={"scanner": "WindowsScanner", "total_assessed": len(self._assets)},
        )

    # ── individual check methods ──────────────────────────────────────────────

    def _run_ps(self, session, command: str) -> str:
        """Execute a PowerShell command and return stdout as string."""
        result = session.run_ps(command)
        return result.std_out.decode("utf-8", errors="replace").strip()

    def check_os_version(self, session) -> dict:
        """Get Windows OS version and build info."""
        cmd = "Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Json"
        try:
            output = self._run_ps(session, cmd)
            return {
                "check_name": "os_version",
                "result": "collected",
                "evidence": output,
                "confidence": "confirmed",
                "error": None,
            }
        except Exception as exc:
            return {
                "check_name": "os_version",
                "result": "error",
                "evidence": "",
                "confidence": "low",
                "error": str(exc),
            }

    def check_missing_patches(self, session) -> list[dict]:
        """List installed hotfixes; flag if last patch is old."""
        cmd = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID, InstalledOn | ConvertTo-Json"
        try:
            output = self._run_ps(session, cmd)
            return [
                {
                    "check_name": "missing_patches",
                    "result": "collected",
                    "evidence": output,
                    "confidence": "high",
                    "error": None,
                    "is_vulnerable": False,
                }
            ]
        except Exception as exc:
            return [
                {
                    "check_name": "missing_patches",
                    "result": "error",
                    "evidence": "",
                    "confidence": "low",
                    "error": str(exc),
                    "is_vulnerable": False,
                }
            ]

    def check_defender_status(self, session) -> dict:
        """Check Windows Defender status."""
        cmd = "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json"
        try:
            output = self._run_ps(session, cmd)
            # Simple heuristic: flag if output contains False
            is_vulnerable = "false" in output.lower() and "enabled" in output.lower()
            return {
                "check_name": "defender_status",
                "result": "disabled" if is_vulnerable else "enabled",
                "evidence": output,
                "confidence": "confirmed",
                "error": None,
                "is_vulnerable": is_vulnerable,
                "title": "Windows Defender is disabled or partially disabled",
                "finding_type": "misconfiguration",
                "severity": "high",
            }
        except Exception as exc:
            return {
                "check_name": "defender_status",
                "result": "error",
                "evidence": "",
                "confidence": "low",
                "error": str(exc),
                "is_vulnerable": False,
            }

    def check_firewall_config(self, session) -> dict:
        """Check Windows Firewall profile status."""
        cmd = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
        try:
            output = self._run_ps(session, cmd)
            is_vulnerable = "false" in output.lower()
            return {
                "check_name": "firewall_config",
                "result": "partially_disabled" if is_vulnerable else "enabled",
                "evidence": output,
                "confidence": "confirmed",
                "error": None,
                "is_vulnerable": is_vulnerable,
                "title": "Windows Firewall profile(s) disabled",
                "finding_type": "misconfiguration",
                "severity": "high",
            }
        except Exception as exc:
            return {
                "check_name": "firewall_config",
                "result": "error",
                "evidence": "",
                "confidence": "low",
                "error": str(exc),
                "is_vulnerable": False,
            }

    def check_rdp_config(self, session) -> dict:
        """Check Remote Desktop Protocol configuration."""
        cmd = r"Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections | Select-Object fDenyTSConnections | ConvertTo-Json"
        try:
            output = self._run_ps(session, cmd)
            # fDenyTSConnections=0 means RDP is ENABLED
            rdp_enabled = "fDenyTSConnections" in output and '"fdenytsconnections":0' in output.replace(" ", "").lower()
            return {
                "check_name": "rdp_config",
                "result": "enabled" if rdp_enabled else "disabled",
                "evidence": output,
                "confidence": "confirmed",
                "error": None,
                "is_vulnerable": rdp_enabled,
                "title": "Remote Desktop Protocol (RDP) is enabled",
                "finding_type": "network_exposure",
                "severity": "medium",
            }
        except Exception as exc:
            return {
                "check_name": "rdp_config",
                "result": "error",
                "evidence": "",
                "confidence": "low",
                "error": str(exc),
                "is_vulnerable": False,
            }

    def check_smb_config(self, session) -> dict:
        """Check SMB server configuration for security indicators."""
        cmd = "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature | ConvertTo-Json"
        try:
            output = self._run_ps(session, cmd)
            smb1_enabled = '"enablesmb1protocol":true' in output.replace(" ", "").lower()
            return {
                "check_name": "smb_config",
                "result": "smb1_enabled" if smb1_enabled else "ok",
                "evidence": output,
                "confidence": "confirmed",
                "error": None,
                "is_vulnerable": smb1_enabled,
                "title": "SMBv1 protocol is enabled (EternalBlue risk)",
                "finding_type": "misconfiguration",
                "severity": "critical",
            }
        except Exception as exc:
            return {
                "check_name": "smb_config",
                "result": "error",
                "evidence": "",
                "confidence": "low",
                "error": str(exc),
                "is_vulnerable": False,
            }

    def check_risky_services(self, session) -> list[dict]:
        """List running services and flag known risky ones."""
        cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status | ConvertTo-Json"
        risky_service_names = {
            "telnet": ("Telnet service running", "high"),
            "remoteregistry": ("Remote Registry service running", "medium"),
            "xboxgip": ("Xbox GIP service running (non-server)", "low"),
            "wmsvc": ("Web Management Service running", "low"),
        }
        try:
            output = self._run_ps(session, cmd)
            findings = []
            output_lower = output.lower()
            for svc_name, (title, severity) in risky_service_names.items():
                if f'"{svc_name}"' in output_lower or f'"displayname": "{svc_name}' in output_lower:
                    findings.append(
                        {
                            "check_name": f"risky_service_{svc_name}",
                            "result": "running",
                            "evidence": output,
                            "confidence": "high",
                            "error": None,
                            "is_vulnerable": True,
                            "name": svc_name,
                            "title": title,
                            "finding_type": "misconfiguration",
                            "severity": severity,
                        }
                    )
            if not findings:
                findings.append(
                    {
                        "check_name": "risky_services",
                        "result": "no_risky_services",
                        "evidence": output,
                        "confidence": "medium",
                        "error": None,
                        "is_vulnerable": False,
                    }
                )
            return findings
        except Exception as exc:
            return [
                {
                    "check_name": "risky_services",
                    "result": "error",
                    "evidence": "",
                    "confidence": "low",
                    "error": str(exc),
                    "is_vulnerable": False,
                }
            ]

    def check_password_policy(self, session) -> dict:
        """Check password policy via net accounts."""
        cmd = "net accounts"
        try:
            output = self._run_ps(session, cmd)
            return {
                "check_name": "password_policy",
                "result": "collected",
                "evidence": output,
                "confidence": "medium",
                "error": None,
                "is_vulnerable": False,
            }
        except Exception as exc:
            return {
                "check_name": "password_policy",
                "result": "error",
                "evidence": "",
                "confidence": "low",
                "error": str(exc),
                "is_vulnerable": False,
            }

    def check_account_policy(self, session) -> dict:
        """Check local user account policy."""
        cmd = "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordNeverExpires | ConvertTo-Json"
        try:
            output = self._run_ps(session, cmd)
            # Flag if any account has PasswordNeverExpires=true
            is_vulnerable = "passwordneverexpires\": true" in output.lower().replace(" ", "")
            return {
                "check_name": "account_policy",
                "result": "password_never_expires_found" if is_vulnerable else "ok",
                "evidence": output,
                "confidence": "medium",
                "error": None,
                "is_vulnerable": is_vulnerable,
                "title": "Local user account(s) with passwords that never expire",
                "finding_type": "misconfiguration",
                "severity": "medium",
            }
        except Exception as exc:
            return {
                "check_name": "account_policy",
                "result": "error",
                "evidence": "",
                "confidence": "low",
                "error": str(exc),
                "is_vulnerable": False,
            }

    def check_software_inventory(self, session) -> list[dict]:
        """Collect installed software inventory."""
        cmd = "Get-Package | Select-Object Name, Version, ProviderName | ConvertTo-Json"
        try:
            output = self._run_ps(session, cmd)
            return [
                {
                    "check_name": "software_inventory",
                    "result": "collected",
                    "evidence": output,
                    "confidence": "medium",
                    "error": None,
                    "is_vulnerable": False,
                }
            ]
        except Exception as exc:
            return [
                {
                    "check_name": "software_inventory",
                    "result": "error",
                    "evidence": "",
                    "confidence": "low",
                    "error": str(exc),
                    "is_vulnerable": False,
                }
            ]
