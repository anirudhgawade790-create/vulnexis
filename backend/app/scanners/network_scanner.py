"""
Network scanner module: host discovery, port scanning, service fingerprinting.
Uses python-nmap (nmap.PortScanner) under the hood.
"""

import ipaddress
import logging
from typing import AsyncGenerator

from app.scanners.base import AbstractScanner, ScanConfig, ScanProgressEvent, ScanResult

logger = logging.getLogger(__name__)

# Services considered risky / high-exposure
_RISKY_PORTS: dict[int, dict] = {
    21: {"service": "ftp", "risk": "Unencrypted file transfer", "severity": "medium"},
    23: {"service": "telnet", "risk": "Unencrypted remote access", "severity": "high"},
    135: {"service": "msrpc", "risk": "Windows RPC endpoint mapper exposed", "severity": "medium"},
    137: {"service": "netbios-ns", "risk": "NetBIOS name service exposed", "severity": "medium"},
    139: {"service": "netbios-ssn", "risk": "NetBIOS session service exposed", "severity": "medium"},
    445: {"service": "smb", "risk": "SMB exposed — potential lateral movement vector", "severity": "high"},
    3389: {"service": "rdp", "risk": "Remote Desktop Protocol exposed", "severity": "high"},
    5900: {"service": "vnc", "risk": "VNC remote desktop exposed", "severity": "high"},
    5985: {"service": "winrm-http", "risk": "WinRM (HTTP) management interface exposed", "severity": "medium"},
    5986: {"service": "winrm-https", "risk": "WinRM (HTTPS) management interface exposed", "severity": "low"},
}


class NetworkScanner(AbstractScanner):
    """Authorized network discovery and port scan using nmap."""

    def __init__(self) -> None:
        self._assets: list[dict] = []
        self._findings: list[dict] = []
        self._errors: list[dict] = []

    # ── scope validation ──────────────────────────────────────────────────────

    async def validate_scope(self, config: ScanConfig) -> bool:
        """Return True if all target_ips are valid IPv4/IPv6 addresses or CIDRs."""
        if not config.target_ips:
            return False
        for ip_str in config.target_ips:
            try:
                # Accepts single IPs and CIDR notation
                ipaddress.ip_network(ip_str, strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(ip_str)
                except ValueError:
                    logger.warning("Invalid IP/CIDR in scan scope: %s", ip_str)
                    return False
        return True

    # ── main scan ─────────────────────────────────────────────────────────────

    async def scan(self, config: ScanConfig) -> AsyncGenerator[ScanProgressEvent, None]:  # type: ignore[override]
        """Three-phase scan: discovery → port scan → service fingerprint."""
        import nmap  # imported here so callers that mock nmap don't need it at module level

        scan_job_id = config.options.get("scan_job_id", "unknown")
        nm = nmap.PortScanner()

        targets = " ".join(config.target_ips)
        timeout = config.options.get("timeout", 60)

        # ── Phase 1: Host discovery ─────────────────────────────────────────
        yield ScanProgressEvent(
            scan_job_id=scan_job_id,
            progress=5,
            phase="discovery",
            message=f"Starting host discovery for {len(config.target_ips)} target(s)",
            current_host=None,
        )

        try:
            nm.scan(hosts=targets, arguments=f"-sn --host-timeout {timeout}s")
        except Exception as exc:
            self._errors.append({"phase": "discovery", "error": str(exc)})
            logger.error("Host discovery failed: %s", exc)
            return

        live_hosts: list[str] = [h for h in nm.all_hosts() if nm[h].state() == "up"]
        logger.info("Discovery found %d live hosts", len(live_hosts))

        yield ScanProgressEvent(
            scan_job_id=scan_job_id,
            progress=20,
            phase="discovery",
            message=f"Discovery complete — {len(live_hosts)} host(s) up",
            current_host=None,
        )

        if not live_hosts:
            yield ScanProgressEvent(
                scan_job_id=scan_job_id,
                progress=100,
                phase="completed",
                message="Network scan complete — no live hosts found",
                current_host=None,
            )
            return

        # ── Phase 2: Port scan ──────────────────────────────────────────────
        total = len(live_hosts)
        for idx, host in enumerate(live_hosts, 1):
            pct = 20 + int((idx / total) * 50)
            yield ScanProgressEvent(
                scan_job_id=scan_job_id,
                progress=pct,
                phase="port_scan",
                message=f"Scanning ports on {host}",
                current_host=host,
            )
            try:
                nm.scan(hosts=host, arguments=f"-sV --open -T4 --host-timeout {timeout}s")
            except Exception as exc:
                self._errors.append({"host": host, "phase": "port_scan", "error": str(exc)})
                logger.warning("Port scan failed for %s: %s", host, exc)
                continue

            if host not in nm.all_hosts():
                continue

            asset = self._parse_nmap_host(nm[host])
            risky = self._detect_risky_services(asset.get("open_ports", []))
            asset["risky_services"] = risky
            self._assets.append(asset)

            for svc in risky:
                self._findings.append(
                    {
                        "asset_ip": host,
                        "check_name": f"risky_service_{svc['port']}",
                        "title": f"Risky service exposed: {svc['service']} on port {svc['port']}",
                        "finding_type": "network_exposure",
                        "severity": svc.get("severity", "medium"),
                        "evidence": f"Port {svc['port']}/{svc['protocol']} ({svc['service']}) open — {svc['risk']}",
                        "detection_method": "nmap_port_scan",
                        "confidence": "high",
                    }
                )

        # ── Phase 3: Service fingerprint summary ────────────────────────────
        yield ScanProgressEvent(
            scan_job_id=scan_job_id,
            progress=90,
            phase="fingerprint",
            message="Service fingerprinting complete",
            current_host=None,
        )

        yield ScanProgressEvent(
            scan_job_id=scan_job_id,
            progress=100,
            phase="completed",
            message=f"Network scan complete — {len(self._assets)} asset(s) discovered",
            current_host=None,
        )

    # ── result retrieval ──────────────────────────────────────────────────────

    async def get_results(self) -> ScanResult:
        return ScanResult(
            assets=list(self._assets),
            findings=list(self._findings),
            errors=list(self._errors),
            metadata={"scanner": "NetworkScanner", "total_assets": len(self._assets)},
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    def _parse_nmap_host(self, host_data) -> dict:
        """Extract structured asset information from a nmap host result."""
        ip = host_data.get("addresses", {}).get("ipv4", "")
        hostname = ""
        hostnames = host_data.get("hostnames", [])
        if hostnames:
            hostname = hostnames[0].get("name", "")

        open_ports: list[dict] = []
        for proto in host_data.all_protocols() if hasattr(host_data, "all_protocols") else []:
            for port, port_data in host_data[proto].items():
                if port_data.get("state") == "open":
                    open_ports.append(
                        {
                            "port": int(port),
                            "protocol": proto,
                            "service": port_data.get("name", ""),
                            "version": port_data.get("version", ""),
                            "banner": port_data.get("product", ""),
                            "extra_info": port_data.get("extrainfo", ""),
                        }
                    )

        os_guess = ""
        osmatch = host_data.get("osmatch", [])
        if osmatch:
            os_guess = osmatch[0].get("name", "")

        return {
            "ip": ip,
            "hostname": hostname,
            "open_ports": open_ports,
            "os_guess": os_guess,
            "state": host_data.state() if hasattr(host_data, "state") else "unknown",
        }

    def _detect_risky_services(self, open_ports: list[dict]) -> list[dict]:
        """Return list of risky service findings for given open ports."""
        risky: list[dict] = []
        for port_entry in open_ports:
            port = int(port_entry.get("port", 0))
            if port in _RISKY_PORTS:
                info = _RISKY_PORTS[port]
                risky.append(
                    {
                        "port": port,
                        "protocol": port_entry.get("protocol", "tcp"),
                        "service": info["service"],
                        "risk": info["risk"],
                        "severity": info["severity"],
                        "banner": port_entry.get("banner", ""),
                        "version": port_entry.get("version", ""),
                    }
                )
        return risky
