"""
Baseline service: assesses assets against configurable security baseline policies.
"""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class BaselineService:
    """
    Evaluate security baseline compliance for assets and scan jobs.
    Each control's check_command is a PowerShell snippet;
    results are pass/fail/unknown.
    """

    async def assess_asset(
        self, asset, policy, db: AsyncSession
    ) -> list[dict]:
        """
        Evaluate a single asset against all controls in a policy.
        Returns list of control result dicts.
        """
        controls = policy.controls or []
        results: list[dict] = []

        for control in controls:
            control_id = control.get("id", "unknown")
            result = {
                "control_id": control_id,
                "title": control.get("title", ""),
                "description": control.get("description", ""),
                "result": "unknown",
                "evidence": "",
                "check_command": control.get("check_command", ""),
            }

            # We don't execute commands here — evidence comes from existing findings
            # Match against stored windows_details or findings for this asset
            check_key = control.get("finding_check_name", "")
            if check_key and asset.windows_details:
                checks = asset.windows_details.get("checks", {})
                check_result = checks.get(check_key, {})
                if isinstance(check_result, dict):
                    result["result"] = (
                        "pass"
                        if check_result.get("result") not in ("error", "disabled", "smb1_enabled")
                        else "fail"
                    )
                    result["evidence"] = str(check_result.get("evidence", ""))

            results.append(result)

        return results

    async def assess_scan(
        self, scan_job_id: str, policy_id: str, db: AsyncSession
    ) -> dict:
        """
        Assess all assets in a scan against a baseline policy.
        Returns summary with per-control results and overall compliance %.
        """
        from app.models.asset import Asset
        from app.models.baseline_policy import BaselinePolicy

        # Load policy
        policy_result = await db.execute(
            select(BaselinePolicy).where(BaselinePolicy.id == policy_id)
        )
        policy = policy_result.scalar_one_or_none()
        if not policy:
            return {"error": f"Policy {policy_id} not found"}

        # Load assets
        assets_result = await db.execute(
            select(Asset).where(Asset.scan_job_id == scan_job_id)
        )
        assets = assets_result.scalars().all()

        all_results: list[dict] = []
        for asset in assets:
            asset_results = await self.assess_asset(asset, policy, db)
            for r in asset_results:
                r["asset_id"] = asset.id
                r["asset_ip"] = asset.ip_address
                all_results.append(r)

        total = len(all_results)
        passed = sum(1 for r in all_results if r["result"] == "pass")
        failed = sum(1 for r in all_results if r["result"] == "fail")
        unknown = sum(1 for r in all_results if r["result"] == "unknown")

        compliance_pct = (passed / total * 100) if total > 0 else 0.0

        return {
            "scan_job_id": scan_job_id,
            "policy_id": policy_id,
            "policy_name": policy.name,
            "total_controls_assessed": total,
            "passed": passed,
            "failed": failed,
            "unknown": unknown,
            "compliance_percentage": round(compliance_pct, 1),
            "results": all_results,
        }
