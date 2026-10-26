from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.dashboard import (
    DashboardSummary,
    ExposureMapData,
    ExposureNode,
    InsightItem,
    TrendData,
    TrendDataPoint,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
async def get_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    # Total assets
    total_assets = (await db.execute(select(func.count(Asset.id)))).scalar_one()
    windows_assets = (
        await db.execute(select(func.count(Asset.id)).where(Asset.is_windows == True))  # noqa: E712
    ).scalar_one()

    # Findings
    findings_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.status == "open")
        .group_by(Finding.severity)
    )
    findings_by_severity = {row[0]: row[1] for row in findings_result}
    open_findings = sum(findings_by_severity.values())

    total_vulns = (
        await db.execute(select(func.count(Finding.id)).where(Finding.finding_type == "confirmed_vulnerability"))
    ).scalar_one()

    remediated = (
        await db.execute(select(func.count(Finding.id)).where(Finding.status == "remediated"))
    ).scalar_one()

    # Last scan
    last_scan_result = await db.execute(
        select(ScanJob.completed_at).order_by(ScanJob.completed_at.desc()).limit(1)
    )
    last_scan_at = last_scan_result.scalar_one_or_none()

    # Compute basic posture score: 100 - penalty for open findings
    critical_count = findings_by_severity.get("critical", 0)
    high_count = findings_by_severity.get("high", 0)
    penalty = min(critical_count * 10 + high_count * 3, 100)
    posture_score = max(0.0, 100.0 - penalty)

    return DashboardSummary(
        total_assets=total_assets,
        windows_assets=windows_assets,
        total_vulnerabilities=total_vulns,
        findings_by_severity=findings_by_severity,
        overall_posture_score=posture_score,
        unpatched_systems=0,
        critical_assets_at_risk=critical_count,
        open_findings=open_findings,
        remediated_findings=remediated,
        last_scan_at=last_scan_at,
    )


@router.get("/trends", response_model=TrendData)
async def get_trends(
    _: User = Depends(get_current_user),
):
    """Return trend data (stub — populated by demo data seeder)."""
    return TrendData(
        period_days=30,
        data_points=[
            TrendDataPoint(date="2025-01-01", critical=0, high=0, medium=0, low=0, total=0)
        ],
        posture_trend=[],
    )


@router.get("/insights", response_model=List[InsightItem])
async def get_insights(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Rule-based security insights derived from current scan data."""
    insights: List[InsightItem] = []
    now = datetime.now(timezone.utc)

    # Insight: critical open findings
    critical_count = (
        await db.execute(
            select(func.count(Finding.id))
            .where(Finding.severity == "critical", Finding.status == "open")
        )
    ).scalar_one()

    if critical_count > 0:
        insights.append(
            InsightItem(
                id="insight-critical-open",
                title=f"{critical_count} critical finding(s) require immediate attention",
                detail=(
                    f"There are {critical_count} open critical-severity findings. "
                    "These represent the highest exploitability risk and should be prioritized."
                ),
                severity="critical",
                category="attention",
                evidence_tags=["critical_findings", "open_status"],
                created_at=now,
            )
        )

    # Insight: KEV-linked findings
    kev_count = (
        await db.execute(
            select(func.count(Finding.id))
            .join(Finding.vulnerability)
            .where(
                Finding.status == "open",
                Finding.vulnerability_id.isnot(None),
            )
        )
    ).scalar_one()

    if kev_count > 0:
        insights.append(
            InsightItem(
                id="insight-kev",
                title=f"{kev_count} finding(s) linked to actively exploited vulnerabilities",
                detail=(
                    "Findings correlated with CISA Known Exploited Vulnerabilities (KEV) "
                    "represent active exploitation risk and should be remediated urgently."
                ),
                severity="critical",
                category="impact",
                evidence_tags=["cisa_kev", "active_exploitation"],
                created_at=now,
            )
        )

    if not insights:
        insights.append(
            InsightItem(
                id="insight-no-data",
                title="No scan data available yet",
                detail="Run a scan to generate security insights.",
                severity="info",
                category="change",
                evidence_tags=[],
                created_at=now,
            )
        )

    return insights


@router.get("/top-risks", response_model=List[dict])
async def get_top_risks(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return top 10 open findings by risk score."""
    result = await db.execute(
        select(Finding)
        .where(Finding.status == "open")
        .order_by(Finding.risk_score.desc())
        .limit(10)
    )
    findings = result.scalars().all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "asset_id": f.asset_id,
            "finding_type": f.finding_type,
        }
        for f in findings
    ]


@router.get("/exposure-map", response_model=ExposureMapData)
async def get_exposure_map(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return asset nodes for exposure visualization."""
    result = await db.execute(
        select(Asset).order_by(Asset.risk_score.desc()).limit(100)
    )
    assets = result.scalars().all()

    nodes = []
    for asset in assets:
        ports = asset.open_ports or []
        # Determine highest finding severity for this asset
        sev_result = await db.execute(
            select(Finding.severity)
            .where(Finding.asset_id == asset.id, Finding.status == "open")
            .order_by(
                Finding.risk_score.desc()
            )
            .limit(1)
        )
        severity = sev_result.scalar_one_or_none() or "info"
        nodes.append(
            ExposureNode(
                id=asset.id,
                ip_address=asset.ip_address,
                hostname=asset.hostname,
                risk_score=asset.risk_score or 0.0,
                asset_type=asset.asset_type,
                open_port_count=len(ports),
                severity=severity,
            )
        )

    total_ports = sum(len(a.open_ports or []) for a in assets)
    high_risk = sum(1 for n in nodes if n.risk_score >= 7.0)

    return ExposureMapData(
        nodes=nodes,
        total_exposed_ports=total_ports,
        high_risk_count=high_risk,
        generated_at=datetime.now(timezone.utc),
    )
