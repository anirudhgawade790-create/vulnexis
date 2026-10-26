"""
Vulnerability service: list, sync, and query vulnerability records.
"""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class VulnService:
    """Service layer for vulnerability intelligence management."""

    async def list_vulns(self, filters: dict, db: AsyncSession) -> list:
        """List vulnerabilities with optional severity/is_kev filters."""
        from app.models.vulnerability import Vulnerability

        query = select(Vulnerability)
        if filters.get("severity"):
            query = query.where(Vulnerability.severity == filters["severity"])
        if filters.get("is_kev") is not None:
            query = query.where(Vulnerability.is_kev == filters["is_kev"])

        page = filters.get("page", 1)
        size = filters.get("size", 50)
        query = query.offset((page - 1) * size).limit(size)

        result = await db.execute(query)
        return result.scalars().all()

    async def get_vuln(self, vuln_id: str, db: AsyncSession):
        """Get a single vulnerability by ID."""
        from app.models.vulnerability import Vulnerability

        result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
        return result.scalar_one_or_none()

    async def sync_vulns(self, db: AsyncSession) -> dict:
        """Sync CISA KEV catalog and return summary."""
        from app.scanners.vuln_correlator import VulnCorrelator

        correlator = VulnCorrelator()
        summary = correlator.sync_kev_catalog(db)
        return summary

    async def list_kev(self, db: AsyncSession) -> list:
        """Return all KEV vulnerabilities."""
        from app.models.vulnerability import Vulnerability

        result = await db.execute(
            select(Vulnerability).where(Vulnerability.is_kev == True)  # noqa: E712
        )
        return result.scalars().all()
