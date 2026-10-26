"""
Asset service: CRUD operations for discovered assets.
"""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class AssetService:
    """Service layer for asset management."""

    async def list_assets(self, filters: dict, db: AsyncSession) -> list:
        """List assets with optional filters."""
        from app.models.asset import Asset

        query = select(Asset)

        if filters.get("scan_job_id"):
            query = query.where(Asset.scan_job_id == filters["scan_job_id"])
        if filters.get("ip_address"):
            query = query.where(Asset.ip_address == filters["ip_address"])
        if filters.get("is_windows") is not None:
            query = query.where(Asset.is_windows == filters["is_windows"])

        page = filters.get("page", 1)
        size = filters.get("size", 50)
        query = query.offset((page - 1) * size).limit(size)

        result = await db.execute(query)
        return result.scalars().all()

    async def get_asset(self, asset_id: str, db: AsyncSession):
        """Get a single asset by ID."""
        from app.models.asset import Asset

        result = await db.execute(select(Asset).where(Asset.id == asset_id))
        return result.scalar_one_or_none()

    async def update_asset_criticality(
        self, asset_id: str, criticality: str, db: AsyncSession
    ):
        """Update the business criticality of an asset."""
        from app.models.asset import Asset

        result = await db.execute(select(Asset).where(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        if not asset:
            return None
        asset.business_criticality = criticality
        await db.commit()
        await db.refresh(asset)
        return asset

    async def get_asset_history(self, ip: str, db: AsyncSession) -> list:
        """Return all asset records for a given IP across all scans."""
        from app.models.asset import Asset

        result = await db.execute(
            select(Asset)
            .where(Asset.ip_address == ip)
            .order_by(Asset.created_at.desc())
        )
        return result.scalars().all()
