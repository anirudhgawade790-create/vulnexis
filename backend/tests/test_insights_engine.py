"""
Tests for InsightsEngine: each rule fires when condition met, returns None when not.
Uses async SQLite via the conftest fixtures.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import TestAsyncSessionLocal, auth_headers


# ── helpers ────────────────────────────────────────────────────────────────────

async def _add(db: AsyncSession, obj):
    db.add(obj)
    await db.flush()
    return obj


async def _get_db() -> AsyncSession:
    async with TestAsyncSessionLocal() as session:
        return session


# ── fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def async_session():
    """Yields a live async session for each test."""
    import asyncio

    loop = asyncio.new_event_loop()

    session_holder = {}

    async def _open():
        session = TestAsyncSessionLocal()
        await session.__aenter__()
        session_holder["s"] = session
        return session

    session = loop.run_until_complete(_open())
    yield session, loop

    async def _close():
        await session.__aexit__(None, None, None)

    loop.run_until_complete(_close())
    loop.close()


def _run(loop, coro):
    return loop.run_until_complete(coro)


# ── seed helpers ───────────────────────────────────────────────────────────────

def _make_user(role="admin"):
    from app.models.user import User
    from app.services.auth_service import hash_password

    return User(
        id=str(uuid.uuid4()),
        username=f"u_{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@test.local",
        hashed_password=hash_password("Admin@1234"),
        role=role,
        is_active=True,
    )


def _make_target(user_id):
    from app.models.target import Target

    return Target(
        id=str(uuid.uuid4()),
        name="Test Target",
        scope_type="ip",
        scope_value="192.168.1.1",
        is_active=True,
        business_criticality="medium",
        created_by=user_id,
    )


def _make_scan(target_id, user_id, status="completed", completed_offset_seconds=0):
    from app.models.scan_job import ScanJob

    now = datetime.now(timezone.utc)
    return ScanJob(
        id=str(uuid.uuid4()),
        target_id=target_id,
        scan_type="full",
        status=status,
        started_by=user_id,
        progress=100 if status == "completed" else 0,
        completed_at=now - timedelta(seconds=completed_offset_seconds),
        started_at=now - timedelta(seconds=completed_offset_seconds + 30),
    )


def _make_asset(scan_id, target_id, ip="10.0.0.1", criticality="medium", is_windows=False, is_supported=True):
    from app.models.asset import Asset

    return Asset(
        id=str(uuid.uuid4()),
        scan_job_id=scan_id,
        target_id=target_id,
        ip_address=ip,
        is_windows=is_windows,
        business_criticality=criticality,
        is_supported_os=is_supported,
    )


def _make_finding(scan_id, asset_id, check_name="test_check", severity="medium",
                  status="open", risk_score=5.0, finding_type="misconfiguration",
                  vuln_id=None, evidence=""):
    from app.models.finding import Finding

    return Finding(
        id=str(uuid.uuid4()),
        scan_job_id=scan_id,
        asset_id=asset_id,
        vulnerability_id=vuln_id,
        title=f"Test finding {check_name}",
        finding_type=finding_type,
        severity=severity,
        check_name=check_name,
        evidence=evidence or "test evidence",
        detection_method="test",
        confidence="high",
        risk_score=risk_score,
        status=status,
    )


def _make_vuln(cve_id=None, is_kev=False, severity="high"):
    from app.models.vulnerability import Vulnerability

    return Vulnerability(
        id=str(uuid.uuid4()),
        cve_id=cve_id,
        title=f"Vuln {cve_id or 'no-cve'}",
        description="Test vulnerability",
        severity=severity,
        is_kev=is_kev,
        source="test",
    )


# ── rule_risk_increased ────────────────────────────────────────────────────────

def test_rule_risk_increased_fires(reset_db, async_session):
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    user = _make_user()
    _run(loop, _add(session, user))

    target = _make_target(user.id)
    _run(loop, _add(session, target))

    scan_old = _make_scan(target.id, user.id, completed_offset_seconds=60)
    scan_new = _make_scan(target.id, user.id, completed_offset_seconds=0)
    _run(loop, _add(session, scan_old))
    _run(loop, _add(session, scan_new))

    asset_old = _make_asset(scan_old.id, target.id, ip="10.0.0.1")
    asset_new = _make_asset(scan_new.id, target.id, ip="10.0.0.1")
    _run(loop, _add(session, asset_old))
    _run(loop, _add(session, asset_new))

    # Old: 1 finding with risk 5.0
    finding_old = _make_finding(scan_old.id, asset_old.id, risk_score=5.0)
    _run(loop, _add(session, finding_old))
    # New: 1 finding with risk 8.0 → 60% increase
    finding_new = _make_finding(scan_new.id, asset_new.id, check_name="test2", risk_score=8.0)
    _run(loop, _add(session, finding_new))

    _run(loop, session.commit())

    engine = InsightsEngine()
    result = _run(loop, engine.rule_risk_increased(session))

    assert result is not None
    assert "increased" in result["title"].lower()


def test_rule_risk_increased_returns_none_single_scan(reset_db, async_session):
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    user = _make_user()
    _run(loop, _add(session, user))
    target = _make_target(user.id)
    _run(loop, _add(session, target))
    scan = _make_scan(target.id, user.id)
    _run(loop, _add(session, scan))
    _run(loop, session.commit())

    engine = InsightsEngine()
    result = _run(loop, engine.rule_risk_increased(session))
    assert result is None


# ── rule_critical_kev ─────────────────────────────────────────────────────────

def test_rule_critical_kev_fires(reset_db, async_session):
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    user = _make_user()
    _run(loop, _add(session, user))
    target = _make_target(user.id)
    _run(loop, _add(session, target))
    scan = _make_scan(target.id, user.id)
    _run(loop, _add(session, scan))
    asset = _make_asset(scan.id, target.id)
    _run(loop, _add(session, asset))

    vuln = _make_vuln(cve_id="CVE-2021-34527", is_kev=True, severity="critical")
    _run(loop, _add(session, vuln))

    finding = _make_finding(
        scan.id, asset.id,
        severity="critical", status="open", vuln_id=vuln.id, risk_score=10.0
    )
    _run(loop, _add(session, finding))
    _run(loop, session.commit())

    engine = InsightsEngine()
    result = _run(loop, engine.rule_critical_kev(session))

    assert result is not None
    assert result["severity"] == "critical"


def test_rule_critical_kev_returns_none_no_kev(reset_db, async_session):
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    engine = InsightsEngine()
    result = _run(loop, engine.rule_critical_kev(session))
    assert result is None


# ── rule_unsupported_os ───────────────────────────────────────────────────────

def test_rule_unsupported_os_fires(reset_db, async_session):
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    user = _make_user()
    _run(loop, _add(session, user))
    target = _make_target(user.id)
    _run(loop, _add(session, target))
    scan = _make_scan(target.id, user.id)
    _run(loop, _add(session, scan))

    eol_asset = _make_asset(scan.id, target.id, ip="10.0.0.5", is_supported=False)
    _run(loop, _add(session, eol_asset))
    _run(loop, session.commit())

    engine = InsightsEngine()
    result = _run(loop, engine.rule_unsupported_os(session))

    assert result is not None
    assert "unsupported" in result["title"].lower()
    assert result["severity"] == "critical"


def test_rule_unsupported_os_returns_none_all_supported(reset_db, async_session):
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    user = _make_user()
    _run(loop, _add(session, user))
    target = _make_target(user.id)
    _run(loop, _add(session, target))
    scan = _make_scan(target.id, user.id)
    _run(loop, _add(session, scan))
    asset = _make_asset(scan.id, target.id, ip="10.0.0.1", is_supported=True)
    _run(loop, _add(session, asset))
    _run(loop, session.commit())

    engine = InsightsEngine()
    result = _run(loop, engine.rule_unsupported_os(session))
    assert result is None


# ── rule_defender_disabled ────────────────────────────────────────────────────

def test_rule_defender_disabled_fires(reset_db, async_session):
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    user = _make_user()
    _run(loop, _add(session, user))
    target = _make_target(user.id)
    _run(loop, _add(session, target))
    scan = _make_scan(target.id, user.id)
    _run(loop, _add(session, scan))
    asset = _make_asset(scan.id, target.id, is_windows=True)
    _run(loop, _add(session, asset))

    finding = _make_finding(
        scan.id, asset.id,
        check_name="defender_status",
        severity="high",
        finding_type="misconfiguration",
        evidence='{"AMServiceEnabled": false}',
    )
    _run(loop, _add(session, finding))
    _run(loop, session.commit())

    engine = InsightsEngine()
    result = _run(loop, engine.rule_defender_disabled(session))

    assert result is not None
    assert "defender" in result["title"].lower()


def test_rule_defender_disabled_returns_none_no_findings(reset_db, async_session):
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    engine = InsightsEngine()
    result = _run(loop, engine.rule_defender_disabled(session))
    assert result is None


# ── rule_top_remediation ──────────────────────────────────────────────────────

def test_rule_top_remediation_fires(reset_db, async_session):
    session, loop = async_session
    from app.models.finding import Finding
    from app.services.insights_engine import InsightsEngine

    user = _make_user()
    _run(loop, _add(session, user))
    target = _make_target(user.id)
    _run(loop, _add(session, target))
    scan = _make_scan(target.id, user.id)
    _run(loop, _add(session, scan))
    asset = _make_asset(scan.id, target.id)
    _run(loop, _add(session, asset))

    finding = _make_finding(scan.id, asset.id, risk_score=9.5, severity="critical")
    finding.remediation_steps = [{"type": "powershell", "command": "Set-MpPreference ..."}]
    _run(loop, _add(session, finding))
    _run(loop, session.commit())

    engine = InsightsEngine()
    result = _run(loop, engine.rule_top_remediation(session))

    assert result is not None
    assert "9.5" in result["detail"]


def test_rule_top_remediation_returns_none_no_open_findings(reset_db, async_session):
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    engine = InsightsEngine()
    result = _run(loop, engine.rule_top_remediation(session))
    assert result is None


# ── generate_insights ordering ────────────────────────────────────────────────

def test_generate_insights_ordered_by_severity(reset_db, async_session):
    """Insights should be ordered critical → high → medium → low → info."""
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    user = _make_user()
    _run(loop, _add(session, user))
    target = _make_target(user.id)
    _run(loop, _add(session, target))
    scan = _make_scan(target.id, user.id)
    _run(loop, _add(session, scan))
    asset = _make_asset(scan.id, target.id, is_supported=False)
    _run(loop, _add(session, asset))
    _run(loop, session.commit())

    engine = InsightsEngine()
    results = _run(loop, engine.generate_insights(session))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    severities = [severity_order.get(r["severity"], 99) for r in results]
    assert severities == sorted(severities)


def test_generate_insights_max_10(reset_db, async_session):
    """generate_insights must return at most 10 results."""
    session, loop = async_session
    from app.services.insights_engine import InsightsEngine

    engine = InsightsEngine()
    results = _run(loop, engine.generate_insights(session))
    assert len(results) <= 10
