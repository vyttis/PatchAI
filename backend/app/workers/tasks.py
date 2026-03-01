"""Celery task wrappers — thin sync shells around async IntelFetcher.run().

Each task wraps the async fetcher logic via asyncio.run().
"""

import asyncio
import logging
from uuid import UUID

import httpx

from backend.app.database import async_session
from backend.app.workers.celery_app import app
from backend.app.workers.intel_fetcher import (
    EPSSFetcher,
    GHSAFetcher,
    KEVFetcher,
    MSRCFetcher,
    NVDFetcher,
    check_staleness,
)

logger = logging.getLogger(__name__)


async def _run_fetcher(fetcher_cls, **kwargs):
    """Run a fetcher class inside a fresh DB session and HTTP client."""
    async with httpx.AsyncClient(timeout=60) as http:
        async with async_session() as db:
            fetcher = fetcher_cls(db=db, http=http, **kwargs)
            result = await fetcher.run()
            await db.commit()
            return {"status": result.status, "entity_count": result.entity_count}


@app.task(name="backend.app.workers.tasks.fetch_kev")
def fetch_kev():
    """Fetch CISA KEV catalog (every 4h)."""
    return asyncio.run(_run_fetcher(KEVFetcher))


@app.task(name="backend.app.workers.tasks.fetch_msrc")
def fetch_msrc():
    """Fetch MSRC security updates (every 2h)."""
    return asyncio.run(_run_fetcher(MSRCFetcher))


@app.task(name="backend.app.workers.tasks.fetch_epss")
def fetch_epss():
    """Fetch EPSS scores (daily 02:00)."""
    return asyncio.run(_run_fetcher(EPSSFetcher))


@app.task(name="backend.app.workers.tasks.fetch_nvd")
def fetch_nvd():
    """Fetch NVD modified CVEs (every 6h — enrichment ONLY, Invariant #9)."""
    return asyncio.run(_run_fetcher(NVDFetcher))


@app.task(name="backend.app.workers.tasks.fetch_ghsa")
def fetch_ghsa():
    """Fetch GitHub Security Advisories (daily 03:00)."""
    return asyncio.run(_run_fetcher(GHSAFetcher))


@app.task(name="backend.app.workers.tasks.check_feed_staleness")
def check_feed_staleness():
    """Check all feeds against staleness thresholds (every 1h)."""
    async def _check():
        async with async_session() as db:
            result = await check_staleness(db)
            await db.commit()
            return result

    return asyncio.run(_check())


@app.task(name="backend.app.workers.tasks.check_fleet_for_kev_exposure")
def check_fleet_for_kev_exposure(cve_id: str):
    """Fleet-wide vulnerability check triggered by new CISA KEV entry.

    Finds all devices and runs OS + app matching against the new KEV CVE.
    """
    async def _run():
        async with async_session() as db:
            from backend.app.workers.vuln_matching import (
                check_fleet_for_kev_exposure as _check,
            )
            result = await _check(db, cve_id)
            await db.commit()
            return result

    return asyncio.run(_run())


@app.task(name="backend.app.workers.tasks.vuln_match_os")
def vuln_match_os_task(device_id: str):
    """OS-level vulnerability matching for a single device (KB baseline + build)."""
    async def _run():
        async with async_session() as db:
            from backend.app.workers.vuln_matching import vuln_match_os
            result = await vuln_match_os(db, UUID(device_id))
            await db.commit()
            return result

    return asyncio.run(_run())


@app.task(name="backend.app.workers.tasks.vuln_match_apps")
def vuln_match_apps_task(device_id: str):
    """Third-party app vulnerability matching for a single device (CPE normalization)."""
    async def _run():
        async with async_session() as db:
            from backend.app.workers.vuln_matching import vuln_match_apps
            result = await vuln_match_apps(db, UUID(device_id))
            await db.commit()
            return result

    return asyncio.run(_run())
