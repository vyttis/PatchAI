"""Celery application and Beat schedule for PatchPilot intel feed workers.

Feed cadence (settled — do not change):
  KEV:  every 4h  — emergency trigger
  MSRC: every 2h  — emergency co-trigger
  EPSS: daily 02:00 — urgency multiplier
  NVD:  every 6h  — enrichment ONLY (Invariant #9)
  GHSA: daily 03:00 — third-party coverage
  Staleness check: every 1h
  Recheck unpatched exposures: every 1h (zero-day response)
  GDPR retention cleanup: daily 04:00
"""

from celery import Celery
from celery.schedules import crontab

from backend.app.config import settings

app = Celery(
    "patchpilot",
    broker=settings.redis_url or "redis://localhost:6379/0",
    backend=settings.redis_url or "redis://localhost:6379/0",
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

app.conf.beat_schedule = {
    "fetch_kev": {
        "task": "backend.app.workers.tasks.fetch_kev",
        "schedule": crontab(minute=0, hour="*/4"),
    },
    "fetch_msrc": {
        "task": "backend.app.workers.tasks.fetch_msrc",
        "schedule": crontab(minute=0, hour="*/2"),
    },
    "fetch_epss": {
        "task": "backend.app.workers.tasks.fetch_epss",
        "schedule": crontab(minute=0, hour=2),
    },
    "fetch_nvd": {
        "task": "backend.app.workers.tasks.fetch_nvd",
        "schedule": crontab(minute=0, hour="*/6"),
    },
    "fetch_ghsa": {
        "task": "backend.app.workers.tasks.fetch_ghsa",
        "schedule": crontab(minute=0, hour=3),
    },
    "check_feed_staleness": {
        "task": "backend.app.workers.tasks.check_feed_staleness",
        "schedule": crontab(minute=0),
    },
    "recheck_unpatched_exposures": {
        "task": "backend.app.workers.tasks.recheck_unpatched_exposures",
        "schedule": crontab(minute=30),
    },
    "gdpr_retention_cleanup": {
        "task": "backend.app.workers.tasks.gdpr_retention_cleanup",
        "schedule": crontab(minute=0, hour=4),
    },
}
