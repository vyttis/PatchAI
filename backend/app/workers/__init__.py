"""PatchPilot Celery workers — imported by `celery -A backend.app.workers`."""

from backend.app.workers.celery_app import app as celery_app

__all__ = ["celery_app"]
