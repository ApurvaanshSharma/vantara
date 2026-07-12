"""
Celery application instance.

task_ignore_result=True: we don't call .get() on these tasks anywhere — the
ingest endpoint fires a task and moves on (fire-and-forget). Without this,
Celery stores a result for every task run in Redis forever, for no reason
we'd ever read.
"""

from celery import Celery

from app.core.config import settings

celery_app = Celery("vantara", broker=settings.celery_broker_url)
celery_app.conf.task_ignore_result = True

# Auto-discovers tasks in app/workers/tasks.py without needing to import it
# manually everywhere the app is created.
celery_app.autodiscover_tasks(["app.workers"])
