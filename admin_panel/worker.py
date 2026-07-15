from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from admin_panel.core import Database
from admin_panel.jobs import run_job


logger = logging.getLogger("admin_panel.worker")

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.getenv("ADMIN_DB_PATH", str(ROOT / "admin_panel" / "data" / "profiles.sqlite3")))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    db = Database(DB_PATH)
    db.fail_interrupted_jobs()
    poll_seconds = max(0.2, float(os.getenv("ADMIN_WORKER_POLL_SECONDS", "1")))
    logger.info("Profile worker watching %s", DB_PATH)
    while True:
        job_id = db.claim_next_job()
        if job_id is None:
            time.sleep(poll_seconds)
            continue
        try:
            run_job(db, ROOT, job_id)
        except Exception as exc:
            db.fail_job(job_id, f"Worker error: {exc}")


if __name__ == "__main__":
    main()
