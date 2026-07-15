from __future__ import annotations

from pathlib import Path

from admin_panel.core import Database
from admin_panel.integrations import ProfileCreator


def run_job(db: Database, root: Path, job_id: int) -> None:
    creator = ProfileCreator(root)
    accounts = db.job_accounts(job_id)
    completed = 0
    failed = 0
    db.mark_job(job_id, "running", completed, failed)
    for account in accounts:
        try:
            selected = creator.select_low_fraud_proxy(account["country"])
            proxy = selected["proxy"]
            fraud = selected["fraud"]
            proxy_id = creator.create_vision_proxy(account["profile_name"], proxy)
            profile_id = creator.create_vision_profile(account, proxy_id)
            completed += 1
            db.mark_account_result(
                account["id"],
                profile_id=profile_id,
                proxy_id=proxy_id,
                proxy_endpoint=creator.proxy_endpoint(proxy),
            )
            db.mark_fraud_checked(account["id"], fraud["score"], fraud["ip"], fraud["risk"])
        except Exception as exc:
            failed += 1
            db.mark_account_result(account["id"], error=str(exc))
        db.mark_job(job_id, "running", completed, failed)
    db.mark_job(job_id, "completed" if not failed else "completed_with_errors", completed, failed)
