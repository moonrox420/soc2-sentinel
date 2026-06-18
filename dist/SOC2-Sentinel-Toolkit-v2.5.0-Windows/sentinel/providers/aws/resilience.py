from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.providers._snapshot import api_error, finalize_snapshot
from sentinel.providers.aws._client import AwsClients

logger = logging.getLogger("sentinel.providers.aws.resilience")


def resilience_snapshot(ctx: AwsClients) -> dict[str, Any]:
    logger.info("collecting AWS resilience snapshot")
    backup = ctx.client("backup")
    rds = ctx.client("rds")

    last_backup_hours: float | None = None
    last_restore_days: int | None = None
    backup_success = 0
    backup_failed = 0
    failover_passed: bool | None = None
    restore_jobs_found = 0

    since = datetime.now(timezone.utc) - timedelta(days=30)
    jobs_resp = ctx.call(
        "backup",
        "aws_backup_list_jobs",
        lambda: backup.list_backup_jobs(ByCreatedAfter=since, MaxResults=100),
    )
    if jobs_resp:
        latest: datetime | None = None
        for job in jobs_resp.get("BackupJobs", []):
            state = job.get("State", "")
            if state == "COMPLETED":
                backup_success += 1
            elif state == "FAILED":
                backup_failed += 1
            created = job.get("CreationDate")
            if created and (latest is None or created > latest):
                latest = created
        if latest:
            last_backup_hours = round(
                (datetime.now(timezone.utc) - latest).total_seconds() / 3600, 1
            )

    restore_resp = ctx.call(
        "backup",
        "aws_backup_restore_jobs",
        lambda: backup.list_restore_jobs(ByCreatedAfter=since, MaxResults=50),
    )
    if restore_resp:
        latest_restore: datetime | None = None
        for job in restore_resp.get("RestoreJobs", []):
            restore_jobs_found += 1
            created = job.get("CreationDate")
            if created and (latest_restore is None or created > latest_restore):
                latest_restore = created
        if latest_restore:
            last_restore_days = (datetime.now(timezone.utc) - latest_restore).days
            failover_passed = any(
                j.get("State") == "COMPLETED" for j in restore_resp.get("RestoreJobs", [])
            )

    if last_backup_hours is None:
        snap_resp = ctx.call("rds", "aws_rds_snapshots", lambda: rds.describe_db_snapshots())
        if snap_resp:
            latest_snap: datetime | None = None
            for snap in snap_resp.get("DBSnapshots", []):
                created = snap.get("SnapshotCreateTime")
                if created and (latest_snap is None or created > latest_snap):
                    latest_snap = created
            if latest_snap:
                last_backup_hours = round(
                    (datetime.now(timezone.utc) - latest_snap).total_seconds() / 3600, 1
                )
                backup_success += 1

    data: dict[str, Any] = {
        "last_backup_hours_ago": last_backup_hours,
        "last_restore_test_days_ago": last_restore_days,
        "rto_target_hours": 4,
        "rpo_target_hours": 1,
        "failover_test_days_ago": last_restore_days,
        "failover_test_passed": failover_passed,
        "backup_jobs_success_30d": backup_success,
        "backup_jobs_failed_30d": backup_failed,
    }

    if last_backup_hours is None:
        ctx.errors.append(
            api_error(
                "NoBackupEvidence",
                "No AWS Backup jobs or RDS snapshots found in the last 30 days",
                service="backup",
                severity="critical",
            )
        )
    if failover_passed is None:
        ctx.errors.append(
            api_error(
                "NoRestoreEvidence",
                "No restore job evidence; failover_test_passed not asserted",
                service="backup",
                severity="medium",
            )
        )

    return finalize_snapshot(
        data,
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )