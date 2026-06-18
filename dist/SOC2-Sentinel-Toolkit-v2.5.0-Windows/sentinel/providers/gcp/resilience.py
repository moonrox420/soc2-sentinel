from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import api_error, finalize_snapshot
from sentinel.providers.gcp._client import GcpContext

logger = logging.getLogger("sentinel.providers.gcp.resilience")


def resilience_snapshot(ctx: GcpContext) -> dict[str, Any]:
    logger.info("collecting GCP resilience snapshot")
    last_backup_hours: float | None = None
    last_restore_days: int | None = None
    backup_success = 0
    backup_failed = 0
    failover_passed: bool | None = None

    try:
        from google.cloud import compute_v1

        compute = compute_v1.SnapshotsClient()
        ctx.attempt()
        snapshots = call_with_retry(
            lambda: list(compute.list(project=ctx.project_id)),
            operation="gcp_list_snapshots",
        )
        ctx.succeed()
        latest: datetime | None = None
        for snap in snapshots:
            backup_success += 1
            created = snap.creation_timestamp
            if created:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                if latest is None or dt > latest:
                    latest = dt
        if latest:
            last_backup_hours = round((datetime.now(timezone.utc) - latest).total_seconds() / 3600, 1)
    except Exception as exc:
        ctx.record_error("compute", exc)

    try:
        from googleapiclient import discovery
        import google.auth

        credentials, _ = google.auth.default()
        service = discovery.build("sqladmin", "v1", credentials=credentials, cache_discovery=False)
        ctx.attempt()
        instances = call_with_retry(
            lambda: service.instances().list(project=ctx.project_id).execute(),
            operation="gcp_sql_list_instances",
        )
        ctx.succeed()
        for instance in instances.get("items", []):
            name = instance["name"]
            runs = call_with_retry(
                lambda n=name: service.backupRuns()
                .list(project=ctx.project_id, instance=n)
                .execute(),
                operation="gcp_sql_backup_runs",
            )
            for run in runs.get("items", []):
                if run.get("status") == "SUCCESSFUL":
                    backup_success += 1
                    end = run.get("endTime")
                    if end:
                        dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                        hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
                        if last_backup_hours is None or hours < last_backup_hours:
                            last_backup_hours = round(hours, 1)
                elif run.get("status") == "FAILED":
                    backup_failed += 1
    except Exception as exc:
        ctx.record_error("sqladmin", exc)

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
                "No compute snapshots or Cloud SQL backups found",
                service="compute",
                severity="critical",
            )
        )

    return finalize_snapshot(
        data,
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )