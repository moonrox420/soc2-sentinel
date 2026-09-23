from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import api_error, finalize_snapshot
from sentinel.providers.azure._client import AzureContext

logger = logging.getLogger("sentinel.providers.azure.resilience")


def resilience_snapshot(ctx: AzureContext) -> dict[str, Any]:
    logger.info("collecting Azure resilience snapshot")
    last_backup_hours: float | None = None
    last_successful_restore_days: int | None = None
    backup_success = 0
    backup_failed = 0

    try:
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        backup_client = RecoveryServicesBackupClient(
            ctx.credential,
            ctx.subscription_id,
        )
        ctx.attempt()
        vaults = call_with_retry(
            lambda: list(backup_client.backup_vaults.list_in_subscription()),
            operation="azure_list_backup_vaults",
        )
        ctx.succeed()

        latest_backup: datetime | None = None
        latest_restore: datetime | None = None
        window_start = datetime.now(timezone.utc) - timedelta(days=30)
        window_filter = f"startTime ge {window_start.strftime('%Y-%m-%dT%H:%M:%SZ')}"

        for vault in vaults:
            vault_name = vault.name
            rg = vault.id.split("/")[4]
            jobs = call_with_retry(
                lambda: list(
                    backup_client.backup_jobs.list(
                        rg,
                        vault_name,
                        filter=window_filter,
                    )
                ),
                operation="azure_backup_jobs",
            )
            for job in jobs:
                status = str(getattr(job.properties, "status", "") or "")
                operation = str(getattr(job.properties, "operation", "") or "").lower()
                end = getattr(job.properties, "end_time", None)

                if status == "Completed":
                    if "restore" in operation:
                        if end and (latest_restore is None or end > latest_restore):
                            latest_restore = end
                    elif "backup" in operation:
                        backup_success += 1
                        if end and (latest_backup is None or end > latest_backup):
                            latest_backup = end
                elif status == "Failed" and "backup" in operation:
                    backup_failed += 1

            protected = call_with_retry(
                lambda: list(
                    backup_client.backup_protected_items.list(rg, vault_name)
                ),
                operation="azure_protected_items",
            )
            for item in protected:
                lrp = getattr(item.properties, "last_recovery_point", None)
                if lrp:
                    hours = (
                        datetime.now(timezone.utc) - lrp.replace(tzinfo=timezone.utc)
                    ).total_seconds() / 3600
                    if last_backup_hours is None or hours < last_backup_hours:
                        last_backup_hours = round(hours, 1)

        if latest_backup:
            last_backup_hours = round(
                (
                    datetime.now(timezone.utc)
                    - latest_backup.replace(tzinfo=timezone.utc)
                ).total_seconds()
                / 3600,
                1,
            )

        if latest_restore:
            last_successful_restore_days = (
                datetime.now(timezone.utc)
                - latest_restore.replace(tzinfo=timezone.utc)
            ).days

    except Exception as exc:
        ctx.record_error("recoveryservicesbackup", exc)

    data: dict[str, Any] = {
        "last_backup_hours_ago": last_backup_hours,
        "last_restore_test_days_ago": None,
        "last_successful_restore_days_ago": last_successful_restore_days,
        "rto_target_hours": 4,
        "rpo_target_hours": 1,
        "failover_test_days_ago": None,
        "failover_test_passed": None,
        "backup_jobs_success_30d": backup_success,
        "backup_jobs_failed_30d": backup_failed,
    }

    if last_backup_hours is None:
        ctx.errors.append(
            api_error(
                "NoBackupEvidence",
                "No Recovery Services backup jobs or recovery points found",
                service="recoveryservicesbackup",
                severity="critical",
            )
        )

    ctx.errors.append(
        api_error(
            "FailoverTestNotCollected",
            "Backup success does not prove restore-test or failover-test execution",
            service="recoveryservicesbackup",
            severity="high",
        )
    )

    return finalize_snapshot(
        data,
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )
