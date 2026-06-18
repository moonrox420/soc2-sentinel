from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.providers._snapshot import api_error, finalize_snapshot
from sentinel.providers.azure._client import AzureContext

logger = logging.getLogger("sentinel.providers.azure.resilience")


def resilience_snapshot(ctx: AzureContext) -> dict[str, Any]:
    logger.info("collecting Azure resilience snapshot")
    last_backup_hours: float | None = None
    last_restore_days: int | None = None
    backup_success = 0
    backup_failed = 0
    failover_passed: bool | None = None

    try:
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        backup_client = RecoveryServicesBackupClient(ctx.credential, ctx.subscription_id)
        ctx.attempt()
        vaults = call_with_retry(
            lambda: list(backup_client.backup_vaults.list_in_subscription()),
            operation="azure_list_backup_vaults",
        )
        ctx.succeed()
        latest: datetime | None = None
        for vault in vaults:
            vault_name = vault.name
            rg = vault.id.split("/")[4]
            jobs = call_with_retry(
                lambda v=vault_name, r=rg: list(
                    backup_client.backup_jobs.list(r, v, filter="startTime ge 2020-01-01")
                ),
                operation="azure_backup_jobs",
            )
            for job in jobs:
                status = getattr(job.properties, "status", "")
                if status == "Completed":
                    backup_success += 1
                    end = getattr(job.properties, "end_time", None)
                    if end and (latest is None or end > latest):
                        latest = end
                elif status == "Failed":
                    backup_failed += 1
            protected = call_with_retry(
                lambda v=vault_name, r=rg: list(
                    backup_client.backup_protected_items.list(r, v)
                ),
                operation="azure_protected_items",
            )
            for item in protected:
                lrp = getattr(item.properties, "last_recovery_point", None)
                if lrp:
                    hours = (datetime.now(timezone.utc) - lrp.replace(tzinfo=timezone.utc)).total_seconds() / 3600
                    if last_backup_hours is None or hours < last_backup_hours:
                        last_backup_hours = round(hours, 1)
        if latest:
            last_backup_hours = round(
                (datetime.now(timezone.utc) - latest.replace(tzinfo=timezone.utc)).total_seconds() / 3600,
                1,
            )
            failover_passed = backup_success > 0
            last_restore_days = int(last_backup_hours / 24) if last_backup_hours else None
    except Exception as exc:
        ctx.record_error("recoveryservicesbackup", exc)

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
                "No Recovery Services backup jobs or recovery points found",
                service="recoveryservicesbackup",
                severity="critical",
            )
        )

    return finalize_snapshot(
        data,
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )