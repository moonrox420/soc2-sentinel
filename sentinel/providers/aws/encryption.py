from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from sentinel.providers._snapshot import finalize_snapshot
from sentinel.providers.aws._client import AwsClients

logger = logging.getLogger("sentinel.providers.aws.encryption")

_FIPS_SPECS = frozenset({"SYMMETRIC_DEFAULT", "RSA_2048", "RSA_3072", "RSA_4096", "ECC_NIST_P256"})


def encryption_snapshot(ctx: AwsClients) -> dict[str, Any]:
    logger.info("collecting AWS encryption snapshot")
    s3 = ctx.client("s3")
    rds = ctx.client("rds")
    kms = ctx.client("kms")
    acm = ctx.client("acm")
    elbv2 = ctx.client("elbv2")

    resources: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    fips_keys = 0
    pending_rotation = 0
    tls_checked = 0
    weak_tls = 0

    buckets_resp = ctx.call("s3", "aws_s3_list_buckets", lambda: s3.list_buckets())
    if buckets_resp:
        for bucket in buckets_resp.get("Buckets", []):
            name = bucket["Name"]
            encrypted = False
            ctx.attempt()
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                ctx.succeed()
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                encrypted = any(
                    r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                    in ("AES256", "aws:kms")
                    for r in rules
                )
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    ctx.succeed()
                    encrypted = False
                else:
                    ctx.record_access_denied("s3", exc)
            resources.append({"resource": f"s3://{name}", "encrypted": encrypted, "type": "S3"})
            if not encrypted:
                findings.append({"resource": f"s3://{name}", "issue": "unencrypted"})

    rds_resp = ctx.call("rds", "aws_rds_describe", lambda: rds.describe_db_instances())
    if rds_resp:
        for db in rds_resp.get("DBInstances", []):
            encrypted = db.get("StorageEncrypted", False)
            resources.append(
                {"resource": db["DBInstanceIdentifier"], "encrypted": encrypted, "type": "RDS"}
            )
            if not encrypted:
                findings.append({"resource": db["DBInstanceIdentifier"], "issue": "unencrypted"})

    keys_resp = ctx.call("kms", "aws_kms_list_keys", lambda: kms.list_keys())
    if keys_resp:
        for key in keys_resp.get("Keys", []):
            meta_resp = ctx.call(
                "kms",
                "aws_kms_describe_key",
                lambda k=key: kms.describe_key(KeyId=k["KeyId"]),
            )
            if not meta_resp:
                continue
            meta = meta_resp.get("KeyMetadata", {})
            if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
                spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec", "")
                rot_resp = ctx.call(
                    "kms",
                    "aws_kms_rotation",
                    lambda k=key: kms.get_key_rotation_status(KeyId=k["KeyId"]),
                )
                if rot_resp and rot_resp.get("KeyRotationEnabled"):
                    if spec in _FIPS_SPECS:
                        fips_keys += 1
                else:
                    pending_rotation += 1

    certs_resp = ctx.call("acm", "aws_acm_list_certs", lambda: acm.list_certificates())
    if certs_resp:
        for summary in certs_resp.get("CertificateSummaryList", []):
            tls_checked += 1
            arn = summary["CertificateArn"]
            detail_resp = ctx.call(
                "acm",
                "aws_acm_describe_cert",
                lambda a=arn: acm.describe_certificate(CertificateArn=a),
            )
            if detail_resp:
                cert = detail_resp.get("Certificate", {})
                not_after = cert.get("NotAfter")
                if not_after and not_after < datetime.now(timezone.utc):
                    weak_tls += 1
                    findings.append({"resource": arn, "issue": "expired certificate"})

    ssl_resp = ctx.call("elbv2", "aws_elb_ssl_policies", lambda: elbv2.describe_ssl_policies())
    if ssl_resp:
        for policy in ssl_resp.get("SslPolicies", []):
            tls_checked += 1
            name = policy.get("Name", "")
            if "2016" in name or "2015" in name:
                weak_tls += 1

    unencrypted = len([r for r in resources if not r.get("encrypted")])

    return finalize_snapshot(
        {
            "resources": resources,
            "total_confidential_resources": len(resources),
            "encrypted_at_rest": len(resources) - unencrypted,
            "unencrypted_cui_count": unencrypted,
            "fips_compliant_keys": fips_keys,
            "keys_pending_rotation": pending_rotation,
            "tls_endpoints_checked": tls_checked,
            "weak_cipher_endpoints": weak_tls,
            "findings": findings,
        },
        ctx.errors,
        checks_attempted=ctx._checks_attempted,
        checks_succeeded=ctx._checks_succeeded,
    )