"""Vendor Risk Management (VRM) Engine for SOC 2 Type II CC9.2.

Automates third-party risk classification, standardized security questionnaire
evaluations (SIG Lite / CAIQ / SOC 2 Vendor), DPA/BAA verification, and SOC 2
report expiration tracking.
"""

from __future__ import annotations

import enum
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from sentinel.tenancy import get_current_tenant_id

logger = logging.getLogger("sentinel.vendor_risk")


class VendorTier(str, enum.Enum):
    """Vendor criticality tiers."""

    TIER_1_CRITICAL = (
        "TIER_1_CRITICAL"  # Stores customer data/PII or critical infrastructure
    )
    TIER_2_HIGH = "TIER_2_HIGH"  # Direct production access or operational dependency
    TIER_3_MEDIUM = "TIER_3_MEDIUM"  # Business tools without production access
    TIER_4_LOW = "TIER_4_LOW"  # Non-sensitive commodity software/hardware


class VendorStatus(str, enum.Enum):
    """Vendor compliance evaluation status."""

    APPROVED = "APPROVED"
    UNDER_REVIEW = "UNDER_REVIEW"
    CONDITIONAL = "CONDITIONAL"
    REJECTED = "REJECTED"
    OFFBOARDED = "OFFBOARDED"


class DataClassification(str, enum.Enum):
    """Classification of data shared with vendor."""

    RESTRICTED = "RESTRICTED"  # PII, financial, PHI, credentials
    CONFIDENTIAL = "CONFIDENTIAL"  # Internal business IP, source code
    INTERNAL = "INTERNAL"  # Standard operational logs/telemetry
    PUBLIC = "PUBLIC"  # Publicly accessible data


@dataclass
class SecurityQuestionnaire:
    """Standardized third-party vendor security assessment questionnaire."""

    has_soc2_type2: bool = False
    soc2_report_date: Optional[str] = None
    soc2_clean_opinion: bool = False
    enforces_mfa: bool = False
    encrypts_data_at_rest: bool = False
    encrypts_data_in_transit: bool = False
    has_annual_pentest: bool = False
    has_incident_response_plan: bool = False
    has_business_continuity_plan: bool = False
    has_background_checks: bool = False
    dpa_executed: bool = False
    baa_executed: bool = False
    subprocessors_documented: bool = False

    def calculate_score(self) -> float:
        """Calculate weighted compliance percentage (0.0 to 100.0)."""
        weights = {
            "has_soc2_type2": 25.0,
            "soc2_clean_opinion": 10.0,
            "enforces_mfa": 15.0,
            "encrypts_data_at_rest": 10.0,
            "encrypts_data_in_transit": 10.0,
            "has_annual_pentest": 10.0,
            "has_incident_response_plan": 5.0,
            "has_business_continuity_plan": 5.0,
            "dpa_executed": 5.0,
            "has_background_checks": 5.0,
        }
        score = 0.0
        for attr, weight in weights.items():
            if getattr(self, attr, False):
                score += weight
        return min(100.0, score)


@dataclass
class Vendor:
    """Third-party vendor compliance record."""

    vendor_id: str
    name: str
    service_description: str
    tier: VendorTier = VendorTier.TIER_3_MEDIUM
    data_classification: DataClassification = DataClassification.INTERNAL
    owner_email: str = ""
    status: VendorStatus = VendorStatus.UNDER_REVIEW
    soc2_valid_until: Optional[str] = None
    questionnaire: SecurityQuestionnaire = field(default_factory=SecurityQuestionnaire)
    risk_score: float = 0.0
    findings: List[str] = field(default_factory=list)
    last_assessment_date: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def evaluate_risk(self) -> None:
        """Perform automated risk assessment and update score/status."""
        findings: List[str] = []
        base_score = self.questionnaire.calculate_score()

        # Check SOC 2 expiration
        now = datetime.now(timezone.utc)
        if self.soc2_valid_until:
            try:
                valid_until_dt = datetime.fromisoformat(
                    self.soc2_valid_until.replace("Z", "+00:00")
                )
                days_left = (valid_until_dt - now).days
                if days_left < 0:
                    findings.append(
                        f"CRITICAL: Vendor SOC 2 Type II report expired {abs(days_left)} days ago."
                    )
                    base_score -= 20.0
                elif days_left <= 60:
                    findings.append(
                        f"WARNING: Vendor SOC 2 Type II report expires in {days_left} days."
                    )
            except Exception:
                findings.append("WARNING: Invalid soc2_valid_until datetime format.")
        elif self.tier in (VendorTier.TIER_1_CRITICAL, VendorTier.TIER_2_HIGH):
            findings.append(
                "HIGH: No SOC 2 Type II report on file for high-criticality vendor."
            )
            base_score -= 15.0

        # Tier 1 Critical requirements
        if self.tier == VendorTier.TIER_1_CRITICAL:
            if not self.questionnaire.dpa_executed and self.data_classification in (
                DataClassification.RESTRICTED,
                DataClassification.CONFIDENTIAL,
            ):
                findings.append(
                    "CRITICAL: Data Processing Agreement (DPA) missing for Tier 1 vendor."
                )
                base_score -= 15.0
            if not self.questionnaire.enforces_mfa:
                findings.append(
                    "CRITICAL: Vendor does not enforce MFA on staff identities."
                )
                base_score -= 15.0
            if not self.questionnaire.encrypts_data_at_rest:
                findings.append("CRITICAL: Encryption at rest not affirmed by vendor.")
                base_score -= 10.0

        self.risk_score = max(0.0, min(100.0, base_score))
        self.findings = findings

        if any(f.startswith("CRITICAL:") for f in findings):
            self.status = (
                VendorStatus.CONDITIONAL
                if self.risk_score >= 50.0
                else VendorStatus.REJECTED
            )
        elif self.risk_score >= 80.0:
            self.status = VendorStatus.APPROVED
        else:
            self.status = VendorStatus.UNDER_REVIEW

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tier"] = self.tier.value
        d["status"] = self.status.value
        d["data_classification"] = self.data_classification.value
        return d


class VendorRiskManager:
    """Manages vendor lifecycle, assessments, and SOC 2 CC9.2 compliance exports."""

    def __init__(self, base_root: Path | None = None) -> None:
        self.base_root = base_root or Path.cwd()

    def _get_storage_file(self, tenant_id: str) -> Path:
        if tenant_id == "default":
            folder = self.base_root / "config"
        else:
            folder = self.base_root / "tenants" / tenant_id / "config"
        folder.mkdir(parents=True, exist_ok=True)
        return folder / "vendors.json"

    def list_vendors(self, tenant_id: Optional[str] = None) -> List[Vendor]:
        """List all vendors registered in tenant storage."""
        tid = tenant_id or get_current_tenant_id()
        file_path = self._get_storage_file(tid)
        if not file_path.exists():
            return []

        try:
            raw = json.loads(file_path.read_text(encoding="utf-8"))
            vendors: List[Vendor] = []
            for item in raw:
                q_dict = item.pop("questionnaire", {})
                q = (
                    SecurityQuestionnaire(**q_dict)
                    if isinstance(q_dict, dict)
                    else SecurityQuestionnaire()
                )
                v = Vendor(
                    vendor_id=item["vendor_id"],
                    name=item["name"],
                    service_description=item.get("service_description", ""),
                    tier=VendorTier(item.get("tier", VendorTier.TIER_3_MEDIUM.value)),
                    data_classification=DataClassification(
                        item.get(
                            "data_classification", DataClassification.INTERNAL.value
                        )
                    ),
                    owner_email=item.get("owner_email", ""),
                    status=VendorStatus(
                        item.get("status", VendorStatus.UNDER_REVIEW.value)
                    ),
                    soc2_valid_until=item.get("soc2_valid_until"),
                    questionnaire=q,
                    risk_score=float(item.get("risk_score", 0.0)),
                    findings=item.get("findings", []),
                    last_assessment_date=item.get("last_assessment_date", ""),
                )
                vendors.append(v)
            return vendors
        except Exception as ex:
            logger.error("Failed to load vendors for tenant %s: %s", tid, ex)
            return []

    def save_vendor(self, vendor: Vendor, tenant_id: Optional[str] = None) -> Vendor:
        """Add or update a vendor record and persist to disk."""
        tid = tenant_id or get_current_tenant_id()
        vendor.evaluate_risk()
        vendors = self.list_vendors(tid)

        updated = False
        for idx, existing in enumerate(vendors):
            if existing.vendor_id == vendor.vendor_id:
                vendors[idx] = vendor
                updated = True
                break

        if not updated:
            vendors.append(vendor)

        file_path = self._get_storage_file(tid)
        serialized = [v.to_dict() for v in vendors]
        file_path.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
        return vendor

    def get_vendor(
        self, vendor_id: str, tenant_id: Optional[str] = None
    ) -> Optional[Vendor]:
        """Retrieve a specific vendor by ID."""
        for v in self.list_vendors(tenant_id):
            if v.vendor_id == vendor_id:
                return v
        return None

    def generate_cc92_report(self, tenant_id: Optional[str] = None) -> dict[str, Any]:
        """Generate SOC 2 CC9.2 Third-Party Vendor Risk Audit Summary."""
        vendors = self.list_vendors(tenant_id)
        total = len(vendors)
        approved = len([v for v in vendors if v.status == VendorStatus.APPROVED])
        conditional = len([v for v in vendors if v.status == VendorStatus.CONDITIONAL])
        rejected = len([v for v in vendors if v.status == VendorStatus.REJECTED])
        under_review = len(
            [v for v in vendors if v.status == VendorStatus.UNDER_REVIEW]
        )

        critical_gaps = []
        for v in vendors:
            for f in v.findings:
                if f.startswith("CRITICAL:"):
                    critical_gaps.append(f"[{v.name}] {f}")

        avg_score = (
            round(sum(v.risk_score for v in vendors) / total, 1) if total > 0 else 100.0
        )

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "control_id": "CC9.2",
            "title": "Vendor Risk Management Assessment Summary",
            "total_vendors": total,
            "approved": approved,
            "conditional": conditional,
            "under_review": under_review,
            "rejected": rejected,
            "average_compliance_score": avg_score,
            "compliant": len(critical_gaps) == 0 and rejected == 0,
            "critical_gaps": critical_gaps,
            "vendors": [v.to_dict() for v in vendors],
        }
