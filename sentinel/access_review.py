"""User Access Review (UAR) & Access Certification Engine (SOC 2 CC6.1, CC6.2, CC6.3).

Automates periodic access certification campaigns, tracks reviewer decisions
(maintain, revoke, modify), and produces cryptographically signed audit
certificates for quarterly auditor examination.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from sentinel.tenancy import get_current_tenant_id

logger = logging.getLogger("sentinel.access_review")


class ReviewDecision(str, enum.Enum):
    """Reviewer decision on an identity access entitlement."""

    PENDING = "PENDING"
    MAINTAIN = "MAINTAIN"
    REVOKE = "REVOKE"
    MODIFY = "MODIFY"


class CampaignStatus(str, enum.Enum):
    """Lifecycle status of an access certification campaign."""

    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


@dataclass
class AccessReviewItem:
    """Individual identity access line item under review."""

    item_id: str
    identity_name: str
    identity_email: str
    provider: str
    role_or_policy: str
    resource: str
    is_admin: bool = False
    mfa_enabled: bool = True
    last_login_date: Optional[str] = None
    decision: ReviewDecision = ReviewDecision.PENDING
    reviewer_notes: str = ""
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None

    def record_decision(
        self, decision: ReviewDecision, reviewer: str, notes: str = ""
    ) -> None:
        """Record a decision and timestamp the review."""
        self.decision = decision
        self.reviewed_by = reviewer
        self.reviewer_notes = notes
        self.reviewed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d


@dataclass
class AccessCampaign:
    """Quarterly or annual user access review campaign."""

    campaign_id: str
    title: str
    period: str  # e.g. "2026-Q3"
    created_at: str
    due_date: str
    status: CampaignStatus = CampaignStatus.ACTIVE
    completed_at: Optional[str] = None
    signatory: Optional[str] = None
    sign_off_hash: Optional[str] = None
    items: List[AccessReviewItem] = field(default_factory=list)

    @property
    def total_items(self) -> int:
        return len(self.items)

    @property
    def pending_count(self) -> int:
        return len([i for i in self.items if i.decision == ReviewDecision.PENDING])

    @property
    def maintained_count(self) -> int:
        return len([i for i in self.items if i.decision == ReviewDecision.MAINTAIN])

    @property
    def revoked_count(self) -> int:
        return len([i for i in self.items if i.decision == ReviewDecision.REVOKE])

    @property
    def modified_count(self) -> int:
        return len([i for i in self.items if i.decision == ReviewDecision.MODIFY])

    @property
    def is_complete(self) -> bool:
        return self.total_items > 0 and self.pending_count == 0

    def complete_and_sign(
        self, signatory_name: str, signing_secret: Optional[str] = None
    ) -> str:
        """Finalize campaign and compute cryptographic tamper-evident sign-off digest."""
        if not self.is_complete:
            raise ValueError(
                f"Cannot sign campaign with {self.pending_count} pending reviews remaining."
            )

        self.status = CampaignStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.signatory = signatory_name

        # Calculate deterministic digest of all decisions and signatory metadata
        summary_lines = [
            f"{i.item_id}:{i.identity_email}:{i.decision.value}:{i.reviewed_by}"
            for i in sorted(self.items, key=lambda x: x.item_id)
        ]
        payload = (
            f"{self.campaign_id}|{self.period}|{self.completed_at}|{self.signatory}|"
            + ";".join(summary_lines)
        )
        if signing_secret:
            self.sign_off_hash = hmac.new(
                signing_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
            ).hexdigest()
        else:
            self.sign_off_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self.sign_off_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "title": self.title,
            "period": self.period,
            "created_at": self.created_at,
            "due_date": self.due_date,
            "status": self.status.value,
            "completed_at": self.completed_at,
            "signatory": self.signatory,
            "sign_off_hash": self.sign_off_hash,
            "total_items": self.total_items,
            "pending_count": self.pending_count,
            "maintained_count": self.maintained_count,
            "revoked_count": self.revoked_count,
            "modified_count": self.modified_count,
            "items": [i.to_dict() for i in self.items],
        }


class AccessReviewManager:
    """Manages access review campaigns and compliance certifications."""

    def __init__(self, base_root: Path | None = None) -> None:
        self.base_root = base_root or Path.cwd()

    def _get_storage_dir(self, tenant_id: str) -> Path:
        if tenant_id == "default":
            folder = self.base_root / "access_reviews"
        else:
            folder = self.base_root / "tenants" / tenant_id / "access_reviews"
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def list_campaigns(self, tenant_id: Optional[str] = None) -> List[AccessCampaign]:
        """List all campaigns in tenant storage."""
        tid = tenant_id or get_current_tenant_id()
        folder = self._get_storage_dir(tid)
        campaigns: List[AccessCampaign] = []

        for cfile in sorted(folder.glob("campaign_*.json")):
            try:
                data = json.loads(cfile.read_text(encoding="utf-8"))
                items = [
                    AccessReviewItem(
                        item_id=it["item_id"],
                        identity_name=it["identity_name"],
                        identity_email=it["identity_email"],
                        provider=it["provider"],
                        role_or_policy=it["role_or_policy"],
                        resource=it["resource"],
                        is_admin=it.get("is_admin", False),
                        mfa_enabled=it.get("mfa_enabled", True),
                        last_login_date=it.get("last_login_date"),
                        decision=ReviewDecision(
                            it.get("decision", ReviewDecision.PENDING.value)
                        ),
                        reviewer_notes=it.get("reviewer_notes", ""),
                        reviewed_by=it.get("reviewed_by"),
                        reviewed_at=it.get("reviewed_at"),
                    )
                    for it in data.get("items", [])
                ]
                camp = AccessCampaign(
                    campaign_id=data["campaign_id"],
                    title=data["title"],
                    period=data["period"],
                    created_at=data["created_at"],
                    due_date=data["due_date"],
                    status=CampaignStatus(
                        data.get("status", CampaignStatus.ACTIVE.value)
                    ),
                    completed_at=data.get("completed_at"),
                    signatory=data.get("signatory"),
                    sign_off_hash=data.get("sign_off_hash"),
                    items=items,
                )
                campaigns.append(camp)
            except Exception as ex:
                logger.error("Failed loading campaign from %s: %s", cfile, ex)

        return campaigns

    def save_campaign(
        self, campaign: AccessCampaign, tenant_id: Optional[str] = None
    ) -> AccessCampaign:
        """Persist campaign to storage."""
        tid = tenant_id or get_current_tenant_id()
        folder = self._get_storage_dir(tid)
        cfile = folder / f"campaign_{campaign.campaign_id}.json"
        cfile.write_text(json.dumps(campaign.to_dict(), indent=2), encoding="utf-8")
        return campaign

    def get_campaign(
        self, campaign_id: str, tenant_id: Optional[str] = None
    ) -> Optional[AccessCampaign]:
        """Retrieve a campaign by ID."""
        for c in self.list_campaigns(tenant_id):
            if c.campaign_id == campaign_id:
                return c
        return None

    def create_campaign_from_evidence(
        self,
        campaign_id: str,
        title: str,
        period: str,
        due_date: str,
        iam_evidence: dict[str, Any],
        tenant_id: Optional[str] = None,
    ) -> AccessCampaign:
        """Initialize a new campaign populated with IAM identities from collector evidence."""
        items: List[AccessReviewItem] = []
        raw_users = iam_evidence.get("users", []) or iam_evidence.get(
            "raw_data", {}
        ).get("users", [])
        provider = iam_evidence.get("provider", "aws")

        for idx, u in enumerate(raw_users):
            uname = u.get("user_name") or u.get("name") or f"user-{idx+1}"
            email = u.get("email") or f"{uname}@sentinel.local"
            items.append(
                AccessReviewItem(
                    item_id=f"{campaign_id}-item-{idx+1:03d}",
                    identity_name=uname,
                    identity_email=email,
                    provider=provider,
                    role_or_policy=u.get("role")
                    or u.get("policy")
                    or "ReadWriteAccess",
                    resource=u.get("arn") or u.get("resource") or "global",
                    is_admin=bool(u.get("is_admin", False)),
                    mfa_enabled=bool(u.get("mfa_active", True)),
                    last_login_date=u.get("last_active") or u.get("password_last_used"),
                )
            )

        campaign = AccessCampaign(
            campaign_id=campaign_id,
            title=title,
            period=period,
            created_at=datetime.now(timezone.utc).isoformat(),
            due_date=due_date,
            items=items,
        )
        return self.save_campaign(campaign, tenant_id=tenant_id)
