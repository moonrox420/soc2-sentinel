"""Unit tests for User Access Review (UAR) and Certification Engine."""

from pathlib import Path

import pytest

from sentinel.access_review import (
    AccessCampaign,
    AccessReviewItem,
    AccessReviewManager,
    CampaignStatus,
    ReviewDecision,
)


def test_access_review_item_decision_recording() -> None:
    item = AccessReviewItem(
        item_id="item-001",
        identity_name="Alice Dev",
        identity_email="alice@company.com",
        provider="aws",
        role_or_policy="AdministratorAccess",
        resource="arn:aws:iam::123456789:role/Admin",
        is_admin=True,
    )
    assert item.decision == ReviewDecision.PENDING

    item.record_decision(
        decision=ReviewDecision.REVOKE,
        reviewer="Security Manager",
        notes="Transferred to non-engineering role",
    )
    assert item.decision == ReviewDecision.REVOKE
    assert item.reviewed_by == "Security Manager"
    assert item.reviewed_at is not None


def test_access_campaign_counts_and_signoff() -> None:
    item1 = AccessReviewItem(
        item_id="i-1",
        identity_name="Bob",
        identity_email="bob@corp.com",
        provider="aws",
        role_or_policy="ReadOnly",
        resource="*",
    )
    item2 = AccessReviewItem(
        item_id="i-2",
        identity_name="Charlie",
        identity_email="charlie@corp.com",
        provider="azure",
        role_or_policy="Contributor",
        resource="subscriptions/sub-1",
    )

    camp = AccessCampaign(
        campaign_id="CAMP-2026-Q3",
        title="Q3 Privileged Access Review",
        period="2026-Q3",
        created_at="2026-09-01T00:00:00Z",
        due_date="2026-10-01T00:00:00Z",
        items=[item1, item2],
    )

    assert camp.total_items == 2
    assert camp.pending_count == 2
    assert camp.is_complete is False

    # Cannot sign with pending items
    with pytest.raises(ValueError, match="Cannot sign campaign"):
        camp.complete_and_sign("CISO")

    item1.record_decision(ReviewDecision.MAINTAIN, "CISO")
    item2.record_decision(ReviewDecision.REVOKE, "CISO")

    assert camp.is_complete is True
    assert camp.maintained_count == 1
    assert camp.revoked_count == 1

    sig_hash = camp.complete_and_sign("CISO")
    assert len(sig_hash) == 64
    assert camp.status == CampaignStatus.COMPLETED
    assert camp.signatory == "CISO"


def test_access_review_manager_workflow(tmp_path: Path) -> None:
    mgr = AccessReviewManager(tmp_path)
    assert len(mgr.list_campaigns()) == 0

    dummy_iam = {
        "provider": "aws",
        "users": [
            {"user_name": "dev_1", "role": "DevRole", "is_admin": False},
            {"user_name": "admin_1", "role": "AdminRole", "is_admin": True},
        ],
    }

    camp = mgr.create_campaign_from_evidence(
        campaign_id="2026-Q3-IAM",
        title="Q3 All IAM Users",
        period="2026-Q3",
        due_date="2026-09-30",
        iam_evidence=dummy_iam,
    )
    assert camp.total_items == 2

    # Verify retrieval
    fetched = mgr.get_campaign("2026-Q3-IAM")
    assert fetched is not None
    assert fetched.campaign_id == "2026-Q3-IAM"

    campaigns = mgr.list_campaigns()
    assert len(campaigns) == 1
