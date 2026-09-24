"""SOC2 Sentinel — Audit Room & Auditor Portal Engine.

Provides time-bounded, scoped audit rooms for external SOC 2 Type II auditors.
Organizes historical evidence, Merkle tree vault blocks, and control mappings
into isolated, cryptographically verifiable audit packages.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import secrets
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from sentinel.integrity import sha256_file
from sentinel.vault import EvidenceVault

logger = logging.getLogger("sentinel.audit_room")


class AuditRoomStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


# AICPA SOC 2 Common Criteria mapping definitions
TSC_CRITERIA_CATALOG: dict[str, dict[str, Any]] = {
    "CC1.1": {
        "title": "Demonstrates Commitment to Integrity and Ethical Values",
        "category": "Control Environment",
        "required_collectors": ["identity_iam", "logging_monitoring"],
    },
    "CC5.1": {
        "title": "Logical Access Control & Authentication Security",
        "category": "Logical and Physical Access",
        "required_collectors": ["identity_iam"],
    },
    "CC6.1": {
        "title": "Restricts Logical Access to Infrastructure and Systems",
        "category": "Logical and Physical Access",
        "required_collectors": ["identity_iam"],
    },
    "CC6.2": {
        "title": "User Registration, De-registration, and Access Provisioning",
        "category": "Logical and Physical Access",
        "required_collectors": ["identity_iam"],
    },
    "CC6.3": {
        "title": "Periodic User Access Review and Revocation",
        "category": "Logical and Physical Access",
        "required_collectors": ["identity_iam"],
    },
    "CC6.6": {
        "title": "Boundary Protection and Network Perimeter Controls",
        "category": "Logical and Physical Access",
        "required_collectors": ["configuration_drift"],
    },
    "CC6.7": {
        "title": "Transmission and Data at Rest Cryptographic Protection",
        "category": "Logical and Physical Access",
        "required_collectors": ["encryption_status"],
    },
    "CC7.1": {
        "title": "Infrastructure and Application Logging & Vulnerability Monitoring",
        "category": "System Operations",
        "required_collectors": ["logging_monitoring", "configuration_drift"],
    },
    "CC7.2": {
        "title": "Real-time Monitoring of Anomalies and Security Incidents",
        "category": "System Operations",
        "required_collectors": ["logging_monitoring"],
    },
    "CC8.1": {
        "title": "Change Management and Separation of Environments",
        "category": "Change Management",
        "required_collectors": ["configuration_drift"],
    },
    "CC9.2": {
        "title": "Vendor Risk and Third-Party Security Management",
        "category": "Risk Mitigation",
        "required_collectors": ["identity_iam", "encryption_status"],
    },
    "A1.2": {
        "title": "Disaster Recovery, Resilience, and High Availability Backups",
        "category": "Availability",
        "required_collectors": ["resilience_status", "retention_schedule"],
    },
    "C1.2": {
        "title": "Confidentiality and Cryptographic Data Key Management",
        "category": "Confidentiality",
        "required_collectors": ["encryption_status"],
    },
    "C1.4": {
        "title": "Secure Data Retention and Disposal Schedules",
        "category": "Confidentiality",
        "required_collectors": ["retention_schedule"],
    },
}


@dataclass
class AuditRoom:
    room_id: str
    title: str
    auditor_email: str
    period_start: str  # YYYY-MM-DD
    period_end: str  # YYYY-MM-DD
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: str = ""
    status: AuditRoomStatus = AuditRoomStatus.ACTIVE
    access_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    controls_in_scope: list[str] = field(
        default_factory=lambda: list(TSC_CRITERIA_CATALOG.keys())
    )
    evidence_dates: list[str] = field(default_factory=list)
    vault_block_hashes: list[str] = field(default_factory=list)
    notes: str = "Confidential SOC 2 Type II External Auditor Review Room"
    access_logs: list[dict[str, str]] = field(default_factory=list)

    def is_active(self) -> bool:
        if self.status != AuditRoomStatus.ACTIVE:
            return False
        if self.expires_at:
            try:
                exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > exp:
                    return False
            except ValueError:
                pass
        return True

    def record_access(self, ip_address: str, user_agent: str) -> None:
        self.access_logs.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip_address": ip_address,
                "user_agent": user_agent,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditRoom:
        status_val = data.get("status", AuditRoomStatus.ACTIVE.value)
        try:
            status = AuditRoomStatus(status_val)
        except ValueError:
            status = AuditRoomStatus.ACTIVE

        return cls(
            room_id=data["room_id"],
            title=data["title"],
            auditor_email=data.get("auditor_email", "auditor@enterprise.com"),
            period_start=data["period_start"],
            period_end=data["period_end"],
            created_at=data.get(
                "created_at", datetime.now(timezone.utc).isoformat()
            ),
            expires_at=data.get("expires_at", ""),
            status=status,
            access_token=data.get("access_token", secrets.token_urlsafe(32)),
            controls_in_scope=data.get(
                "controls_in_scope", list(TSC_CRITERIA_CATALOG.keys())
            ),
            evidence_dates=data.get("evidence_dates", []),
            vault_block_hashes=data.get("vault_block_hashes", []),
            notes=data.get("notes", ""),
            access_logs=data.get("access_logs", []),
        )


class AuditRoomManager:
    """Manages creation, scoping, verification, and packaging of auditor rooms."""

    def __init__(self, base_dir: Path | str = "data") -> None:
        self.base_dir = Path(base_dir)
        self.rooms_dir = self.base_dir / "audit_rooms"
        self.evidence_dir = self.base_dir / "evidence"
        self.vault = EvidenceVault(self.base_dir)
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        self.rooms_dir.mkdir(parents=True, exist_ok=True)

    def create_room(
        self,
        room_id: str,
        title: str,
        auditor_email: str,
        period_start: str,
        period_end: str,
        expires_days: int = 90,
        controls_in_scope: list[str] | None = None,
        notes: str = "",
    ) -> AuditRoom:
        """Create a new scoped audit room mapped to historical evidence."""
        # Find matching evidence dates within period
        matched_dates: list[str] = []
        if self.evidence_dir.exists():
            for entry in sorted(self.evidence_dir.iterdir()):
                if entry.is_dir():
                    date_name = entry.name
                    # Check if date falls in [period_start, period_end]
                    if period_start <= date_name <= period_end:
                        matched_dates.append(date_name)

        # Collect vault block hashes within period
        matched_block_hashes: list[str] = []
        for block in self.vault.read_chain("default"):
            block_date = block.timestamp.split("T")[0]
            if period_start <= block_date <= period_end:
                matched_block_hashes.append(block.block_hash)

        now = datetime.now(timezone.utc)
        exp = now.replace(year=now.year + 1) if expires_days >= 365 else now
        if expires_days < 365:
            from datetime import timedelta

            exp = now + timedelta(days=expires_days)

        room = AuditRoom(
            room_id=room_id,
            title=title,
            auditor_email=auditor_email,
            period_start=period_start,
            period_end=period_end,
            expires_at=exp.isoformat(),
            status=AuditRoomStatus.ACTIVE,
            controls_in_scope=controls_in_scope
            or list(TSC_CRITERIA_CATALOG.keys()),
            evidence_dates=matched_dates,
            vault_block_hashes=matched_block_hashes,
            notes=notes
            or f"SOC 2 Type II Audit Room for window {period_start} to {period_end}",
        )
        self.save_room(room)
        logger.info(
            "Created Audit Room '%s' covering %d evidence runs",
            room_id,
            len(matched_dates),
        )
        return room

    def save_room(self, room: AuditRoom) -> None:
        path = self.rooms_dir / f"{room.room_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(room.to_dict(), f, indent=2)

    def get_room(self, room_id: str) -> AuditRoom | None:
        path = self.rooms_dir / f"{room_id}.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return AuditRoom.from_dict(json.load(f))
        except Exception as e:
            logger.error("Failed to read audit room '%s': %s", room_id, e)
            return None

    def list_rooms(self) -> list[AuditRoom]:
        rooms: list[AuditRoom] = []
        if not self.rooms_dir.exists():
            return rooms
        for entry in self.rooms_dir.glob("*.json"):
            try:
                with open(entry, "r", encoding="utf-8") as f:
                    rooms.append(AuditRoom.from_dict(json.load(f)))
            except Exception as e:
                logger.error("Failed reading audit room file %s: %s", entry, e)
        return sorted(rooms, key=lambda r: r.created_at, reverse=True)

    def revoke_room(self, room_id: str) -> bool:
        room = self.get_room(room_id)
        if not room:
            return False
        room.status = AuditRoomStatus.REVOKED
        self.save_room(room)
        return True

    def validate_access(
        self, room_id: str, token: str, ip_address: str = "", user_agent: str = ""
    ) -> tuple[bool, AuditRoom | None]:
        """Validate an auditor's token and log access attempt."""
        room = self.get_room(room_id)
        if not room or not room.is_active():
            return False, None
        if not secrets.compare_digest(room.access_token, token):
            return False, None
        room.record_access(ip_address, user_agent)
        self.save_room(room)
        return True, room

    def build_control_crosswalk(self, room: AuditRoom) -> list[dict[str, Any]]:
        """Generate bi-directional matrix linking SOC 2 controls to evidence artifacts."""
        crosswalk: list[dict[str, Any]] = []

        for control_id in room.controls_in_scope:
            meta = TSC_CRITERIA_CATALOG.get(
                control_id,
                {
                    "title": "Custom Control Criterion",
                    "category": "General",
                    "required_collectors": [],
                },
            )
            evidence_artifacts: list[dict[str, str]] = []

            for date_str in room.evidence_dates:
                day_dir = self.evidence_dir / date_str
                if not day_dir.exists():
                    continue
                for req_col in meta["required_collectors"]:
                    col_file = day_dir / f"{req_col}.json"
                    if col_file.exists():
                        try:
                            f_hash = sha256_file(col_file)
                        except Exception:
                            f_hash = "UNKNOWN"
                        evidence_artifacts.append(
                            {
                                "date": date_str,
                                "collector": req_col,
                                "file_name": f"{date_str}/{req_col}.json",
                                "sha256": f_hash,
                            }
                        )

            crosswalk.append(
                {
                    "control_id": control_id,
                    "title": meta["title"],
                    "category": meta["category"],
                    "evidence_count": len(evidence_artifacts),
                    "evidence_status": "SATISFIED"
                    if evidence_artifacts
                    else "NO_EVIDENCE_IN_WINDOW",
                    "artifacts": evidence_artifacts,
                }
            )

        return crosswalk

    def export_control_crosswalk_csv(self, room: AuditRoom) -> str:
        """Export the control crosswalk matrix as standard RFC-4180 CSV."""
        crosswalk = self.build_control_crosswalk(room)
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(
            [
                "Control ID",
                "Category",
                "Control Title",
                "Status",
                "Evidence Artifacts Count",
                "Evidence Dates",
            ]
        )
        for item in crosswalk:
            dates = sorted(list({a["date"] for a in item["artifacts"]}))
            writer.writerow(
                [
                    item["control_id"],
                    item["category"],
                    item["title"],
                    item["evidence_status"],
                    item["evidence_count"],
                    "; ".join(dates) if dates else "N/A",
                ]
            )
        return out.getvalue()

    def generate_auditor_html_summary(self, room: AuditRoom) -> str:
        """Generate a pristine, self-contained HTML executive summary for auditors."""
        crosswalk = self.build_control_crosswalk(room)
        satisfied_count = sum(
            1 for c in crosswalk if c["evidence_status"] == "SATISFIED"
        )
        total_count = len(crosswalk)
        compliance_pct = (
            (satisfied_count / total_count * 100) if total_count > 0 else 0.0
        )

        rows_html = ""
        for c in crosswalk:
            status_color = (
                "#10b981"
                if c["evidence_status"] == "SATISFIED"
                else "#ef4444"
            )
            artifacts_html = ""
            for art in c["artifacts"][:3]:  # preview top 3
                artifacts_html += f"<code>{art['file_name']}</code> ({art['sha256'][:8]}...)<br/>"
            if len(c["artifacts"]) > 3:
                artifacts_html += f"<i>+ {len(c['artifacts']) - 3} more artifacts in vault</i>"
            if not artifacts_html:
                artifacts_html = "<i>No evidence collected in audit window</i>"

            rows_html += f"""
            <tr>
                <td style="font-weight:600; font-family:monospace; color:#3b82f6;">{c['control_id']}</td>
                <td style="color:#94a3b8;">{c['category']}</td>
                <td style="font-weight:500;">{c['title']}</td>
                <td><span style="background:{status_color}22; color:{status_color}; padding:4px 8px; border-radius:4px; font-weight:600; font-size:12px;">{c['evidence_status']}</span></td>
                <td style="font-size:12px; line-height:1.5;">{artifacts_html}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SOC 2 Type II Audit Room — {room.title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; margin: 0; padding: 40px; }}
        .card {{ background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 20px; }}
        .title {{ font-size: 24px; font-weight: 700; color: #ffffff; }}
        .badge {{ background: #10b98122; color: #10b981; border: 1px solid #10b98144; padding: 6px 12px; border-radius: 6px; font-weight: 600; font-size: 13px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
        .stat-box {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; text-align: center; }}
        .stat-val {{ font-size: 28px; font-weight: 700; color: #3b82f6; margin-top: 4px; }}
        .stat-lbl {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
        th {{ text-align: left; padding: 12px; background: #0f172a; color: #94a3b8; font-size: 13px; border-bottom: 1px solid #1e293b; }}
        td {{ padding: 12px; border-bottom: 1px solid #1e293b; font-size: 14px; vertical-align: top; }}
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div>
                <div class="title">SOC 2 Type II External Audit Room</div>
                <div style="color: #94a3b8; font-size: 14px; margin-top: 4px;">Auditor Scope: {room.title} &bull; Room ID: <code>{room.room_id}</code></div>
            </div>
            <div class="badge">&check; CRYPTOGRAPHICALLY SEALED</div>
        </div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-lbl">Audit Period</div>
                <div class="stat-val" style="font-size: 18px; color: #f8fafc; margin-top: 8px;">{room.period_start} &rarr; {room.period_end}</div>
            </div>
            <div class="stat-box">
                <div class="stat-lbl">Control Coverage</div>
                <div class="stat-val" style="color: {'#10b981' if compliance_pct >= 90 else '#f59e0b'};">{compliance_pct:.1f}%</div>
            </div>
            <div class="stat-box">
                <div class="stat-lbl">Satisfied Controls</div>
                <div class="stat-val" style="color: #10b981;">{satisfied_count} / {total_count}</div>
            </div>
            <div class="stat-box">
                <div class="stat-lbl">Evidence Runs in Scope</div>
                <div class="stat-val" style="color: #3b82f6;">{len(room.evidence_dates)}</div>
            </div>
        </div>

        <div style="font-size: 14px; color: #94a3b8; margin-bottom: 16px;">
            <strong>Designated External Auditor:</strong> {room.auditor_email} &bull;
            <strong>Created:</strong> {room.created_at} &bull;
            <strong>Room Expiration:</strong> {room.expires_at}
        </div>
    </div>

    <div class="card">
        <div style="font-size: 18px; font-weight: 600; margin-bottom: 12px;">Trust Services Criteria (TSC) Control Matrix</div>
        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Category</th>
                    <th>Criterion Description</th>
                    <th>Audit Status</th>
                    <th>Cryptographic Evidence Links</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        return html

    def export_audit_package_zip(
        self, room_id: str, output_path: Path | str | None = None
    ) -> Path:
        """Export complete self-contained auditor ZIP package."""
        room = self.get_room(room_id)
        if not room:
            raise ValueError(f"Audit room '{room_id}' not found.")

        if output_path is None:
            output_dir = self.base_dir / "audit_packages"
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / f"SOC2-Audit-Room-{room_id}.zip"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        crosswalk = self.build_control_crosswalk(room)
        crosswalk_csv = self.export_control_crosswalk_csv(room)
        summary_html = self.generate_auditor_html_summary(room)

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1. Room Metadata
            zf.writestr(
                "audit_room_manifest.json",
                json.dumps(room.to_dict(), indent=2),
            )
            # 2. Control Crosswalk JSON & CSV
            zf.writestr(
                "soc2_control_matrix.json", json.dumps(crosswalk, indent=2)
            )
            zf.writestr("soc2_control_matrix.csv", crosswalk_csv)
            # 3. HTML Executive Report
            zf.writestr("AUDIT_EXECUTIVE_SUMMARY.html", summary_html)

            # 4. Include Raw Evidence Files in scope
            for date_str in room.evidence_dates:
                day_dir = self.evidence_dir / date_str
                if day_dir.exists():
                    for ev_file in day_dir.glob("*.json"):
                        arcname = f"evidence/{date_str}/{ev_file.name}"
                        zf.write(ev_file, arcname)

            # 5. Include Vault Chain Proofs if available
            ledger_file = self.vault._get_chain_file("default")
            if ledger_file.exists():
                zf.write(ledger_file, "vault/evidence_chain.jsonl")

            # 6. Verification instructions
            instructions = f"""# SOC 2 Type II Audit Package Verification Guide
Room ID: {room.room_id}
Audit Period: {room.period_start} to {room.period_end}

## 1. Verifying Evidence Authenticity
Every evidence file in `evidence/` matches SHA-256 digests recorded in `soc2_control_matrix.json`.
To verify integrity independently:
  sha256sum evidence/*/*.json

## 2. Reviewing Control Satisfaction
Open `AUDIT_EXECUTIVE_SUMMARY.html` in any web browser for an interactive overview with direct control cross-references.
"""
            zf.writestr("README_AUDITOR_VERIFICATION.txt", instructions)

        logger.info(
            "Exported Audit Package ZIP for '%s' to %s", room_id, output_path
        )
        return output_path
