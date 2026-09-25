"""Enterprise Dashboard Server with Multi-Tenant & RBAC Support."""

from __future__ import annotations

import ipaddress
import json
import logging
import mimetypes
import os
import re
import socket
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.access_review import AccessReviewManager, ReviewDecision
from sentinel.audit_room import AuditRoomManager
from sentinel.auth import (
    AuthError,
    Permission,
    Role,
    TokenManager,
    UserIdentity,
    assert_permission,
    auth_scope,
    get_current_user,
)
from sentinel.cli import RUN_ALL_MAPPING
from sentinel.collectors import COLLECTORS
from sentinel.config import SentinelConfig
from sentinel.connectors.github import GitHubConnector
from sentinel.daemon import ContinuousMonitoringDaemon
from sentinel.dashboard.assets import DASHBOARD_HTML
from sentinel.dogfood import DogfoodAssessor
from sentinel.drift import detect_configuration_drift
from sentinel.integrity import verify_evidence_tree
from sentinel.notifications import (
    AlertSeverity,
    ComplianceAlert,
    NotificationChannel,
    NotificationManager,
)
from sentinel.onboarding import diagnose_all_providers
from sentinel.policy import PolicyEngine
from sentinel.providers import get_provider
from sentinel.reporting import export_audit_pack, generate_executive_html_report
from sentinel.scoring import compute_compliance_scorecard
from sentinel.siem import SIEMExporter
from sentinel.telemetry import TELEMETRY
from sentinel.tenancy import (
    TenantStorageManager,
    get_current_tenant,
    get_current_tenant_id,
    tenant_scope,
)
from sentinel.trust_center import TrustCenterManager
from sentinel.vault import EvidenceVault
from sentinel.vendor_risk import (
    DataClassification,
    SecurityQuestionnaire,
    Vendor,
    VendorRiskManager,
    VendorStatus,
    VendorTier,
)

logger = logging.getLogger("sentinel.dashboard.server")


def _is_allowed_origin(origin: str) -> bool:
    if not origin:
        return False
    try:
        parsed = urllib.parse.urlparse(origin)
        if parsed.scheme not in {"http", "https"}:
            return False
        hostname = (parsed.hostname or "").lower()
        return hostname in {"localhost", "127.0.0.1", "::1"}
    except Exception:
        return False


def _validate_outbound_url(url: str) -> None:
    """Ensure outbound destination URL is safe from SSRF attacks."""
    if not url or not url.startswith(("http://", "https://")):
        raise ValueError("Invalid URL scheme: must start with http:// or https://")
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("Missing hostname in URL")

    # Resolve destination hostname to inspect IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except Exception as exc:
        raise ValueError(
            f"Failed to resolve destination hostname '{hostname}': {exc}"
        )

    for entry in addr_info:
        ip_str = entry[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_loopback
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                raise ValueError(
                    f"Prohibited destination IP address range: {ip_str} ({hostname})"
                )
        except ValueError as ve:
            raise ve


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer  # type: ignore

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug(
            "%s - - [%s] %s",
            self.address_string(),
            self.log_date_time_string(),
            format % args,
        )

    def _get_tenant_base(self, tenant_id: str) -> Path:
        """Resolve isolated storage directory for the active tenant."""
        if tenant_id == "default":
            return self.server.output_base
        mgr = TenantStorageManager(self.server.output_base)
        t_ctx = mgr.get_tenant(tenant_id)
        if not t_ctx:
            t_ctx = mgr.create_tenant(tenant_id)
        return t_ctx.workspace_dir

    def _extract_context(self) -> tuple[str, UserIdentity]:
        """Extract tenant ID and user identity from request headers with strict validation."""
        tenant_hdr = self.headers.get("X-Tenant-ID", "").strip()
        auth_hdr = self.headers.get("Authorization", "")
        token = (
            auth_hdr.replace("Bearer ", "").strip()
            if auth_hdr.startswith("Bearer ")
            else ""
        )

        if token:
            verified = TokenManager.verify_token(token)
            if verified:
                if tenant_hdr and tenant_hdr != verified.tenant_id:
                    raise AuthError(
                        f"Header tenant '{tenant_hdr}' conflicts with token tenant '{verified.tenant_id}'",
                        status_code=403,
                    )
                return verified.tenant_id, verified
            else:
                return tenant_hdr or "default", UserIdentity.anonymous(
                    tenant_id=tenant_hdr or "default"
                )

        return tenant_hdr or "default", UserIdentity.anonymous(
            tenant_id=tenant_hdr or "default"
        )

    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        origin = self.headers.get("Origin", "")
        if _is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Audit-Token"
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, html_text: str, status: int = 200) -> None:
        payload = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        origin = self.headers.get("Origin", "")
        if _is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(payload)

    def _read_body_json(self) -> dict[str, Any]:
        length_header = self.headers.get("Content-Length")
        if not length_header:
            return {}
        try:
            length = int(length_header)
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw) if raw else {}
        except Exception as exc:
            logger.debug("Failed parsing JSON body: %s", exc)
            return {}

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        origin = self.headers.get("Origin", "")
        if _is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Tenant-ID, X-Audit-Token",
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        tenant_id, user = self._extract_context()
        with tenant_scope(tenant_id), auth_scope(user):
            self._handle_get()

    def do_POST(self) -> None:
        tenant_id, user = self._extract_context()
        with tenant_scope(tenant_id), auth_scope(user):
            self._handle_post()

    def _handle_get(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in {"/", "/index.html"}:
            self._send_html(DASHBOARD_HTML)
            return

        if path == "/api/status":
            daemon_status = (
                self.server.daemon.get_status().to_dict()
                if self.server.daemon
                else None
            )
            curr_t = get_current_tenant()
            tid = curr_t.tenant_id if hasattr(curr_t, "tenant_id") else str(curr_t)
            self._send_json(
                {
                    "version": __version__,
                    "output_base": str(self.server.output_base),
                    "daemon": daemon_status,
                    "pid": os.getpid(),
                    "tenant_id": tid,
                    "user": get_current_user().to_dict(),
                }
            )
            return

        if path == "/api/scorecard":
            try:
                assert_permission(Permission.READ_EVIDENCE)
                base = self._get_tenant_base(get_current_tenant_id())
                scorecard = compute_compliance_scorecard(base / "evidence")
                self._send_json(scorecard.to_dict())
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            except Exception as exc:
                logger.error("Error computing scorecard: %s", exc, exc_info=True)
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/drift":
            try:
                assert_permission(Permission.READ_EVIDENCE)
                base = self._get_tenant_base(get_current_tenant_id())
                drift = detect_configuration_drift(base / "evidence")
                self._send_json(drift.to_dict())
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            except Exception as exc:
                logger.error("Error computing drift: %s", exc, exc_info=True)
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/credentials":
            try:
                assert_permission(Permission.READ_CONFIG)
                diag = diagnose_all_providers(self.server.config)
                self._send_json(diag)
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            except Exception as exc:
                logger.error("Error diagnosing providers: %s", exc, exc_info=True)
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/evidence":
            try:
                assert_permission(Permission.READ_EVIDENCE)
                base = self._get_tenant_base(get_current_tenant_id())
                ev_dir = base / "evidence"
                dates: list[str] = []
                if ev_dir.exists():
                    dates = sorted(
                        [
                            d.name
                            for d in ev_dir.iterdir()
                            if d.is_dir() and d.name != "manifests"
                        ],
                        reverse=True,
                    )
                self._send_json(dates)
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path.startswith("/api/evidence/"):
            try:
                assert_permission(Permission.READ_EVIDENCE)
                parts = path.strip("/").split("/")
                if len(parts) >= 3:
                    date_str = parts[2]
                    file_target = (
                        "/".join(parts[3:]) if len(parts) > 3 else "manifest.json"
                    )
                    base = self._get_tenant_base(get_current_tenant_id())
                    base_ev_dir = (base / "evidence").resolve()
                    target_file = (
                        base / "evidence" / date_str / file_target
                    ).resolve()
                    if not target_file.is_relative_to(base_ev_dir):
                        self._send_json(
                            {"error": "Path traversal prohibited"}, status=403
                        )
                        return
                    if target_file.exists() and target_file.is_file():
                        try:
                            content = json.loads(
                                target_file.read_text(encoding="utf-8")
                            )
                            self._send_json(content)
                            return
                        except Exception:
                            self._send_json(
                                {
                                    "raw": target_file.read_text(
                                        encoding="utf-8", errors="replace"
                                    )
                                }
                            )
                            return
                    else:
                        self._send_json(
                            {"error": "Artifact not found", "path": target_file.name},
                            status=404,
                        )
                        return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/report/latest":
            try:
                assert_permission(Permission.READ_REPORT)
                base = self._get_tenant_base(get_current_tenant_id())
                ev_dir = base / "evidence"
                if not ev_dir.exists():
                    self._send_html(
                        "<h1>No evidence directories exist yet.</h1>", status=404
                    )
                    return
                dirs = sorted(
                    [
                        d
                        for d in ev_dir.iterdir()
                        if d.is_dir() and d.name != "manifests"
                    ],
                    key=lambda d: d.name,
                )
                if not dirs:
                    self._send_html("<h1>No evidence runs found.</h1>", status=404)
                    return
                latest_dir = dirs[-1]
                scorecard = compute_compliance_scorecard(
                    ev_dir, date_str=latest_dir.name
                )
                html_report = generate_executive_html_report(scorecard, latest_dir)
                self._send_html(html_report)
                return
            except PermissionError as pe:
                self._send_html(f"<h1>Forbidden: {pe}</h1>", status=403)
                return

        if path == "/api/policy/rules":
            try:
                assert_permission(Permission.READ_POLICY)
                engine = PolicyEngine()
                self._send_json([r.to_dict() for r in engine.rules.values()])
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path == "/api/tenants":
            try:
                assert_permission(Permission.MANAGE_TENANT)
                mgr = TenantStorageManager(self.server.output_base)
                self._send_json({"tenants": mgr.list_tenants()})
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path == "/api/stream/events":
            try:
                assert_permission(Permission.READ_AUDIT)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                origin = self.headers.get("Origin", "")
                if _is_allowed_origin(origin):
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                self.end_headers()

                # Send initial connection confirmation & recent events
                init_msg = f"event: connected\ndata: {json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(), 'tenant_id': get_current_tenant_id()})}\n\n"
                self.wfile.write(init_msg.encode("utf-8"))
                self.wfile.flush()

                recent = TELEMETRY.get_recent_events(limit=10, tenant_id=get_current_tenant_id())
                for ev in reversed(recent):
                    ev_msg = f"event: telemetry\ndata: {json.dumps(ev)}\n\n"
                    self.wfile.write(ev_msg.encode("utf-8"))
                    self.wfile.flush()
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            except Exception as exc:
                logger.debug("SSE stream connection closed: %s", exc)
            return

        if path == "/api/live/metrics":
            try:
                assert_permission(Permission.READ_REPORT)
                base = self._get_tenant_base(get_current_tenant_id())
                diag = diagnose_all_providers(self.server.config)
                scorecard = compute_compliance_scorecard(base / "evidence")
                self._send_json({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "overall_score": scorecard.overall_posture_score,
                    "providers": diag,
                    "daemon_active": self.server.daemon.is_running if self.server.daemon else False,
                })
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            except Exception as exc:
                logger.error("Error computing live metrics: %s", exc, exc_info=True)
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/vcs/github":
            try:
                assert_permission(Permission.READ_EVIDENCE)
                repo = query.get("repo", ["enterprise-org/soc2-sentinel"])[0]
                connector = GitHubConnector(repo=repo)
                report = connector.audit()
                self._send_json(report.to_dict())
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path == "/api/telemetry/events":
            try:
                assert_permission(Permission.READ_AUDIT)
                limit = int(query.get("limit", ["50"])[0])
                events = TELEMETRY.get_recent_events(
                    limit=limit, tenant_id=get_current_tenant_id()
                )
                self._send_json({"events": events})
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        # Phase 2 Endpoints
        if path == "/api/vault/chain":
            try:
                assert_permission(Permission.READ_EVIDENCE)
                base = self._get_tenant_base(get_current_tenant_id())
                vault = EvidenceVault(base)
                tid = get_current_tenant_id()
                verification = vault.verify_chain(tid)
                blocks = [b.to_dict() for b in vault.read_chain(tid)]
                self._send_json({"verification": verification, "blocks": blocks})
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path == "/api/vendor-risk/vendors":
            try:
                assert_permission(Permission.READ_CONFIG)
                base = self._get_tenant_base(get_current_tenant_id())
                vrm = VendorRiskManager(base)
                self._send_json([v.to_dict() for v in vrm.list_vendors()])
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path == "/api/vendor-risk/report":
            try:
                assert_permission(Permission.READ_REPORT)
                base = self._get_tenant_base(get_current_tenant_id())
                vrm = VendorRiskManager(base)
                self._send_json(vrm.generate_cc92_report())
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path == "/api/access-review/campaigns":
            try:
                assert_permission(Permission.READ_EVIDENCE)
                base = self._get_tenant_base(get_current_tenant_id())
                uar = AccessReviewManager(base)
                self._send_json([c.to_dict() for c in uar.list_campaigns()])
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        # Phase 3 Endpoints
        if path == "/trust-center":
            base = self._get_tenant_base(get_current_tenant_id())
            tcm = TrustCenterManager(base)
            html = tcm.generate_trust_center_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        if path == "/api/trust-center":
            try:
                base = self._get_tenant_base(get_current_tenant_id())
                tcm = TrustCenterManager(base)
                self._send_json(tcm.get_profile().to_dict())
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
            return

        if path == "/api/dogfood":
            try:
                assert_permission(Permission.READ_REPORT)
                base = self._get_tenant_base(get_current_tenant_id())
                assessor = DogfoodAssessor(base)
                dogfood_rep = assessor.run_assessment()
                self._send_json(dogfood_rep.to_dict())
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path == "/api/audit-rooms":
            try:
                assert_permission(Permission.READ_AUDIT)
                base = self._get_tenant_base(get_current_tenant_id())
                arm = AuditRoomManager(base)
                self._send_json([r.to_dict() for r in arm.list_rooms()])
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path.startswith("/api/audit-rooms/"):
            try:
                r_id = path.replace("/api/audit-rooms/", "").strip()
                r_id = re.sub(r"[^a-zA-Z0-9_\-]", "", r_id)
                base = self._get_tenant_base(get_current_tenant_id())
                arm = AuditRoomManager(base)
                room = arm.get_room(r_id)
                if not room:
                    self._send_json(
                        {"error": f"Audit room '{r_id}' not found"}, status=404
                    )
                    return
                # Check for auditor room token in header first, then query
                room_tok = self.headers.get("X-Audit-Token", "").strip() or query.get("token", [""])[0]
                if room_tok:
                    valid, _ = arm.validate_access(
                        r_id,
                        room_tok,
                        ip_address=(
                            self.client_address[0] if self.client_address else ""
                        ),
                    )
                    if not valid:
                        self._send_json(
                            {"error": "Invalid or expired audit room token"}, status=403
                        )
                        return
                else:
                    assert_permission(Permission.READ_AUDIT)

                crosswalk = arm.build_control_crosswalk(room)
                self._send_json({"room": room.to_dict(), "crosswalk": crosswalk})
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
            return

        if path.startswith("/api/download/"):
            try:
                assert_permission(Permission.READ_REPORT)
                fname = path.replace("/api/download/", "").strip()
                if ".." in fname or fname.startswith("/") or fname.startswith("\\"):
                    self._send_json({"error": "Path traversal prohibited"}, status=403)
                    return
                base = self._get_tenant_base(get_current_tenant_id())
                allowed_roots = [
                    (base / "evidence").resolve(),
                    (base / "audit_packages").resolve(),
                ]
                target_path = None
                for root in allowed_roots:
                    candidate = (root / fname).resolve()
                    if candidate.is_relative_to(root) and candidate.exists() and candidate.is_file():
                        target_path = candidate
                        break

                if target_path and target_path.exists() and target_path.is_file():
                    self.send_response(200)
                    content_type, _ = mimetypes.guess_type(str(target_path))
                    self.send_header(
                        "Content-Type", content_type or "application/octet-stream"
                    )
                    self.send_header(
                        "Content-Disposition",
                        f'attachment; filename="{target_path.name}"',
                    )
                    self.send_header("Content-Length", str(target_path.stat().st_size))
                    self.end_headers()
                    with target_path.open("rb") as f:
                        while chunk := f.read(65536):
                            self.wfile.write(chunk)
                    return
                else:
                    self._send_json({"error": "File not found"}, status=404)
                    return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        self._send_json({"error": "Endpoint not found", "path": path}, status=404)

    def _handle_post(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_body_json()

        if path == "/api/verify":
            try:
                assert_permission(Permission.VERIFY_INTEGRITY)
                date_str = body.get("date")
                if not date_str:
                    self._send_json({"error": "Missing 'date' parameter"}, status=400)
                    return
                base = self._get_tenant_base(get_current_tenant_id())
                target_dir = base / "evidence" / date_str
                if not target_dir.exists():
                    self._send_json(
                        {
                            "valid": False,
                            "errors": [f"Directory {target_dir} does not exist"],
                        },
                        status=404,
                    )
                    return
                tree_res = verify_evidence_tree(target_dir)
                valid = not bool(tree_res.get("failed"))
                errors: list[str] = []
                for ctrl, issues in tree_res.get("failed", {}).items():
                    errors.extend(f"{ctrl}: {i}" for i in issues)

                TELEMETRY.emit(
                    action="VERIFY_EVIDENCE",
                    resource=f"evidence/{date_str}",
                    outcome="SUCCESS" if valid else "FAILURE",
                    details={"valid": valid, "error_count": len(errors)},
                )
                self._send_json(
                    {
                        "valid": valid,
                        "errors": errors,
                        "date": date_str,
                        "tree": tree_res,
                    }
                )
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/policy/evaluate":
            try:
                assert_permission(Permission.RUN_POLICY)
                engine = PolicyEngine()
                state = body.get("state", {})
                report = engine.evaluate(state)

                TELEMETRY.emit(
                    action="EVALUATE_POLICY",
                    resource="policy_engine",
                    outcome="SUCCESS" if report.passed else "VIOLATION",
                    details={
                        "passed": report.passed,
                        "violations": len(report.violations),
                    },
                )
                self._send_json(report.to_dict())
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/tenants":
            try:
                assert_permission(Permission.MANAGE_TENANT)
                slug = body.get("tenant_id", "").strip()
                if not slug:
                    self._send_json({"error": "Missing tenant_id"}, status=400)
                    return
                mgr = TenantStorageManager(self.server.output_base)
                t_ctx = mgr.create_tenant(slug)

                TELEMETRY.emit(
                    action="CREATE_TENANT",
                    resource=f"tenant/{slug}",
                    outcome="SUCCESS",
                )
                self._send_json({"status": "created", "tenant_id": t_ctx.tenant_id})
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return
            except ValueError as ve:
                self._send_json({"error": str(ve)}, status=400)
                return

        if path == "/api/tokens/create":
            try:
                assert_permission(Permission.TOKEN_MANAGE)
                uid = body.get("user_id", "admin")
                role_str = body.get("role", "SUPER_ADMIN").upper()
                role = getattr(Role, role_str, Role.SYSTEM_USER)
                tenant = body.get("tenant_id", get_current_tenant_id())
                expires = int(body.get("expires_in_seconds", 86400))

                user_id_obj = UserIdentity(user_id=uid, role=role, tenant_id=tenant)
                token = TokenManager.create_token(
                    user_id_obj, expires_in_seconds=expires
                )

                TELEMETRY.emit(
                    action="CREATE_AUTH_TOKEN",
                    resource=f"user/{uid}",
                    outcome="SUCCESS",
                    details={"role": role.name, "tenant_id": tenant},
                )
                self._send_json({"token": token, "user": user_id_obj.to_dict()})
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        # Phase 2 POST Endpoints
        if path == "/api/vault/seal":
            try:
                assert_permission(Permission.VERIFY_INTEGRITY)
                date_str = body.get("date")
                if not date_str:
                    self._send_json({"error": "Missing date parameter"}, status=400)
                    return
                base = self._get_tenant_base(get_current_tenant_id())
                ev_dir = base / "evidence" / date_str
                vault = EvidenceVault(base)
                block = vault.seal_run(ev_dir)

                TELEMETRY.emit(
                    action="SEAL_EVIDENCE_BLOCK",
                    resource=f"vault/block_{block.block_index}",
                    outcome="SUCCESS",
                    details={
                        "merkle_root": block.merkle_root,
                        "block_hash": block.block_hash,
                    },
                )
                self._send_json(block.to_dict())
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/vendor-risk/vendors":
            try:
                assert_permission(Permission.MANAGE_CREDENTIALS)
                v_data = body.get("vendor", {})
                q_data = v_data.get("questionnaire", {})
                q = (
                    SecurityQuestionnaire(**q_data)
                    if q_data
                    else SecurityQuestionnaire()
                )
                vendor = Vendor(
                    vendor_id=v_data.get("vendor_id", "v-unknown"),
                    name=v_data.get("name", "Unknown Vendor"),
                    service_description=v_data.get("service_description", ""),
                    tier=VendorTier(v_data.get("tier", VendorTier.TIER_3_MEDIUM.value)),
                    data_classification=DataClassification(
                        v_data.get(
                            "data_classification", DataClassification.INTERNAL.value
                        )
                    ),
                    owner_email=v_data.get("owner_email", ""),
                    status=VendorStatus(
                        v_data.get("status", VendorStatus.UNDER_REVIEW.value)
                    ),
                    soc2_valid_until=v_data.get("soc2_valid_until"),
                    questionnaire=q,
                )
                base = self._get_tenant_base(get_current_tenant_id())
                vrm = VendorRiskManager(base)
                saved = vrm.save_vendor(vendor)

                TELEMETRY.emit(
                    action="SAVE_VENDOR_ASSESSMENT",
                    resource=f"vendor/{saved.vendor_id}",
                    outcome="SUCCESS",
                    details={
                        "risk_score": saved.risk_score,
                        "status": saved.status.value,
                    },
                )
                self._send_json(saved.to_dict())
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/access-review/decide":
            try:
                assert_permission(Permission.MANAGE_USER)
                camp_id = body.get("campaign_id")
                item_id = body.get("item_id")
                decision_str = body.get("decision", "MAINTAIN").upper()
                notes = body.get("notes", "")

                base = self._get_tenant_base(get_current_tenant_id())
                uar = AccessReviewManager(base)
                camp = uar.get_campaign(camp_id) if camp_id else None
                if not camp:
                    self._send_json(
                        {"error": f"Campaign '{camp_id}' not found"}, status=404
                    )
                    return

                found_item = False
                for it in camp.items:
                    if it.item_id == item_id:
                        it.record_decision(
                            decision=ReviewDecision(decision_str),
                            reviewer=get_current_user().user_id,
                            notes=notes,
                        )
                        found_item = True
                        break

                if not found_item:
                    self._send_json(
                        {"error": f"Item '{item_id}' not found in campaign"}, status=404
                    )
                    return

                uar.save_campaign(camp)
                TELEMETRY.emit(
                    action="UAR_DECISION",
                    resource=f"uar/{camp_id}/{item_id}",
                    outcome="SUCCESS",
                    details={"decision": decision_str},
                )
                self._send_json(camp.to_dict())
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/access-review/signoff":
            try:
                assert_permission(Permission.MANAGE_USER)
                camp_id = body.get("campaign_id")
                signatory = body.get("signatory", get_current_user().user_id)

                base = self._get_tenant_base(get_current_tenant_id())
                uar = AccessReviewManager(base)
                camp = uar.get_campaign(camp_id) if camp_id else None
                if not camp:
                    self._send_json(
                        {"error": f"Campaign '{camp_id}' not found"}, status=404
                    )
                    return

                sig_hash = camp.complete_and_sign(signatory)
                uar.save_campaign(camp)

                TELEMETRY.emit(
                    action="UAR_SIGNOFF_COMPLETED",
                    resource=f"uar/{camp_id}",
                    outcome="SUCCESS",
                    details={"sign_off_hash": sig_hash},
                )
                self._send_json(
                    {
                        "status": "completed",
                        "sign_off_hash": sig_hash,
                        "campaign": camp.to_dict(),
                    }
                )
                return
            except ValueError as ve:
                self._send_json({"error": str(ve)}, status=400)
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/notifications/test":
            try:
                assert_permission(Permission.MANAGE_CREDENTIALS)
                webhook_url = body.get("webhook_url", "")
                _validate_outbound_url(webhook_url)
                channel_str = body.get("channel", "generic").lower()
                channel = getattr(
                    NotificationChannel,
                    channel_str.upper(),
                    NotificationChannel.GENERIC_WEBHOOK,
                )

                alert = ComplianceAlert(
                    title="Test Compliance Notification",
                    message="Verification check from SOC2-Sentinel Enterprise Hub.",
                    severity=AlertSeverity.INFO,
                    control_id="CC7.2",
                )
                delivered = NotificationManager.send_webhook(
                    webhook_url=webhook_url, alert=alert, channel=channel
                )
                self._send_json({"delivered": delivered, "alert": alert.to_dict()})
                return
            except ValueError as ve:
                self._send_json({"error": str(ve)}, status=400)
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        # Phase 3 POST Endpoints
        if path == "/api/audit-rooms":
            try:
                assert_permission(Permission.MANAGE_USER)
                r_id = (
                    body.get("room_id")
                    or f"room_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
                )
                r_id = re.sub(r"[^a-zA-Z0-9_\-]", "", r_id)
                title = body.get("title", "SOC 2 Type II Audit Room")
                email = body.get("auditor_email", "auditor@enterprise.com")
                p_start = body.get(
                    "period_start", datetime.now(timezone.utc).strftime("%Y-%m-%d")
                )
                p_end = body.get(
                    "period_end", datetime.now(timezone.utc).strftime("%Y-%m-%d")
                )
                exp_days = int(body.get("expires_days", 90))
                notes = body.get("notes", "")

                base = self._get_tenant_base(get_current_tenant_id())
                arm = AuditRoomManager(base)
                room = arm.create_room(
                    room_id=r_id,
                    title=title,
                    auditor_email=email,
                    period_start=p_start,
                    period_end=p_end,
                    expires_days=exp_days,
                    notes=notes,
                )
                TELEMETRY.emit(
                    action="CREATE_AUDIT_ROOM",
                    resource=f"audit_room/{r_id}",
                    outcome="SUCCESS",
                    details={"auditor_email": email, "period": f"{p_start}:{p_end}"},
                )
                self._send_json(room.to_dict())
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/audit-rooms/revoke":
            try:
                assert_permission(Permission.MANAGE_USER)
                r_id = body.get("room_id", "")
                r_id = re.sub(r"[^a-zA-Z0-9_\-]", "", r_id)
                base = self._get_tenant_base(get_current_tenant_id())
                arm = AuditRoomManager(base)
                revoked = arm.revoke_room(r_id)
                if not revoked:
                    self._send_json(
                        {"error": f"Audit room '{r_id}' not found"}, status=404
                    )
                    return
                TELEMETRY.emit(
                    action="REVOKE_AUDIT_ROOM",
                    resource=f"audit_room/{r_id}",
                    outcome="SUCCESS",
                )
                self._send_json({"status": "revoked", "room_id": r_id})
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/audit-rooms/export":
            try:
                assert_permission(Permission.READ_REPORT)
                r_id = body.get("room_id", "")
                r_id = re.sub(r"[^a-zA-Z0-9_\-]", "", r_id)
                base = self._get_tenant_base(get_current_tenant_id())
                arm = AuditRoomManager(base)
                try:
                    zip_path = arm.export_audit_package_zip(r_id)
                    TELEMETRY.emit(
                        action="EXPORT_AUDIT_ROOM_ZIP",
                        resource=f"audit_room/{r_id}",
                        outcome="SUCCESS",
                        details={"path": str(zip_path)},
                    )
                    self._send_json(
                        {
                            "status": "success",
                            "room_id": r_id,
                            "download_url": f"/api/download/{zip_path.name}",
                            "file_name": zip_path.name,
                        }
                    )
                except ValueError as ve:
                    self._send_json({"error": str(ve)}, status=404)
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/siem/export":
            try:
                target = body.get("target", "NDJSON_FILE").upper()
                limit = int(body.get("limit", 200))
                base = self._get_tenant_base(get_current_tenant_id())
                exporter = SIEMExporter(base)

                if target == "NDJSON_FILE":
                    assert_permission(Permission.READ_AUDIT)
                    out_path = base / "siem_export.ndjson"
                    cnt = exporter.export_to_ndjson_file(out_path, limit=limit)
                    self._send_json(
                        {
                            "status": "exported",
                            "events_count": cnt,
                            "path": str(out_path),
                        }
                    )
                    return
                elif target == "SPLUNK_HEC":
                    assert_permission(Permission.MANAGE_CREDENTIALS)
                    url = body.get("endpoint_url", "")
                    _validate_outbound_url(url)
                    token = body.get("token", "")
                    ok, cnt, msg = exporter.forward_to_splunk_hec(url, token)
                    self._send_json(
                        {"success": ok, "forwarded_count": cnt, "message": msg},
                        status=200 if ok else 400,
                    )
                    return
                elif target == "DATADOG":
                    assert_permission(Permission.MANAGE_CREDENTIALS)
                    api_key = body.get("api_key", "")
                    site = body.get("site", "datadoghq.com")
                    ok, cnt, msg = exporter.forward_to_datadog(api_key, site=site)
                    self._send_json(
                        {"success": ok, "forwarded_count": cnt, "message": msg},
                        status=200 if ok else 400,
                    )
                    return
                elif target == "GENERIC_WEBHOOK":
                    assert_permission(Permission.MANAGE_CREDENTIALS)
                    webhook_url = body.get("webhook_url", "")
                    _validate_outbound_url(webhook_url)
                    secret_key = body.get("secret_key", "")
                    ok, cnt, msg = exporter.forward_to_webhook(
                        webhook_url, secret_key=secret_key
                    )
                    self._send_json(
                        {"success": ok, "forwarded_count": cnt, "message": msg},
                        status=200 if ok else 400,
                    )
                    return
                else:
                    self._send_json(
                        {"error": f"Unsupported SIEM target '{target}'"}, status=400
                    )
                    return
            except ValueError as ve:
                self._send_json({"error": str(ve)}, status=400)
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/scan":
            try:
                assert_permission(Permission.TRIGGER_COLLECTION)
                provider_name = body.get("provider", "aws")
                collector_req = body.get("collector", "all")
                base = self._get_tenant_base(get_current_tenant_id())

                try:
                    prov = get_provider(provider_name, self.server.config)
                except Exception as exc:
                    self._send_json(
                        {"status": "error", "error": f"Provider init error: {exc}"},
                        status=400,
                    )
                    return

                results = []
                targets = (
                    RUN_ALL_MAPPING.items()
                    if collector_req == "all"
                    else [(collector_req, RUN_ALL_MAPPING.get(collector_req, "CUSTOM"))]
                )

                for col_name, ctrl_id in targets:
                    fn = COLLECTORS.get(col_name)
                    if not fn:
                        continue
                    try:
                        written_path = fn(
                            provider=prov,
                            base=base,
                            control_id=ctrl_id,
                            config=self.server.config,
                        )
                        quality = "complete"
                        if written_path.exists():
                            try:
                                ev_data = json.loads(
                                    written_path.read_text(encoding="utf-8")
                                )
                                quality = ev_data.get("collection_quality", "complete")
                            except Exception:
                                pass
                        results.append(
                            {
                                "collector": col_name,
                                "control_id": ctrl_id,
                                "quality": quality,
                            }
                        )
                    except Exception as exc:
                        results.append(
                            {
                                "collector": col_name,
                                "control_id": ctrl_id,
                                "quality": "failed",
                                "error": str(exc),
                            }
                        )

                ev_dir = base / "evidence"
                dirs = (
                    sorted(
                        [
                            d.name
                            for d in ev_dir.iterdir()
                            if d.is_dir() and d.name != "manifests"
                        ]
                    )
                    if ev_dir.exists()
                    else []
                )
                latest_date = dirs[-1] if dirs else "today"

                TELEMETRY.emit(
                    action="TRIGGER_SCAN",
                    resource=f"provider/{provider_name}",
                    outcome="SUCCESS",
                    details={"collectors_run": len(results)},
                )

                self._send_json(
                    {
                        "status": "ok",
                        "date": latest_date,
                        "provider": provider_name,
                        "results": results,
                    }
                )
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return

        if path == "/api/export":
            try:
                assert_permission(Permission.READ_REPORT)
                base = self._get_tenant_base(get_current_tenant_id())
                ev_dir = base / "evidence"
                dirs_list: list[Path] = (
                    sorted(
                        [
                            d
                            for d in ev_dir.iterdir()
                            if d.is_dir() and d.name != "manifests"
                        ],
                        key=lambda d: d.name,
                    )
                    if ev_dir.exists()
                    else []
                )
                if not dirs_list:
                    self._send_json(
                        {
                            "status": "error",
                            "error": "No evidence directories found to package",
                        },
                        status=404,
                    )
                    return
                latest_dir = dirs_list[-1]
                zip_path = export_audit_pack(latest_dir, output_dir=ev_dir)

                TELEMETRY.emit(
                    action="EXPORT_AUDIT_PACK",
                    resource=f"evidence/{latest_dir.name}",
                    outcome="SUCCESS",
                    details={"file": zip_path.name, "size": zip_path.stat().st_size},
                )

                self._send_json(
                    {
                        "status": "ok",
                        "filename": zip_path.name,
                        "download_url": f"/api/download/{zip_path.name}",
                        "size_bytes": zip_path.stat().st_size,
                        "date": latest_dir.name,
                    }
                )
                return
            except PermissionError as pe:
                self._send_json({"error": str(pe)}, status=403)
                return
            except Exception as exc:
                self._send_json({"status": "error", "error": str(exc)}, status=500)
                return

        self._send_json({"error": "Endpoint not found", "path": path}, status=404)


class DashboardServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        *,
        output_base: Path,
        config: SentinelConfig | None = None,
        daemon: ContinuousMonitoringDaemon | None = None,
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.output_base = output_base
        self.config = config
        self.daemon = daemon


def run_dashboard_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    output_base: Path | None = None,
    config: SentinelConfig | None = None,
    enable_daemon: bool = False,
    daemon_interval: int = 3600,
    provider: str = "aws",
    open_browser: bool = True,
) -> None:
    base = output_base or Path.cwd()
    daemon: ContinuousMonitoringDaemon | None = None

    if enable_daemon:
        daemon = ContinuousMonitoringDaemon(
            provider_name=provider,
            interval_seconds=daemon_interval,
            output_base=base,
            config=config,
        )
        daemon.start()

    actual_port = port
    server: DashboardServer | None = None
    for attempt in range(10):
        try:
            server = DashboardServer(
                (host, actual_port),
                DashboardHandler,
                output_base=base,
                config=config,
                daemon=daemon,
            )
            break
        except OSError:
            actual_port += 1

    if not server:
        raise OSError(
            f"Could not bind dashboard server to {host} in port range {port}-{actual_port}"
        )

    url = f"http://{host}:{actual_port}"
    print("\n=======================================================")
    print(f"  SOC2 Sentinel v{__version__} Enterprise Dashboard Active")
    print(f"  URL: {url}")
    print(f"  Output Base: {base}")
    print(
        f"  Continuous Daemon: {'ENABLED (' + str(daemon_interval) + 's)' if enable_daemon else 'DISABLED'}"
    )
    print("=======================================================\n")

    if open_browser:
        try:
            import webbrowser

            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Sentinel dashboard server...")
    finally:
        if daemon:
            daemon.stop()
        server.server_close()
