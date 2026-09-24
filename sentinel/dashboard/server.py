from __future__ import annotations

import json
import logging
import mimetypes
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.cli import RUN_ALL_MAPPING
from sentinel.collectors import COLLECTORS
from sentinel.config import SentinelConfig
from sentinel.daemon import ContinuousMonitoringDaemon
from sentinel.dashboard.assets import DASHBOARD_HTML
from sentinel.drift import detect_configuration_drift
from sentinel.integrity import verify_evidence_tree
from sentinel.onboarding import diagnose_all_providers
from sentinel.providers import get_provider
from sentinel.reporting import export_audit_pack, generate_executive_html_report
from sentinel.scoring import compute_compliance_scorecard

logger = logging.getLogger("sentinel.dashboard.server")


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer  # type: ignore

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)

    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, html_text: str, status: int = 200) -> None:
        payload = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in {"/", "/index.html"}:
            self._send_html(DASHBOARD_HTML)
            return

        if path == "/api/status":
            daemon_status = self.server.daemon.get_status().to_dict() if self.server.daemon else None
            self._send_json({
                "version": __version__,
                "output_base": str(self.server.output_base),
                "daemon": daemon_status,
                "pid": os.getpid(),
            })
            return

        if path == "/api/scorecard":
            try:
                scorecard = compute_compliance_scorecard(self.server.output_base / "evidence")
                self._send_json(scorecard.to_dict())
            except Exception as exc:
                logger.error("Error computing scorecard: %s", exc, exc_info=True)
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/drift":
            try:
                drift = detect_configuration_drift(self.server.output_base / "evidence")
                self._send_json(drift.to_dict())
            except Exception as exc:
                logger.error("Error computing drift: %s", exc, exc_info=True)
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/credentials":
            try:
                diag = diagnose_all_providers(self.server.config)
                self._send_json(diag)
            except Exception as exc:
                logger.error("Error diagnosing providers: %s", exc, exc_info=True)
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/evidence":
            ev_dir = self.server.output_base / "evidence"
            dates: list[str] = []
            if ev_dir.exists():
                dates = sorted(
                    [d.name for d in ev_dir.iterdir() if d.is_dir() and d.name != "manifests"],
                    reverse=True,
                )
            self._send_json(dates)
            return

        if path.startswith("/api/evidence/"):
            parts = path.strip("/").split("/")
            # /api/evidence/<date>/<file>
            if len(parts) >= 3:
                date_str = parts[2]
                file_target = "/".join(parts[3:]) if len(parts) > 3 else "manifest.json"
                ev_dir = self.server.output_base / "evidence" / date_str
                target_file = ev_dir / file_target
                if target_file.exists() and target_file.is_file():
                    try:
                        content = json.loads(target_file.read_text(encoding="utf-8"))
                        self._send_json(content)
                        return
                    except Exception:
                        self._send_json({"raw": target_file.read_text(encoding="utf-8", errors="replace")})
                        return
                else:
                    self._send_json({"error": "Artifact not found", "path": str(target_file)}, status=404)
                    return

        if path == "/api/report/latest":
            ev_dir = self.server.output_base / "evidence"
            if not ev_dir.exists():
                self._send_html("<h1>No evidence directories exist yet.</h1>", status=404)
                return
            dirs = sorted([d for d in ev_dir.iterdir() if d.is_dir() and d.name != "manifests"], key=lambda d: d.name)
            if not dirs:
                self._send_html("<h1>No evidence runs found.</h1>", status=404)
                return
            latest_dir = dirs[-1]
            scorecard = compute_compliance_scorecard(ev_dir, date_str=latest_dir.name)
            html_report = generate_executive_html_report(scorecard, latest_dir)
            self._send_html(html_report)
            return

        if path.startswith("/api/download/"):
            fname = path.replace("/api/download/", "")
            target_path = self.server.output_base / "evidence" / fname
            if not target_path.exists() or not target_path.is_file():
                # Check root output_base
                target_path = self.server.output_base / fname
            if target_path.exists() and target_path.is_file():
                self.send_response(200)
                content_type, _ = mimetypes.guess_type(str(target_path))
                self.send_header("Content-Type", content_type or "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{target_path.name}"')
                self.send_header("Content-Length", str(target_path.stat().st_size))
                self.end_headers()
                with target_path.open("rb") as f:
                    while chunk := f.read(65536):
                        self.wfile.write(chunk)
                return
            else:
                self._send_json({"error": "File not found"}, status=404)
                return

        self._send_json({"error": "Endpoint not found", "path": path}, status=404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_body_json()

        if path == "/api/verify":
            date_str = body.get("date")
            if not date_str:
                self._send_json({"error": "Missing 'date' parameter"}, status=400)
                return
            target_dir = self.server.output_base / "evidence" / date_str
            if not target_dir.exists():
                self._send_json({"valid": False, "errors": [f"Directory {target_dir} does not exist"]}, status=404)
                return
            tree_res = verify_evidence_tree(target_dir)
            valid = not bool(tree_res.get("failed"))
            errors: list[str] = []
            for ctrl, issues in tree_res.get("failed", {}).items():
                errors.extend(f"{ctrl}: {i}" for i in issues)
            self._send_json({"valid": valid, "errors": errors, "date": date_str, "tree": tree_res})
            return

        if path == "/api/scan":
            provider_name = body.get("provider", "mock")
            collector_req = body.get("collector", "all")
            enc_key = body.get("encryption_key")
            if enc_key:
                os.environ["SENTINEL_EVIDENCE_KEY"] = enc_key

            try:
                prov = get_provider(provider_name, self.server.config)
            except Exception as exc:
                self._send_json({"status": "error", "error": f"Provider init error: {exc}"}, status=400)
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
                        base=self.server.output_base,
                        control_id=ctrl_id,
                        config=self.server.config,
                    )
                    quality = "complete"
                    if written_path.exists():
                        try:
                            ev_data = json.loads(written_path.read_text(encoding="utf-8"))
                            quality = ev_data.get("collection_quality", "complete")
                        except Exception:
                            pass
                    results.append({
                        "collector": col_name,
                        "control_id": ctrl_id,
                        "quality": quality,
                    })
                except Exception as exc:
                    results.append({
                        "collector": col_name,
                        "control_id": ctrl_id,
                        "quality": "failed",
                        "error": str(exc),
                    })

            # Check latest run date
            ev_dir = self.server.output_base / "evidence"
            dirs = sorted([d.name for d in ev_dir.iterdir() if d.is_dir() and d.name != "manifests"]) if ev_dir.exists() else []
            latest_date = dirs[-1] if dirs else "today"

            self._send_json({
                "status": "ok",
                "date": latest_date,
                "provider": provider_name,
                "results": results,
            })
            return

        if path == "/api/export":
            ev_dir = self.server.output_base / "evidence"
            dirs_list: list[Path] = (
                sorted([d for d in ev_dir.iterdir() if d.is_dir() and d.name != "manifests"], key=lambda d: d.name)
                if ev_dir.exists()
                else []
            )
            if not dirs_list:
                self._send_json({"status": "error", "error": "No evidence directories found to package"}, status=404)
                return
            latest_dir = dirs_list[-1]
            try:
                zip_path = export_audit_pack(latest_dir, output_dir=ev_dir)
                self._send_json({
                    "status": "ok",
                    "filename": zip_path.name,
                    "download_url": f"/api/download/{zip_path.name}",
                    "size_bytes": zip_path.stat().st_size,
                    "date": latest_dir.name,
                })
            except Exception as exc:
                logger.error("Audit pack export error: %s", exc, exc_info=True)
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
    provider: str = "mock",
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

    # Find open port if specified port is in use
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
        raise OSError(f"Could not bind dashboard server to {host} in port range {port}-{actual_port}")

    url = f"http://{host}:{actual_port}"
    print("\n=======================================================")
    print(f"  SOC2 Sentinel v{__version__} Dashboard Active")
    print(f"  URL: {url}")
    print(f"  Output Base: {base}")
    print(f"  Continuous Daemon: {'ENABLED (' + str(daemon_interval) + 's)' if enable_daemon else 'DISABLED'}")
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
