from __future__ import annotations

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC2 Sentinel — Enterprise Compliance & Audit Platform</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #07090e;
      --bg-surface: #0e131f;
      --bg-card: rgba(18, 24, 38, 0.7);
      --bg-card-hover: rgba(26, 34, 54, 0.85);
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-focus: #3b82f6;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent-primary: #3b82f6;
      --accent-glow: rgba(59, 130, 246, 0.25);
      --status-success: #10b981;
      --status-success-glow: rgba(16, 185, 129, 0.2);
      --status-warning: #f59e0b;
      --status-warning-glow: rgba(245, 158, 11, 0.2);
      --status-danger: #ef4444;
      --status-danger-glow: rgba(239, 68, 68, 0.2);
      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 16px;
      --transition-fast: 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg-base);
      color: var(--text-main);
      min-height: 100vh;
      overflow-x: hidden;
      background-image:
        radial-gradient(circle at 15% 10%, rgba(59, 130, 246, 0.08) 0%, transparent 40%),
        radial-gradient(circle at 85% 80%, rgba(16, 185, 129, 0.05) 0%, transparent 45%);
    }

    /* Layout */
    .app-header {
      position: sticky;
      top: 0;
      z-index: 50;
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      background: rgba(7, 9, 14, 0.85);
      border-bottom: 1px solid var(--border-subtle);
      padding: 14px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      color: var(--text-main);
    }
    .brand-icon {
      width: 36px;
      height: 36px;
      background: linear-gradient(135deg, #2563eb, #10b981);
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 18px;
      color: #fff;
      box-shadow: 0 0 16px rgba(37, 99, 235, 0.4);
    }
    .brand-title {
      font-size: 18px;
      font-weight: 700;
      letter-spacing: -0.3px;
    }
    .brand-version {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      background: rgba(59, 130, 246, 0.15);
      color: var(--accent-primary);
      margin-left: 6px;
    }

    .header-nav {
      display: flex;
      gap: 4px;
      background: rgba(14, 19, 31, 0.9);
      padding: 4px;
      border-radius: var(--radius-md);
      border: 1px solid var(--border-subtle);
    }
    .nav-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 8px 14px;
      border-radius: var(--radius-sm);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all var(--transition-fast);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .nav-btn:hover {
      color: var(--text-main);
      background: rgba(255, 255, 255, 0.04);
    }
    .nav-btn.active {
      background: var(--accent-primary);
      color: #fff;
      box-shadow: 0 2px 8px var(--accent-glow);
    }

    .header-status {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .provider-pill {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border-subtle);
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
    }
    .indicator-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--status-success);
      box-shadow: 0 0 8px var(--status-success);
    }

    .main-container {
      max-width: 1380px;
      margin: 0 auto;
      padding: 32px 28px;
    }

    /* Tab View Management */
    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.25s ease-out; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }

    /* Cards & Components */
    .glass-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      padding: 24px;
      margin-bottom: 24px;
      transition: border-color var(--transition-fast);
    }
    .glass-card:hover {
      border-color: rgba(255, 255, 255, 0.14);
    }

    /* Hero Scoreboard */
    .hero-grid {
      display: grid;
      grid-template-columns: 280px 1fr;
      gap: 28px;
      align-items: center;
    }
    .gauge-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
    }
    .gauge-circle {
      position: relative;
      width: 180px;
      height: 180px;
    }
    .gauge-circle svg {
      width: 100%;
      height: 100%;
      transform: rotate(-90deg);
    }
    .gauge-bg {
      fill: none;
      stroke: rgba(255, 255, 255, 0.08);
      stroke-width: 14;
    }
    .gauge-fill {
      fill: none;
      stroke: var(--status-success);
      stroke-width: 14;
      stroke-linecap: round;
      stroke-dasharray: 471;
      stroke-dashoffset: 80;
      transition: stroke-dashoffset 1s ease-in-out, stroke 0.3s;
    }
    .gauge-value {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      font-size: 40px;
      font-weight: 800;
      letter-spacing: -1px;
    }
    .gauge-label {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-top: 12px;
    }

    .hero-details h2 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
    .hero-details p { color: var(--text-muted); font-size: 14px; line-height: 1.6; max-width: 780px; }
    .hero-actions { display: flex; gap: 12px; margin-top: 20px; }

    /* Framework Grid */
    .framework-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
      gap: 20px;
      margin-bottom: 28px;
    }
    .fw-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 20px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .fw-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }
    .fw-title { font-size: 15px; font-weight: 700; }
    .fw-score { font-size: 24px; font-weight: 800; }
    .fw-readiness {
      font-size: 12px;
      font-weight: 600;
      margin-bottom: 14px;
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
    }
    .readiness-audit { background: var(--status-success-glow); color: var(--status-success); }
    .readiness-partial { background: var(--status-warning-glow); color: var(--status-warning); }
    .readiness-gap { background: var(--status-danger-glow); color: var(--status-danger); }

    .fw-bars { display: flex; flex-direction: column; gap: 8px; margin-top: 8px; }
    .bar-row { display: flex; align-items: center; justify-content: space-between; font-size: 12px; }
    .bar-label { color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 140px; }
    .bar-track { flex: 1; height: 6px; background: rgba(255, 255, 255, 0.06); border-radius: 3px; margin: 0 10px; overflow: hidden; }
    .bar-fill { height: 100%; background: var(--accent-primary); border-radius: 3px; }
    .bar-val { font-weight: 600; width: 34px; text-align: right; }

    /* Tables */
    .table-container {
      width: 100%;
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      text-align: left;
    }
    th {
      padding: 14px 12px;
      border-bottom: 1px solid var(--border-subtle);
      color: var(--text-dim);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.5px;
    }
    td {
      padding: 14px 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      vertical-align: top;
    }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    /* Badges & Buttons */
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: var(--radius-sm);
      font-weight: 700;
      font-size: 11px;
      letter-spacing: 0.3px;
    }
    .badge-pass { background: var(--status-success-glow); color: var(--status-success); border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-partial { background: var(--status-warning-glow); color: var(--status-warning); border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-fail { background: var(--status-danger-glow); color: var(--status-danger); border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-neutral { background: rgba(255, 255, 255, 0.06); color: var(--text-muted); }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 18px;
      border-radius: var(--radius-sm);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all var(--transition-fast);
      border: 1px solid transparent;
      text-decoration: none;
    }
    .btn-primary {
      background: var(--accent-primary);
      color: #fff;
      box-shadow: 0 2px 10px var(--accent-glow);
    }
    .btn-primary:hover {
      background: #2563eb;
      transform: translateY(-1px);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.06);
      color: var(--text-main);
      border-color: var(--border-subtle);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: rgba(255, 255, 255, 0.15);
    }
    .btn-success {
      background: var(--status-success);
      color: #fff;
    }
    .btn-sm { padding: 6px 12px; font-size: 12px; }

    /* Console & Code */
    .console-box {
      background: #04060a;
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 16px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: #e2e8f0;
      min-height: 240px;
      max-height: 480px;
      overflow-y: auto;
      line-height: 1.6;
      white-space: pre-wrap;
    }
    .console-cursor {
      display: inline-block;
      width: 8px;
      height: 14px;
      background: var(--accent-primary);
      animation: blink 1s infinite;
      vertical-align: middle;
    }
    @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }

    /* Form Controls */
    .form-group { margin-bottom: 16px; }
    .form-label { display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; }
    .form-select, .form-input {
      width: 100%;
      background: #090d16;
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
      padding: 10px 14px;
      border-radius: var(--radius-sm);
      font-size: 13px;
      outline: none;
      transition: border-color var(--transition-fast);
    }
    .form-select:focus, .form-input:focus { border-color: var(--border-focus); }

    /* Diagnostics Cards */
    .onboarding-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 20px;
    }
    .cloud-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 24px;
      position: relative;
    }
    .cloud-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }
    .cloud-name { font-size: 18px; font-weight: 700; text-transform: uppercase; }
    .check-list { list-style: none; margin: 16px 0; font-size: 12px; display: flex; flex-direction: column; gap: 8px; }
    .check-item { display: flex; align-items: flex-start; gap: 8px; }
    .check-pass { color: var(--status-success); }
    .check-fail { color: var(--status-danger); }
    .policy-box {
      background: #050811;
      border: 1px solid rgba(255, 255, 255, 0.06);
      padding: 12px;
      border-radius: var(--radius-sm);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      max-height: 180px;
      overflow-y: auto;
      margin-top: 10px;
      color: #94a3b8;
    }

    /* Modal / Alert Notifications */
    .toast-container {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 100;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .toast {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-left: 4px solid var(--accent-primary);
      padding: 12px 18px;
      border-radius: var(--radius-sm);
      font-size: 13px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
      animation: slideIn 0.3s ease;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    @keyframes slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }
  </style>
</head>
<body>

  <!-- Top Navigation Bar -->
  <header class="app-header">
    <a href="#" class="brand">
      <div class="brand-icon">S</div>
      <div>
        <span class="brand-title">SOC2 Sentinel</span>
        <span class="brand-version">v2.5.0</span>
      </div>
    </a>

    <nav class="header-nav">
      <button class="nav-btn active" id="nav-btn-posture" onclick="switchTab('posture')">
        <span>Executive Posture</span>
      </button>
      <button class="nav-btn" id="nav-btn-scanner" onclick="switchTab('scanner')">
        <span>Live Scanner</span>
      </button>
      <button class="nav-btn" id="nav-btn-evidence" onclick="switchTab('evidence')">
        <span>Evidence Explorer</span>
      </button>
      <button class="nav-btn" id="nav-btn-drift" onclick="switchTab('drift')">
        <span>Configuration Drift</span>
      </button>
      <button class="nav-btn" id="nav-btn-onboarding" onclick="switchTab('onboarding')">
        <span>Cloud Diagnostics</span>
      </button>
      <button class="nav-btn" id="nav-btn-export" onclick="switchTab('export')">
        <span>Audit Pack Export</span>
      </button>
      <button class="nav-btn" id="nav-btn-directions" onclick="switchTab('directions')">
        <span>How to Run</span>
      </button>
    </nav>

    <div class="header-status">
      <div class="provider-pill" id="active-provider-pill">
        <div class="indicator-dot" id="provider-dot"></div>
        <span id="active-provider-name">Provider: MOCK</span>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="refreshAllData()" title="Reload telemetry">
        &#x21bb; Refresh
      </button>
    </div>
  </header>

  <div class="main-container">

    <!-- 1. Executive Posture Tab -->
    <div id="tab-posture" class="tab-content active">
      <div class="glass-card hero-grid">
        <div class="gauge-wrapper">
          <div class="gauge-circle">
            <svg viewBox="0 0 180 180">
              <circle class="gauge-bg" cx="90" cy="90" r="75"></circle>
              <circle class="gauge-fill" id="hero-gauge-circle" cx="90" cy="90" r="75"></circle>
            </svg>
            <div class="gauge-value" id="hero-gauge-val">--%</div>
          </div>
          <div class="gauge-label">Composite Security Posture</div>
        </div>
        <div class="hero-details">
          <h2>Enterprise Multi-Framework Compliance Scoreboard</h2>
          <p>
            Continuous compliance evaluation across SOC 2 Type II, NIST SP 800-171/172, CMMC 2.0 Level 2, and CISA Zero Trust Maturity Model.
            All metrics reflect tamper-evident cryptographic evidence collected from active infrastructure.
          </p>
          <div class="hero-actions">
            <button class="btn btn-primary" onclick="switchTab('scanner')">Run Live Collection Cycle</button>
            <button class="btn btn-secondary" onclick="switchTab('export')">Generate Executive Audit Pack</button>
          </div>
        </div>
      </div>

      <!-- Framework Cards Grid -->
      <div class="framework-grid" id="frameworks-container">
        <!-- Dynamically rendered -->
      </div>

      <!-- Control Evaluation Matrix -->
      <div class="glass-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
          <div>
            <h3 style="font-size: 18px; font-weight: 700;">Controls Evaluation Matrix</h3>
            <p style="color: var(--text-muted); font-size: 13px;">Real-time automated control status derived from 7 core evidence collectors</p>
          </div>
          <div style="display: flex; gap: 8px;">
            <select class="form-select" id="control-filter" onchange="filterControls()" style="width: 160px; padding: 6px 10px;">
              <option value="ALL">All Controls</option>
              <option value="PASS">Passing</option>
              <option value="PARTIAL">Partial</option>
              <option value="FAIL">Failing / Gaps</option>
            </select>
          </div>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Control ID</th>
                <th>Domain / Capability</th>
                <th>Status</th>
                <th>Score</th>
                <th>Collection Quality</th>
                <th>Telemetry Metrics</th>
                <th>Deficiencies & Findings</th>
              </tr>
            </thead>
            <tbody id="controls-table-body">
              <!-- Dynamically populated -->
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- 2. Live Scanner Tab -->
    <div id="tab-scanner" class="tab-content">
      <div class="glass-card">
        <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 6px;">Live Evidence Collection Runner</h3>
        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 24px;">Execute real-time evidence collection against AWS, GCP, Azure, or offline Mock testbeds</p>

        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 16px; align-items: flex-end; margin-bottom: 24px;">
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="scan-provider-select">Target Cloud Provider</label>
            <select class="form-select" id="scan-provider-select">
              <option value="mock">Mock Fixture (Offline Demo)</option>
              <option value="aws">Amazon Web Services (AWS Live)</option>
              <option value="gcp">Google Cloud Platform (GCP Live)</option>
              <option value="azure">Microsoft Azure (Azure Live)</option>
            </select>
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="scan-collector-select">Collector Routine</label>
            <select class="form-select" id="scan-collector-select">
              <option value="all">ALL 7 COLLECTORS (Complete Suite)</option>
              <option value="iam_access_review">IAM Access Review (CC6.1)</option>
              <option value="log_aggregator">Log Aggregator & Streams (CC7.1)</option>
              <option value="config_drift">Config Drift & Baselines (CC6.2)</option>
              <option value="encryption_status">Encryption Status (C1.2)</option>
              <option value="retention_check">Retention & Purge Check (C1.4)</option>
              <option value="resilience_testing">Resilience & Backup Testing (A1.2)</option>
              <option value="zt_continuous_verification">Zero Trust Verification (ZT-1)</option>
            </select>
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label" for="scan-encryption-key">AES-GCM Key (Optional)</label>
            <input type="password" class="form-input" id="scan-encryption-key" placeholder="SENTINEL_EVIDENCE_KEY (32-byte hex)">
          </div>
          <button class="btn btn-primary" id="btn-trigger-scan" onclick="triggerScan()" style="height: 40px;">
            Execute Collection
          </button>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <span style="font-size: 12px; font-weight: 600; color: var(--text-dim); text-transform: uppercase;">Live Terminal Console</span>
          <button class="btn btn-secondary btn-sm" onclick="clearConsole()">Clear Logs</button>
        </div>
        <div class="console-box" id="scanner-console">
[READY] SOC2 Sentinel v2.5.0 Engine initialized.
Select a target cloud provider and collector routine to execute an evidence run.<span class="console-cursor"></span>
        </div>
      </div>
    </div>

    <!-- 3. Evidence Explorer Tab -->
    <div id="tab-evidence" class="tab-content">
      <div style="display: grid; grid-template-columns: 320px 1fr; gap: 24px;">
        <div class="glass-card" style="height: fit-content;">
          <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 12px;">Evidence History</h3>
          <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 16px;">Historical audit windows stored in local evidence repository</p>
          <div id="evidence-dates-list" style="display: flex; flex-direction: column; gap: 8px;">
            <!-- Rendered list of dates -->
          </div>
        </div>

        <div class="glass-card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <div>
              <h3 style="font-size: 18px; font-weight: 700;" id="evidence-viewer-title">Evidence Inspection</h3>
              <p style="color: var(--text-muted); font-size: 12px;" id="evidence-viewer-subtitle">Select an evidence artifact to view cryptographic payload</p>
            </div>
            <div style="display: flex; gap: 10px;">
              <button class="btn btn-secondary btn-sm" id="btn-verify-manifest" onclick="verifyCurrentManifest()">
                Verify SHA-256 Manifest
              </button>
            </div>
          </div>
          <div class="console-box" id="evidence-payload-viewer" style="min-height: 400px;">
// Select an evidence date and collector from the left panel to inspect raw payload and HMAC digest.
          </div>
        </div>
      </div>
    </div>

    <!-- 4. Configuration Drift Tab -->
    <div id="tab-drift" class="tab-content">
      <div class="glass-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <div>
            <h3 style="font-size: 18px; font-weight: 700;">Configuration Drift & Regressions</h3>
            <p style="color: var(--text-muted); font-size: 13px;">Automated diff comparing latest infrastructure state against previous baseline</p>
          </div>
          <span class="badge" id="drift-status-badge">No Drift Detected</span>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Collector</th>
                <th>Control ID</th>
                <th>Drifted Parameter</th>
                <th>Baseline Value</th>
                <th>Current Value</th>
                <th>Impact & Description</th>
              </tr>
            </thead>
            <tbody id="drift-table-body">
              <!-- Dynamically populated -->
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- 5. Cloud Diagnostics & Onboarding Tab -->
    <div id="tab-onboarding" class="tab-content">
      <div class="glass-card" style="margin-bottom: 24px;">
        <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 6px;">Tri-Cloud Preflight & Guided IAM Onboarding</h3>
        <p style="color: var(--text-muted); font-size: 13px;">
          Sentinel connects directly to live cloud APIs with least-privilege read-only permissions.
          Below is the live credential health status for each supported provider with minimal copy-paste IAM remediation policies.
        </p>
      </div>

      <div class="onboarding-grid" id="onboarding-cards-container">
        <!-- Rendered dynamically -->
      </div>
    </div>

    <!-- 6. Audit Pack Export Tab -->
    <div id="tab-export" class="tab-content">
      <div class="glass-card" style="max-width: 800px; margin: 0 auto;">
        <h3 style="font-size: 20px; font-weight: 700; margin-bottom: 8px;">1-Click Executive Audit Pack Exporter</h3>
        <p style="color: var(--text-muted); font-size: 13px; line-height: 1.6; margin-bottom: 24px;">
          Generate an audit-grade package containing a self-contained, printable Executive HTML Report, raw evidence JSON payloads,
          cryptographic SHA-256 manifests, HMAC verification signatures, and tamper-evident audit logs.
        </p>

        <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 20px; margin-bottom: 24px;">
          <h4 style="font-size: 14px; font-weight: 600; margin-bottom: 12px;">Package Contents:</h4>
          <ul style="list-style-type: square; padding-left: 20px; font-size: 13px; color: var(--text-muted); display: flex; flex-direction: column; gap: 6px;">
            <li><strong>Executive HTML Report:</strong> High-impact visual dashboard report (printable to PDF)</li>
            <li><strong>Signed Evidence Trees:</strong> Complete JSON evidence for all evaluated controls</li>
            <li><strong>Integrity Manifest:</strong> SHA-256 digests of every file with HMAC verification</li>
            <li><strong>Immutable Audit Trail:</strong> JSONL event log tracking all collection and verification events</li>
            <li><strong>Auditor Verification Readme:</strong> Exact CLI verification instructions for external auditors</li>
          </ul>
        </div>

        <div style="display: flex; gap: 14px;">
          <button class="btn btn-primary" id="btn-export-pack" onclick="exportAuditPack()">
            Generate & Download Audit Pack ZIP
          </button>
          <button class="btn btn-secondary" onclick="viewExecutiveReport()">
            Open Executive HTML Report in New Tab
          </button>
        </div>

        <div id="export-result-box" style="margin-top: 20px; display: none;"></div>
      </div>
    </div>

    <!-- 7. How to Run & Directions Tab -->
    <div id="tab-directions" class="tab-content">
      <div class="glass-card">
        <h2 style="font-size: 22px; font-weight: 800; margin-bottom: 8px; display: flex; align-items: center; gap: 10px;">
          <span>Execution Guide &amp; Operational Directions</span>
          <span class="badge badge-pass" style="font-size: 11px;">v2.5.0 Manual</span>
        </h2>
        <p style="color: var(--text-muted); font-size: 14px; line-height: 1.6; margin-bottom: 24px;">
          Step-by-step instructions for running evidence collection, continuous monitoring, multi-framework scorecards, and audit pack generation via both the Web Dashboard and the CLI.
        </p>

        <!-- 3 Quick Cards Grid -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 24px;">
          <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 18px;">
            <div style="font-weight: 700; font-size: 15px; color: var(--accent-primary); margin-bottom: 6px;">1. Instant Mock Demo</div>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">Test the full collection, scoring, and reporting pipeline with zero cloud credentials required.</p>
            <div style="background: #000; padding: 10px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 12px; position: relative;">
              <code>sentinel run-all --provider mock</code>
              <button onclick="copyCommand('sentinel run-all --provider mock')" style="position: absolute; right: 8px; top: 8px; background: rgba(255,255,255,0.1); border: none; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 10px; cursor: pointer;">Copy</button>
            </div>
          </div>

          <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 18px;">
            <div style="font-weight: 700; font-size: 15px; color: var(--status-success); margin-bottom: 6px;">2. Web Dashboard &amp; Daemon</div>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">Launch this embedded UI and start the continuous monitoring background worker.</p>
            <div style="background: #000; padding: 10px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 12px; position: relative;">
              <code>sentinel serve --port 8443</code>
              <button onclick="copyCommand('sentinel serve --port 8443')" style="position: absolute; right: 8px; top: 8px; background: rgba(255,255,255,0.1); border: none; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 10px; cursor: pointer;">Copy</button>
            </div>
          </div>

          <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 18px;">
            <div style="font-weight: 700; font-size: 15px; color: #a855f7; margin-bottom: 6px;">3. 1-Click Audit Pack</div>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">Compile signed HTML executive report and verified cryptographic ZIP package.</p>
            <div style="background: #000; padding: 10px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 12px; position: relative;">
              <code>sentinel audit-pack evidence</code>
              <button onclick="copyCommand('sentinel audit-pack evidence')" style="position: absolute; right: 8px; top: 8px; background: rgba(255,255,255,0.1); border: none; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 10px; cursor: pointer;">Copy</button>
            </div>
          </div>
        </div>

        <!-- Section: Cloud Provider Setup -->
        <h3 style="font-size: 16px; font-weight: 700; margin-top: 24px; margin-bottom: 12px;">Live Tri-Cloud Provider Configuration</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 24px;">
          <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 16px;">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 8px; color: #93c5fd;">Amazon Web Services (AWS)</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">Requires standard AWS environment variables or AWS CLI profile. Needs read-only IAM permissions for IAM, CloudTrail, Config, KMS, and AWS Backup.</p>
            <pre style="background: #000; padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #93c5fd;">$env:AWS_ACCESS_KEY_ID="AKIA..."
$env:AWS_SECRET_ACCESS_KEY="..."
$env:AWS_DEFAULT_REGION="us-east-1"
sentinel onboarding --provider aws</pre>
          </div>

          <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 16px;">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 8px; color: #86efac;">Google Cloud Platform (GCP)</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">Uses Application Default Credentials (ADC) or Service Account key. Needs Cloud Asset, Cloud Logging, KMS, and Compute snapshot viewers.</p>
            <pre style="background: #000; padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #86efac;">gcloud auth application-default login
$env:GOOGLE_CLOUD_PROJECT="my-project"
sentinel onboarding --provider gcp</pre>
          </div>

          <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 16px;">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 8px; color: #c084fc;">Microsoft Azure</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">Authenticate via Azure CLI or Service Principal. Needs Reader on Subscription and Microsoft Graph Directory/AuditLog read permissions.</p>
            <pre style="background: #000; padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #c084fc;">az login
$env:AZURE_SUBSCRIPTION_ID="..."
sentinel onboarding --provider azure</pre>
          </div>
        </div>

        <!-- Section: CLI Command Reference -->
        <h3 style="font-size: 16px; font-weight: 700; margin-top: 24px; margin-bottom: 12px;">Full CLI Command Cheat Sheet</h3>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Command</th>
                <th>Flags / Arguments</th>
                <th>Description</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><code>sentinel serve</code></td>
                <td><code>--port 8443 --interval 3600</code></td>
                <td>Launch Web Dashboard &amp; Continuous Daemon</td>
                <td><button class="btn btn-secondary btn-sm" onclick="copyCommand('sentinel serve')">Copy</button></td>
              </tr>
              <tr>
                <td><code>sentinel run-all</code></td>
                <td><code>--provider aws|gcp|azure|mock</code></td>
                <td>Execute all 7 automated evidence collectors</td>
                <td><button class="btn btn-secondary btn-sm" onclick="copyCommand('sentinel run-all --provider mock')">Copy</button></td>
              </tr>
              <tr>
                <td><code>sentinel scorecard</code></td>
                <td><code>--date YYYY-MM-DD</code></td>
                <td>Compute multi-framework compliance posture (SOC2, NIST, CMMC, ZT)</td>
                <td><button class="btn btn-secondary btn-sm" onclick="copyCommand('sentinel scorecard')">Copy</button></td>
              </tr>
              <tr>
                <td><code>sentinel drift</code></td>
                <td><code>--baseline &lt;date&gt; --current &lt;date&gt;</code></td>
                <td>Detect configuration regressions &amp; compliance drift</td>
                <td><button class="btn btn-secondary btn-sm" onclick="copyCommand('sentinel drift')">Copy</button></td>
              </tr>
              <tr>
                <td><code>sentinel onboarding</code></td>
                <td><code>--provider aws|gcp|azure</code></td>
                <td>Preflight permission diagnostics &amp; minimal IAM policy fixes</td>
                <td><button class="btn btn-secondary btn-sm" onclick="copyCommand('sentinel onboarding --provider aws')">Copy</button></td>
              </tr>
              <tr>
                <td><code>sentinel verify</code></td>
                <td><code>evidence/&lt;date&gt;</code></td>
                <td>Cryptographically verify SHA-256 digests &amp; HMAC signatures</td>
                <td><button class="btn btn-secondary btn-sm" onclick="copyCommand('sentinel verify evidence')">Copy</button></td>
              </tr>
              <tr>
                <td><code>sentinel audit-pack</code></td>
                <td><code>evidence/&lt;date&gt;</code></td>
                <td>Generate printable HTML executive report &amp; signed ZIP archive</td>
                <td><button class="btn btn-secondary btn-sm" onclick="copyCommand('sentinel audit-pack evidence')">Copy</button></td>
              </tr>
              <tr>
                <td><code>sentinel validate</code></td>
                <td><code>--provider aws|gcp|azure|mock</code></td>
                <td>Validate cloud credentials and configuration integrity</td>
                <td><button class="btn btn-secondary btn-sm" onclick="copyCommand('sentinel validate --provider mock')">Copy</button></td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Section: Interactive Launcher -->
        <div style="margin-top: 24px; padding: 16px; background: rgba(59, 130, 246, 0.05); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: var(--radius-md);">
          <div style="font-weight: 700; color: var(--accent-primary); margin-bottom: 6px;">💡 Windows Interactive Launcher &amp; Written Manual</div>
          <p style="font-size: 13px; color: var(--text-muted); line-height: 1.5;">
            Double-clicking <code>bin\\sentinel.exe</code> on Windows directly opens the interactive console launcher with zero command-line input required. The complete written documentation is also available in <code>DIRECTIONS.md</code> in the project root.
          </p>
        </div>
      </div>
    </div>

  </div>

  <div class="toast-container" id="toast-container"></div>

  <script>
    let currentScorecard = null;
    let currentDriftReport = null;
    let currentDiagnostics = null;
    let selectedEvidenceDate = null;

    function copyCommand(text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          showToast('Copied: ' + text, 'success');
        }).catch(() => {
          prompt('Press Ctrl+C to copy command:', text);
        });
      } else {
        prompt('Press Ctrl+C to copy command:', text);
      }
    }

    function showToast(message, type = 'info') {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.textContent = message;
      if (type === 'error') toast.style.borderLeftColor = 'var(--status-danger)';
      if (type === 'success') toast.style.borderLeftColor = 'var(--status-success)';
      container.appendChild(toast);
      setTimeout(() => toast.remove(), 4000);
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
      const targetTab = document.getElementById('tab-' + tabId);
      const targetBtn = document.getElementById('nav-btn-' + tabId);
      if (targetTab) targetTab.classList.add('active');
      if (targetBtn) targetBtn.classList.add('active');
    }

    async function fetchJSON(url, options = {}) {
      try {
        const resp = await fetch(url, options);
        if (!resp.ok) {
          const errText = await resp.text();
          throw new Error(errText || resp.statusText);
        }
        return await resp.json();
      } catch (err) {
        console.error('API Error:', url, err);
        throw err;
      }
    }

    async function loadScorecard() {
      try {
        const data = await fetchJSON('/api/scorecard');
        currentScorecard = data;
        renderScorecard(data);
      } catch (err) {
        console.warn('Scorecard not ready yet:', err);
      }
    }

    function renderScorecard(data) {
      if (!data) return;
      // Hero Gauge
      const score = data.overall_posture_score || 0;
      document.getElementById('hero-gauge-val').textContent = Math.round(score) + '%';
      const circle = document.getElementById('hero-gauge-circle');
      const maxOffset = 471;
      const offset = maxOffset - (maxOffset * (score / 100));
      circle.style.strokeDashoffset = offset;
      if (score >= 85) circle.style.stroke = 'var(--status-success)';
      else if (score >= 70) circle.style.stroke = 'var(--status-warning)';
      else circle.style.stroke = 'var(--status-danger)';

      // Provider
      const provName = (data.provider || 'MOCK').toUpperCase();
      document.getElementById('active-provider-name').textContent = 'Provider: ' + provName;

      // Frameworks Grid
      const fwContainer = document.getElementById('frameworks-container');
      fwContainer.innerHTML = '';
      const fws = [data.soc2, data.nist, data.cmmc, data.zero_trust];
      fws.forEach(fw => {
        if (!fw) return;
        let readinessClass = 'readiness-partial';
        if (fw.overall_score >= 85) readinessClass = 'readiness-audit';
        else if (fw.overall_score < 70) readinessClass = 'readiness-gap';

        let barsHtml = '';
        for (const [pname, pscore] of Object.entries(fw.pillar_scores || {})) {
          barsHtml += `
            <div class="bar-row">
              <span class="bar-label" title="${pname}">${pname}</span>
              <div class="bar-track"><div class="bar-fill" style="width: ${pscore}%"></div></div>
              <span class="bar-val">${Math.round(pscore)}%</span>
            </div>
          `;
        }

        const card = document.createElement('div');
        card.className = 'fw-card';
        card.innerHTML = `
          <div>
            <div class="fw-head">
              <span class="fw-title">${fw.framework_name}</span>
              <span class="fw-score">${fw.overall_score.toFixed(1)}%</span>
            </div>
            <span class="fw-readiness ${readinessClass}">${fw.readiness_level}</span>
            <div class="fw-bars">${barsHtml}</div>
          </div>
          <div style="margin-top: 16px; font-size: 11px; color: var(--text-dim); display: flex; gap: 8px;">
            <span>Pass: <strong>${fw.controls_passed}</strong></span>
            <span>Partial: <strong>${fw.controls_partial}</strong></span>
            <span>Gaps: <strong>${fw.controls_failed}</strong></span>
          </div>
        `;
        fwContainer.appendChild(card);
      });

      renderControlsTable(data.controls || []);
    }

    function renderControlsTable(controls) {
      const tbody = document.getElementById('controls-table-body');
      tbody.innerHTML = '';
      if (!controls || controls.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No control evidence collected yet. Run a collection cycle.</td></tr>';
        return;
      }

      const filter = document.getElementById('control-filter').value;
      const filtered = controls.filter(c => {
        if (filter === 'ALL') return true;
        return c.status === filter;
      });

      filtered.forEach(c => {
        let badgeClass = 'badge-pass';
        if (c.status === 'PARTIAL') badgeClass = 'badge-partial';
        if (c.status === 'FAIL') badgeClass = 'badge-fail';
        if (c.status === 'NOT_ASSESSED') badgeClass = 'badge-neutral';

        let metricsHtml = Object.entries(c.metrics_summary || {})
          .map(([k, v]) => `<span style="font-size: 11px; background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px;"><strong>${k}:</strong> ${v}</span>`)
          .join(' ');

        let findingsHtml = (c.findings || []).map(f => `<li>${f}</li>`).join('');
        if (!findingsHtml) findingsHtml = '<span style="color: var(--text-dim);">No deficiencies</span>';
        else findingsHtml = `<ul style="list-style-type: square; padding-left: 14px; font-size: 12px; color: var(--text-muted);">${findingsHtml}</ul>`;

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><span style="font-family: monospace; font-weight: 700; color: var(--accent-primary);">${c.control_id}</span></td>
          <td>
            <strong>${c.name}</strong>
            <div style="font-size: 11px; color: var(--text-dim); margin-top: 2px;">${c.category}</div>
          </td>
          <td><span class="badge ${badgeClass}">${c.status}</span></td>
          <td><strong>${Math.round(c.score)}%</strong></td>
          <td><span style="text-transform: capitalize; font-size: 12px;">${c.evidence_quality}</span></td>
          <td><div style="display: flex; flex-wrap: wrap; gap: 4px;">${metricsHtml}</div></td>
          <td>${findingsHtml}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    function filterControls() {
      if (currentScorecard && currentScorecard.controls) {
        renderControlsTable(currentScorecard.controls);
      }
    }

    async function loadDrift() {
      try {
        const data = await fetchJSON('/api/drift');
        currentDriftReport = data;
        const badge = document.getElementById('drift-status-badge');
        const tbody = document.getElementById('drift-table-body');
        tbody.innerHTML = '';

        if (!data || !data.drift_detected) {
          badge.textContent = 'No Drift Detected';
          badge.className = 'badge badge-pass';
          tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No configuration drift or policy regressions detected against baseline.</td></tr>';
          return;
        }

        badge.textContent = `${data.total_drift_items} Drift Items Detected`;
        badge.className = 'badge badge-fail';

        data.items.forEach(item => {
          let sevClass = 'badge-fail';
          if (item.severity === 'MEDIUM') sevClass = 'badge-partial';
          if (item.severity === 'LOW') sevClass = 'badge-neutral';

          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td><span class="badge ${sevClass}">${item.severity}</span></td>
            <td><code>${item.collector}</code></td>
            <td><strong>${item.control_id}</strong></td>
            <td><code>${item.field_name}</code></td>
            <td><span style="color: var(--text-muted);">${item.baseline_value}</span></td>
            <td><strong style="color: #fff;">${item.current_value}</strong></td>
            <td style="font-size: 12px;">${item.description}</td>
          `;
          tbody.appendChild(tr);
        });
      } catch (err) {
        console.warn('Drift report error:', err);
      }
    }

    async function loadOnboarding() {
      try {
        const data = await fetchJSON('/api/credentials');
        currentDiagnostics = data;
        const container = document.getElementById('onboarding-cards-container');
        container.innerHTML = '';

        for (const [pname, diag] of Object.entries(data)) {
          let statusBadge = `<span class="badge badge-pass">READY</span>`;
          if (diag.status === 'CREDENTIALS_MISSING') statusBadge = `<span class="badge badge-fail">CREDENTIALS MISSING</span>`;
          if (diag.status === 'PERMISSION_DENIED') statusBadge = `<span class="badge badge-partial">INSUFFICIENT PERMISSIONS</span>`;

          let passedItems = (diag.checks_passed || []).map(c => `<li class="check-item"><span class="check-pass">&#10003;</span> ${c}</li>`).join('');
          let failedItems = (diag.checks_failed || []).map(c => `<li class="check-item"><span class="check-fail">&#10007;</span> ${c}</li>`).join('');

          let snippetHtml = '';
          if (diag.policy_snippet) {
            const rawStr = typeof diag.policy_snippet === 'string' ? diag.policy_snippet : JSON.stringify(diag.policy_snippet, null, 2);
            snippetHtml = `
              <div style="margin-top: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                  <span style="font-size: 11px; font-weight: 600; color: var(--text-dim);">Minimal IAM Policy Fix:</span>
                  <button class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 10px;" onclick="copyToClipboard('${btoa(rawStr)}')">Copy JSON</button>
                </div>
                <pre class="policy-box">${rawStr}</pre>
              </div>
            `;
          }

          const card = document.createElement('div');
          card.className = 'cloud-card';
          card.innerHTML = `
            <div class="cloud-card-header">
              <span class="cloud-name">${diag.provider}</span>
              ${statusBadge}
            </div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">
              <strong>Identity:</strong> ${diag.identity || 'Not connected'}<br>
              <strong>Account / Scope:</strong> ${diag.account_or_project || 'None'}
            </div>
            <ul class="check-list">
              ${passedItems}
              ${failedItems}
            </ul>
            ${snippetHtml}
          `;
          container.appendChild(card);
        }
      } catch (err) {
        console.warn('Diagnostics error:', err);
      }
    }

    async function loadEvidenceList() {
      try {
        const dates = await fetchJSON('/api/evidence');
        const container = document.getElementById('evidence-dates-list');
        container.innerHTML = '';
        if (!dates || dates.length === 0) {
          container.innerHTML = '<span style="font-size: 12px; color: var(--text-muted);">No evidence directories found</span>';
          return;
        }

        dates.forEach((d, idx) => {
          const btn = document.createElement('button');
          btn.className = 'btn btn-secondary btn-sm';
          btn.style.justifyContent = 'flex-start';
          btn.textContent = d;
          btn.onclick = () => selectEvidenceDate(d);
          container.appendChild(btn);
          if (idx === 0 && !selectedEvidenceDate) selectEvidenceDate(d);
        });
      } catch (err) {
        console.warn('Evidence list error:', err);
      }
    }

    async function selectEvidenceDate(dateStr) {
      selectedEvidenceDate = dateStr;
      document.getElementById('evidence-viewer-title').textContent = 'Evidence Inspection: ' + dateStr;
      document.getElementById('evidence-viewer-subtitle').textContent = 'Loading manifest and collectors...';
      const viewer = document.getElementById('evidence-payload-viewer');
      viewer.textContent = 'Loading evidence payloads for ' + dateStr + '...';

      try {
        const manifest = await fetchJSON(`/api/evidence/${dateStr}/manifest.json`);
        viewer.textContent = JSON.stringify(manifest, null, 2);
        document.getElementById('evidence-viewer-subtitle').textContent = 'Loaded manifest.json with ' + Object.keys(manifest.files || {}).length + ' artifacts';
      } catch (err) {
        viewer.textContent = 'Manifest not found or encrypted: ' + err.message;
      }
    }

    async function verifyCurrentManifest() {
      if (!selectedEvidenceDate) {
        showToast('Please select an evidence date first', 'error');
        return;
      }
      try {
        const res = await fetchJSON('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ date: selectedEvidenceDate })
        });
        if (res.valid) {
          showToast(`Cryptographic Verification PASSED for ${selectedEvidenceDate}! All SHA-256 hashes match.`, 'success');
        } else {
          showToast(`Integrity Warning: ${res.errors.join('; ')}`, 'error');
        }
      } catch (err) {
        showToast('Verification failed: ' + err.message, 'error');
      }
    }

    function logToConsole(text) {
      const con = document.getElementById('scanner-console');
      con.innerHTML = con.innerHTML.replace('<span class="console-cursor"></span>', '');
      con.innerHTML += text + '\\n<span class="console-cursor"></span>';
      con.scrollTop = con.scrollHeight;
    }

    function clearConsole() {
      document.getElementById('scanner-console').innerHTML = '[CONSOLE CLEARED]<span class="console-cursor"></span>';
    }

    async function triggerScan() {
      const provider = document.getElementById('scan-provider-select').value;
      const collector = document.getElementById('scan-collector-select').value;
      const key = document.getElementById('scan-encryption-key').value;
      const btn = document.getElementById('btn-trigger-scan');

      btn.disabled = true;
      btn.textContent = 'Scanning...';
      logToConsole(`\\n[START] Triggering collection: provider=${provider}, collector=${collector}...`);

      try {
        const res = await fetchJSON('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider, collector, encryption_key: key || null })
        });

        if (res.status === 'ok') {
          logToConsole(`[SUCCESS] Collection finished for date: ${res.date}`);
          (res.results || []).forEach(r => {
            logToConsole(`  -> ${r.collector} [${r.control_id}]: quality=${r.quality}`);
          });
          showToast('Collection completed successfully', 'success');
          await refreshAllData();
        } else {
          logToConsole(`[FAIL] Error during scan: ${res.error}`);
          showToast('Scan failed: ' + res.error, 'error');
        }
      } catch (err) {
        logToConsole(`[ERROR] Request failed: ${err.message}`);
        showToast('Scan error: ' + err.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Execute Collection';
      }
    }

    async function exportAuditPack() {
      const btn = document.getElementById('btn-export-pack');
      btn.disabled = true;
      btn.textContent = 'Generating Package...';
      const box = document.getElementById('export-result-box');

      try {
        const res = await fetchJSON('/api/export', { method: 'POST' });
        if (res.status === 'ok') {
          box.style.display = 'block';
          box.innerHTML = `
            <div class="toast" style="border-left-color: var(--status-success); width: 100%;">
              <div>
                <strong>Audit Pack Successfully Generated!</strong><br>
                <span>Archive: ${res.filename} (${(res.size_bytes / 1024).toFixed(1)} KB)</span><br>
                <a href="${res.download_url}" class="btn btn-primary btn-sm" style="margin-top: 8px;">Download ZIP Package</a>
              </div>
            </div>
          `;
          showToast('Audit Pack Generated', 'success');
        } else {
          showToast('Export error: ' + res.error, 'error');
        }
      } catch (err) {
        showToast('Export request failed: ' + err.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Generate & Download Audit Pack ZIP';
      }
    }

    function viewExecutiveReport() {
      window.open('/api/report/latest', '_blank');
    }

    function copyToClipboard(b64) {
      const text = atob(b64);
      navigator.clipboard.writeText(text).then(() => {
        showToast('Minimal IAM policy copied to clipboard', 'success');
      });
    }

    async function refreshAllData() {
      await Promise.all([
        loadScorecard(),
        loadDrift(),
        loadOnboarding(),
        loadEvidenceList()
      ]);
    }

    // Auto-initialize on load
    window.addEventListener('DOMContentLoaded', () => {
      refreshAllData();
      setInterval(() => {
        loadScorecard();
        loadDrift();
      }, 30000);
    });
  </script>
</body>
</html>
"""
