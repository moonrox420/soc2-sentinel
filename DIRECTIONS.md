# SOC2 Sentinel v2.5.0 — Directions & Execution Guide

See the full comprehensive guide at [DIRECTIONS.md](file:///c:/Users/droxa/soc2-sentinel/DIRECTIONS.md).

## Quick Reference Commands

### Start Web Dashboard:
```powershell
sentinel serve
# or
sentinel dashboard
```

### Instant Mock Demo:
```powershell
sentinel run-all --provider mock
sentinel scorecard
sentinel audit-pack evidence
```

### Live Tri-Cloud Collection:
```powershell
sentinel onboarding --provider aws
sentinel run-all --provider aws
sentinel scorecard
sentinel verify evidence
```
