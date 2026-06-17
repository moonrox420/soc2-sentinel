# Carrd Landing Page Copy — SOC2 Sentinel Toolkit v2.3

---

## Hero

### Headline
**Compliance evidence that runs from your terminal.**

### Subheadline
SOC2 Sentinel v2.3 automates IAM reviews, logging checks, encryption scans, resilience validation, and Zero Trust verification—for defense contractors and regulated SaaS—with 110 CMMC practices, DFARS 72-hour IR docs, ATT&CK hunts, and the policies auditors ask for.

### CTA buttons
- **Get the Toolkit** → [Gumroad / checkout URL]
- **See what's inside** → `#contents`

### Trust line (small text)
Python 3.10+ · AWS / GCP / Azure · MIT License · Not legal advice · Not a certification guarantee

---

## Problem section

### Heading
Your auditor wants proof. Your C3PAO wants 110 practices. Your prime wants DFARS readiness.

### Body
Spreadsheet-driven compliance breaks the moment someone asks for *current* IAM exports, CMMC Met/Not Met status across 110 controls, or a documented 72-hour incident workflow.

SOC2 Sentinel replaces the monthly fire drill with:

```bash
pip install -e .
sentinel run-all --provider aws
sentinel report --input data/cmmc-l2-controls-110.csv --mode cmmc
```

Structured JSON lands in `evidence/`. Your policies reference the same collectors. Your Notion workspace tracks CMMC X/110, incidents, vendors, and ZT maturity.

---

## Features grid

### ⚡ Automated collectors (7)
| Collector | What it checks |
|-----------|----------------|
| `iam_access_review` | Orphaned accounts, privileged users |
| `log_aggregator` | CloudTrail / logging coverage |
| `config_drift` | MFA gaps, weak TLS listeners |
| `encryption_status` | Unencrypted stores, key rotation |
| `retention_check` | Lifecycle policy compliance |
| `resilience_testing` | Backup/resilience signals |
| `zt_continuous_verification` | Zero Trust cross-pillar check |

### 📋 Policy library (17)
Core policies plus **incident response**, **micro-segmentation**, **continuous verification**, and **supply chain risk**—with evidence hooks, not generic filler.

### 🎯 CMMC, DFARS, ATT&CK, Zero Trust
- **110 CMMC L2 practices** — CSV + `sentinel report --mode cmmc`
- **DFARS 7012** — classification, 7-step 72h workflow, DIBNet template, tabletop record
- **MITRE ATT&CK** — technique mapping + threat hunting playbook
- **Zero Trust** — seven pillars + `sentinel report --mode zt`
- **800-171 / 800-172** crosswalks + C3PAO 30/60/90 prep

### 🗂️ Notion workflow (7 databases)
Controls, CMMC L2, Evidence Log, POA&M, Incident Tracker, Pre-Assessment Gates, Vendor Assessment — plus ATT&CK and ZT views.

---

## Who it's for

**Built for:**
- Defense contractors approaching CMMC Level 2 (and planning L3)
- B2B SaaS vendors with SOC 2 and security questionnaire pressure
- Platform teams without a six-figure GRC budget

**Not built for:**
- Enterprises needing full GRC workflow automation
- Anyone seeking guaranteed certification in a box

---

## How it works

1. **Install** — `pip install -e .`
2. **Test** — `sentinel run-all --provider mock`
3. **Connect** — AWS IAM read-only policy included; GCP/Azure guides included
4. **Collect** — Monthly evidence to `evidence/YYYY-MM-DD/`
5. **Report** — CMMC X/110 and ZT maturity from CSV inputs
6. **Operate** — Annual DFARS tabletop; vendor questionnaires; threat hunts

---

## What's in the box

- Python package (`soc2-sentinel` v2.3.0)
- 7 cloud evidence collectors + schema validation
- 17 policy templates
- 20+ documentation guides + 4 operational templates
- 110-practice CMMC CSV + ATT&CK + ZT data files
- 6 Notion import packs
- MIT license — internal use, no seat fees

[Full inventory → link to whats-inside.md or expand section]

---

## Honest section

### Heading
We tell you what this doesn't do.

- ❌ Does not file DFARS / DIBNet reports
- ❌ Does not replace your C3PAO
- ❌ Does not provide legal advice
- ❌ Does not guarantee SOC 2 or CMMC certification
- ❌ Does not ship with 110/110 CMMC practices pre-implemented (seed shows 22 automated Met—you do the work)
- ❌ Does not include fictional customer case studies

It **does** give your team a credible, repeatable evidence pipeline—the same kind regulated customers expect before they trust you with CUI.

---

## Social proof placeholder

> "We went from manual IAM spreadsheets to automated monthly exports in a weekend."
> — *Use real customer quotes when available. Do not fabricate testimonials.*

---

## Pricing

### Single team license
**$[PRICE]** — unlimited internal users, MIT license, lifetime updates for v2.x

Includes full toolkit, docs, policies, and templates.

### Optional
Consulting / setup calls sold separately if offered.

---

## FAQ

**Does this work without AWS?**  
Yes. `--provider mock` demos the full pipeline. GCP and Azure supported with documented setup.

**Is this enough for CMMC certification?**  
It's preparation tooling. CMMC L2 certification requires assessment by an authorized C3PAO. The toolkit tracks 110 practices and automates evidence for a subset.

**What about DFARS 7012?**  
You get IR policy, expanded procedure, DIBNet field template, and tabletop record. Legal and your FSO submit actual reports.

**Can I customize policies?**  
Yes. All policies are markdown templates with `[ORGANIZATION_NAME]` placeholders.

**Do you store my cloud data?**  
No. Everything runs locally. Evidence stays in your `evidence/` directory.

---

## Footer CTA

### Heading
Run your first collection in 10 minutes.

### Button
**Get SOC2 Sentinel v2.3** → [checkout URL]

### Fine print
Templates and automation for compliance readiness only. Consult qualified professionals for legal and certification decisions.