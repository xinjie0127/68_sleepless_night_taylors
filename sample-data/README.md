# FixFlow AI

**AI-assisted cyber remediation workflow for SMEs.**

FixFlow AI takes three CSV inputs — security scanner findings, asset inventory, and business priority — and produces a complete, explainable remediation plan with dashboard, downloadable CSV, management report, owner notifications, and a validation summary.

---

## Quick start

```bash
# Option A: just open the file
open index.html          # macOS
start index.html         # Windows
xdg-open index.html      # Linux

# Option B: serve locally (recommended)
cd fixflow-ai
python -m http.server 8000
# then visit http://localhost:8000
```

Once loaded:

1. Go to **Inputs** → click **Load sample data**
2. Click **Run full remediation** (top-right button)
3. Browse all seven views

No server, no API keys, no build step. Runs entirely in the browser.

---

## The workflow

```
CSV inputs → Validate & normalize → Detect duplicates → Link assets & business priority
→ Prioritize (0–110 score) → Generate remediation tasks → Validate outputs vs inputs
→ Dashboard + CSV + Report + Notifications
```

### Step 1 — Validate & normalize
Every row is checked for required fields. Missing values are set to `UNKNOWN` — never guessed. Severity values are normalized. CVSS is parsed or defaulted from severity.

### Step 2 — Duplicate detection
Findings are matched by asset + CVE (or title if no CVE). Duplicates are merged into the original and tracked in the validation summary.

### Step 3 — Asset linking
Each finding is matched against the asset inventory by name. Linked findings inherit criticality, owner, team, data sensitivity, and exposure from the asset record.

### Step 4 — Business priority linking
Findings are matched to business functions by asset type/name keywords. Linked findings inherit revenue impact, regulatory impact, and priority tier.

### Step 5 — Prioritization
Each unique finding is scored on a 0–110 scale:

| Factor | Weight | Source |
|--------|--------|--------|
| Severity | 0–40 | CVSS or qualitative |
| Asset criticality | 0–20 | Asset inventory |
| Exposure | 0–20 | Findings (internet > internal) |
| Business impact | 0–20 | Business priority (revenue + regulatory) |
| Data sensitivity | 0–10 | Asset inventory (PCI > PII > Confidential > Internal > Public) |

Priority tiers: **P0** (90+), **P1** (70–89), **P2** (50–69), **P3** (30–49), **P4** (<30).

### Step 6 — Task generation
Each unique finding becomes a remediation task with:
- Owner (from asset inventory or business priority)
- Due date (SLA-based: P0=3d, P1=7d, P2=14d, P3=30d, P4=90d)
- Dependencies (P0 tasks may depend on P1 tasks in the same team)
- Approval requirement (P0/P1 require change board approval)
- Validation status

### Step 7 — Validation
Seven automated cross-checks verify outputs against inputs:
1. Every unique finding has a task
2. No fabricated findings in output
3. Duplicates merged and tracked
4. All task owners resolved from inputs
5. Missing information marked UNKNOWN
6. Severity not inflated beyond original input
7. Due dates are valid and future-dated

---

## Inputs

| File | Required columns |
|------|-----------------|
| `security-findings.csv` | `finding_id, title, description, severity, cvss, affected_asset, asset_type, exposure, discovered_date, source, reporter, cve_id, remediation_hint` |
| `asset-inventory.csv` | `asset_id, name, asset_type, criticality, owner, team, location, environment, data_sensitivity, internet_exposed, last_patched` |
| `business-priority.csv` | `business_function, priority, revenue_impact, regulatory_impact, downtime_tolerance, owner, notes` |

Sample files are in `sample-data/`.

---

## Views

| View | What it shows |
|------|--------------|
| **Dashboard** | KPIs, prioritized findings table with filters, charts by owner and severity |
| **Inputs** | File upload, validation issues, normalized data preview |
| **Remediation tasks** | Full task backlog with downloadable CSV |
| **Management report** | Executive narrative in markdown (copy or download) |
| **Owner notifications** | Draft messages grouped by owner (copy to clipboard) |
| **Validation summary** | 7 cross-checks with pass/warn/fail status |
| **About & README** | This documentation |

---

## Deliverables

- **Dashboard** — interactive, filterable, with KPIs and bar charts
- **Remediation CSV** — downloadable from the Tasks view
- **Management report** — markdown, downloadable from the Report view
- **Owner notifications** — copy-ready drafts per owner
- **Validation summary** — automated cross-check report

---

## Demo script

1. **Load sample data** → show 20 findings, 19 assets, 10 business functions in Inputs view
2. **Run full remediation** → dashboard populates with KPIs and charts
3. **Tasks view** → show 19 tasks (one duplicate merged), SLA dates, owners, dependencies
4. **Report view** → copy markdown for stakeholders
5. **Notifications** → show draft messages per owner
6. **Validation** → all 7 checks pass (1 duplicate merged, UNKNOWN fields tracked)
7. **Download remediation CSV** from Tasks view

---

## Important constraints

- **Synthetic data only**: all sample data is fictional. Do not use with real production data without review.
- **No external calls**: FixFlow AI never contacts real people, sends emails, or executes security changes.
- **No assumptions**: missing fields are always marked `UNKNOWN`, never guessed.
- **Self-contained**: runs entirely in the browser. No server, no API keys, no data leaves your machine.

---

## Tech stack

- Vanilla HTML/CSS/JS — no frameworks, no build step
- Single-page app with 7 views
- CSV parsing, duplicate detection, scoring engine, validation engine — all client-side
- ~600 lines of JavaScript, ~300 lines of CSS

## File structure

```
fixflow-ai/
├── index.html              # App shell with 7 views
├── styles.css              # Dark theme styling
├── app.js                  # Core logic: parsing, scoring, validation, rendering
├── README.md               # This file
└── sample-data/
    ├── security-findings.csv   # 20 synthetic findings (incl. 1 duplicate)
    ├── asset-inventory.csv     # 19 synthetic assets
    └── business-priority.csv   # 10 business functions
```
