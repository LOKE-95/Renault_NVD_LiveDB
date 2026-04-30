# Automotive Cybersecurity Dashboard

A single-page dashboard correlating **NVD CVE** data with vehicle **ECU / software components** for **Renault**, **Mahindra**, and **Maruti Suzuki**, mapped against **ISO/SAE 21434**, **UN R155 / R156**, and **AIS-189** compliance clauses.

Built as a static site, deployable for free to **GitHub Pages**. NVD data is refreshed automatically by a scheduled **GitHub Action** using your NVD API key (stored as a repo secret — never embedded in the page).

---

## Features

- OEM filter (All / Renault / Mahindra / Maruti Suzuki)
- KPI cards: total CVEs, Critical, High, average CVSS
- Charts: severity distribution, CVEs over time, top affected components
- Searchable / filterable CVE table with direct links to NVD
- ECU & component-level breakdown (infotainment, telematics, gateway, BCM, ADAS, powertrain, etc.)
- Compliance matrix tab covering:
  - **ISO/SAE 21434** clauses 8 – 15 (incl. TARA)
  - **UN R155** CSMS + Annex 5 threat catalogue
  - **UN R156** SUMS / RxSWIN
  - **AIS-189** (India CSMS / SUMS adoption)

---

## Repository structure

```
automotive-cyber-dashboard/
├── index.html
├── assets/
│   ├── css/styles.css
│   └── js/
│       ├── dashboard.js
│       └── compliance.js
├── data/
│   ├── cves.json              # refreshed by GitHub Action
│   ├── ecu_components.json    # OEM -> supplier / ECU / keyword map (editable)
│   ├── compliance_map.json    # category -> standard clause map (editable)
│   └── health.json            # API key + fetch status (drives the dashboard pill)
├── scripts/
│   ├── check_key.py           # validates NVD_API_KEY, writes health.json
│   └── fetch_nvd.py
├── .github/workflows/
│   └── refresh-data.yml       # daily cron, uses NVD_API_KEY secret
├── requirements.txt
├── .gitignore
└── README.md
```

---

## One-time setup

### 1. Create the GitHub repo

```bash
cd automotive-cyber-dashboard
git init
git add .
git commit -m "Initial commit: automotive cyber dashboard"
git branch -M main
git remote add origin https://github.com/<your-username>/automotive-cyber-dashboard.git
git push -u origin main
```

### 2. Add your NVD API key as a repository secret

> **Important: never paste your API key into any file in this repo.** It only goes here:

1. Go to your repo on GitHub → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**
2. Name: `NVD_API_KEY`
3. Value: *(paste your NVD API key)*
4. Save

### 3. Allow the Action to write back to the repo

Settings → **Actions** → **General** → **Workflow permissions** → select **Read and write permissions** → Save.

### 4. Enable GitHub Pages

Settings → **Pages** → **Source: Deploy from a branch** → Branch: `main` / `/ (root)` → Save.

After ~1 minute your dashboard is live at:

```
https://<your-username>.github.io/automotive-cyber-dashboard/
```

### 5. Trigger the first data refresh

- Go to **Actions** → **Refresh NVD data** → **Run workflow**.
- The Action **first validates your API key** (`scripts/check_key.py`), then pulls CVEs (`scripts/fetch_nvd.py`), and commits `data/cves.json` and `data/health.json` to `main`. The dashboard picks up new data on next page load.
- Subsequent runs happen automatically every day at 03:00 UTC.

### Health pill on the dashboard

The top-right of the dashboard shows a status pill driven by `data/health.json`:

| Pill colour | Meaning |
| --- | --- |
| Green &mdash; **API key OK** | Last validation passed and data refreshed within the last 2 days. |
| Yellow &mdash; **Data stale** / **Fetch skipped** | Key worked but data hasn't refreshed recently, or fetch was skipped. |
| Red &mdash; **API key invalid / missing** or **Last fetch failed** | The Action couldn't authenticate or the fetch step errored. |
| Grey &mdash; **Health-check pending** | The validation workflow hasn't run yet (true on first deploy). |

Click the pill for a popover with the exact NVD HTTP response, rate-limit ceiling, last-run timestamp, and fetch outcome.

If the pill is red:
1. Open the **Actions** tab → most recent run → **Validate NVD API key** step. The log shows the exact reason.
2. If you registered for an NVD key but never clicked the activation email, the key is technically valid but rate-limited to 5/30s &mdash; activate it and re-run the workflow.

---

## Customizing OEM / ECU keywords

Edit `data/ecu_components.json`. Each OEM has:
- `keywords`: free-text terms searched against NVD (OEM name, supplier names, common platforms).
- `ecu_classes`: ECU groupings with their typical software components.

Example:

```json
{
  "renault": {
    "display_name": "Renault",
    "keywords": ["renault", "alliance ventures", "easy link", "openr link"],
    "ecu_classes": { ... }
  }
}
```

You can add new OEMs, suppliers, or platforms here without touching any code.

## Customizing the compliance map

Edit `data/compliance_map.json` to refine which categories of vulnerabilities map to which clauses of ISO 21434, UN R155, UN R156, and AIS-189. Each category has a `match` block (keywords / CWE IDs) and a `clauses` block listing the standards it touches.

---

## Local preview (optional)

The dashboard is a static site, so any static server works:

```bash
cd automotive-cyber-dashboard
python -m http.server 8080
# open http://localhost:8080
```

To regenerate `data/cves.json` locally without GitHub Actions:

```bash
pip install -r requirements.txt
export NVD_API_KEY="your-key-here"   # PowerShell: $env:NVD_API_KEY="your-key-here"
python scripts/fetch_nvd.py
```

---

## Notes / disclaimers

- NVD does not categorise CVEs by automotive OEM. Mapping is best-effort, based on keyword matches against suppliers, platforms, and software stacks. Treat results as **indicative**, not exhaustive — refine `ecu_components.json` over time.
- The compliance map is an interpretive aid, not a substitute for a TARA, audit, or formal type-approval evidence package.
- ISO/SAE 21434, UN R155, UN R156, and AIS-189 are referenced by name only; consult the official documents for normative text.
