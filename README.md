# Zero-Day Sentinel (Local Lab)

A defensive vulnerability-intelligence monitor for a personal lab. Collects CISA KEV, recently modified NVD CVE records, and optional trusted RSS/Atom advisories; stores findings in SQLite; applies a transparent triage score; exports JSON reports; and emails new high-priority or possible zero-day leads.

**It does not fetch exploit payloads, execute proof-of-concept code, scan third-party systems, or access private dark-web services.** Dark-web findings can be added later through an authorized threat-intelligence feed or analyst-reviewed import, but claims are treated as unverified until corroborated.

## Requirements
- Python 3.10+
- Internet access to the configured HTTPS sources
- SMTP mailbox for email alerts (optional)

No third-party Python packages are required.

## Quick start — Windows PowerShell
1. Install Python 3.10+ from python.org and enable the Python PATH option.
2. Extract this folder somewhere you own, e.g. `C:\SecurityLab\zero_day_sentinel`.
3. Copy `.env.example` to `.env` and edit the SMTP values. Do not share `.env` or commit it to source control.
4. Set environment variables for the current PowerShell session (simple approach):

```powershell
$env:SMTP_HOST = "smtp.your-provider.example"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "your-alert-mailbox@example.com"
$env:SMTP_PASSWORD = "YOUR_APP_PASSWORD"
$env:ALERT_FROM = "your-alert-mailbox@example.com"
$env:ALERT_TO = "your-personal-mailbox@example.com"
python .\agent.py test-email
python .\agent.py once --days 3
python .\agent.py top --limit 20
```

The script intentionally does not automatically parse `.env`; set variables in your shell or use a trusted secret manager. This avoids accidentally loading secrets from an unexpected working directory.

## Quick start — Linux
```bash
cd zero_day_sentinel
export SMTP_HOST='smtp.your-provider.example'
export SMTP_PORT='587'
export SMTP_USER='your-alert-mailbox@example.com'
export SMTP_PASSWORD='YOUR_APP_PASSWORD'
export ALERT_FROM='your-alert-mailbox@example.com'
export ALERT_TO='your-personal-mailbox@example.com'
python3 agent.py test-email
python3 agent.py once --days 3
python3 agent.py top --limit 20
```

Use an app password or dedicated service mailbox when supported. Keep credentials out of scripts, terminal history, logs, and version control. For production, use OS-level secret storage and a dedicated restricted account.

## Optional RSS/Atom sources
Set `ZDS_RSS_FEEDS` to a comma-separated list of **HTTPS** RSS/Atom URLs from vendors, national CERTs, or security research teams you trust. Example format (replace with actual approved feeds):

```text
ZDS_RSS_FEEDS=https://vendor.example/security/rss.xml,https://cert.example/advisories/feed.xml
```

The collector reads titles, descriptions, publication dates, and links only. It does not follow linked exploit files or download attachments. Feed items are treated as low-confidence leads unless independently corroborated.

## Schedule it
Run `python agent.py once` manually first. For a local lab, use Windows Task Scheduler or cron to run every 2–4 hours. A simple Windows task action is:

- Program: full path to `python.exe`
- Arguments: `C:\SecurityLab\zero_day_sentinel\agent.py once --days 3`
- Start in: `C:\SecurityLab\zero_day_sentinel`

Use a dedicated non-admin account and set its environment variables securely. Avoid overlapping runs; SQLite helps with data integrity, but scheduling one instance at a time is preferred.

## Scoring (0–100)
- CVSS: up to 35 points, scaled from the base score
- Listed in CISA KEV: +40
- Text indicates possible zero-day / active exploitation: +20
- Exploit-related claim language: +10
- High-impact terms (e.g. RCE, authentication bypass): +5
- Maximum 100

Severity: Critical ≥80; High ≥60; Medium ≥35; Low ≥15; otherwise Informational.

This is a **triage heuristic, not a probability of compromise or a formal CVSS score**. The confidence label is separate: CISA KEV entries are high confidence for known exploitation; NVD records medium; generic RSS claims low pending verification. Some source records may be duplicated under separate source IDs.

## Operational notes and limitations
- CISA KEV is a curated list of vulnerabilities known to have been exploited in the wild; presence does not mean your systems are affected.
- NVD returns recently modified records, not a guaranteed list of all new zero-days. API limits and availability can vary.
- RSS keyword matches are only leads. Validate affected versions and claims against vendor advisories and independent sources.
- No alert is proof of an unpatched zero-day. Verify product, version, exposure, vendor mitigation, and asset inventory.
- Email is sent only for newly seen high-scoring findings, zero-day-language leads, or KEV entries. Existing findings are not re-emailed every run.
- Data and reports are stored in `data/`. Protect that directory if it contains internal notes or asset information.

## Safe response checklist
1. Validate the source and affected product/version.
2. Compare against your asset inventory and internet exposure.
3. Check vendor guidance and available patches/workarounds.
4. Apply approved mitigation, test, and document change control.
5. Add available vendor detection guidance and monitor relevant logs.
6. Record evidence, confidence, owner, and next review time.

## Data files
- `data/sentinel.sqlite3`: findings database
- `data/reports/report-*.json`: per-run reports

## Troubleshooting
- NVD/CISA timeouts: rerun later; source errors are logged and other sources continue.
- No email: configure all six `SMTP_*` / `ALERT_*` variables and run `python agent.py test-email`.
- Too many feed alerts: use fewer trusted feeds and refine feed selection; don't treat keywords as confirmed exploit evidence.
