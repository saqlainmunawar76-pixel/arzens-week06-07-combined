# IOC Manager — Lifecycle Management & Automation

Stores enriched IOCs from `ti_enricher.py` (Task 2) in a JSON database, tracks
their lifecycle (add → update → expire), computes a rule-based confidence
score, exports SIEM-ready blocklists, and generates HTML analyst reports.

## Setup

```bash
pip install pyyaml
```

## Commands

```bash
# Import new/updated IOCs from a ti_enricher output file (JSON or CSV)
python ioc_manager.py --add-file enrichment_results.csv

# Re-enrich / refresh metadata for every tracked IOC
python ioc_manager.py --update-all

# Remove IOCs past their verdict-based expiry
python ioc_manager.py --expire-check

# Export a SIEM/firewall-ready blocklist
python ioc_manager.py --export-blocklist

# Generate a styled HTML analyst report
python ioc_manager.py --generate-report

# Bonus: database health/status summary
python ioc_manager.py --health-check

# Bonus: check for un-alerted high-severity IOCs
python ioc_manager.py --alert-check
```

Commands can be combined in one call, e.g.:
```bash
python ioc_manager.py --update-all --expire-check --export-blocklist --generate-report
```

## Lifecycle design

- **first_seen / last_seen** — set on add, `last_seen` refreshed on every
  update or `--update-all` pass.
- **expires_at** — computed from `ioc_config.yaml`'s `expiration_days`,
  keyed by verdict (MALICIOUS IOCs are kept 90 days for retrospective
  hunting; CLEAN entries age out in 3 days to keep the DB lean).
- **history[]** — every prior score is appended before an update, which
  feeds the confidence calculation (see below) and lets an analyst see how
  an indicator's risk has trended.

## Confidence scoring (rule-based)

`confidence = 0.4 × source_diversity + 0.35 × score_stability + 0.25 × recency`, ×100

- **Source diversity** — fraction of the 3 TI sources (VirusTotal, AbuseIPDB,
  OTX) that returned a signal on the latest enrichment. An IOC only VT flagged
  is less trusted than one flagged by all three.
- **Score stability** — low variance across an IOC's historical scores means
  the verdict is consistent, not a one-off spike; computed with
  `statistics.pvariance`.
- **Recency** — exponential decay (`0.5^(days_since_last_seen / 14)`), so an
  IOC not re-confirmed in weeks loses confidence even if its last known score
  was high.

## Automation (bonus feature)

`ioc_config.yaml` documents recommended cron schedules
(`automation.update_all_cron`, etc.) for wiring this into a scheduler:

```cron
0 3 * * *   cd /opt/ti-platform && python3 ioc_manager.py --update-all
30 3 * * *  cd /opt/ti-platform && python3 ioc_manager.py --expire-check --export-blocklist --generate-report
0 * * * *   cd /opt/ti-platform && python3 ioc_manager.py --health-check >> health.log
```

## Alerting (bonus feature)

`--alert-check` scans for un-alerted IOCs matching `alerting.alert_on_verdicts`
(default: MALICIOUS). It's a safe stub: with `alerting.enabled: false` (the
default) it only logs what *would* fire, so running it never makes an
unexpected outbound network call. Flip `enabled: true` and fill in
`webhook_url` to wire it to Slack/Teams/PagerDuty in production.

## Files

| File | Purpose |
|---|---|
| `ioc_manager.py` | Main lifecycle manager |
| `ioc_config.yaml` | Expiration policy, confidence weights, blocklist/alerting config |
| `ioc_database.json` | Sample populated database (from a test run against Task 2's sample output) |
| `blocklist.txt` | Sample SIEM/firewall blocklist export |
| `weekly_report.html` | Sample styled analyst report |
| `sample_enrichment_input.csv` | The Task 2 output used to populate the sample database (for reproducing the demo) |
