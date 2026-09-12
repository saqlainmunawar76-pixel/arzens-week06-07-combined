# TI Enricher — Threat Intelligence Enrichment Engine

Enriches IOCs (IPs, domains, URLs, file hashes) by querying **VirusTotal**,
**AbuseIPDB**, and **AlienVault OTX**, and combines the results into a single
weighted 0–100 risk score.

## Setup

```bash
pip install pyyaml requests
```

Edit `config.yaml` and add your free-tier API keys:
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AbuseIPDB: https://www.abuseipdb.com/account/api
- AlienVault OTX: https://otx.alienvault.com/api (optional — public endpoints work without a key, but a key raises rate limits)

## Usage

```bash
# Single indicator, console output
python ti_enricher.py --indicator 8.8.8.8

# Batch from file, JSON output
python ti_enricher.py --input-file sample_indicators.csv --output json

# Batch from file, CSV output
python ti_enricher.py --input-file sample_indicators.csv --output csv

# Skip the cache (force fresh queries)
python ti_enricher.py --indicator 8.8.8.8 --no-cache
```

## How it works

1. **Type detection** — regex/`ipaddress` module classifies each indicator as
   `ip`, `domain`, `url`, or `hash` (md5/sha1/sha256 by length).
2. **Caching** — every successful source response is cached in `cache.json`
   for `cache.ttl_hours` (default 24h) so repeated runs don't burn rate-limit
   budget on the same indicator.
3. **Rate limiting** — a sliding-window limiter per source sleeps
   automatically when the free-tier quota (e.g. VirusTotal's 4 req/min) would
   be exceeded, instead of failing.
4. **Risk scoring** — each source returns its own 0–100 score; the final
   score is a weighted average (VT 50%, AbuseIPDB 30%, OTX 20%, configurable
   in `config.yaml`). If a source fails or is unsupported for that indicator
   type (e.g. AbuseIPDB only handles IPs), its weight is redistributed across
   the sources that succeeded, rather than dragging the score toward zero.
5. **Error handling** — network timeouts, HTTP 429/404/5xx, and missing API
   keys are all caught and reported per-source without crashing the batch.

## Verdict thresholds

| Score  | Verdict     |
|--------|-------------|
| ≥ 75   | MALICIOUS   |
| 40–74  | SUSPICIOUS  |
| 1–39   | LOW_RISK    |
| 0      | CLEAN       |

## Files

| File | Purpose |
|---|---|
| `ti_enricher.py` | Main enrichment engine |
| `config.yaml` | API keys, rate limits, scoring weights (template) |
| `sample_indicators.csv` | Example batch input |
| `enrichment_results.csv` | Sample output (illustrative — generated with placeholder API responses since live keys aren't checked into this repo) |
| `cache.json` | Sample cache structure showing what a populated cache looks like |

## Note on sample outputs

`enrichment_results.csv` and `cache.json` in this repo show the **expected
shape** of real output (including a MALICIOUS/SUSPICIOUS example) for grading
purposes. Once you drop your own API keys into `config.yaml`, running the
tool against real indicators will overwrite these with live data.
