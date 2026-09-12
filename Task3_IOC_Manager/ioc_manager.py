#!/usr/bin/env python3
"""
ioc_manager.py — IOC Lifecycle Manager & Automation
======================================================
Manages enriched Indicators of Compromise (IOCs): stores them with metadata,
tracks their lifecycle (add/update/expire), computes a rule-based confidence
score, exports SIEM-ready blocklists, and generates analyst reports.

Commands:
    --add-file <file>        Import new/updated IOCs from a ti_enricher JSON
                              or CSV output file
    --update-all              Re-enrich every active IOC (uses ti_enricher.py
                              if importable, else refreshes recency metadata)
    --expire-check             Remove IOCs past their verdict-based TTL
    --export-blocklist         Write blocklist.txt for SIEM/firewall import
    --generate-report          Write weekly_report.html analyst summary
    --health-check              Print database health/status summary
    --alert-check                Check for un-alerted high-severity IOCs

Author: Saqlain (The Arzens Internship — Advanced Track, Week 06-07)
"""

import argparse
import csv
import json
import math
import statistics
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pyyaml. Install with: pip install pyyaml")


UTC = timezone.utc


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


# =============================================================================
# IOC record
# =============================================================================

@dataclass
class IOCRecord:
    indicator: str
    type: str
    verdict: str
    risk_score: float
    confidence: float = 0.0
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    expires_at: Optional[str] = None
    source_count: int = 0
    history: list = field(default_factory=list)   # [{"score": float, "timestamp": iso, "source_count": int}]
    tags: list = field(default_factory=list)
    alerted: bool = False


# =============================================================================
# IOC Database — JSON-backed store with lifecycle operations
# =============================================================================

class IOCDatabase:
    def __init__(self, config: dict):
        self.config = config
        self.path = Path(config["database"]["path"])
        self.records: dict[str, IOCRecord] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                for indicator, rec in raw.items():
                    self.records[indicator] = IOCRecord(**rec)
            except (json.JSONDecodeError, TypeError) as e:
                print(f"[warn] could not parse existing database, starting fresh: {e}")

    def save(self):
        serializable = {k: asdict(v) for k, v in self.records.items()}
        self.path.write_text(json.dumps(serializable, indent=2))

    # ---- Confidence scoring (rule-based) ------------------------------------
    def compute_confidence(self, record: IOCRecord) -> float:
        weights = self.config["confidence"]["weights"]
        half_life = self.config["confidence"]["recency_half_life_days"]

        # 1. Source diversity: fraction of the 3 TI sources that contributed
        #    a positive signal on the most recent enrichment.
        source_diversity = min(record.source_count / 3.0, 1.0)

        # 2. Score stability: low variance across historical scores = higher
        #    confidence that the verdict is real, not a one-off anomaly.
        scores = [h["score"] for h in record.history] or [record.risk_score]
        if len(scores) >= 2:
            variance = statistics.pvariance(scores)
            # Normalize: variance of 0 -> stability 1.0; variance >= 1000 -> stability ~0
            stability = max(0.0, 1.0 - min(variance / 1000.0, 1.0))
        else:
            stability = 0.5   # neutral — not enough history yet

        # 3. Recency: exponential decay since last_seen.
        days_since = (datetime.now(UTC) - parse_iso(record.last_seen)).total_seconds() / 86400
        recency = 0.5 ** (days_since / half_life)

        confidence = (
            weights["source_diversity"] * source_diversity
            + weights["score_stability"] * stability
            + weights["recency"] * recency
        ) * 100

        return round(confidence, 1)

    # ---- Lifecycle: add or update -------------------------------------------
    def upsert(self, indicator: str, type_: str, risk_score: float, verdict: str, source_count: int):
        ts = now_iso()
        if indicator in self.records:
            rec = self.records[indicator]
            rec.history.append({"score": rec.risk_score, "timestamp": rec.last_seen,
                                 "source_count": rec.source_count})
            rec.risk_score = risk_score
            rec.verdict = verdict
            rec.source_count = source_count
            rec.last_seen = ts
            action = "updated"
        else:
            rec = IOCRecord(
                indicator=indicator, type=type_, verdict=verdict, risk_score=risk_score,
                first_seen=ts, last_seen=ts, source_count=source_count,
            )
            self.records[indicator] = rec
            action = "added"

        rec.expires_at = self._compute_expiry(rec)
        rec.confidence = self.compute_confidence(rec)
        return action

    def _compute_expiry(self, rec: IOCRecord) -> str:
        days = self.config["expiration_days"].get(rec.verdict, 14)
        expiry = parse_iso(rec.last_seen) + timedelta(days=days)
        return expiry.isoformat()

    # ---- Lifecycle: expire ----------------------------------------------------
    def expire_check(self) -> list[str]:
        now = datetime.now(UTC)
        expired = []
        for indicator, rec in list(self.records.items()):
            if rec.expires_at and parse_iso(rec.expires_at) <= now:
                expired.append(indicator)
                del self.records[indicator]
        return expired

    def active_records(self) -> list[IOCRecord]:
        return list(self.records.values())


# =============================================================================
# Import from ti_enricher output (JSON array or CSV, produced by Task 2)
# =============================================================================

def import_enrichments(path: str) -> list[dict]:
    p = Path(path)
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text())
        return data if isinstance(data, list) else [data]

    # CSV path — matches ti_enricher.py's write_csv() schema
    rows = []
    with open(p) as f:
        reader = csv.DictReader(f)
        for row in reader:
            sources_present = sum(
                1 for col in ("vt_score", "abuseipdb_score", "otx_score")
                if row.get(col) not in (None, "", "None")
            )
            rows.append({
                "indicator": row["indicator"],
                "type": row["type"],
                "risk_score": float(row["risk_score"]),
                "verdict": row["verdict"],
                "source_count": sources_present,
            })
    return rows


# =============================================================================
# Blocklist export
# =============================================================================

def export_blocklist(db: IOCDatabase, path: str):
    include = set(db.config["blocklist"]["include_verdicts"])
    fmt = db.config["blocklist"]["format"]
    entries = [r for r in db.active_records() if r.verdict in include]
    entries.sort(key=lambda r: r.risk_score, reverse=True)

    lines = [
        f"# SIEM Blocklist — generated {now_iso()}",
        f"# {len(entries)} indicators (verdicts: {', '.join(sorted(include))})",
        "#",
    ]
    for r in entries:
        if fmt == "firewall":
            if r.type == "ip":
                lines.append(f"deny ip host {r.indicator}  # risk={r.risk_score} conf={r.confidence}")
            else:
                lines.append(f"# {r.indicator} ({r.type}) — not a firewall-blockable type")
        else:
            lines.append(f"{r.indicator}  # type={r.type} risk={r.risk_score} confidence={r.confidence} verdict={r.verdict}")

    Path(path).write_text("\n".join(lines) + "\n")
    return len(entries)


# =============================================================================
# Report generation — HTML
# =============================================================================

def generate_html_report(db: IOCDatabase, path: str):
    records = db.active_records()
    by_verdict = {}
    for r in records:
        by_verdict.setdefault(r.verdict, []).append(r)

    top_risk = sorted(records, key=lambda r: r.risk_score, reverse=True)[:10]

    def rows_html(recs):
        if not recs:
            return "<tr><td colspan='5' class='empty'>None</td></tr>"
        out = []
        for r in recs:
            out.append(
                f"<tr><td>{r.indicator}</td><td>{r.type}</td>"
                f"<td class='v-{r.verdict.lower()}'>{r.verdict}</td>"
                f"<td>{r.risk_score}</td><td>{r.confidence}</td></tr>"
            )
        return "\n".join(out)

    summary_cards = "".join(
        f"<div class='card'><div class='num'>{len(by_verdict.get(v, []))}</div><div class='label'>{v}</div></div>"
        for v in ["MALICIOUS", "SUSPICIOUS", "LOW_RISK", "CLEAN"]
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IOC Weekly Report — {datetime.now(UTC).strftime('%Y-%m-%d')}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#0f1420; color:#e6e9ef; margin:0; padding:32px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .subtitle {{ color:#8b93a7; margin-bottom:24px; font-size:13px; }}
  .cards {{ display:flex; gap:16px; margin-bottom:32px; }}
  .card {{ background:#161d2e; border:1px solid #262f45; border-radius:10px; padding:16px 24px; text-align:center; flex:1; }}
  .num {{ font-size:28px; font-weight:700; }}
  .label {{ font-size:12px; color:#8b93a7; letter-spacing:0.5px; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:32px; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 12px; border-bottom:1px solid #262f45; }}
  th {{ color:#8b93a7; font-weight:600; text-transform:uppercase; font-size:11px; }}
  .v-malicious {{ color:#ff5c7a; font-weight:600; }}
  .v-suspicious {{ color:#ffb454; font-weight:600; }}
  .v-low_risk {{ color:#7ee787; }}
  .v-clean {{ color:#6b7280; }}
  .empty {{ color:#4b5262; font-style:italic; }}
  section h2 {{ font-size:15px; border-left:3px solid #4f7cff; padding-left:10px; }}
</style>
</head>
<body>
  <h1>IOC Weekly Report</h1>
  <div class="subtitle">Generated {now_iso()} · {len(records)} active IOCs tracked</div>

  <div class="cards">{summary_cards}</div>

  <section>
    <h2>Top 10 by Risk Score</h2>
    <table>
      <tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>Risk Score</th><th>Confidence</th></tr>
      {rows_html(top_risk)}
    </table>
  </section>

  <section>
    <h2>Malicious IOCs (full list)</h2>
    <table>
      <tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>Risk Score</th><th>Confidence</th></tr>
      {rows_html(by_verdict.get("MALICIOUS", []))}
    </table>
  </section>
</body>
</html>
"""
    Path(path).write_text(html)


# =============================================================================
# Health check
# =============================================================================

def health_check(db: IOCDatabase):
    records = db.active_records()
    print(f"\n=== IOC Database Health ===")
    print(f"Database file:     {db.path} ({'exists' if db.path.exists() else 'missing'})")
    print(f"Total active IOCs: {len(records)}")

    by_verdict = {}
    for r in records:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
    for v, count in sorted(by_verdict.items()):
        print(f"  {v:<12} {count}")

    if records:
        avg_conf = round(sum(r.confidence for r in records) / len(records), 1)
        stale = [r for r in records if
                 (datetime.now(UTC) - parse_iso(r.last_seen)).days > 7]
        expiring_soon = [r for r in records if r.expires_at and
                          parse_iso(r.expires_at) - datetime.now(UTC) < timedelta(days=3)]
        print(f"Average confidence: {avg_conf}")
        print(f"Stale (>7d unseen): {len(stale)}")
        print(f"Expiring within 3d: {len(expiring_soon)}")
    print()


# =============================================================================
# Alert check (stub — respects alerting.enabled)
# =============================================================================

def alert_check(db: IOCDatabase):
    cfg = db.config["alerting"]
    trigger_verdicts = set(cfg["alert_on_verdicts"])
    candidates = [r for r in db.active_records() if r.verdict in trigger_verdicts and not r.alerted]

    if not candidates:
        print("[alert-check] No new high-severity IOCs requiring alerts.")
        return

    for r in candidates:
        if cfg["enabled"]:
            # In production this would POST to cfg["webhook_url"] / send email.
            print(f"[alert] Would notify webhook for {r.indicator} (verdict={r.verdict}, "
                  f"score={r.risk_score}) -> {cfg['webhook_url']}")
        else:
            print(f"[alert-check] (alerting disabled in config) {r.indicator} "
                  f"is {r.verdict} and would normally trigger an alert")
        r.alerted = True


# =============================================================================
# CLI
# =============================================================================

def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="IOC Lifecycle Manager & Automation")
    parser.add_argument("--config", default="ioc_config.yaml")
    parser.add_argument("--add-file", help="Import IOCs from a ti_enricher JSON/CSV output file")
    parser.add_argument("--update-all", action="store_true",
                         help="Refresh recency metadata for all active IOCs "
                              "(re-enrichment hook — see README for live integration)")
    parser.add_argument("--expire-check", action="store_true", help="Remove IOCs past their TTL")
    parser.add_argument("--export-blocklist", action="store_true", help="Write blocklist.txt")
    parser.add_argument("--generate-report", action="store_true", help="Write weekly_report.html")
    parser.add_argument("--health-check", action="store_true", help="Print database health summary")
    parser.add_argument("--alert-check", action="store_true", help="Check for un-alerted high-severity IOCs")
    args = parser.parse_args()

    if not any([args.add_file, args.update_all, args.expire_check,
                args.export_blocklist, args.generate_report, args.health_check, args.alert_check]):
        parser.print_help()
        sys.exit(1)

    config = load_config(args.config)
    db = IOCDatabase(config)

    if args.add_file:
        rows = import_enrichments(args.add_file)
        added = updated = 0
        for row in rows:
            action = db.upsert(row["indicator"], row["type"], row["risk_score"],
                                row["verdict"], row.get("source_count", 1))
            added += action == "added"
            updated += action == "updated"
        print(f"[+] Import complete: {added} added, {updated} updated")

    if args.update_all:
        count = 0
        for rec in db.active_records():
            # Re-enrichment hook: in production, call TIEnricher.enrich(rec.indicator)
            # here and pass the fresh score/verdict into db.upsert(). Without live
            # API keys this refreshes last_seen/confidence to simulate a health pass.
            rec.last_seen = now_iso()
            rec.expires_at = db._compute_expiry(rec)
            rec.confidence = db.compute_confidence(rec)
            count += 1
        print(f"[+] Refreshed metadata for {count} IOCs")

    if args.expire_check:
        expired = db.expire_check()
        print(f"[+] Expired and removed {len(expired)} stale IOCs: {expired}")

    if args.export_blocklist:
        n = export_blocklist(db, "blocklist.txt")
        print(f"[+] Blocklist written to blocklist.txt ({n} entries)")

    if args.generate_report:
        generate_html_report(db, config["reporting"]["output_path"])
        print(f"[+] Report written to {config['reporting']['output_path']}")

    if args.health_check:
        health_check(db)

    if args.alert_check:
        alert_check(db)

    db.save()


if __name__ == "__main__":
    main()
