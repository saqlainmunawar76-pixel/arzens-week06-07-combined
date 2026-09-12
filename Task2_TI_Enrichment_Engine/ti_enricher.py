#!/usr/bin/env python3
"""
ti_enricher.py — Threat Intelligence Enrichment Engine
========================================================
Enriches indicators of compromise (IOCs) — IPs, domains, URLs, file hashes —
by querying VirusTotal, AbuseIPDB, and AlienVault OTX, then combines the
results into a single 0-100 risk score.

Usage:
    python ti_enricher.py --indicator 8.8.8.8
    python ti_enricher.py --indicator evil-domain.com --output json
    python ti_enricher.py --input-file sample_indicators.csv --output csv
    python ti_enricher.py --input-file sample_indicators.csv --no-cache

Author: Saqlain (The Arzens Internship — Advanced Track, Week 06-07)
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pyyaml. Install with: pip install pyyaml requests")

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: requests. Install with: pip install pyyaml requests")


# =============================================================================
# Indicator type detection
# =============================================================================

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def detect_indicator_type(indicator: str) -> str:
    """Classify an indicator as ip, domain, url, or hash."""
    indicator = indicator.strip()

    if indicator.startswith(("http://", "https://")):
        return "url"

    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass

    if re.fullmatch(r"[a-fA-F0-9]+", indicator) and len(indicator) in HASH_LENGTHS:
        return "hash"

    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
    if re.fullmatch(domain_pattern, indicator):
        return "domain"

    return "unknown"


# =============================================================================
# Rate limiter — simple sliding-window token bucket per source
# =============================================================================

class RateLimiter:
    def __init__(self, requests_allowed: int, window_seconds: int):
        self.requests_allowed = requests_allowed
        self.window_seconds = window_seconds
        self._timestamps: list[float] = []

    def wait_if_needed(self):
        now = time.time()
        self._timestamps = [t for t in self._timestamps if now - t < self.window_seconds]
        if len(self._timestamps) >= self.requests_allowed:
            oldest = self._timestamps[0]
            sleep_for = self.window_seconds - (now - oldest) + 0.5
            if sleep_for > 0:
                print(f"  [rate-limit] sleeping {sleep_for:.1f}s to respect quota...")
                time.sleep(sleep_for)
        self._timestamps.append(time.time())


# =============================================================================
# Cache — JSON-backed, TTL-based
# =============================================================================

class Cache:
    def __init__(self, path: str, ttl_hours: int, enabled: bool = True):
        self.path = Path(path)
        self.ttl = timedelta(hours=ttl_hours)
        self.enabled = enabled
        self._data: dict = {}
        if self.enabled and self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def _key(self, source: str, indicator: str) -> str:
        return f"{source}:{indicator}"

    def get(self, source: str, indicator: str) -> Optional[dict]:
        if not self.enabled:
            return None
        entry = self._data.get(self._key(source, indicator))
        if not entry:
            return None
        cached_at = datetime.fromisoformat(entry["cached_at"])
        if datetime.now(timezone.utc) - cached_at > self.ttl:
            return None
        return entry["result"]

    def set(self, source: str, indicator: str, result: dict):
        if not self.enabled:
            return
        self._data[self._key(source, indicator)] = {
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }

    def save(self):
        if not self.enabled:
            return
        try:
            self.path.write_text(json.dumps(self._data, indent=2))
        except OSError as e:
            print(f"  [warn] could not write cache: {e}")


# =============================================================================
# Source result container
# =============================================================================

@dataclass
class SourceResult:
    source: str
    success: bool
    score: Optional[float] = None       # normalized 0-100 for this source alone
    details: dict = field(default_factory=dict)
    error: Optional[str] = None


# =============================================================================
# TI Enricher — orchestrates queries, caching, scoring
# =============================================================================

class TIEnricher:
    def __init__(self, config: dict, use_cache: bool = True):
        self.config = config
        self.cache = Cache(
            path=config["cache"]["path"],
            ttl_hours=config["cache"]["ttl_hours"],
            enabled=use_cache,
        )
        rl = config["rate_limits"]
        self.limiters = {
            "virustotal": RateLimiter(rl["virustotal"]["requests"], rl["virustotal"]["window_seconds"]),
            "abuseipdb": RateLimiter(rl["abuseipdb"]["requests"], rl["abuseipdb"]["window_seconds"]),
            "otx": RateLimiter(rl["otx"]["requests"], rl["otx"]["window_seconds"]),
        }
        self.timeout = config["network"]["timeout_seconds"]
        self.max_retries = config["network"]["max_retries"]
        self.backoff = config["network"]["backoff_seconds"]

    # ---- HTTP helper with retry/backoff -----------------------------------
    def _get(self, url: str, headers: dict = None, params: dict = None) -> requests.Response:
        last_exc = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = requests.get(url, headers=headers, params=params, timeout=self.timeout)
                return resp
            except requests.exceptions.RequestException as e:
                last_exc = e
                if attempt < self.max_retries:
                    time.sleep(self.backoff * (attempt + 1))
        raise last_exc

    # ---- VirusTotal ---------------------------------------------------------
    def query_virustotal(self, indicator: str, ind_type: str) -> SourceResult:
        cached = self.cache.get("virustotal", indicator)
        if cached:
            return SourceResult(**cached)

        api_key = self.config["api_keys"]["virustotal"]
        if not api_key or "YOUR_" in api_key:
            return SourceResult("virustotal", False, error="API key not configured")

        endpoints = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
            "url": f"https://www.virustotal.com/api/v3/urls/{hashlib.sha256(indicator.encode()).hexdigest()}",
            "hash": f"https://www.virustotal.com/api/v3/files/{indicator}",
        }
        url = endpoints.get(ind_type)
        if not url:
            return SourceResult("virustotal", False, error=f"unsupported indicator type: {ind_type}")

        self.limiters["virustotal"].wait_if_needed()
        try:
            resp = self._get(url, headers={"x-apikey": api_key})
        except requests.exceptions.RequestException as e:
            return SourceResult("virustotal", False, error=f"network error: {e}")

        if resp.status_code == 404:
            result = SourceResult("virustotal", True, score=0.0,
                                   details={"note": "not found in VT database"})
        elif resp.status_code == 200:
            stats = (resp.json().get("data", {}).get("attributes", {})
                     .get("last_analysis_stats", {}))
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            score = round(((malicious * 1.0 + suspicious * 0.5) / total) * 100, 1)
            result = SourceResult("virustotal", True, score=score, details={"stats": stats})
        elif resp.status_code == 429:
            result = SourceResult("virustotal", False, error="rate limited (429)")
        else:
            result = SourceResult("virustotal", False, error=f"HTTP {resp.status_code}")

        if result.success:
            self.cache.set("virustotal", indicator, asdict(result))
        return result

    # ---- AbuseIPDB (IPs only) ------------------------------------------------
    def query_abuseipdb(self, indicator: str, ind_type: str) -> SourceResult:
        if ind_type != "ip":
            return SourceResult("abuseipdb", False, error="AbuseIPDB only supports IP indicators")

        cached = self.cache.get("abuseipdb", indicator)
        if cached:
            return SourceResult(**cached)

        api_key = self.config["api_keys"]["abuseipdb"]
        if not api_key or "YOUR_" in api_key:
            return SourceResult("abuseipdb", False, error="API key not configured")

        self.limiters["abuseipdb"].wait_if_needed()
        try:
            resp = self._get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": indicator, "maxAgeInDays": 90},
            )
        except requests.exceptions.RequestException as e:
            return SourceResult("abuseipdb", False, error=f"network error: {e}")

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = float(data.get("abuseConfidenceScore", 0))
            result = SourceResult("abuseipdb", True, score=score, details={
                "totalReports": data.get("totalReports"),
                "countryCode": data.get("countryCode"),
                "isWhitelisted": data.get("isWhitelisted"),
            })
        elif resp.status_code == 429:
            result = SourceResult("abuseipdb", False, error="rate limited (429)")
        else:
            result = SourceResult("abuseipdb", False, error=f"HTTP {resp.status_code}")

        if result.success:
            self.cache.set("abuseipdb", indicator, asdict(result))
        return result

    # ---- AlienVault OTX -------------------------------------------------------
    def query_otx(self, indicator: str, ind_type: str) -> SourceResult:
        cached = self.cache.get("otx", indicator)
        if cached:
            return SourceResult(**cached)

        api_key = self.config["api_keys"]["otx"]
        section_map = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}
        section = section_map.get(ind_type)
        if not section:
            return SourceResult("otx", False, error=f"unsupported indicator type: {ind_type}")

        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general"
        headers = {"X-OTX-API-KEY": api_key} if api_key and "YOUR_" not in api_key else {}

        self.limiters["otx"].wait_if_needed()
        try:
            resp = self._get(url, headers=headers)
        except requests.exceptions.RequestException as e:
            return SourceResult("otx", False, error=f"network error: {e}")

        if resp.status_code == 200:
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            # Heuristic: more threat-intel "pulses" referencing this indicator => higher risk.
            score = min(pulse_count * 10, 100)
            result = SourceResult("otx", True, score=float(score),
                                   details={"pulse_count": pulse_count})
        elif resp.status_code == 404:
            result = SourceResult("otx", True, score=0.0, details={"note": "no pulses found"})
        elif resp.status_code == 429:
            result = SourceResult("otx", False, error="rate limited (429)")
        else:
            result = SourceResult("otx", False, error=f"HTTP {resp.status_code}")

        if result.success:
            self.cache.set("otx", indicator, asdict(result))
        return result

    # ---- Combine into final risk score --------------------------------------
    def compute_risk_score(self, results: list[SourceResult]) -> float:
        weights = self.config["scoring"]["weights"]
        successful = [r for r in results if r.success and r.score is not None]
        if not successful:
            return 0.0

        if self.config["scoring"].get("redistribute_on_failure", True):
            total_weight = sum(weights[r.source] for r in successful)
            if total_weight == 0:
                return 0.0
            weighted = sum(r.score * (weights[r.source] / total_weight) for r in successful)
        else:
            weighted = sum(r.score * weights.get(r.source, 0) for r in successful)

        return round(weighted, 1)

    # ---- Full pipeline for one indicator -------------------------------------
    def enrich(self, indicator: str) -> dict:
        ind_type = detect_indicator_type(indicator)
        print(f"[*] Enriching {indicator} ({ind_type})...")

        results = [
            self.query_virustotal(indicator, ind_type),
            self.query_abuseipdb(indicator, ind_type),
            self.query_otx(indicator, ind_type),
        ]
        risk_score = self.compute_risk_score(results)

        return {
            "indicator": indicator,
            "type": ind_type,
            "risk_score": risk_score,
            "verdict": self._verdict(risk_score),
            "sources": {r.source: asdict(r) for r in results},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _verdict(score: float) -> str:
        if score >= 75:
            return "MALICIOUS"
        if score >= 40:
            return "SUSPICIOUS"
        if score > 0:
            return "LOW_RISK"
        return "CLEAN"


# =============================================================================
# Output formatting
# =============================================================================

def print_console_table(enrichments: list[dict]):
    headers = ["Indicator", "Type", "Risk Score", "Verdict", "VT", "AbuseIPDB", "OTX"]
    rows = []
    for e in enrichments:
        src = e["sources"]

        def cell(name):
            s = src.get(name, {})
            if s.get("success"):
                return f"{s.get('score', '-')}"
            return f"n/a ({s.get('error', 'skipped')[:15]})"

        rows.append([
            e["indicator"], e["type"], f"{e['risk_score']}", e["verdict"],
            cell("virustotal"), cell("abuseipdb"), cell("otx"),
        ])

    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    print("\n" + line)
    print("-" * len(line))
    for r in rows:
        print(" | ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    print()


def write_json(enrichments: list[dict], path: str):
    Path(path).write_text(json.dumps(enrichments, indent=2))
    print(f"[+] JSON written to {path}")


def write_csv(enrichments: list[dict], path: str):
    fieldnames = ["indicator", "type", "risk_score", "verdict",
                  "vt_score", "abuseipdb_score", "otx_score", "timestamp"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in enrichments:
            src = e["sources"]
            writer.writerow({
                "indicator": e["indicator"],
                "type": e["type"],
                "risk_score": e["risk_score"],
                "verdict": e["verdict"],
                "vt_score": src.get("virustotal", {}).get("score", ""),
                "abuseipdb_score": src.get("abuseipdb", {}).get("score", ""),
                "otx_score": src.get("otx", {}).get("score", ""),
                "timestamp": e["timestamp"],
            })
    print(f"[+] CSV written to {path}")


# =============================================================================
# CLI entry point
# =============================================================================

def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def read_indicators_from_file(path: str) -> list[str]:
    indicators = []
    with open(path) as f:
        reader = csv.reader(f)
        rows = list(reader)
    # Support both a plain one-per-line file and a CSV with an "indicator" header.
    if rows and rows[0] and rows[0][0].strip().lower() == "indicator":
        rows = rows[1:]
    for row in rows:
        if row and row[0].strip():
            indicators.append(row[0].strip())
    return indicators


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Enrichment Engine")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--indicator", help="Single indicator to enrich (IP, domain, URL, or hash)")
    group.add_argument("--input-file", help="CSV/text file with one indicator per line")
    parser.add_argument("--output", choices=["console", "json", "csv"], default=None,
                         help="Output format (default: from config.yaml)")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--no-cache", action="store_true", help="Disable the query cache")
    args = parser.parse_args()

    config = load_config(args.config)
    output_format = args.output or config["output"]["default_format"]

    enricher = TIEnricher(config, use_cache=not args.no_cache)

    indicators = [args.indicator] if args.indicator else read_indicators_from_file(args.input_file)
    if not indicators:
        sys.exit("No indicators found to process.")

    enrichments = [enricher.enrich(ind) for ind in indicators]
    enricher.cache.save()

    if output_format == "console":
        print_console_table(enrichments)
    elif output_format == "json":
        write_json(enrichments, "enrichment_results.json")
    elif output_format == "csv":
        write_csv(enrichments, config["output"]["results_file"])


if __name__ == "__main__":
    main()
