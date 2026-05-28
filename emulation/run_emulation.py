#!/usr/bin/env python3
"""
run_emulation.py — Purple Team Detection Validation Script
Holberton Cybersecurity — Adversary Emulation Lab (P.1)

What this script does:
  1. Connects to the Wazuh indexer API
  2. For each ATT&CK technique, checks whether the custom detection
     rule fired within the last N minutes
  3. Prints a pass/fail result per technique
  4. Saves a structured validation report to logs/validation-<timestamp>.json

Usage:
  python3 run_emulation.py               # check last 60 minutes
  python3 run_emulation.py --window 30   # check last 30 minutes
  python3 run_emulation.py --window 1440 # check last 24 hours

Prerequisites:
  - Wazuh indexer running at https://127.0.0.1:9200
  - Atomic Red Team tests already executed on Win10-Victim
  - Custom rules 100002-100006 deployed in Wazuh

Author: walid
Date:   2026-05-22
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import ssl
import base64
from datetime import datetime, timezone


# ── Configuration ────────────────────────────────────────────────────────────

INDEXER_URL   = "https://127.0.0.1:9200"
INDEXER_USER  = "admin"
INDEXER_PASS  = "ly3ar+g1BB.+L2wygfa6xgQLvIHcoaHN"
INDEX_PATTERN = "wazuh-alerts-4.x-*"

# Output directory for validation reports
LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "logs")

# ── Technique definitions ─────────────────────────────────────────────────────
# Each entry maps a technique to the Wazuh rule IDs that should fire.
# Multiple rule IDs = any one firing counts as detected.

TECHNIQUES = [
    {
        "technique_id":   "T1059.001",
        "technique_name": "PowerShell Encoded Command Execution",
        "tactic":         "Execution",
        "rule_ids":       ["100002", "92057"],
        "primary_rule":   "100002",
        "test_tool":      "Atomic Red Team Test #17",
        "confidence":     5,
        "noise":          1,
    },
    {
        "technique_id":   "T1547.001",
        "technique_name": "Registry Run Key Persistence",
        "tactic":         "Persistence",
        "rule_ids":       ["100003", "92302"],
        "primary_rule":   "100003",
        "test_tool":      "Atomic Red Team Test #1",
        "confidence":     5,
        "noise":          2,
    },
    {
        "technique_id":   "T1087.001",
        "technique_name": "Local Account Discovery via net.exe",
        "tactic":         "Discovery",
        "rule_ids":       ["100004", "92036"],
        "primary_rule":   "100004",
        "test_tool":      "Atomic Red Team Test #8",
        "confidence":     5,
        "noise":          3,
    },
    {
        "technique_id":   "T1003.001",
        "technique_name": "LSASS Memory Credential Dumping",
        "tactic":         "Credential Access",
        "rule_ids":       ["100005", "100006"],
        "primary_rule":   "100005",
        "test_tool":      "MITRE Caldera / Out-Minidump.ps1",
        "confidence":     5,
        "noise":          2,
    },
]

# ── Colors ────────────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def green(s):  return f"{GREEN}{s}{RESET}"
def red(s):    return f"{RED}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def cyan(s):   return f"{CYAN}{s}{RESET}"
def bold(s):   return f"{BOLD}{s}{RESET}"


# ── Indexer helpers ───────────────────────────────────────────────────────────

def _auth_header():
    """Return Basic Auth header value for the indexer."""
    token = base64.b64encode(
        f"{INDEXER_USER}:{INDEXER_PASS}".encode()
    ).decode()
    return f"Basic {token}"


def _ssl_context():
    """Return an SSL context that skips certificate verification."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def query_indexer(rule_id: str, window_minutes: int) -> dict:
    """
    Query the Wazuh indexer for alerts matching rule_id within the
    last window_minutes minutes.

    Returns the raw hits dict from the indexer response.
    """
    url  = f"{INDEXER_URL}/{INDEX_PATTERN}/_search"
    body = {
        "size": 5,
        "query": {
            "bool": {
                "must": [
                    {"match": {"rule.id": rule_id}},
                    {"range": {"timestamp": {
                        "gte": f"now-{window_minutes}m"
                    }}}
                ]
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "rule.id", "rule.description",
                    "rule.level", "agent.name"]
    }

    data    = json.dumps(body).encode()
    headers = {
        "Authorization": _auth_header(),
        "Content-Type":  "application/json",
    }

    req  = urllib.request.Request(url, data=data, headers=headers)
    resp = urllib.request.urlopen(req, context=_ssl_context(), timeout=10)
    return json.loads(resp.read())


def check_technique(technique: dict, window_minutes: int) -> dict:
    """
    Check all rule IDs for a technique.
    Returns a result dict with detected status and alert details.
    """
    detected       = False
    firing_rule_id = None
    alert_count    = 0
    latest_alert   = None
    errors         = []

    for rule_id in technique["rule_ids"]:
        try:
            response = query_indexer(rule_id, window_minutes)
            hits     = response.get("hits", {})
            count    = hits.get("total", {}).get("value", 0)

            if count > 0:
                detected       = True
                firing_rule_id = rule_id
                alert_count    = count
                # grab most recent alert timestamp
                if hits.get("hits"):
                    src = hits["hits"][0].get("_source", {})
                    latest_alert = src.get("timestamp", "unknown")
                break  # first match is enough

        except urllib.error.URLError as e:
            errors.append(f"rule {rule_id}: connection error — {e}")
        except Exception as e:
            errors.append(f"rule {rule_id}: {e}")

    return {
        "technique_id":   technique["technique_id"],
        "technique_name": technique["technique_name"],
        "tactic":         technique["tactic"],
        "test_tool":      technique["test_tool"],
        "detected":       detected,
        "firing_rule_id": firing_rule_id,
        "alert_count":    alert_count,
        "latest_alert":   latest_alert,
        "confidence":     technique["confidence"],
        "noise":          technique["noise"],
        "errors":         errors,
        "window_minutes": window_minutes,
    }


# ── Output ────────────────────────────────────────────────────────────────────

def print_banner():
    print()
    print(bold(cyan("═" * 60)))
    print(bold(cyan("  Purple Team Detection Validation")))
    print(bold(cyan("  Holberton Cybersecurity — Adversary Emulation Lab")))
    print(bold(cyan("═" * 60)))
    print()


def print_result(result: dict):
    tid    = result["technique_id"]
    tname  = result["technique_name"]
    tactic = result["tactic"]

    if result["detected"]:
        status = green("PASS")
        detail = (f"rule {result['firing_rule_id']} fired "
                  f"{result['alert_count']}x — "
                  f"latest: {result['latest_alert']}")
    else:
        status = red("FAIL")
        detail = "no alert found in window"
        if result["errors"]:
            detail += f" — errors: {'; '.join(result['errors'])}"

    print(f"  [{status}] {bold(tid)} — {tname}")
    print(f"         Tactic: {tactic} | Tool: {result['test_tool']}")
    print(f"         {detail}")
    print(f"         Confidence: {result['confidence']}/5 | "
          f"Noise: {result['noise']}/5")
    print()


def print_summary(results: list, window_minutes: int):
    total    = len(results)
    detected = sum(1 for r in results if r["detected"])
    rate     = f"{detected}/{total}"

    print(bold(cyan("─" * 60)))
    print(bold(f"  Results: {rate} techniques detected"))
    print(f"  Window:  last {window_minutes} minutes")
    print(f"  Time:    {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")

    if detected == total:
        print(bold(green("  Status:  ALL DETECTIONS PASSING")))
    else:
        missing = [r["technique_id"] for r in results if not r["detected"]]
        print(bold(red(f"  Status:  GAPS FOUND — {', '.join(missing)}")))

    print(bold(cyan("─" * 60)))
    print()


def save_report(results: list, window_minutes: int) -> str:
    """Save validation results to logs/validation-<timestamp>.json"""
    os.makedirs(LOGS_DIR, exist_ok=True)

    ts       = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"validation-{ts}.json"
    filepath = os.path.join(LOGS_DIR, filename)

    detected = sum(1 for r in results if r["detected"])
    report   = {
        "metadata": {
            "script":          "run_emulation.py",
            "run_timestamp":   datetime.now(timezone.utc).isoformat(),
            "window_minutes":  window_minutes,
            "indexer_url":     INDEXER_URL,
            "index_pattern":   INDEX_PATTERN,
        },
        "summary": {
            "techniques_tested":   len(results),
            "techniques_detected": detected,
            "detection_rate":      f"{detected}/{len(results)}",
            "all_passing":         detected == len(results),
        },
        "results": results,
    }

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)

    return filepath


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate Purple Team detection rules against Wazuh alerts"
    )
    parser.add_argument(
        "--window", type=int, default=60,
        help="Time window in minutes to search for alerts (default: 60)"
    )
    parser.add_argument(
        "--technique", type=str, default=None,
        help="Run check for a single technique ID only (e.g. T1059.001)"
    )
    parser.add_argument(
        "--no-save", action="store_true",
        help="Do not save a validation report to disk"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    techniques = TECHNIQUES
    if args.technique:
        techniques = [t for t in TECHNIQUES
                      if t["technique_id"] == args.technique]
        if not techniques:
            print(red(f"Unknown technique: {args.technique}"))
            print(f"Available: {', '.join(t['technique_id'] for t in TECHNIQUES)}")
            sys.exit(1)

    print_banner()
    print(f"  Querying Wazuh indexer — last {args.window} minutes")
    print(f"  Checking {len(techniques)} technique(s)...")
    print()

    results = []
    for technique in techniques:
        print(f"  Checking {technique['technique_id']}...", end=" ", flush=True)
        result = check_technique(technique, args.window)
        results.append(result)
        print(green("done") if result["detected"] else red("no alert"))
        time.sleep(0.5)  # avoid hammering the indexer

    print()
    for result in results:
        print_result(result)

    print_summary(results, args.window)

    if not args.no_save:
        filepath = save_report(results, args.window)
        print(f"  Report saved: {filepath}")
        print()

    # exit code 1 if any technique not detected
    sys.exit(0 if all(r["detected"] for r in results) else 1)


if __name__ == "__main__":
    main()