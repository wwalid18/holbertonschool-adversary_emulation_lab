# Debugging Log

## Day 1 — 2026-05-07

### Issue 1: vboxdrv kernel module not found
- **Error:** Module vboxdrv not found in /lib/modules/6.19.11+kali-amd64
- **Cause:** Kernel updated to 6.19.11 but DKMS built for 6.18.5
- **Fix:** `sudo dkms autoinstall` rebuilt the module for the running kernel
- **Result:** `lsmod | grep vbox` confirmed vboxdrv loaded 

### Issue 2: vboxnet0 not available
- **Error:** failed to open /dev/vboxnetctl: No such file or directory
- **Cause:** vboxnetadp module not loaded
- **Fix:** `sudo modprobe vboxnetadp` then `sudo vboxmanage hostonlyif create`
- **Result:** vboxnet0 created, VM gets 192.168.56.x IP 

## Day 2 — 2026-05-08

### Issue: Enable-PSRemoting failed — network set to Public
- **Error:** WinRM firewall exception won't work on Public network
- **Fix:** `Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private`
- **Result:** PSRemoting enabled successfully 

### Issue: Set-MpPreference didn't disable Defender
- **Cause:** Tamper Protection was blocking PowerShell changes
- **Fix:** Disabled Tamper Protection manually via Windows Security GUI, then toggled Real-time protection OFF
- **Result:** `Get-MpPreference | Select DisableRealtimeMonitoring` returns True

## Day 3 — 2026-05-08

### Sysmon Installation
- Downloaded Sysmon.zip and sysmonconfig-export.xml via Kali HTTP server (python3 -m http.server 8080)
- Reason: VM has no internet (host-only network — expected and correct)
- Installed Sysmon64 v15.20 with SwiftOnSecurity config (schema 4.50)
- Verified: Get-Service Sysmon64 → Status: Running 
- Verified: Event ID 1 (Process Create) and Event ID 22 (DNS Query) generating 
- Key fields confirmed: Image, CommandLine, ParentImage, Hashes, User

## Day 4 — 2026-05-08

### Wazuh Server Verification
- wazuh-manager: active (running) 
- wazuh-indexer: active (running) 
- wazuh-dashboard: active (running) 
- Dashboard accessible at https://127.0.0.1 
- Early ECONNREFUSED errors in dashboard log: normal (dashboard started before indexer was ready)
- Admin login confirmed

## Day 5-6 — 2026-05-08

### Wazuh Agent Installation
- Downloaded wazuh-agent-4.7.5-1.msi via Kali HTTP server (no internet on VM)
- Installed with WAZUH_MANAGER=192.168.56.1, WAZUH_AGENT_NAME=Win10-Victim
- NET START WazuhSvc → started successfully 
- Win10-Victim showing Active (green) in Wazuh dashboard 

### Issue: Sysmon events not appearing in Wazuh
- **Cause:** ossec.conf missing Sysmon localfile block
- **Fix:** Added localfile block for Microsoft-Windows-Sysmon/Operational
- **Issue 2:** First edit placed block outside </ossec_config> tag
- **Error:** (1230): Invalid element in the configuration: 'localfile'
- **Fix:** Used PowerShell regex to remove bad block and reinsert correctly
- **Result:** Sysmon events flowing into Wazuh dashboard 

### End-to-End Telemetry Verified
- Ran whoami, net user, ipconfig on Windows VM
- Sysmon Event ID 1 (process create) visible in Wazuh within 30 seconds 
- rule.groups: sysmon filter confirmed working 
- VM IP confirmed: 192.168.56.101 

## Day 7 — 2026-05-13

### Caldera Installation Issues
- Caldera 5.0 incompatible with Python 3.13 (aiohttp, lxml, distutils issues)
- Fix: Compiled Python 3.11.9 from source (deadsnakes PPA not available on Kali)
- Fix: Installed Caldera 5.2.0 in Python 3.11 venv, excluded donut-shellcode
- Fix: Created local.yml with app.contact.http: http://192.168.56.1:8888
- Result: Caldera running, API responding 

### Sandcat Agent Connection Issues
- Generated command used 0.0.0.0 — replaced with 192.168.56.1
- Agent beaconed (ALIVE) but didn't appear in UI
- Fix: local.yml contact.http was missing on reinstall — recreated
- Result: Agent registered, paw: nmqubm, Win10-Victim Active 

### Recurring VirtualBox Kernel Module Issues
- Kernel updated multiple times (6.18 → 6.19.11 → 6.19.14)
- Fix each time: sudo dkms autoinstall && sudo modprobe vboxdrv vboxnetflt vboxnetadp
- Permanent fix: /etc/modules-load.d/virtualbox.conf created
- vboxnet0 had to be recreated after each kernel update

### Wazuh Dashboard SSL Certificate Issue
- Error: dashboard-key.pem not found
- Cause: certs named wazuh-dashboard-key.pem not dashboard-key.pem
- Fix: Created symlinks to match expected filenames
- Result: Dashboard accessible 

### Wazuh Dashboard IPv6 Issue
- Error: ECONNREFUSED ::1:9200 (dashboard trying IPv6)
- Cause: opensearch.hosts set to localhost (resolves to ::6 on Kali)
- Fix: Changed localhost to 127.0.0.1 in opensearch_dashboards.yml
- Result: Dashboard fully connected to indexer 

### Final State
- Caldera running on Python 3.11.9 venv 
- Sandcat agent connected: Win10-Victim, group: red, contact: HTTP 
- Wazuh dashboard accessible at https://127.0.0.1 
- Win10-Victim agent Active in Wazuh 
- Snapshot taken: Lab Ready — Week 2 Start 