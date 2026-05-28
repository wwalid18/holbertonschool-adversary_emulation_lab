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
- Verified: Get-Service Sysmon64 — Status: Running
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
- NET START WazuhSvc — started successfully
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
- Agent beaconed (ALIVE) but did not appear in UI
- Fix: local.yml contact.http was missing on reinstall — recreated
- Result: Agent registered, paw: nmqubm, Win10-Victim Active

### Recurring VirtualBox Kernel Module Issues
- Kernel updated multiple times (6.18 — 6.19.11 — 6.19.14)
- Fix each time: sudo dkms autoinstall && sudo modprobe vboxdrv vboxnetflt vboxnetadp
- Permanent fix: /etc/modules-load.d/virtualbox.conf created
- vboxnet0 had to be recreated after each kernel update

### Wazuh Dashboard SSL Certificate Issue
- **Error:** dashboard-key.pem not found
- **Cause:** certs named wazuh-dashboard-key.pem not dashboard-key.pem
- **Fix:** Created symlinks to match expected filenames
- **Result:** Dashboard accessible

### Wazuh Dashboard IPv6 Issue
- **Error:** ECONNREFUSED ::1:9200 (dashboard trying IPv6)
- **Cause:** opensearch.hosts set to localhost (resolves to ::6 on Kali)
- **Fix:** Changed localhost to 127.0.0.1 in opensearch_dashboards.yml
- **Result:** Dashboard fully connected to indexer

### Final State
- Caldera running on Python 3.11.9 venv
- Sandcat agent connected: Win10-Victim, group: red, contact: HTTP
- Wazuh dashboard accessible at https://127.0.0.1
- Win10-Victim agent Active in Wazuh
- Snapshot taken: Lab Ready — Week 2 Start

---

# Debugging Log — Week 2

## Day 8 — 2026-05-14

### Issue: invoke-atomicredteam module not found after extraction
- **Error:** `Import-Module : The specified module 'invoke-atomicredteam' was not loaded because no valid module file was found`
- **Cause:** GitHub zip extracts into a nested `invoke-atomicredteam-master\` subfolder; PowerShell expects the `.psd1` at the module root
- **Fix:**
```powershell
$modRoot = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\invoke-atomicredteam"
$nested  = "$modRoot\invoke-atomicredteam-master"
Get-ChildItem $nested -Force | Move-Item -Destination $modRoot -Force
Remove-Item $nested -Recurse -Force
```
- **Result:** `Invoke-AtomicRedTeam.psd1` found at module root, module recognized

### Issue: powershell-yaml dependency missing
- **Error:** `Import-Module : The required module 'powershell-yaml' is not loaded`
- **Cause:** invoke-atomicredteam v2.1.0 requires powershell-yaml; not included in the zip and VM has no internet
- **Fix:** Downloaded `powershell-yaml` nupkg from PowerShell Gallery on Kali, served via `python3 -m http.server 8080`, installed manually on Win10-Victim:
```powershell
IWR "http://192.168.56.1:8080/powershell-yaml.zip" -OutFile "$env:TEMP\powershell-yaml.zip" -UseBasicParsing
Expand-Archive "$env:TEMP\powershell-yaml.zip" -DestinationPath `
  "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\powershell-yaml" -Force
```
- **Result:** powershell-yaml v0.4.12 loaded successfully

### Issue: LoadFile error for YAML DLLs after accidental lib folder move
- **Error:** `Exception calling "LoadFile" with "1" argument(s): The system cannot find the file specified`
- **Cause:** Ran the nested-folder fix on powershell-yaml which moved `lib\` contents up, breaking the relative DLL paths in `powershell-yaml.psm1`
- **Fix:** Removed the broken install and re-extracted the zip cleanly without moving any subfolders:
```powershell
Remove-Item "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\powershell-yaml" -Recurse -Force
Expand-Archive "$env:TEMP\powershell-yaml.zip" -DestinationPath `
  "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\powershell-yaml" -Force
```
- **Result:** DLLs load correctly, ConvertFrom-Yaml functional

### Verification results
- invoke-atomicredteam v2.1.0 loaded
- powershell-yaml v0.4.12 loaded
- T1059.001 — 22 tests parsed
- T1547.001 — 20 tests parsed
- T1087.001 — 11 tests parsed
- Wazuh agent: Running
- Sysmon64: Running
- Sysmon EID 1 pipeline: verified (whoami — EID 1 captured)
- Snapshot taken: ART Installed

---

# Debugging Log — Week 3

## Day 15 — 2026-05-19

- Wrote all 4 Sigma rules from scratch based on real Wazuh alert JSON logs collected in Week 2
- Rules based on actual Sysmon field values — no assumptions used
- T1059-001: matched on CommandLine not Image — real log showed cmd.exe as image, not powershell.exe directly
- T1547-001: used TargetObject|contains on \CurrentVersion\Run\ — HKCU appears as HKU\<SID> in real Sysmon logs
- T1087-001: correct MITRE tag T1087.001 applied — Wazuh rule 92036 incorrectly tags this as T1059.003 + T1574.001
- T1003-001: dual-condition rule written — EID 1 (immediate) + EID 10 (requires Sysmon config fix on Day 17)

## Day 16 — 2026-05-19

### Review: T1059-001
- Simulated real log CommandLine through detection condition
- Double space in `powershell.exe -e  <blob>` — contains modifier handles this correctly, no fix needed
- Evasion check: `-w hidden -e`, `-nop -e` — encoded flag still present, rule still catches it
- Rule finalized, no changes required

### Review: T1547-001
- Simulated TargetObject `HKU\S-1-5-21-...\CurrentVersion\Run\Atomic Red Team` through detection condition
- `\CurrentVersion\Run\` is contained within the real path — match confirmed
- RunOnce variant covered by second contains entry
- Rule finalized, no changes required

### Review: T1087-001
- Simulated `net  user` (double space) through `CommandLine|contains: ' user'` — space+user present, match confirmed
- Case sensitivity check: Sigma contains is case-insensitive in Wazuh backend — `NET USER` still matches
- Rule finalized, no changes required

### Issue: T1003-001 — taskmgr.exe incorrectly included in filter_system block
- **Finding:** `taskmgr.exe` was included in the legitimate process filter for EID 10
- **Problem:** Task Manager accessing lsass is a known living-off-the-land technique — attackers can use it to dump lsass memory without any third-party tools, bypassing the rule entirely if filtered out
- **Fix:** Removed `\Windows\System32\taskmgr.exe` from the filter_system block in T1003-001-lsass-access.yml
- **Also:** Updated falsepositives section — replaced "Task Manager is a false positive" with "Task Manager alerts are intentional — investigate every one"
- **Result:** Rule now catches taskmgr.exe opening lsass.exe via EID 10

### All 4 rules finalized

## Day 17 — 2026-05-22

### Issue: ossec-logtest not found
- **Error:** `sudo: /var/ossec/bin/ossec-logtest: command not found`
- **Cause:** Wazuh 4.x replaced ossec-logtest with wazuh-analysisd
- **Fix:** `sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -i error`
- **Result:** Validation working, no errors on custom rules

### Issue: Sysmon config path incorrect
- **Error:** `Cannot find path 'C:\Sysmon\sysmon-config.xml'`
- **Cause:** File is named `sysmonconfig.xml` not `sysmon-config.xml`
- **Fix:** Located correct path via `Get-ChildItem -Path C:\ -Recurse -Filter "*.xml" | Where-Object { $_.Name -match "sysmon" }`
- **Result:** Correct path confirmed as `C:\Sysmon\sysmonconfig.xml`

### Issue: EID 10 not generating — Sysmon ProcessAccess block empty
- **Error:** Zero EID 10 events in Sysmon log
- **Cause:** SwiftOnSecurity config has `<ProcessAccess onmatch="include">` with no rules inside — the comment inside confirms nothing is logged when include has no entries
- **Fix:** Added `<TargetImage condition="end with">lsass.exe</TargetImage>` inside the ProcessAccess block, reloaded with `C:\Windows\Sysmon64.exe -c C:\Sysmon\sysmonconfig.xml`
- **Result:** EID 10 generating immediately after reload confirmed

### Issue: VBoxService.exe generating false positive EID 10 alerts on rule 100006
- **Finding:** VBoxService.exe accesses lsass every ~15 seconds with GrantedAccess 0x1400
- **Cause:** Normal VirtualBox guest service behavior — was not in the original negate filter
- **Fix:** Added `VBoxService\.exe` to the negate filter in rule 100006
- **Result:** VBoxService alerts suppressed

### Issue: wazuh-agent.exe and MicrosoftEdgeUpdate.exe generating false positive EID 10 alerts
- **Finding:** wazuh-agent.exe opened lsass with GrantedAccess 0x1FFFFF, MicrosoftEdgeUpdate.exe with 0x1000
- **Cause:** Wazuh agent legitimately reads lsass for monitoring; Edge updater checks session info during update
- **Fix:** Added `wazuh-agent\.exe` and `MicrosoftEdgeUpdate\.exe` to the negate filter in rule 100006
- **Result:** False positives suppressed, powershell.exe opening lsass still fires correctly at level 15

### Issue: Rule 100005 never firing — wrong detection approach for Out-Minidump
- **Error:** No alerts for rule 100005 after running Out-Minidump
- **Cause:** Out-Minidump is a PowerShell function loaded via dot-sourcing — it never appears in a process creation command line because no new process is spawned. The function executes inside the existing PowerShell process. EID 1 CommandLine approach was fundamentally wrong
- **Fix:** Changed rule 100005 from EID 1 CommandLine match on `out-minidump` to EID 11 FileCreate match on `lsass.*\.dmp` in targetFilename
- **Result:** Rule 100005 fired at level 15 on `lsass_600.dmp` creation confirmed

### Issue: Rule 100005 still not firing after EID 11 fix — wrong group
- **Error:** Rule 100005 still not triggering even after switching to EID 11
- **Cause:** Rule used `if_group sysmon_eid11_detections` which only activates when an existing base rule already matched the EID 11 event. No base Wazuh rule matches `.dmp` files so the group was never entered and rule 100005 was never evaluated
- **Fix:** Changed `if_group` from `sysmon_eid11_detections` to `sysmon` and added explicit `<field name="win.system.eventID">^11$</field>` to the rule
- **Result:** Rule fires correctly on any lsass dump file creation

### All 5 rules verified firing
- Rule 100002 — T1059.001 — level 12 — EID 1 — fired x2
- Rule 100003 — T1547.001 — level 12 — EID 13 — fired x1
- Rule 100004 — T1087.001 — level 8 — EID 1 — fired x3
- Rule 100005 — T1003.001 — level 15 — EID 11 — fired x1
- Rule 100006 — T1003.001 — level 15 — EID 10 — fired confirmed

## Day 18 — 2026-05-22

### Rule tuning — false positive analysis across all 5 rules

- Rule 100002 (T1059.001): no false positives observed at rest
- Rule 100003 (T1547.001): no false positives observed at rest
- Rule 100004 (T1087.001): net user and net localgroup fire on legitimate admin use — acceptable at level 8, requires analyst triage
- Rule 100005 (T1003.001): no false positives observed — no process writes lsass*.dmp during normal operation
- Rule 100006 (T1003.001): three false positive sources identified from Day 17 testing

### Issue: Rule 100006 negate filter not suppressing wazuh-agent.exe and MicrosoftEdgeUpdate.exe
- **Finding:** wazuh-agent.exe (3 alerts) and MicrosoftEdgeUpdate.exe (2 alerts) still appearing in rule 100006 alerts after initial filter deployment
- **Cause:** Original negate regex used escaped backslashes and full path patterns — parentheses in `Program Files (x86)` are regex special characters and caused the entire pattern to fail silently
- **Fix:** Simplified negate regex to match on process name only without path — `(?i)(VBoxService|MsMpEng|WinDefend|svchost|wininit|csrss|services|lsm|wmiprvse|wazuh-agent|ossec-agent|MicrosoftEdgeUpdate|EdgeUpdate)`
- **Result:** All timestamps for false positive sources confirmed before fix deployment — no new false positive alerts after 11:42

### Final false positive disposition
- VBoxService.exe — suppressed via negate filter
- wazuh-agent.exe / ossec-agent — suppressed via negate filter
- MicrosoftEdgeUpdate.exe — suppressed via negate filter
- powershell.exe opening lsass — intentional alert, investigate every instance
- net user / net localgroup — intentional alert at level 8, expected admin noise

### All 5 rules tuned and finalized

## Day 19 — 2026-05-22

- Detection scores documented for all 4 techniques using Confidence/Noise 1-5 scale per planning doc
- Scoring aligned with dashboard and AAR requirements — percentages from initial draft replaced with 1-5 scale
- T1059.001: confidence 5/5, noise 1/5 — double coverage, zero false positives
- T1547.001: confidence 5/5, noise 2/5 — solid EID 13 coverage, msiexec filtered
- T1087.001: confidence 5/5, noise 3/5 — correct MITRE mapping applied, medium noise from legitimate net.exe use
- T1003.001: confidence 5/5, noise 2/5 — dual coverage via EID 10 and EID 11, three FP sources suppressed
- JSON validated locally with python3 before commit — all 4 techniques parsed correctly
- Overall: 4/4 detection rate, average confidence 5.0, average noise 2.0