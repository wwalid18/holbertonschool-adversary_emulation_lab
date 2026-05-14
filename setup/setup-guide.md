# Lab Setup Guide

## Day 1 — Windows 10 VM Creation

### VM Specifications
| Setting | Value |
|---|---|
| Name | Win10-Victim |
| OS | Windows 10 Pro (64-bit) |
| RAM | 4096 MB |
| Disk | 50 GB (VDI, dynamically allocated) |
| Network | Host-only Adapter (vboxnet0) |
| Local Account | victim |

### Steps Performed
1. Installed VirtualBox on Kali Linux host
2. Fixed vboxdrv kernel module mismatch (kernel 6.19.11)
3. Created vboxnet0 host-only network adapter
4. Created Win10-Victim VM with exact specs
5. Installed Windows 10 Pro, local account: victim
6. Confirmed host-only IP: 192.168.56.x

### Issues & Fixes
- **Issue:** vboxdrv not found in kernel 6.19.11
- **Fix:** `sudo dkms autoinstall && sudo modprobe vboxdrv`
- **Issue:** vboxnet0 not available — /dev/vboxnetctl missing
- **Fix:** `sudo modprobe vboxnetadp && sudo vboxmanage hostonlyif create

## Day 2 — Post-Install Configuration

### Steps Performed
1. Set network profile from Public to Private
2. Set PowerShell execution policy to Unrestricted
3. Enabled PSRemoting via Enable-PSRemoting -Force
4. Disabled Tamper Protection manually via Windows Security GUI
5. Disabled Defender real-time protection — confirmed DisableRealtimeMonitoring: True
6. Took VM snapshot: "Clean Install"

### Commands Used
```powershell
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
Set-ExecutionPolicy Unrestricted -Force
Enable-PSRemoting -Force
Set-MpPreference -DisableRealtimeMonitoring $true
```

### Snapshot
- Name: Clean Install
- State: Windows 10 Pro, Defender off, PSRemoting enabled`

## Day 3 — Sysmon Installation

### Steps Performed
1. Downloaded Sysmon.zip from Kali HTTP server (no internet on VM)
2. Downloaded SwiftOnSecurity sysmonconfig-export.xml
3. Extracted and installed: .\Sysmon64.exe -accepteula -i sysmonconfig.xml
4. Verified service running: Get-Service Sysmon64 → Running
5. Verified events generating: Event ID 1 and 22 confirmed

### Key Event IDs Now Active
| ID | Type |
|---|---|
| 1 | Process Create |
| 3 | Network Connect |
| 10 | Process Access |
| 11 | File Create |
| 12/13 | Registry |
| 22 | DNS Query |

## Day 4 — Wazuh Server Verification

### Services Status
| Service | Status |
|---|---|
| wazuh-manager | active (running) |
| wazuh-indexer | active (running) |
| wazuh-dashboard | active (running) |

### Access
- Dashboard URL: https://127.0.0.1
- Login: admin
- All 3 services set to enabled (auto-start on boot)

## Day 5 — Wazuh Agent Installation

### Steps Performed
1. Downloaded wazuh-agent-4.7.5-1.msi via Kali HTTP server
2. Installed: msiexec /i wazuh-agent.msi /q WAZUH_MANAGER='192.168.56.1' WAZUH_AGENT_NAME='Win10-Victim'
3. Started service: NET START WazuhSvc
4. Added Sysmon localfile block to ossec.conf:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

5. Restarted WazuhSvc — confirmed Active in dashboard

## Day 6 — End-to-End Telemetry Verification

### Test Performed
- Ran whoami, net user, ipconfig on Windows VM
- Confirmed Sysmon events in Wazuh dashboard within 30 seconds
- Filter used: rule.groups: sysmon

### Result
- Full telemetry pipeline working: Windows → Sysmon → Wazuh Agent → Wazuh Server 

## Day 7 — Caldera Setup & Final Snapshot

### Caldera Installation
- Python 3.11.9 compiled from source (Kali only has 3.13)
- Caldera 5.2.0 installed in venv: python3.11 -m venv .calderavenv
- Requirements installed excluding donut-shellcode
- local.yml created with app.contact.http: http://192.168.56.1:8888

### Starting Caldera
```bash
cd ~/caldera
source .calderavenv/bin/activate
python3 server.py --insecure
```

### Sandcat Agent Deployment
- Campaigns → Agents → Deploy Agent → Sandcat → Windows → PowerShell
- Replace 0.0.0.0 with 192.168.56.1 in generated command
- Run on Windows VM as Administrator
- Agent appears in Caldera UI within 60 seconds

### Wazuh Dashboard Fixes
- SSL cert symlinks: dashboard-key.pem → wazuh-dashboard-key.pem
- opensearch.hosts: changed localhost to 127.0.0.1

### Final Snapshot
- Name: Lab Ready — Week 2 Start
- State: Wazuh agent active, Sysmon running, Caldera tested


## Day 8 — Atomic Red Team Offline Installation

### Steps Performed
1. Staged all files on Kali HTTP server (VM has no internet)
2. Downloaded invoke-atomicredteam v2.1.0 and powershell-yaml v0.4.12 zips
3. Downloaded T1059.001, T1547.001, T1087.001 YAML files individually
4. Installed invoke-atomicredteam module on Win10-Victim
5. Installed powershell-yaml dependency manually
6. Downloaded atomic YAML files to C:\AtomicRedTeam\atomics\
7. Verified full pipeline: modules loaded, YAMLs parsed, Sysmon EID 1 firing
8. Took snapshot: "ART Installed"

### Kali — Stage and Serve Files
```bash
mkdir -p ~/art-offline && cd ~/art-offline

curl -L https://github.com/redcanaryco/invoke-atomicredteam/archive/refs/heads/master.zip \
  -o invoke-atomicredteam.zip

curl -L "https://www.powershellgallery.com/api/v2/package/powershell-yaml" \
  -o powershell-yaml.zip

mkdir -p atomics
for t in T1059.001 T1547.001 T1087.001; do
  mkdir -p atomics/$t
  curl -L "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/$t/$t.yaml" \
    -o atomics/$t/$t.yaml
done

python3 -m http.server 8080
```

### Win10-Victim — Install (PowerShell as Administrator)
```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
$kali = "http://192.168.56.1:8080"

# invoke-atomicredteam
IWR "$kali/invoke-atomicredteam.zip" -OutFile "$env:TEMP\invoke-atomicredteam.zip" -UseBasicParsing
$modRoot = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\invoke-atomicredteam"
New-Item -ItemType Directory -Force -Path $modRoot
Expand-Archive "$env:TEMP\invoke-atomicredteam.zip" -DestinationPath $modRoot -Force
# Fix GitHub zip nesting
$nested = "$modRoot\invoke-atomicredteam-master"
Get-ChildItem $nested -Force | Move-Item -Destination $modRoot -Force
Remove-Item $nested -Recurse -Force

# powershell-yaml — do NOT flatten subfolders, lib\ must stay intact
IWR "$kali/powershell-yaml.zip" -OutFile "$env:TEMP\powershell-yaml.zip" -UseBasicParsing
$yamlDest = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\powershell-yaml"
New-Item -ItemType Directory -Force -Path $yamlDest
Expand-Archive "$env:TEMP\powershell-yaml.zip" -DestinationPath $yamlDest -Force

# Atomics
foreach ($t in @("T1059.001","T1547.001","T1087.001")) {
    $dir = "C:\AtomicRedTeam\atomics\$t"
    New-Item -ItemType Directory -Force -Path $dir
    IWR "$kali/atomics/$t/$t.yaml" -OutFile "$dir\$t.yaml" -UseBasicParsing
}

# Import and verify
Import-Module powershell-yaml -Force
Import-Module invoke-atomicredteam -Force
Get-Command Invoke-AtomicTest
```

### Versions Installed
| Package | Version |
|---|---|
| invoke-atomicredteam | 2.1.0 |
| powershell-yaml | 0.4.12 |
| Atomic tests — T1059.001 | 22 tests |
| Atomic tests — T1547.001 | 20 tests |
| Atomic tests — T1087.001 | 11 tests |

### Issues & Fixes
- **Issue:** `Import-Module` failed — module not found
- **Cause:** GitHub zip extracts into nested `invoke-atomicredteam-master\` subfolder
- **Fix:** Moved contents up one level, removed nested folder

- **Issue:** `powershell-yaml` dependency missing
- **Cause:** Not bundled with invoke-atomicredteam, VM has no internet
- **Fix:** Downloaded nupkg from PowerShell Gallery on Kali, served via HTTP, installed manually

- **Issue:** `LoadFile` error — YAML DLLs not found
- **Cause:** Accidentally flattened `lib\` subfolder in powershell-yaml during nested-folder fix
- **Fix:** Removed broken install, re-extracted zip cleanly without touching subfolders

### Snapshot
- Name: ART Installed
- State: ART 2.1.0 installed, Sysmon EID 1 pipeline verified, Wazuh agent Active

