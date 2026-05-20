# Week 2 — Technique Runbook

## Environment
- Attacker: Kali Linux 192.168.56.1 (Wazuh + Caldera)
- Victim: Win10-Victim 192.168.56.101 (user: walid)
- Network: VirtualBox host-only 192.168.56.0/24
- Sysmon: v15.20 SwiftOnSecurity config
- Wazuh agent: v4.7.5
- Atomic Red Team: v2.1.0 (invoke-atomicredteam)
- Caldera: v5.2.0

---

## T1059.001 — PowerShell Execution
**Tactic:** Execution
**Tool:** Atomic Red Team, Test #17 (PowerShell Command Execution)
**Date run:** 2026-05-19

### What the technique does
Attackers abuse PowerShell to execute malicious commands, often encoding them in Base64 to evade basic string detection. The `-e` / `-EncodedCommand` flag allows an entire script to be passed as a Base64 blob, hiding the true intent from casual inspection and simple signature-based tools.

### Execution command
cmd.exe /c powershell.exe -e JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
### System artifacts
- Sysmon Event ID: 1 (Process Create)
- Key fields:
  - Image: `C:\Windows\System32\cmd.exe`
  - CommandLine: `cmd.exe /c powershell.exe -e <base64blob>`
  - ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  - User: `WIN10-VICTIM\walid`
  - IntegrityLevel: High
  - SHA256: `B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450`
- Raw log: `logs/raw-samples/T1059-001.json`

### Detection anchor
`CommandLine` contains `-e ` or `-EncodedCommand` followed by a Base64 string, spawned by `cmd.exe` with parent `powershell.exe`. The `-e` short flag is the key IOC — legitimate PowerShell administration rarely uses encoded commands interactively.

### Wazuh default behavior
**Caught by default rules.** Rule **92057** fired at level **12**:
> "Powershell.exe spawned a powershell process which executed a base64 encoded command"
- Groups: `sysmon`, `sysmon_eid1_detections`, `windows`
- MITRE mapping: T1059.001 — Execution
- No custom rule needed. Existing rule is sufficient for detection.

### Deep Analysis

**What exact process was spawned?**
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` spawned by `cmd.exe` which was itself spawned by the parent PowerShell session running ART.

**What was the full command line?**
`cmd.exe /c powershell.exe -e JgAgACgAZwBjAG0A...` — the `-e` flag is the short form of `-EncodedCommand`. The base64 payload decodes to a `Write-Host` command but the encoding pattern is identical to real malware.

**What parent process launched it?**
`C:\Windows\System32\cmd.exe` — spawned by the ART PowerShell session. Full chain:
`powershell.exe (ART) → cmd.exe → powershell.exe -e <base64>`

**What Sysmon Event ID fired?**
EID 1 (Process Create) — captured correctly.

**What made this event unique vs normal activity?**
Three things combined:
1. `-e` / `-EncodedCommand` flag — legitimate interactive PowerShell almost never uses this
2. `cmd.exe` spawning `powershell.exe` — unusual parent/child relationship
3. High integrity level — running as elevated user

**Did Wazuh alert automatically?**
Yes — rule **92057** fired at level **12**. MITRE correctly mapped to T1059.001. No tuning needed.

**What would a false positive look like?**
Software installers or update scripts that use encoded commands for legitimate automation. Key differentiator: legitimate tools typically have a known parent process (installer.exe, msiexec.exe) not cmd.exe spawning PowerShell interactively.

**Week 3 action:** No new rule needed. Existing rule 92057 is accurate and well-mapped.

---

## T1547.001 — Registry Run Key Persistence
**Tactic:** Persistence, Privilege Escalation
**Tool:** Atomic Red Team, Test #1 (Reg Key Run)
**Date run:** 2026-05-19

### What the technique does
Attackers write a value to the Windows Registry Run key so their payload executes automatically every time the user logs in. This is one of the most common and oldest persistence mechanisms used by malware and APT groups. The key requires no elevated privileges when targeting HKCU, making it accessible to any user-level process.

### Execution command
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
### System artifacts
- Sysmon Event ID: 1 (Process Create — reg.exe spawned)
  - Image: `C:\Windows\system32\reg.exe`
  - CommandLine: `REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"`
  - ParentImage: `C:\Windows\System32\cmd.exe`
  - User: `WIN10-VICTIM\walid`
  - Wazuh rule: 92041 — "Value added to registry key has Base64-like pattern", level 10
- Sysmon Event ID: 13 (Registry Value Set)
  - Image: `C:\Windows\system32\reg.exe`
  - EventType: `SetValue`
  - TargetObject: `HKU\S-1-5-21-2438391329-815147474-3294604396-1000\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team`
  - Details: `C:\Path\AtomicRedTeam.exe`
  - RuleName: `T1060,RunKey` (tagged by SwiftOnSecurity Sysmon config)
  - User: `WIN10-VICTIM\walid`
  - Wazuh rule: 92302 — "Registry entry to be executed on next logon was modified", level 6
- Raw log: `logs/raw-samples/T1547-001.json`

### Detection anchor
`TargetObject` contains `\CurrentVersion\Run\` AND `Image` is `reg.exe` or any non-system process. The SwiftOnSecurity Sysmon config already tags this with `T1060,RunKey` in the RuleName field — making it trivial to filter. Any write to the Run key by a non-OS process is suspicious.

### Wazuh default behavior
**Caught by default rules — two alerts fired:**
- Rule **92041** at level **10** (EID 1): "Value added to registry key has Base64-like pattern"
- Rule **92302** at level **6** (EID 13): "Registry entry to be executed on next logon was modified using command line application reg.exe"
- MITRE mapping: T1547.001 — Persistence / Privilege Escalation
- No custom rule needed. Consider raising rule 92302 level to 10+ in Week 3 given persistence impact.

### Deep Analysis

**What exact process was spawned?**
`C:\Windows\system32\reg.exe` — the built-in registry editor CLI tool.

**What was the full command line?**
`REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"`

**What parent process launched it?**
`C:\Windows\System32\cmd.exe` — full parent command:
`cmd.exe /c REG ADD "HKCU\...\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"`

**What Sysmon Event IDs fired?**
EID 1 (Process Create for reg.exe) and EID 13 (Registry Value Set) — both captured correctly. SwiftOnSecurity config tagged EID 13 with `T1060,RunKey` automatically.

**What made this event unique vs normal activity?**
Three things:
1. `reg.exe` writing to `\CurrentVersion\Run\` — the classic persistence key
2. Value points to non-standard path `C:\Path\` — legitimate software uses proper install directories
3. Arbitrary value name — in real attacks this is spoofed as a legitimate app name

**Did Wazuh alert automatically?**
Yes — two rules fired. Rule 92302 correctly mapped to T1547.001. Rule 92041 fired on EID 1 for the reg.exe process create.

**What would a false positive look like?**
Legitimate software adding itself to startup via reg.exe — antivirus, backup agents, corporate tools. Key differentiator: legitimate software uses signed binaries in `Program Files`. Filter by `Details` field — if path is outside `Program Files` or `Windows`, escalate.

**Week 3 action:** Raise rule 92302 level from 6 to 10+. Add filter on `Details` field to exclude known-good paths.

---

## T1087.001 — Local Account Discovery
**Tactic:** Discovery
**Tool:** Atomic Red Team, Test #8 (Enumerate all accounts on Windows Local)
**Date run:** 2026-05-19

### What the technique does
After gaining access to a system, attackers enumerate local user accounts and groups to understand the privilege landscape. This helps identify admin accounts to target, service accounts to abuse, and other users on the machine. The technique uses built-in Windows commands requiring no special tools or downloads.

### Execution command
cmd.exe /c net user & dir c:\Users\ & cmdkey.exe /list & net localgroup "Users" & net localgroup
### System artifacts
- Sysmon Event ID: 1 (Process Create — net.exe and net1.exe)
  - Image: `C:\Windows\System32\net.exe`
  - CommandLine: `net user`, `net localgroup`, `net localgroup "Users"`
  - ParentImage: `C:\Windows\System32\cmd.exe`
  - User: `WIN10-VICTIM\walid`
  - IntegrityLevel: High
  - SHA256: `9F376759BCBCD705F726460FC4A7E2B07F310F52BAA73CAAAAA124FDDBDF993E`
  - Note: `net1.exe` also spawned as child of `net.exe` for each command
- Raw log: `logs/raw-samples/T1087-001.json`

### Detection anchor
`Image` ends in `net.exe` AND `CommandLine` contains `user` or `localgroup`, spawned by `cmd.exe` from a user context. The combination of `net user` + `net localgroup` in the same parent command line is a strong discovery signal — legitimate admin activity rarely chains both in one command.

### Wazuh default behavior
**Partially caught — wrong MITRE mapping.** Two rules fired:
- Rule **92036** at level **3**: "A C:\\Windows\\System32\\net.exe binary was started by a Windows cmd shell"
  - MITRE mapped to T1059.003 / T1574.001 — **incorrect**, should be T1087.001
- Rule **92031** at level **3**: "Discovery activity executed"
  - Generic discovery rule, no specific MITRE mapping
- Level 3 is too low for account discovery activity
- **Custom rule needed in Week 3** to correctly map net.exe user enumeration to T1087.001 with higher severity

### Deep Analysis

**What exact process was spawned?**
`C:\Windows\System32\net.exe` and `C:\Windows\System32\net1.exe` — net1 is always spawned as a child of net.exe for every net command executed.

**What was the full command line?**
`net user`, `net localgroup`, `net localgroup "Users"` — all chained in one parent cmd.exe command with `&` operators.

**What parent process launched it?**
`C:\Windows\System32\cmd.exe` — full parent command:
`cmd.exe /c net user & dir c:\Users\ & cmdkey.exe /list & net localgroup "Users" & net localgroup`

**What Sysmon Event ID fired?**
EID 1 (Process Create) — captured for both net.exe and net1.exe correctly.

**What made this event unique vs normal activity?**
The chaining of `net user` + `net localgroup` + `cmdkey /list` in a single command line is a reconnaissance pattern. Legitimate admin use typically runs one command at a time interactively, not chained enumeration. User context (`walid`) rather than SYSTEM also flags this.

**Did Wazuh alert automatically?**
Partially — rules 92036 and 92031 fired but both at level 3 with incorrect MITRE mapping. The detection exists but is miscategorized and under-severity.

**What would a false positive look like?**
IT admin scripts that enumerate users for auditing. Differentiator: admin scripts typically run as SYSTEM or a service account, not as an interactive user. User context + chained net.exe enumeration = suspicious.

**Week 3 action:** Write custom Sigma rule targeting `net.exe` with `user` or `localgroup` in CommandLine, map to T1087.001, set level 8+.

---

## T1003.001 — LSASS Credential Dumping
**Tactic:** Credential Access
**Tool:** MITRE Caldera + Out-Minidump.ps1 (served via Kali HTTP server)
**Date run:** 2026-05-19

### What the technique does
LSASS (Local Security Authority Subsystem Service) stores authentication credentials in memory. Attackers dump LSASS memory to extract password hashes, plaintext passwords, and Kerberos tickets for lateral movement and privilege escalation. This is one of the most commonly used post-exploitation techniques and a primary target for EDR solutions.

### Execution command
Caldera sent via HTTP C2 to agent `wbtfwr` (Win10-Victim):
powershell.exe -ExecutionPolicy Bypass -C "get-process lsass | Out-Minidump"
- Caldera ability: "Dump LSASS.exe Memory using Out-Minidump.ps1"
- Ability ID: `60bb6f8468aa98b75be2521861a164d5`
- Operation: `T1003-LSASS-Dump`
- Agent location: `C:\Users\Public\splunkd.exe`
- Delegated: 2026-05-19T10:47:59Z
- Collected: 2026-05-19T10:48:07Z
- Exit code: 1 (IWR blocked — VM has no internet, script never downloaded)
- Cleanup ran: `Remove-Item $env:TEMP\lsass_*.dmp` — exit code 0

Manual execution on Win10-Victim succeeded:
```powershell
. "$env:TEMP\Out-Minidump.ps1"
Get-Process lsass | Out-Minidump -DumpFilePath $env:TEMP
```
Dump file created: `%TEMP%\lsass_624.dmp` — 53,714,305 bytes, lsass PID 624.

### System artifacts
- Sysmon Event ID: 1 (Process Create — PowerShell spawning dump command)
  - Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  - CommandLine: `powershell.exe -ExecutionPolicy Bypass -C "get-process lsass | Out-Minidump"`
  - User: `WIN10-VICTIM\walid`
  - Timestamp: 2026-05-19T10:48:07
- Sysmon Event ID: 10 (Process Access) — **NOT CAPTURED** (see detection gap)
- Dump artifact: `%TEMP%\lsass_624.dmp` (53MB)
- Raw log: `logs/raw-samples/T1003-001.json`
- Caldera report: `emulation/caldera-profiles/T1003-report.json`

### Detection anchor
Primary: `TargetImage` = `lsass.exe` in Sysmon EID 10 with `GrantedAccess` = `0x1010` or `0x1FFFFF`.
Secondary: `CommandLine` contains `Out-Minidump` or `lsass` in EID 1.
Tertiary: `.dmp` file creation in `%TEMP%` via EID 11.

### Wazuh default behavior
**NOT detected.** Three gaps identified:
1. **Sysmon EID 10 not captured** — SwiftOnSecurity config has no ProcessAccess rules for lsass.exe. Zero EID 10 events in entire Sysmon log. Sysmon config must be updated in Week 3 to add lsass.exe as monitored target with GrantedAccess filter for `0x1010` and `0x1FFFFF`.
2. **No Wazuh rule fired** for the dump execution. Default rules don't detect Out-Minidump.ps1 or MiniDumpWriteDump calls.
3. **Cleanup partially detected** — rule 92021 (level 3) fired for `Remove-Item lsass*.dmp`. Attacker cleanup caught but primary attack completely missed.
- Custom Sysmon config update + custom Wazuh rule both required in Week 3.

### Deep Analysis

**What exact process was spawned?**
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` running the Out-Minidump command, spawned by the Caldera Sandcat agent (`splunkd.exe`).

**What was the full command line?**
`powershell.exe -ExecutionPolicy Bypass -C "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; ... get-process lsass | Out-Minidump"`

**What parent process launched it?**
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` — the Caldera Sandcat agent running disguised as `splunkd.exe` at `C:\Users\Public\splunkd.exe`.

**What Sysmon Event IDs fired?**
EID 1 only. EID 10 (Process Access) was NOT captured — critical gap in SwiftOnSecurity config. The config must explicitly add lsass.exe process access monitoring.

**What made this event unique vs normal activity?**
`-ExecutionPolicy Bypass` combined with `get-process lsass` in the command line is a strong IOC. No legitimate software bypasses execution policy and accesses lsass in the same command. Parent process disguised as `splunkd.exe` from `C:\Users\Public\` is also highly suspicious — legitimate Splunk runs from `Program Files`.

**Did Wazuh alert automatically?**
No. Complete detection failure for the primary technique. This is the most critical gap found in Week 2.

**What would a false positive look like?**
Security tools and AV products legitimately access lsass.exe for scanning. Differentiator: legitimate tools are signed, run as SYSTEM from known paths, and use lower GrantedAccess values. Attacker tools use `0x1010` or `0x1FFFFF` from user context and non-standard paths.

**Week 3 action:**
1. Update Sysmon config to add ProcessAccess rule for lsass.exe targeting GrantedAccess `0x1010` and `0x1FFFFF`
2. Write Wazuh rule for EID 10 targeting lsass.exe
3. Write Sigma rule: CommandLine contains `lsass` AND `-ExecutionPolicy Bypass`

---

## IOC Summary — All 4 Techniques

| Technique | Primary IOC | Sysmon EID | Wazuh Rule | Level | False Positive Risk | Week 3 Action |
|---|---|---|---|---|---|---|
| T1059.001 | CommandLine contains `-e <base64>` | 1 | 92057 | 12 | Low — `-e` rare in legit use | None needed |
| T1547.001 | TargetObject contains `\CurrentVersion\Run\` | 13 | 92302 | 6 | Medium — some software uses reg.exe | Raise level to 10+ |
| T1087.001 | net.exe CommandLine contains `user`/`localgroup` | 1 | 92036 (wrong MITRE) | 3 | Medium — IT admin scripts | Custom rule, remap to T1087.001 |
| T1003.001 | lsass.exe accessed / CommandLine contains `lsass` | 10 (missing) | None | — | Low — context makes it clear | Update Sysmon config + new rule |

---

## Week 2 Detection Gap Summary

| Gap | Impact | Fix in Week 3 |
|---|---|---|
| Sysmon EID 10 not configured for lsass.exe | T1003.001 completely invisible at process access level | Add ProcessAccess rule to sysmon config |
| Rule 92036 wrong MITRE mapping for net.exe | T1087.001 miscategorized as T1059.003 | Custom Sigma rule with correct T1087.001 mapping |
| Rule 92302 level too low (6) for persistence | T1547.001 may be missed in high-volume environments | Tune rule level to 10+ |
| No rule for Out-Minidump / MiniDumpWriteDump | LSASS dump method undetected | New Wazuh rule targeting lsass dump patterns |
EOF