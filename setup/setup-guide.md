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