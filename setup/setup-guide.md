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
- **Fix:** `sudo modprobe vboxnetadp && sudo vboxmanage hostonlyif create`