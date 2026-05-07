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