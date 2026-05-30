---
name: project-adlockoutbuster
description: "ADLockoutBuster — AD account lockout source finder tool, v1.0.0, GitHub and Obsidian synced"
metadata: 
  node_type: memory
  type: project
  originSessionId: 2bb3fd33-9e5c-43b7-be28-e8b894cf72c5
---

ADLockoutBuster is a Windows desktop tool for finding the source of Active Directory account lockouts.

**Project location:** `C:\Users\MorrisJames\Documents\Claude_Projects\ADLockoutBuster\`
**GitHub repo:** https://github.com/Morris-James/ADLockoutBuster
**Obsidian notes:** `C:\Users\MorrisJames\Documents\Obsidian Vault\ADLockoutBuster\`

**Why:** Morris wanted a better version of Microsoft's LockoutStatus.exe with a beautiful UI, more thorough source detection (Netlogon, services, tasks, spray detection), and portability.

**Tech stack:** Python 3.12 + PyQt6 + PowerShell for all Windows queries. Single file (`lockout_finder.py`). Portable exe via `build.bat`.

**Key features built:**
- Multi-DC event scanning (4625, 4740, 4771, 4776, 4648)
- Password spray detection (sliding window algorithm)
- Netlogon.log parser
- Service/scheduled task detection
- AD account info + one-click unlock
- Real-time live monitor (30s polling)
- Export: CSV, JSON, TXT

**How to apply:** When continuing this project, sync changes to GitHub after each session and update Obsidian docs if documentation changes.
