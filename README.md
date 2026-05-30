# 🔐 ADLockoutBuster

**The professional-grade Account Lockout Source Finder for Active Directory environments.**

Built by Techify · Morris James

---

## What It Does

ADLockoutBuster hunts down *exactly* what is causing AD account lockouts — the machine, IP address, application, service, or scheduled task responsible — and presents everything in a clean, dark-themed desktop UI.

### Why This Beats Microsoft's Tools

| Feature | Microsoft LockoutStatus | ADLockoutBuster |
|---|---|---|
| Beautiful modern UI | ❌ | ✅ Dark theme, cards, color-coded events |
| Multi-DC scan at once | Partial | ✅ All DCs in parallel |
| Netlogon.log parser | ❌ | ✅ Built-in |
| Service/Task detection | ❌ | ✅ Auto-scans services & scheduled tasks |
| Password spray detection | ❌ | ✅ Built-in with configurable threshold |
| One-click unlock | ❌ | ✅ Unlock directly from the app |
| Source analysis report | ❌ | ✅ Plain-English cause summary |
| Portable (no install) | ❌ | ✅ Single `.exe` via build.bat |
| Export CSV / JSON / TXT | ❌ | ✅ Full export |
| Real-time live monitor | ❌ | ✅ 30-second polling |

---

## Quick Start

### Option A — Run with Python (recommended for dev)

```
pip install -r requirements.txt
python lockout_finder.py
```

### Option B — Build portable .exe (no Python needed anywhere)

```
build.bat
```
Output: `dist\ADLockoutBuster.exe` — copy anywhere, runs standalone.

---

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+ (built into Windows)
- **For AD features:** Domain-joined machine or network access to DCs
- **For AD module features:** RSAT `ActiveDirectory` module installed
  - Workstations: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
  - Servers: `Install-WindowsFeature RSAT-AD-PowerShell`
- Python 3.10+ (only needed to run from source; not needed for .exe)

---

## Pages Overview

| Page | Purpose |
|---|---|
| **Dashboard** | Quick stats + recent events table + spray alerts |
| **Investigate** | Deep-dive a single account — timeline, source summary, AD info, services, Netlogon |
| **Active Lockouts** | All currently locked accounts + one-click unlock |
| **Live Monitor** | Real-time 30-second polling of all DCs |
| **DC Manager** | Auto-discover or manually add domain controllers |
| **Reports** | Export to CSV, JSON, or plain-text report |
| **Settings** | Tune scan windows, spray thresholds, Netlogon options |

---

## Key Events Tracked

| Event ID | Name | What It Tells You |
|---|---|---|
| 4740 | Account Locked Out | The lockout itself — caller computer recorded here on PDC |
| 4625 | Failed Logon | Every individual failed attempt — includes source IP/machine |
| 4771 | Kerberos Pre-Auth Failed | Kerberos-specific failures — includes client IP |
| 4776 | NTLM Credential Validation | NTLM-based failures — common for mapped drives & legacy apps |
| 4648 | Explicit Credentials Used | RunAs / Credential Manager / applications using saved creds |

---

## Common Lockout Causes (What to Look For)

| Logon Type | Typical Cause |
|---|---|
| **Service (5)** | Windows service using old saved password |
| **Batch (4)** | Scheduled task using expired credentials |
| **Network (3)** | Mapped drive, file share, or web app using cached creds |
| **Unlock (7)** | Locked workstation trying old cached password |
| **Remote Interactive (10)** | Saved RDP credentials with old password |
| **Network Cleartext (8)** | IIS app pool or legacy application sending old password |

---

## Documentation

- [User Guide](docs/USER_GUIDE.md) — step-by-step usage
- [How It Works](docs/HOW_IT_WORKS.md) — technical deep-dive
- [Architecture](docs/ARCHITECTURE.md) — code structure and design decisions
- [Changelog](docs/CHANGELOG.md) — version history

---

## Permissions Required

| Feature | Required Permission |
|---|---|
| Read Security event logs on DCs | `Event Log Readers` group on each DC |
| AD account queries | `Domain Users` (read-only) |
| Unlock accounts | `Account Operators` or delegated reset rights |
| Netlogon.log access | Local Administrator on DCs (for `\\DC\ADMIN$` share) |
| Service/Task scan | Local Administrator on the target machine |

---

## License

MIT — free for personal and commercial use.
