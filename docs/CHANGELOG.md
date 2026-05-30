# Changelog

All notable changes to ADLockoutBuster are documented here.

## [1.0.0] — 2026-05-30

### Initial Release

#### Features
- **Dashboard** — stat cards for lockouts, failed logons, affected users, unique sources, and spray alerts
- **Investigate** — per-account deep analysis with 5 tabs: Event Timeline, Source Summary, AD Account Info, Services & Tasks, Netlogon Logs
- **Active Lockouts** — query all currently locked AD accounts with bulk unlock
- **Live Monitor** — real-time 30-second polling with lockout popup alerts
- **DC Manager** — auto-discover DCs from AD, manual add, ping test, PDC Emulator identification
- **Reports** — export to CSV, JSON, and plain-text report
- **Settings** — configurable scan window, spray detection thresholds, Netlogon parsing toggle

#### Technical
- Single-file Python application (no extra modules beyond PyQt6)
- All Windows queries via PowerShell (no pywin32 dependency)
- Multi-threaded scanning with QThread workers
- GitHub-dark inspired stylesheet
- PyInstaller portable .exe build script

#### Event Coverage
- 4625 — Failed Logon (all failure types)
- 4740 — Account Locked Out
- 4771 — Kerberos Pre-Authentication Failed
- 4776 — NTLM Credential Validation
- 4648 — Logon with Explicit Credentials

#### Lockout Source Detection
- Source machine name (WorkstationName / CallerComputerName)
- Source IP with automatic reverse DNS resolution
- Logon type with plain-English cause explanation
- NTLM vs Kerberos authentication package analysis
- NTSTATUS / SubStatus code decoding
- Service and scheduled task scanning
- Netlogon.log parsing
- Password spray detection (sliding window algorithm)
