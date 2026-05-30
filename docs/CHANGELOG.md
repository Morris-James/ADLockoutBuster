# Changelog

All notable changes to ADLockoutBuster are documented here.

## [1.1.0] — 2026-05-30

### Added
- **Event Timeline Chart** — Custom hourly bar chart on Dashboard. Red = lockouts, orange = failed logons, blue = other. Hover any bar to see per-event-type counts. Instantly shows whether lockouts are happening at a specific time of day (scheduled task pattern) or continuously (service with stale password).
- **Remote Machine Scanner** — Services & Tasks tab now has a "Scan Remote Machine" input. Enter the source machine identified in the investigation and scan it directly for services/tasks running as the locked account. Requires WMI access or PSRemoting to the target machine.
- **System Tray** — App minimizes to system tray when Live Monitor is active and you close the window. Shows a Windows notification toast on every lockout. Double-click the tray icon to restore. Right-click for Show/Quit menu. Keeps monitoring in the background without a window.
- **Portable EXE** — `dist\ADLockoutBuster.exe` (34 MB, no Python required, copy anywhere)

### Changed
- Services & Tasks table expanded to 5 columns (added Detail/path column)
- Service rows highlighted orange, Scheduled Task rows highlighted purple for quick visual distinction
- Monitor lockout alerts now also fire as tray notifications even when the window is minimized

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
