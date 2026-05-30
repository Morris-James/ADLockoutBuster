# ADLockoutBuster — Architecture

## File Structure

```
ADLockoutBuster/
├── lockout_finder.py       # Single-file application (all code)
├── requirements.txt        # Python dependencies (PyQt6 only)
├── build.bat               # Builds portable .exe with PyInstaller
├── .gitignore
├── README.md
├── docs/
│   ├── USER_GUIDE.md
│   ├── HOW_IT_WORKS.md
│   ├── ARCHITECTURE.md     ← you are here
│   └── CHANGELOG.md
└── memory/                 # Claude AI project context (isolated)
```

## Application Structure (lockout_finder.py)

The application is intentionally kept as a **single Python file** to maximize portability. The internal structure follows a layered pattern:

```
lockout_finder.py
│
├── DATA MODELS
│   ├── LockoutEvent        — Immutable event record
│   ├── DCInfo              — Domain controller metadata
│   └── SprayAlert          — Password spray detection result
│
├── CONSTANTS
│   ├── STATUS_CODES        — NTSTATUS → human-readable dict
│   └── LOCKOUT_CAUSES      — Logon type → explanation dict
│
├── CORE ENGINE (LockoutEngine)
│   ├── build_filter_xml()  — Generates WinEvent XML query
│   ├── scan_events()       — PowerShell event collection
│   ├── _parse_event()      — JSON → LockoutEvent parsing
│   ├── get_domain_controllers()
│   ├── get_pdc_emulator()
│   ├── get_locked_accounts()
│   ├── unlock_account()
│   ├── get_ad_account_info()
│   ├── get_services_for_account()
│   ├── parse_netlogon_logs()
│   ├── detect_spray_attacks()
│   └── analyze_lockout_source()
│
├── WORKER THREADS
│   ├── ScanWorker          — Non-blocking event collection
│   ├── DCDiscoveryWorker   — Non-blocking DC enumeration
│   ├── MonitorWorker       — Periodic polling (30s intervals)
│   └── LockedAccountsWorker — Non-blocking AD query
│
├── STYLESHEET (APP_STYLE)
│   └── GitHub-dark inspired CSS for Qt widgets
│
├── UI COMPONENTS (reusable)
│   ├── StatCard            — Metric card widget
│   ├── EventTable          — Color-coded sortable event table
│   └── EventDetailDialog   — Full event detail popup
│
├── PAGES
│   ├── DashboardPage       — Overview + stat cards + spray alerts
│   ├── InvestigatePage     — Per-account deep analysis
│   ├── ActiveLockoutsPage  — Currently locked AD accounts
│   ├── MonitorPage         — Real-time event stream
│   ├── DCManagerPage       — DC configuration
│   ├── ReportsPage         — Export functionality
│   └── SettingsPage        — Persisted configuration
│
└── MAIN WINDOW (MainWindow)
    ├── Sidebar navigation
    ├── Stacked page container
    ├── Status bar + progress bar
    └── Signal/slot wiring
```

## Key Design Decisions

### Why PowerShell Instead of win32evtlog?

`win32evtlog` from `pywin32` requires an additional dependency and has limited remote querying support. PowerShell's `Get-WinEvent` with XML filters:

- Is built into all supported Windows versions
- Works identically for local and remote queries
- Returns structured data easily serialized as JSON
- Is well-documented and supported by Microsoft

This reduces requirements.txt to a single line: `PyQt6`.

### Why a Single Python File?

For a security/sysadmin tool:
- Easy to audit (no hidden imports across files)
- Easy to deploy (copy one file)
- Easy to run on domain controllers (no `pip install` dance)
- PyInstaller packages it cleanly into one `.exe`

### Why PyQt6?

- Best-looking native Qt widgets on Windows
- Full dark mode support via stylesheets
- QThread for real non-blocking background work
- Widely used, well-documented
- No browser/Electron dependency

### Why Not a Web App?

Browser-based tools (Flask + React) look great but:
- Opening a browser on a DC feels wrong
- Single .exe is simpler to distribute to sysadmins
- No need for Node.js/npm build pipeline
- Port conflicts on shared servers

### Thread Safety

All inter-thread communication uses Qt's signal/slot mechanism, which is thread-safe. Worker threads emit signals; the UI thread processes them. No shared mutable state outside of signal parameters.

## Settings Persistence

Settings are stored in:
```
%USERPROFILE%\.adlockoutbuster_settings.json
```

This location:
- Persists across runs
- Is per-user (no admin rights needed)
- Does NOT affect the portable .exe location

## Signal Flow Diagram

```
User clicks "Quick Scan"
    → DashboardPage.scan_requested (signal)
    → MainWindow._quick_scan()
    → MainWindow._run_scan()
    → ScanWorker.start()            [background thread]
        → LockoutEngine.scan_events() × N DCs
        → ScanWorker.complete (signal)
    → MainWindow._on_scan_done()
        → DashboardPage.update()
        → InvestigatePage.update_events()
        → ReportsPage.update_events()
```

## Adding New Features

### Add a new event ID to scan

In `LockoutEngine.SCAN_EVENT_IDS`:
```python
SCAN_EVENT_IDS = [4625, 4740, 4771, 4776, 4648, 4647]  # add 4647 here
```

### Add a new page

1. Create a `class MyPage(QWidget)` with `def _build(self)`
2. Add to `MainWindow._build_ui()` stack
3. Add to `_page_map` dict
4. Add nav button to `nav_items` list

### Add a new export format

In `ReportsPage._build()`:
```python
QPushButton("Export XML").clicked.connect(self._export_xml)
```
Then implement `_export_xml()`.
