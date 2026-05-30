# ADLockoutBuster — User Guide

## Table of Contents

1. [Installation](#installation)
2. [First Launch](#first-launch)
3. [Step 1 — Configure Domain Controllers](#step-1--configure-domain-controllers)
4. [Step 2 — Dashboard Quick Scan](#step-2--dashboard-quick-scan)
5. [Step 3 — Investigate a Specific Account](#step-3--investigate-a-specific-account)
6. [Active Lockouts Page](#active-lockouts-page)
7. [Live Monitor](#live-monitor)
8. [Interpreting Results](#interpreting-results)
9. [Common Lockout Scenarios](#common-lockout-scenarios)
10. [Exporting Reports](#exporting-reports)
11. [Enabling Netlogon Debug Logging](#enabling-netlogon-debug-logging)
12. [Troubleshooting](#troubleshooting)

---

## Installation

### Run from Python source

```powershell
pip install -r requirements.txt
python lockout_finder.py
```

### Build portable .exe

Double-click `build.bat`. The output `dist\ADLockoutBuster.exe` is fully portable — copy it to a USB drive, a server, or any Windows machine.

---

## First Launch

When ADLockoutBuster opens you will see the **Dashboard** page. Before scanning, you need to tell it which domain controllers to query.

> **Tip:** The status bar at the bottom shows your detected domain name on startup.

---

## Step 1 — Configure Domain Controllers

1. Click **🖥 DC Manager** in the sidebar.
2. Click **Auto-Discover DCs from AD** — the tool queries Active Directory for all domain controllers and identifies the PDC Emulator (shown in orange).
3. If auto-discovery fails (not domain-joined, AD module missing), type a DC hostname or IP in the manual field and click **Add**.
4. Click **🏓 Ping All** to verify connectivity.

> **Important:** The **PDC Emulator** is the most critical DC to include — Event 4740 (Account Locked Out) is always written on the PDC Emulator. If you only add one DC, make it the PDC.

---

## Step 2 — Dashboard Quick Scan

1. Go to **📊 Dashboard**.
2. Click **⟳ Quick Scan (All DCs)**.
3. The tool scans all configured DCs for the last 24 hours (configurable in Settings).
4. The five stat cards update:
   - **Account Lockouts** — Event 4740 count
   - **Failed Logons** — Event 4625 count
   - **Affected Users** — unique usernames
   - **Unique Sources** — unique source machines/IPs
   - **Spray Alerts** — potential password spray attacks detected

If a **red spray alert banner** appears, multiple accounts are failing from the same source — this indicates either a password spray attack or a misconfigured application.

---

## Step 3 — Investigate a Specific Account

This is the most powerful feature. Use it when you have a specific account that keeps locking out.

1. Go to **🔍 Investigate**.
2. Enter the **username** (SAM account name, e.g. `john.doe`).
3. Select the time range (default: Last 24 hours).
4. Click **🔍 Investigate**.

### Tabs in the Investigate Page

#### 📅 Event Timeline
A chronological table of every lockout-related event for this user. Color coded:
- **Red** = Account Locked Out (4740) — the actual lockout
- **Orange** = Failed Logon (4625) — the attempts causing lockout
- **Deep Orange** = Kerberos failure (4771)

Double-click any row to see full event details including raw status codes.

#### 🎯 Source Summary
A plain-English analysis including:
- **Top source machines/IPs** (sorted by event count)
- **IP addresses with reverse DNS** — tells you the real hostname behind an IP
- **Logon type breakdown** with explanations (e.g. "Logon Type 5 = Service — a Windows Service is using stale credentials")
- **Authentication package breakdown** — heavy NTLM suggests mapped drives; Kerberos failures suggest password mismatch
- **Failure reason codes** decoded
- **Most likely causes** listed at the bottom

#### 🏢 AD Account Info
Live Active Directory data for the account:
- Current locked status
- Bad password count
- Last bad password attempt timestamp
- Password expiry
- Account enabled/disabled status

Click **🔓 Unlock Account** to unlock directly from this tab.

#### ⚙ Services & Tasks
Scans the **local machine** for Windows Services and Scheduled Tasks running as this account. These are a very common cause of lockouts after a password change — the service keeps trying the old password.

> Note: This only scans the machine ADLockoutBuster is running on. To check a remote machine, run the tool there, or use: `Get-WmiObject Win32_Service | Where StartName -like "*username*"`

#### 📜 Netlogon Logs
If you have admin share access to the DCs (`\\DC\ADMIN$`), this tab shows raw Netlogon.log entries for the account. Netlogon logs can reveal the source even when event logs don't have the caller computer populated.

---

## Active Lockouts Page

1. Click **🔒 Active Lockouts**.
2. Click **⟳ Refresh** to query AD for all currently locked accounts.
3. The table shows:
   - Username
   - Bad password count (how many wrong attempts)
   - Last bad password attempt time
   - Last successful logon date

4. Select one or more rows and click **🔓 Unlock Selected** to unlock in bulk.

---

## Live Monitor

Use this to catch lockouts as they happen in real time.

1. Configure DCs first.
2. Go to **📡 Live Monitor**.
3. Click **▶ Start Monitoring**.
4. The tool polls all DCs every 30 seconds and streams new events into the table.
5. Enable **Popup alert on lockout** to get an immediate dialog when any account locks out.

---

## Interpreting Results

### Source Machine is Empty / "—"

This is common. It means:
- The event was logged from a **Kerberos** authentication (4771) rather than NTLM — Kerberos events record the client IP, not hostname
- The source machine field wasn't populated in the event log

**Fix:** Look at the **IP address** column instead. Use the Source Summary tab which automatically does reverse DNS lookups on IPs.

### Multiple Events from "—" Source with Same IP

The source machine is blank but you have an IP. Use:
```powershell
[System.Net.Dns]::GetHostEntry("192.168.1.50")
```
Or ping with -a: `ping -a 192.168.1.50`

### Very High Count from One Machine

This almost always means a **service or scheduled task** on that machine is using the old password. RDP to that machine and check:
- Services console (services.msc) — filter by account
- Task Scheduler — check Principal/Account

### Logon Type = 3 (Network) with NTLM

Classic **mapped drive** or **network share** with saved/old credentials. Check:
```powershell
net use  # on the source machine
```
Look for credentials in Credential Manager:
```
Control Panel → Credential Manager → Windows Credentials
```

### Logon Type = 5 (Service) or 4 (Batch)

A service or scheduled task. The Services & Tasks tab will show if it's on the local machine. For remote machines, check via:
```powershell
Get-WmiObject Win32_Service -Computer MACHINENAME | Where StartName -like "*username*"
```

---

## Common Lockout Scenarios

### Scenario 1: Password just changed — account keeps relocking

**Cause:** Service, scheduled task, or mapped drive still using old password.

**Steps:**
1. Check the Source Summary tab for the top source machine
2. RDP to that machine
3. Open Services (services.msc) → find services running as the account
4. Update the password in the service properties
5. Check Task Scheduler
6. Check Credential Manager (Windows Credentials)

### Scenario 2: Account locks at specific time each day

**Cause:** Scheduled task using old credentials.

**Steps:**
1. Check the Event Timeline — note the time pattern
2. Cross-reference with scheduled tasks on the source machine

### Scenario 3: Account locks from a mobile device

**Cause:** Phone/tablet with Exchange ActiveSync configured with old password.

**Steps:**
1. Look for source IPs that belong to Exchange/OWA servers
2. Check Exchange Management Console → ActiveSync device partnerships
3. The user needs to update their email password on their device

### Scenario 4: Spray alert showing many different accounts from one IP

**Cause:** External brute-force attempt or misconfigured application.

**Steps:**
1. Immediately check if the IP is internal or external
2. If external: block at firewall, check VPN
3. If internal: identify the machine and investigate

---

## Exporting Reports

Go to **📋 Reports**:

- **Export CSV** — All events as a spreadsheet. Import into Excel for pivot tables.
- **Export TXT** — Pre-formatted statistics report you can paste into a ticket.
- **Export JSON** — Machine-readable format for SIEM ingestion or scripting.

---

## Enabling Netlogon Debug Logging

For the deepest source tracing, enable Netlogon logging on all DCs:

```powershell
# Run on each DC (or via remote PowerShell)
nltest /dbflag:0x2080ffff

# Log location:
# C:\Windows\debug\netlogon.log
# C:\Windows\debug\netlogon.bak
```

To disable:
```powershell
nltest /dbflag:0x0
```

> Netlogon logs record the source machine even in cases where the Security event log doesn't.

---

## Troubleshooting

### "No events found" after scan

- Check DC connectivity: DC Manager → Ping All
- Verify you have Event Log Reader rights on the DCs
- Try adding `localhost` as a DC if running on a DC itself
- Check PowerShell execution policy: `Get-ExecutionPolicy`

### AD Account Info tab shows nothing

- The `ActiveDirectory` PowerShell module is not installed
- Install: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
- Or on a server: `Install-WindowsFeature RSAT-AD-PowerShell`

### Unlock Account fails

- Your account needs `Account Operators` membership or delegated "Reset Password" rights in AD
- Check AD delegation on the OU containing the user

### Build.bat fails

- Ensure Python 3.10+ is installed and in PATH
- Run as Administrator if you get permission errors
- PyInstaller may need Visual C++ Redistributable

### Spray detection false positives

- Go to Settings and increase the **spray threshold** (default: 5 users in 10 minutes)
- A shared IP (VPN gateway, NAT) will show many users — this is expected
