#!/usr/bin/env python3
"""
ADLockoutBuster - Account Lockout Source Finder
Author: Morris James / Techify
Version: 1.0.0
"""

import sys
import os
import subprocess
import json
import re
import csv
import time
import socket
import datetime
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass, field

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QLineEdit, QComboBox, QTableWidget,
        QTableWidgetItem, QHeaderView, QAbstractItemView, QFrame,
        QStackedWidget, QTextEdit, QProgressBar, QStatusBar, QSplitter,
        QTabWidget, QCheckBox, QSpinBox, QFormLayout, QFileDialog,
        QMessageBox, QMenu, QListWidget, QListWidgetItem, QScrollArea,
        QGroupBox, QDialog, QDialogButtonBox
    )
    from PyQt6.QtCore import (
        Qt, QThread, pyqtSignal, QTimer, QSize, QPoint
    )
    from PyQt6.QtGui import (
        QColor, QFont, QIcon, QPixmap, QPainter, QBrush, QPalette,
        QAction, QFontDatabase
    )
except ImportError:
    print("PyQt6 not installed. Run: pip install PyQt6")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LockoutEvent:
    timestamp: datetime.datetime
    event_id: int
    username: str
    domain: str = ""
    caller_machine: str = ""
    caller_ip: str = ""
    logon_type: int = 0
    auth_package: str = ""
    failure_reason: str = ""
    process_name: str = ""
    source_dc: str = ""
    status_code: str = ""
    sub_status_code: str = ""
    raw_data: dict = field(default_factory=dict)

    @property
    def event_type(self) -> str:
        return {
            4625: "Failed Logon",
            4740: "Account Locked Out",
            4771: "Kerberos Pre-Auth Failed",
            4776: "NTLM Auth Attempted",
            4648: "Explicit Credentials Used",
        }.get(self.event_id, f"Event {self.event_id}")

    @property
    def logon_type_name(self) -> str:
        return {
            2: "Interactive",
            3: "Network",
            4: "Batch",
            5: "Service",
            7: "Unlock",
            8: "Network Cleartext",
            9: "New Credentials",
            10: "Remote Interactive (RDP)",
            11: "Cached Interactive",
        }.get(self.logon_type, str(self.logon_type) if self.logon_type else "-")

    @property
    def severity_color(self) -> str:
        return {
            4740: "#ef5350",
            4771: "#ff7043",
            4625: "#ffa726",
            4776: "#ffca28",
            4648: "#ab47bc",
        }.get(self.event_id, "#e0e0e0")


@dataclass
class DCInfo:
    hostname: str
    ip: str = ""
    is_pdc: bool = False
    status: str = "Unknown"
    event_count: int = 0


@dataclass
class SprayAlert:
    source_ip: str
    source_machine: str
    affected_users: List[str]
    event_count: int
    first_seen: datetime.datetime
    last_seen: datetime.datetime


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & STATUS CODES
# ─────────────────────────────────────────────────────────────────────────────

STATUS_CODES = {
    "0xc000006a": "Wrong Password",
    "0xc0000064": "Username Does Not Exist",
    "0xc000006d": "Generic Logon Failure",
    "0xc000006e": "Account Restriction",
    "0xc000006f": "Invalid Logon Hours",
    "0xc0000070": "Invalid Workstation",
    "0xc0000071": "Password Expired",
    "0xc0000072": "Account Disabled",
    "0xc0000193": "Account Expired",
    "0xc0000224": "Must Change Password at Next Logon",
    "0xc0000234": "Account Locked Out",
    "0x0": "Success",
    "0x6": "Username Does Not Exist (Kerberos)",
    "0x12": "Account Disabled/Locked/Expired (Kerberos)",
    "0x17": "Password Expired (Kerberos)",
    "0x18": "Wrong Password (Kerberos)",
    "0x25": "Clock Skew Too Large (Kerberos)",
}

LOCKOUT_CAUSES = {
    "Service": "A Windows Service is using saved (now incorrect) credentials for this account.",
    "Batch": "A Scheduled Task is using saved (now incorrect) credentials for this account.",
    "Network": "A network resource (mapped drive, share, or application) is authenticating as this user.",
    "Remote Interactive (RDP)": "A Remote Desktop session is saved/running with stale credentials.",
    "Unlock": "A locked workstation is trying to unlock using old cached credentials.",
    "Interactive": "Direct login attempt with wrong password — check the source machine.",
    "Network Cleartext": "An application is sending credentials in cleartext — likely IIS or a legacy app.",
    "New Credentials": "RunAs or a credential-based application is using saved credentials.",
}


# ─────────────────────────────────────────────────────────────────────────────
# CORE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class LockoutEngine:
    """Core engine: all event log scanning, AD queries, and analysis."""

    SCAN_EVENT_IDS = [4625, 4740, 4771, 4776, 4648]

    def build_filter_xml(self, hours: float, username: str = "",
                          event_ids: list = None, since: datetime.datetime = None) -> str:
        if since:
            start_time = since.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        else:
            start = datetime.datetime.utcnow() - datetime.timedelta(hours=max(hours, 0.083))
            start_time = start.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        ids = event_ids or self.SCAN_EVENT_IDS
        id_filter = " or ".join(f"EventID={eid}" for eid in ids)

        user_filter = ""
        if username:
            safe = username.replace("'", "\\'")
            user_filter = (
                " and *[EventData[Data[@Name='TargetUserName'] and "
                f"(Data='{safe}' or Data='{safe.upper()}' or Data='{safe.lower()}')]]"
            )

        return f"""<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[({id_filter}) and TimeCreated[@SystemTime&gt;='{start_time}']] {user_filter}]</Select>
  </Query>
</QueryList>"""

    def scan_events(self, server: str, hours: float, username: str = "",
                    since: datetime.datetime = None,
                    progress_fn=None) -> List[LockoutEvent]:
        filter_xml = self.build_filter_xml(hours, username, since=since)
        comp_param = f"-ComputerName '{server}'" if server.lower() not in ("localhost", "127.0.0.1", socket.gethostname().lower()) else ""

        script = f"""
$ErrorActionPreference = 'SilentlyContinue'
try {{
    $events = Get-WinEvent {comp_param} -FilterXml @'
{filter_xml}
'@ -ErrorAction SilentlyContinue

    $result = foreach ($e in $events) {{
        $xml = [xml]$e.ToXml()
        $d = @{{}}
        foreach ($node in $xml.Event.EventData.Data) {{
            if ($node.Name) {{ $d[$node.Name] = $node.'#text' }}
        }}
        [PSCustomObject]@{{
            T  = $e.TimeCreated.ToUniversalTime().ToString('o')
            ID = $e.Id
            UN = $d['TargetUserName']
            DN = $d['TargetDomainName']
            WN = $d['WorkstationName']
            IP = $d['IpAddress']
            LT = $d['LogonType']
            AP = $d['AuthenticationPackageName']
            FR = $d['FailureReason']
            PN = $d['ProcessName']
            ST = $d['Status']
            SS = $d['SubStatus']
            SU = $d['SubjectUserName']
            CC = $d['CallerComputerName']
            KC = $d['Keylength']
        }}
    }}
    if ($result) {{ $result | ConvertTo-Json -Depth 2 -Compress }}
}} catch {{
    Write-Error $_.Exception.Message
}}
"""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-Command", script],
                capture_output=True, text=True, timeout=120
            )

            if not r.stdout.strip():
                if r.stderr and progress_fn:
                    progress_fn(f"  Warning on {server}: {r.stderr.strip()[:120]}")
                return []

            raw = json.loads(r.stdout.strip())
            if isinstance(raw, dict):
                raw = [raw]

            events = []
            for item in raw:
                ev = self._parse_event(item, server)
                if ev:
                    events.append(ev)
            return events

        except subprocess.TimeoutExpired:
            if progress_fn:
                progress_fn(f"  Timeout scanning {server}")
            return []
        except json.JSONDecodeError:
            return []
        except Exception as e:
            if progress_fn:
                progress_fn(f"  Error on {server}: {e}")
            return []

    def _parse_event(self, item: dict, source_dc: str) -> Optional[LockoutEvent]:
        try:
            ts_str = item.get('T', '')
            ts = datetime.datetime.fromisoformat(ts_str.replace('Z', '+00:00')).replace(tzinfo=None) if ts_str else datetime.datetime.utcnow()

            event_id = int(item.get('ID', 0))
            username = (item.get('UN') or item.get('SU') or '').strip()

            skip_names = {'', '-', 'system', 'anonymous logon', 'local service',
                          'network service', 'dwa', 'iis apppool\\defaultapppool'}
            if not username or username.lower() in skip_names or username.endswith('$'):
                return None

            caller = (item.get('WN') or item.get('CC') or '').strip()
            ip = (item.get('IP') or '').strip()
            for bad in ('-', 'NULL', 'null', '::1', '127.0.0.1', '', '0.0.0.0'):
                if caller == bad:
                    caller = ''
                if ip == bad:
                    ip = ''

            logon_type = 0
            try:
                lt = item.get('LT')
                if lt:
                    logon_type = int(lt)
            except (ValueError, TypeError):
                pass

            status = (item.get('ST') or '').lower()
            sub = (item.get('SS') or '').lower()
            failure_reason = ''
            if status:
                failure_reason = STATUS_CODES.get(status, status.upper())
            if sub and sub not in ('0x0', '0x00000000', ''):
                sr = STATUS_CODES.get(sub, sub.upper())
                failure_reason = f"{failure_reason} / {sr}" if failure_reason and sr != failure_reason else failure_reason or sr

            process = (item.get('PN') or '').strip()
            if process in ('-', 'NULL', ''):
                process = ''

            return LockoutEvent(
                timestamp=ts,
                event_id=event_id,
                username=username,
                domain=(item.get('DN') or '').strip(),
                caller_machine=caller,
                caller_ip=ip,
                logon_type=logon_type,
                auth_package=(item.get('AP') or '').strip(),
                failure_reason=failure_reason,
                process_name=process,
                source_dc=source_dc,
                status_code=status,
                sub_status_code=sub,
                raw_data=item,
            )
        except Exception:
            return None

    def get_domain_controllers(self) -> List[str]:
        dcs = []
        scripts = [
            "nltest /dclist: 2>$null | ForEach-Object { if ($_ -match '\\\\(\\S+)') { $matches[1] } }",
            "(Get-ADDomain -ErrorAction SilentlyContinue).ReplicaDirectoryServers | ForEach-Object { $_ }",
            "([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | Select-Object -Expand Name) 2>$null",
        ]
        for ps in scripts:
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                    capture_output=True, text=True, timeout=20
                )
                for line in r.stdout.splitlines():
                    dc = line.strip().rstrip('.')
                    if dc and dc not in dcs and '.' in dc or (dc and len(dc) > 2):
                        dcs.append(dc)
                if dcs:
                    break
            except Exception:
                continue
        return dcs

    def get_pdc_emulator(self) -> str:
        scripts = [
            "(Get-ADDomain -ErrorAction SilentlyContinue).PDCEmulator",
            "([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name) 2>$null",
        ]
        for ps in scripts:
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                    capture_output=True, text=True, timeout=15
                )
                pdc = r.stdout.strip().rstrip('.')
                if pdc:
                    return pdc
            except Exception:
                continue
        return ""

    def get_locked_accounts(self) -> List[dict]:
        ps = """
$ErrorActionPreference = 'SilentlyContinue'
try {
    Search-ADAccount -LockedOut -ErrorAction SilentlyContinue |
        Select-Object SamAccountName, DistinguishedName, LastLogonDate,
            @{N='BadLogonCount';E={(Get-ADUser $_.SamAccountName -Properties BadLogonCount -ErrorAction SilentlyContinue).BadLogonCount}},
            @{N='LastBadPwd';E={(Get-ADUser $_.SamAccountName -Properties LastBadPasswordAttempt -ErrorAction SilentlyContinue).LastBadPasswordAttempt}} |
        ConvertTo-Json -Depth 2 -Compress
} catch {
    @() | ConvertTo-Json
}
"""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=30
            )
            if r.stdout.strip():
                data = json.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                return data or []
        except Exception:
            pass
        return []

    def unlock_account(self, username: str) -> tuple[bool, str]:
        ps = f"Unlock-ADAccount -Identity '{username}' -ErrorAction Stop; Write-Output 'OK'"
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=20
            )
            if 'OK' in r.stdout:
                return True, "Account unlocked successfully."
            return False, r.stderr.strip() or "Unknown error"
        except Exception as e:
            return False, str(e)

    def get_ad_account_info(self, username: str) -> dict:
        ps = f"""
Get-ADUser '{username}' -Properties LockedOut, BadLogonCount, LastBadPasswordAttempt,
    PasswordExpired, PasswordLastSet, AccountExpires, LastLogonDate,
    AccountExpirationDate, Enabled, PasswordNeverExpires, DistinguishedName,
    Department, Title, Manager, Description -ErrorAction SilentlyContinue |
Select-Object SamAccountName, Enabled, LockedOut, BadLogonCount,
    LastBadPasswordAttempt, PasswordExpired, PasswordLastSet,
    AccountExpires, LastLogonDate, PasswordNeverExpires,
    Department, Title, Description, DistinguishedName |
ConvertTo-Json -Depth 2 -Compress
"""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=20
            )
            if r.stdout.strip():
                return json.loads(r.stdout.strip())
        except Exception:
            pass
        return {}

    def get_services_for_account(self, username: str) -> List[dict]:
        ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
$svc = Get-WmiObject Win32_Service |
    Where-Object {{ $_.StartName -like '*{username}*' }} |
    Select-Object Name, DisplayName, StartName, State, PathName
$task = Get-ScheduledTask |
    Where-Object {{ $_.Principal.UserId -like '*{username}*' }} |
    Select-Object TaskName, TaskPath,
        @{{N='UserId';E={{$_.Principal.UserId}}}},
        @{{N='State';E={{$_.State.ToString()}}}},
        @{{N='Type';E={{'ScheduledTask'}}}}
$result = @()
if ($svc)  {{ $result += $svc  | Select-Object @{{N='Type';E={{'Service'}}}}, @{{N='Name';E={{$_.DisplayName}}}}, @{{N='Account';E={{$_.StartName}}}}, @{{N='State';E={{$_.State}}}}, @{{N='Detail';E={{$_.PathName}}}} }}
if ($task) {{ $result += $task | Select-Object @{{N='Type';E={{$_.Type}}}}, @{{N='Name';E={{$_.TaskName}}}}, @{{N='Account';E={{$_.UserId}}}}, @{{N='State';E={{$_.State}}}}, @{{N='Detail';E={{$_.TaskPath}}}} }}
$result | ConvertTo-Json -Depth 2 -Compress
"""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=30
            )
            if r.stdout.strip():
                data = json.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                return data or []
        except Exception:
            pass
        return []

    def parse_netlogon_logs(self, dc: str, username: str) -> List[dict]:
        results = []
        paths = [
            f"\\\\{dc}\\ADMIN$\\debug\\netlogon.log",
            f"\\\\{dc}\\ADMIN$\\debug\\netlogon.bak",
        ]
        pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(BADPASSWD|BAD_PASSWORD|LOCK|Kerberos|NtLm|Error).*?'
            r'\\\\?(\S+)\s+' + re.escape(username),
            re.IGNORECASE
        )
        for path in paths:
            try:
                with open(path, 'r', errors='ignore') as f:
                    for line in f:
                        if username.lower() in line.lower():
                            m = pattern.search(line)
                            results.append({
                                'timestamp': m.group(1) if m else '',
                                'dc': dc,
                                'source': m.group(4) if m else 'Unknown',
                                'line': line.strip(),
                            })
            except Exception:
                pass
        return results

    def detect_spray_attacks(self, events: List[LockoutEvent],
                              window_minutes: int = 10,
                              threshold: int = 5) -> List[SprayAlert]:
        by_source: Dict[str, List[LockoutEvent]] = {}
        for e in events:
            if e.event_id in (4625, 4771, 4776):
                src = e.caller_ip or e.caller_machine or "Unknown"
                by_source.setdefault(src, []).append(e)

        alerts = []
        for src, evs in by_source.items():
            evs.sort(key=lambda x: x.timestamp)
            window_start = 0
            for i, ev in enumerate(evs):
                while (ev.timestamp - evs[window_start].timestamp).total_seconds() > window_minutes * 60:
                    window_start += 1
                window = evs[window_start:i + 1]
                affected = set(e.username for e in window)
                if len(affected) >= threshold:
                    alerts.append(SprayAlert(
                        source_ip=src if '.' in src or ':' in src else '',
                        source_machine=src if '.' not in src and ':' not in src else '',
                        affected_users=list(affected),
                        event_count=len(window),
                        first_seen=window[0].timestamp,
                        last_seen=window[-1].timestamp,
                    ))
                    break

        return alerts

    def analyze_lockout_source(self, username: str, events: List[LockoutEvent]) -> str:
        user_events = [e for e in events if e.username.lower() == username.lower()]
        if not user_events:
            return "No events found for this account."

        lines = []
        lines.append(f"LOCKOUT SOURCE ANALYSIS — {username}")
        lines.append("=" * 60)
        lines.append(f"Events analysed: {len(user_events)}")
        lines.append(f"Period: {min(e.timestamp for e in user_events).strftime('%Y-%m-%d %H:%M')} "
                     f"→ {max(e.timestamp for e in user_events).strftime('%Y-%m-%d %H:%M')}")
        lines.append("")

        lockouts = [e for e in user_events if e.event_id == 4740]
        lines.append(f"Lockout events (4740): {len(lockouts)}")
        lines.append(f"Failed logon events (4625): {len([e for e in user_events if e.event_id == 4625])}")
        lines.append("")

        # Source machines
        machines = {}
        for e in user_events:
            src = e.caller_machine or e.caller_ip or "Unknown"
            machines[src] = machines.get(src, 0) + 1
        if machines:
            lines.append("TOP SOURCE MACHINES / IPs:")
            lines.append("-" * 40)
            for m, c in sorted(machines.items(), key=lambda x: -x[1])[:10]:
                lines.append(f"  {m:35s} {c:4d} event(s)")
            lines.append("")

        # IPs with reverse DNS
        ips = {}
        for e in user_events:
            if e.caller_ip:
                ips[e.caller_ip] = ips.get(e.caller_ip, 0) + 1
        if ips:
            lines.append("SOURCE IP ADDRESSES (with DNS resolution):")
            lines.append("-" * 40)
            for ip, c in sorted(ips.items(), key=lambda x: -x[1]):
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    lines.append(f"  {ip:20s} → {hostname:30s}  ({c} events)")
                except Exception:
                    lines.append(f"  {ip:20s} → (no reverse DNS)              ({c} events)")
            lines.append("")

        # Logon types
        lt_counts = {}
        for e in user_events:
            lt = e.logon_type_name
            lt_counts[lt] = lt_counts.get(lt, 0) + 1
        if lt_counts:
            lines.append("LOGON TYPE BREAKDOWN:")
            lines.append("-" * 40)
            for lt, c in sorted(lt_counts.items(), key=lambda x: -x[1]):
                cause = LOCKOUT_CAUSES.get(lt, "")
                lines.append(f"  {lt:30s} {c:4d} event(s)")
                if cause:
                    lines.append(f"    → {cause}")
            lines.append("")

        # Auth packages
        ap_counts = {}
        for e in user_events:
            if e.auth_package:
                ap_counts[e.auth_package] = ap_counts.get(e.auth_package, 0) + 1
        if ap_counts:
            lines.append("AUTHENTICATION PACKAGES:")
            lines.append("-" * 40)
            for ap, c in sorted(ap_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  {ap:30s} {c:4d} event(s)")
            if 'NTLM' in ap_counts and ap_counts.get('NTLM', 0) > ap_counts.get('Kerberos', 0):
                lines.append("  ⚠  NTLM dominates — check mapped drives, legacy apps, or saved credentials")
            lines.append("")

        # Failure reasons
        fr_counts = {}
        for e in user_events:
            if e.failure_reason:
                fr_counts[e.failure_reason] = fr_counts.get(e.failure_reason, 0) + 1
        if fr_counts:
            lines.append("FAILURE REASONS:")
            lines.append("-" * 40)
            for fr, c in sorted(fr_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  {fr:45s} {c:4d} event(s)")
            lines.append("")

        # Most likely cause
        lines.append("MOST LIKELY CAUSES:")
        lines.append("-" * 40)
        if machines:
            top_machine = max(machines.items(), key=lambda x: x[1])
            lines.append(f"  1. Primary source: {top_machine[0]} ({top_machine[1]} events)")

        for lt in lt_counts:
            if lt in ("Service", "Batch"):
                lines.append(f"  2. A Windows Service or Scheduled Task is likely using stale credentials.")
                lines.append(f"     → Check the Services/Tasks tab for confirmed matches.")
                break

        if ap_counts.get('NTLM', 0) > 5:
            lines.append("  3. Mapped network drives or legacy applications using NTLM with old password.")
        if any(e.logon_type == 7 for e in user_events):
            lines.append("  4. Locked workstation auto-unlock attempts with old cached password.")
        if any(e.logon_type == 10 for e in user_events):
            lines.append("  5. Remote Desktop (RDP) saved credentials with old password.")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# WORKER THREADS
# ─────────────────────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    progress = pyqtSignal(str)
    complete = pyqtSignal(list)

    def __init__(self, servers: List[str], hours: float, username: str = ""):
        super().__init__()
        self.servers = servers
        self.hours = hours
        self.username = username
        self.engine = LockoutEngine()
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        all_events = []
        for i, srv in enumerate(self.servers):
            if self._stop:
                break
            self.progress.emit(f"Scanning {srv} ({i+1}/{len(self.servers)})...")
            evs = self.engine.scan_events(
                srv, self.hours, self.username,
                progress_fn=lambda m: self.progress.emit(m)
            )
            all_events.extend(evs)
            self.progress.emit(f"  {srv}: {len(evs)} events found")
        all_events.sort(key=lambda e: e.timestamp, reverse=True)
        self.complete.emit(all_events)


class DCDiscoveryWorker(QThread):
    found = pyqtSignal(list, str)
    progress = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.engine = LockoutEngine()

    def run(self):
        self.progress.emit("Querying Active Directory for domain controllers...")
        dcs = self.engine.get_domain_controllers()
        self.progress.emit("Looking up PDC emulator...")
        pdc = self.engine.get_pdc_emulator()
        self.found.emit(dcs, pdc)


class MonitorWorker(QThread):
    event_found = pyqtSignal(object)
    status = pyqtSignal(str)

    def __init__(self, servers: List[str]):
        super().__init__()
        self.servers = servers
        self.engine = LockoutEngine()
        self._stop = False
        self.last_scan = datetime.datetime.utcnow() - datetime.timedelta(seconds=60)

    def stop(self):
        self._stop = True

    def run(self):
        self.status.emit("active")
        while not self._stop:
            since = self.last_scan
            self.last_scan = datetime.datetime.utcnow()
            for srv in self.servers:
                if self._stop:
                    break
                evs = self.engine.scan_events(srv, 0, since=since)
                for e in evs:
                    self.event_found.emit(e)
            for _ in range(30):
                if self._stop:
                    break
                time.sleep(1)
        self.status.emit("stopped")


class LockedAccountsWorker(QThread):
    complete = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.engine = LockoutEngine()

    def run(self):
        accounts = self.engine.get_locked_accounts()
        self.complete.emit(accounts)


# ─────────────────────────────────────────────────────────────────────────────
# STYLESHEET
# ─────────────────────────────────────────────────────────────────────────────

APP_STYLE = """
* { font-family: 'Segoe UI', Arial, sans-serif; }

QMainWindow, QDialog { background: #0d1117; color: #c9d1d9; }
QWidget { background: #0d1117; color: #c9d1d9; font-size: 13px; }

/* ── Sidebar ─────────────────────────────── */
#sidebar {
    background: #161b22;
    border-right: 1px solid #21262d;
    min-width: 230px; max-width: 230px;
}
#logo_area {
    background: #161b22;
    border-bottom: 1px solid #21262d;
    padding: 18px 16px 14px 16px;
}
QPushButton#nav_btn {
    background: transparent;
    border: none; border-left: 3px solid transparent;
    border-radius: 0;
    padding: 11px 16px 11px 20px;
    text-align: left; color: #8b949e;
    font-size: 13px; font-weight: 500;
}
QPushButton#nav_btn:hover  { background: #1c2128; color: #e6edf3; }
QPushButton#nav_btn[active="true"] {
    background: #1c2128; color: #58a6ff;
    border-left: 3px solid #58a6ff;
}

/* ── Cards ───────────────────────────────── */
QFrame#card {
    background: #161b22; border: 1px solid #21262d;
    border-radius: 10px; padding: 16px;
}
QFrame#stat_card {
    background: #161b22; border: 1px solid #21262d;
    border-radius: 10px; padding: 18px 20px;
}

/* ── Buttons ─────────────────────────────── */
QPushButton#primary_btn {
    background: #1f6feb; color: #fff;
    border: none; border-radius: 6px;
    padding: 9px 18px; font-weight: 600;
}
QPushButton#primary_btn:hover  { background: #388bfd; }
QPushButton#primary_btn:pressed { background: #1158c7; }
QPushButton#primary_btn:disabled { background: #21262d; color: #484f58; }

QPushButton#danger_btn {
    background: #b91c1c; color: #fff;
    border: none; border-radius: 6px; padding: 9px 18px; font-weight: 600;
}
QPushButton#danger_btn:hover { background: #ef4444; }

QPushButton#success_btn {
    background: #1a7f37; color: #fff;
    border: none; border-radius: 6px; padding: 9px 18px; font-weight: 600;
}
QPushButton#success_btn:hover { background: #2da44e; }

QPushButton#secondary_btn {
    background: #21262d; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 6px; padding: 9px 18px;
}
QPushButton#secondary_btn:hover { background: #282e37; border-color: #8b949e; }

QPushButton#warn_btn {
    background: #9a6700; color: #fff;
    border: none; border-radius: 6px; padding: 9px 18px; font-weight: 600;
}
QPushButton#warn_btn:hover { background: #d29922; }

/* ── Inputs ──────────────────────────────── */
QLineEdit, QComboBox, QSpinBox {
    background: #0d1117; border: 1px solid #30363d;
    border-radius: 6px; padding: 7px 11px; color: #c9d1d9;
    selection-background-color: #1f6feb;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #388bfd; }
QLineEdit::placeholder { color: #484f58; }
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView {
    background: #161b22; border: 1px solid #30363d;
    selection-background-color: #1f6feb; outline: none;
}
QComboBox QAbstractItemView::item { padding: 6px 12px; }

/* ── Tables ──────────────────────────────── */
QTableWidget {
    background: #0d1117; border: 1px solid #21262d;
    border-radius: 8px; gridline-color: #21262d;
    alternate-background-color: #161b22; outline: none;
}
QTableWidget::item { padding: 7px 12px; border: none; }
QTableWidget::item:selected { background: #1c2a4a; color: #79c0ff; }
QTableWidget::item:hover:!selected { background: #1c2128; }
QHeaderView { background: #161b22; }
QHeaderView::section {
    background: #161b22; color: #8b949e;
    padding: 8px 12px; border: none;
    border-bottom: 1px solid #21262d;
    font-weight: 600; font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.5px;
}
QHeaderView::section:hover { background: #1c2128; color: #c9d1d9; }

/* ── Tabs ────────────────────────────────── */
QTabWidget::pane {
    background: #161b22; border: 1px solid #21262d;
    border-radius: 0 8px 8px 8px;
}
QTabBar::tab {
    background: #0d1117; color: #8b949e;
    padding: 9px 18px; border: 1px solid #21262d;
    border-bottom: none; border-radius: 6px 6px 0 0; margin-right: 2px;
}
QTabBar::tab:selected { background: #161b22; color: #58a6ff; border-top: 2px solid #58a6ff; }
QTabBar::tab:hover:!selected { background: #161b22; color: #c9d1d9; }

/* ── Scrollbars ──────────────────────────── */
QScrollBar:vertical { background: #161b22; width: 7px; }
QScrollBar::handle:vertical { background: #30363d; border-radius: 3px; min-height: 20px; }
QScrollBar::handle:vertical:hover { background: #484f58; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #161b22; height: 7px; }
QScrollBar::handle:horizontal { background: #30363d; border-radius: 3px; min-width: 20px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Text areas ──────────────────────────── */
QTextEdit, QPlainTextEdit {
    background: #0d1117; border: 1px solid #30363d;
    border-radius: 6px; color: #c9d1d9;
    font-family: 'Consolas', 'Cascadia Code', monospace; font-size: 12px;
    padding: 8px; selection-background-color: #1f6feb;
}

/* ── Labels ──────────────────────────────── */
QLabel#page_title  { color: #e6edf3; font-size: 22px; font-weight: 700; }
QLabel#page_sub    { color: #8b949e; font-size: 13px; }
QLabel#section_ttl { color: #c9d1d9; font-size: 14px; font-weight: 600; }
QLabel#stat_num    { font-size: 30px; font-weight: 700; }
QLabel#stat_lbl    { color: #8b949e; font-size: 11px; font-weight: 500; }

/* ── Status bar ──────────────────────────── */
QStatusBar { background: #161b22; color: #8b949e; border-top: 1px solid #21262d; font-size: 12px; }

/* ── Progress ────────────────────────────── */
QProgressBar { background: #21262d; border: none; border-radius: 3px; height: 5px; }
QProgressBar::chunk { background: #1f6feb; border-radius: 3px; }

/* ── GroupBox ────────────────────────────── */
QGroupBox {
    color: #58a6ff; border: 1px solid #21262d; border-radius: 8px;
    margin-top: 18px; padding: 12px; font-weight: 600; font-size: 11px;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 10px;
    padding: 0 6px; background: #161b22;
    text-transform: uppercase; letter-spacing: 0.5px;
}

/* ── Checkbox ────────────────────────────── */
QCheckBox { color: #c9d1d9; spacing: 8px; }
QCheckBox::indicator {
    width: 15px; height: 15px;
    border: 2px solid #30363d; border-radius: 3px; background: #0d1117;
}
QCheckBox::indicator:checked { background: #1f6feb; border-color: #1f6feb; }
QCheckBox::indicator:hover { border-color: #58a6ff; }

/* ── Tooltip ─────────────────────────────── */
QToolTip {
    background: #1c2128; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 4px;
    padding: 4px 8px; font-size: 12px;
}

/* ── Menu ────────────────────────────────── */
QMenu { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 4px; }
QMenu::item { padding: 7px 20px; color: #c9d1d9; border-radius: 4px; }
QMenu::item:selected { background: #1f6feb; color: #fff; }

/* ── List ────────────────────────────────── */
QListWidget { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; }
QListWidget::item { padding: 8px 12px; color: #c9d1d9; }
QListWidget::item:selected { background: #1c2a4a; color: #79c0ff; }
QListWidget::item:hover { background: #1c2128; }
"""


# ─────────────────────────────────────────────────────────────────────────────
# REUSABLE UI COMPONENTS
# ─────────────────────────────────────────────────────────────────────────────

class StatCard(QFrame):
    def __init__(self, label: str, value: str = "0", color: str = "#58a6ff", icon: str = ""):
        super().__init__()
        self.setObjectName("stat_card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(4)

        top = QHBoxLayout()
        if icon:
            ico = QLabel(icon)
            ico.setStyleSheet(f"font-size: 22px; color: {color}; background: transparent;")
            top.addWidget(ico)
        lbl = QLabel(label)
        lbl.setObjectName("stat_lbl")
        top.addWidget(lbl)
        top.addStretch()
        lay.addLayout(top)

        self.val_lbl = QLabel(value)
        self.val_lbl.setObjectName("stat_num")
        self.val_lbl.setStyleSheet(f"color: {color}; font-size: 30px; font-weight: 700; background: transparent;")
        lay.addWidget(self.val_lbl)

    def set_value(self, v: str):
        self.val_lbl.setText(v)


class EventTable(QTableWidget):
    COLS = ["Timestamp", "Event", "Username", "Source Machine", "IP Address", "Logon Type", "Failure Reason", "DC"]

    row_double_clicked = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.setColumnCount(len(self.COLS))
        self.setHorizontalHeaderLabels(self.COLS)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(True)
        self.setShowGrid(True)
        self.verticalHeader().setVisible(False)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self.doubleClicked.connect(self._on_double_click)

        h = self.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)

    def _on_double_click(self, index):
        item = self.item(index.row(), 0)
        if item:
            ev = item.data(Qt.ItemDataRole.UserRole)
            if ev:
                self.row_double_clicked.emit(ev)

    def add_event(self, event: LockoutEvent):
        row = self.rowCount()
        self.insertRow(row)
        vals = [
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            event.event_type,
            event.username,
            event.caller_machine or "—",
            event.caller_ip or "—",
            event.logon_type_name,
            event.failure_reason or "—",
            event.source_dc,
        ]
        color = QColor(event.severity_color)
        for col, text in enumerate(vals):
            item = QTableWidgetItem(text)
            item.setForeground(color)
            item.setData(Qt.ItemDataRole.UserRole, event)
            self.setItem(row, col, item)

    def populate(self, events: List[LockoutEvent]):
        self.setSortingEnabled(False)
        self.clearContents()
        self.setRowCount(0)
        for ev in events:
            self.add_event(ev)
        self.setSortingEnabled(True)

    def _context_menu(self, pos):
        item = self.itemAt(pos)
        if not item:
            return
        ev = item.data(Qt.ItemDataRole.UserRole)
        if not ev:
            return

        menu = QMenu(self)
        menu.addAction("Copy Row").triggered.connect(lambda: self._copy_row(ev))
        menu.addAction(f"Copy Username: {ev.username}").triggered.connect(
            lambda: QApplication.clipboard().setText(ev.username))
        if ev.caller_ip:
            menu.addAction(f"Copy IP: {ev.caller_ip}").triggered.connect(
                lambda: QApplication.clipboard().setText(ev.caller_ip))
        if ev.caller_machine:
            menu.addAction(f"Copy Machine: {ev.caller_machine}").triggered.connect(
                lambda: QApplication.clipboard().setText(ev.caller_machine))
        menu.addSeparator()
        menu.addAction("View Full Details").triggered.connect(
            lambda: self.row_double_clicked.emit(ev))
        menu.exec(self.mapToGlobal(pos))

    def _copy_row(self, ev: LockoutEvent):
        row = "\t".join([ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                          ev.event_type, ev.username, ev.caller_machine,
                          ev.caller_ip, ev.logon_type_name, ev.failure_reason, ev.source_dc])
        QApplication.clipboard().setText(row)


class EventDetailDialog(QDialog):
    def __init__(self, event: LockoutEvent, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Event Details — {event.username}")
        self.setMinimumSize(600, 450)
        lay = QVBoxLayout(self)

        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setFont(QFont("Consolas", 11))

        lines = [
            f"Event ID:          {event.event_id}  ({event.event_type})",
            f"Timestamp (UTC):   {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Username:          {event.username}",
            f"Domain:            {event.domain}",
            "",
            f"Source Machine:    {event.caller_machine or '—'}",
            f"Source IP:         {event.caller_ip or '—'}",
            f"Source DC:         {event.source_dc}",
            "",
            f"Logon Type:        {event.logon_type_name}  (type {event.logon_type})",
            f"Auth Package:      {event.auth_package or '—'}",
            f"Process Name:      {event.process_name or '—'}",
            "",
            f"Failure Reason:    {event.failure_reason or '—'}",
            f"Status Code:       {event.status_code or '—'}",
            f"Sub-Status Code:   {event.sub_status_code or '—'}",
        ]

        if event.logon_type_name in LOCKOUT_CAUSES:
            lines += ["", "LIKELY CAUSE:", f"  {LOCKOUT_CAUSES[event.logon_type_name]}"]

        txt.setPlainText("\n".join(lines))
        lay.addWidget(txt)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)


# ─────────────────────────────────────────────────────────────────────────────
# PAGES
# ─────────────────────────────────────────────────────────────────────────────

class DashboardPage(QWidget):
    scan_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(18)

        # Header
        hdr = QHBoxLayout()
        t = QLabel("Dashboard"); t.setObjectName("page_title"); hdr.addWidget(t)
        hdr.addStretch()
        self.scan_btn = QPushButton("⟳  Quick Scan (All DCs)")
        self.scan_btn.setObjectName("primary_btn")
        self.scan_btn.clicked.connect(self.scan_requested)
        hdr.addWidget(self.scan_btn)
        lay.addLayout(hdr)

        sub = QLabel("Account lockout activity overview  ·  Last 24 hours")
        sub.setObjectName("page_sub"); lay.addWidget(sub)

        # Stat cards
        cards = QHBoxLayout(); cards.setSpacing(14)
        self.c_lockouts = StatCard("Account Lockouts", "0", "#ef5350", "🔒")
        self.c_failed   = StatCard("Failed Logons",    "0", "#ffa726", "⚠")
        self.c_users    = StatCard("Affected Users",   "0", "#ab47bc", "👤")
        self.c_sources  = StatCard("Unique Sources",   "0", "#26c6da", "💻")
        self.c_spray    = StatCard("Spray Alerts",     "0", "#f44336", "🎯")
        for c in [self.c_lockouts, self.c_failed, self.c_users, self.c_sources, self.c_spray]:
            cards.addWidget(c)
        lay.addLayout(cards)

        # Spray alert banner (hidden by default)
        self.spray_banner = QFrame()
        self.spray_banner.setObjectName("card")
        self.spray_banner.setStyleSheet(
            "QFrame#card { background: #3d1f1f; border-color: #f44336; border-width: 1px; }")
        spray_lay = QHBoxLayout(self.spray_banner)
        spray_lbl = QLabel("🎯  PASSWORD SPRAY DETECTED — Multiple accounts failing from the same source IP.")
        spray_lbl.setStyleSheet("color: #ef5350; font-weight: 600; background: transparent;")
        spray_lay.addWidget(spray_lbl)
        self.spray_detail_btn = QPushButton("View Details")
        self.spray_detail_btn.setObjectName("danger_btn")
        spray_lay.addWidget(self.spray_detail_btn)
        self.spray_banner.setVisible(False)
        lay.addWidget(self.spray_banner)

        # Event table
        tbl_frame = QFrame(); tbl_frame.setObjectName("card")
        tbl_lay = QVBoxLayout(tbl_frame)

        tbl_hdr = QHBoxLayout()
        ttl = QLabel("Recent Events"); ttl.setObjectName("section_ttl"); tbl_hdr.addWidget(ttl)
        tbl_hdr.addStretch()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by username...")
        self.filter_edit.setFixedWidth(200)
        self.filter_edit.textChanged.connect(self._filter)
        tbl_hdr.addWidget(self.filter_edit)
        tbl_lay.addLayout(tbl_hdr)

        self.table = EventTable()
        self.table.row_double_clicked.connect(self._show_detail)
        tbl_lay.addWidget(self.table)
        lay.addWidget(tbl_frame, 1)

        self.status_lbl = QLabel("No scan performed. Configure DCs and click Quick Scan.")
        self.status_lbl.setObjectName("page_sub")
        lay.addWidget(self.status_lbl)

        self._spray_alerts: List[SprayAlert] = []

    def _show_detail(self, ev: LockoutEvent):
        d = EventDetailDialog(ev, self)
        d.exec()

    def update(self, events: List[LockoutEvent], spray_alerts: List[SprayAlert]):
        lockouts = [e for e in events if e.event_id == 4740]
        failed   = [e for e in events if e.event_id == 4625]
        users    = set(e.username for e in events)
        sources  = set(e.caller_machine or e.caller_ip for e in events if e.caller_machine or e.caller_ip)

        self.c_lockouts.set_value(str(len(lockouts)))
        self.c_failed.set_value(str(len(failed)))
        self.c_users.set_value(str(len(users)))
        self.c_sources.set_value(str(len(sources)))
        self.c_spray.set_value(str(len(spray_alerts)))

        self._spray_alerts = spray_alerts
        self.spray_banner.setVisible(len(spray_alerts) > 0)

        self.table.populate(events)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_lbl.setText(f"Last scan: {ts}  ·  {len(events)} total events  ·  {len(lockouts)} lockouts")

    def _filter(self, text: str):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 2)
            match = not text or text.lower() in (item.text().lower() if item else '')
            self.table.setRowHidden(row, not match)


class InvestigatePage(QWidget):
    scan_requested = pyqtSignal(str, float, list)

    def __init__(self):
        super().__init__()
        self.engine = LockoutEngine()
        self._events: List[LockoutEvent] = []
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(18)

        t = QLabel("Investigate Account"); t.setObjectName("page_title"); lay.addWidget(t)
        s = QLabel("Deep-dive lockout source analysis for a specific user account")
        s.setObjectName("page_sub"); lay.addWidget(s)

        # Search bar
        sf = QFrame(); sf.setObjectName("card")
        sl = QVBoxLayout(sf)
        sl.setSpacing(10)

        row = QHBoxLayout(); row.setSpacing(12)

        ugrp = QVBoxLayout()
        ul = QLabel("Username"); ul.setStyleSheet("color:#8b949e;font-size:11px;")
        self.user_edit = QLineEdit(); self.user_edit.setPlaceholderText("e.g.  john.doe")
        self.user_edit.setFixedHeight(36)
        ugrp.addWidget(ul); ugrp.addWidget(self.user_edit)
        row.addLayout(ugrp, 2)

        tgrp = QVBoxLayout()
        tl = QLabel("Time Range"); tl.setStyleSheet("color:#8b949e;font-size:11px;")
        self.time_combo = QComboBox()
        self.time_combo.addItems(["Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 48 hours", "Last 7 days"])
        self.time_combo.setCurrentIndex(2)
        self.time_combo.setFixedHeight(36)
        tgrp.addWidget(tl); tgrp.addWidget(self.time_combo)
        row.addLayout(tgrp, 1)

        bgrp = QVBoxLayout()
        bgrp.addWidget(QLabel(""))
        self.inv_btn = QPushButton("🔍  Investigate")
        self.inv_btn.setObjectName("primary_btn"); self.inv_btn.setFixedHeight(36)
        self.inv_btn.clicked.connect(self._start)
        bgrp.addWidget(self.inv_btn)
        row.addLayout(bgrp)

        sl.addLayout(row)
        self.prog_lbl = QLabel(""); self.prog_lbl.setObjectName("page_sub")
        sl.addWidget(self.prog_lbl)
        lay.addWidget(sf)

        # Results tabs
        self.tabs = QTabWidget()

        # Timeline
        w1 = QWidget(); l1 = QVBoxLayout(w1)
        self.timeline = EventTable()
        self.timeline.row_double_clicked.connect(self._show_detail)
        l1.addWidget(self.timeline)
        self.tabs.addTab(w1, "📅  Event Timeline")

        # Source Summary
        w2 = QWidget(); l2 = QVBoxLayout(w2)
        self.summary_txt = QTextEdit(); self.summary_txt.setReadOnly(True)
        l2.addWidget(self.summary_txt)
        self.tabs.addTab(w2, "🎯  Source Summary")

        # AD Account Info
        w3 = QWidget(); l3 = QVBoxLayout(w3)
        hdr3 = QHBoxLayout()
        hdr3.addWidget(QLabel("Active Directory Account Details"))
        hdr3.addStretch()
        unlock_btn = QPushButton("🔓  Unlock Account")
        unlock_btn.setObjectName("warn_btn")
        unlock_btn.clicked.connect(self._unlock)
        hdr3.addWidget(unlock_btn)
        l3.addLayout(hdr3)
        self.ad_txt = QTextEdit(); self.ad_txt.setReadOnly(True)
        l3.addWidget(self.ad_txt)
        self.tabs.addTab(w3, "🏢  AD Account Info")

        # Services & Tasks
        w4 = QWidget(); l4 = QVBoxLayout(w4)
        l4.addWidget(QLabel("Services and Scheduled Tasks running as this account (checked on local machine):"))
        self.svc_table = QTableWidget()
        self.svc_table.setColumnCount(4)
        self.svc_table.setHorizontalHeaderLabels(["Type", "Name", "Account", "State"])
        self.svc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.svc_table.setAlternatingRowColors(True)
        self.svc_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        l4.addWidget(self.svc_table)
        l4.addWidget(QLabel("⚠  Services on remote machines are not scanned here — "
                             "check each source machine individually.",
                            styleSheet="color:#8b949e;font-size:11px;"))
        self.tabs.addTab(w4, "⚙  Services & Tasks")

        # Netlogon
        w5 = QWidget(); l5 = QVBoxLayout(w5)
        l5.addWidget(QLabel("Netlogon.log entries for this account (requires admin$ share access to DCs):"))
        self.netlog_txt = QTextEdit(); self.netlog_txt.setReadOnly(True)
        l5.addWidget(self.netlog_txt)
        self.tabs.addTab(w5, "📜  Netlogon Logs")

        lay.addWidget(self.tabs, 1)

    def _start(self):
        user = self.user_edit.text().strip()
        if not user:
            QMessageBox.warning(self, "Username Required", "Please enter a username.")
            return
        hours_map = {0: 1, 1: 6, 2: 24, 3: 48, 4: 168}
        hours = hours_map[self.time_combo.currentIndex()]
        self.inv_btn.setEnabled(False)
        self.prog_lbl.setText(f"Scanning for {user}...")
        self.scan_requested.emit(user, hours, [])
        QTimer.singleShot(200, lambda: self._local_checks(user))

    def _local_checks(self, username: str):
        try:
            ad = self.engine.get_ad_account_info(username)
            if ad:
                lines = ["AD Account Information\n" + "="*50]
                for k, v in ad.items():
                    if v is not None and str(v).strip():
                        lines.append(f"  {k:<35} {v}")
                self.ad_txt.setPlainText("\n".join(lines))
            else:
                self.ad_txt.setPlainText(
                    "Could not retrieve AD information.\n"
                    "Ensure you have AD read access and the ActiveDirectory PowerShell module is installed.\n"
                    "On the DC, run: Import-Module ActiveDirectory\n"
                    "On a workstation: Install-WindowsFeature RSAT-AD-PowerShell"
                )
        except Exception as e:
            self.ad_txt.setPlainText(f"Error: {e}")

        try:
            svcs = self.engine.get_services_for_account(username)
            self.svc_table.setRowCount(0)
            for s in svcs:
                r = self.svc_table.rowCount(); self.svc_table.insertRow(r)
                for c, k in enumerate(['Type', 'Name', 'Account', 'State']):
                    self.svc_table.setItem(r, c, QTableWidgetItem(str(s.get(k, ''))))
            if not svcs:
                self.svc_table.setRowCount(1)
                item = QTableWidgetItem("No local services or scheduled tasks found for this account.")
                item.setForeground(QColor("#8b949e"))
                self.svc_table.setItem(0, 0, item)
                self.svc_table.setSpan(0, 0, 1, 4)
        except Exception as e:
            pass

    def update_events(self, events: List[LockoutEvent], servers: List[str]):
        user = self.user_edit.text().strip()
        user_events = [e for e in events if e.username.lower() == user.lower()]
        self._events = user_events

        self.timeline.populate(user_events)
        self.inv_btn.setEnabled(True)
        self.prog_lbl.setText(f"Found {len(user_events)} events for '{user}'")

        # Source summary
        summary = self.engine.analyze_lockout_source(user, events)
        self.summary_txt.setPlainText(summary)

        # Netlogon
        netlog_lines = []
        for srv in servers:
            entries = self.engine.parse_netlogon_logs(srv, user)
            for e in entries:
                netlog_lines.append(f"[{e['dc']}]  {e['timestamp']}  Source: {e['source']}\n  {e['line']}\n")
        self.netlog_txt.setPlainText(
            "\n".join(netlog_lines) if netlog_lines
            else "No Netlogon log entries found.\n\n"
                 "This may be because:\n"
                 "  · You don't have admin share access to the DCs\n"
                 "  · Netlogon debug logging is not enabled\n"
                 "  · No entries exist for this account\n\n"
                 "To enable Netlogon logging on a DC:\n"
                 "  nltest /dbflag:0x2080ffff"
        )

    def _show_detail(self, ev: LockoutEvent):
        d = EventDetailDialog(ev, self)
        d.exec()

    def _unlock(self):
        user = self.user_edit.text().strip()
        if not user:
            QMessageBox.warning(self, "No Username", "Enter a username first.")
            return
        reply = QMessageBox.question(
            self, "Unlock Account",
            f"Are you sure you want to unlock '{user}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            ok, msg = self.engine.unlock_account(user)
            if ok:
                QMessageBox.information(self, "Success", msg)
            else:
                QMessageBox.critical(self, "Failed", f"Could not unlock account:\n{msg}")


class ActiveLockoutsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.engine = LockoutEngine()
        self._worker = None
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(18)

        hdr = QHBoxLayout()
        t = QLabel("Active Lockouts"); t.setObjectName("page_title"); hdr.addWidget(t)
        hdr.addStretch()
        self.refresh_btn = QPushButton("⟳  Refresh")
        self.refresh_btn.setObjectName("primary_btn")
        self.refresh_btn.clicked.connect(self._refresh)
        hdr.addWidget(self.refresh_btn)
        lay.addLayout(hdr)

        s = QLabel("Accounts currently locked out in Active Directory")
        s.setObjectName("page_sub"); lay.addWidget(s)

        frame = QFrame(); frame.setObjectName("card")
        fl = QVBoxLayout(frame)

        fhdr = QHBoxLayout()
        self.count_lbl = QLabel(""); fhdr.addWidget(self.count_lbl)
        fhdr.addStretch()
        self.unlock_sel_btn = QPushButton("🔓  Unlock Selected")
        self.unlock_sel_btn.setObjectName("warn_btn")
        self.unlock_sel_btn.clicked.connect(self._unlock_selected)
        fhdr.addWidget(self.unlock_sel_btn)
        fl.addLayout(fhdr)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Username", "Bad Password Count",
                                               "Last Bad Attempt", "Last Logon", "Distinguished Name"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        fl.addWidget(self.table)
        lay.addWidget(frame, 1)

        self.status_lbl = QLabel("Click Refresh to load currently locked accounts.")
        self.status_lbl.setObjectName("page_sub"); lay.addWidget(self.status_lbl)

    def _refresh(self):
        self.refresh_btn.setEnabled(False)
        self.status_lbl.setText("Querying Active Directory for locked accounts...")
        self._worker = LockedAccountsWorker()
        self._worker.complete.connect(self._on_complete)
        self._worker.start()

    def _on_complete(self, accounts: List[dict]):
        self.table.setRowCount(0)
        for acc in accounts:
            r = self.table.rowCount(); self.table.insertRow(r)
            vals = [
                str(acc.get('SamAccountName', '')),
                str(acc.get('BadLogonCount', '')),
                str(acc.get('LastBadPwd', '') or ''),
                str(acc.get('LastLogonDate', '') or ''),
                str(acc.get('DistinguishedName', '')),
            ]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 0:
                    item.setForeground(QColor("#ef5350"))
                self.table.setItem(r, c, item)

        n = len(accounts)
        self.count_lbl.setText(f"{n} account{'s' if n != 1 else ''} currently locked out")
        self.status_lbl.setText(f"Refreshed at {datetime.datetime.now().strftime('%H:%M:%S')}")
        self.refresh_btn.setEnabled(True)

    def _unlock_selected(self):
        rows = set(i.row() for i in self.table.selectedIndexes())
        if not rows:
            QMessageBox.information(self, "No Selection", "Select one or more accounts to unlock.")
            return
        usernames = [self.table.item(r, 0).text() for r in rows if self.table.item(r, 0)]
        reply = QMessageBox.question(
            self, "Unlock Accounts",
            f"Unlock {len(usernames)} account(s)?\n\n" + "\n".join(usernames),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            results = []
            for u in usernames:
                ok, msg = self.engine.unlock_account(u)
                results.append(f"{'✓' if ok else '✗'}  {u}: {msg}")
            QMessageBox.information(self, "Results", "\n".join(results))
            self._refresh()


class MonitorPage(QWidget):
    def __init__(self):
        super().__init__()
        self.servers: List[str] = []
        self._monitor: Optional[MonitorWorker] = None
        self._all_events: List[LockoutEvent] = []
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(18)

        hdr = QHBoxLayout()
        t = QLabel("Live Monitor"); t.setObjectName("page_title"); hdr.addWidget(t)
        hdr.addStretch()
        self.dot = QLabel("● STOPPED")
        self.dot.setStyleSheet("color:#ef5350;font-weight:600;font-size:13px;background:transparent;")
        hdr.addWidget(self.dot)
        self.toggle_btn = QPushButton("▶  Start Monitoring")
        self.toggle_btn.setObjectName("success_btn")
        self.toggle_btn.clicked.connect(self._toggle)
        hdr.addWidget(self.toggle_btn)
        lay.addLayout(hdr)

        sub = QLabel("Real-time event stream  ·  Polls all configured DCs every 30 seconds")
        sub.setObjectName("page_sub"); lay.addWidget(sub)

        # Options bar
        opt = QFrame(); opt.setObjectName("card")
        ol = QHBoxLayout(opt)
        self.lockout_only = QCheckBox("Show lockouts only (hide failed logons)")
        self.lockout_only.stateChanged.connect(self._apply_filter)
        ol.addWidget(self.lockout_only)
        self.alert_cb = QCheckBox("Popup alert on lockout")
        self.alert_cb.setChecked(True)
        ol.addWidget(self.alert_cb)
        ol.addStretch()
        self.count_lbl = QLabel("0 events")
        self.count_lbl.setObjectName("page_sub")
        ol.addWidget(self.count_lbl)
        clear = QPushButton("Clear"); clear.setObjectName("secondary_btn")
        clear.clicked.connect(self._clear)
        ol.addWidget(clear)
        lay.addWidget(opt)

        # Stream table
        sf = QFrame(); sf.setObjectName("card")
        sl = QVBoxLayout(sf)
        self.stream = EventTable()
        self.stream.row_double_clicked.connect(self._show_detail)
        sl.addWidget(self.stream)
        lay.addWidget(sf, 1)

    def set_servers(self, servers: List[str]):
        self.servers = servers

    def _toggle(self):
        if self._monitor and self._monitor.isRunning():
            self._stop()
        else:
            self._start()

    def _start(self):
        if not self.servers:
            QMessageBox.warning(self, "No DCs", "Configure domain controllers in DC Manager first.")
            return
        self._monitor = MonitorWorker(self.servers)
        self._monitor.event_found.connect(self._on_event)
        self._monitor.status.connect(self._on_status)
        self._monitor.start()

    def _stop(self):
        if self._monitor:
            self._monitor.stop()

    def _on_status(self, s: str):
        if s == "active":
            self.dot.setText("● MONITORING")
            self.dot.setStyleSheet("color:#2da44e;font-weight:600;font-size:13px;background:transparent;")
            self.toggle_btn.setText("⏹  Stop Monitoring")
            self.toggle_btn.setObjectName("danger_btn")
            self.toggle_btn.style().polish(self.toggle_btn)
        else:
            self.dot.setText("● STOPPED")
            self.dot.setStyleSheet("color:#ef5350;font-weight:600;font-size:13px;background:transparent;")
            self.toggle_btn.setText("▶  Start Monitoring")
            self.toggle_btn.setObjectName("success_btn")
            self.toggle_btn.style().polish(self.toggle_btn)

    def _on_event(self, ev: LockoutEvent):
        self._all_events.append(ev)
        if self.lockout_only.isChecked() and ev.event_id != 4740:
            return
        self.stream.add_event(ev)
        self.stream.scrollToBottom()
        self.count_lbl.setText(f"{len(self._all_events)} events")
        if self.alert_cb.isChecked() and ev.event_id == 4740:
            QMessageBox.warning(self, "Account Locked Out!",
                                f"Account '{ev.username}' locked out!\n"
                                f"Source: {ev.caller_machine or ev.caller_ip or 'Unknown'}\n"
                                f"DC: {ev.source_dc}")

    def _apply_filter(self):
        lockouts_only = self.lockout_only.isChecked()
        for row in range(self.stream.rowCount()):
            item = self.stream.item(row, 1)
            hide = lockouts_only and item and item.text() != "Account Locked Out"
            self.stream.setRowHidden(row, hide)

    def _clear(self):
        self._all_events.clear()
        self.stream.clearContents()
        self.stream.setRowCount(0)
        self.count_lbl.setText("0 events")

    def _show_detail(self, ev: LockoutEvent):
        d = EventDetailDialog(ev, self)
        d.exec()


class DCManagerPage(QWidget):
    servers_changed = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.dcs: List[str] = []
        self.pdc: str = ""
        self._worker = None
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(18)

        t = QLabel("DC Manager"); t.setObjectName("page_title"); lay.addWidget(t)
        s = QLabel("Configure domain controllers for scanning")
        s.setObjectName("page_sub"); lay.addWidget(s)

        # Controls
        cf = QFrame(); cf.setObjectName("card")
        cl = QVBoxLayout(cf)
        r1 = QHBoxLayout()
        self.disc_btn = QPushButton("🔎  Auto-Discover DCs from AD")
        self.disc_btn.setObjectName("primary_btn")
        self.disc_btn.clicked.connect(self._discover)
        r1.addWidget(self.disc_btn)
        r1.addStretch()
        cl.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Or add manually:"))
        self.dc_edit = QLineEdit()
        self.dc_edit.setPlaceholderText("DC hostname or IP address...")
        self.dc_edit.setFixedHeight(34)
        r2.addWidget(self.dc_edit, 1)
        add_btn = QPushButton("Add"); add_btn.setObjectName("secondary_btn")
        add_btn.setFixedHeight(34); add_btn.clicked.connect(self._add)
        r2.addWidget(add_btn)
        cl.addLayout(r2)

        self.disc_lbl = QLabel(""); self.disc_lbl.setObjectName("page_sub")
        cl.addWidget(self.disc_lbl)
        lay.addWidget(cf)

        # DC table
        tf = QFrame(); tf.setObjectName("card")
        tl = QVBoxLayout(tf)
        thdr = QHBoxLayout()
        self.dc_count_lbl = QLabel("0 DCs configured"); thdr.addWidget(self.dc_count_lbl)
        thdr.addStretch()
        ping_btn = QPushButton("🏓  Ping All"); ping_btn.setObjectName("secondary_btn")
        ping_btn.clicked.connect(self._ping_all); thdr.addWidget(ping_btn)
        tl.addLayout(thdr)

        self.dc_table = QTableWidget()
        self.dc_table.setColumnCount(4)
        self.dc_table.setHorizontalHeaderLabels(["Hostname", "Role", "IP", "Status"])
        h = self.dc_table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.dc_table.setAlternatingRowColors(True)
        self.dc_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.dc_table.verticalHeader().setVisible(False)
        self.dc_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.dc_table.customContextMenuRequested.connect(self._ctx)
        tl.addWidget(self.dc_table)
        lay.addWidget(tf, 1)

    def _discover(self):
        self.disc_btn.setEnabled(False)
        self.disc_lbl.setText("Discovering...")
        self._worker = DCDiscoveryWorker()
        self._worker.found.connect(self._on_found)
        self._worker.progress.connect(lambda m: self.disc_lbl.setText(m))
        self._worker.start()

    def _on_found(self, dcs: List[str], pdc: str):
        self.pdc = pdc
        for dc in dcs:
            if dc not in self.dcs:
                self.dcs.append(dc)
        if not self.dcs:
            localhost = socket.gethostname()
            if localhost not in self.dcs:
                self.dcs.append(localhost)
        self._refresh()
        self.disc_btn.setEnabled(True)
        self.disc_lbl.setText(f"Found {len(self.dcs)} DC(s).  PDC: {pdc or 'Unknown'}")
        self.servers_changed.emit(self.dcs)

    def _add(self):
        dc = self.dc_edit.text().strip()
        if dc and dc not in self.dcs:
            self.dcs.append(dc)
            self.dc_edit.clear()
            self._refresh()
            self.servers_changed.emit(self.dcs)

    def _refresh(self):
        self.dc_table.setRowCount(0)
        for dc in self.dcs:
            r = self.dc_table.rowCount(); self.dc_table.insertRow(r)
            role = "PDC Emulator" if dc == self.pdc else "DC"
            self.dc_table.setItem(r, 0, QTableWidgetItem(dc))
            role_item = QTableWidgetItem(role)
            if role == "PDC Emulator":
                role_item.setForeground(QColor("#ffa726"))
            self.dc_table.setItem(r, 1, role_item)
            self.dc_table.setItem(r, 2, QTableWidgetItem(""))
            self.dc_table.setItem(r, 3, QTableWidgetItem("—"))
        self.dc_count_lbl.setText(f"{len(self.dcs)} DC(s) configured")

    def _ping_all(self):
        for i, dc in enumerate(self.dcs):
            try:
                r = subprocess.run(["ping", "-n", "1", "-w", "1500", dc],
                                   capture_output=True, timeout=5)
                ok = r.returncode == 0
                item = QTableWidgetItem("Online" if ok else "Offline")
                item.setForeground(QColor("#2da44e" if ok else "#ef5350"))
                self.dc_table.setItem(i, 3, item)
                try:
                    ip = socket.gethostbyname(dc)
                    self.dc_table.setItem(i, 2, QTableWidgetItem(ip))
                except Exception:
                    pass
            except Exception:
                self.dc_table.setItem(i, 3, QTableWidgetItem("Error"))

    def _ctx(self, pos):
        row = self.dc_table.currentRow()
        if row < 0:
            return
        dc = self.dc_table.item(row, 0).text() if self.dc_table.item(row, 0) else ""
        menu = QMenu(self)
        menu.addAction(f"Remove {dc}").triggered.connect(lambda: self._remove(dc))
        menu.addAction(f"Ping {dc}").triggered.connect(lambda: self._single_ping(dc))
        menu.exec(self.dc_table.mapToGlobal(pos))

    def _remove(self, dc: str):
        if dc in self.dcs:
            self.dcs.remove(dc)
            self._refresh()
            self.servers_changed.emit(self.dcs)

    def _single_ping(self, dc: str):
        try:
            r = subprocess.run(["ping", "-n", "4", dc], capture_output=True, text=True, timeout=15)
            QMessageBox.information(self, f"Ping {dc}", r.stdout or r.stderr)
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def get_servers(self) -> List[str]:
        return self.dcs.copy()


class ReportsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.events: List[LockoutEvent] = []
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(18)

        t = QLabel("Reports"); t.setObjectName("page_title"); lay.addWidget(t)
        s = QLabel("Export event data and generate analysis reports")
        s.setObjectName("page_sub"); lay.addWidget(s)

        exp = QFrame(); exp.setObjectName("card")
        el = QVBoxLayout(exp)
        el.addWidget(QLabel("Export Data", objectName="section_ttl"))
        br = QHBoxLayout()
        for label, fn, obj in [
            ("📄  Export CSV", self._export_csv, "primary_btn"),
            ("📋  Export TXT Report", self._export_txt, "secondary_btn"),
            ("📦  Export JSON", self._export_json, "secondary_btn"),
        ]:
            b = QPushButton(label); b.setObjectName(obj); b.clicked.connect(fn); br.addWidget(b)
        br.addStretch()
        el.addLayout(br)
        lay.addWidget(exp)

        sf = QFrame(); sf.setObjectName("card")
        sl = QVBoxLayout(sf)
        sl.addWidget(QLabel("Statistics Report", objectName="section_ttl"))
        self.stats_txt = QTextEdit(); self.stats_txt.setReadOnly(True)
        sl.addWidget(self.stats_txt)
        lay.addWidget(sf, 1)

        self.status = QLabel("No data. Run a scan first."); self.status.setObjectName("page_sub")
        lay.addWidget(self.status)

    def update_events(self, events: List[LockoutEvent]):
        self.events = events
        self._gen_stats()

    def _gen_stats(self):
        if not self.events:
            self.stats_txt.setPlainText("No events loaded.")
            return
        e = self.events
        lines = [
            "ACCOUNT LOCKOUT REPORT", "="*60,
            f"Generated:    {datetime.datetime.now():%Y-%m-%d %H:%M:%S}",
            f"Total Events: {len(e)}",
            "",
        ]
        by_type = {}
        for ev in e: by_type[ev.event_type] = by_type.get(ev.event_type, 0) + 1
        lines += ["BY EVENT TYPE:", "-"*40]
        for k, v in sorted(by_type.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<35} {v}")
        lines.append("")

        by_user = {}
        for ev in e: by_user[ev.username] = by_user.get(ev.username, 0) + 1
        lines += ["TOP AFFECTED ACCOUNTS:", "-"*40]
        for k, v in sorted(by_user.items(), key=lambda x: -x[1])[:15]:
            lines.append(f"  {k:<35} {v}")
        lines.append("")

        by_mach = {}
        for ev in e:
            if ev.caller_machine:
                by_mach[ev.caller_machine] = by_mach.get(ev.caller_machine, 0) + 1
        if by_mach:
            lines += ["TOP SOURCE MACHINES:", "-"*40]
            for k, v in sorted(by_mach.items(), key=lambda x: -x[1])[:10]:
                lines.append(f"  {k:<35} {v}")
            lines.append("")

        by_ip = {}
        for ev in e:
            if ev.caller_ip:
                by_ip[ev.caller_ip] = by_ip.get(ev.caller_ip, 0) + 1
        if by_ip:
            lines += ["TOP SOURCE IPs:", "-"*40]
            for k, v in sorted(by_ip.items(), key=lambda x: -x[1])[:10]:
                lines.append(f"  {k:<20} {v}")
            lines.append("")

        self.stats_txt.setPlainText("\n".join(lines))
        self.status.setText(f"{len(self.events)} events loaded")

    def _export_csv(self):
        if not self.events:
            QMessageBox.information(self, "No Data", "No events to export."); return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV",
            f"lockout_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv", "CSV Files (*.csv)")
        if path:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["Timestamp","EventID","EventType","Username","Domain",
                             "SourceMachine","SourceIP","LogonType","AuthPackage",
                             "FailureReason","ProcessName","SourceDC"])
                for ev in self.events:
                    w.writerow([ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                                 ev.event_id, ev.event_type, ev.username, ev.domain,
                                 ev.caller_machine, ev.caller_ip, ev.logon_type_name,
                                 ev.auth_package, ev.failure_reason, ev.process_name, ev.source_dc])
            QMessageBox.information(self, "Exported", f"Saved to:\n{path}")

    def _export_txt(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report",
            f"lockout_report_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt", "Text Files (*.txt)")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.stats_txt.toPlainText())
            QMessageBox.information(self, "Exported", f"Saved to:\n{path}")

    def _export_json(self):
        if not self.events:
            QMessageBox.information(self, "No Data", "No events to export."); return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON",
            f"lockout_{datetime.datetime.now():%Y%m%d_%H%M%S}.json", "JSON Files (*.json)")
        if path:
            data = [{"timestamp": ev.timestamp.isoformat(), "event_id": ev.event_id,
                      "event_type": ev.event_type, "username": ev.username, "domain": ev.domain,
                      "caller_machine": ev.caller_machine, "caller_ip": ev.caller_ip,
                      "logon_type": ev.logon_type, "logon_type_name": ev.logon_type_name,
                      "auth_package": ev.auth_package, "failure_reason": ev.failure_reason,
                      "process_name": ev.process_name, "source_dc": ev.source_dc}
                     for ev in self.events]
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            QMessageBox.information(self, "Exported", f"Saved to:\n{path}")


class SettingsPage(QWidget):
    def __init__(self):
        super().__init__()
        self._build()
        self._load()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(18)

        t = QLabel("Settings"); t.setObjectName("page_title"); lay.addWidget(t)

        sf = QFrame(); sf.setObjectName("card")
        sl = QFormLayout(sf)
        sl.setSpacing(14)

        self.def_hours = QComboBox()
        self.def_hours.addItems(["1 hour","6 hours","24 hours","48 hours","7 days"])
        self.def_hours.setCurrentIndex(2)
        sl.addRow("Default scan range:", self.def_hours)

        self.spray_thresh = QSpinBox()
        self.spray_thresh.setRange(3, 50); self.spray_thresh.setValue(5)
        sl.addRow("Spray detection threshold (unique users):", self.spray_thresh)

        self.spray_window = QSpinBox()
        self.spray_window.setRange(1, 60); self.spray_window.setValue(10)
        sl.addRow("Spray detection window (minutes):", self.spray_window)

        self.skip_machine = QCheckBox("Skip machine accounts (usernames ending in $)")
        self.skip_machine.setChecked(True)
        sl.addRow("", self.skip_machine)

        self.skip_service = QCheckBox("Skip built-in service accounts (SYSTEM, LOCAL SERVICE, etc.)")
        self.skip_service.setChecked(True)
        sl.addRow("", self.skip_service)

        self.inc_kerb = QCheckBox("Include Kerberos pre-auth failures (Event 4771)")
        self.inc_kerb.setChecked(True)
        sl.addRow("", self.inc_kerb)

        self.inc_ntlm = QCheckBox("Include NTLM validation events (Event 4776)")
        self.inc_ntlm.setChecked(False)
        sl.addRow("", self.inc_ntlm)

        self.parse_netlog = QCheckBox("Parse Netlogon.log on DCs (requires admin$ share access)")
        sl.addRow("", self.parse_netlog)

        lay.addWidget(sf)

        save = QPushButton("💾  Save Settings"); save.setObjectName("primary_btn")
        save.clicked.connect(self._save); lay.addWidget(save, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addStretch()

    def _save(self):
        s = {
            'def_hours': [1,6,24,48,168][self.def_hours.currentIndex()],
            'spray_thresh': self.spray_thresh.value(),
            'spray_window': self.spray_window.value(),
            'skip_machine': self.skip_machine.isChecked(),
            'skip_service': self.skip_service.isChecked(),
            'inc_kerb': self.inc_kerb.isChecked(),
            'inc_ntlm': self.inc_ntlm.isChecked(),
            'parse_netlog': self.parse_netlog.isChecked(),
        }
        p = Path.home() / ".adlockoutbuster_settings.json"
        try:
            p.write_text(json.dumps(s, indent=2))
            QMessageBox.information(self, "Saved", "Settings saved successfully.")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _load(self):
        p = Path.home() / ".adlockoutbuster_settings.json"
        if not p.exists():
            return
        try:
            s = json.loads(p.read_text())
            idx = {1:0,6:1,24:2,48:3,168:4}.get(s.get('def_hours',24), 2)
            self.def_hours.setCurrentIndex(idx)
            self.spray_thresh.setValue(s.get('spray_thresh', 5))
            self.spray_window.setValue(s.get('spray_window', 10))
            self.skip_machine.setChecked(s.get('skip_machine', True))
            self.skip_service.setChecked(s.get('skip_service', True))
            self.inc_kerb.setChecked(s.get('inc_kerb', True))
            self.inc_ntlm.setChecked(s.get('inc_ntlm', False))
            self.parse_netlog.setChecked(s.get('parse_netlog', False))
        except Exception:
            pass

    def get(self) -> dict:
        return {
            'def_hours': [1,6,24,48,168][self.def_hours.currentIndex()],
            'spray_thresh': self.spray_thresh.value(),
            'spray_window': self.spray_window.value(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ADLockoutBuster — Account Lockout Finder Pro")
        self.setMinimumSize(1280, 720)
        self.resize(1440, 860)

        self._events: List[LockoutEvent] = []
        self._servers: List[str] = []
        self._scan_worker: Optional[ScanWorker] = None
        self.engine = LockoutEngine()

        self._build_ui()
        self._setup_statusbar()
        self._detect_env()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ──────────────────────────────────────────────
        sidebar = QWidget(); sidebar.setObjectName("sidebar")
        sb_lay = QVBoxLayout(sidebar)
        sb_lay.setContentsMargins(0, 0, 0, 0)
        sb_lay.setSpacing(0)

        logo = QWidget(); logo.setObjectName("logo_area"); logo.setFixedHeight(75)
        ll = QVBoxLayout(logo); ll.setContentsMargins(16, 16, 16, 10)
        title_lbl = QLabel("🔐 ADLockoutBuster")
        title_lbl.setStyleSheet("color:#58a6ff;font-size:15px;font-weight:700;background:transparent;")
        ll.addWidget(title_lbl)
        sub_lbl = QLabel("Pro Edition · Techify")
        sub_lbl.setStyleSheet("color:#484f58;font-size:11px;background:transparent;")
        ll.addWidget(sub_lbl)
        sb_lay.addWidget(logo)

        nav_items = [
            ("dashboard",    "📊  Dashboard"),
            ("investigate",  "🔍  Investigate"),
            ("active",       "🔒  Active Lockouts"),
            ("monitor",      "📡  Live Monitor"),
            ("dcmanager",    "🖥  DC Manager"),
            ("reports",      "📋  Reports"),
            ("settings",     "⚙  Settings"),
        ]
        self._nav_btns: Dict[str, QPushButton] = {}
        nav_wrap = QWidget(); nav_wrap.setStyleSheet("background:transparent;")
        nw = QVBoxLayout(nav_wrap); nw.setContentsMargins(8, 16, 8, 8); nw.setSpacing(2)
        for key, label in nav_items:
            btn = QPushButton(label); btn.setObjectName("nav_btn"); btn.setFixedHeight(42)
            btn.clicked.connect(lambda _, k=key: self._nav(k))
            nw.addWidget(btn); self._nav_btns[key] = btn
        nw.addStretch()
        sb_lay.addWidget(nav_wrap)

        ver = QLabel("v1.0.0"); ver.setStyleSheet("color:#484f58;font-size:11px;padding:8px 16px;background:transparent;")
        sb_lay.addWidget(ver)
        root.addWidget(sidebar)

        # ── Stack ─────────────────────────────────────────────────
        self.stack = QStackedWidget()
        self.dashboard_pg    = DashboardPage()
        self.investigate_pg  = InvestigatePage()
        self.active_pg       = ActiveLockoutsPage()
        self.monitor_pg      = MonitorPage()
        self.dcmanager_pg    = DCManagerPage()
        self.reports_pg      = ReportsPage()
        self.settings_pg     = SettingsPage()

        for pg in [self.dashboard_pg, self.investigate_pg, self.active_pg,
                   self.monitor_pg, self.dcmanager_pg, self.reports_pg, self.settings_pg]:
            self.stack.addWidget(pg)

        self._page_map = {
            "dashboard": 0, "investigate": 1, "active": 2,
            "monitor": 3, "dcmanager": 4, "reports": 5, "settings": 6,
        }

        # Wire signals
        self.dashboard_pg.scan_requested.connect(self._quick_scan)
        self.investigate_pg.scan_requested.connect(self._investigate_scan)
        self.dcmanager_pg.servers_changed.connect(self._on_servers_changed)

        root.addWidget(self.stack)
        self._nav("dashboard")

    def _setup_statusbar(self):
        sb = self.statusBar()
        self._status_lbl = QLabel("Ready  ·  Go to DC Manager to configure domain controllers")
        sb.addPermanentWidget(self._status_lbl, 1)
        self._progress = QProgressBar(); self._progress.setFixedSize(180, 5)
        self._progress.setVisible(False)
        sb.addPermanentWidget(self._progress)

    def _detect_env(self):
        domain = os.environ.get('USERDNSDOMAIN', '') or os.environ.get('USERDOMAIN', '')
        if domain:
            self._status_lbl.setText(f"Domain: {domain}  ·  Go to DC Manager → Auto-Discover DCs")
        else:
            self._status_lbl.setText("Not domain-joined (or domain undetected)  ·  Add DCs manually in DC Manager")

    def _nav(self, key: str):
        self.stack.setCurrentIndex(self._page_map.get(key, 0))
        for k, btn in self._nav_btns.items():
            btn.setProperty("active", str(k == key).lower())
            btn.style().unpolish(btn); btn.style().polish(btn)

    def _quick_scan(self):
        hours = self.settings_pg.get()['def_hours']
        servers = self._servers or ["localhost"]
        self._run_scan(servers, hours, "")

    def _investigate_scan(self, username: str, hours: float, _):
        servers = self._servers or ["localhost"]
        self._run_scan(servers, hours, username)

    def _run_scan(self, servers: List[str], hours: float, username: str):
        if self._scan_worker and self._scan_worker.isRunning():
            return
        self._progress.setVisible(True)
        self._progress.setRange(0, 0)
        self._status_lbl.setText(f"Scanning {len(servers)} DC(s)  ·  {username or 'all users'}  ·  {hours}h window...")
        self.dashboard_pg.scan_btn.setEnabled(False)

        self._scan_worker = ScanWorker(servers, hours, username)
        self._scan_worker.progress.connect(lambda m: self._status_lbl.setText(m))
        self._scan_worker.complete.connect(lambda evs: self._on_scan_done(evs, servers))
        self._scan_worker.start()

    def _on_scan_done(self, events: List[LockoutEvent], servers: List[str]):
        self._events = events
        cfg = self.settings_pg.get()
        sprays = self.engine.detect_spray_attacks(
            events,
            window_minutes=cfg['spray_window'],
            threshold=cfg['spray_thresh']
        )
        self.dashboard_pg.update(events, sprays)
        self.investigate_pg.update_events(events, servers)
        self.reports_pg.update_events(events)

        self._progress.setVisible(False)
        self.dashboard_pg.scan_btn.setEnabled(True)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._status_lbl.setText(
            f"Scan complete {ts}  ·  {len(events)} events  ·  "
            f"{len([e for e in events if e.event_id == 4740])} lockouts  ·  "
            f"{len(sprays)} spray alert(s)"
        )

    def _on_servers_changed(self, servers: List[str]):
        self._servers = servers
        self.monitor_pg.set_servers(servers)
        self._status_lbl.setText(f"{len(servers)} DC(s) configured  ·  Ready to scan")

    def closeEvent(self, event):
        if self._scan_worker and self._scan_worker.isRunning():
            self._scan_worker.stop()
        if self.monitor_pg._monitor and self.monitor_pg._monitor.isRunning():
            self.monitor_pg._monitor.stop()
        event.accept()


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("ADLockoutBuster")
    app.setOrganizationName("Techify")
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLE)

    win = MainWindow()
    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
