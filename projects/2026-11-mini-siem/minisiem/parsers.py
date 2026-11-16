"""Parsers that normalise three log formats into the shared event schema.

Supported inputs:
  - auth: Linux syslog sshd lines, e.g.
      Oct 15 22:14:03 soclab sshd[1842]: Failed password for root from 203.0.113.7 port 51235 ssh2
  - winevent: CSV exports of Windows Security log events, columns:
      TimeCreated,EventID,Computer,TargetUserName,TargetDomainName,
      SubjectUserName,IpAddress,LogonType,WorkstationName
  - access: Apache/Nginx combined access log lines.

Only authentication-relevant lines are kept; everything else is dropped.
"""

import csv
import re
from datetime import datetime, timezone

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

AUTH_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)
AUTH_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")
AUTH_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port")

ACCESS_LINE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) \d+ "[^"]*" "[^"]*"$'
)

# Event IDs mapped to the normalised event names.
WINEVENT_MAP = {
    4624: "auth_success",
    4625: "auth_failed",
    4720: "user_created",
    4740: "account_locked",
}

# HTTP statuses on login-looking paths that count as failed auth attempts.
WEB_FAILED_STATUSES = {401, 403}
WEB_LOGIN_PATH_HINTS = ("login", "wp-login", "signin", "auth", "admin")


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_auth_log(path, year=None):
    """Parse a Linux auth.log, returning normalised event dicts."""
    events = []
    year = year or datetime.now(timezone.utc).year
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = AUTH_LINE.match(line)
            if not m:
                continue
            try:
                dt = datetime(
                    year,
                    MONTHS[m.group("mon")],
                    int(m.group("day")),
                    *map(int, m.group("time").split(":")),
                    tzinfo=timezone.utc,
                )
            except (KeyError, ValueError):
                continue
            msg = m.group("msg")
            failed = AUTH_FAILED.search(msg)
            accepted = AUTH_ACCEPTED.search(msg)
            if failed:
                user, ip = failed.group(1), failed.group(2)
                events.append({
                    "ts": _iso(dt), "src": "auth", "host": m.group("host"),
                    "user": user, "src_ip": ip, "event": "auth_failed",
                    "detail": "sshd failed password", "raw": line,
                })
            elif accepted:
                user, ip = accepted.group(1), accepted.group(2)
                events.append({
                    "ts": _iso(dt), "src": "auth", "host": m.group("host"),
                    "user": user, "src_ip": ip, "event": "auth_success",
                    "detail": "sshd accepted logon", "raw": line,
                })
    return events


def parse_winevent_csv(path):
    """Parse a Windows Security event CSV export."""
    events = []
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            try:
                event_id = int(str(row.get("EventID", "")).strip())
            except ValueError:
                continue
            if event_id not in WINEVENT_MAP:
                continue
            ts_raw = str(row.get("TimeCreated", "")).strip()
            try:
                dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                continue
            events.append({
                "ts": _iso(dt),
                "src": "winevent",
                "host": (row.get("Computer") or "").strip() or None,
                "user": (row.get("TargetUserName") or "").strip() or None,
                "src_ip": (row.get("IpAddress") or "").strip() or None,
                "event": WINEVENT_MAP[event_id],
                "detail": "EventID %d LogonType %s" % (
                    event_id, (row.get("LogonType") or "").strip() or "-"),
                "raw": ",".join((row.get(k) or "") for k in
                                ("TimeCreated", "EventID", "Computer",
                                 "TargetUserName", "IpAddress", "LogonType")),
            })
    return events


def parse_access_log(path):
    """Parse a combined web access log, keeping failed logon attempts."""
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = ACCESS_LINE.match(line)
            if not m:
                continue
            ip, ts_raw, method, path, status = (
                m.group(1), m.group(2), m.group(3), m.group(4), int(m.group(5)))
            lowered = path.lower()
            if status not in WEB_FAILED_STATUSES:
                continue
            if not any(hint in lowered for hint in WEB_LOGIN_PATH_HINTS):
                continue
            try:
                dt = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                continue
            events.append({
                "ts": _iso(dt), "src": "access", "host": None,
                "user": None, "src_ip": ip, "event": "http_auth_failed",
                "detail": "%s %s -> %d" % (method, path, status),
                "raw": line,
            })
    return events


FAILED_EVENTS = ("auth_failed", "http_auth_failed")
SUCCESS_EVENTS = ("auth_success",)
