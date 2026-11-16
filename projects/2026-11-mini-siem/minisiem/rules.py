"""YAML detection rules and the engine that evaluates them.

Each rule file is YAML with: id, name, severity, description, type, params.
Supported rule types:
  burst              - N failed logons from one source IP inside a window
  spray              - one source IP failing against M distinct accounts
  success_after_fail - a successful logon from an IP shortly after its burst
  new_user           - a user-creation event was observed
  off_hours_admin    - a privileged account logging on outside working hours
"""

import glob
import os
from datetime import datetime, timedelta, timezone

import yaml

from .parsers import FAILED_EVENTS, SUCCESS_EVENTS

ADMIN_USERS = {"administrator", "admin", "root", "sa", "domain admins"}


def load_rules(rules_dir):
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml")) +
                       glob.glob(os.path.join(rules_dir, "*.yaml"))):
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if doc:
            doc["_file"] = os.path.basename(path)
            rules.append(doc)
    return rules


def _parse_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fetch(conn, event_names, extra=""):
    q = ("SELECT ts, src, host, user, src_ip, event, detail, raw FROM events"
         " WHERE event IN (%s) %s ORDER BY ts" % (
             ",".join("?" * len(event_names)), extra))
    return [dict(zip(
        ("ts", "src", "host", "user", "src_ip", "event", "detail", "raw"), row))
        for row in conn.execute(q, event_names)]


def _fmt_evidence(rows, limit=10):
    lines = []
    for r in rows[:limit]:
        lines.append("%s | %-8s | ip=%s user=%s | %s" % (
            r["ts"], r["src"], r["src_ip"] or "-", r["user"] or "-", r["detail"] or ""))
    if len(rows) > limit:
        lines.append("... and %d more events" % (len(rows) - limit))
    return "\n".join(lines)


def _rule_burst(conn, rule):
    p = rule["params"]
    window = timedelta(minutes=p["window_minutes"])
    threshold = p["threshold"]
    by_ip = {}
    for e in _fetch(conn, list(FAILED_EVENTS)):
        by_ip.setdefault(e["src_ip"], []).append(e)
    alerts = []
    for ip, evs in sorted(by_ip.items()):
        evs.sort(key=lambda e: e["ts"])
        i = 0
        while i < len(evs):
            j = i
            while j + 1 < len(evs) and \
                    _parse_ts(evs[j + 1]["ts"]) - _parse_ts(evs[i]["ts"]) <= window:
                j += 1
            count = j - i + 1
            if count >= threshold:
                win = evs[i:j + 1]
                users = sorted({e["user"] for e in win if e["user"]})
                alerts.append({
                    "rule_id": rule["id"], "rule_name": rule["name"],
                    "severity": rule["severity"], "ts": win[-1]["ts"],
                    "src_ip": ip, "user": users[0] if users else None,
                    "title": "Failed logon burst: %d failures from %s" % (count, ip),
                    "summary": ("%d failed logons from %s within %d minutes,"
                                " targeting %d account(s): %s" % (
                                    count, ip, p["window_minutes"],
                                    len(users), ", ".join(users[:5]) or "-")),
                    "evidence": _fmt_evidence(win),
                    "_burst": {"ip": ip, "start": win[0]["ts"], "end": win[-1]["ts"]},
                })
                i = j + 1
            else:
                i += 1
    return alerts


def _rule_spray(conn, rule):
    p = rule["params"]
    window = timedelta(minutes=p["window_minutes"])
    by_ip = {}
    for e in _fetch(conn, list(FAILED_EVENTS)):
        if e["user"]:
            by_ip.setdefault(e["src_ip"], []).append(e)
    alerts = []
    for ip, evs in sorted(by_ip.items()):
        evs.sort(key=lambda e: e["ts"])
        i = 0
        while i < len(evs):
            j = i
            while j + 1 < len(evs) and \
                    _parse_ts(evs[j + 1]["ts"]) - _parse_ts(evs[i]["ts"]) <= window:
                j += 1
            win = evs[i:j + 1]
            users = {e["user"] for e in win}
            if len(win) >= p["min_failures"] and len(users) >= p["min_accounts"]:
                alerts.append({
                    "rule_id": rule["id"], "rule_name": rule["name"],
                    "severity": rule["severity"], "ts": win[-1]["ts"],
                    "src_ip": ip, "user": None,
                    "title": "Possible password spray: %d accounts from %s" % (
                        len(users), ip),
                    "summary": ("%d failed logons against %d distinct accounts"
                                " from %s within %d minutes" % (
                                    len(win), len(users), ip, p["window_minutes"])),
                    "evidence": _fmt_evidence(win),
                })
                i = j + 1
            else:
                i += 1
    return alerts


def _rule_success_after_fail(conn, rule, burst_alerts):
    p = rule["params"]
    follow = timedelta(minutes=p["follow_minutes"])
    successes = _fetch(conn, list(SUCCESS_EVENTS))
    alerts = []
    for b in burst_alerts:
        info = b["_burst"]
        start = _parse_ts(info["start"])
        end = _parse_ts(info["end"])
        hits = [e for e in successes
                if e["src_ip"] == info["ip"]
                and start <= _parse_ts(e["ts"]) <= end + follow]
        for e in hits:
            alerts.append({
                "rule_id": rule["id"], "rule_name": rule["name"],
                "severity": rule["severity"], "ts": e["ts"],
                "src_ip": e["src_ip"], "user": e["user"],
                "title": "Successful logon after burst from %s" % e["src_ip"],
                "summary": ("Account '%s' logged on successfully from %s within"
                            " %d minutes of a failed-logon burst - possible"
                            " compromised credential" % (
                                e["user"], e["src_ip"], p["follow_minutes"])),
                "evidence": _fmt_evidence([e]),
            })
    return alerts


def _rule_new_user(conn, rule):
    alerts = []
    for e in _fetch(conn, ["user_created"]):
        alerts.append({
            "rule_id": rule["id"], "rule_name": rule["name"],
            "severity": rule["severity"], "ts": e["ts"],
            "src_ip": e["src_ip"], "user": e["user"],
            "title": "New user account created: %s" % (e["user"] or "?"),
            "summary": "User creation event on %s: %s" % (e["host"] or "-", e["detail"]),
            "evidence": _fmt_evidence([e]),
        })
    return alerts


def _rule_off_hours_admin(conn, rule):
    p = rule["params"]
    start, end = p["day_start_hour"], p["day_end_hour"]
    alerts = []
    for e in _fetch(conn, list(SUCCESS_EVENTS)):
        if not e["user"] or e["user"].lower() not in ADMIN_USERS:
            continue
        hour = _parse_ts(e["ts"]).hour
        if start <= hour < end:
            continue
        alerts.append({
            "rule_id": rule["id"], "rule_name": rule["name"],
            "severity": rule["severity"], "ts": e["ts"],
            "src_ip": e["src_ip"], "user": e["user"],
            "title": "Off-hours privileged logon: %s" % e["user"],
            "summary": ("Privileged account '%s' logged on at %s UTC from %s,"
                        " outside the %02d:00-%02d:00 window" % (
                            e["user"], e["ts"][11:16], e["src_ip"] or "-",
                            start, end)),
            "evidence": _fmt_evidence([e]),
        })
    return alerts


def run_rules(conn, rules):
    """Evaluate every rule; returns a list of alert dicts (without _burst)."""
    alerts = []
    burst_alerts = []
    for rule in rules:
        rtype = rule["type"]
        if rtype == "burst":
            found = _rule_burst(conn, rule)
            burst_alerts.extend(found)
            alerts.extend(found)
        elif rtype == "spray":
            alerts.extend(_rule_spray(conn, rule))
        elif rtype == "new_user":
            alerts.extend(_rule_new_user(conn, rule))
        elif rtype == "off_hours_admin":
            alerts.extend(_rule_off_hours_admin(conn, rule))
        elif rtype == "success_after_fail":
            alerts.extend(_rule_success_after_fail(conn, rule, burst_alerts))
        else:
            raise ValueError("Unknown rule type %r in %s" % (rtype, rule.get("_file")))
    for a in alerts:
        a.pop("_burst", None)
    # Drop exact duplicates: one success can fall inside the follow window
    # of two overlapping bursts from the same source IP.
    seen = set()
    unique = []
    for a in alerts:
        key = (a["rule_id"], a["ts"], a["src_ip"], a["user"], a["title"])
        if key not in seen:
            seen.add(key)
            unique.append(a)
    unique.sort(key=lambda a: a["ts"])
    return unique
