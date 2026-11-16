"""Generate the bundled sample logs.

Deterministic (fixed seed) synthetic data with planted attacks so the tool
runs out of the box. No real systems, credentials or addresses are used.
Documentation ranges (203.0.113.0/24, 198.51.100.0/24) stand in for
attacker and internal addresses.
"""

import csv
import os
import random
from datetime import datetime, timedelta, timezone

SEED = 7
BASE = datetime(2026, 10, 15, 0, 0, 0, tzinfo=timezone.utc)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(HERE, "samples")

ATTACKER = "203.0.113.7"
SPRAYER = "198.51.100.44"
INTERNAL = ["198.51.100.9", "198.51.100.21", "198.51.100.30"]
STAFF = ["arun", "priya", "david", "mei"]
SPRAY_USERS = ["admin", "root", "test", "user", "guest", "oracle",
               "postgres", "backup", "operator", "manager", "support", "info"]

os.makedirs(SAMPLES, exist_ok=True)


def write_auth_log():
    rng = random.Random(SEED)
    lines = []

    def line(dt, host, pid, msg):
        return "%s %s sshd[%d]: %s" % (
            dt.strftime("%b %d %H:%M:%S"), host, pid, msg)

    # Benign daytime logons.
    pid = 1000
    for hour in range(7, 19):
        for _ in range(rng.randint(2, 5)):
            dt = BASE + timedelta(hours=hour, minutes=rng.randint(0, 59),
                                  seconds=rng.randint(0, 59))
            user = rng.choice(STAFF)
            ip = rng.choice(INTERNAL)
            pid += 1
            lines.append(line(dt, "soclab", pid,
                              "Accepted password for %s from %s port %d ssh2"
                              % (user, ip, rng.randint(40000, 60000))))
    # Occasional mistyped password, then a success.
    for day_minute in (8 * 60 + 41, 13 * 60 + 7):
        dt = BASE + timedelta(minutes=day_minute)
        pid += 1
        lines.append(line(dt, "soclab", pid,
                          "Failed password for arun from 198.51.100.9 port 51201 ssh2"))
        pid += 1
        lines.append(line(dt + timedelta(seconds=18), "soclab", pid,
                          "Accepted password for arun from 198.51.100.9 port 51202 ssh2"))

    # Attack A: web login brute force, then SSH brute force, then a success.
    dt = BASE + timedelta(hours=22, minutes=5)
    for i in range(22):
        dt += timedelta(seconds=rng.randint(15, 35))
        pid += 1
        lines.append(line(dt, "soclab", pid,
                          "Failed password for invalid user admin from %s port %d ssh2"
                          % (ATTACKER, rng.randint(40000, 60000))))
    dt = BASE + timedelta(hours=22, minutes=14, seconds=3)
    for i in range(25):
        user = rng.choice(["root", "admin"])
        lines.append(line(dt, "soclab", pid + 1 + i,
                          "Failed password for %s%s from %s port %d ssh2" % (
                              "invalid user " if user == "admin" else "",
                              user, ATTACKER, rng.randint(40000, 60000))))
        dt += timedelta(seconds=rng.randint(10, 25))
    # The brute force worked: root logs on 12 minutes after the burst.
    lines.append(line(dt + timedelta(minutes=12), "soclab", pid + 100,
                      "Accepted password for root from %s port 51555 ssh2" % ATTACKER))

    # Attack B: password spray, slow enough to dodge the burst rule.
    dt = BASE + timedelta(hours=9, minutes=2)
    for i in range(30):
        user = SPRAY_USERS[i % len(SPRAY_USERS)]
        lines.append(line(dt, "soclab", 2000 + i,
                          "Failed password for %s%s from %s port %d ssh2" % (
                              "invalid user " if user in ("test", "guest", "info") else "",
                              user, SPRAYER, rng.randint(40000, 60000))))
        dt += timedelta(seconds=rng.randint(90, 130))

    # Service noise the parser must ignore.
    for i in range(6):
        dt = BASE + timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
        lines.append("%s soclab CRON[%d]: pam_unix(cron:session): session opened"
                     % (dt.strftime("%b %d %H:%M:%S"), 3000 + i))

    lines.sort()
    with open(os.path.join(SAMPLES, "auth.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote auth.log: %d lines" % len(lines))


def write_winevent_csv():
    rng = random.Random(SEED + 1)
    rows = []

    def row(dt, event_id, user, ip=None, logon_type=""):
        return {
            "TimeCreated": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EventID": event_id,
            "Computer": "DC01.corp.local",
            "TargetUserName": user,
            "TargetDomainName": "CORP",
            "SubjectUserName": "-",
            "IpAddress": ip or "-",
            "LogonType": logon_type,
            "WorkstationName": "-",
        }

    # Benign logons through the day.
    for hour in range(7, 18):
        dt = BASE + timedelta(hours=hour, minutes=rng.randint(0, 59))
        rows.append(row(dt, 4624, rng.choice(STAFF), rng.choice(INTERNAL), "2"))
    # One failed logon pair a user would recognise as a typo.
    rows.append(row(BASE + timedelta(hours=11, minutes=22), 4625, "arun",
                    "198.51.100.9", "2"))
    rows.append(row(BASE + timedelta(hours=11, minutes=23), 4624, "arun",
                    "198.51.100.9", "2"))

    # Attack C: 4625 burst against one account, then a 4624 success.
    dt = BASE + timedelta(hours=21, minutes=40)
    for i in range(15):
        rows.append(row(dt, 4625, "j.chen", ATTACKER, "3"))
        dt += timedelta(seconds=rng.randint(20, 45))
    rows.append(row(dt + timedelta(minutes=18), 4624, "j.chen", ATTACKER, "3"))

    # Attack D: off-hours privileged logon, then a new service-style account.
    rows.append(row(BASE + timedelta(hours=3, minutes=42), 4624,
                    "Administrator", "198.51.100.21", "2"))
    rows.append(row(BASE + timedelta(hours=3, minutes=47), 4720,
                    "svc_backup", "-", ""))

    rows.sort(key=lambda r: r["TimeCreated"])
    path = os.path.join(SAMPLES, "windows_security.csv")
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print("wrote windows_security.csv: %d rows" % len(rows))


def write_access_log():
    rng = random.Random(SEED + 2)
    lines = []

    def line(dt, ip, method, path, status, size=5123):
        return ('%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "Mozilla/5.0"' % (
            ip, dt.strftime("%d/%b/%Y:%H:%M:%S +0000"), method, path, status, size))

    # Benign traffic.
    for i in range(120):
        dt = BASE + timedelta(hours=rng.randint(6, 22),
                              minutes=rng.randint(0, 59),
                              seconds=rng.randint(0, 59))
        lines.append(line(dt, rng.choice(INTERNAL), "GET",
                          rng.choice(["/", "/index.html", "/about", "/docs/api"]), 200))
    # Attack A continued: wp-login brute force with 401s.
    dt = BASE + timedelta(hours=22, minutes=5)
    for i in range(22):
        lines.append(line(dt, ATTACKER, "POST", "/wp-login.php", 401, 482))
        dt += timedelta(seconds=rng.randint(15, 35))

    lines.sort()
    with open(os.path.join(SAMPLES, "access.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote access.log: %d lines" % len(lines))


if __name__ == "__main__":
    write_auth_log()
    write_winevent_csv()
    write_access_log()
