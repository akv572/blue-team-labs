#!/usr/bin/env python3
"""Command line interface for mini-siem.

Usage:
    python3 main.py run
        Ingest the bundled samples, run the rules and write report.md.

    python3 main.py ingest --auth samples/auth.log --winevent samples/windows_security.csv \\
        --access samples/access.log --db minisiem.db
    python3 main.py detect --db minisiem.db --rules rules/
    python3 main.py report --db minisiem.db --out report.md
"""

import argparse
import os
import sqlite3
import sys

from minisiem import parsers, report as report_mod, rules as rules_mod, schema

HERE = os.path.dirname(os.path.abspath(__file__))


def cmd_ingest(args):
    events = []
    if args.auth:
        events.extend(parsers.parse_auth_log(args.auth, year=args.year))
    if args.winevent:
        events.extend(parsers.parse_winevent_csv(args.winevent))
    if args.access:
        events.extend(parsers.parse_access_log(args.access))
    if os.path.exists(args.db):
        os.remove(args.db)
    conn = sqlite3.connect(args.db)
    schema.init_db(conn)
    schema.insert_events(conn, events)
    by_src = {}
    for e in events:
        by_src[e["src"]] = by_src.get(e["src"], 0) + 1
    conn.close()
    print("ingested %d events: %s" % (
        len(events), ", ".join("%s=%d" % kv for kv in sorted(by_src.items()))))
    return {"events": len(events), "by_src": by_src}


def cmd_detect(args):
    conn = sqlite3.connect(args.db)
    loaded = rules_mod.load_rules(args.rules)
    print("loaded %d rules" % len(loaded))
    alerts = rules_mod.run_rules(conn, loaded)
    conn.execute("DELETE FROM alerts")
    for a in alerts:
        schema.insert_alert(conn, a)
    conn.close()
    print("raised %d alerts" % len(alerts))
    return alerts


def cmd_report(args):
    conn = sqlite3.connect(args.db)
    cols = ("rule_id", "rule_name", "severity", "ts", "src_ip", "user",
            "title", "summary", "evidence")
    alerts = [dict(zip(cols, row)) for row in conn.execute(
        "SELECT %s FROM alerts ORDER BY ts" % ",".join(cols))]
    by_src = dict(conn.execute(
        "SELECT src, COUNT(*) FROM events GROUP BY src"))
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    report_mod.write_report(args.out, alerts, {"events": total, "by_src": by_src})
    print("wrote %s" % args.out)
    return alerts


def main(argv=None):
    ap = argparse.ArgumentParser(description="mini-siem log analyser")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest")
    p.add_argument("--auth", default=None)
    p.add_argument("--winevent", default=None)
    p.add_argument("--access", default=None)
    p.add_argument("--db", default=os.path.join(HERE, "minisiem.db"))
    p.add_argument("--year", type=int, default=2026,
                   help="year assumed for auth.log timestamps")

    p = sub.add_parser("detect")
    p.add_argument("--db", default=os.path.join(HERE, "minisiem.db"))
    p.add_argument("--rules", default=os.path.join(HERE, "rules"))

    p = sub.add_parser("report")
    p.add_argument("--db", default=os.path.join(HERE, "minisiem.db"))
    p.add_argument("--out", default=os.path.join(HERE, "report.md"))

    sub.add_parser("run")
    args = ap.parse_args(argv)

    if args.cmd == "run":
        args.auth = os.path.join(HERE, "samples", "auth.log")
        args.winevent = os.path.join(HERE, "samples", "windows_security.csv")
        args.access = os.path.join(HERE, "samples", "access.log")
        args.db = os.path.join(HERE, "minisiem.db")
        args.rules = os.path.join(HERE, "rules")
        args.out = os.path.join(HERE, "report.md")
        args.year = 2026
        cmd_ingest(args)
        cmd_detect(args)
        cmd_report(args)
        return 0

    if args.cmd == "ingest":
        cmd_ingest(args)
    elif args.cmd == "detect":
        cmd_detect(args)
    elif args.cmd == "report":
        cmd_report(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
