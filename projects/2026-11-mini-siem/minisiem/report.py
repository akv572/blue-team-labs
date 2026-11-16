"""Markdown alert report writer."""

from datetime import datetime, timezone


def write_report(path, alerts, stats):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ordered = sorted(alerts, key=lambda a: (sev_rank.get(a["severity"], 9), a["ts"]))

    lines = []
    lines.append("# mini-siem alert report")
    lines.append("")
    lines.append("Generated: %s" % now)
    lines.append("Events analysed: %d (%s)" % (
        stats["events"],
        ", ".join("%s=%d" % kv for kv in sorted(stats["by_src"].items()))))
    lines.append("Alerts raised: %d" % len(alerts))
    lines.append("")

    if not alerts:
        lines.append("No alerts. Nothing matched the loaded detection rules.")
        lines.append("")
    else:
        lines.append("## Summary")
        lines.append("")
        lines.append("| # | Severity | Rule | Alert | Time (UTC) |")
        lines.append("|---|----------|------|-------|------------|")
        for i, a in enumerate(ordered, 1):
            lines.append("| %d | %s | %s | %s | %s |" % (
                i, a["severity"], a["rule_id"], a["title"], a["ts"]))
        lines.append("")
        for i, a in enumerate(ordered, 1):
            lines.append("## %d. %s" % (i, a["title"]))
            lines.append("")
            lines.append("- Severity: %s" % a["severity"])
            lines.append("- Rule: %s (%s)" % (a["rule_name"], a["rule_id"]))
            lines.append("- Time: %s" % a["ts"])
            lines.append("- Source IP: %s" % (a["src_ip"] or "-"))
            lines.append("- User: %s" % (a["user"] or "-"))
            lines.append("- What happened: %s" % (a["summary"] or "-"))
            lines.append("")
            lines.append("Evidence:")
            lines.append("")
            lines.append("```")
            lines.append(a["evidence"] or "(none)")
            lines.append("```")
            lines.append("")

    lines.append("---")
    lines.append("Scope note: mini-siem is a from-scratch learning build. It")
    lines.append("detects a small set of logon-abuse patterns in batch, not real")
    lines.append("time, and it is not a substitute for a production SIEM.")
    lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path
