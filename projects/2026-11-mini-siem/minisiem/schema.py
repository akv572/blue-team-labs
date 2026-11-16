"""Shared SQLite schema for normalised events and generated alerts."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    src TEXT NOT NULL,
    host TEXT,
    user TEXT,
    src_ip TEXT,
    event TEXT NOT NULL,
    detail TEXT,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_event ON events (event);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    ts TEXT NOT NULL,
    src_ip TEXT,
    user TEXT,
    title TEXT NOT NULL,
    summary TEXT,
    evidence TEXT
);
"""

# ts is an ISO-8601 UTC string, src is one of auth | winevent | access,
# event is one of auth_failed | auth_success | http_auth_failed |
# user_created | account_locked.


def init_db(conn):
    conn.executescript(SCHEMA)
    conn.commit()


def insert_events(conn, events):
    conn.executemany(
        "INSERT INTO events (ts, src, host, user, src_ip, event, detail, raw)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                e["ts"],
                e["src"],
                e.get("host"),
                e.get("user"),
                e.get("src_ip"),
                e["event"],
                e.get("detail"),
                e.get("raw"),
            )
            for e in events
        ],
    )
    conn.commit()


def insert_alert(conn, alert):
    conn.execute(
        "INSERT INTO alerts (rule_id, rule_name, severity, ts, src_ip, user,"
        " title, summary, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            alert["rule_id"],
            alert["rule_name"],
            alert["severity"],
            alert["ts"],
            alert.get("src_ip"),
            alert.get("user"),
            alert["title"],
            alert.get("summary"),
            alert.get("evidence"),
        ),
    )
    conn.commit()
