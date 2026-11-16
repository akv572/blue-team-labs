# mini-siem

A small SIEM-style log analyser written from scratch in Python. It ingests
Linux auth logs, Windows Security event CSV exports and web access logs,
normalises them into one event schema in SQLite, runs YAML detection rules,
and writes a Markdown alert report.

## What it does

```
samples/ --ingest--> SQLite events --rules--> alerts --report--> report.md
```

1. **Parsers** read three log formats and keep only authentication-relevant
   lines: sshd failed/accepted logons from `auth.log`, Event IDs 4624, 4625,
   4720 and 4740 from a Windows Security CSV export, and 401/403 responses
   on login-looking paths from a combined web access log.
2. **Normalisation** stores every kept line as one row with a UTC timestamp,
   source, host, user, source IP, event name, detail and the raw line.
3. **Rules** are plain YAML files in `rules/`. Five ship with the project:
   failed logon burst, password spray, successful logon after a burst,
   new user creation, and off-hours privileged logon.
4. **Report** renders every alert with severity, evidence rows and a
   plain-English summary.

## Honest scope

This is a from-scratch learning build, not production SIEM experience. It
runs in batch on static log files, has no real-time ingestion, no agent,
no correlation across days, and no alert tuning beyond the five bundled
rules. The sample logs are synthetic. I built it to practise the log
analysis workflow SOC analysts actually do: parse, normalise, detect,
triage, write it up.

## Quickstart

```bash
pip install -r requirements.txt
python3 scripts/make_samples.py   # regenerate the bundled sample logs
python3 main.py run               # ingest, detect, report
```

`report.md` appears in the project root. Individual steps:

```bash
python3 main.py ingest --auth samples/auth.log \
    --winevent samples/windows_security.csv --access samples/access.log \
    --db minisiem.db --year 2026
python3 main.py detect --db minisiem.db --rules rules/
python3 main.py report --db minisiem.db --out report.md
python3 test_smoke.py   # end-to-end check: every rule must fire
```

Drop your own logs in by pointing `ingest` at your files, and add rules by
copying one of the YAML files in `rules/` and changing the type and params.
Rule types: `burst`, `spray`, `success_after_fail`, `new_user`,
`off_hours_admin`.

## Rules

| Rule | Type | Default threshold |
|---|---|---|
| Failed logon burst | `burst` | 10 failures, one IP, 10 min |
| Password spray | `spray` | 10 failures across 5 accounts, one IP, 60 min |
| Successful logon after burst | `success_after_fail` | success within 30 min of a burst, same IP |
| New user account created | `new_user` | any Event ID 4720 |
| Off-hours privileged logon | `off_hours_admin` | admin/root logon outside 06:00-22:00 |

## Example output

On the bundled samples (173 events), the tool raises 9 alerts, including:

- critical: `Successful logon after burst from 203.0.113.7` - the SSH brute
  force against root worked; a logon followed 12 minutes later.
- high: `Possible password spray: 12 accounts from 198.51.100.44` - 30
  failures across 12 usernames inside an hour, deliberately slow enough to
  dodge the burst rule.
- high: `Failed logon burst: 48 failures from 203.0.113.7` - the same
  attacker hitting SSH and wp-login in the same 10 minute window, which is
  why cross-source normalisation matters.
- medium: `Off-hours privileged logon: Administrator` at 03:42, followed by
  `New user account created: svc_backup` five minutes later.

## Layout

```
main.py            CLI: ingest | detect | report | run
minisiem/          parsers, SQLite schema, rule engine, report writer
rules/             five YAML detection rules
samples/           synthetic logs (regenerate with scripts/make_samples.py)
scripts/           sample log generator
test_smoke.py      end-to-end test
```
