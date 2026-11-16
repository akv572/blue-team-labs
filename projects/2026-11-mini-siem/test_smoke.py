#!/usr/bin/env python3
"""End-to-end smoke test: regenerate samples, ingest, detect, report,
and check every rule fires on the synthetic attacks."""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECT = {
    "failed-logon-burst": 1,
    "password-spray": 1,
    "success-after-burst": 1,
    "new-user-created": 1,
    "off-hours-admin-logon": 1,
}


def run(*cmd, cwd=HERE):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        print("FAILED:", " ".join(cmd))
        print(r.stdout)
        print(r.stderr)
        sys.exit(1)
    return r.stdout


def main():
    tmp = tempfile.mkdtemp(prefix="minisiem-test-")
    for name in ("minisiem", "rules"):
        shutil.copytree(os.path.join(HERE, name), os.path.join(tmp, name))
    shutil.copy(os.path.join(HERE, "main.py"), tmp)
    os.makedirs(os.path.join(tmp, "samples"))
    run(sys.executable, os.path.join(HERE, "scripts", "make_samples.py"))
    for f in os.listdir(os.path.join(HERE, "samples")):
        shutil.copy(os.path.join(HERE, "samples", f),
                    os.path.join(tmp, "samples", f))

    run(sys.executable, "main.py", "ingest",
        "--auth", "samples/auth.log",
        "--winevent", "samples/windows_security.csv",
        "--access", "samples/access.log",
        "--db", "t.db", "--year", "2026", cwd=tmp)
    run(sys.executable, "main.py", "detect", "--db", "t.db",
        "--rules", "rules", cwd=tmp)
    run(sys.executable, "main.py", "report", "--db", "t.db",
        "--out", "report.md", cwd=tmp)

    with open(os.path.join(tmp, "report.md"), encoding="utf-8") as fh:
        content = fh.read()

    failures = []
    for rule_id, minimum in EXPECT.items():
        count = content.count("| %s |" % rule_id)
        if count < minimum:
            failures.append("%s: expected >= %d alerts, found %d"
                            % (rule_id, minimum, count))
    for needle in ("Failed logon burst", "password spray",
                   "Successful logon after burst",
                   "New user account created",
                   "Off-hours privileged logon"):
        if needle not in content:
            failures.append("missing alert title %r" % needle)

    shutil.rmtree(tmp, ignore_errors=True)
    if failures:
        print("SMOKE TEST FAILED")
        for f in failures:
            print(" -", f)
        sys.exit(1)
    print("smoke test passed: every rule fired on the sample logs")


if __name__ == "__main__":
    main()
