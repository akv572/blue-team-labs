"""Phishing email header analyzer.

Usage:
    python main.py analyze suspicious.eml   # analyse a real .eml file
    python main.py demo                      # analyse the bundled sample
"""

from __future__ import annotations

import argparse
from pathlib import Path

from src.analyzer import parse_eml
from src.heuristics import run_checks, verdict

HERE = Path(__file__).resolve().parent


def report(path: Path) -> None:
    signals = parse_eml(path)
    findings = run_checks(signals)
    label, score = verdict(findings)

    print(f"File:    {path.name}")
    print(f"Subject: {signals.subject}")
    print(f"From:    {signals.from_header}")
    print(f"Verdict: {label} (risk score {score}/100)")
    print()
    if not findings:
        print("No suspicious indicators found.")
        return
    print(f"{'severity':<10}{'check'}")
    print("-" * 60)
    for f in sorted(findings, key=lambda x: -x.weight):
        sev = {3: "HIGH", 2: "MED", 1: "LOW"}[f.weight]
        print(f"{sev:<10}{f.check}")
        print(f"{'':<10}{f.detail}")
    print()
    print("Note: heuristic triage aid. Confirm with sandbox detonation and")
    print("threat intel before acting.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phishing header analyzer")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("analyze")
    p.add_argument("eml", help="Path to a .eml file")
    sub.add_parser("demo", help="Analyse the bundled phishing sample")
    args = parser.parse_args()

    if args.command == "demo":
        report(HERE / "samples" / "phishing.eml")
    else:
        report(Path(args.eml))


if __name__ == "__main__":
    main()
