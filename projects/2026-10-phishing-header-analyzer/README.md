# Phishing Header Analyzer

Triage aid for suspicious emails: parses a `.eml` file and scores it against
the header checks a SOC analyst runs first. Standard library only, no
dependencies.

## What it checks

| Check | Severity | Why it matters |
|---|---|---|
| Reply-To domain differs from From | High | Classic credential harvesting setup |
| SPF / DKIM / DMARC failures | High/Med | Sender authentication broken or absent |
| Display name spoofing | High | "PayPal Security" from a stranger domain |
| Lookalike domain | High | `paypaI-secure.com`, punycode, hyphen tricks |
| Return-Path mismatch | Med | Envelope sender does not match the header |
| Body links to foreign domains | Med | Lure points somewhere unexpected |
| Urgency language in subject | Low | Pressure tactics |
| Thin Received chain | Low | External mail normally crosses several hops |

Findings are weighted into a 0-100 risk score: 50+ is likely phishing,
20-49 is suspicious, below 20 is likely legitimate.

## Scope

Heuristic triage, not a verdict engine. It reads headers and plain text
bodies; it does not detonate attachments, follow links, or consult threat
intel. Confirm anything important in a sandbox before acting.

## Quickstart

```bash
# No dependencies to install: standard library only
python main.py demo                      # analyse the bundled sample
python main.py analyze suspicious.eml    # analyse a real message
```

## Example output

```
File:    phishing.eml
Subject: Urgent: unusual activity detected, verify now
From:    PayPal Security <security@paypaI-secure.com>
Verdict: LIKELY PHISHING (risk score 100/100)

severity  check
------------------------------------------------------------
HIGH      Reply-To mismatch
          Reply-To domain fastmail-provider.net differs from From domain paypai-secure.com
HIGH      DMARC fail
          Authentication-Results reports DMARC=fail
HIGH      Display name spoofing
          Display name claims 'PayPal Security' but the sender domain is paypai-secure.com
HIGH      Lookalike domain
          Sender domain paypai-secure.com resembles 'paypal'
...
```

The bundled legitimate sample scores 0/100 with no findings.

## Project structure

```
├── main.py            # CLI: analyze <file.eml> | demo
├── src/
│   ├── analyzer.py    # .eml parsing, signal extraction
│   └── heuristics.py  # checks, scoring, verdict
└── samples/
    ├── phishing.eml
    └── legitimate.eml
```

*Part of the [Blue Team Labs](https://github.com/akv572/blue-team-labs) monthly series.*
