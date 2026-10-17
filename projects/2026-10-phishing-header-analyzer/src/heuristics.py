"""Heuristic checks over parsed email signals.

Each check returns a Finding with a severity weight. The weights add up to a
risk score and a plain language verdict. These are triage aids: they surface
what a human analyst should look at, not a final malicious/benign verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from .analyzer import EmailSignals

# Brands most impersonated in phishing, used for display name spoof checks.
IMPERSONATED_BRANDS = (
    "paypal", "microsoft", "apple", "amazon", "google", "netflix",
    "bankofamerica", "chase", "wellsfargo", "dhl", "fedex", "irs",
)

URGENCY_WORDS = (
    "urgent", "immediately", "suspended", "verify now", "action required",
    "expires today", "unusual activity", "security alert",
)


@dataclass
class Finding:
    check: str
    detail: str
    weight: int  # 1 = note, 2 = suspicious, 3 = strong indicator


def _looks_like_brand_domain(domain: str) -> str | None:
    """Return the impersonated brand if the domain mangles a known brand."""
    for brand in IMPERSONATED_BRANDS:
        if brand in domain and not domain.endswith(brand + ".com"):
            return brand
        # hyphen insertion: pay-pal, micros oft style tricks
        if brand[:4] in domain.replace("-", "") and "-" in domain:
            return brand
    if domain.startswith("xn--"):
        return "punycode domain"
    return None


def run_checks(signals: EmailSignals) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Reply-To mismatch: classic credential harvesting setup.
    if signals.reply_to_domain and signals.reply_to_domain != signals.from_domain:
        findings.append(Finding(
            "Reply-To mismatch",
            f"Reply-To domain {signals.reply_to_domain} differs from "
            f"From domain {signals.from_domain}",
            3,
        ))

    # 2. Return-Path mismatch: envelope sender does not match the header.
    if signals.return_path_domain and signals.return_path_domain != signals.from_domain:
        findings.append(Finding(
            "Return-Path mismatch",
            f"Envelope sender {signals.return_path_domain} differs from "
            f"From domain {signals.from_domain}",
            2,
        ))

    # 3. Authentication failures.
    for method in ("spf", "dkim", "dmarc"):
        result = signals.auth_results.get(method)
        if result in ("fail", "softfail"):
            findings.append(Finding(
                f"{method.upper()} {result}",
                f"Authentication-Results reports {method.upper()}={result}",
                3 if method == "dmarc" else 2,
            ))
        elif result == "none" and method == "dmarc":
            findings.append(Finding(
                "No DMARC policy",
                "Domain publishes no DMARC policy; spoofing is easier",
                1,
            ))

    # 4. Display name spoofing.
    display = signals.from_display_name.lower()
    for brand in IMPERSONATED_BRANDS:
        if brand in display and brand not in signals.from_domain:
            findings.append(Finding(
                "Display name spoofing",
                f"Display name claims '{signals.from_display_name}' but the "
                f"sender domain is {signals.from_domain}",
                3,
            ))
            break

    # 5. Lookalike domain.
    brand = _looks_like_brand_domain(signals.from_domain)
    if brand:
        findings.append(Finding(
            "Lookalike domain",
            f"Sender domain {signals.from_domain} resembles '{brand}'",
            3,
        ))

    # 6. Body links pointing away from the sender domain.
    foreign = sorted({u.lower() for u in signals.body_urls
                      if signals.from_domain not in u.lower()})
    if foreign:
        findings.append(Finding(
            "Links to foreign domains",
            f"Body links point to: {', '.join(foreign[:5])}",
            2,
        ))

    # 7. Urgency language in the subject.
    subject = signals.subject.lower()
    hits = [w for w in URGENCY_WORDS if w in subject]
    if hits:
        findings.append(Finding(
            "Urgency language",
            f"Subject uses pressure words: {', '.join(hits)}",
            1,
        ))

    # 8. Thin Received chain on an external message.
    if signals.from_domain and len(signals.received_hops) < 2:
        findings.append(Finding(
            "Thin Received chain",
            f"Only {len(signals.received_hops)} Received hop(s); external mail "
            f"normally crosses several",
            1,
        ))

    return findings


def verdict(findings: list[Finding]) -> tuple[str, int]:
    """Return (verdict label, risk score 0-100)."""
    score = min(100, sum(f.weight for f in findings) * 8)
    if score >= 50:
        label = "LIKELY PHISHING"
    elif score >= 20:
        label = "SUSPICIOUS"
    else:
        label = "LIKELY LEGITIMATE"
    return label, score
