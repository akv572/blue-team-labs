"""Parse .eml files and extract the signals phishing triage depends on."""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path

AUTH_RES_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE
)
RECEIVED_RE = re.compile(r"from\s+(\S+)", re.IGNORECASE)
URL_RE = re.compile(r"https?://([A-Za-z0-9_.\-]+)", re.IGNORECASE)


def _domain_of(address: str | None) -> str:
    if not address:
        return ""
    match = re.search(r"@([A-Za-z0-9_.\-]+)", address)
    return match.group(1).lower() if match else ""


@dataclass
class EmailSignals:
    subject: str = ""
    from_header: str = ""
    from_domain: str = ""
    from_display_name: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    return_path_domain: str = ""
    received_hops: list = field(default_factory=list)
    auth_results: dict = field(default_factory=dict)
    body_urls: list = field(default_factory=list)
    body_text: str = ""


def parse_eml(path: str | Path) -> EmailSignals:
    """Parse an .eml file into triage signals."""
    raw = Path(path).read_bytes()
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)

    signals = EmailSignals(subject=str(msg.get("Subject", "")))

    from_header = str(msg.get("From", ""))
    signals.from_header = from_header
    signals.from_domain = _domain_of(from_header)
    name, _ = email.utils.parseaddr(from_header)
    signals.from_display_name = name

    reply_to = str(msg.get("Reply-To", ""))
    signals.reply_to = reply_to
    signals.reply_to_domain = _domain_of(reply_to)
    signals.return_path_domain = _domain_of(str(msg.get("Return-Path", "")))

    for received in msg.get_all("Received", []):
        match = RECEIVED_RE.search(str(received))
        if match:
            signals.received_hops.append(match.group(1).strip("()"))

    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    for method, result in AUTH_RES_RE.findall(auth):
        signals.auth_results[method.lower()] = result.lower()

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""
    signals.body_text = body if isinstance(body, str) else ""
    signals.body_urls = sorted(set(URL_RE.findall(signals.body_text)))

    return signals
