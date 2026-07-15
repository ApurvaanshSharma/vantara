"""
Enrichment scoring.

Combined score is a deliberately simple, documented heuristic — not a
statistical model, and that's a fair thing to say plainly in an interview
rather than oversell: 60% weight on AbuseIPDB's abuseConfidenceScore (a
continuous 0-100 value backed by community abuse reports specifically),
40% weight on a bucketed version of OTX's pulse_info.count (a coarser
signal — "has this indicator appeared in any curated threat report at
all"). AbuseIPDB gets the larger weight because it's a finer-grained
measurement of the same kind of thing this project's alerts are about
(abuse), where OTX pulses cover a broader range of threat types.

Known limitation, stated rather than hidden: an IP with no data from
either source scores 0 — identical to an IP both sources have explicitly
checked and found clean. Distinguishing "unknown" from "confirmed clean"
would need each score to carry a separate confidence/coverage flag; out of
scope here, worth naming as a real gap.
"""

import ipaddress
import re

_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ip_from_message(message: str) -> str | None:
    """Best-effort IPv4 extraction from free text (e.g. a YARA-matched
    command string), for source types that don't have a structured
    source_ip field the way linux_auth/firewall_json do. Deliberately
    permissive (doesn't validate octet ranges) — is_enrichable_ip() is the
    actual validation step; this just finds a candidate."""
    match = _IPV4_PATTERN.search(message)
    return match.group(0) if match else None


def is_enrichable_ip(ip: str) -> bool:
    """False for private/reserved/loopback addresses — no point spending
    API quota on IPs that will never appear in a public reputation
    database, and this project's own demo/test data uses exactly these
    ranges (RFC 5737 documentation blocks, private RFC 1918 ranges)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local
    )


def _otx_pulse_score(pulse_count: int) -> int:
    if pulse_count == 0:
        return 0
    if pulse_count <= 2:
        return 30
    if pulse_count <= 5:
        return 60
    return 90


def compute_combined_score(abuseipdb_data: dict | None, otx_data: dict | None) -> int:
    abuseipdb_score = 0
    if abuseipdb_data is not None:
        abuseipdb_score = abuseipdb_data.get("abuseConfidenceScore", 0)

    otx_score = 0
    if otx_data is not None:
        pulse_count = otx_data.get("pulse_info", {}).get("count", 0)
        otx_score = _otx_pulse_score(pulse_count)

    combined = round(0.6 * abuseipdb_score + 0.4 * otx_score)
    return max(0, min(100, combined))
