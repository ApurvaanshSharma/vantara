"""
Normalization: turn three genuinely different shapes into one NormalizedEvent.

Each parser is intentionally separate rather than one big if/elif of field
lookups — new source types get their own function and one new dispatch
entry, without touching the others. This is the extension point Phase 7+
(Sysmon, Zeek, Suricata, etc.) would grow from.
"""

import re
from datetime import datetime, timezone

from app.schemas.event import NormalizedEvent, RawEventIn

# Matches classic BSD syslog (RFC 3164) SSH auth lines, e.g.:
#   "Jul 12 10:23:45 webserver01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
#   "Jul 12 10:23:45 webserver01 sshd[1234]: Accepted password for deploy from 203.0.113.7 port 51520 ssh2"
_LINUX_AUTH_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\ssshd\[\d+\]:\s"
    r"(?P<status>Failed|Accepted)\spassword\sfor\s"
    r"(?:invalid user\s)?(?P<user>\S+)\sfrom\s(?P<source_ip>\S+)\sport\s\d+"
)


class NormalizationError(ValueError):
    """Raised when a raw payload doesn't match its declared source_type's
    expected shape. Caught by the Celery task — see workers/tasks.py — so
    one malformed event doesn't crash the whole batch."""


def normalize_generic_json(payload: dict) -> NormalizedEvent:
    timestamp_raw = payload.get("timestamp")
    event_timestamp = (
        datetime.fromisoformat(timestamp_raw)
        if timestamp_raw
        else datetime.now(timezone.utc)
    )
    return NormalizedEvent(
        event_timestamp=event_timestamp,
        source_type="generic_json",
        host=payload.get("host"),
        message=payload.get("message", "(no message field provided)"),
        raw=payload,
    )


def normalize_firewall_json(payload: dict) -> NormalizedEvent:
    required = {"src_ip", "action"}
    if not required.issubset(payload):
        raise NormalizationError(
            f"firewall_json payload missing required fields: {required}"
        )

    timestamp_raw = payload.get("timestamp")
    event_timestamp = (
        datetime.fromisoformat(timestamp_raw)
        if timestamp_raw
        else datetime.now(timezone.utc)
    )
    action = str(payload["action"]).upper()
    severity = "warning" if action == "BLOCK" else "info"

    return NormalizedEvent(
        event_timestamp=event_timestamp,
        source_type="firewall_json",
        host=payload.get("firewall_host"),
        severity=severity,
        action=f"connection_{action.lower()}",
        source_ip=payload["src_ip"],
        destination_ip=payload.get("dst_ip"),
        message=f"Firewall {action} {payload['src_ip']} -> {payload.get('dst_ip', '?')}",
        raw=payload,
    )


def normalize_linux_auth(line: str) -> NormalizedEvent:
    match = _LINUX_AUTH_RE.match(line.strip())
    if not match:
        raise NormalizationError(
            f"linux_auth line did not match expected sshd format: {line!r}"
        )

    fields = match.groupdict()
    # Classic BSD syslog (RFC 3164) has no year in the timestamp — a real,
    # known limitation of the format, not an oversight here. We assume the
    # current year, which is wrong exactly once a year, right at midnight
    # on Dec 31st. Structured syslog (RFC 5424) fixed this; worth naming in
    # an interview as a reason RFC 5424 exists.
    current_year = datetime.now(timezone.utc).year
    event_timestamp = datetime.strptime(
        f"{current_year} {fields['timestamp']}", "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=timezone.utc)

    failed = fields["status"] == "Failed"
    return NormalizedEvent(
        event_timestamp=event_timestamp,
        source_type="linux_auth",
        host=fields["host"],
        severity="warning" if failed else "info",
        action="login_failed" if failed else "login_succeeded",
        user=fields["user"],
        source_ip=fields["source_ip"],
        message=line.strip(),
        raw=line,
    )


_DISPATCH = {
    "generic_json": normalize_generic_json,
    "firewall_json": normalize_firewall_json,
    "linux_auth": normalize_linux_auth,
}


def normalize(event: RawEventIn) -> NormalizedEvent:
    parser = _DISPATCH[event.source_type]
    return parser(event.payload)
