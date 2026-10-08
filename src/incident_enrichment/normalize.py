"""Turn raw Wazuh events into one flat, consistent record per raw line.

Key points
- Every raw record gets its own ``record_uid``. Wazuh's ``id`` is kept but is NOT
  unique (Wazuh reuses it across archive records), so it is never used as a key.
- ``event_time`` is read from the syslog line itself; ``ingest_time`` is when Wazuh
  processed it (usually 1-2 s later, and batched).
- When Wazuh's decoders did not extract the source IP / user / port, they are parsed
  from the log text. ``fields_from`` records where each value came from.
"""

from __future__ import annotations

import re
from datetime import timedelta

import pandas as pd

SYSLOG_PREFIX = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<program>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:"
)

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
LOG_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("source_ip", re.compile(rf"from {_IP} port \d+")),
    ("source_ip", re.compile(rf"authenticating user \S+ {_IP} port")),
    ("source_ip", re.compile(rf"rhost={_IP}")),
    ("source_port", re.compile(r"port (\d+)")),
    ("target_user", re.compile(r"authenticating user (\S+) ")),
    ("target_user", re.compile(r"(?:Failed|Accepted) \w+ for (?:invalid user )?(\S+) from")),
    ("target_user", re.compile(r"\buser=(\S+)")),
    ("target_user", re.compile(r"for user \((\S+)\)")),
]


def _get_nested(data, *keys):
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def parse_event_time(full_log: str | None, ingest_time: pd.Timestamp) -> pd.Timestamp:
    """Timestamp written in the syslog line. Syslog has no year, so it is taken
    from the ingestion time (with a guard for December -> January rollover)."""
    if not full_log or pd.isna(ingest_time):
        return ingest_time
    m = SYSLOG_PREFIX.match(full_log)
    if not m:
        return ingest_time
    text = f"{ingest_time.year} {m['mon']} {m['day']} {m['time']}"
    t = pd.to_datetime(text, format="%Y %b %d %H:%M:%S", utc=True, errors="coerce")
    if pd.isna(t):
        return ingest_time
    if t - ingest_time > timedelta(days=1):
        t = t.replace(year=t.year - 1)
    return t


def extract_from_log(full_log: str | None) -> dict:
    """Fallback extraction of source_ip / source_port / target_user from log text."""
    found: dict = {}
    if not full_log:
        return found
    for field, pattern in LOG_PATTERNS:
        if field in found:
            continue
        m = pattern.search(full_log)
        if m:
            found[field] = m.group(1)
    return found


def normalize_event(event: dict, source: str, line_no: int) -> dict:
    """Normalize one raw Wazuh event. ``source`` is 'alert' or 'archive'."""
    rule = event.get("rule") or {}
    data = event.get("data") or {}
    mitre = rule.get("mitre") or {}
    techniques = mitre.get("id", [])
    if isinstance(techniques, str):
        techniques = [techniques]

    full_log = event.get("full_log")
    prefix = SYSLOG_PREFIX.match(full_log or "")

    record = {
        "record_uid": f"{source}:{line_no}",
        "source": source,
        "wazuh_id": event.get("id"),
        "ingest_time": event.get("timestamp"),
        "host": _get_nested(event, "agent", "name"),
        "host_ip": _get_nested(event, "agent", "ip"),
        "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
        "rule_level": rule.get("level"),
        "description": rule.get("description"),
        "decoder": _get_nested(event, "decoder", "name"),
        "program": prefix["program"] if prefix else _get_nested(event, "predecoder", "program_name"),
        "pid": prefix["pid"] if prefix else None,
        "source_ip": data.get("srcip"),
        "source_port": data.get("srcport"),
        "target_user": data.get("dstuser") or data.get("srcuser"),
        "techniques": list(techniques),
        "groups": rule.get("groups", []),
        "full_log": full_log,
        "raw_event": event,
    }

    parsed = extract_from_log(full_log)
    fields_from = {}
    for field in ("source_ip", "source_port", "target_user"):
        if record[field]:
            fields_from[field] = "wazuh"
        elif field in parsed:
            record[field] = parsed[field]
            fields_from[field] = "parsed_from_log"
    record["fields_from"] = fields_from
    return record


def build_records_frame(alerts: list[dict], archives: list[dict]) -> pd.DataFrame:
    """Normalize alerts + archives into one DataFrame sorted by event time."""
    records = [normalize_event(e, "alert", i) for i, e in enumerate(alerts, start=1)]
    records += [normalize_event(e, "archive", i) for i, e in enumerate(archives, start=1)]
    df = pd.DataFrame(records)
    df["ingest_time"] = pd.to_datetime(df["ingest_time"], utc=True, errors="coerce")
    df["event_time"] = [parse_event_time(fl, it) for fl, it in zip(df["full_log"], df["ingest_time"])]
    return df.sort_values(["event_time", "ingest_time"]).reset_index(drop=True)
