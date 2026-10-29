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
    ("target_user", re.compile(r"[Ii]nvalid user (\S+) (?:from )?\d")),
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
    if not isinstance(full_log, str) or not full_log or pd.isna(ingest_time):
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
    if not isinstance(full_log, str) or not full_log:
        return found
    for field, pattern in LOG_PATTERNS:
        if field in found:
            continue
        m = pattern.search(full_log)
        if m:
            found[field] = m.group(1)
    return found


def _text(value) -> str | None:
    """Scalar -> clean string; anything else (None, NaN, dict, list, empty) -> None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, float):
        if value != value:  # NaN
            return None
        value = int(value) if value.is_integer() else value
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        return text or None
    return None


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _str_list(value) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [t for t in (_text(v) for v in value) if t]


def normalize_event(event: dict, source: str, line_no: int) -> dict:
    """Normalize one raw Wazuh event. ``source`` is 'alert' or 'archive'.
    Fields of the wrong type (e.g. a number where text is expected) are treated as missing."""
    rule = _dict(event.get("rule"))
    data = _dict(event.get("data"))
    techniques = _str_list(_dict(rule.get("mitre")).get("id"))

    full_log = _text(event.get("full_log"))
    prefix = SYSLOG_PREFIX.match(full_log or "")
    level = rule.get("level")
    try:
        level = int(level) if level is not None and not isinstance(level, bool) else None
    except (TypeError, ValueError):
        level = None
    timestamp = event.get("timestamp")
    timestamp = timestamp if isinstance(timestamp, str) else None

    record = {
        "record_uid": f"{source}:{line_no}",
        "source": source,
        "wazuh_id": _text(event.get("id")),
        "ingest_time": timestamp,
        "host": _text(_get_nested(event, "agent", "name")),
        "host_ip": _text(_get_nested(event, "agent", "ip")),
        "rule_id": _text(rule.get("id")),
        "rule_level": level,
        "description": _text(rule.get("description")),
        "decoder": _text(_get_nested(event, "decoder", "name")),
        "program": prefix["program"] if prefix else _text(_get_nested(event, "predecoder", "program_name")),
        "pid": prefix["pid"] if prefix else None,
        "source_ip": _text(data.get("srcip")),
        "source_port": _text(data.get("srcport")),
        "target_user": _text(data.get("dstuser")) or _text(data.get("srcuser")),
        "techniques": techniques,
        "groups": _str_list(rule.get("groups")),
        "full_log": full_log,
        "raw_event": event,
        # OCSF finding uid of this record when it came through the pipeline (set by the
        # ClickHouse bridge); links the record to a correlation's contributing uids.
        "ocsf_uid": _text(event.get("_ocsf_finding_uid")),
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


RECORD_COLUMNS = ["record_uid", "source", "wazuh_id", "ingest_time", "host", "host_ip", "rule_id",
                  "rule_level", "description", "decoder", "program", "pid", "source_ip", "source_port",
                  "target_user", "techniques", "groups", "full_log", "raw_event", "ocsf_uid", "fields_from"]


def build_records_frame(alerts: list[dict], archives: list[dict]) -> pd.DataFrame:
    """Normalize alerts + archives into one DataFrame sorted by event time.
    Non-dict entries are skipped; an empty input gives an empty frame with all columns."""
    records = [normalize_event(e, "alert", i) for i, e in enumerate(alerts, start=1) if isinstance(e, dict)]
    records += [normalize_event(e, "archive", i) for i, e in enumerate(archives, start=1) if isinstance(e, dict)]
    df = pd.DataFrame(records, columns=RECORD_COLUMNS)
    df["ingest_time"] = pd.to_datetime(df["ingest_time"], utc=True, errors="coerce")
    df["event_time"] = pd.to_datetime(
        pd.Series([parse_event_time(fl, it) for fl, it in zip(df["full_log"], df["ingest_time"])],
                  index=df.index, dtype=object), utc=True, errors="coerce")
    return df.sort_values(["event_time", "ingest_time"]).reset_index(drop=True)
