"""Merge duplicate records into canonical events.

Wazuh writes the same log line to both alerts.json and archives.json. The duplicate
is the same log line from the same host, so the canonical key is ``host | full_log``.
The syslog line carries its own timestamp and PID, so two genuinely different
events never collide. (The Wazuh timestamp is not a safe key: Wazuh processes logs
in batches, so distinct events can share one.)
"""

from __future__ import annotations

import hashlib

import pandas as pd


def canonical_key(row) -> str:
    if row["full_log"]:
        return f"{row['host']}|{row['full_log'].strip()}"
    return f"record|{row['record_uid']}"


def event_uid_for(key: str) -> str:
    return "evt_" + hashlib.sha1(key.encode()).hexdigest()[:12]


def _first_non_null(series):
    s = series.dropna()
    return s.iloc[0] if len(s) else None


def _merge_field_sources(series):
    merged: dict = {}
    for d in series:
        for k, v in (d or {}).items():
            if merged.get(k) != "wazuh":  # prefer Wazuh-decoded over parsed
                merged[k] = v
    return merged


def canonicalize(df: pd.DataFrame) -> pd.DataFrame:
    """Return one row per canonical event, with provenance (sources, record_uids)."""
    df = df.copy()
    df["canonical_key"] = df.apply(canonical_key, axis=1)
    df["event_uid"] = df["canonical_key"].map(event_uid_for)

    canonical = (
        df.groupby("event_uid", sort=False)
        .agg(
            event_time=("event_time", "min"),
            ingest_time=("ingest_time", "min"),
            host=("host", _first_non_null),
            program=("program", _first_non_null),
            pid=("pid", _first_non_null),
            rule_id=("rule_id", _first_non_null),
            rule_level=("rule_level", "max"),
            description=("description", _first_non_null),
            decoder=("decoder", _first_non_null),
            source_ip=("source_ip", _first_non_null),
            source_port=("source_port", _first_non_null),
            target_user=("target_user", _first_non_null),
            techniques=("techniques", lambda s: sorted({t for ts in s for t in ts})),
            full_log=("full_log", _first_non_null),
            fields_from=("fields_from", _merge_field_sources),
            sources=("source", lambda s: sorted(set(s))),
            record_uids=("record_uid", list),
            wazuh_ids=("wazuh_id", lambda s: sorted(set(x for x in s if x))),
        )
        .reset_index()
        .sort_values(["event_time", "ingest_time"])
        .reset_index(drop=True)
    )
    canonical["raw_record_count"] = canonical["record_uids"].map(len)
    return canonical
