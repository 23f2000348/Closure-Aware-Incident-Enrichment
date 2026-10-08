"""Correlated findings: the input to the enrichment layer.

In production a finding comes from the Sigma correlation engine (via ClickHouse).
For offline testing, ``simulate_sigma_threshold`` reproduces what a threshold rule
such as "≥ 5 auth-failure alerts from one source IP within 10 minutes" would emit.
It only looks at alerts that carry a source IP, so the enrichment step has to find
the rest of the evidence on its own.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

REQUIRED_FIELDS = ("finding_id", "title", "source_ip", "target_user", "target_host",
                   "first_seen", "last_seen")


def simulate_sigma_threshold(
    canonical: pd.DataFrame,
    threshold: int = 5,
    window: pd.Timedelta = pd.Timedelta(minutes=10),
) -> list[dict]:
    """Group IP-bearing authentication-failure alerts by (ip, user, host) and emit a
    finding for each group meeting the threshold inside the window."""
    alerts = canonical[
        canonical["sources"].map(lambda s: "alert" in s)
        & canonical["source_ip"].notna()
        & canonical["description"].fillna("").str.contains("fail|missed", case=False)
    ]
    findings = []
    for i, ((ip, user, host), grp) in enumerate(
        alerts.groupby(["source_ip", "target_user", "host"]), start=1
    ):
        grp = grp.sort_values("event_time")
        span = grp["event_time"].max() - grp["event_time"].min()
        if len(grp) >= threshold and span <= window:
            findings.append({
                "finding_id": f"finding-sim-{i:03d}",
                "finding_source": "simulated_sigma_threshold",
                "rule": f">= {threshold} auth-failure alerts per source IP within "
                        f"{int(window.total_seconds() // 60)} min",
                "title": "Repeated SSH authentication failures",
                "source_ip": ip,
                "target_user": user,
                "target_host": host,
                "first_seen": grp["event_time"].min(),
                "last_seen": grp["event_time"].max(),
                "matched_alert_count": len(grp),
                "techniques": sorted({t for ts in grp["techniques"] for t in ts}),
                "matched_event_uids": grp["event_uid"].tolist(),
            })
    return findings


def load_finding(path: str | Path) -> dict:
    """Load a finding from JSON (e.g. exported from the Sigma findings table)."""
    with open(path, "r", encoding="utf-8") as f:
        finding = json.load(f)
    missing = [k for k in REQUIRED_FIELDS if k not in finding]
    if missing:
        raise ValueError(f"finding is missing fields: {missing}")
    finding["first_seen"] = pd.Timestamp(finding["first_seen"])
    finding["last_seen"] = pd.Timestamp(finding["last_seen"])
    for k in ("first_seen", "last_seen"):
        if finding[k].tzinfo is None:
            finding[k] = finding[k].tz_localize("UTC")
    finding.setdefault("techniques", [])
    finding.setdefault("finding_source", "external")
    return finding
