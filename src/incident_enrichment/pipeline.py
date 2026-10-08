"""End-to-end enrichment: finding -> context -> canonical events -> scoring ->
sessions/outcome -> techniques -> graph -> incident object."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
import pandas as pd

from .canonicalize import canonicalize
from .finding import simulate_sigma_threshold
from .graph import build_graph, graph_to_dict
from .loader import load_wazuh_files
from .normalize import build_records_frame
from .scoring import ScoringWeights, score_context
from .sessions import assess_techniques, reconstruct_sessions, short_summary, summarize_outcome

SCHEMA_VERSION = "0.1"


@dataclass
class EnrichmentConfig:
    context_pad: pd.Timedelta = pd.Timedelta(minutes=1)
    weights: ScoringWeights = field(default_factory=ScoringWeights)
    sigma_threshold: int = 5
    sigma_window: pd.Timedelta = pd.Timedelta(minutes=10)


@dataclass
class EnrichmentResult:
    finding: dict
    records: pd.DataFrame          # every raw record, normalized
    canonical: pd.DataFrame        # deduplicated events (all)
    context: pd.DataFrame          # events in the window, scored, with role
    incident: pd.DataFrame         # events belonging to the incident
    sessions: list[dict]
    outcome: dict
    techniques: list[dict]
    graph: nx.DiGraph
    incident_object: dict


def _iso(t):
    return None if t is None or pd.isna(t) else pd.Timestamp(t).isoformat()


def enrich_finding(finding: dict, records: pd.DataFrame, canonical: pd.DataFrame,
                   config: EnrichmentConfig = EnrichmentConfig()) -> EnrichmentResult:
    """Enrich one finding using already-normalized records and canonical events."""
    context = score_context(canonical, finding, pad=config.context_pad, weights=config.weights)
    incident, sessions = reconstruct_sessions(context[context["role"] == "incident"])
    incident["summary"] = incident.apply(short_summary, axis=1) if len(incident) else []

    outcome = summarize_outcome(sessions, records, finding["source_ip"])
    techniques = assess_techniques(incident, outcome)
    G = build_graph(incident, sessions, finding, techniques)
    obj = build_incident_object(finding, context, incident, sessions, outcome, techniques, G)
    return EnrichmentResult(finding, records, canonical, context, incident,
                            sessions, outcome, techniques, G, obj)


def enrich_files(alerts_path, archives_path, finding: dict | None = None,
                 config: EnrichmentConfig = EnrichmentConfig()) -> list[EnrichmentResult]:
    """Load Wazuh files and enrich the given finding, or every simulated finding."""
    alerts, archives = load_wazuh_files(alerts_path, archives_path)
    records = build_records_frame(alerts, archives)
    canonical = canonicalize(records)
    findings = [finding] if finding else simulate_sigma_threshold(
        canonical, threshold=config.sigma_threshold, window=config.sigma_window)
    return [enrich_finding(f, records, canonical, config) for f in findings]


def build_incident_object(finding, context, incident, sessions, outcome, techniques, G) -> dict:
    entities = {
        "source_ips": sorted(set(incident["source_ip"].dropna())),
        "users": sorted(set(incident["target_user"].dropna())),
        "hosts": sorted(set(incident["host"].dropna())),
    }
    service_ctx = context[context["role"] == "service_context"]

    summary = (
        f"{outcome['failed_password_attempts']} failed SSH password attempts for user "
        f"{finding['target_user']} from {finding['source_ip']} on host {finding['target_host']}, "
        f"in {outcome['sessions']} session(s) between {finding['first_seen'].strftime('%H:%M:%S')} and "
        f"{finding['last_seen'].strftime('%H:%M:%S')} UTC. "
    )
    if outcome["successful_logins"] == 0:
        summary += "No successful login from this source was observed in the available logs."
    else:
        summary += f"{outcome['successful_logins']} successful login(s) from this source were observed."
    if len(service_ctx):
        lead = (finding["first_seen"] - service_ctx["event_time"].min()).total_seconds()
        if 0 <= lead <= 300:
            summary += f" The SSH service on the host started {lead:.0f} s before the first attempt."

    obj = {
        "schema_version": SCHEMA_VERSION,
        "incident_id": "INC-" + hashlib.sha1(finding["finding_id"].encode()).hexdigest()[:8].upper(),
        "status": "open",
        "closed_at": None,
        "watch_until": None,
        "finding": {
            **{k: v for k, v in finding.items() if k not in ("first_seen", "last_seen")},
            "first_seen": _iso(finding["first_seen"]),
            "last_seen": _iso(finding["last_seen"]),
        },
        "outcome": outcome,
        "sessions": [{**s, "start": _iso(s["start"]), "end": _iso(s["end"])} for s in sessions],
        "entities": entities,
        "techniques": techniques,
        "timeline": [
            {
                "event_ref": r["event_ref"],
                "event_uid": r["event_uid"],
                "event_time": _iso(r["event_time"]),
                "ingest_time": _iso(r["ingest_time"]),
                "session_ref": r["session_ref"],
                "program": r["program"],
                "rule_id": r["rule_id"],
                "rule_level": None if pd.isna(r["rule_level"]) else int(r["rule_level"]),
                "summary": r["summary"],
                "source_ip": r["source_ip"],
                "target_user": r["target_user"],
                "techniques": r["techniques"],
                "link_type": r["link_type"],
                "relationship_score": int(r["relationship_score"]),
                "relationship_reasons": r["relationship_reasons"],
                "fields_from": r["fields_from"],
                "sources": r["sources"],
                "record_uids": r["record_uids"],
            }
            for _, r in incident.iterrows()
        ],
        "service_context": [
            {"event_uid": r["event_uid"], "event_time": _iso(r["event_time"]), "log": r["full_log"]}
            for _, r in service_ctx.iterrows()
        ],
        "graph": graph_to_dict(G),
        "evidence": {
            "incident_event_count": len(incident),
            "raw_record_count": int(incident["raw_record_count"].sum()),
            "context_event_count": len(context),
            "event_uids": incident["event_uid"].tolist(),
        },
        "evidence_summary": summary,
    }
    uids = obj["evidence"]["event_uids"]
    assert len(uids) == len(set(uids)), "event_uids must be unique"
    return obj


def save_incident(obj: dict, path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=str)
