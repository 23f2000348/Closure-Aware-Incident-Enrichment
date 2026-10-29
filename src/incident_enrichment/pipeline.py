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
from .process import (
    complete_from_linked_events,
    incident_id_for,
    assess_process_techniques,
    build_process_graph,
    build_process_incident_object,
    finding_from_anomaly,
    group_process_activity,
    is_process_finding,
    link_process_events,
    load_clickhouse_rows,
    normalize_ocsf_process_events,
    summarize_process_outcome,
)
from .scoring import calculate_relationship, present
from .sessions import assess_techniques, reconstruct_sessions, short_summary, summarize_outcome
from .sigma import (
    VERDICTS,
    RuleCatalog,
    combined_verdict,
    group_finding,
    integrity_check,
)

SCHEMA_VERSION = "0.4"


@dataclass
class EnrichmentConfig:
    context_pad: pd.Timedelta = pd.Timedelta(minutes=1)
    weights: ScoringWeights = field(default_factory=ScoringWeights)
    sigma_threshold: int = 5
    sigma_window: pd.Timedelta = pd.Timedelta(minutes=10)
    process_context_pad: pd.Timedelta = pd.Timedelta(minutes=10)
    # Sigma safeguards
    recovery_after: pd.Timedelta = pd.Timedelta(minutes=10)   # look this far past last_seen for dropped evidence
    merge_gap: pd.Timedelta = pd.Timedelta(minutes=10)        # findings this close (same IP) are one attack
    rules: RuleCatalog | None = None                           # None -> built-in SSH rules


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
    integrity: list[dict] = field(default_factory=list)   # per merged finding (Sigma path)


class EmptyGroup(ValueError):
    """A finding group with no usable time and no events: nothing to enrich."""


@dataclass
class ProcessEnrichmentResult:
    finding: dict
    events: pd.DataFrame           # OCSF process events supplied
    labelled: pd.DataFrame         # events linked to the finding (incident + context)
    incident: pd.DataFrame         # events belonging to the incident
    groups: list[dict]             # (host, user, parent -> process) groups
    missing_event_uids: list[str]  # listed by the model but not found in ``events``
    outcome: dict
    techniques: list[dict]
    graph: nx.DiGraph
    incident_object: dict


def _iso(t):
    return None if t is None or pd.isna(t) else pd.Timestamp(t).isoformat()


def _linked_mask(df: pd.DataFrame, linked: set) -> pd.Series:
    if not linked or "ocsf_uids" not in df.columns or not len(df):
        return pd.Series(False, index=df.index)
    return df["ocsf_uids"].map(lambda u: bool(set(u or []) & linked))


def enrich_finding(finding: dict, records: pd.DataFrame, canonical: pd.DataFrame,
                   config: EnrichmentConfig = EnrichmentConfig(),
                   extend_after: pd.Timedelta | None = None, strict_source: bool = False,
                   linked_uids: set | None = None) -> EnrichmentResult:
    """Enrich one SSH / authentication finding using normalized records and canonical events.
    Process anomalies go through ``enrich_process_finding``.

    ``linked_uids``: OCSF uids the engine listed; those events are always part of the
    incident (``engine_linked``), even if they fall outside the window or score low."""
    if is_process_finding(finding):
        raise ValueError("process anomaly findings use enrich_process_finding() with OCSF process events")
    linked = set(linked_uids or [])
    context = score_context(canonical, finding, pad=config.context_pad, weights=config.weights,
                            extend_after=extend_after, strict_source=strict_source)
    if linked:
        outside = canonical[_linked_mask(canonical, linked) & ~canonical["event_uid"].isin(context["event_uid"])].copy()
        if len(outside):
            scored = [calculate_relationship(r, finding, config.weights) for _, r in outside.iterrows()]
            outside["relationship_score"] = [s for s, _ in scored]
            outside["relationship_reasons"] = [r for _, r in scored]
            outside["role"] = "incident"
            outside["link_type"] = None
            context = pd.concat([context, outside]).sort_values(["event_time", "ingest_time"])
    context["engine_linked"] = _linked_mask(context, linked)
    if linked and len(context):
        forced = context["engine_linked"] & (context["role"] != "incident")
        context.loc[context["engine_linked"], "role"] = "incident"
        context.loc[forced, "link_type"] = [
            "direct" if "same_source_ip" in reasons else "inferred"
            for reasons in context.loc[forced, "relationship_reasons"]
        ]
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


def enrich_process_finding(finding: dict, events: pd.DataFrame,
                           config: EnrichmentConfig = EnrichmentConfig()) -> ProcessEnrichmentResult:
    """Enrich one process anomaly (e.g. from ``finding_from_anomaly``) with OCSF process
    events (from ``normalize_ocsf_process_events``)."""
    finding = complete_from_linked_events(finding, events)
    labelled, missing = link_process_events(events, finding, pad=config.process_context_pad)
    incident = labelled[labelled["role"] == "incident"] if len(labelled) else labelled
    incident, groups = group_process_activity(incident)
    outcome = summarize_process_outcome(finding, incident, groups, missing)
    techniques = assess_process_techniques(finding, incident)
    finding = {**finding, "techniques": [t["technique"] for t in techniques]}
    G = build_process_graph(finding, groups, techniques)
    obj = build_process_incident_object(finding, labelled, incident, groups, outcome,
                                        techniques, G, missing, SCHEMA_VERSION)
    return ProcessEnrichmentResult(finding, events, labelled, incident, groups, missing,
                                   outcome, techniques, G, obj)


def enrich_process_files(anomalies_path, events_path,
                         config: EnrichmentConfig = EnrichmentConfig()) -> list[ProcessEnrichmentResult]:
    """Enrich every anomaly in a ClickHouse export of ``wazuh_ml_anomalies``, using a
    ClickHouse export of ``wazuh_ocsf_events``."""
    anomalies = load_clickhouse_rows(anomalies_path)
    events = normalize_ocsf_process_events(load_clickhouse_rows(events_path))
    return [enrich_process_finding(finding_from_anomaly(a), events, config) for a in anomalies]


def enrich_sigma_group(members: list[dict], records: pd.DataFrame,
                       config: EnrichmentConfig = EnrichmentConfig()) -> EnrichmentResult:
    """Enrich a group of Sigma findings that describe one attack (see
    ``sigma.merge_findings``) with engine-independent safeguards:

    - evidence recovery: matching events up to ``config.recovery_after`` past the
      finding are included (only from the same source IP when the event has one);
    - the engine's own events are always included and marked ``engine_linked``;
    - integrity check per finding: the rule is re-evaluated on distinct events.
    """
    catalog = config.rules or RuleCatalog.builtin()
    tenants = {m.get("tenant_uid") for m in members if m.get("tenant_uid")}
    if len(tenants) > 1:
        raise ValueError(f"findings from different tenants cannot form one incident: {sorted(tenants)}")
    finding = group_finding(members)
    if finding.get("tenant_uid") and len(records):
        # defence in depth: drop records that belong to another tenant
        other = records["raw_event"].map(lambda e: isinstance(e, dict) and bool(e.get("_tenant_uid"))
                                         and e.get("_tenant_uid") != finding["tenant_uid"])
        records = records[~other].reset_index(drop=True)
    linked = set(finding["contributing_finding_uids"])
    canonical = canonicalize(records)

    linked_rows = canonical[_linked_mask(canonical, linked)]
    users = linked_rows["target_user"].dropna().astype(str)
    users = users[users.str.strip() != ""]
    finding["target_users"] = sorted(users.unique().tolist())
    counts = users.value_counts()
    # one clearly dominant user, otherwise none (e.g. password spraying: many users, no target)
    dominant = len(counts) == 1 or (len(counts) > 1 and counts.iloc[0] > counts.iloc[1])
    finding["target_user"] = counts.index[0] if len(counts) and dominant else None
    if not present(finding.get("target_host")):
        hosts = linked_rows["host"].dropna()
        finding["target_host"] = hosts.mode().iloc[0] if len(hosts) else None

    if finding.get("first_seen") is None:
        times = (linked_rows if len(linked_rows) else canonical)["event_time"].dropna()
        if not len(times):
            raise EmptyGroup(f"{finding['finding_id']}: no time on the finding and no events")
        finding["first_seen"], finding["last_seen"] = times.min(), times.max()
        finding.setdefault("notes", []).append("finding had no time; window taken from its events")

    res = enrich_finding(finding, records, canonical, config, extend_after=config.recovery_after,
                         strict_source=True, linked_uids=linked)
    reports = [integrity_check(m, catalog.lookup(m.get("rule_id"), m.get("title")), res.incident, canonical)
               for m in members]

    obj = res.incident_object
    obj["finding"]["merged_from"] = [{**m, "first_seen": _iso(m.get("first_seen")),
                                      "last_seen": _iso(m.get("last_seen"))}
                                     for m in finding.get("merged_from", [])]
    incident = res.incident
    eng = incident["engine_linked"] if "engine_linked" in incident.columns else pd.Series(False, index=incident.index)
    obj["evidence"].update({
        "engine_linked_events": int(eng.sum()),
        "recovered_events": int((~eng).sum()),
        "recovered_event_refs": incident.loc[~eng, "event_ref"].tolist() if len(incident) else [],
        "engine_uids_missing": sorted({u for r in reports for u in r["engine_uids_missing"]}),
    })
    obj["integrity"] = {
        "verdict": combined_verdict(reports),
        "findings": reports,
        "verdict_meanings": {v: VERDICTS[v] for v in {r["verdict"] for r in reports}},
    }
    obj["integrity"]["recommended_action"] = RECOMMENDED_ACTION[obj["integrity"]["verdict"]]
    if len(members) > 1:
        obj["evidence_summary"] += f" Merged from {len(members)} findings for the same attack."
    obj["evidence_summary"] += " " + " ".join(r["note"] for r in reports)
    res.integrity = reports
    return res


RECOMMENDED_ACTION = {
    "confirmed": "triage",
    "confirmed_with_recovered_evidence": "triage",
    "below_threshold_after_dedup": "review: likely false positive caused by duplicate delivery",
    "below_threshold": "review: rule condition not met on available events",
    "unverifiable": "review: evidence incomplete",
    "rule_unknown": "triage: rule not re-checked",
}


def _who(finding: dict, entities: dict) -> str:
    users = entities.get("users") or []
    if len(users) > 1:
        shown = ", ".join(users[:5]) + (f" (+{len(users) - 5})" if len(users) > 5 else "")
        return f"users {shown}"
    if users:
        return f"user {users[0]}"
    return f"user {finding['target_user']}" if present(finding.get("target_user")) else "an unknown user"


def build_incident_object(finding, context, incident, sessions, outcome, techniques, G) -> dict:
    entities = {
        "source_ips": sorted(set(incident["source_ip"].dropna())),
        "users": sorted(set(incident["target_user"].dropna())),
        "hosts": sorted(set(incident["host"].dropna())),
    }
    service_ctx = context[context["role"] == "service_context"]

    who = _who(finding, entities)
    src = finding.get("source_ip") or "an unknown source"
    hosts = entities.get("hosts") or ([finding["target_host"]] if present(finding.get("target_host")) else [])
    where = f"host {', '.join(hosts)}" if hosts else "an unknown host"
    if len(incident):
        t0, t1 = incident["event_time"].min(), incident["event_time"].max()
    else:
        t0, t1 = finding["first_seen"], finding["last_seen"]
    span = f"between {t0:%Y-%m-%d %H:%M:%S} and {t1:%H:%M:%S} UTC"
    if outcome["sessions"]:
        summary = (f"{outcome['failed_password_attempts']} failed SSH password attempts for {who} from {src} "
                   f"on {where}, in {outcome['sessions']} session(s) {span}. ")
    elif len(incident):
        summary = (f"{len(incident)} authentication event(s) for {who} from {src} on {where} {span}. "
                   "No SSH sessions could be rebuilt: the records carry no sshd process lines. ")
    else:
        summary = f"No events available for this finding from {src} on {where}. "
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
        "incident_type": "ssh_authentication",
        "incident_id": incident_id_for(finding),
        "tenant_uid": finding.get("tenant_uid"),
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
                "engine_linked": bool(r["engine_linked"]) if "engine_linked" in r.index else None,
                "ocsf_uids": list(r["ocsf_uids"]) if "ocsf_uids" in r.index else [],
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
