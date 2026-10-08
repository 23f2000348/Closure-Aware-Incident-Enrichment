"""Incident graph: incident -> sessions -> events -> techniques.

Entities (IP / user / host) attach to sessions rather than to every event, so the
graph carries structure instead of "everything touches everything". Temporal edges
run only within a session, plus one session-to-session edge carrying the gap.
"""

from __future__ import annotations

import networkx as nx
import pandas as pd


def build_graph(incident: pd.DataFrame, sessions: list[dict], finding: dict,
                technique_assessment: list[dict]) -> nx.DiGraph:
    G = nx.DiGraph()
    inc_id = finding["finding_id"]

    G.add_node(inc_id, kind="incident", label="Incident")
    for s in sessions:
        if s["source_ip"]:
            G.add_node(f"ip:{s['source_ip']}", kind="entity", label=s["source_ip"])
        if s["target_user"]:
            G.add_node(f"user:{s['target_user']}", kind="entity", label=f"user: {s['target_user']}")
    G.add_node(f"host:{finding['target_host']}", kind="entity", label=f"host: {finding['target_host']}")

    for s in sessions:
        sid = s["session_ref"]
        G.add_node(sid, kind="session", label=f"{sid}\n{s['failed_attempts']} failed")
        G.add_edge(inc_id, sid, rel="contains", style="semantic")
        if s["source_ip"]:
            G.add_edge(f"ip:{s['source_ip']}", sid, rel="initiated", style="semantic")
        if s["target_user"]:
            G.add_edge(sid, f"user:{s['target_user']}", rel="targeted", style="semantic")
        G.add_edge(sid, f"host:{finding['target_host']}", rel="on_host", style="semantic")

    for _, e in incident.iterrows():
        G.add_node(e["event_uid"], kind="event", label=e["event_ref"], link_type=e["link_type"])
        if e["session_ref"]:
            G.add_edge(e["session_ref"], e["event_uid"], rel="contains",
                       style="inferred" if e["link_type"] == "inferred" else "semantic")
        for t in e["techniques"]:
            G.add_node(f"t:{t}", kind="technique", label=t)
            G.add_edge(e["event_uid"], f"t:{t}", rel="mapped_to", style="semantic")

    for t in technique_assessment:
        if t["parent"] and f"t:{t['parent']}" in G:
            G.add_edge(f"t:{t['technique']}", f"t:{t['parent']}", rel="subtechnique_of", style="semantic")

    for _, grp in incident.groupby("session_ref"):
        uids = grp.sort_values("event_time")["event_uid"].tolist()
        for a, b in zip(uids, uids[1:]):
            G.add_edge(a, b, rel="precedes", style="temporal")
    for a, b in zip(sessions, sessions[1:]):
        G.add_edge(a["session_ref"], b["session_ref"], rel="followed_by",
                   gap_seconds=(b["start"] - a["end"]).total_seconds(), style="temporal")
    return G


def graph_to_dict(G: nx.DiGraph) -> dict:
    return {
        "nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
        "edges": [{"source": u, "target": v, **d} for u, v, d in G.edges(data=True)],
    }
