"""Figures: incident graph, activity heatmap, impact-scope card.

Each function returns the matplotlib Figure and optionally saves it.
Colours follow a validated categorical palette; identity is also carried by labels.
"""

from __future__ import annotations

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

from .sessions import activity_category

NODE_STYLE = {
    "incident":  {"color": "#3d3c39", "size": 2600, "label": "Incident"},
    "session":   {"color": "#8a8983", "size": 2300, "label": "SSH session"},
    "entity":    {"color": "#eb6834", "size": 2600, "label": "Entity (IP / user / host)"},
    "event":     {"color": "#2a78d6", "size": 750,  "label": "Event, direct link (shares source IP)"},
    "technique": {"color": "#1baf7a", "size": 2100, "label": "MITRE technique"},
}
EDGE_STYLE = {
    "semantic": {"color": "#b9b8b2", "style": "solid",  "width": 1.2, "label": "Relationship"},
    "temporal": {"color": "#3d3c39", "style": "dashed", "width": 1.6, "label": "Temporal: precedes / followed by"},
}
TEXT_SECONDARY = "#52514e"


def plot_incident_graph(G: nx.DiGraph, incident: pd.DataFrame, sessions: list[dict],
                        finding: dict, technique_assessment: list[dict], save_path=None):
    """Readable drawing of the graph. The saved graph keeps every edge; the drawing
    shows session membership by row and draws techniques once from the incident,
    with per-session counts in each technique label."""
    inc_id = finding["finding_id"]
    D = nx.DiGraph()
    for n, d in G.nodes(data=True):
        D.add_node(n, **d)

    first_uid = {
        sref: grp.sort_values("event_time")["event_uid"].iloc[0]
        for sref, grp in incident.groupby("session_ref")
    }
    for u, v, d in G.edges(data=True):
        if d["rel"] == "contains" and G.nodes[v]["kind"] == "event" and first_uid.get(u) != v:
            continue
        if d["rel"] == "mapped_to":
            continue
        D.add_edge(u, v, **{**d, "style": "temporal" if d["style"] == "temporal" else "semantic"})

    tech_counts: dict = {}
    for _, e in incident.iterrows():
        for t in e["techniques"]:
            key = (e["session_ref"], f"t:{t}")
            tech_counts[key] = tech_counts.get(key, 0) + 1
    for tnode in sorted({tn for (_, tn) in tech_counts}):
        D.add_edge(inc_id, tnode, rel="uses_technique", style="semantic")
        parts = [f"{s}×{c}" for (s, tn), c in sorted(tech_counts.items()) if tn == tnode and s]
        D.nodes[tnode]["label"] = f"{D.nodes[tnode]['label']}\n" + " · ".join(parts)

    inferred = set(incident.loc[incident["link_type"] == "inferred", "event_uid"])

    # layout
    pos = {inc_id: (-9.5, 4.6)}
    entities = [n for n, d in D.nodes(data=True) if d["kind"] == "entity"]
    for i, n in enumerate(sorted(entities, key=lambda n: ("ip:", "user:", "host:").index(n.split(":")[0] + ":"))):
        pos[n] = (-14.0, 2.9 - i * 2.8)
    techs = sorted((n for n, d in D.nodes(data=True) if d["kind"] == "technique"),
                   key=lambda n: (n.split(":")[1].split(".")[0], n))  # parent next to its sub-techniques
    for i, n in enumerate(techs):
        pos[n] = (1.5 + i * 5.0, 4.6)
    for row_i, s in enumerate(sessions):
        y = 1.6 - row_i * 3.0
        pos[s["session_ref"]] = (-9.5, y)
        evs = incident[incident["session_ref"] == s["session_ref"]].sort_values("event_time")
        for j, uid in enumerate(evs["event_uid"]):
            pos[uid] = (-7.6 + j * 1.95, y)
    for n in D.nodes:  # anything unplaced (e.g. events outside a session)
        pos.setdefault(n, (-7.6, 1.6 - len(sessions) * 3.0))

    fig, ax = plt.subplots(figsize=(19, 10.5))
    first_session = sessions[0]["session_ref"] if sessions else None
    for u, v, d in D.edges(data=True):
        st = EDGE_STYLE[d["style"]]
        if d["style"] == "temporal":
            cs = "arc3,rad=0.25"
        elif d["rel"] == "uses_technique":
            cs = "arc3,rad=-0.12"
        elif d["rel"] == "contains" and u == inc_id and v != first_session:
            cs = "arc3,rad=0.35"
        else:
            cs = "arc3"
        nx.draw_networkx_edges(D, pos, edgelist=[(u, v)], ax=ax, edge_color=st["color"],
                               style=st["style"], width=st["width"], arrows=True,
                               arrowsize=11, node_size=1100, connectionstyle=cs)

    for kind, st in NODE_STYLE.items():
        nodes = [n for n, d in D.nodes(data=True) if d["kind"] == kind and n not in inferred]
        nx.draw_networkx_nodes(D, pos, nodelist=nodes, node_color=st["color"], node_size=st["size"],
                               edgecolors="white", linewidths=2, ax=ax)
    nx.draw_networkx_nodes(D, pos, nodelist=list(inferred), node_color="white",
                           node_size=NODE_STYLE["event"]["size"],
                           edgecolors=NODE_STYLE["event"]["color"], linewidths=2, ax=ax)

    labels = {n: d["label"] for n, d in D.nodes(data=True)}
    white = {n for n, d in D.nodes(data=True) if d["kind"] in ("incident", "event") and n not in inferred}
    nx.draw_networkx_labels(D, pos, {n: l for n, l in labels.items() if n in white},
                            font_size=8, font_color="white", ax=ax)
    nx.draw_networkx_labels(D, pos, {n: l for n, l in labels.items() if n not in white},
                            font_size=8.5, font_color="#0b0b0b", ax=ax)

    for t in technique_assessment:
        x, y = pos.get(f"t:{t['technique']}", (None, None))
        if x is None:
            continue
        if t["parent"] and f"t:{t['parent']}" in pos:
            px, _ = pos[f"t:{t['parent']}"]
            ax.text((x + px) / 2, y - 0.3, "sub-technique of", ha="center", va="top",
                    fontsize=8, color=TEXT_SECONDARY)
        if t["status"] == "attempted_only":
            ax.text(x, y - 0.95, "attempted only\n(no successful login)", ha="center", va="top",
                    fontsize=8, color=TEXT_SECONDARY)
    for a, b in zip(sessions, sessions[1:]):
        (x1, y1), (_, y2) = pos[a["session_ref"]], pos[b["session_ref"]]
        ax.text(x1 + 0.9, (y1 + y2) / 2, f"gap {(b['start'] - a['end']).total_seconds():.0f} s",
                ha="left", va="center", fontsize=9, color=TEXT_SECONDARY)

    handles = [Patch(facecolor=st["color"], label=st["label"]) for st in NODE_STYLE.values()]
    handles.insert(4, Line2D([0], [0], marker="o", color="none", markerfacecolor="white",
                             markeredgecolor=NODE_STYLE["event"]["color"], markeredgewidth=2,
                             markersize=10, label="Event, inferred link (user + host + time only)"))
    handles += [Line2D([0], [0], color=st["color"], linestyle=st["style"], linewidth=st["width"] + 0.6,
                       label=st["label"]) for st in EDGE_STYLE.values()]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.01), fontsize=9,
              frameon=False, ncol=4)
    ax.set_title(f"Incident graph — {len(sessions)} SSH sessions, {len(incident)} events, "
                 f"{len(technique_assessment)} techniques", fontsize=14)
    xs = [x for x, _ in pos.values()]; ys = [y for _, y in pos.values()]
    ax.set_xlim(min(xs) - 1.2, max(xs) + 1.6)   # explicit: curved edges confuse autoscaling
    ax.set_ylim(min(ys) - 1.0, max(ys) + 1.6)
    ax.axis("off")
    fig.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=130, bbox_inches="tight")
    return fig


def plot_activity_heatmap(incident: pd.DataFrame, save_path=None):
    """Events per activity type per minute, including empty minutes."""
    inc = incident.copy()
    inc["activity"] = inc.apply(activity_category, axis=1)
    inc["minute"] = inc["event_time"].dt.floor("1min")
    minutes = pd.date_range(inc["minute"].min(), inc["minute"].max(), freq="1min")
    order = ["Failed password (sshd)", "Password check (unix_chkpwd)", "PAM auth failure",
             "PAM failure summary", "Successful login", "Session closed", "Other SSH activity"]
    heat = (pd.crosstab(inc["activity"], inc["minute"])
            .reindex(columns=minutes, fill_value=0)
            .reindex([o for o in order if o in set(inc["activity"])]))

    vmax = int(heat.values.max())
    cmap = plt.get_cmap("Blues", vmax + 1)
    fig, ax = plt.subplots(figsize=(12, 4.8))
    im = ax.imshow(heat.values, aspect="auto", cmap=cmap, vmin=-0.5, vmax=vmax + 0.5)
    ax.set_xticks(range(len(minutes)), [m.strftime("%H:%M") for m in minutes])
    ax.set_yticks(range(len(heat.index)), heat.index)
    for i in range(heat.shape[0]):
        for j in range(heat.shape[1]):
            v = int(heat.iloc[i, j])
            if v:
                ax.text(j, i, str(v), ha="center", va="center", fontsize=11, fontweight="bold",
                        color="white" if v > vmax / 2 else "#0b0b0b")
    cbar = fig.colorbar(im, ticks=range(vmax + 1))
    cbar.set_label("Events per minute")
    ax.set_xlabel("Time (UTC, from log line)")
    ax.set_title("Incident activity per minute")
    fig.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=130, bbox_inches="tight")
    return fig


def plot_impact_scope(incident: pd.DataFrame, outcome: dict, entities: dict, save_path=None):
    metrics = [
        ("Source IPs", len(entities["source_ips"])),
        ("Users", len(entities["users"])),
        ("Hosts", len(entities["hosts"])),
        ("SSH sessions", outcome["sessions"]),
        ("Failed attempts", outcome["failed_password_attempts"]),
        ("Successful logins", outcome["successful_logins"]),
        ("Incident events", len(incident)),
        ("Raw records", int(incident["raw_record_count"].sum())),
    ]
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.axis("off")
    ax.text(0.5, 0.95, "Incident impact scope", ha="center", fontsize=18, fontweight="bold")
    for i, (label, value) in enumerate(metrics):
        x = 0.11 + (i % 4) * 0.26
        y = 0.62 if i < 4 else 0.25
        ax.text(x, y + 0.08, str(value), ha="center", fontsize=26, fontweight="bold", color="#0b0b0b")
        ax.text(x, y - 0.03, label, ha="center", fontsize=11, color=TEXT_SECONDARY)
    ax.text(0.5, 0.02,
            f"Source {', '.join(entities['source_ips'])}  |  user {', '.join(entities['users'])}  |  "
            f"host {', '.join(entities['hosts'])}  |  outcome: {outcome['status'].replace('_', ' ')}",
            ha="center", fontsize=10, color=TEXT_SECONDARY)
    if save_path:
        fig.savefig(save_path, dpi=130, bbox_inches="tight")
    return fig
