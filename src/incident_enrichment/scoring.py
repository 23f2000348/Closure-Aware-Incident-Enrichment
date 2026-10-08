"""Context retrieval and relationship scoring.

Each canonical event in a time window around the finding is scored against the
finding. Events at or above the threshold belong to the incident and are labelled
``direct`` (share the finding's source IP) or ``inferred`` (user + host + time only).
SSH-service events on the target host that do not score high enough are kept as
``service_context`` (e.g. "Server listening on port 22") instead of background.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

SSH_PROGRAMS = {"sshd", "sshd-session"}


@dataclass(frozen=True)
class ScoringWeights:
    same_source_ip: int = 3
    same_target_user: int = 2
    same_target_host: int = 2
    shared_mitre_technique: int = 2
    inside_finding_window: int = 1
    threshold: int = 5


def calculate_relationship(event, finding: dict, w: ScoringWeights = ScoringWeights()):
    score, reasons = 0, []
    if event["source_ip"] and event["source_ip"] == finding["source_ip"]:
        score += w.same_source_ip; reasons.append("same_source_ip")
    if event["target_user"] and event["target_user"] == finding["target_user"]:
        score += w.same_target_user; reasons.append("same_target_user")
    if event["host"] and event["host"] == finding["target_host"]:
        score += w.same_target_host; reasons.append("same_target_host")
    if set(event["techniques"]) & set(finding.get("techniques", [])):
        score += w.shared_mitre_technique; reasons.append("shared_mitre_technique")
    if finding["first_seen"] <= event["event_time"] <= finding["last_seen"]:
        score += w.inside_finding_window; reasons.append("inside_finding_window")
    return score, reasons


def score_context(
    canonical: pd.DataFrame,
    finding: dict,
    pad: pd.Timedelta = pd.Timedelta(minutes=1),
    weights: ScoringWeights = ScoringWeights(),
) -> pd.DataFrame:
    """Return the context window with score, reasons, role and link_type columns."""
    start, end = finding["first_seen"] - pad, finding["last_seen"] + pad
    context = canonical[(canonical["event_time"] >= start) & (canonical["event_time"] <= end)].copy()

    scored = [calculate_relationship(r, finding, weights) for _, r in context.iterrows()]
    context["relationship_score"] = [s for s, _ in scored]
    context["relationship_reasons"] = [r for _, r in scored]

    def role_of(row):
        if row["relationship_score"] >= weights.threshold:
            return "incident"
        if row["host"] == finding["target_host"] and row["program"] in SSH_PROGRAMS:
            return "service_context"
        return "background"

    context["role"] = context.apply(role_of, axis=1) if len(context) else []
    context["link_type"] = [
        None if role != "incident"
        else ("direct" if "same_source_ip" in reasons else "inferred")
        for role, reasons in zip(context["role"], context["relationship_reasons"])
    ]
    return context
