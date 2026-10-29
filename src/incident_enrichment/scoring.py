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


def present(value) -> bool:
    """True for a real value; False for None, NaN and empty strings."""
    if value is None:
        return False
    try:
        if pd.isna(value):
            return False
    except (TypeError, ValueError):
        pass
    return str(value).strip() != ""


def calculate_relationship(event, finding: dict, w: ScoringWeights = ScoringWeights()):
    score, reasons = 0, []
    if present(event["source_ip"]) and event["source_ip"] == finding.get("source_ip"):
        score += w.same_source_ip; reasons.append("same_source_ip")
    if present(event["target_user"]) and event["target_user"] == finding.get("target_user"):
        score += w.same_target_user; reasons.append("same_target_user")
    if present(event["host"]) and event["host"] == finding.get("target_host"):
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
    extend_after: pd.Timedelta | None = None,
    strict_source: bool = False,
) -> pd.DataFrame:
    """Return the context window with score, reasons, role and link_type columns.

    ``extend_after`` widens the window after ``last_seen`` (to recover evidence that
    arrived after the finding was emitted). With ``strict_source``, an event that
    carries a source IP different from the finding's can never join the incident.
    """
    start = finding["first_seen"] - pad
    end = finding["last_seen"] + max(pad, extend_after or pd.Timedelta(0))
    context = canonical[(canonical["event_time"] >= start) & (canonical["event_time"] <= end)].copy()

    scored = [calculate_relationship(r, finding, weights) for _, r in context.iterrows()]
    context["relationship_score"] = [s for s, _ in scored]
    context["relationship_reasons"] = [r for _, r in scored]

    finding_ip = finding.get("source_ip")

    def role_of(row):
        other_source = (strict_source and present(finding_ip) and present(row["source_ip"])
                        and str(row["source_ip"]) != str(finding_ip))
        if row["relationship_score"] >= weights.threshold and not other_source:
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
