"""SSH session reconstruction, outcome, and MITRE technique assessment.

Each SSH connection is handled by one ``sshd-session`` process, so its PID identifies
the session. ``unix_chkpwd`` runs as a separate child process and is attached to the
session whose time range covers it (an inferred link).
"""

from __future__ import annotations

import pandas as pd

from .normalize import SYSLOG_PREFIX

# OpenSSH 9.8+ logs per-connection lines as "sshd-session"; older versions as "sshd".
SESSION_PROGRAMS = {"sshd-session", "sshd"}
CHILD_TOLERANCE = pd.Timedelta(seconds=2)

TECHNIQUE_INFO = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "parent": None},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access", "parent": "T1110"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access", "parent": "T1110"},
    "T1021.004": {"name": "Remote Services: SSH", "tactic": "Lateral Movement", "parent": "T1021"},
}


def _first_non_null(series):
    s = series.dropna()
    return s.iloc[0] if len(s) else None


def reconstruct_sessions(incident: pd.DataFrame) -> tuple[pd.DataFrame, list[dict]]:
    """Return (incident with session_ref and event_ref columns, list of sessions)."""
    incident = incident.sort_values("event_time").reset_index(drop=True).copy()
    by_pid: dict = {}
    for pid, grp in incident[incident["program"].isin(SESSION_PROGRAMS) & incident["pid"].notna()].groupby("pid"):
        logs = grp["full_log"].fillna("")
        failed = int(logs.str.contains(r"Failed \w+ for").sum())
        accepted = int(logs.str.contains(r"Accepted \w+ for").sum())
        closed = bool(logs.str.contains(r"\[preauth\]").any())
        outcome = "success" if accepted else ("failed_client_disconnected" if closed else "unknown")
        by_pid[pid] = {
            "pid": pid,
            "start": grp["event_time"].min(),
            "end": grp["event_time"].max(),
            "source_ip": _first_non_null(grp["source_ip"]),
            "source_port": _first_non_null(grp["source_port"]),
            "target_user": _first_non_null(grp["target_user"]),
            "failed_attempts": failed,
            "successful_logins": accepted,
            "outcome": outcome,
        }

    sessions = sorted(by_pid.values(), key=lambda s: s["start"])
    for i, s in enumerate(sessions, start=1):
        s["session_ref"] = f"S{i}"

    def assign(row):
        if row["program"] in SESSION_PROGRAMS and row["pid"] in by_pid:
            return by_pid[row["pid"]]["session_ref"]
        for s in sessions:
            if s["start"] - CHILD_TOLERANCE <= row["event_time"] <= s["end"] + CHILD_TOLERANCE:
                return s["session_ref"]
        return None

    incident["session_ref"] = incident.apply(assign, axis=1) if len(incident) else []
    incident["event_ref"] = [f"E{i}" for i in range(1, len(incident) + 1)]
    return incident, sessions


def summarize_outcome(sessions: list[dict], all_records: pd.DataFrame, source_ip: str) -> dict:
    """Overall outcome, checking ALL available records (not only the window) for a
    successful login from the source IP."""
    success_anywhere = all_records[
        all_records["full_log"].fillna("").str.contains(r"Accepted \w+ for", regex=True)
        & (all_records["source_ip"] == source_ip)
    ]
    return {
        "sessions": len(sessions),
        "failed_password_attempts": sum(s["failed_attempts"] for s in sessions),
        "successful_logins": int(len(success_anywhere)),
        "status": ("no_successful_authentication_observed" if success_anywhere.empty
                   else "successful_authentication_observed"),
        "observed_until": str(all_records["event_time"].max()),
        "note": "Absence of evidence only covers the logs available up to observed_until.",
    }


def assess_techniques(incident: pd.DataFrame, outcome: dict) -> list[dict]:
    """Attach evidence and an evidence status to each MITRE technique.

    Wazuh maps every failed SSH login to T1021.004 (Lateral Movement). Lateral
    movement needs a working remote session, so with zero successful logins it is
    reported as ``attempted_only``.
    """
    assessment = []
    for t in sorted({t for ts in incident["techniques"] for t in ts}):
        info = TECHNIQUE_INFO.get(t, {"name": None, "tactic": None, "parent": None})
        evidence = incident.loc[incident["techniques"].map(lambda ts: t in ts), "event_ref"].tolist()
        if info["tactic"] == "Lateral Movement" and outcome["successful_logins"] == 0:
            status, why = "attempted_only", "Tagged by Wazuh rule mapping, but no successful remote session was observed."
        else:
            status, why = "observed", "Directly supported by the evidence events."
        assessment.append({"technique": t, **info, "status": status,
                           "evidence_events": evidence, "reason": why})
    return assessment


def short_summary(row) -> str:
    """Rule description if there is one, otherwise the log message without its prefix."""
    if pd.notna(row["description"]) and row["description"]:
        return row["description"]
    log = row["full_log"] or ""
    m = SYSLOG_PREFIX.match(log)
    return (log[m.end():].strip() if m else log)[:70]


def activity_category(row) -> str:
    text = f"{row['description'] or ''} {row['full_log'] or ''}".lower()
    if "failed password" in text:
        return "Failed password (sshd)"
    if "password check failed" in text:
        return "Password check (unix_chkpwd)"
    if "pam_unix(sshd:auth): authentication failure" in text:
        return "PAM auth failure"
    if "more authentication failure" in text:
        return "PAM failure summary"
    if "accepted" in text:
        return "Successful login"
    if "connection closed" in text or "disconnected" in text:
        return "Session closed"
    return "Other SSH activity"
