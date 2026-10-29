"""Process-execution enrichment (endpoint anomalies).

Input
- A process anomaly, e.g. one row of ``default.wazuh_ml_anomalies`` (Isolation Forest):
  host, user, parent process -> process, occurrence count, anomaly score, the
  OCSF finding uids it was built from, and a sample command.
- OCSF process-creation events (``default.wazuh_ocsf_events``): the events the
  anomaly points to, plus other process activity on the same host around it.

Output
- Events linked to the anomaly: ``direct`` (listed by the model) or ``inferred``
  (same host, user and parent -> process inside the window, not listed).
- Process groups: activity grouped by (host, user, parent -> process).
- Outcome: host and user, lineage, volume and score, sample command.
- MITRE ATT&CK candidates mapped from the process and its command line.
- Graph: user -executed_on-> host -ran-> parent -spawned-> process -maps_to-> technique.

Nothing here touches the SSH path; a finding is routed here by ``is_process_finding``.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PureWindowsPath

import networkx as nx
import pandas as pd

PROCESS_FINDING_TYPE = "process_anomaly"
SCORE_NOTE = "Isolation Forest score: lower (more negative) means more anomalous."


# --------------------------------------------------------------------------- loading

def load_clickhouse_rows(path: str | Path) -> list[dict]:
    """Read rows exported from ClickHouse.

    Accepts ``FORMAT JSON`` (an object with ``data``), a JSON list, or
    ``JSONEachRow`` (one object per line), in UTF-8 or UTF-16 (Windows exports).
    """
    raw = Path(path).read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig")
    text = text.strip()
    if not text:
        return []
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(doc, dict):
        return list(doc.get("data", []))
    if isinstance(doc, list):
        return doc
    raise ValueError(f"{path}: unrecognised ClickHouse export")


def _ts(value) -> pd.Timestamp | None:
    """ClickHouse time -> UTC timestamp. Integers are epoch milliseconds;
    strings without a zone are taken as UTC."""
    if value is None or value == "" or (isinstance(value, float) and pd.isna(value)):
        return None
    if isinstance(value, (int, float)):
        return pd.to_datetime(int(value), unit="ms", utc=True)
    return pd.to_datetime(value, utc=True, errors="coerce")


def _json_obj(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _json_list(value) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def proc_key(name) -> str | None:
    """Comparable process name: file name only, lower case (``C:\\x\\PowerShell.EXE`` -> ``powershell.exe``)."""
    if name is None or (isinstance(name, float) and pd.isna(name)) or str(name).strip() == "":
        return None
    return PureWindowsPath(str(name).strip()).name.lower()


def _command_from(obj: dict) -> str | None:
    for key in ("cmd", "command_line", "commandLine", "process_cmd_line", "CommandLine"):
        if obj.get(key):
            return str(obj[key])
    return None


# --------------------------------------------------------------------------- findings

# Event codes of the process-creation events the ML worker models (Windows 4688,
# Sysmon 1, and the Wazuh rule ids used for them in LogManthan).
PROCESS_EVENT_CODES = {"4688", "1", "91802", "67027"}


def _first_of(row: dict, *keys):
    """First present value among ``keys`` (None, NaN and empty strings are skipped)."""
    for k in keys:
        v = row.get(k)
        if v is None or (isinstance(v, float) and pd.isna(v)) or (isinstance(v, str) and not v.strip()):
            continue
        return v
    return None


def _num(value) -> float | None:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return None if pd.isna(f) else f


def _mode(series: pd.Series):
    s = series.dropna().astype(str)
    s = s[s.str.strip() != ""]
    return s.mode().iloc[0] if len(s) else None


def complete_from_linked_events(finding: dict, events: pd.DataFrame) -> dict:
    """Fill host, user, parent/process and times the anomaly row does not carry from
    the events it lists (and restrict events to the finding's tenant). Never overrides
    a value the row has. Returns a new finding with ``notes`` on what was filled."""
    finding = {**finding, "notes": list(finding.get("notes") or [])}
    listed = set(finding.get("contributing_finding_uids", []))
    linked = events[events["event_uid"].isin(listed)] if len(events) else events
    fills = {"target_host": "host", "target_user": "user", "parent_process": "parent_process", "process": "process"}
    filled = []
    for attr, col in fills.items():
        if not finding.get(attr) and len(linked):
            v = _mode(linked[col])
            if v and col in ("parent_process", "process"):
                v = PureWindowsPath(v).name or v      # file name, as the ML worker reports it
            if v:
                finding[attr] = v
                filled.append(attr)
    if finding.get("first_seen") is None and len(linked) and linked["event_time"].notna().any():
        finding["first_seen"] = linked["event_time"].min()
        finding["last_seen"] = linked["event_time"].max()
        filled.append("first_seen/last_seen")
    if filled:
        finding["notes"].append("filled from the anomaly's linked events: " + ", ".join(filled))
        if "parent_process" in filled or "process" in filled:
            finding["title"] = (f"Anomalous process execution: {finding.get('parent_process') or '?'} -> "
                                f"{finding.get('process') or '?'}")
    return finding

def is_process_finding(finding: dict) -> bool:
    return (finding.get("finding_type") == PROCESS_FINDING_TYPE
            or "isolation_forest" in str(finding.get("finding_source", "")))


def finding_from_anomaly(row: dict, finding_source: str = "v2_isolation_forest") -> dict:
    """Turn one ``wazuh_ml_anomalies`` row into a process finding."""
    raw = _json_obj(row.get("raw_event"))
    evidence = _json_obj(row.get("evidence"))
    uids = row.get("contributing_finding_uids") or []
    if isinstance(uids, str):
        uids = _json_list(uids) or [uids]
    parent = row.get("parent_process_name") or evidence.get("parent_process_name")
    process = row.get("process_name") or evidence.get("process_name")
    first = _ts(_first_of(row, "first_seen_time", "first_seen", "event_time"))
    last = _ts(_first_of(row, "last_seen_time", "last_seen", "event_time")) or first
    if first is not None and last is not None and first > last:
        first, last = last, first
    uid = _first_of(row, "anomaly_uid", "anomaly_id", "id")
    min_score = _num(_first_of(row, "min_score", "min_anomaly_score") if _first_of(row, "min_score", "min_anomaly_score") is not None
                     else evidence.get("min_anomaly_score"))
    mean_score = _num(_first_of(row, "mean_score", "mean_anomaly_score") if _first_of(row, "mean_score", "mean_anomaly_score") is not None
                      else evidence.get("mean_anomaly_score"))
    return {
        "finding_id": f"ML-ANOMALY-{uid}",
        "anomaly_uid": None if uid is None else str(uid),
        "finding_type": PROCESS_FINDING_TYPE,
        "finding_source": finding_source,
        "model_version": row.get("model_version"),
        "title": f"Anomalous process execution: {parent or '?'} -> {process or '?'}",
        "tenant_uid": row.get("tenant_uid"),
        "event_type": row.get("event_type") or evidence.get("event_type"),
        "target_host": row.get("device_hostname") or evidence.get("device_hostname"),
        "target_user": row.get("user_name") or evidence.get("user_name"),
        "parent_process": parent,
        "process": process,
        "first_seen": first,
        "last_seen": last,
        "occurrence_count": int(_num(row.get("occurrence_count") or evidence.get("occurrence_count")) or 0),
        "score": _num(row.get("score")),
        "min_anomaly_score": min_score,
        "mean_anomaly_score": mean_score,
        "sample_command": _command_from(raw),
        "contributing_finding_uids": [str(u) for u in uids],
        "source_ip": None,
        "techniques": [],
    }


# --------------------------------------------------------------------------- events

EVENT_COLUMNS = ["event_uid", "event_time", "ingest_time", "host", "user", "parent_process",
                 "process", "process_path", "parent_process_path", "pid", "cmd_line",
                 "event_code", "attacks", "source", "tenant_uid"]


def normalize_ocsf_process_events(rows: list[dict]) -> pd.DataFrame:
    """OCSF rows (``wazuh_ocsf_events``) -> one flat row per event."""
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        raw = _json_obj(r.get("raw_data"))
        out.append({
            "event_uid": str(r.get("finding_uid")),
            "event_time": _ts(r.get("time")) if r.get("time") not in (None, "") else _ts(r.get("time_dt")),
            "ingest_time": _ts(r.get("ingested_at")),
            "host": r.get("device_hostname"),
            "user": r.get("user_name"),
            "parent_process": r.get("parent_process_name"),
            "process": r.get("process_name"),
            "process_path": r.get("process_path"),
            "parent_process_path": r.get("parent_process_path"),
            "pid": r.get("process_pid"),
            "cmd_line": r.get("process_cmd_line") or _command_from(raw),
            "event_code": None if _first_of(r, "event_code", "rule_id") is None
                          else str(_first_of(r, "event_code", "rule_id")),
            "attacks": _json_list(r.get("attacks")),
            "source": "ocsf",
            "tenant_uid": r.get("tenant_uid") or None,
        })
    df = pd.DataFrame(out, columns=EVENT_COLUMNS)
    if len(df):
        df = df.drop_duplicates("event_uid").sort_values("event_time").reset_index(drop=True)
    return df


def link_process_events(events: pd.DataFrame, finding: dict,
                        pad: pd.Timedelta = pd.Timedelta(minutes=10)) -> tuple[pd.DataFrame, list[str]]:
    """Label events for one finding.

    - ``incident`` / ``direct``: listed in the anomaly's contributing uids (any time)
    - ``incident`` / ``inferred``: same host, user and parent -> process, inside the window
    - ``context``: other process activity on the same host, inside the window
    Returns (labelled events, contributing uids not found in ``events``).
    """
    listed = set(finding.get("contributing_finding_uids", []))
    df = events.copy()
    tenant = finding.get("tenant_uid")
    if tenant and "tenant_uid" in df.columns and len(df):
        # never link another tenant's events (events without a tenant are kept)
        df = df[df["tenant_uid"].isna() | (df["tenant_uid"].astype(str) == str(tenant))]
    if df.empty:
        df["role"] = []
        df["link_type"] = []
        return df, sorted(listed)

    same_host = df["host"].fillna("").str.lower() == str(finding.get("target_host") or "").lower()
    if finding.get("first_seen") is not None:
        start, end = finding["first_seen"] - pad, finding["last_seen"] + pad
        in_window = (df["event_time"] >= start) & (df["event_time"] <= end)
    else:  # no time on the anomaly or its events: only the listed events can be linked
        in_window = pd.Series(False, index=df.index)
    same_pattern = (
        (df["user"].fillna("").str.lower() == str(finding.get("target_user") or "").lower())
        & (df["parent_process"].map(proc_key) == proc_key(finding.get("parent_process")))
        & (df["process"].map(proc_key) == proc_key(finding.get("process")))
    )
    direct = df["event_uid"].isin(listed)
    inferred = ~direct & same_host & in_window & same_pattern
    is_process = df["process"].notna() & (df["process"].astype(str).str.strip() != "")
    context = ~direct & ~inferred & same_host & in_window & is_process

    df["role"] = None
    df.loc[direct | inferred, "role"] = "incident"
    df.loc[context, "role"] = "context"
    df["link_type"] = None
    df.loc[direct, "link_type"] = "direct"
    df.loc[inferred, "link_type"] = "inferred"
    df = df[df["role"].notna()].sort_values("event_time").reset_index(drop=True)

    missing = sorted(listed - set(df["event_uid"]))
    return df, missing


def group_process_activity(incident: pd.DataFrame) -> tuple[pd.DataFrame, list[dict]]:
    """Group incident events by (host, user, parent -> process). Adds ``group_ref``
    and ``event_ref`` columns and returns the groups."""
    incident = incident.copy()
    if incident.empty:
        incident["group_ref"] = []
        incident["event_ref"] = []
        return incident, []
    keys = ["host", "user", "parent_key", "proc_key"]
    incident["parent_key"] = incident["parent_process"].map(proc_key)
    incident["proc_key"] = incident["process"].map(proc_key)
    groups = []
    for (host, user, pk, ck), grp in incident.groupby(keys, dropna=False, sort=False):
        grp = grp.sort_values("event_time")
        commands = [c for c in grp["cmd_line"].dropna().astype(str).unique()][:3]
        groups.append({
            "host": host, "user": user,
            "parent_process": grp["parent_process"].iloc[0], "process": grp["process"].iloc[0],
            "lineage": f"{grp['parent_process'].iloc[0]} -> {grp['process'].iloc[0]}",
            "events": len(grp),
            "direct_events": int((grp["link_type"] == "direct").sum()),
            "inferred_events": int((grp["link_type"] == "inferred").sum()),
            "first": grp["event_time"].min(), "last": grp["event_time"].max(),
            "sample_commands": commands,
            "event_uids": grp["event_uid"].tolist(),
            "_key": (host, user, pk, ck),
        })
    groups.sort(key=lambda g: g["first"])
    for i, g in enumerate(groups, start=1):
        g["group_ref"] = f"G{i}"
    ref = {g["_key"]: g["group_ref"] for g in groups}
    incident["group_ref"] = [ref[k] for k in zip(*(incident[k] for k in keys))]
    for g in groups:
        g.pop("_key")
    incident = incident.drop(columns=["parent_key", "proc_key"]).sort_values("event_time").reset_index(drop=True)
    incident["event_ref"] = [f"E{i}" for i in range(1, len(incident) + 1)]
    return incident, groups


# --------------------------------------------------------------------------- outcome

def summarize_process_outcome(finding: dict, incident: pd.DataFrame, groups: list[dict],
                              missing_uids: list[str]) -> dict:
    """Host and user, lineage, volume and score, command context."""
    sample = finding.get("sample_command")
    if not sample and len(incident):
        cmds = incident["cmd_line"].dropna()
        sample = str(cmds.iloc[0]) if len(cmds) else None
    listed = len(finding.get("contributing_finding_uids", []))
    return {
        "type": "process_execution",
        "host": finding.get("target_host"),
        "user": finding.get("target_user"),
        "lineage": f"{finding.get('parent_process')} -> {finding.get('process')}",
        "occurrence_count": finding.get("occurrence_count"),
        "min_anomaly_score": finding.get("min_anomaly_score"),
        "mean_anomaly_score": finding.get("mean_anomaly_score"),
        "model_version": finding.get("model_version"),
        "score_note": SCORE_NOTE,
        "sample_command": sample,
        "first_seen": finding.get("first_seen"),
        "last_seen": finding.get("last_seen"),
        "events_listed_by_model": listed,
        "events_found": int((incident["link_type"] == "direct").sum()) if len(incident) else 0,
        "events_missing": len(missing_uids),
        "inferred_events": int((incident["link_type"] == "inferred").sum()) if len(incident) else 0,
        "process_groups": len(groups),
    }


# --------------------------------------------------------------------------- MITRE

# (process names, command-line regex or None, technique, name, tactic)
# Process-name-only rules give a *candidate*; a matching command line strengthens it.
TECHNIQUE_RULES = [
    ({"powershell.exe", "pwsh.exe"}, None, "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    ({"powershell.exe", "pwsh.exe"}, r"(?i)\s-(e|ec|enc|encodedcommand)\b", "T1027.010", "Obfuscated Files or Information: Command Obfuscation", "Defense Evasion"),
    ({"powershell.exe", "pwsh.exe"}, r"(?i)(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer)", "T1105", "Ingress Tool Transfer", "Command and Control"),
    ({"cmd.exe"}, None, "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    ({"certutil.exe"}, r"(?i)(-urlcache|-verifyctl|https?://)", "T1105", "Ingress Tool Transfer", "Command and Control"),
    ({"certutil.exe"}, r"(?i)-decode(hex)?\b", "T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
    ({"bitsadmin.exe"}, None, "T1197", "BITS Jobs", "Defense Evasion, Persistence"),
    ({"mshta.exe"}, None, "T1218.005", "System Binary Proxy Execution: Mshta", "Defense Evasion"),
    ({"rundll32.exe"}, None, "T1218.011", "System Binary Proxy Execution: Rundll32", "Defense Evasion"),
    ({"regsvr32.exe"}, None, "T1218.010", "System Binary Proxy Execution: Regsvr32", "Defense Evasion"),
    ({"wmic.exe"}, None, "T1047", "Windows Management Instrumentation", "Execution"),
    ({"schtasks.exe"}, r"(?i)/create\b", "T1053.005", "Scheduled Task/Job: Scheduled Task", "Execution, Persistence, Privilege Escalation"),
    ({"sc.exe"}, r"(?i)\b(create|config)\b", "T1543.003", "Create or Modify System Process: Windows Service", "Persistence, Privilege Escalation"),
    ({"sc.exe"}, r"(?i)\bstop\b", "T1489", "Service Stop", "Impact"),
    ({"mofcomp.exe"}, None, "T1546.003", "Event Triggered Execution: WMI Event Subscription", "Persistence, Privilege Escalation"),
    ({"whoami.exe"}, None, "T1033", "System Owner/User Discovery", "Discovery"),
    ({"net.exe", "net1.exe"}, r"(?i)\b(user|group|localgroup)\b", "T1087", "Account Discovery", "Discovery"),
]


def map_process_techniques(process, commands: list[str], ocsf_attacks: list | None = None) -> list[dict]:
    """MITRE candidates for a process, with the basis of each mapping."""
    name = proc_key(process)
    cmd_text = " ".join(c for c in commands if c)
    found: dict[str, dict] = {}
    for names, pattern, tid, tname, tactic in TECHNIQUE_RULES:
        if name not in names:
            continue
        if pattern is None:
            basis, status = "process_name", "candidate"
        elif cmd_text and re.search(pattern, cmd_text):
            basis, status = "command_line", "supported_by_command_line"
        else:
            continue
        if tid not in found or status == "supported_by_command_line":
            found[tid] = {"technique": tid, "name": tname, "tactic": tactic,
                          "parent": tid.split(".")[0] if "." in tid else None,
                          "status": status, "basis": basis}
    for a in ocsf_attacks or []:  # techniques the source already attached to the event
        tech = (a.get("technique") or {}) if isinstance(a, dict) else {}
        tid = tech.get("uid")
        if tid:
            tactic = (a.get("tactic") or {}).get("name") if isinstance(a.get("tactic"), dict) else None
            found[tid] = {"technique": tid, "name": tech.get("name"), "tactic": tactic,
                          "parent": tid.split(".")[0] if "." in tid else None,
                          "status": "reported_by_source", "basis": "ocsf_attacks"}
    return sorted(found.values(), key=lambda t: t["technique"])


def assess_process_techniques(finding: dict, incident: pd.DataFrame) -> list[dict]:
    commands = [finding.get("sample_command")] if finding.get("sample_command") else []
    attacks: list = []
    if len(incident):
        commands += incident["cmd_line"].dropna().astype(str).tolist()
        for lst in incident["attacks"]:
            attacks += list(lst or [])
    techniques = map_process_techniques(finding.get("process"), commands, attacks)
    for t in techniques:
        t["evidence_events"] = incident["event_ref"].tolist() if len(incident) else []
    return techniques


# --------------------------------------------------------------------------- graph

def build_process_graph(finding: dict, groups: list[dict], techniques: list[dict]) -> nx.DiGraph:
    """user -executed_on-> host -ran-> parent -spawned-> process -maps_to-> technique.
    Without linked events the graph is built from the finding itself."""
    G = nx.DiGraph()
    inc = finding["finding_id"]
    G.add_node(inc, kind="incident", label="Incident")
    lineages = groups or [{
        "host": finding.get("target_host"), "user": finding.get("target_user"),
        "parent_process": finding.get("parent_process"), "process": finding.get("process"),
        "events": 0, "group_ref": None,
    }]
    for g in lineages:
        host, user = g["host"], g["user"]
        u, h = f"user:{user}", f"host:{host}"
        p, c = f"proc:{host}:{proc_key(g['parent_process'])}", f"proc:{host}:{proc_key(g['process'])}"
        G.add_node(u, kind="user", label=str(user))
        G.add_node(h, kind="host", label=str(host))
        G.add_node(p, kind="parent_process", label=str(g["parent_process"]))
        G.add_node(c, kind="process", label=str(g["process"]))
        G.add_edge(u, h, rel="executed_on")
        G.add_edge(h, p, rel="ran")
        G.add_edge(p, c, rel="spawned",
                   count=int(finding.get("occurrence_count") or g.get("events") or 0),
                   events_found=int(g.get("events") or 0))
        G.add_edge(inc, c, rel="flagged")
        for t in techniques:
            tn = f"t:{t['technique']}"
            G.add_node(tn, kind="technique", label=t["technique"], name=t["name"], status=t["status"])
            G.add_edge(c, tn, rel="maps_to", status=t["status"])
    for t in techniques:
        if t["parent"] and f"t:{t['parent']}" in G:
            G.add_edge(f"t:{t['technique']}", f"t:{t['parent']}", rel="subtechnique_of")
    return G


# --------------------------------------------------------------------------- incident object

def _iso(t):
    return None if t is None or pd.isna(t) else pd.Timestamp(t).isoformat()


def process_evidence_summary(finding: dict, outcome: dict, techniques: list[dict]) -> str:
    first, last = finding.get("first_seen"), finding.get("last_seen")
    window = (f"between {first:%Y-%m-%d %H:%M} and {last:%H:%M} UTC" if first is not None and last is not None
              else "in the anomaly window")
    score = outcome.get("min_anomaly_score")
    score_txt = f", min anomaly score {score:.4f} (lower is more anomalous)" if isinstance(score, (int, float)) else ""
    model = f" (model {outcome['model_version']})" if outcome.get("model_version") else ""
    text = (f"Isolation Forest{model} flagged {outcome['lineage']} run by {outcome['user']} on "
            f"{outcome['host']}: {outcome['occurrence_count']} occurrence(s) {window}{score_txt}.")
    if outcome.get("sample_command"):
        text += f" Sample command: {outcome['sample_command']}."
    if techniques:
        text += " Candidate techniques: " + "; ".join(f"{t['technique']} {t['name']}" for t in techniques) + "."
    text += (f" Linked events found: {outcome['events_found']} of {outcome['events_listed_by_model']}")
    if outcome["events_missing"]:
        text += (" (none were in the supplied OCSF events)" if outcome["events_found"] == 0
                 else " (the rest were not in the supplied OCSF events)")
    if outcome["inferred_events"]:
        text += f"; {outcome['inferred_events']} more with the same pattern"
    return text + "."


def _values(from_finding, incident: pd.DataFrame, column: str) -> list[str]:
    vals = {str(from_finding)} if from_finding else set()
    if len(incident):
        vals |= set(incident[column].dropna().astype(str))
    return sorted(vals)


def incident_id_for(finding: dict) -> str:
    """INC-XXXXXXXX from the tenant and the finding id (stable across reruns; the same
    finding id in two tenants gives two incidents)."""
    key = finding["finding_id"] if not finding.get("tenant_uid") else f"{finding['tenant_uid']}|{finding['finding_id']}"
    return "INC-" + hashlib.sha1(key.encode()).hexdigest()[:8].upper()


def build_process_incident_object(finding, labelled, incident, groups, outcome, techniques,
                                  G, missing_uids, schema_version: str) -> dict:
    from .graph import graph_to_dict

    context = labelled[labelled["role"] == "context"] if len(labelled) else labelled
    obj = {
        "schema_version": schema_version,
        "incident_type": "process_execution",
        "incident_id": incident_id_for(finding),
        "tenant_uid": finding.get("tenant_uid"),
        "status": "open",
        "closed_at": None,
        "watch_until": None,
        "finding": {**{k: v for k, v in finding.items() if k not in ("first_seen", "last_seen")},
                    "first_seen": _iso(finding.get("first_seen")),
                    "last_seen": _iso(finding.get("last_seen"))},
        "outcome": {**outcome, "first_seen": _iso(outcome.get("first_seen")),
                    "last_seen": _iso(outcome.get("last_seen"))},
        "process_groups": [{**g, "first": _iso(g["first"]), "last": _iso(g["last"])} for g in groups],
        "sessions": [],
        "entities": {
            "hosts": _values(finding.get("target_host"), incident, "host"),
            "users": _values(finding.get("target_user"), incident, "user"),
            "processes": sorted({str(x) for x in [finding.get("parent_process"), finding.get("process")] if x}),
            "source_ips": [],
        },
        "techniques": techniques,
        "timeline": [
            {
                "event_ref": r["event_ref"], "event_uid": r["event_uid"],
                "event_time": _iso(r["event_time"]), "group_ref": r["group_ref"],
                "host": r["host"], "user": r["user"],
                "parent_process": r["parent_process"], "process": r["process"],
                "cmd_line": r["cmd_line"], "event_code": r["event_code"], "link_type": r["link_type"],
            }
            for _, r in incident.iterrows()
        ],
        "context_events": [
            {"event_uid": r["event_uid"], "event_time": _iso(r["event_time"]), "user": r["user"],
             "lineage": f"{r['parent_process']} -> {r['process']}"}
            for _, r in context.iterrows()
        ],
        "graph": graph_to_dict(G),
        "evidence": {
            "incident_event_count": len(incident),
            "events_listed_by_model": outcome["events_listed_by_model"],
            "events_found": outcome["events_found"],
            "missing_event_uids": missing_uids,
            "context_event_count": len(context),
            "event_uids": incident["event_uid"].tolist() if len(incident) else [],
        },
        "evidence_summary": process_evidence_summary(finding, outcome, techniques),
    }
    return obj
