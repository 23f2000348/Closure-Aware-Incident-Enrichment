"""Engine-independent safeguards for Sigma correlation findings.

The enrichment layer must produce correct incidents even when the correlation
engine or ingestion misbehaves. This module provides:

1. Rule catalogue: the correlation rules (thresholds, group-by fields, time spans),
   read from the engine's Sigma YAML files, with built-in copies of the SSH rules.
2. Robust findings: ``finding_from_correlation`` turns a ``wazuh_correlations`` row
   into a finding, tolerating missing fields, JSON-string arrays, duplicate uids,
   naive or swapped timestamps.
3. Merging: findings for the same attack (same source IP, compatible host,
   overlapping or close time windows) are grouped into one incident.
4. Integrity check: each finding's rule is re-evaluated on DISTINCT events (after
   de-duplication), with and without evidence recovered from the time window, and
   gets a verdict such as ``confirmed`` or ``below_threshold_after_dedup``.
5. Input hardening: ``alert_from_ocsf_row`` builds a Wazuh-style record from an
   OCSF row, falling back to the OCSF columns when ``raw_data`` is missing or broken.

Nothing here trusts the engine's counts; everything is recomputed from events.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from .normalize import _text
from .scoring import present

# Sigma / OCSF field -> column in the normalised records
FIELD_MAP = {
    "src_endpoint.ip": "source_ip",
    "device.hostname": "host",
    "user.name": "target_user",
}
# Finding attribute holding the group value for each record column
FINDING_ATTR = {"source_ip": "source_ip", "host": "target_host", "target_user": "target_user"}

VERDICTS = {
    "confirmed": "The rule's condition holds on distinct events.",
    "confirmed_with_recovered_evidence": "The condition holds only once events recovered from the time window are added.",
    "below_threshold_after_dedup": "After removing duplicate records the condition does not hold; the engine likely counted duplicates.",
    "below_threshold": "The condition does not hold on the events available, and no duplicates explain it.",
    "unverifiable": "Not enough information to re-check (events missing, or a group/condition field cannot be mapped).",
    "rule_unknown": "The rule is not in the catalogue, so its condition cannot be re-checked.",
}


class MalformedFinding(ValueError):
    """A correlation row that cannot become a finding (e.g. no finding uid)."""


# --------------------------------------------------------------------------- rules

@dataclass(frozen=True)
class RuleSpec:
    title: str
    name: str | None
    rule_id: str | None
    ctype: str                         # event_count | value_count | other
    group_by: tuple[str, ...]
    timespan: pd.Timedelta | None
    gte: int | None
    field: str | None                  # value_count field
    base_rules: tuple[str, ...]
    base_event_codes: frozenset[str] | None
    techniques: tuple[str, ...]
    source: str = "builtin"

    def describe(self) -> str:
        span = f"{int(self.timespan.total_seconds() // 60)} min" if self.timespan is not None else "?"
        grp = ", ".join(self.group_by) or "-"
        if self.ctype == "value_count":
            return f">= {self.gte} distinct {self.field} per ({grp}) within {span}"
        return f">= {self.gte} events per ({grp}) within {span}"


def parse_timespan(value) -> pd.Timedelta | None:
    if value is None:
        return None
    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", str(value))
    if not m:
        return None
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    return pd.Timedelta(**{units[m.group(2)]: int(m.group(1))})


def techniques_from_tags(tags) -> tuple[str, ...]:
    out = []
    for t in tags or []:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(t).strip().lower())
        if m:
            out.append(m.group(1).upper())
    return tuple(out)


SSH_BASE_CODES = frozenset({"5710", "5716", "5760"})

BUILTIN_RULES = (
    RuleSpec(
        title="Multiple SSH Authentication Failures", name="multiple_ssh_auth_failures",
        rule_id="9a78e471-bc25-4fe0-9d04-5858cf7b3299", ctype="event_count",
        group_by=("src_endpoint.ip", "device.hostname"), timespan=pd.Timedelta(minutes=10),
        gte=5, field=None, base_rules=("ssh_auth_failure",), base_event_codes=SSH_BASE_CODES,
        techniques=("T1110.001", "T1021.004"),
    ),
    RuleSpec(
        title="SSH Password Spraying", name=None, rule_id="pwd-spray-cor-1", ctype="value_count",
        group_by=("src_endpoint.ip",), timespan=pd.Timedelta(minutes=10),
        gte=3, field="user.name", base_rules=("ssh_auth_failure",), base_event_codes=SSH_BASE_CODES,
        techniques=("T1110.003", "T1021.004"),
    ),
)


def _event_codes_in(detection) -> set[str]:
    """Collect values of any ``metadata.event_code`` key inside a Sigma detection block."""
    codes: set[str] = set()
    if isinstance(detection, dict):
        for k, v in detection.items():
            if str(k).split("|")[0] == "metadata.event_code":
                vals = v if isinstance(v, list) else [v]
                codes |= {str(x) for x in vals if x is not None}
            else:
                codes |= _event_codes_in(v)
    elif isinstance(detection, list):
        for item in detection:
            codes |= _event_codes_in(item)
    return codes


class RuleCatalog:
    """Look-up of correlation rules by id, name or title (case-insensitive)."""

    def __init__(self, specs=(), warnings=()):
        self.specs: list[RuleSpec] = list(specs)
        self.warnings: list[str] = list(warnings)

    @classmethod
    def builtin(cls) -> "RuleCatalog":
        return cls(BUILTIN_RULES)

    @classmethod
    def from_dir(cls, rules_dir: str | Path, include_builtin: bool = True) -> "RuleCatalog":
        """Read Sigma correlation rules from a directory. Rules found on disk replace
        the built-in copies with the same id/name/title. Unreadable files are
        skipped and listed in ``warnings``."""
        warnings: list[str] = []
        try:
            import yaml
        except ImportError:  # pragma: no cover - PyYAML is a declared dependency
            return cls(BUILTIN_RULES if include_builtin else (), ["PyYAML not installed; using built-in rules"])

        docs = []
        for path in sorted(Path(rules_dir).glob("*.y*ml")):
            try:
                for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                    if isinstance(doc, dict):
                        docs.append((path.name, doc))
            except Exception as exc:  # malformed YAML must not stop the run
                warnings.append(f"{path.name}: {exc.__class__.__name__}: {exc}")

        base_codes: dict[str, frozenset[str]] = {}
        for _, doc in docs:
            if "detection" in doc:
                codes = frozenset(_event_codes_in(doc["detection"]))
                for key in (doc.get("name"), doc.get("id"), doc.get("title")):
                    if key and codes:
                        base_codes[str(key).lower()] = codes

        specs = []
        for fname, doc in docs:
            corr = doc.get("correlation")
            if not isinstance(corr, dict):
                continue
            cond = corr.get("condition") or {}
            refs = tuple(str(r) for r in (corr.get("rules") or []))
            codes = set()
            for r in refs:
                codes |= set(base_codes.get(r.lower(), ()))
            gte = cond.get("gte") if isinstance(cond, dict) else None
            specs.append(RuleSpec(
                title=str(doc.get("title") or doc.get("name") or doc.get("id") or fname),
                name=doc.get("name"), rule_id=str(doc["id"]) if doc.get("id") else None,
                ctype=str(corr.get("type") or "other"),
                group_by=tuple(str(g) for g in (corr.get("group-by") or corr.get("group_by") or [])),
                timespan=parse_timespan(corr.get("timespan")),
                gte=int(gte) if isinstance(gte, (int, float)) else None,
                field=cond.get("field") if isinstance(cond, dict) else None,
                base_rules=refs, base_event_codes=frozenset(codes) or None,
                techniques=techniques_from_tags(doc.get("tags")), source=fname,
            ))

        if include_builtin:
            keys = {k for s in specs for k in _spec_keys(s)}
            specs += [b for b in BUILTIN_RULES if not (_spec_keys(b) & keys)]
        return cls(specs, warnings)

    def lookup(self, rule_id=None, title=None) -> RuleSpec | None:
        wanted = [str(v).strip().lower() for v in (rule_id, title) if present(v)]
        for w in wanted:
            for s in self.specs:
                if w in _spec_keys(s):
                    return s
        return None


def _spec_keys(spec: RuleSpec) -> set[str]:
    return {str(k).lower() for k in (spec.rule_id, spec.name, spec.title) if k}


# --------------------------------------------------------------------------- parsing helpers

def to_utc(value) -> pd.Timestamp | None:
    """Any ClickHouse time -> UTC timestamp. Integers are epoch ms (or s if small);
    strings without a zone are UTC. Unparseable -> None."""
    if not present(value):
        return None
    if isinstance(value, pd.Timestamp):
        return value.tz_localize("UTC") if value.tzinfo is None else value.tz_convert("UTC")
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if value <= 0:
                return None
            unit = "ms" if abs(value) > 1e11 else "s"
            return pd.to_datetime(int(value), unit=unit, utc=True)
        ts = pd.to_datetime(str(value), utc=True, errors="coerce")
    except (ValueError, OverflowError, TypeError, pd.errors.OutOfBoundsDatetime):
        return None   # out-of-range or nonsensical time
    return None if pd.isna(ts) else ts


def as_list(value) -> list:
    """Arrays may arrive as lists, JSON strings, or comma-separated strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if hasattr(value, "tolist"):
        return list(value.tolist())
    s = str(value).strip()
    if not s:
        return []
    if s.startswith("["):
        try:
            parsed = json.loads(s)
            return parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            s = s.strip("[]")
    return [p.strip().strip("'\"") for p in s.split(",") if p.strip()]


def _clean_uids(values) -> tuple[list[str], int]:
    """Drop empties and placeholders, de-duplicate in order. Returns (uids, duplicates)."""
    seen, out, dups = set(), [], 0
    for v in values:
        u = _text(v)
        if not u or u.upper() in ("N/A", "NONE", "NULL"):
            continue
        if u in seen:
            dups += 1
            continue
        seen.add(u)
        out.append(u)
    return out, dups


def _group_value(row: dict, field: str):
    gk = row.get("group_key")
    if isinstance(gk, str) and gk.strip().startswith("{"):
        try:
            gk = json.loads(gk)          # the engine stores group_key as a JSON string
        except json.JSONDecodeError:
            pass
    if isinstance(gk, dict):
        return gk.get(field)
    if present(gk):
        for part in str(gk).split("|"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == field:
                    return v.strip()
    return None


# --------------------------------------------------------------------------- findings

def finding_from_correlation(row: dict, catalog: RuleCatalog | None = None) -> dict:
    """``wazuh_correlations`` row -> finding. Raises ``MalformedFinding`` only when
    the row has no finding uid; every other gap is recorded in ``notes``."""
    catalog = catalog or RuleCatalog.builtin()
    fid = row.get("finding_uid")
    if not present(fid):
        raise MalformedFinding("correlation row without finding_uid")
    notes: list[str] = []

    raw_uids = as_list(row.get("contributing_finding_uids"))
    uids, dup_uids = _clean_uids(raw_uids)
    if dup_uids:
        notes.append(f"{dup_uids} uid(s) appear more than once in the engine's contributing list")
    engine_count = row.get("contributing_event_count")
    try:
        engine_count = int(float(engine_count)) if present(engine_count) else len(raw_uids)
    except (TypeError, ValueError):
        engine_count = len(raw_uids)
        notes.append("contributing_event_count unreadable; using the length of the uid list")

    first, last = to_utc(row.get("first_seen_time")), to_utc(row.get("last_seen_time"))
    if first is None and last is None:
        first = last = to_utc(row.get("time"))
    first = first or last
    last = last or first
    if first is not None and last is not None and first > last:
        first, last = last, first
        notes.append("first_seen was after last_seen; swapped")

    src_ip = row.get("src_ip") if present(row.get("src_ip")) else _group_value(row, "src_endpoint.ip")
    host_raw = row.get("device_hostname") if present(row.get("device_hostname")) else _group_value(row, "device.hostname")
    hosts = [h for h in (_text(x) for x in (as_list(host_raw) if present(host_raw) else [])) if h]
    src_ip = _text(src_ip)
    title, rule_id = _text(row.get("finding_title")), _text(row.get("rule_id"))

    spec = catalog.lookup(rule_id, title)
    techniques: list[str] = []
    for a in as_list(row.get("attacks")):
        a = a if isinstance(a, dict) else {}
        tid = (a.get("technique") or {}).get("uid") if isinstance(a.get("technique"), dict) else None
        if tid:
            techniques.append(str(tid).upper())
    if not techniques and spec:
        techniques = list(spec.techniques)

    return {
        "finding_id": str(fid),
        "finding_source": "sigma",
        "tenant_uid": _text(row.get("tenant_uid")),
        "snapshot_version": _snapshot(row),
        "title": title or (spec.title if spec else "Sigma correlation"),
        "rule_id": rule_id or (spec.rule_id if spec else None),
        "rule_title": spec.title if spec else None,
        "source_ip": src_ip,
        "target_host": hosts[0] if hosts else None,
        "hosts": hosts,
        "target_user": None,
        "first_seen": first,
        "last_seen": last,
        "techniques": sorted(set(techniques)),
        "contributing_finding_uids": uids,
        "engine_contributing_count": engine_count,
        "engine_uid_duplicates": dup_uids,
        "notes": notes,
    }


def _snapshot(row: dict) -> int | None:
    try:
        v = row.get("snapshot_version")
        return int(float(v)) if present(v) else None
    except (TypeError, ValueError):
        return None


def dedupe_correlation_rows(rows: list[dict]) -> tuple[list[dict], int]:
    """One row per (tenant_uid, finding_uid): the highest ``snapshot_version``.

    The engine stores a finding as cumulative snapshots (same ``finding_uid``, rising
    ``snapshot_version``); the latest one holds all evidence so far. Repeated rows of
    the same snapshot (retries) are also dropped. Rows without a uid are kept so that
    ``finding_from_correlation`` can count them as malformed. Order of first appearance
    is preserved. Returns (rows, dropped)."""
    best: dict[tuple, tuple[int, dict]] = {}
    order: list = []
    for i, r in enumerate(rows):
        key = r.get("finding_uid")
        key = str(key) if present(key) and not isinstance(key, (dict, list)) else None
        if key is None:
            order.append(("row", i, r))
            continue
        k = (_text(r.get("tenant_uid")) or "", key)
        version = _snapshot(r)
        rank = (version if version is not None else -1, i)   # later row wins a tie
        if k not in best:
            order.append(("key", k, None))
            best[k] = (rank, r)
        elif rank > best[k][0]:
            best[k] = (rank, r)
    out = [best[x[1]][1] if x[0] == "key" else x[2] for x in order]
    return out, len(rows) - len(out)


def merge_findings(findings: list[dict], gap: pd.Timedelta = pd.Timedelta(minutes=10)) -> list[list[dict]]:
    """Group findings that describe the same attack: same tenant and source IP, compatible hosts
    (equal, overlapping, or one side unknown), and windows that overlap or are at most
    ``gap`` apart. Findings without a source IP or time are never merged."""
    groups: list[list[dict]] = []
    by_ip: dict[tuple, list[dict]] = {}
    for f in findings:
        if present(f.get("source_ip")) and f.get("first_seen") is not None:
            # findings from different tenants are never merged
            by_ip.setdefault((f.get("tenant_uid") or "", str(f["source_ip"])), []).append(f)
        else:
            groups.append([f])
    for ip in sorted(by_ip):
        items = sorted(by_ip[ip], key=lambda f: (f["first_seen"], f["finding_id"]))
        open_groups: list[dict] = []   # {"members", "end", "hosts"}
        for f in items:
            fh = set(f.get("hosts") or [])
            target = None
            for g in open_groups:
                close = f["first_seen"] <= g["end"] + gap
                hosts_ok = not fh or not g["hosts"] or bool(fh & g["hosts"])
                if close and hosts_ok:
                    target = g
                    break
            if target is None:
                target = {"members": [], "end": f["last_seen"], "hosts": set()}
                open_groups.append(target)
            target["members"].append(f)
            target["end"] = max(target["end"], f["last_seen"])
            target["hosts"] |= fh
        groups += [g["members"] for g in open_groups]
    groups.sort(key=lambda g: (min((f["first_seen"] for f in g if f.get("first_seen") is not None),
                                   default=pd.Timestamp.max.tz_localize("UTC")), g[0]["finding_id"]))
    return groups


def group_finding(members: list[dict]) -> dict:
    """One finding representing a group of merged findings (deterministic id)."""
    members = sorted(members, key=lambda f: (f.get("first_seen") or pd.Timestamp.max.tz_localize("UTC"),
                                             f["finding_id"]))
    # The incident keeps the id of the attack's earliest finding, so it stays the same
    # when later findings (or later snapshots) join it on a rerun.
    fid = members[0]["finding_id"]
    titles = list(dict.fromkeys(str(m.get("title") or "?") for m in members))
    hosts = list(dict.fromkeys(h for m in members for h in (m.get("hosts") or [])))
    host_counts = Counter(m.get("target_host") for m in members if present(m.get("target_host")))
    uids: list[str] = []
    for m in members:
        uids += [u for u in m.get("contributing_finding_uids", []) if u not in uids]
    firsts = [m["first_seen"] for m in members if m.get("first_seen") is not None]
    lasts = [m["last_seen"] for m in members if m.get("last_seen") is not None]
    return {
        "finding_id": fid,
        "finding_source": "sigma",
        "tenant_uid": members[0].get("tenant_uid"),
        "title": " + ".join(titles),
        "source_ip": members[0].get("source_ip"),
        "target_host": host_counts.most_common(1)[0][0] if host_counts else None,
        "hosts": hosts,
        "target_user": None,
        "first_seen": min(firsts) if firsts else None,
        "last_seen": max(lasts) if lasts else None,
        "techniques": sorted({t for m in members for t in m.get("techniques", [])}),
        "contributing_finding_uids": uids,
        "merged_from": [
            {"finding_id": m["finding_id"], "title": m.get("title"), "rule_id": m.get("rule_id"),
             "snapshot_version": m.get("snapshot_version"),
             "first_seen": m.get("first_seen"), "last_seen": m.get("last_seen"),
             "engine_contributing_count": m.get("engine_contributing_count")}
            for m in members
        ],
        "notes": [n for m in members for n in m.get("notes", [])],
    }


# --------------------------------------------------------------------------- integrity

def evaluate_rule(spec: RuleSpec, events: pd.DataFrame, finding: dict) -> dict:
    """Re-evaluate a correlation condition on the given (distinct) events, restricted
    to the finding's group and to the base rule's event codes, over any sliding
    window of the rule's time span. ``met`` is None when it cannot be evaluated."""
    out = {"met": None, "value": None, "threshold": spec.gte, "reason": None}
    if spec.ctype not in ("event_count", "value_count") or spec.gte is None or spec.timespan is None:
        out["reason"] = f"unsupported correlation ({spec.ctype})"
        return out
    df = events
    for g in spec.group_by:
        col = FIELD_MAP.get(g)
        if col is None:
            out["reason"] = f"group field {g} has no mapping"
            return out
        val = finding.get(FINDING_ATTR[col])
        if not present(val):
            out["reason"] = f"finding has no value for group field {g}"
            return out
        df = df[df[col].astype(str) == str(val)]
    if spec.base_event_codes:
        df = df[df["rule_id"].astype(str).isin(spec.base_event_codes)]
    value_col = None
    if spec.ctype == "value_count":
        value_col = FIELD_MAP.get(spec.field or "")
        if value_col is None:
            out["reason"] = f"condition field {spec.field} has no mapping"
            return out
    df = df[df["event_time"].notna()].sort_values("event_time")
    times = list(df["event_time"])
    values = list(df[value_col]) if value_col else None

    best, lo, counts = 0, 0, Counter()
    for hi in range(len(times)):
        if values is not None and present(values[hi]):
            counts[values[hi]] += 1
        while times[hi] - times[lo] > spec.timespan:
            if values is not None and present(values[lo]):
                counts[values[lo]] -= 1
                if counts[values[lo]] == 0:
                    del counts[values[lo]]
            lo += 1
        best = max(best, len(counts) if values is not None else hi - lo + 1)
    out["value"] = best
    out["met"] = best >= spec.gte
    return out


def integrity_check(finding: dict, spec: RuleSpec | None, incident: pd.DataFrame,
                    canonical_all: pd.DataFrame) -> dict:
    """Compare what the engine claimed with what the events show."""
    linked = set(finding.get("contributing_finding_uids", []))
    has_uids = "ocsf_uids" in canonical_all.columns and len(canonical_all)
    found_uids = set().union(*canonical_all["ocsf_uids"]) & linked if has_uids else set()
    missing = sorted(linked - found_uids)

    def is_linked(uids) -> bool:
        return bool(set(uids or []) & linked)

    linked_rows = canonical_all[canonical_all["ocsf_uids"].map(is_linked)] if has_uids else canonical_all.iloc[0:0]
    recovered_rows = (incident[~incident["ocsf_uids"].map(is_linked)]
                      if len(incident) and "ocsf_uids" in incident.columns else incident.iloc[0:0])
    merged_dups = len(found_uids) - len(linked_rows)  # distinct uids that turned out to be the same event

    report = {
        "finding_id": finding["finding_id"],
        "rule": spec.title if spec else finding.get("title"),
        "condition": spec.describe() if spec else None,
        "engine_contributing_count": finding.get("engine_contributing_count"),
        "engine_uids_listed": len(linked),
        "engine_uids_found": len(found_uids),
        "engine_uids_missing": missing,
        "distinct_linked_events": len(linked_rows),
        "duplicate_records_merged": merged_dups + int(finding.get("engine_uid_duplicates") or 0),
        "recovered_events": len(recovered_rows),
    }
    if spec is None:
        report.update(verdict="rule_unknown", on_linked=None, with_recovered=None)
    else:
        on_linked = evaluate_rule(spec, linked_rows, finding)
        if spec.base_event_codes:
            both = (pd.concat([linked_rows, recovered_rows]).drop_duplicates("event_uid")
                    if len(recovered_rows) else linked_rows)
            with_rec = evaluate_rule(spec, both, finding)
        else:
            # Without the base rule's event codes we cannot tell whether a recovered
            # event would have matched it, so recovered events are not counted.
            with_rec = {**on_linked, "reason": "recovered events not counted: base rule's event codes unknown"}
        report.update(on_linked=on_linked, with_recovered=with_rec)
        if on_linked["met"] is None:
            verdict = "unverifiable"
        elif on_linked["met"]:
            verdict = "confirmed"
        elif with_rec["met"]:
            verdict = "confirmed_with_recovered_evidence"
        elif missing:
            verdict = "unverifiable"
        elif report["duplicate_records_merged"] > 0:
            verdict = "below_threshold_after_dedup"
        else:
            verdict = "below_threshold"
        report["verdict"] = verdict
    report["verdict_meaning"] = VERDICTS[report["verdict"]]
    report["note"] = integrity_note(report)
    return report


def integrity_note(r: dict) -> str:
    parts = [f"{r['rule']}: engine listed {r['engine_contributing_count']} record(s)"]
    parts.append(f"{r['distinct_linked_events']} distinct event(s) found")
    if r["duplicate_records_merged"]:
        parts.append(f"{r['duplicate_records_merged']} duplicate(s) merged")
    if r["engine_uids_missing"]:
        parts.append(f"{len(r['engine_uids_missing'])} listed event(s) not found")
    if r["recovered_events"]:
        parts.append(f"{r['recovered_events']} more matching event(s) recovered from the window")
    text = ", ".join(parts) + "."
    v = r["verdict"]
    lv = (r.get("on_linked") or {}).get("value")
    th = (r.get("on_linked") or {}).get("threshold")
    if v == "confirmed":
        text += f" Condition confirmed ({lv} >= {th})."
    elif v == "confirmed_with_recovered_evidence":
        text += f" Condition met only with recovered events ({r['with_recovered']['value']} >= {th})."
    elif v == "below_threshold_after_dedup":
        text += f" Below threshold after de-duplication ({lv} < {th}): likely duplicate delivery."
    elif v == "below_threshold":
        text += f" Below threshold on available events ({lv} < {th})."
    elif v == "unverifiable":
        reason = (r.get("on_linked") or {}).get("reason") or "listed events missing"
        text += f" Could not re-check: {reason}."
    else:
        text += " Rule not in catalogue; not re-checked."
    return text


def combined_verdict(reports: list[dict]) -> str:
    order = ["below_threshold_after_dedup", "below_threshold", "unverifiable", "rule_unknown",
             "confirmed_with_recovered_evidence", "confirmed"]
    vs = {r["verdict"] for r in reports}
    if vs <= {"confirmed", "confirmed_with_recovered_evidence"} and vs:
        return "confirmed_with_recovered_evidence" if "confirmed_with_recovered_evidence" in vs else "confirmed"
    for v in order:
        if v in vs:
            return v
    return "unverifiable"


# --------------------------------------------------------------------------- OCSF rows -> records

def alert_from_ocsf_row(row: dict) -> tuple[dict, bool]:
    """Build a Wazuh-style alert dict from a ``wazuh_ocsf_events`` row.

    Uses ``raw_data`` when it holds the original Wazuh alert; otherwise (missing,
    malformed, or not an alert) builds one from the OCSF columns. Fields missing
    from the raw alert are filled from the columns, never overwritten.
    Returns (alert, synthesized)."""
    raw = row.get("raw_data")
    alert: dict = {}
    if isinstance(raw, dict):
        alert = dict(raw)
    elif present(raw):
        try:
            parsed = json.loads(raw)
            alert = parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            alert = {}
    synthesized = not ("rule" in alert or "full_log" in alert)
    if synthesized:
        alert = {}

    t = to_utc(row.get("time")) or to_utc(row.get("time_dt"))
    if not present(alert.get("timestamp")) and t is not None:
        alert["timestamp"] = t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    if not present(alert.get("full_log")) and present(row.get("message")):
        alert["full_log"] = str(row["message"])
    agent = dict(alert.get("agent") or {})
    if not present(agent.get("name")) and present(row.get("device_hostname")):
        agent["name"] = str(row["device_hostname"])
    if not present(agent.get("id")) and present(row.get("device_uid")):
        agent["id"] = str(row["device_uid"])
    if agent:
        alert["agent"] = agent
    rule = dict(alert.get("rule") or {})
    code = row.get("rule_id") if present(row.get("rule_id")) else row.get("event_code")
    if not present(rule.get("id")) and present(code):
        rule["id"] = str(code)
    if not present(rule.get("description")) and present(row.get("finding_title")):
        rule["description"] = str(row["finding_title"])
    if rule:
        alert["rule"] = rule
    data = dict(alert.get("data") or {})
    if not present(data.get("srcip")) and present(row.get("src_ip")):
        data["srcip"] = str(row["src_ip"])
    if not present(data.get("dstuser")) and not present(data.get("srcuser")) and present(row.get("user_name")):
        data["dstuser"] = str(row["user_name"])
    if data:
        alert["data"] = data
    if present(row.get("finding_uid")):
        alert["_ocsf_finding_uid"] = str(row["finding_uid"])
    if _text(row.get("tenant_uid")):
        alert["_tenant_uid"] = _text(row["tenant_uid"])
    return alert, synthesized


def in_group_window(row: dict, finding: dict, before: pd.Timedelta, after: pd.Timedelta) -> bool:
    """Offline equivalent of the bridge's window query: listed by the finding, or
    same source IP / host within [first_seen - before, last_seen + after]."""
    if not isinstance(row, dict):
        return False
    tenant = finding.get("tenant_uid")
    if tenant and present(row.get("tenant_uid")) and str(row["tenant_uid"]) != str(tenant):
        return False
    if str(row.get("finding_uid")) in set(finding.get("contributing_finding_uids", [])):
        return True
    t = to_utc(row.get("time")) or to_utc(row.get("time_dt"))
    if t is None or finding.get("first_seen") is None:
        return False
    if not (finding["first_seen"] - before <= t <= finding["last_seen"] + after):
        return False
    same_ip = present(finding.get("source_ip")) and str(row.get("src_ip")) == str(finding["source_ip"])
    hosts = set(finding.get("hosts") or ([finding["target_host"]] if present(finding.get("target_host")) else []))
    same_host = present(row.get("device_hostname")) and str(row["device_hostname"]) in hosts
    return bool(same_ip or same_host)
