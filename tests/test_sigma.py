"""Sigma safeguards: the layer must give correct incidents even when the correlation
engine or ingestion misbehaves. Fixtures in tests/fixtures/sigma are SYNTHETIC
(see make_fixtures.py) and reproduce the duplicate-delivery and early-spraying cases."""

import importlib.util
import json
from pathlib import Path

import pandas as pd
import pytest

from incident_enrichment.canonicalize import canonicalize
from incident_enrichment.normalize import build_records_frame
from incident_enrichment.pipeline import EmptyGroup, EnrichmentConfig, build_incident_object, enrich_sigma_group
from incident_enrichment.process import load_clickhouse_rows
from incident_enrichment.scoring import score_context
from incident_enrichment.sigma import (
    MalformedFinding,
    RuleCatalog,
    alert_from_ocsf_row,
    dedupe_correlation_rows,
    finding_from_correlation,
    group_finding,
    in_group_window,
    merge_findings,
    parse_timespan,
)

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "sigma"
CORR = load_clickhouse_rows(FIX / "correlations.json")
EVENTS = load_clickhouse_rows(FIX / "ocsf_events.json")
CONFIG = EnrichmentConfig()


def corr(uid):
    return next(r for r in CORR if r["finding_uid"] == uid)


def records_for(finding_group: dict, events=EVENTS):
    rows = [r for r in events if in_group_window(r, finding_group, CONFIG.context_pad, CONFIG.recovery_after)]
    return build_records_frame([alert_from_ocsf_row(r)[0] for r in rows], [])


def enrich(*uids, events=EVENTS, config=CONFIG):
    members = [finding_from_correlation(corr(u)) for u in uids]
    return enrich_sigma_group(members, records_for(group_finding(members), events), config)


# --------------------------------------------------------------------------- parsing findings

def test_finding_tolerates_json_strings_duplicates_and_naive_times():
    row = {
        "finding_uid": "f1", "rule_id": "multiple_ssh_auth_failures",
        "contributing_finding_uids": '["a", "b", "a", "", "N/A"]',
        "first_seen_time": "2026-10-13 18:06:00", "last_seen_time": "2026-10-13T18:07:00Z",
        "src_ip": None, "group_key": '{"src_endpoint.ip": "203.0.113.45", "device.hostname": "web-01"}',
    }
    f = finding_from_correlation(row)
    assert f["contributing_finding_uids"] == ["a", "b"]
    assert f["engine_uid_duplicates"] == 1
    assert f["source_ip"] == "203.0.113.45"          # recovered from the JSON group_key
    assert f["target_host"] == "web-01"
    assert str(f["first_seen"].tz) == "UTC"
    assert f["techniques"]                           # from the rule catalogue


def test_swapped_and_missing_times():
    f = finding_from_correlation({"finding_uid": "f", "first_seen_time": "2026-10-13T18:10:00Z",
                                  "last_seen_time": "2026-10-13T18:00:00Z"})
    assert f["first_seen"] < f["last_seen"] and any("swapped" in n for n in f["notes"])
    g = finding_from_correlation({"finding_uid": "g", "time": 1791914760000})
    assert g["first_seen"] == g["last_seen"] is not None
    h = finding_from_correlation({"finding_uid": "h", "first_seen_time": "garbage"})
    assert h["first_seen"] is None


def test_row_without_uid_is_malformed():
    with pytest.raises(MalformedFinding):
        finding_from_correlation({"finding_uid": "  ", "rule_id": "x"})


def test_duplicate_correlation_rows_are_dropped():
    unique, dropped = dedupe_correlation_rows(CORR)
    assert dropped == 1
    assert len([r for r in unique if r["finding_uid"] == "corr-brute-0001"]) == 1


def test_parse_timespan():
    assert parse_timespan("10m") == pd.Timedelta(minutes=10)
    assert parse_timespan("1h") == pd.Timedelta(hours=1)
    assert parse_timespan("bogus") is None


# --------------------------------------------------------------------------- merging

def _f(fid, ip, hosts, start, end):
    t = lambda s: pd.Timestamp(s, tz="UTC")  # noqa: E731
    return {"finding_id": fid, "source_ip": ip, "hosts": hosts, "target_host": hosts[0] if hosts else None,
            "first_seen": t(start), "last_seen": t(end), "contributing_finding_uids": [fid + "-u"]}


def test_merge_rules():
    a = _f("a", "1.1.1.1", ["web-01"], "2026-10-13 18:00", "2026-10-13 18:01")
    b = _f("b", "1.1.1.1", [], "2026-10-13 18:00:30", "2026-10-13 18:02")          # unknown host -> merges
    c = _f("c", "2.2.2.2", ["web-01"], "2026-10-13 18:00", "2026-10-13 18:01")     # other IP -> separate
    d = _f("d", "1.1.1.1", ["web-01"], "2026-10-13 20:00", "2026-10-13 20:01")     # 2 h later -> separate
    e = _f("e", "1.1.1.1", ["db-01"], "2026-10-13 18:00", "2026-10-13 18:01")      # other host -> separate
    groups = merge_findings([d, c, b, a, e])
    ids = sorted(sorted(m["finding_id"] for m in g) for g in groups)
    assert ids == [["a", "b"], ["c"], ["d"], ["e"]]


def test_group_id_is_deterministic():
    a = finding_from_correlation(corr("corr-spray-0001"))
    b = finding_from_correlation(corr("corr-brute-0001"))
    assert group_finding([a, b])["finding_id"] == group_finding([b, a])["finding_id"]
    # the merged incident keeps the earliest finding's id, so it does not change when
    # a later finding joins it
    assert group_finding([a, b])["finding_id"] == "corr-brute-0001"   # earliest (tie -> lowest id)


# --------------------------------------------------------------------------- integrity verdicts

def test_duplicate_delivery_is_flagged():
    res = enrich("corr-dup-0001")
    obj = res.incident_object
    assert len(res.incident) == 3                       # 5 records, 3 distinct events
    assert obj["evidence"]["raw_record_count"] == 5
    r = obj["integrity"]["findings"][0]
    assert r["verdict"] == "below_threshold_after_dedup"
    assert r["distinct_linked_events"] == 3 and r["duplicate_records_merged"] == 2
    assert obj["integrity"]["recommended_action"].startswith("review")
    assert "duplicate" in obj["evidence_summary"]


def test_spraying_alone_recovers_dropped_attempts():
    res = enrich("corr-spray-0001")
    obj = res.incident_object
    assert sorted(obj["entities"]["users"]) == ["admin", "oracle", "root", "test", "ubuntu"]
    assert obj["evidence"]["engine_linked_events"] == 3
    assert obj["evidence"]["recovered_events"] == 2
    assert obj["integrity"]["verdict"] == "confirmed"
    assert obj["integrity"]["findings"][0]["with_recovered"]["value"] == 5
    assert obj["finding"]["target_user"] is None       # spraying: no single target user
    assert obj["outcome"]["failed_password_attempts"] == 5


def test_unrelated_ip_on_same_host_is_excluded():
    res = enrich("corr-spray-0001", "corr-brute-0001")   # host known -> window pulls in the other IP
    assert set(res.incident["source_ip"]) == {"203.0.113.45"}
    other = res.context[res.context["source_ip"] == "198.51.100.7"]
    assert len(other) == 2 and (other["role"] != "incident").all()


def test_brute_force_and_spraying_become_one_incident():
    members = [finding_from_correlation(corr(u)) for u in ("corr-spray-0001", "corr-brute-0001")]
    groups = merge_findings(members)
    assert len(groups) == 1
    res = enrich_sigma_group(groups[0], records_for(group_finding(groups[0])), CONFIG)
    obj = res.incident_object
    assert len(res.incident) == 5
    assert len(obj["finding"]["merged_from"]) == 2
    assert {r["verdict"] for r in obj["integrity"]["findings"]} == {"confirmed"}


def test_missing_events_are_unverifiable_not_a_crash():
    members = [finding_from_correlation({**corr("corr-dup-0001"), "finding_uid": "corr-gone",
                                         "contributing_finding_uids": ["gone-1", "gone-2"]})]
    gf = group_finding(members)
    res = enrich_sigma_group(members, records_for(gf, events=[]), CONFIG)
    r = res.incident_object["integrity"]["findings"][0]
    assert r["verdict"] == "unverifiable" and r["engine_uids_missing"] == ["gone-1", "gone-2"]
    assert "No events available" in res.incident_object["evidence_summary"]


def test_some_listed_events_missing():
    events = [e for e in EVENTS if e["finding_uid"] not in ("dup-2a",)]
    res = enrich("corr-dup-0001", events=events)
    r = res.incident_object["integrity"]["findings"][0]
    assert r["engine_uids_missing"] == ["dup-2a"]
    assert r["verdict"] == "unverifiable"            # cannot rule out the missing ones


def test_unknown_rule():
    row = {**corr("corr-dup-0001"), "finding_uid": "corr-x", "rule_id": "something_new", "finding_title": "New rule"}
    members = [finding_from_correlation(row)]
    res = enrich_sigma_group(members, records_for(group_finding(members)), CONFIG)
    assert res.incident_object["integrity"]["verdict"] == "rule_unknown"


def test_group_without_time_or_events_raises_empty_group():
    members = [finding_from_correlation({"finding_uid": "z"})]
    with pytest.raises(EmptyGroup):
        enrich_sigma_group(members, build_records_frame([], []), CONFIG)


def test_group_without_time_uses_its_events():
    row = {**corr("corr-dup-0001"), "first_seen_time": None, "last_seen_time": None, "time": None}
    members = [finding_from_correlation(row)]
    rows = [e for e in EVENTS if e["finding_uid"] in row["contributing_finding_uids"]]
    res = enrich_sigma_group(members, build_records_frame([alert_from_ocsf_row(r)[0] for r in rows], []), CONFIG)
    assert len(res.incident) == 3
    assert any("no time" in n for n in res.incident_object["finding"]["notes"])


# --------------------------------------------------------------------------- input hardening

def test_broken_raw_data_is_rebuilt_from_columns():
    row = next(e for e in EVENTS if e["finding_uid"] == "noise-1")
    alert, synthesized = alert_from_ocsf_row(row)
    assert synthesized
    assert alert["agent"]["name"] == "web-01" and alert["data"]["srcip"] == "198.51.100.7"
    assert alert["full_log"] == row["message"] and alert["_ocsf_finding_uid"] == "noise-1"
    rec = build_records_frame([alert], [])
    assert rec.loc[0, "target_user"] == "admin" and str(rec.loc[0, "event_time"]).startswith("2026-10-13 18:06:07")


def test_raw_data_kept_and_gaps_filled():
    row = {**next(e for e in EVENTS if e["finding_uid"] == "spray-root")}
    raw = json.loads(row["raw_data"])
    del raw["agent"]
    row["raw_data"] = raw                                  # dict, not string
    alert, synthesized = alert_from_ocsf_row(row)
    assert not synthesized and alert["agent"]["name"] == "web-01" and alert["rule"]["id"] == "5760"


def test_empty_and_junk_inputs():
    records = build_records_frame([None, "x", 3], [])
    assert len(records) == 0 and "full_log" in records.columns
    canonical = canonicalize(records)
    assert len(canonical) == 0
    f = finding_from_correlation(corr("corr-dup-0001"))
    ctx = score_context(canonical, f)
    assert len(ctx) == 0


def test_rule_catalogue_from_engine_rules_and_bad_yaml(tmp_path):
    (tmp_path / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    (tmp_path / "ssh_auth_failure.yml").write_text(
        "title: SSH Authentication Failure\nname: ssh_auth_failure\n"
        "detection:\n  sel:\n    metadata.event_code: ['5710', '5760']\n  condition: sel\n", encoding="utf-8")
    (tmp_path / "brute.yml").write_text(
        "title: Brute\nname: brute_custom\ntags: [attack.t1110]\ncorrelation:\n  type: event_count\n"
        "  rules: [ssh_auth_failure]\n  group-by: [src_endpoint.ip]\n  timespan: 5m\n"
        "  condition:\n    gte: 4\n", encoding="utf-8")
    cat = RuleCatalog.from_dir(tmp_path)
    assert any("broken.yml" in w for w in cat.warnings)
    spec = cat.lookup("brute_custom")
    assert spec.gte == 4 and spec.timespan == pd.Timedelta(minutes=5)
    assert spec.base_event_codes == {"5710", "5760"} and "T1110" in spec.techniques
    assert cat.lookup("pwd-spray-cor-1") is not None          # built-ins still present


def test_build_incident_object_handles_empty_incident():
    f = finding_from_correlation(corr("corr-dup-0001"))
    f["target_user"] = None
    empty = canonicalize(build_records_frame([], []))
    ctx = score_context(empty, f)
    ctx["engine_linked"] = []
    from incident_enrichment.sessions import reconstruct_sessions, summarize_outcome
    inc, sessions = reconstruct_sessions(ctx)
    inc["summary"] = []
    outcome = summarize_outcome(sessions, build_records_frame([], []), f["source_ip"])
    import networkx as nx
    obj = build_incident_object(f, ctx, inc, sessions, outcome, [], nx.DiGraph())
    assert obj["timeline"] == [] and "No events" in obj["evidence_summary"]


# --------------------------------------------------------------------------- end to end

def test_bridge_offline_end_to_end(tmp_path):
    spec = importlib.util.spec_from_file_location("bridge", ROOT / "integrations" / "integrate_clickhouse_enrichment.py")
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    rc = bridge.main(["--from-files", "--correlations", str(FIX / "correlations.json"),
                      "--sigma-events", str(FIX / "ocsf_events.json"), "--out", str(tmp_path)])
    assert rc == 0
    report = json.loads((tmp_path / "run_report.json").read_text())
    s = report["sigma"]
    assert (s["correlation_rows_read"], s["duplicate_rows_dropped"], s["malformed_rows_skipped"]) == (5, 1, 1)
    assert s["groups"] == 2 and s["incidents_written"] == 2 and s["groups_failed"] == 0
    assert s["verdicts"] == {"below_threshold_after_dedup": 1, "confirmed": 1}
    assert s["event_rows_synthesized"] == 1
    assert len(list(tmp_path.glob("INC-*.json"))) == 2
    assert len(list(tmp_path.glob("INC-*_graph.png"))) == 2


def test_bridge_survives_corrupted_rows(tmp_path):
    """Random wrong-typed values in correlation and event rows: every group is still
    enriched or reported, never a crash (a lighter version of the fuzzing done in development)."""
    import random
    spec = importlib.util.spec_from_file_location("bridge", ROOT / "integrations" / "integrate_clickhouse_enrichment.py")
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    junk = [None, "", "garbage", 0, -1, [], {}, "[]", "{", "2026-13-45", 1e20, "N/A"]
    rng = random.Random(7)
    for trial in range(5):
        c, e = [dict(r) for r in CORR], [dict(r) for r in EVENTS]
        for r in rng.sample(c, 2) + rng.sample(e, 4):
            r[rng.choice(list(r))] = rng.choice(junk)
        c.append(rng.choice(junk))
        e.append(rng.choice(junk))
        d = tmp_path / str(trial)
        d.mkdir()
        (d / "c.json").write_text(json.dumps(c))
        (d / "e.json").write_text(json.dumps(e))
        assert bridge.main(["--from-files", "--correlations", str(d / "c.json"),
                            "--sigma-events", str(d / "e.json"), "--out", str(d / "out")]) == 0
        report = json.loads((d / "out" / "run_report.json").read_text())
        assert [x for x in report["errors"] if x["kind"] != "sigma_row"] == [], report["errors"]
