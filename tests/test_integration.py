"""Integration checks requested for the LogManthan hand-off:

1. latest Sigma snapshot selection and cumulative evidence,
2. the six-username SSH spraying / brute-force scenario,
3. tenant isolation,
4. ML anomaly (Bharat's schema) -> OCSF event linking,
5. end-to-end INC-*.json with the fields the Wiki / analytics scripts read.

Fixtures in tests/fixtures/integration are SYNTHETIC (see make_fixtures.py there).
"""

import importlib.util
import json
from pathlib import Path

import pandas as pd
import pytest

from incident_enrichment.pipeline import EnrichmentConfig, enrich_process_finding, enrich_sigma_group
from incident_enrichment.normalize import build_records_frame
from incident_enrichment.process import finding_from_anomaly, load_clickhouse_rows, normalize_ocsf_process_events
from incident_enrichment.sigma import (
    alert_from_ocsf_row,
    dedupe_correlation_rows,
    finding_from_correlation,
    group_finding,
    in_group_window,
    merge_findings,
)

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "integration"
CORR = load_clickhouse_rows(FIX / "correlations.json")
SSH = load_clickhouse_rows(FIX / "ocsf_events.json")
ANOM = load_clickhouse_rows(FIX / "ml_anomalies.json")
PROC = load_clickhouse_rows(FIX / "process_events.json")
CONFIG = EnrichmentConfig()
SIX = ["admin", "oracle", "postgres", "root", "test", "ubuntu"]


def sigma_groups():
    latest, _ = dedupe_correlation_rows(CORR)
    return merge_findings([finding_from_correlation(r) for r in latest], gap=CONFIG.merge_gap)


def enrich_group(members):
    gf = group_finding(members)
    rows = [r for r in SSH if in_group_window(r, gf, CONFIG.context_pad, CONFIG.recovery_after)]
    return enrich_sigma_group(members, build_records_frame([alert_from_ocsf_row(r)[0] for r in rows], []), CONFIG)


@pytest.fixture(scope="module")
def bridge_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("bridge")
    spec = importlib.util.spec_from_file_location("bridge", ROOT / "integrations" / "integrate_clickhouse_enrichment.py")
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    rc = bridge.main(["--from-files", "--out", str(out),
                      "--correlations", str(FIX / "correlations.json"), "--sigma-events", str(FIX / "ocsf_events.json"),
                      "--anomalies", str(FIX / "ml_anomalies.json"), "--process-events", str(FIX / "process_events.json")])
    assert rc == 0
    incidents = [json.loads(p.read_text()) for p in sorted(out.glob("INC-*.json"))]
    return json.loads((out / "run_report.json").read_text()), incidents


# --------------------------------------------------------------------------- 1. snapshots

def test_latest_snapshot_is_selected_regardless_of_order():
    latest, dropped = dedupe_correlation_rows(CORR)
    assert dropped == 6                      # 10 rows -> 2 findings x 2 tenants
    got = {(r["tenant_uid"], r["finding_uid"]): r["snapshot_version"] for r in latest}
    assert got == {("tenant-a", "corr-spray-7f3a"): 3, ("tenant-a", "corr-brute-7f3a"): 2,
                   ("tenant-b", "corr-spray-7f3a"): 3, ("tenant-b", "corr-brute-7f3a"): 2}
    for r in latest:
        assert len(r["contributing_finding_uids"]) == 6   # cumulative evidence kept


def test_rows_without_snapshot_version_still_work():
    rows = [{**r, "snapshot_version": None} for r in CORR if r["tenant_uid"] == "tenant-a"
            and r["finding_uid"] == "corr-spray-7f3a"]
    latest, _ = dedupe_correlation_rows(rows)
    assert len(latest) == 1                 # older tables: last row wins, no crash


# --------------------------------------------------------------------------- 2. six usernames

def test_six_username_scenario_is_one_complete_incident():
    groups = [g for g in sigma_groups() if g[0]["tenant_uid"] == "tenant-a"]
    assert len(groups) == 1 and len(groups[0]) == 2          # spraying + brute force merged
    res = enrich_group(groups[0])
    obj = res.incident_object
    assert obj["entities"]["users"] == SIX
    assert len(obj["timeline"]) == 6 and obj["outcome"]["failed_password_attempts"] == 6
    assert len(set(obj["evidence"]["event_uids"])) == 6      # nothing duplicated
    assert obj["evidence"]["engine_linked_events"] == 6 and obj["evidence"]["recovered_events"] == 0
    assert {r["verdict"] for r in obj["integrity"]["findings"]} == {"confirmed"}
    assert {m["snapshot_version"] for m in obj["finding"]["merged_from"]} == {2, 3}
    assert obj["finding"]["target_user"] is None              # spraying: no single target


def test_incident_id_is_stable_across_snapshots():
    """Rerunning on an older snapshot set gives the same incident id (the file is updated, not duplicated)."""
    full = enrich_group([g for g in sigma_groups() if g[0]["tenant_uid"] == "tenant-a"][0])
    early_rows = [r for r in CORR if r["tenant_uid"] == "tenant-a" and r["snapshot_version"] == 1]
    early = merge_findings([finding_from_correlation(r) for r in early_rows])
    assert len(early) == 1
    assert enrich_group(early[0]).incident_object["incident_id"] == full.incident_object["incident_id"]


# --------------------------------------------------------------------------- 3. tenants

def test_same_attack_in_two_tenants_gives_two_incidents():
    groups = sigma_groups()
    assert len(groups) == 2
    objs = [enrich_group(g).incident_object for g in groups]
    assert {o["tenant_uid"] for o in objs} == {"tenant-a", "tenant-b"}
    assert objs[0]["incident_id"] != objs[1]["incident_id"]   # same finding_uid, different tenant
    for o in objs:
        assert all(u.startswith(o["tenant_uid"] + "-") for t in o["timeline"] for u in t["ocsf_uids"])


def test_findings_from_two_tenants_are_never_merged():
    findings = [finding_from_correlation(r) for r in dedupe_correlation_rows(CORR)[0]]
    for g in merge_findings(findings):
        assert len({f["tenant_uid"] for f in g}) == 1
    with pytest.raises(ValueError):
        enrich_sigma_group([f for f in findings if f["finding_id"] == "corr-brute-7f3a"],
                           build_records_frame([], []), CONFIG)


def test_other_tenant_events_are_dropped_even_if_passed_in():
    group = [g for g in sigma_groups() if g[0]["tenant_uid"] == "tenant-a"][0]
    all_rows = [alert_from_ocsf_row(r)[0] for r in SSH]           # both tenants, deliberately
    res = enrich_sigma_group(group, build_records_frame(all_rows, []), CONFIG)
    assert len(res.incident) == 6
    assert all(u.startswith("tenant-a-") for t in res.incident_object["timeline"] for u in t["ocsf_uids"])


# --------------------------------------------------------------------------- 4. ML anomalies

def test_bharat_schema_is_read():
    f = finding_from_anomaly(ANOM[0])
    assert f["anomaly_uid"] == "anom-tenant-a-01" and f["tenant_uid"] == "tenant-a"
    assert f["min_anomaly_score"] == -0.067 and f["mean_anomaly_score"] == -0.041
    assert f["occurrence_count"] == 3
    assert str(f["first_seen"]) == "2026-10-27 11:00:00+00:00" and str(f["last_seen"]) == "2026-10-27 11:02:00+00:00"
    assert len(f["contributing_finding_uids"]) == 3


def test_anomaly_links_to_its_ocsf_events_within_its_tenant():
    events = normalize_ocsf_process_events(PROC)                   # both tenants
    res = enrich_process_finding(finding_from_anomaly(ANOM[0]), events, CONFIG)
    obj = res.incident_object
    assert obj["outcome"]["events_found"] == 3 and obj["outcome"]["events_missing"] == 0
    assert obj["outcome"]["lineage"] == "cmd.exe -> powershell.exe"     # filled from the events
    assert obj["finding"]["target_host"] == "ws-07" and obj["finding"]["target_user"] == "j.doe"
    assert obj["outcome"]["sample_command"].startswith("powershell -nop -enc")
    assert {e["event_code"] for e in obj["timeline"]} == {"4688", "1"}
    assert obj["context_events"] == []           # tenant-b's certutil on "ws-07" is not tenant-a's
    assert "T1059.001" in [t["technique"] for t in obj["techniques"]]


def test_anomaly_with_no_events_is_reported_not_crashed():
    res = enrich_process_finding(finding_from_anomaly(ANOM[0]), normalize_ocsf_process_events([]), CONFIG)
    assert res.incident_object["outcome"]["events_missing"] == 3


# --------------------------------------------------------------------------- 5. end to end

WIKI_PATHS = ["incident_id", "incident_type", "tenant_uid", "finding.title", "finding.source_ip",
              "finding.target_host", "finding.target_user", "entities.source_ips", "entities.users",
              "entities.hosts", "techniques", "timeline", "sessions"]
ML_PATHS = ["outcome.lineage", "outcome.occurrence_count", "outcome.min_anomaly_score"]


def _has(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return False
        obj = obj[part]
    return True


def test_end_to_end_run(bridge_run):
    report, incidents = bridge_run
    assert report["errors"] == []
    assert report["sigma"]["incidents_written"] == 2 and report["process"]["incidents_written"] == 2
    assert sorted(i["incident_type"] for i in incidents) == ["process_execution"] * 2 + ["ssh_authentication"] * 2
    assert len({i["incident_id"] for i in incidents}) == 4


def test_incidents_have_the_fields_the_wiki_reads(bridge_run):
    _, incidents = bridge_run
    for inc in incidents:
        missing = [p for p in WIKI_PATHS if not _has(inc, p)]
        if inc["incident_type"] == "process_execution":
            missing += [p for p in ML_PATHS if not _has(inc, p)]
        assert not missing, (inc["incident_id"], missing)
        assert inc["incident_id"].startswith("INC-") and len(inc["incident_id"]) == 12
        assert isinstance(inc["timeline"], list) and isinstance(inc["sessions"], list)
        for key in ("source_ips", "users", "hosts"):
            assert isinstance(inc["entities"][key], list)
        for t in inc["techniques"]:
            assert {"technique", "name", "status"} <= set(t)
        json.dumps(inc)                                     # serialisable as written
