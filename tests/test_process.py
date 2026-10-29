"""Process-execution path.

data/sample/process/  : real ClickHouse exports supplied by the team (UTF-16). The OCSF
                        file holds baseline events only; none of the anomalies' linked
                        events are in it.
tests/fixtures/       : synthetic events that DO match the anomalies' linked uids, to test
                        linking, grouping and the timeline.
"""

from pathlib import Path

import pandas as pd
import pytest

from incident_enrichment import pipeline
from incident_enrichment.pipeline import enrich_finding, enrich_process_files
from incident_enrichment.process import (
    finding_from_anomaly,
    load_clickhouse_rows,
    map_process_techniques,
    proc_key,
)

ROOT = Path(__file__).resolve().parents[1]
ANOMALIES = ROOT / "data" / "sample" / "process" / "ml_anomalies.json"
SAMPLE_EVENTS = ROOT / "data" / "sample" / "process" / "ocsf_process_events.json"
LINKED_EVENTS = ROOT / "tests" / "fixtures" / "process_linked_events.json"


def by_lineage(results):
    return {r.outcome["lineage"]: r for r in results}


def test_loads_utf16_clickhouse_export():
    rows = load_clickhouse_rows(ANOMALIES)
    assert len(rows) == 2 and rows[0]["anomaly_uid"]


def test_finding_from_anomaly_fields():
    row = load_clickhouse_rows(ANOMALIES)[1]
    f = finding_from_anomaly(row)
    assert f["finding_type"] == "process_anomaly"
    assert f["target_host"] == "workstation-01" and f["target_user"] == "sec_admin"
    assert (f["parent_process"], f["process"]) == ("cmd.exe", "powershell.exe")
    assert f["occurrence_count"] == 5
    assert f["sample_command"] == "powershell -enc malicious_0"
    assert f["first_seen"] == pd.Timestamp("2026-10-12 03:00", tz="UTC")
    assert f["source_ip"] is None  # no placeholder IPs


def test_real_samples_without_linked_events():
    results = by_lineage(enrich_process_files(ANOMALIES, SAMPLE_EVENTS))
    ps = results["cmd.exe -> powershell.exe"]
    assert ps.outcome["events_listed_by_model"] == 5
    assert ps.outcome["events_found"] == 0
    assert len(ps.missing_event_uids) == 5
    assert "none were in the supplied OCSF events" in ps.incident_object["evidence_summary"]
    assert "SSH" not in ps.incident_object["evidence_summary"]
    # the graph is still built from the finding itself
    rels = {(d["rel"]) for _, _, d in ps.graph.edges(data=True)}
    assert {"executed_on", "ran", "spawned", "maps_to"} <= rels


def test_linked_events_direct_inferred_context():
    results = by_lineage(enrich_process_files(ANOMALIES, LINKED_EVENTS))
    ps = results["cmd.exe -> powershell.exe"]
    assert ps.outcome["events_found"] == 5
    assert ps.outcome["inferred_events"] == 1          # extra_ps_006: same pattern, not listed
    assert ps.missing_event_uids == []
    ctx = ps.labelled[ps.labelled["role"] == "context"]["event_uid"].tolist()
    assert "ctx_007" in ctx                            # other process on the same host
    assert "other_host_008" not in ps.labelled["event_uid"].tolist()
    assert len(ps.groups) == 1 and ps.groups[0]["events"] == 6
    times = ps.incident["event_time"].tolist()
    assert times == sorted(times)


def test_summary_spec_fields():
    ps = by_lineage(enrich_process_files(ANOMALIES, LINKED_EVENTS))["cmd.exe -> powershell.exe"]
    o = ps.outcome
    assert (o["host"], o["user"], o["lineage"]) == ("workstation-01", "sec_admin", "cmd.exe -> powershell.exe")
    assert o["occurrence_count"] == 5
    assert o["min_anomaly_score"] == pytest.approx(-0.05015414882917357)
    assert o["sample_command"] == "powershell -enc malicious_0"
    s = ps.incident_object["evidence_summary"]
    for part in ("workstation-01", "sec_admin", "cmd.exe -> powershell.exe", "5 occurrence", "-0.0502"):
        assert part in s


def test_graph_shape():
    cert = by_lineage(enrich_process_files(ANOMALIES, LINKED_EVENTS))["powershell.exe -> certutil.exe"]
    G = cert.graph
    edges = {(u, d["rel"], v) for u, v, d in G.edges(data=True)}
    assert ("user:sec_admin", "executed_on", "host:workstation-01") in edges
    assert ("host:workstation-01", "ran", "proc:workstation-01:powershell.exe") in edges
    assert ("proc:workstation-01:powershell.exe", "spawned", "proc:workstation-01:certutil.exe") in edges
    assert ("proc:workstation-01:certutil.exe", "maps_to", "t:T1105") in edges


def test_technique_mapping_basis():
    techs = {t["technique"]: t for t in map_process_techniques("powershell.exe", ["powershell -enc abc"])}
    assert techs["T1059.001"]["status"] == "candidate"
    assert techs["T1027.010"]["status"] == "supported_by_command_line"
    assert map_process_techniques("certutil.exe", []) == []          # no command line, no claim
    assert map_process_techniques("certutil.exe", ["certutil -urlcache -f http://x"])[0]["technique"] == "T1105"
    assert map_process_techniques("conhost.exe", ["conhost.exe 0xffffffff"]) == []
    assert proc_key(r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE") == "powershell.exe"


def test_ssh_entry_point_rejects_process_findings():
    f = finding_from_anomaly(load_clickhouse_rows(ANOMALIES)[0])
    with pytest.raises(ValueError, match="enrich_process_finding"):
        enrich_finding(f, pd.DataFrame(), pd.DataFrame())


def test_schema_and_type():
    r = enrich_process_files(ANOMALIES, LINKED_EVENTS)[0]
    assert r.incident_object["incident_type"] == "process_execution"
    assert r.incident_object["schema_version"] == pipeline.SCHEMA_VERSION
