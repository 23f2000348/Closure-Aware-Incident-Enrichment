"""Regression tests on the sample lab data (data/sample).

Expected values come from manually reading the raw logs: two SSH sessions from
192.168.1.34 against root on host 'agent', three wrong passwords each, both closed
by the client before authenticating, no successful login.
"""

from pathlib import Path

import pytest

from incident_enrichment import enrich_files

DATA = Path(__file__).resolve().parents[1] / "data" / "sample"


@pytest.fixture(scope="module")
def result():
    results = enrich_files(DATA / "alerts.json", DATA / "archives.json")
    assert len(results) == 1, "sample data should produce exactly one simulated finding"
    return results[0]


def test_record_uids_are_unique(result):
    assert result.records["record_uid"].is_unique
    # Wazuh ids are NOT unique, which is why they are not used as keys
    assert not result.records["wazuh_id"].is_unique


def test_distinct_failed_passwords_are_not_merged(result):
    # 04:03:42 and 04:03:43 share one Wazuh timestamp but are different events
    s1_failed = result.incident[
        result.incident["full_log"].fillna("").str.contains("Failed password .* port 52966", regex=True)
    ]
    assert len(s1_failed) == 3


def test_incident_event_count(result):
    assert len(result.incident) == 17
    assert result.incident_object["evidence"]["raw_record_count"] == 31


def test_event_uids_unique(result):
    uids = result.incident_object["evidence"]["event_uids"]
    assert len(uids) == len(set(uids))


def test_session_closing_lines_recovered(result):
    closed = result.incident["full_log"].fillna("").str.contains("Connection closed")
    assert closed.sum() == 2
    assert result.incident.loc[closed, "source_ip"].eq("192.168.1.34").all()


def test_events_ordered_by_log_time(result):
    times = result.incident["event_time"].tolist()
    assert times == sorted(times)


def test_sessions_and_outcome(result):
    assert [s["failed_attempts"] for s in result.sessions] == [3, 3]
    assert all(s["outcome"] == "failed_client_disconnected" for s in result.sessions)
    assert result.outcome["successful_logins"] == 0
    assert result.outcome["status"] == "no_successful_authentication_observed"
    gap = (result.sessions[1]["start"] - result.sessions[0]["end"]).total_seconds()
    assert gap == pytest.approx(149, abs=1)


def test_link_types(result):
    counts = result.incident["link_type"].value_counts().to_dict()
    assert counts == {"direct": 12, "inferred": 5}
    inferred_programs = set(result.incident.loc[result.incident["link_type"] == "inferred", "program"])
    assert inferred_programs == {"unix_chkpwd"}


def test_technique_status(result):
    status = {t["technique"]: t["status"] for t in result.techniques}
    assert status["T1110.001"] == "observed"
    assert status["T1110"] == "observed"
    assert status["T1021.004"] == "attempted_only"
    parents = {t["technique"]: t["parent"] for t in result.techniques}
    assert parents["T1110.001"] == "T1110"


def test_service_context_found(result):
    logs = [c["log"] for c in result.incident_object["service_context"]]
    assert any("Server listening on 0.0.0.0 port 22" in l for l in logs)


def test_graph_has_subtechnique_edge(result):
    assert result.graph.has_edge("t:T1110.001", "t:T1110")
