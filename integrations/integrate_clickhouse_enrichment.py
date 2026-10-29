"""ClickHouse -> Incident Enrichment Layer bridge.

Reads Sigma correlations and Isolation Forest process anomalies from ClickHouse,
pulls the OCSF events behind them, and writes enriched incidents (JSON + figures)
plus a ``run_report.json`` describing what was read, merged, skipped or failed.

    pip install -e ".[clickhouse]"
    export CLICKHOUSE_HOST=127.0.0.1 CLICKHOUSE_PORT=8123 CLICKHOUSE_USER=lm_admin
    export CLICKHOUSE_PASSWORD=...            # never hard-code it
    python integrations/integrate_clickhouse_enrichment.py --out output_clickhouse \
        --rules-dir ../Logmanthan-pipeline/sigma-engine/rules

Offline (no ClickHouse), from exported files:
    python integrations/integrate_clickhouse_enrichment.py --from-files \
        --anomalies data/sample/process/ml_anomalies.json \
        --process-events data/sample/process/ocsf_process_events.json
    python integrations/integrate_clickhouse_enrichment.py --from-files \
        --correlations tests/fixtures/sigma/correlations.json \
        --sigma-events tests/fixtures/sigma/ocsf_events.json

Sigma safeguards (the engine's output is never taken at face value):
- duplicate correlation rows are dropped; rows without a finding uid are counted, not fatal;
- findings for the same attack (same source IP, compatible host, close in time) are
  merged into one incident;
- events are fetched by the engine's uids AND by source IP / host over a window that
  extends past the finding, so evidence the engine dropped is recovered;
- every finding gets an integrity verdict (rule re-checked on distinct events);
- one bad group never stops the run: its error is recorded in run_report.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from incident_enrichment.normalize import build_records_frame  # noqa: E402
from incident_enrichment.pipeline import (  # noqa: E402
    EmptyGroup,
    EnrichmentConfig,
    enrich_process_finding,
    enrich_sigma_group,
    save_incident,
)
from incident_enrichment.process import (  # noqa: E402
    finding_from_anomaly,
    load_clickhouse_rows,
    normalize_ocsf_process_events,
)
from incident_enrichment.sigma import (  # noqa: E402
    MalformedFinding,
    RuleCatalog,
    alert_from_ocsf_row,
    dedupe_correlation_rows,
    finding_from_correlation,
    group_finding,
    in_group_window,
    merge_findings,
)
from incident_enrichment.viz import (  # noqa: E402
    plot_activity_heatmap,
    plot_impact_scope,
    plot_incident_graph,
    plot_process_graph,
    plot_process_impact,
    plot_process_timeline,
)

EVENT_LIMIT = 5000          # max window events fetched per Sigma group / process anomaly
CORRELATION_LIMIT = 10000   # max correlation rows read per run


def new_report() -> dict:
    return {
        "sigma": {
            "correlation_rows_read": 0,
            "duplicate_rows_dropped": 0,          # older snapshots of a finding + repeated rows
            "malformed_rows_skipped": 0,
            "findings": 0,
            "groups": 0,
            "incidents_written": 0,
            "groups_failed": 0,
            "event_rows_read": 0,
            "event_rows_synthesized": 0,
            "groups_window_truncated": [],
            "verdicts": {},
            "rule_catalogue": [],
            "rule_catalogue_warnings": [],
        },
        "process": {"anomalies_read": 0, "incidents_written": 0, "failed": 0},
        "errors": [],
    }


# --------------------------------------------------------------------------- ClickHouse

def get_client():
    import clickhouse_connect

    password = os.environ.get("CLICKHOUSE_PASSWORD")
    if not password:
        sys.exit("Set CLICKHOUSE_PASSWORD (and CLICKHOUSE_USER / HOST / PORT if not default).")
    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST", "127.0.0.1"),
        port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
        username=os.environ.get("CLICKHOUSE_USER", "lm_admin"),
        password=password,
        database=os.environ.get("CLICKHOUSE_DATABASE", "default"),
    )


def rows(client, sql: str, **params) -> list[dict]:
    """Parameterised query (values are sent separately, never pasted into the SQL)."""
    return list(client.query(sql, parameters=params).named_results())


def _ms(t: pd.Timestamp) -> int:
    return int(t.timestamp() * 1000)


def _tenant_sql(tenant) -> tuple[str, dict]:
    """``AND tenant_uid = ...`` when the tenant is known; nothing otherwise."""
    if tenant:
        return " AND tenant_uid = {tenant:String}", {"tenant": str(tenant)}
    return "", {}


def _by_uids(client, uids: list[str], tenant) -> dict[str, dict]:
    """OCSF events by finding_uid, in chunks; never truncated."""
    t_sql, t_par = _tenant_sql(tenant)
    out: dict[str, dict] = {}
    for i in range(0, len(uids), 1000):
        for r in rows(client, f"""
            SELECT * FROM default.wazuh_ocsf_events
            WHERE finding_uid IN {{uids:Array(String)}}{t_sql}
        """, uids=uids[i:i + 1000], **t_par):
            out.setdefault(str(r.get("finding_uid")), r)
    return out


# --------------------------------------------------------------------------- process anomalies

def fetch_process_events(client, finding: dict, config: EnrichmentConfig) -> pd.DataFrame:
    """The events the model listed, plus other process activity on the same host
    within the context window (so the layer can show what else ran)."""
    pad = config.process_context_pad
    tenant = finding.get("tenant_uid")
    found = _by_uids(client, list(finding["contributing_finding_uids"]), tenant)
    host, first, last = finding.get("target_host"), finding.get("first_seen"), finding.get("last_seen")
    if not host or first is None:
        # the anomaly row may not carry host/time: take them from its listed events
        linked = normalize_ocsf_process_events(list(found.values()))
        if len(linked):
            host = host or (linked["host"].dropna().mode().iloc[0] if linked["host"].notna().any() else None)
            if first is None and linked["event_time"].notna().any():
                first, last = linked["event_time"].min(), linked["event_time"].max()
    if host and first is not None:
        t_sql, t_par = _tenant_sql(tenant)
        for r in rows(client, f"""
            SELECT * FROM default.wazuh_ocsf_events
            WHERE device_hostname = {{host:String}} AND time BETWEEN {{t0:Int64}} AND {{t1:Int64}}{t_sql}
            ORDER BY time
            LIMIT {int(EVENT_LIMIT)}
        """, host=host, t0=_ms(first - pad), t1=_ms(last + pad), **t_par):
            found.setdefault(str(r.get("finding_uid")), r)
    return normalize_ocsf_process_events(list(found.values()))


def enrich_anomalies(anomaly_rows: list[dict], events_for, out: Path,
                     config: EnrichmentConfig, report: dict) -> None:
    report["process"]["anomalies_read"] += len(anomaly_rows)
    for row in anomaly_rows:
        ref = (row.get("anomaly_uid") or row.get("anomaly_id") or row.get("id") or "?") if isinstance(row, dict) else "?"
        try:
            finding = finding_from_anomaly(row)
            res = enrich_process_finding(finding, events_for(finding), config)
            obj = res.incident_object
            inc_id = obj["incident_id"]
            save_incident(obj, out / f"{inc_id}.json")
            plot_process_graph(res.graph, res.finding, res.outcome, save_path=out / f"{inc_id}_graph.png")
            plot_process_timeline(res.incident, res.finding, res.outcome, save_path=out / f"{inc_id}_timeline.png")
            plot_process_impact(res.outcome, obj["entities"], res.techniques, save_path=out / f"{inc_id}_impact.png")
            report["process"]["incidents_written"] += 1
            print(f"[+] {inc_id}  {res.outcome['lineage']}  "
                  f"events {res.outcome['events_found']}/{res.outcome['events_listed_by_model']}")
        except Exception as exc:  # one bad anomaly must not stop the run
            report["process"]["failed"] += 1
            report["errors"].append({"kind": "process", "ref": str(ref), "error": repr(exc),
                                     "trace": traceback.format_exc(limit=3)})
            print(f"[!] anomaly {ref}: {exc!r}")
        finally:
            plt.close("all")


# --------------------------------------------------------------------------- Sigma correlations

def fetch_correlations(client, hours: int, tenant=None, final: bool = True) -> list[dict]:
    """Correlations of the last ``hours``. With ``final`` (ReplacingMergeTree on the
    reliability branch), ClickHouse returns the latest snapshot per finding; the layer
    also keeps only the highest snapshot_version itself, so older tables work too."""
    since = _ms(pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=hours))
    t_sql, t_par = _tenant_sql(tenant)
    return rows(client, f"""
        SELECT * FROM default.wazuh_correlations{" FINAL" if final else ""}
        WHERE time >= {{since:Int64}}{t_sql}
        ORDER BY time
        LIMIT {int(CORRELATION_LIMIT)}
    """, since=since, **t_par)


def fetch_group_events(client, finding: dict, config: EnrichmentConfig) -> tuple[list[dict], bool]:
    """All events the engine listed (never truncated), plus events from the same source
    IP or host in [first_seen - context_pad, last_seen + recovery_after] (capped at
    EVENT_LIMIT). Returns (rows, window_truncated)."""
    tenant = finding.get("tenant_uid")
    out = _by_uids(client, list(finding.get("contributing_finding_uids") or []), tenant)
    t_sql, t_par = _tenant_sql(tenant)

    truncated = False
    ip, hosts = finding.get("source_ip") or "", list(finding.get("hosts") or [])
    if finding.get("first_seen") is not None and (ip or hosts):
        t0 = _ms(finding["first_seen"] - config.context_pad)
        t1 = _ms(finding["last_seen"] + max(config.context_pad, config.recovery_after))
        window = rows(client, f"""
            SELECT * FROM default.wazuh_ocsf_events
            WHERE time BETWEEN {{t0:Int64}} AND {{t1:Int64}}
              AND ((src_ip = {{ip:String}} AND {{ip:String}} != '') OR has({{hosts:Array(String)}}, device_hostname)){t_sql}
            ORDER BY time
            LIMIT {int(EVENT_LIMIT) + 1}
        """, t0=t0, t1=t1, ip=ip, hosts=hosts, **t_par)
        truncated = len(window) > EVENT_LIMIT
        for r in window[:EVENT_LIMIT]:
            out.setdefault(str(r.get("finding_uid")), r)
    return list(out.values()), truncated


def file_group_events(all_rows: list[dict], finding: dict, config: EnrichmentConfig) -> tuple[list[dict], bool]:
    """Offline equivalent of ``fetch_group_events`` over an exported events file."""
    after = max(config.context_pad, config.recovery_after)
    return [r for r in all_rows if in_group_window(r, finding, config.context_pad, after)], False


def build_findings(corr_rows: list[dict], catalog: RuleCatalog, report: dict) -> list[dict]:
    rep = report["sigma"]
    rep["correlation_rows_read"] += len(corr_rows)
    unique, dups = dedupe_correlation_rows([r for r in corr_rows if isinstance(r, dict)])
    rep["duplicate_rows_dropped"] += dups
    rep["malformed_rows_skipped"] += len(corr_rows) - len(unique) - dups
    findings = []
    for r in unique:
        try:
            findings.append(finding_from_correlation(r, catalog))
        except Exception as exc:  # MalformedFinding, or anything unexpected in one row
            rep["malformed_rows_skipped"] += 1
            msg = str(exc) if isinstance(exc, MalformedFinding) else repr(exc)
            report["errors"].append({"kind": "sigma_row", "ref": str(r.get("finding_uid") or r.get("rule_id") or "?"),
                                     "error": msg})
    rep["findings"] += len(findings)
    return findings


def enrich_sigma(corr_rows: list[dict], events_for, out: Path, config: EnrichmentConfig,
                 report: dict) -> list[dict]:
    """Run the whole Sigma path. ``events_for(group_finding) -> (ocsf_rows, truncated)``.
    Returns the incident objects written."""
    catalog = config.rules or RuleCatalog.builtin()
    rep = report["sigma"]
    rep["rule_catalogue"] = [s.title for s in catalog.specs]
    rep["rule_catalogue_warnings"] = list(catalog.warnings)

    groups = merge_findings(build_findings(corr_rows, catalog, report), gap=config.merge_gap)
    rep["groups"] += len(groups)
    written = []
    for members in groups:
        ref = ", ".join(m["finding_id"] for m in members)
        try:
            gf = group_finding(members)
            ocsf_rows, truncated = events_for(gf)
            ocsf_rows = [r for r in ocsf_rows if isinstance(r, dict)]
            alerts = []
            for r in ocsf_rows:
                alert, synthesized = alert_from_ocsf_row(r)
                rep["event_rows_synthesized"] += int(synthesized)
                alerts.append(alert)
            rep["event_rows_read"] += len(ocsf_rows)
            records = build_records_frame(alerts, [])

            res = enrich_sigma_group(members, records, config)
            obj = res.incident_object
            if truncated:
                rep["groups_window_truncated"].append(obj["incident_id"])
                obj["evidence"]["window_truncated"] = True
                obj["evidence_summary"] += (f" Window query hit the {EVENT_LIMIT}-event limit; "
                                            "recovered evidence may be incomplete.")
            inc_id = obj["incident_id"]
            save_incident(obj, out / f"{inc_id}.json")
            plot_incident_graph(res.graph, res.incident, res.sessions, res.finding, res.techniques,
                                save_path=out / f"{inc_id}_graph.png")
            plot_activity_heatmap(res.incident, save_path=out / f"{inc_id}_heatmap.png")
            plot_impact_scope(res.incident, res.outcome, obj["entities"], save_path=out / f"{inc_id}_impact.png")
            verdict = obj["integrity"]["verdict"]
            rep["verdicts"][verdict] = rep["verdicts"].get(verdict, 0) + 1
            rep["incidents_written"] += 1
            written.append(obj)
            print(f"[+] {inc_id}  {obj['finding']['title']}  events {len(res.incident)}  verdict {verdict}")
        except EmptyGroup as exc:
            rep["groups_failed"] += 1
            report["errors"].append({"kind": "sigma_group", "ref": ref, "error": str(exc)})
            print(f"[-] {ref}: {exc}")
        except Exception as exc:  # one bad group must not stop the run
            rep["groups_failed"] += 1
            report["errors"].append({"kind": "sigma_group", "ref": ref, "error": repr(exc),
                                     "trace": traceback.format_exc(limit=3)})
            print(f"[!] {ref}: {exc!r}")
        finally:
            plt.close("all")
    return written


# --------------------------------------------------------------------------- main

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    env = os.environ.get
    p.add_argument("--out", default=env("ENRICH_OUT_DIR", "output_clickhouse"),
                   help="output folder (env ENRICH_OUT_DIR)")
    p.add_argument("--hours", type=int, default=int(env("ENRICH_LOOKBACK_HOURS", "24")),
                   help="look back N hours for correlations and anomalies (env ENRICH_LOOKBACK_HOURS)")
    p.add_argument("--rules-dir", default=env("ENRICH_RULES_DIR"),
                   help="sigma-engine/rules directory; default: built-in SSH rules (env ENRICH_RULES_DIR)")
    p.add_argument("--tenant", default=env("ENRICH_TENANT_UID"),
                   help="only this tenant; default: all tenants, each isolated (env ENRICH_TENANT_UID)")
    p.add_argument("--no-final", action="store_true",
                   default=env("ENRICH_CORRELATIONS_FINAL", "1").strip().lower() in ("0", "false", "no"),
                   help="read wazuh_correlations without FINAL (tables before the snapshot schema; "
                        "env ENRICH_CORRELATIONS_FINAL=0)")
    p.add_argument("--skip-sigma", action="store_true")
    p.add_argument("--skip-process", action="store_true")
    p.add_argument("--from-files", action="store_true", help="read exported files instead of ClickHouse")
    p.add_argument("--anomalies", help="(--from-files) export of wazuh_ml_anomalies")
    p.add_argument("--process-events", help="(--from-files) export of wazuh_ocsf_events (process)")
    p.add_argument("--correlations", help="(--from-files) export of wazuh_correlations")
    p.add_argument("--sigma-events", help="(--from-files) export of wazuh_ocsf_events (authentication)")
    args = p.parse_args(argv)

    catalog = RuleCatalog.from_dir(args.rules_dir) if args.rules_dir else RuleCatalog.builtin()
    config = EnrichmentConfig(rules=catalog)
    report = new_report()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.from_files:
        do_process = bool(args.anomalies or args.process_events)
        do_sigma = bool(args.correlations or args.sigma_events)
        if not (do_process or do_sigma):
            p.error("--from-files needs --anomalies/--process-events and/or --correlations/--sigma-events")
        if do_process and not (args.anomalies and args.process_events):
            p.error("process mode needs both --anomalies and --process-events")
        if do_sigma and not (args.correlations and args.sigma_events):
            p.error("Sigma mode needs both --correlations and --sigma-events")
        def tenant_rows(rs):
            return [r for r in rs if not args.tenant or (isinstance(r, dict) and str(r.get("tenant_uid")) == args.tenant)]
        if do_sigma and not args.skip_sigma:
            ev_rows = tenant_rows(load_clickhouse_rows(args.sigma_events))
            enrich_sigma(tenant_rows(load_clickhouse_rows(args.correlations)),
                         lambda f: file_group_events(ev_rows, f, config), out, config, report)
        if do_process and not args.skip_process:
            events = normalize_ocsf_process_events(tenant_rows(load_clickhouse_rows(args.process_events)))
            enrich_anomalies(tenant_rows(load_clickhouse_rows(args.anomalies)), lambda f: events, out, config, report)
    else:
        client = get_client()
        if not args.skip_sigma:
            enrich_sigma(fetch_correlations(client, args.hours, args.tenant, final=not args.no_final),
                         lambda f: fetch_group_events(client, f, config), out, config, report)
        if not args.skip_process:
            t_sql, t_par = _tenant_sql(args.tenant)
            anomalies = rows(client, f"""
                SELECT * FROM default.wazuh_ml_anomalies FINAL
                WHERE ingested_at > now() - INTERVAL {int(args.hours)} HOUR{t_sql}
            """, **t_par)
            enrich_anomalies(anomalies, lambda f: fetch_process_events(client, f, config), out, config, report)

    with open(out / "run_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    s = report["sigma"]
    print(f"[done] {s['incidents_written']} Sigma incident(s) from {s['findings']} finding(s) "
          f"({s['duplicate_rows_dropped']} duplicate / {s['malformed_rows_skipped']} malformed rows), "
          f"{report['process']['incidents_written']} process incident(s), "
          f"{len(report['errors'])} error(s). Report: {(out / 'run_report.json').resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
