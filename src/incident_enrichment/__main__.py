"""Command line.

SSH / authentication findings (Wazuh logs):
    python -m incident_enrichment --alerts alerts.json --archives archives.json --out output

Process anomalies (ClickHouse exports of wazuh_ml_anomalies + wazuh_ocsf_events):
    python -m incident_enrichment --anomalies anomalies.json --process-events ocsf_events.json --out output
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless: write PNGs, no windows

import matplotlib.pyplot as plt  # noqa: E402


def _run_ssh(args, config, out: Path) -> int:
    from .finding import load_finding
    from .pipeline import enrich_files, save_incident

    finding = load_finding(args.finding) if args.finding else None
    results = enrich_files(args.alerts, args.archives, finding=finding, config=config)
    if not results:
        print("No findings met the threshold; nothing to enrich.")
        return 0
    for res in results:
        obj = res.incident_object
        inc_id = obj["incident_id"]
        save_incident(obj, out / f"{inc_id}.json")
        print(f"{inc_id}  ({res.finding['finding_id']}, {res.finding.get('finding_source')})")
        print(f"  events: {len(res.incident)}  raw records: {obj['evidence']['raw_record_count']}  "
              f"sessions: {res.outcome['sessions']}  failed attempts: {res.outcome['failed_password_attempts']}  "
              f"successful logins: {res.outcome['successful_logins']}")
        print(f"  {obj['evidence_summary']}")
        if not args.no_plots:
            from .viz import plot_activity_heatmap, plot_impact_scope, plot_incident_graph
            plot_incident_graph(res.graph, res.incident, res.sessions, res.finding, res.techniques,
                                save_path=out / f"{inc_id}_graph.png")
            plot_activity_heatmap(res.incident, save_path=out / f"{inc_id}_heatmap.png")
            plot_impact_scope(res.incident, res.outcome, obj["entities"], save_path=out / f"{inc_id}_impact.png")
            plt.close("all")
    print(f"written to {out}/")
    return 0


def _run_process(args, config, out: Path) -> int:
    from .pipeline import enrich_process_files, save_incident

    results = enrich_process_files(args.anomalies, args.process_events, config=config)
    if not results:
        print("No anomalies in the file; nothing to enrich.")
        return 0
    for res in results:
        obj = res.incident_object
        inc_id = obj["incident_id"]
        save_incident(obj, out / f"{inc_id}.json")
        print(f"{inc_id}  ({res.finding['finding_id']})")
        print(f"  {obj['evidence_summary']}")
        if not args.no_plots:
            from .viz import plot_process_graph, plot_process_impact, plot_process_timeline
            plot_process_graph(res.graph, res.finding, res.outcome, save_path=out / f"{inc_id}_graph.png")
            plot_process_timeline(res.incident, res.finding, res.outcome, save_path=out / f"{inc_id}_timeline.png")
            plot_process_impact(res.outcome, obj["entities"], res.techniques, save_path=out / f"{inc_id}_impact.png")
            plt.close("all")
    print(f"written to {out}/")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="incident_enrichment",
        description="Enrich correlated findings into structured incidents.",
    )
    ssh = p.add_argument_group("SSH / authentication findings")
    ssh.add_argument("--alerts", help="path to Wazuh alerts.json (JSON lines)")
    ssh.add_argument("--archives", help="path to Wazuh archives.json (JSON lines)")
    ssh.add_argument("--finding", help="optional finding JSON; if omitted, findings are simulated "
                                       "with a Sigma-style threshold rule")
    ssh.add_argument("--context-minutes", type=float, default=1.0,
                     help="context padding around the finding window, in minutes (default 1)")
    proc = p.add_argument_group("process anomalies")
    proc.add_argument("--anomalies", help="ClickHouse export of wazuh_ml_anomalies")
    proc.add_argument("--process-events", help="ClickHouse export of wazuh_ocsf_events (process creation)")
    proc.add_argument("--process-context-minutes", type=float, default=10.0,
                      help="window padding for related process events, in minutes (default 10)")
    p.add_argument("--out", default="output", help="output directory (default: output)")
    p.add_argument("--no-plots", action="store_true", help="skip PNG figures")
    args = p.parse_args(argv)

    import pandas as pd

    from .pipeline import EnrichmentConfig

    config = EnrichmentConfig(context_pad=pd.Timedelta(minutes=args.context_minutes),
                              process_context_pad=pd.Timedelta(minutes=args.process_context_minutes))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    ssh_mode = bool(args.alerts or args.archives)
    process_mode = bool(args.anomalies or args.process_events)
    if ssh_mode == process_mode:
        p.error("give either --alerts and --archives, or --anomalies and --process-events")
    if ssh_mode:
        if not (args.alerts and args.archives):
            p.error("--alerts and --archives are both required")
        return _run_ssh(args, config, out)
    if not (args.anomalies and args.process_events):
        p.error("--anomalies and --process-events are both required")
    return _run_process(args, config, out)


if __name__ == "__main__":
    raise SystemExit(main())
