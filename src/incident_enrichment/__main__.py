"""Command line: python -m incident_enrichment --alerts ... --archives ... --out ..."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless: write PNGs, no windows

from .finding import load_finding
from .pipeline import EnrichmentConfig, enrich_files, save_incident


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="incident_enrichment",
        description="Enrich correlated findings from Wazuh logs into structured incidents.",
    )
    p.add_argument("--alerts", required=True, help="path to Wazuh alerts.json (JSON lines)")
    p.add_argument("--archives", required=True, help="path to Wazuh archives.json (JSON lines)")
    p.add_argument("--finding", help="optional finding JSON; if omitted, findings are simulated "
                                     "with a Sigma-style threshold rule")
    p.add_argument("--out", default="output", help="output directory (default: output)")
    p.add_argument("--no-plots", action="store_true", help="skip PNG figures")
    p.add_argument("--context-minutes", type=float, default=1.0,
                   help="context padding around the finding window, in minutes (default 1)")
    args = p.parse_args(argv)

    import pandas as pd

    config = EnrichmentConfig(context_pad=pd.Timedelta(minutes=args.context_minutes))
    finding = load_finding(args.finding) if args.finding else None
    results = enrich_files(args.alerts, args.archives, finding=finding, config=config)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
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
            plot_impact_scope(res.incident, res.outcome, obj["entities"],
                              save_path=out / f"{inc_id}_impact.png")
        print(f"  written to {out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
