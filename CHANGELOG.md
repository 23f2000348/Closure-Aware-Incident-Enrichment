# Changelog

## 0.4.0

- Sigma cumulative snapshots: `wazuh_correlations FINAL`, and the highest `snapshot_version` per (`tenant_uid`, `finding_uid`) is kept for offline files and older tables
- Tenant isolation: `tenant_uid` filter on every query (correlations, ML anomalies, OCSF events), no merging across tenants, other-tenant events dropped, `tenant_uid` on every incident and in its id
- Stable incident ids: a merged incident keeps the id of its earliest finding, so later snapshots and findings update the same `INC-*.json`
- ML anomalies read with the ML worker's schema (`anomaly_uid`, `first_seen_time`, `last_seen_time`, `min_score`, `mean_score`); host, user and lineage taken from the linked OCSF process events when the row does not carry them; context limited to process events
- Settings as environment variables (`.env.example`); `--tenant`, `--no-final`
- Integration tests and synthetic fixtures for the hand-off checks; `docs/sample_output/`
- Incident object schema 0.4: `tenant_uid`

## 0.3.0

- Sigma correlations from ClickHouse with engine-independent safeguards (`sigma.py`): rule catalogue read from the engine's Sigma YAML (`--rules-dir`) with built-in SSH rules; robust parsing of correlation rows; de-duplication of repeated rows; merging of findings for the same attack; evidence recovery past the finding window; engine-linked events always kept; integrity verdict per finding with a recommended action
- Bridge: correlations read by time (`--hours`) instead of a fixed count; events fetched by uid and by source IP / host window; per-group error isolation; `run_report.json`; offline `--correlations` / `--sigma-events` mode
- Strict source: an event from a different source IP never joins a Sigma incident
- OCSF rows with missing or broken `raw_data` are rebuilt from the OCSF columns; wrongly typed fields are treated as missing; empty inputs produce empty incidents instead of errors
- Summary handles several users, unknown source or host, and no events
- Incident object schema 0.3: `integrity`, `finding.merged_from`, `evidence.engine_linked_events` / `recovered_events` / `engine_uids_missing`, `timeline[].engine_linked` / `ocsf_uids`
- New dependency: PyYAML

## 0.2.0

- Process-execution path for endpoint anomalies (Isolation Forest, `wazuh_ml_anomalies` + `wazuh_ocsf_events`): linking (`direct` / `inferred` / `context`), grouping by host, user and parent → process, outcome summary (lineage, volume, score, command), MITRE candidates with their basis, process graph, timeline and scope figures
- ClickHouse export loader (`FORMAT JSON` / `JSONEachRow`, UTF-8 / UTF-16)
- CLI: `--anomalies` and `--process-events`
- `integrations/integrate_clickhouse_enrichment.py`: ClickHouse bridge for Sigma correlations and ML anomalies (parameterised queries, credentials from environment variables, offline `--from-files` mode)
- SSH sessions are now rebuilt from both `sshd-session` (OpenSSH 9.8+) and `sshd` (older OpenSSH) lines; when none can be rebuilt, the summary says so instead of reporting zero attempts
- Incident object schema 0.2: `incident_type`

## 0.1.0

First release.

- Normalisation of Wazuh `alerts.json` and `archives.json` into one record per raw line, with a unique `record_uid`, the event time read from the syslog line, and IP / user / port parsed from the log text when Wazuh's decoders did not extract them
- De-duplication of alert/archive copies by host + log line, with a stable `event_uid` and provenance per event
- Simulated Sigma-style threshold findings, or an external finding loaded from JSON (`--finding`)
- Context retrieval and relationship scoring, with `direct` / `inferred` links and SSH service context
- SSH session reconstruction, outcome (attempts, how each session ended, successful logins)
- MITRE ATT&CK techniques with evidence status (`observed` / `attempted_only`) and sub-technique → parent links
- Incident graph, activity heatmap and impact-scope figures
- Incident object (JSON, schema 0.1)
- Command-line interface (`python -m incident_enrichment`) and regression tests on the sample data
