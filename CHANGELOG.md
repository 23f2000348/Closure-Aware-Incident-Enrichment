# Changelog

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
