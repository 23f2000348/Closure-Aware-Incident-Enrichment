"""Incident Enrichment Layer.

Takes a correlated finding (e.g. from the Sigma engine) plus Wazuh alert/archive
records, and produces a structured incident: canonical events, timeline, SSH
sessions and outcome, MITRE techniques with evidence status, and an incident graph.
Process anomalies (Isolation Forest + OCSF process events) have their own path: process.py.
Sigma correlations from ClickHouse get engine-independent safeguards: sigma.py.

Author: Shambhavi Shekhar
"""

from .pipeline import (
    EnrichmentConfig,
    EnrichmentResult,
    ProcessEnrichmentResult,
    enrich_files,
    enrich_finding,
    enrich_process_files,
    enrich_process_finding,
    enrich_sigma_group,
    save_incident,
)
from .sigma import RuleCatalog, finding_from_correlation, merge_findings

__version__ = "0.4.0"
__all__ = ["EnrichmentConfig", "EnrichmentResult", "ProcessEnrichmentResult", "enrich_files",
           "enrich_finding", "enrich_process_files", "enrich_process_finding", "enrich_sigma_group",
           "save_incident", "RuleCatalog", "finding_from_correlation", "merge_findings"]
