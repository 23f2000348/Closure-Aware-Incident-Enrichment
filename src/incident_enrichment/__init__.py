"""Incident Enrichment Layer.

Takes a correlated finding (e.g. from the Sigma engine) plus Wazuh alert/archive
records, and produces a structured incident: canonical events, timeline, SSH
sessions and outcome, MITRE techniques with evidence status, and an incident graph.

Author: Shambhavi Shekhar
"""

from .pipeline import EnrichmentConfig, EnrichmentResult, enrich_files, enrich_finding, save_incident

__version__ = "0.1.0"
__all__ = ["EnrichmentConfig", "EnrichmentResult", "enrich_files", "enrich_finding", "save_incident"]
