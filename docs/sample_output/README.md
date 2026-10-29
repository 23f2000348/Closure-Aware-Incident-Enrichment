Sample output of

    python integrations/integrate_clickhouse_enrichment.py --from-files --tenant tenant-a \
        --correlations tests/fixtures/integration/correlations.json --sigma-events tests/fixtures/integration/ocsf_events.json \
        --anomalies tests/fixtures/integration/ml_anomalies.json --process-events tests/fixtures/integration/process_events.json \
        --out docs/sample_output

Inputs are SYNTHETIC (tests/fixtures/integration). One SSH incident (six-username spraying + brute force) and one ML process incident.
