"""Load Wazuh JSON-lines files (alerts.json / archives.json)."""

from __future__ import annotations

import json
from pathlib import Path


def load_jsonl(path: str | Path) -> list[dict]:
    """Read a JSON-lines file, skipping blank lines."""
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: line {line_no} is not valid JSON") from exc
    return events


def load_wazuh_files(alerts_path: str | Path, archives_path: str | Path) -> tuple[list[dict], list[dict]]:
    """Return (alerts, archives) as lists of raw Wazuh events."""
    return load_jsonl(alerts_path), load_jsonl(archives_path)
