import json
import os
from datetime import datetime

HISTORY_DIR = os.path.join(os.path.dirname(__file__), "..", "scan_history")


def _ensure_dir():
    os.makedirs(HISTORY_DIR, exist_ok=True)


def save_scan(report):
    _ensure_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = report.target.replace(":", "_").replace("/", "_")
    filename = f"{timestamp}_{safe_target}.json"
    path = os.path.normpath(os.path.join(HISTORY_DIR, filename))
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2)
    return path


def list_scans():
    _ensure_dir()
    entries = []
    for name in os.listdir(HISTORY_DIR):
        if not name.endswith(".json"):
            continue
        path = os.path.join(HISTORY_DIR, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            entries.append((
                path,
                data.get("target", "unknown"),
                data.get("started_at", ""),
                len(data.get("findings", [])),
            ))
        except (json.JSONDecodeError, OSError):
            continue
    entries.sort(key=lambda e: e[2], reverse=True)
    return entries


def load_scan(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def summarize_findings(data):
    counts = {}
    for f in data.get("findings", []):
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
