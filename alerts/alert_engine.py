"""Compatibility file logger. The dashboard persists alerts in SQLite."""

from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = ROOT / "alerts" / "alerts.log"


def send_alert(message, source="SYSTEM"):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    alert = f"[{timestamp}] [{source}] {message}"
    print(alert)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(alert + "\n")
