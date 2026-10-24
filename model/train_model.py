"""Compatibility wrapper. New artifacts are written to ml/artifacts/, not ids_model.pkl."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.training.train import train

if __name__ == "__main__":
    print(json.dumps(train(), indent=2))
