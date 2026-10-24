"""Compatibility wrapper. Prefer: python -m ml.preprocessing.prepare"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.preprocessing.prepare import prepare_dataset

if __name__ == "__main__":
    print(json.dumps(prepare_dataset(), indent=2, default=str))
