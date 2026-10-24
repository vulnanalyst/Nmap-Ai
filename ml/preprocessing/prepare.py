from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from backend.app.core.paths import repo_root
from ml.preprocessing.schema import FEATURE_NAMES, LABEL_COLUMN, LABEL_MAPPING


def default_raw_path() -> Path:
    return repo_root() / "dataset" / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"


def default_prepared_path() -> Path:
    return repo_root() / "dataset" / "final_dataset.csv"


def prepare_dataset(
    raw_path: Path | None = None,
    output_path: Path | None = None,
    per_class_cap: int | None = 1000,
    binary: bool = True,
) -> dict:
    raw_path = raw_path or default_raw_path()
    output_path = output_path or default_prepared_path()
    df = pd.read_csv(raw_path, low_memory=False)
    df.columns = df.columns.str.strip()
    missing = [c for c in FEATURE_NAMES + [LABEL_COLUMN] if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")
    df = df[FEATURE_NAMES + [LABEL_COLUMN]].copy()
    df.replace([float("inf"), float("-inf")], pd.NA, inplace=True)
    df.dropna(inplace=True)
    for col in FEATURE_NAMES:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)

    original_counts = df[LABEL_COLUMN].astype(str).value_counts().to_dict()
    if binary:
        df[LABEL_COLUMN] = df[LABEL_COLUMN].apply(_binary_label)

    pieces = []
    for label, group in df.groupby(LABEL_COLUMN):
        if per_class_cap is not None and len(group) > per_class_cap:
            group = group.sample(per_class_cap, random_state=42)
        elif per_class_cap is not None and len(group) == 0:
            continue
        pieces.append(group)
    if not pieces:
        raise ValueError("No rows remained after cleaning")
    final = pd.concat(pieces).sample(frac=1, random_state=42)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    final.to_csv(output_path, index=False)
    report = {
        "raw_path": str(raw_path),
        "output_path": str(output_path),
        "rows": int(len(final)),
        "original_label_counts": original_counts,
        "prepared_label_counts": final[LABEL_COLUMN].value_counts().to_dict(),
        "features": FEATURE_NAMES,
        "label_mapping": LABEL_MAPPING,
        "notes": [
            "Infinite values were converted to NA and dropped.",
            "Sampling is skipped when a class has fewer rows than the cap.",
            "Binary mapping: BENIGN -> 0, any other CIC label -> 1 (ATTACK).",
        ],
    }
    (output_path.parent / "prepare_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report


def _binary_label(value) -> int:
    text = str(value).strip()
    if text in LABEL_MAPPING:
        return LABEL_MAPPING[text]
    if "BENIGN" in text.upper():
        return 0
    return 1


if __name__ == "__main__":
    print(json.dumps(prepare_dataset(), indent=2, default=str))
