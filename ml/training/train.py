from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from backend.app.core.paths import repo_root
from ml.preprocessing.schema import CLASS_NAMES, FEATURE_NAMES, LABEL_COLUMN


def artifacts_dir() -> Path:
    path = repo_root() / "ml" / "artifacts"
    path.mkdir(parents=True, exist_ok=True)
    return path


def train(
    dataset_path: Path | None = None,
    compare_gbdt: bool = True,
    random_state: int = 42,
) -> dict:
    dataset_path = dataset_path or (repo_root() / "dataset" / "final_dataset.csv")
    df = pd.read_csv(dataset_path)
    missing = [c for c in FEATURE_NAMES + [LABEL_COLUMN] if c not in df.columns]
    if missing:
        raise ValueError(f"Training dataset missing columns: {missing}")
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    X = df[FEATURE_NAMES]
    y = df[LABEL_COLUMN].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=random_state, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=200,
        random_state=random_state,
        class_weight="balanced_subsample",
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_metrics = _evaluate(rf, X_test, y_test, "random_forest")

    chosen = rf
    chosen_name = "random_forest"
    gb_metrics = None
    if compare_gbdt:
        gb = GradientBoostingClassifier(random_state=random_state)
        gb.fit(X_train, y_train)
        gb_metrics = _evaluate(gb, X_test, y_test, "gradient_boosting")
        if gb_metrics["f1_macro"] > rf_metrics["f1_macro"]:
            chosen = gb
            chosen_name = "gradient_boosting"

    version = datetime.now(timezone.utc).strftime("rf-%Y%m%dT%H%M%SZ")
    model_path = artifacts_dir() / f"{version}.joblib"
    schema_path = artifacts_dir() / f"{version}.schema.json"
    metrics_path = artifacts_dir() / f"{version}.metrics.json"
    joblib.dump(chosen, model_path)
    schema = {
        "version": version,
        "model_type": type(chosen).__name__,
        "algorithm": chosen_name,
        "feature_names": FEATURE_NAMES,
        "classes": [int(c) for c in chosen.classes_],
        "class_names": {str(k): v for k, v in CLASS_NAMES.items()},
        "dataset_source": str(dataset_path),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "sklearn_note": "Offline CIC-IDS2017 evaluation does not guarantee accuracy on live lab traffic.",
    }
    schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    importance = []
    if hasattr(chosen, "feature_importances_"):
        importance = [
            {"feature": name, "importance": float(val)}
            for name, val in sorted(
                zip(FEATURE_NAMES, chosen.feature_importances_),
                key=lambda item: item[1],
                reverse=True,
            )
        ]
    metrics = {
        "random_forest": rf_metrics,
        "gradient_boosting": gb_metrics,
        "selected": chosen_name,
        "feature_importance": importance,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "dataset_source": str(dataset_path),
        "trained_at": schema["trained_at"],
        "version": version,
    }
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    latest = {
        "model_path": str(model_path),
        "schema_path": str(schema_path),
        "metrics_path": str(metrics_path),
        **schema,
        "metrics": metrics,
    }
    (artifacts_dir() / "latest.json").write_text(json.dumps(latest, indent=2), encoding="utf-8")
    return latest


def _evaluate(model, X_test, y_test, name: str) -> dict:
    y_pred = model.predict(X_test)
    labels = sorted(set(y_test) | set(y_pred))
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    return {
        "name": name,
        "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "confusion_matrix": confusion_matrix(y_test, y_pred, labels=labels).tolist(),
        "labels": [int(x) for x in labels],
        "classification_report": report,
    }


if __name__ == "__main__":
    print(json.dumps(train(), indent=2))
