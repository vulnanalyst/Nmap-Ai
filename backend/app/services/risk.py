from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

DEFAULT_WEIGHTS = {
    "severity": 0.35,
    "exposure": 0.20,
    "evidence": 0.20,
    "asset": 0.10,
    "ml": 0.10,
    "freshness": 0.05,
}

SEVERITY_SCORE = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.05,
}

VALIDATION_SCORE = {
    "validated_vulnerability": 1.0,
    "confirmed_by_check": 0.9,
    "detected": 0.6,
    "suspected": 0.35,
    "observed": 0.2,
    "potential_issue": 0.3,
    "no_verified_cve_match": 0.05,
}

EXPOSURE_SCORE = {
    "open": 1.0,
    "filtered": 0.4,
    "closed": 0.1,
    "unknown": 0.2,
}


def score_finding(
    *,
    severity: str,
    validation_status: str,
    port_state: str | None,
    asset_importance: float | None,
    ml_anomaly: float | None,
    last_observed: datetime | None,
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    sev = SEVERITY_SCORE.get((severity or "info").lower(), 0.05)
    evid = VALIDATION_SCORE.get((validation_status or "suspected").lower(), 0.35)
    exp = EXPOSURE_SCORE.get((port_state or "unknown").lower(), 0.2)
    asset = asset_importance if asset_importance is not None else 0.0
    ml = ml_anomaly if ml_anomaly is not None else 0.0
    freshness = 1.0
    if last_observed is not None:
        if last_observed.tzinfo is None:
            last_observed = last_observed.replace(tzinfo=timezone.utc)
        age_hours = max(0.0, (datetime.now(timezone.utc) - last_observed).total_seconds() / 3600)
        freshness = pow(2.718281828, -age_hours / 72.0)

    raw = (
        w["severity"] * sev
        + w["exposure"] * exp
        + w["evidence"] * evid
        + w["asset"] * asset
        + w["ml"] * ml
        + w["freshness"] * freshness
    )
    return {
        "score": round(100 * raw, 2),
        "weights": w,
        "signals": {
            "severity": sev,
            "exposure": exp,
            "evidence": evid,
            "asset_importance": asset if asset_importance is not None else None,
            "ml_anomaly": ml if ml_anomaly is not None else None,
            "freshness": round(freshness, 4),
        },
        "formula": "100 * (w_sev*severity + w_exp*exposure + w_evid*evidence + w_asset*asset + w_ml*ml + w_fresh*freshness)",
        "notes": [
            "Asset importance is omitted (treated as 0) unless configured.",
            "ML anomaly is a separate contributing signal, not proof of compromise.",
            "Scores rank investigation order; they do not confirm exploitation.",
        ],
    }
