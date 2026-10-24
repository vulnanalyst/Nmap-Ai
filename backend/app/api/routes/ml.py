import threading
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter

from backend.app.api.deps import AuthDep, DbDep
from backend.app.core.errors import AppError
from backend.app.models import ModelVersion, TrainingRun
from backend.app.schemas.api import InferenceRequest
from ml.inference.predict import FeatureSchemaError, latest_artifact, predict
from ml.training.train import train

router = APIRouter(prefix="/ml", tags=["ml"])


@router.get("/model")
def model_info(_: AuthDep, db: DbDep):
    latest = latest_artifact()
    rows = db.query(ModelVersion).order_by(ModelVersion.trained_at.desc()).all()
    return {
        "active": latest,
        "disclaimer": "Benchmark-dataset evaluation does not guarantee accuracy on this lab's live traffic.",
        "history": [
            {"version": m.version, "trained_at": m.trained_at.isoformat(), "is_active": m.is_active, "metrics": m.metrics}
            for m in rows
        ],
    }


@router.post("/infer")
def infer(_: AuthDep, body: InferenceRequest):
    try:
        return predict(body.features)
    except FileNotFoundError as exc:
        raise AppError(str(exc), status_code=409, code="model_missing") from exc
    except FeatureSchemaError as exc:
        raise AppError(str(exc), status_code=400, code="feature_schema") from exc


@router.get("/training")
def training_jobs(_: AuthDep, db: DbDep):
    rows = db.query(TrainingRun).order_by(TrainingRun.started_at.desc()).all()
    return {
        "items": [
            {
                "id": r.id,
                "status": r.status,
                "error": r.error,
                "metrics": r.metrics,
                "model_version": r.model_version,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            }
            for r in rows
        ]
    }


@router.post("/training")
def start_training(_: AuthDep, db: DbDep):
    run = TrainingRun(id=str(uuid.uuid4()), status="running")
    db.add(run)
    db.commit()

    def _job(run_id: str) -> None:
        from backend.app.db.session import get_session_factory

        session = get_session_factory()()
        row = session.query(TrainingRun).filter_by(id=run_id).one()
        try:
            result = train()
            row.status = "completed"
            row.metrics = result.get("metrics") or {}
            row.model_version = result.get("version")
            row.finished_at = datetime.now(timezone.utc)
            session.add(
                ModelVersion(
                    version=result["version"],
                    path=result["model_path"],
                    schema_path=result["schema_path"],
                    dataset_source=result.get("dataset_source") or "",
                    metrics=result.get("metrics") or {},
                    feature_names=result.get("feature_names") or [],
                    classes=result.get("classes") or [],
                    is_active=True,
                )
            )
            session.query(ModelVersion).filter(ModelVersion.version != result["version"]).update({"is_active": False})
        except Exception as exc:  # persist real training error
            row.status = "error"
            row.error = str(exc)
            row.finished_at = datetime.now(timezone.utc)
        session.commit()
        session.close()

    threading.Thread(target=_job, args=(run.id,), daemon=True).start()
    return {"id": run.id, "status": run.status}
