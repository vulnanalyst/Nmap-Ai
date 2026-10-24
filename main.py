"""Compatibility launcher. Prefer the FastAPI application in backend/app/main.py."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.chdir(ROOT)

if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("NMAP_AI_HOST", "127.0.0.1")
    port = int(os.environ.get("NMAP_AI_PORT", "8000"))
    print("Nmap-AI Security Intelligence Platform")
    print(f"API: http://{host}:{port}/docs")
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=False)
