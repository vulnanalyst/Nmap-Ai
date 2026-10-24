from pathlib import Path


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "backend" / "app" / "main.py").exists() and (parent / "docs").exists():
            return parent
        if (parent / "dataset" / "prepare.py").exists() and (parent / "backend").exists():
            return parent
    return here.parents[3]
