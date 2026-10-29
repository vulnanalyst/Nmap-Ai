from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from backend.app.core.paths import repo_root


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NMAP_AI_",
        env_file=str(repo_root() / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = 8000
    frontend_origin: str = "http://127.0.0.1:5173"
    api_token: str = "changeme-local-only"
    username: str = "lab"
    password: str = "changeme"
    password_hash: str = ""
    database_url: str = ""
    nmap_path: str = "nmap"
    scan_timeout_seconds: int = 600
    scanner_name: str = ""
    scanner_ip: str = ""
    target_name: str = ""
    target_ip: str = ""
    authorized_targets: str = ""
    ingest_host: str = "127.0.0.1"
    ingest_port: int = 9999
    log_level: str = "INFO"
    @property
    def root(self) -> Path:
        return repo_root()

    @property
    def data_dir(self) -> Path:
        path = self.root / "data"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def sqlite_url(self) -> str:
        if self.database_url:
            if self.database_url.startswith("sqlite") and "///" in self.database_url:
                raw = self.database_url.split("sqlite:///")[-1]
                if not raw.startswith("/"):
                    abs_path = self.root / raw
                    abs_path.parent.mkdir(parents=True, exist_ok=True)
                    return f"sqlite:///{abs_path}"
            return self.database_url
        db_path = self.data_dir / "nmap_ai.db"
        return f"sqlite:///{db_path}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
