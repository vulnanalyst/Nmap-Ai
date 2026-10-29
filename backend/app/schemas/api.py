from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128, description="Username for authentication")
    password: str = Field(..., min_length=1, max_length=128, description="Password for authentication")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Username cannot be empty or whitespace only")
        return cleaned

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v:
            raise ValueError("Password cannot be empty")
        return v


class ScanRequest(BaseModel):
    profile: Literal["host_discovery", "tcp_connect", "service_version", "os_fingerprint", "vuln_safe"]
    target: str
    confirm_target: str
    confirm_authorization: bool = False
    dry_run: bool = False
    dataset_target_id: int | None = None


class TargetCreate(BaseModel):
    cidr: str
    label: str = ""


class FindingPatch(BaseModel):
    workflow_status: Literal["new", "investigating", "confirmed", "false_positive", "accepted_risk", "resolved"]


class AlertPatch(BaseModel):
    status: Literal["open", "acknowledged", "investigating", "resolved"] | None = None
    note: str | None = None


class SettingsPatch(BaseModel):
    values: dict[str, str] = Field(default_factory=dict)


class InferenceRequest(BaseModel):
    features: dict[str, float] | list[float]


class PacketIngest(BaseModel):
    src_addr: str
    dst_addr: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "TCP"
    packet_length: int = 0


class AgentHeartbeat(BaseModel):
    scanner_name: str = "Kali"
    scanner_ip: str = "192.168.56.102"
    nmap_version: str | None = None
    nmap_path: str = "/usr/bin/nmap"
    status: str = "online"


class AgentScanCompleteRequest(BaseModel):
    job_id: str
    return_code: int = 0
    stdout: str = ""
    stderr: str = ""
    xml_content: str = ""

