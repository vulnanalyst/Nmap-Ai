from typing import Any, Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class ScanRequest(BaseModel):
    profile: Literal["host_discovery", "tcp_connect", "service_version", "os_fingerprint", "vuln_safe"]
    target: str
    confirm_target: str
    confirm_authorization: bool = False
    dry_run: bool = False


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
