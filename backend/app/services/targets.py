from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.core.errors import AppError
from backend.app.models import AuthorizedTarget


def parse_target(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | ipaddress.IPv4Address | ipaddress.IPv6Address:
    raw = (value or "").strip()
    if not raw:
        raise AppError("Target is required", code="invalid_target")
    if any(ch in raw for ch in [";", "|", "&", "`", "$", "(", ")", "\n", " "]):
        raise AppError("Target contains invalid characters", code="invalid_target")
    try:
        if "/" in raw:
            return ipaddress.ip_network(raw, strict=False)
        return ipaddress.ip_address(raw)
    except ValueError as exc:
        raise AppError("Target must be an IPv4/IPv6 address or CIDR", code="invalid_target") from exc


def network_of(value: str):
    parsed = parse_target(value)
    if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return parsed
    return ipaddress.ip_network(parsed, strict=False)


def load_allowlist(db: Session) -> list[str]:
    rows = [row.cidr for row in db.query(AuthorizedTarget).all()]
    settings = get_settings()
    extra = [part.strip() for part in settings.authorized_targets.split(",") if part.strip()]
    merged = []
    for item in rows + extra:
        parse_target(item)
        if item not in merged:
            merged.append(item)
    return merged


def is_authorized(target: str, allowlist: list[str]) -> bool:
    candidate = network_of(target)
    for allowed in allowlist:
        allowed_net = network_of(allowed)
        if candidate.version != allowed_net.version:
            continue
        if candidate.subnet_of(allowed_net) or candidate == allowed_net:
            return True
        if candidate.num_addresses == 1 and ipaddress.ip_address(str(candidate.network_address)) in allowed_net:
            return True
    return False


def assert_authorized(db: Session, target: str) -> None:
    allowlist = load_allowlist(db)
    if not allowlist:
        raise AppError(
            "No authorized lab targets are configured. Add CIDRs on the Settings page before scanning.",
            status_code=403,
            code="allowlist_empty",
        )
    if not is_authorized(target, allowlist):
        raise AppError(
            "Target is not on the authorized lab allowlist",
            status_code=403,
            code="unauthorized_target",
            details={"target": target, "allowlist": allowlist},
        )
