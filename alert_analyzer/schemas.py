from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class IncomingAlert:
    event_key: str
    fingerprint: str
    alert_name: str
    status: str
    starts_at: datetime
    ends_at: datetime | None
    resource_key: str
    payload: dict[str, Any]


def _parse_timestamp(value: str | None, fallback: datetime | None = None) -> datetime:
    if not value:
        return fallback or datetime.now(timezone.utc).replace(tzinfo=None)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _stable_fingerprint(alert: dict[str, Any]) -> str:
    # 标准 Alertmanager payload 带 fingerprint；此哈希只作兼容兜底。
    canonical = json.dumps(
        {"labels": alert.get("labels") or {}, "annotations": alert.get("annotations") or {}},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def resource_key_for(alert: dict[str, Any]) -> str:
    # 选取常见 Kubernetes 标签组成可读对象标识，不把整份标签塞入飞书消息。
    labels = alert.get("labels") or {}
    parts = [
        f"{name}={labels[name]}"
        for name in ("cluster", "namespace", "pod", "container", "node", "service", "persistentvolumeclaim")
        if labels.get(name)
    ]
    return "/".join(parts) or f"alert={labels.get('alertname', 'unknown')}"


def normalize_alertmanager_payload(payload: Any) -> list[IncomingAlert]:
    # Alertmanager 一个 webhook 可能分组携带多条 alerts，逐条规范化和入队。
    if not isinstance(payload, dict):
        raise ValueError("Alertmanager webhook body must be a JSON object")
    raw_alerts = payload.get("alerts")
    if not isinstance(raw_alerts, list):
        raise ValueError("Alertmanager webhook body must contain an alerts array")

    normalized: list[IncomingAlert] = []
    for alert in raw_alerts:
        if not isinstance(alert, dict):
            raise ValueError("Each alert must be a JSON object")
        status = str(alert.get("status", payload.get("status", "firing"))).lower()
        if status not in {"firing", "resolved"}:
            raise ValueError(f"Unsupported alert status: {status}")
        labels = alert.get("labels") or {}
        if not isinstance(labels, dict):
            raise ValueError("Alert labels must be an object")
        fingerprint = str(alert.get("fingerprint") or _stable_fingerprint(alert))
        starts_at = _parse_timestamp(alert.get("startsAt"))
        ends_at = _parse_timestamp(alert.get("endsAt"), starts_at) if status == "resolved" else None
        event_seed = f"{fingerprint}|{starts_at.isoformat()}"
        # 同一 firing 周期具有稳定 event_key；resolved 后的新 firing 通常
        # 使用新的 startsAt，因此成为独立事件。
        event_key = hashlib.sha256(event_seed.encode()).hexdigest()
        normalized.append(
            IncomingAlert(
                event_key=event_key,
                fingerprint=fingerprint,
                alert_name=str(labels.get("alertname") or "unknown"),
                status=status,
                starts_at=starts_at,
                ends_at=ends_at,
                resource_key=resource_key_for(alert),
                payload=alert,
            )
        )
    return normalized
