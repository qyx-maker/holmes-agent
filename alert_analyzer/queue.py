from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from alert_analyzer.database import AlertRecord
from alert_analyzer.schemas import IncomingAlert


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass(frozen=True)
class EnqueueResult:
    accepted: int = 0
    duplicates: int = 0
    resolved: int = 0


def enqueue_alerts(session_factory: sessionmaker[Session], alerts: list[IncomingAlert]) -> EnqueueResult:
    accepted = duplicates = resolved = 0
    now = utcnow()
    with session_factory.begin() as session:
        for alert in alerts:
            if alert.status == "resolved":
                # fingerprint 标识一条告警流。resolved 关闭当前 firing 事件，
                # 后续同 fingerprint 的 firing 会创建新事件并重新调查。
                active = session.scalars(
                    select(AlertRecord)
                    .where(
                        AlertRecord.fingerprint == alert.fingerprint,
                        AlertRecord.alert_status == "firing",
                    )
                    .with_for_update()
                ).all()
                for record in active:
                    record.alert_status = "resolved"
                    record.ends_at = alert.ends_at
                    # 未开始的调查在告警结束后已没有分析价值，立即关闭队列项。
                    # 正在运行的 Holmes 请求无法安全中断，完成时由 worker 再检查状态。
                    if record.phase in {"analysis_pending", "analysis_retry"}:
                        record.phase = "skipped"
                        record.next_attempt_at = None
                        record.lease_until = None
                    record.updated_at = now
                    resolved += 1
                continue

            # Alertmanager 会周期性重发仍在 firing 的同一 fingerprint。
            # 更新最新 payload 即可，不能因此重复排队调用 Holmes。
            active = session.scalar(
                select(AlertRecord)
                .where(
                    AlertRecord.fingerprint == alert.fingerprint,
                    AlertRecord.alert_status == "firing",
                )
                .order_by(AlertRecord.id.desc())
                .with_for_update()
            )
            if active is not None:
                active.payload = alert.payload
                active.updated_at = now
                duplicates += 1
                continue

            event_key = alert.event_key
            previous = session.scalar(
                select(AlertRecord).where(AlertRecord.event_key == event_key).with_for_update()
            )
            # Prometheus 通常会在新一轮 firing 时生成新的 startsAt；这里额外
            # 处理测试/重放数据复用相同开始时间的情况，避免事件主键冲突。
            if previous is not None:
                event_key = hashlib.sha256(f"{event_key}|{now.isoformat()}".encode()).hexdigest()
            # 整个事件记录和待调查状态在同一 MySQL 事务提交，之后 HTTP 层
            # 才会向 Alertmanager 返回成功响应。
            session.add(
                AlertRecord(
                    event_key=event_key,
                    fingerprint=alert.fingerprint,
                    alert_name=alert.alert_name,
                    alert_status="firing",
                    starts_at=alert.starts_at,
                    resource_key=alert.resource_key,
                    payload=alert.payload,
                    phase="analysis_pending",
                    created_at=now,
                    updated_at=now,
                )
            )
            accepted += 1
    return EnqueueResult(accepted=accepted, duplicates=duplicates, resolved=resolved)
