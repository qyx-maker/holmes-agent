from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, sessionmaker

from alert_analyzer.config import Settings
from alert_analyzer.database import AlertRecord
from alert_analyzer.integrations.feishu import send_message
from alert_analyzer.integrations.holmes import investigate
from alert_analyzer.queue import utcnow
from alert_analyzer.schemas import IncomingAlert
from alert_analyzer.strategies import StrategyRegistry

logger = logging.getLogger(__name__)


def _build_notification(
    record: AlertRecord,
    analysis: str | None,
    analysis_failed: bool = False,
) -> dict[str, str]:
    """把告警身份和 Holmes 原始自然语言结果渲染为可重试消息。"""
    labels = record.payload.get("labels") or {}
    annotations = record.payload.get("annotations") or {}
    notification_id = hashlib.sha256(f"{record.event_key}|analysis".encode()).hexdigest()
    if analysis_failed:
        title = f"告警调查失败：{record.alert_name}"
        state_label = "调查失败"
    else:
        state_label = "Holmes 分析结果"
        title = f"{state_label}：{record.alert_name}"

    lines = [
        f"**状态：** {state_label}",
        f"**告警：** `{record.alert_name}`",
        f"**指纹：** `{record.fingerprint}`",
        f"**开始时间（UTC）：** {record.starts_at.isoformat()}Z",
        f"**对象：** {record.resource_key}",
    ]
    lines.append(f"**通知 ID：** `{notification_id}`")
    if labels.get("severity"):
        lines.append(f"**级别：** {labels['severity']}")
    if annotations.get("summary"):
        lines.append(f"**告警摘要：** {annotations['summary']}")
    if analysis:
        # 正文保持 Holmes 原文，截断只为遵守飞书卡片的消息长度限制。
        max_analysis_chars = 12000
        body = analysis.strip()
        if len(body) > max_analysis_chars:
            body = body[:max_analysis_chars].rstrip() + "\n\n（分析内容过长，已截断；完整结果保存在 MySQL。）"
        lines.extend(["", "**Holmes 分析：**", body])
    elif analysis_failed:
        lines.extend(["", "Holmes 在最大重试次数内未返回有效分析文本。"])
    if analysis_failed:
        lines.extend(
            [
                "",
                f"**失败阶段：** {record.failure_stage or 'Holmes 调查'}",
                f"**失败原因：** {record.failure_message or '未知错误'}",
            ]
        )
    return {
        "title": title,
        "markdown": "\n".join(lines),
        # 同一个事件的发送重试复用 ID；飞书机器人不保证按此 ID 服务端去重。
        "notification_id": notification_id,
    }


def _retry_or_finish(
    record: AlertRecord,
    stage: str,
    error: Exception,
    settings: Settings,
    now: datetime,
) -> None:
    """按 1/3/10 分钟退避；超过三次重试后转入终态。"""
    attempts = record.analysis_attempts if stage == "analysis" else record.notification_attempts
    record.failure_stage = stage
    record.failure_message = str(error)[:1900]
    record.lease_until = None
    record.updated_at = now

    # attempts 包含初次调用：1 对应第一次重试等待，4 表示三次重试已用尽。
    if attempts <= len(settings.retry_delays_seconds):
        delay = settings.retry_delays_seconds[attempts - 1]
        record.phase = f"{stage}_retry"
        record.next_attempt_at = now + timedelta(seconds=delay)
        logger.warning(
            "Alert %s %s attempt %d failed; retrying in %d seconds: %s",
            record.event_key[:12],
            stage,
            attempts,
            delay,
            error,
        )
        return

    if stage == "analysis":
        # Holmes 多次失败属于调查失败，不伪装成误报或已确认根因；
        # 仍创建一次飞书失败通知，且后续只重试发送，不再重跑调查。
        record.result = {"format": "natural_language", "analysis": None}
        record.failure_stage = "Holmes 调查"
        record.updated_at = now
        logger.error("Holmes investigation exhausted retries for alert %s", record.event_key[:12])
        if settings.feishu_webhook_url:
            record.notification_payload = _build_notification(record, None, analysis_failed=True)
            record.notification_id = record.notification_payload["notification_id"]
            record.phase = "notification_pending"
            record.notification_attempts = 0
            record.next_attempt_at = now
        else:
            # 飞书未配置时保留最终失败记录，不制造必然失败的通知重试。
            record.phase = "failed"
            record.next_attempt_at = None
    else:
        record.phase = "failed"
        record.next_attempt_at = None
        logger.error("Feishu notification exhausted retries for alert %s", record.event_key[:12])


def _claim_job(session_factory: sessionmaker[Session], settings: Settings) -> tuple[int, str] | None:
    now = utcnow()
    stale_before = now - timedelta(seconds=settings.analysis_max_age_seconds)
    due = or_(AlertRecord.next_attempt_at.is_(None), AlertRecord.next_attempt_at <= now)
    ready = and_(AlertRecord.phase.in_(
        ["analysis_pending", "analysis_retry", "notification_pending", "notification_retry"]
    ), due)
    expired = and_(
        AlertRecord.phase.in_(["analysis_running", "notification_running"]),
        AlertRecord.lease_until <= now,
    )
    with session_factory.begin() as session:
        # Alertmanager/webhook 可能因应用停机而在 MySQL 留下积压任务。
        # 只过期分析阶段；通知阶段必须继续重试，因为它不应再次调用 Holmes。
        stale_analysis = session.scalars(
            select(AlertRecord)
            .where(
                AlertRecord.phase.in_(["analysis_pending", "analysis_retry"]),
                AlertRecord.created_at < stale_before,
            )
            .with_for_update()
        ).all()
        for stale in stale_analysis:
            stale.phase = "skipped"
            stale.next_attempt_at = None
            stale.lease_until = None
            stale.updated_at = now
            logger.info("Skipped stale queued alert %s before Holmes investigation", stale.event_key[:12])

        # 过期租约表示进程在调用期间退出；若对应事件也已过时，不再恢复调查。
        expired_stale_running = session.scalars(
            select(AlertRecord)
            .where(
                AlertRecord.phase == "analysis_running",
                AlertRecord.lease_until <= now,
                AlertRecord.created_at < stale_before,
            )
            .with_for_update()
        ).all()
        for stale in expired_stale_running:
            stale.phase = "skipped"
            stale.next_attempt_at = None
            stale.lease_until = None
            stale.updated_at = now
            logger.info("Skipped stale interrupted alert %s before Holmes retry", stale.event_key[:12])

        # 行锁让任务在事务内只被一个 worker 认领。避免依赖 MySQL 8 的
        # SKIP LOCKED，当前集群 MySQL 5.7 也能使用；单副本下按序处理即可。
        record = session.scalar(
            select(AlertRecord)
            .where(or_(ready, expired))
            .order_by(AlertRecord.created_at, AlertRecord.id)
            .limit(1)
            .with_for_update()
        )
        if record is None:
            return None
        stage = "analysis" if record.phase.startswith("analysis") else "notification"
        record.phase = f"{stage}_running"
        if stage == "analysis":
            record.analysis_attempts += 1
        else:
            record.notification_attempts += 1
        record.next_attempt_at = None
        # 若进程在外部调用期间退出，租约过期后任务可被重新认领，避免永久卡在 running。
        record.lease_until = now + timedelta(seconds=settings.task_lease_seconds)
        record.updated_at = now
        record_id = record.id
    return record_id, stage


def _process_analysis(
    session_factory: sessionmaker[Session],
    settings: Settings,
    strategies: StrategyRegistry,
    record_id: int,
) -> None:
    # 先复制必要字段并结束 DB 读取事务，再调用 Holmes；长时间网络等待期间
    # 不持有 MySQL 行锁，Webhook 仍可更新同一告警或写入 resolved 状态。
    with session_factory.begin() as session:
        record = session.get(AlertRecord, record_id)
        if record is None:
            return
        if record.alert_status == "resolved" or record.created_at < utcnow() - timedelta(
            seconds=settings.analysis_max_age_seconds
        ):
            record.phase = "skipped"
            record.next_attempt_at = None
            record.lease_until = None
            record.updated_at = utcnow()
            logger.info("Skipped resolved or stale alert %s before Holmes investigation", record.event_key[:12])
            return
        incoming = IncomingAlert(
            event_key=record.event_key,
            fingerprint=record.fingerprint,
            alert_name=record.alert_name,
            status=record.alert_status,
            starts_at=record.starts_at,
            ends_at=record.ends_at,
            resource_key=record.resource_key,
            payload=record.payload,
        )
        guidance = strategies.instructions_for(record.payload)

    # 明确记录调用起点；Holmes 可能耗时数分钟，未完成前仅看完成日志会像是没有触发。
    logger.info(
        "Starting Holmes investigation for alert %s (%s)",
        record_id,
        incoming.alert_name,
    )
    try:
        result = investigate(incoming, settings, guidance)
    except Exception as exc:
        with session_factory.begin() as session:
            record = session.scalar(select(AlertRecord).where(AlertRecord.id == record_id).with_for_update())
            if record is not None:
                now = utcnow()
                if record.alert_status == "resolved" or record.created_at < now - timedelta(
                    seconds=settings.analysis_max_age_seconds
                ):
                    record.phase = "skipped"
                    record.next_attempt_at = None
                    record.lease_until = None
                    record.updated_at = now
                    logger.info("Skipped retry for resolved or stale alert %s after Holmes failure", record.event_key[:12])
                else:
                    _retry_or_finish(record, "analysis", exc, settings, now)
        return

    now = utcnow()
    with session_factory.begin() as session:
        record = session.scalar(select(AlertRecord).where(AlertRecord.id == record_id).with_for_update())
        if record is None:
            return
        # Webhook 可能在 Holmes 调查期间收到 resolved；结果可留在库内供审计，
        # 但结束或已过时的告警不再生成飞书通知，也不更新原因聚合窗口。
        if record.alert_status == "resolved" or record.created_at < now - timedelta(
            seconds=settings.analysis_max_age_seconds
        ):
            record.result = {"format": "natural_language", "analysis": result}
            record.phase = "skipped"
            record.lease_until = None
            record.next_attempt_at = None
            record.updated_at = now
            logger.info("Stored but suppressed stale/resolved Holmes result for alert %s", record.event_key[:12])
            return
        record.result = {"format": "natural_language", "analysis": result}
        record.failure_stage = None
        record.failure_message = None

        feishu_enabled = bool(settings.feishu_webhook_url)
        if feishu_enabled:
            record.notification_payload = _build_notification(record, result)
            record.notification_id = record.notification_payload["notification_id"]
            record.phase = "notification_pending"
            record.notification_attempts = 0
            record.next_attempt_at = now
        else:
            # 未配置飞书时，首测只验证告警进入 Holmes 并成功持久化结果；
            # 标记完成，避免把“跳过通知”误当成发送失败进入重试队列。
            record.phase = "complete"
            record.notification_payload = None
            record.next_attempt_at = None
        record.lease_until = None
        record.updated_at = now

    if feishu_enabled:
        logger.info(
            "Holmes analysis completed for alert %s (%d characters); Feishu notification queued",
            record_id,
            len(result),
        )
    else:
        logger.info(
            "Holmes analysis completed and saved for alert %s (%d characters); Feishu is not configured, notification skipped",
            record_id,
            len(result),
        )


def _process_notification(
    session_factory: sessionmaker[Session],
    settings: Settings,
    record_id: int,
) -> None:
    # 网络发送也放在数据库事务之外。成功后再单独提交完成状态；失败时保留
    # notification_payload，后续重试只发同一条消息，不会再次调用 Holmes。
    with session_factory() as session:
        record = session.get(AlertRecord, record_id)
        if record is None or not record.notification_payload:
            return
        notification = record.notification_payload

    try:
        send_message(settings, notification)
    except Exception as exc:
        with session_factory.begin() as session:
            record = session.scalar(select(AlertRecord).where(AlertRecord.id == record_id).with_for_update())
            if record is not None:
                _retry_or_finish(record, "notification", exc, settings, utcnow())
        return

    now = utcnow()
    with session_factory.begin() as session:
        record = session.scalar(select(AlertRecord).where(AlertRecord.id == record_id).with_for_update())
        if record is None:
            return
        record.phase = "complete"
        record.lease_until = None
        record.next_attempt_at = None
        record.updated_at = now
    logger.info("Feishu notification %s sent for alert %s", notification["notification_id"][:12], record_id)


def _process_one(session_factory: sessionmaker[Session], settings: Settings, strategies: StrategyRegistry) -> bool:
    claimed = _claim_job(session_factory, settings)
    if claimed is None:
        return False
    record_id, stage = claimed
    if stage == "analysis":
        _process_analysis(session_factory, settings, strategies, record_id)
    else:
        _process_notification(session_factory, settings, record_id)
    return True


async def worker_loop(session_factory: sessionmaker[Session], settings: Settings) -> None:
    """单 worker 轮询持久化队列；取消时未完成任务由租约机制恢复。"""
    strategies = StrategyRegistry(settings.alert_rules_file)
    while True:
        try:
            processed = await asyncio.to_thread(_process_one, session_factory, settings, strategies)
            if not processed:
                await asyncio.sleep(settings.worker_poll_seconds)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Background alert worker iteration failed")
            await asyncio.sleep(settings.worker_poll_seconds)
