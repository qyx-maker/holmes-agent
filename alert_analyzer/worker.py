from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, sessionmaker

from alert_analyzer.config import Settings
from alert_analyzer.database import AlertRecord, CauseState
from alert_analyzer.integrations.feishu import send_message
from alert_analyzer.integrations.holmes import investigate
from alert_analyzer.queue import utcnow
from alert_analyzer.schemas import IncomingAlert
from alert_analyzer.strategies import StrategyRegistry

logger = logging.getLogger(__name__)
def _normalized(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return " ".join(value.strip().lower().split())


def _cause_key(result: dict[str, Any]) -> str | None:
    # 原因类别、范围、根因资源三项都必须存在，才允许跨告警合并；
    # 任一项缺失就不猜测原因是否相同。
    dimensions = [
        _normalized(result.get("cause_category")),
        _normalized(result.get("cause_scope")),
        _normalized(result.get("root_cause_resource")),
    ]
    if not all(dimensions):
        return None
    return hashlib.sha256("|".join(dimensions).encode("utf-8")).hexdigest()


def _resource_list(result: dict[str, Any], fallback: str) -> list[str]:
    raw = result.get("affected_resources") or []
    resources = sorted({str(item).strip() for item in raw if str(item).strip()})
    return resources or [fallback]


def _merge_resources(*values: list[str] | None) -> list[str]:
    return sorted({item for group in values for item in (group or []) if item})


def _build_notification(
    record: AlertRecord,
    result: dict[str, Any],
    cause_key: str | None,
    new_resources: list[str],
    total_affected: int,
    analysis_failed: bool = False,
) -> dict[str, Any]:
    """把持久化分析结果渲染成可重试发送的纯数据消息。"""
    labels = record.payload.get("labels") or {}
    annotations = record.payload.get("annotations") or {}
    verdict = result.get("verdict", "insufficient_evidence")
    if analysis_failed:
        title = f"告警调查失败：{record.alert_name}"
        state_label = "调查失败"
    else:
        state_label = {
            "confirmed_incident": "已确认故障",
            "possible_false_positive": "可能误报",
            "insufficient_evidence": "证据不足",
        }.get(verdict, "证据不足")
        title = f"{state_label}：{record.alert_name}"

    lines = [
        f"**结论：** {state_label}",
        f"**告警：** `{record.alert_name}`",
        f"**指纹：** `{record.fingerprint}`",
        f"**开始时间（UTC）：** {record.starts_at.isoformat()}Z",
        f"**对象：** {record.resource_key}",
    ]
    if labels.get("severity"):
        lines.append(f"**级别：** {labels['severity']}")
    if annotations.get("summary"):
        lines.append(f"**告警摘要：** {annotations['summary']}")
    if result.get("summary"):
        lines.extend(["", f"**分析：** {result['summary']}"])

    evidence = result.get("evidence") or []
    lines.extend(["", "**证据：**"])
    if evidence:
        for item in evidence[:8]:
            availability = "已取得" if item.get("available") else "缺失"
            lines.append(f"- `{item.get('source', '未知来源')}`（{availability}）：{item.get('detail', '')}")
        if len(evidence) > 8:
            lines.append(f"- 另有 {len(evidence) - 8} 项证据未在消息中展开")
    else:
        lines.append("- Holmes 未返回可引用的证据")

    recommendations = [] if analysis_failed else result.get("recommended_actions") or []
    if state_label == "证据不足":
        recommendations = []
    lines.extend(["", "**建议：**"])
    lines.extend([f"- {item}" for item in recommendations[:8]] or ["- 暂无基于证据的修复建议"])

    follow_up = result.get("follow_up") or []
    if follow_up:
        lines.extend(["", "**后续取证：**", *[f"- {item}" for item in follow_up[:6]]])
    if analysis_failed:
        lines.extend(
            [
                "",
                f"**失败阶段：** {record.failure_stage or 'Holmes 调查'}",
                f"**失败原因：** {record.failure_message or '未知错误'}",
            ]
        )
    if cause_key:
        lines.extend(["", f"**原因标识：** `{cause_key[:16]}`"])
        lines.append(f"**当前累计受影响对象：** {total_affected}")
        if new_resources:
            lines.append("**本次新增对象：** " + ", ".join(f"`{item}`" for item in new_resources[:20]))
            if len(new_resources) > 20:
                lines.append(f"（另有 {len(new_resources) - 20} 个新增对象）")

    return {
        "title": title,
        "markdown": "\n".join(lines),
        # 本地稳定 ID 用于审计和避免重复排队；飞书机器人不保证按此 ID 去重。
        "notification_id": hashlib.sha256(f"{record.event_key}|{cause_key or ''}".encode()).hexdigest(),
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
        record.result = {
            "verdict": "insufficient_evidence",
            "summary": "Holmes investigation failed before it could return a valid evidence-based result.",
            "cause_category": None,
            "cause_scope": None,
            "root_cause_resource": None,
            "evidence": [],
            "recommended_actions": [],
            "follow_up": [],
            "affected_resources": [record.resource_key],
        }
        record.notification_payload = _build_notification(
            record,
            record.result,
            None,
            [],
            1,
            analysis_failed=True,
        )
        record.phase = "notification_pending"
        record.notification_attempts = 0
        record.next_attempt_at = now
        record.failure_stage = "Holmes 调查"
        record.updated_at = now
        logger.error("Holmes investigation exhausted retries for alert %s", record.event_key[:12])
    else:
        record.phase = "failed"
        record.next_attempt_at = None
        logger.error("Feishu notification exhausted retries for alert %s", record.event_key[:12])


def _claim_job(session_factory: sessionmaker[Session], settings: Settings) -> tuple[int, str] | None:
    now = utcnow()
    due = or_(AlertRecord.next_attempt_at.is_(None), AlertRecord.next_attempt_at <= now)
    ready = and_(AlertRecord.phase.in_(
        ["analysis_pending", "analysis_retry", "notification_pending", "notification_retry"]
    ), due)
    expired = and_(
        AlertRecord.phase.in_(["analysis_running", "notification_running"]),
        AlertRecord.lease_until <= now,
    )
    with session_factory.begin() as session:
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
    with session_factory() as session:
        record = session.get(AlertRecord, record_id)
        if record is None:
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

    try:
        result = investigate(incoming, settings, guidance)
    except Exception as exc:
        with session_factory.begin() as session:
            record = session.scalar(select(AlertRecord).where(AlertRecord.id == record_id).with_for_update())
            if record is not None:
                _retry_or_finish(record, "analysis", exc, settings, utcnow())
        return

    now = utcnow()
    with session_factory.begin() as session:
        record = session.scalar(select(AlertRecord).where(AlertRecord.id == record_id).with_for_update())
        if record is None:
            return
        record.result = result
        record.failure_stage = None
        record.failure_message = None
        cause_key = _cause_key(result)
        record.cause_key = cause_key
        resources = _resource_list(result, record.resource_key)
        new_resources = resources
        total_affected = len(resources)

        if cause_key:
            # pending_resources 累积上次通知后新出现的对象；30 分钟内只更新
            # 这个集合并抑制消息，窗口过后由下一条同原因告警触发汇总通知。
            state = session.scalar(
                select(CauseState).where(CauseState.cause_key == cause_key).with_for_update()
            )
            if state is None:
                state = CauseState(
                    cause_key=cause_key,
                    last_notified_at=None,
                    affected_resources=[],
                    notified_resources=[],
                    pending_resources=[],
                    updated_at=now,
                )
                session.add(state)
                session.flush()
            affected = _merge_resources(state.affected_resources, resources)
            not_yet_notified = _merge_resources(
                state.pending_resources,
                [item for item in affected if item not in (state.notified_resources or [])],
            )
            state.affected_resources = affected
            state.pending_resources = not_yet_notified
            state.updated_at = now
            total_affected = len(affected)
            recent = state.last_notified_at is not None and (now - state.last_notified_at).total_seconds() < settings.dedup_window_seconds
            if recent:
                record.phase = "suppressed"
                record.notification_payload = None
                record.next_attempt_at = None
                record.lease_until = None
                record.updated_at = now
                logger.info("Suppressed duplicate cause notification for alert %s", record.event_key[:12])
                return
            new_resources = not_yet_notified or resources

        feishu_enabled = bool(settings.feishu_webhook_url)
        if feishu_enabled:
            record.notification_payload = _build_notification(
                record,
                result,
                cause_key,
                new_resources,
                total_affected,
            )
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
            "Holmes analysis completed for alert %s: verdict=%s; Feishu notification queued",
            record_id,
            result["verdict"],
        )
    else:
        logger.info(
            "Holmes analysis completed and saved for alert %s: verdict=%s; Feishu is not configured, notification skipped",
            record_id,
            result["verdict"],
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
        cause_key = record.cause_key

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
        if cause_key:
            # 只有飞书确认成功后，才推进原因通知窗口并清空待汇总对象。
            state = session.scalar(
                select(CauseState).where(CauseState.cause_key == cause_key).with_for_update()
            )
            if state is not None:
                state.last_notified_at = now
                state.notified_resources = list(state.affected_resources or [])
                state.pending_resources = []
                state.updated_at = now
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
