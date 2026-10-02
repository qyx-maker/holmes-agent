from __future__ import annotations

from sqlalchemy import DateTime, Integer, String, create_engine
from sqlalchemy.dialects.mysql import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from alert_analyzer.config import Settings


class Base(DeclarativeBase):
    pass


class AlertRecord(Base):
    """一条告警事件及其分析、通知状态机快照。"""

    __tablename__ = "alert_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    alert_name: Mapped[str] = mapped_column(String(255), nullable=False)
    alert_status: Mapped[str] = mapped_column(String(16), nullable=False, default="firing")
    starts_at: Mapped[object] = mapped_column(DateTime, nullable=False)
    ends_at: Mapped[object | None] = mapped_column(DateTime, nullable=True)
    resource_key: Mapped[str] = mapped_column(String(512), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    phase: Mapped[str] = mapped_column(String(32), index=True, nullable=False, default="analysis_pending")
    analysis_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    notification_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[object | None] = mapped_column(DateTime, nullable=True)
    lease_until: Mapped[object | None] = mapped_column(DateTime, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    notification_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # 旧版本 cause_key 字段为兼容现有 MySQL 表保留；自然语言版本不写入或读取它。
    cause_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    notification_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_stage: Mapped[str | None] = mapped_column(String(32), nullable=True)
    failure_message: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    created_at: Mapped[object] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[object] = mapped_column(DateTime, nullable=False)


class CauseState(Base):
    """保留旧版原因聚合表映射；自然语言版本不再使用或更新此表。"""

    __tablename__ = "cause_notification_state"

    cause_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_notified_at: Mapped[object | None] = mapped_column(DateTime, nullable=True)
    affected_resources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    notified_resources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    pending_resources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    updated_at: Mapped[object] = mapped_column(DateTime, nullable=False)


def build_engine(settings: Settings):
    # pre_ping 让连接池在复用空闲连接前检测 MySQL 是否已断开。
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_recycle=1800,
        pool_size=5,
        max_overflow=5,
    )


def build_session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
