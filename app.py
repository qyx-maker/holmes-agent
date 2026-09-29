"""Alertmanager 到 Holmes 告警分析服务的 FastAPI 入口。"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from sqlalchemy import text

from alert_analyzer.config import Settings
from alert_analyzer.database import Base, build_engine, build_session_factory
from alert_analyzer.queue import enqueue_alerts
from alert_analyzer.schemas import normalize_alertmanager_payload
from alert_analyzer.worker import worker_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.from_env()
    engine = build_engine(settings)
    # 首版直接在启动时建表，避免再引入迁移服务；因此数据库必须先创建，
    # 应用账号需要对该库有建表/索引权限。连接失败时启动失败，避免接收后丢任务。
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)

    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    # HTTP webhook 只负责持久化；独立 worker 在后台从 MySQL 取任务，
    # 所以 Holmes 调用变慢时也不会占住 Alertmanager 的 HTTP 请求。
    worker_task = asyncio.create_task(worker_loop(session_factory, settings))
    logger.info("Alert analyzer started; Holmes endpoint: %s", settings.holmes_api_url)
    try:
        yield
    finally:
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass
        engine.dispose()


app = FastAPI(
    title="Alert Analyzer",
    description="Persist Alertmanager events, investigate them with Holmes, and report to Feishu.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.post("/alert", status_code=202)
async def alert_webhook(request: Request) -> dict[str, Any]:
    """Persist firing/resolved alerts before acknowledging Alertmanager."""
    try:
        payload = await request.json()
        alerts = normalize_alertmanager_payload(payload)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = await asyncio.to_thread(
            enqueue_alerts,
            request.app.state.session_factory,
            alerts,
        )
    except Exception as exc:
        # 只有数据库事务提交成功才返回 202；存储故障返回 503，交给
        # Alertmanager 重试，避免“先确认收到、进程重启后却找不到任务”。
        logger.exception("Could not persist Alertmanager webhook")
        raise HTTPException(status_code=503, detail="Could not persist alert") from exc

    return {
        "status": "accepted",
        "accepted": result.accepted,
        "duplicates": result.duplicates,
        "resolved": result.resolved,
    }


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz(request: Request) -> dict[str, str]:
    try:
        with request.app.state.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="MySQL is unavailable") from exc
    return {"status": "ready"}
