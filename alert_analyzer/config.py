from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.engine import URL


@dataclass(frozen=True)
class Settings:
    mysql_host: str
    mysql_port: int
    mysql_database: str
    mysql_user: str
    mysql_password: str
    holmes_api_url: str
    holmes_api_key: str | None
    holmes_timeout_seconds: float
    feishu_webhook_url: str | None
    feishu_signing_secret: str | None
    alert_rules_file: Path
    worker_poll_seconds: float
    task_lease_seconds: int
    analysis_max_age_seconds: int
    retry_delays_seconds: tuple[int, ...]

    @property
    def database_url(self) -> URL:
        # URL.create 会正确转义密码中的特殊字符，避免手工拼 DSN 出错。
        return URL.create(
            "mysql+pymysql",
            username=self.mysql_user,
            password=self.mysql_password,
            host=self.mysql_host,
            port=self.mysql_port,
            database=self.mysql_database,
            query={"charset": "utf8mb4"},
        )

    @classmethod
    def from_env(cls) -> "Settings":
        # 密码、机器人 URL 等凭据只从环境变量读取，不进入代码或镜像。
        required = ("MYSQL_DATABASE", "MYSQL_USER", "MYSQL_PASSWORD")
        missing = [name for name in required if not os.getenv(name)]
        if missing:
            raise RuntimeError("Missing required environment variables: " + ", ".join(missing))

        retry_values = tuple(
            int(value.strip())
            for value in os.getenv("RETRY_DELAYS_SECONDS", "60,180,600").split(",")
            if value.strip()
        )
        if not retry_values or any(value <= 0 for value in retry_values):
            raise RuntimeError("RETRY_DELAYS_SECONDS must contain positive comma-separated integers")
        holmes_timeout_seconds = float(os.getenv("HOLMES_TIMEOUT_SECONDS", "900"))
        task_lease_seconds = int(os.getenv("TASK_LEASE_SECONDS", "1200"))
        if task_lease_seconds <= holmes_timeout_seconds:
            raise RuntimeError("TASK_LEASE_SECONDS must exceed HOLMES_TIMEOUT_SECONDS")

        analysis_max_age_seconds = int(os.getenv("ANALYSIS_MAX_AGE_SECONDS", "1800"))
        if analysis_max_age_seconds <= 0:
            raise RuntimeError("ANALYSIS_MAX_AGE_SECONDS must be a positive integer")
        if analysis_max_age_seconds <= holmes_timeout_seconds:
            raise RuntimeError("ANALYSIS_MAX_AGE_SECONDS must exceed HOLMES_TIMEOUT_SECONDS")

        return cls(
            mysql_host=os.getenv("MYSQL_HOST", "mysql-0.mysql.mysql.svc.cluster.local"),
            mysql_port=int(os.getenv("MYSQL_PORT", "3306")),
            mysql_database=os.environ["MYSQL_DATABASE"],
            mysql_user=os.environ["MYSQL_USER"],
            mysql_password=os.environ["MYSQL_PASSWORD"],
            holmes_api_url=os.getenv(
                "HOLMES_API_URL",
                "http://holmesgpt-holmes.default.svc.cluster.local",
            ).rstrip("/"),
            holmes_api_key=os.getenv("HOLMES_API_KEY") or None,
            holmes_timeout_seconds=holmes_timeout_seconds,
            feishu_webhook_url=os.getenv("FEISHU_WEBHOOK_URL") or None,
            feishu_signing_secret=os.getenv("FEISHU_SIGNING_SECRET") or None,
            alert_rules_file=Path(os.getenv("ALERT_RULES_FILE", "config/alert_rules.yaml")),
            worker_poll_seconds=float(os.getenv("WORKER_POLL_SECONDS", "2")),
            task_lease_seconds=task_lease_seconds,
            # 超过此年龄的待分析告警已失去时效性，不再交给 Holmes 调查。
            analysis_max_age_seconds=analysis_max_age_seconds,
            retry_delays_seconds=retry_values,
        )
