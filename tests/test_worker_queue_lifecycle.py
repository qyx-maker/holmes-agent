from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, select

from alert_analyzer.config import Settings
from alert_analyzer.database import AlertRecord, Base, build_session_factory
from alert_analyzer.queue import enqueue_alerts
from alert_analyzer.schemas import IncomingAlert
from alert_analyzer.worker import _claim_job


def make_settings() -> Settings:
    return Settings(
        mysql_host="localhost",
        mysql_port=3306,
        mysql_database="alerts",
        mysql_user="app",
        mysql_password="unused",
        holmes_api_url="http://holmes.invalid",
        holmes_api_key=None,
        holmes_timeout_seconds=10,
        feishu_webhook_url=None,
        feishu_signing_secret=None,
        alert_rules_file=Path("missing-rules.yaml"),
        worker_poll_seconds=1,
        task_lease_seconds=420,
        analysis_max_age_seconds=1800,
        retry_delays_seconds=(60, 180, 600),
    )


class QueueLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.sessions = build_session_factory(engine)

    def _record(self, *, phase: str, alert_status: str = "firing", created_at: datetime | None = None) -> AlertRecord:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return AlertRecord(
            event_key=f"event-{phase}-{alert_status}",
            fingerprint="fingerprint-1",
            alert_name="PodCPUUsageHigh",
            alert_status=alert_status,
            starts_at=now,
            resource_key="namespace=python/pod=python-abc",
            payload={"labels": {"alertname": "PodCPUUsageHigh", "namespace": "python"}},
            phase=phase,
            created_at=created_at or now,
            updated_at=created_at or now,
        )

    def test_stale_analysis_retry_is_skipped_without_claiming(self) -> None:
        old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
        with self.sessions.begin() as session:
            record = self._record(phase="analysis_retry", created_at=old)
            record.next_attempt_at = old
            session.add(record)

        claimed = _claim_job(self.sessions, make_settings())

        with self.sessions() as session:
            record = session.scalar(select(AlertRecord))
            self.assertIsNone(claimed)
            self.assertEqual(record.phase, "skipped")
            self.assertEqual(record.analysis_attempts, 0)

    def test_resolved_event_closes_waiting_analysis(self) -> None:
        with self.sessions.begin() as session:
            session.add(self._record(phase="analysis_pending"))

        resolved = IncomingAlert(
            event_key="resolved-event",
            fingerprint="fingerprint-1",
            alert_name="PodCPUUsageHigh",
            status="resolved",
            starts_at=datetime.now(timezone.utc).replace(tzinfo=None),
            ends_at=datetime.now(timezone.utc).replace(tzinfo=None),
            resource_key="namespace=python/pod=python-abc",
            payload={"labels": {"alertname": "PodCPUUsageHigh", "namespace": "python"}},
        )
        enqueue_alerts(self.sessions, [resolved])

        with self.sessions() as session:
            record = session.scalar(select(AlertRecord))
            self.assertEqual(record.alert_status, "resolved")
            self.assertEqual(record.phase, "skipped")


if __name__ == "__main__":
    unittest.main()
