from __future__ import annotations

import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from alert_analyzer.integrations.holmes import HolmesError, investigate
from alert_analyzer.worker import _build_notification
from alert_analyzer.schemas import IncomingAlert


class HolmesNaturalLanguageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = IncomingAlert(
            event_key="event-1",
            fingerprint="fingerprint-1",
            alert_name="PodCPUUsageHigh",
            status="firing",
            starts_at=datetime(2026, 10, 1, 4, 0, 0),
            ends_at=None,
            resource_key="namespace=python/pod=python-abc",
            payload={
                "labels": {"alertname": "PodCPUUsageHigh", "namespace": "python", "pod": "python-abc"},
                "annotations": {"summary": "CPU high"},
            },
        )
        self.settings = SimpleNamespace(
            holmes_api_url="http://holmes.test",
            holmes_api_key=None,
            holmes_timeout_seconds=60,
        )

    @patch("alert_analyzer.integrations.holmes.httpx.Client")
    def test_returns_markdown_without_requesting_json_schema(self, client_type: MagicMock) -> None:
        markdown = "已确认故障\n\n证据：Pod 指标显示 CPU 持续超过阈值。"
        response = MagicMock()
        response.json.return_value = {"analysis": markdown}
        client_type.return_value.__enter__.return_value.post.return_value = response

        result = investigate(self.alert, self.settings, None)

        self.assertEqual(result, markdown)
        call = client_type.return_value.__enter__.return_value.post.call_args
        self.assertTrue(call.args[0].endswith("/api/chat"))
        self.assertNotIn("response_format", call.kwargs["json"])

    @patch("alert_analyzer.integrations.holmes.httpx.Client")
    def test_empty_analysis_is_a_contract_failure(self, client_type: MagicMock) -> None:
        response = MagicMock()
        response.json.return_value = {"analysis": "  "}
        client_type.return_value.__enter__.return_value.post.return_value = response

        with self.assertRaises(HolmesError):
            investigate(self.alert, self.settings, None)

    def test_notification_preserves_original_analysis_text(self) -> None:
        markdown = "可能误报\n\n证据来源：Prometheus 指标。"
        record = SimpleNamespace(
            payload=self.alert.payload,
            event_key=self.alert.event_key,
            alert_name=self.alert.alert_name,
            fingerprint=self.alert.fingerprint,
            starts_at=self.alert.starts_at,
            resource_key=self.alert.resource_key,
            notification_id=None,
            failure_stage=None,
            failure_message=None,
        )

        notification = _build_notification(record, markdown)

        self.assertIn(markdown, notification["markdown"])
        self.assertIn("PodCPUUsageHigh", notification["title"])
        self.assertEqual(len(notification["notification_id"]), 64)


if __name__ == "__main__":
    unittest.main()
