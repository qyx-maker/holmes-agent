from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Any

import httpx

from alert_analyzer.config import Settings


class FeishuError(RuntimeError):
    pass


def send_message(settings: Settings, notification: dict[str, Any]) -> None:
    if not settings.feishu_webhook_url:
        raise FeishuError("FEISHU_WEBHOOK_URL is not configured")

    card: dict[str, Any] = {
        "header": {
            "template": "orange",
            "title": {"tag": "plain_text", "content": notification["title"][:100]},
        },
        "elements": [{"tag": "markdown", "content": notification["markdown"]}],
        "wide_screen_mode": True,
    }
    body: dict[str, Any] = {"msg_type": "interactive", "card": card}
    if settings.feishu_signing_secret:
        # 飞书自定义机器人签名：时间戳和签名密钥组成 HMAC key，结果 Base64 编码。
        timestamp = str(int(time.time()))
        string_to_sign = f"{timestamp}\n{settings.feishu_signing_secret}".encode("utf-8")
        signature = base64.b64encode(hmac.new(string_to_sign, b"", hashlib.sha256).digest()).decode()
        body["timestamp"] = timestamp
        body["sign"] = signature

    try:
        response = httpx.post(settings.feishu_webhook_url, json=body, timeout=20)
        response.raise_for_status()
        result = response.json()
    except httpx.HTTPStatusError as exc:
        # Webhook URL 的 query string 带机器人 token；异常文本会包含完整 URL，
        # 因此只保存 HTTP 状态码，避免把密钥写入 MySQL 或日志。
        raise FeishuError(f"Feishu webhook returned HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise FeishuError(f"Feishu webhook request failed ({type(exc).__name__})") from exc
    except ValueError as exc:
        raise FeishuError("Feishu webhook returned an invalid JSON response") from exc
    if isinstance(result, dict) and result.get("code", 0) not in (0, None):
        raise FeishuError(f"Feishu rejected the message: code={result.get('code')}, msg={result.get('msg', '')}")
