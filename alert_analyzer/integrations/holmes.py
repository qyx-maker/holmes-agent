from __future__ import annotations

import json

import httpx

from alert_analyzer.config import Settings
from alert_analyzer.schemas import IncomingAlert


class HolmesError(RuntimeError):
    """Holmes 调用失败，或没有返回可展示的分析文本。"""


def investigate(
    alert: IncomingAlert,
    settings: Settings,
    strategy_instructions: str | None,
) -> str:
    """调用 HolmesGPT 并原样返回自然语言分析，不要求模型生成 JSON。"""
    labels = alert.payload.get("labels") or {}
    annotations = alert.payload.get("annotations") or {}
    alert_context = {
        "status": alert.status,
        "fingerprint": alert.fingerprint,
        "startsAt": alert.starts_at.isoformat() + "Z",
        "resource": alert.resource_key,
        "labels": labels,
        "annotations": annotations,
        "generatorURL": alert.payload.get("generatorURL"),
    }
    guidance = strategy_instructions or "Investigate only the exact resource identified by this alert."
    ask = f"""Investigate this Prometheus Alertmanager alert in the Kubernetes cluster.

Alert context:
```json
{json.dumps(alert_context, ensure_ascii=False, indent=2)}
```

Investigation guidance:
{guidance}

Safety and response requirements:
- Use only read-only Kubernetes, Linux, logs, metrics, and configuration inspection. Never change cluster state.
- Focus on the exact alerted resource. Do not investigate unrelated workloads or cluster-wide history unless the alert itself indicates a cluster-wide symptom.
- Use at most 6 tool calls. Stop when enough relevant evidence has been collected; do not keep exploring unrelated possibilities.
- Distinguish observed symptoms from proven causes. Do not invent command output, evidence, or certainty.
- Write the result as concise Chinese Markdown in natural language. Do not return JSON, a schema, or a code block.
- Begin with one plain-language status: 已确认故障, 可能误报, or 证据不足. Choose only what the evidence supports.
- Name the evidence sources and say explicitly when an expected source could not be obtained.
- Give a repair recommendation only when evidence supports the cause. If evidence is insufficient, provide only the next read-only evidence to collect.
- Do not claim a normalized root-cause category or affected-resource set unless the evidence establishes it.
"""
    headers = {"Content-Type": "application/json"}
    if settings.holmes_api_key:
        headers["X-API-Key"] = settings.holmes_api_key
    body = {
        "ask": ask,
        "stream": False,
    }

    try:
        # HolmesGPT 0.42.0 的 /api/chat 会返回 analysis 自然语言文本；
        # 不传 response_format，避免把有效的 Markdown 当成 JSON 契约失败。
        with httpx.Client(timeout=settings.holmes_timeout_seconds) as client:
            response = client.post(f"{settings.holmes_api_url}/api/chat", headers=headers, json=body)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HolmesError(f"Holmes request failed: {exc}") from exc

    try:
        envelope = response.json()
    except ValueError as exc:
        raise HolmesError("Holmes returned an invalid response envelope") from exc
    if not isinstance(envelope, dict):
        raise HolmesError("Holmes response envelope is not an object")
    analysis = envelope.get("analysis")
    if not isinstance(analysis, str) or not analysis.strip():
        raise HolmesError("Holmes returned empty or non-text analysis")

    # 只去掉首尾空白，不重写 Holmes 的文字、证据或判断。
    return analysis.strip()
