from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from alert_analyzer.config import Settings
from alert_analyzer.schemas import IncomingAlert

logger = logging.getLogger(__name__)

VERDICT_VALUES = ("confirmed_incident", "possible_false_positive", "insufficient_evidence")

# 这是 Python 与 Holmes 之间的响应契约。严格结构化输出使状态、证据
# 来源和缺失信息都能被校验，而不是依赖解析自由格式的自然语言。
RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICT_VALUES)},
        "summary": {"type": "string"},
        "cause_category": {"type": ["string", "null"]},
        "cause_scope": {"type": ["string", "null"]},
        "root_cause_resource": {"type": ["string", "null"]},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "source": {"type": "string"},
                    "detail": {"type": "string"},
                    "available": {"type": "boolean"},
                },
                "required": ["source", "detail", "available"],
            },
        },
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "follow_up": {"type": "array", "items": {"type": "string"}},
        "affected_resources": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "verdict",
        "summary",
        "cause_category",
        "cause_scope",
        "root_cause_resource",
        "evidence",
        "recommended_actions",
        "follow_up",
        "affected_resources",
    ],
}


class HolmesError(RuntimeError):
    pass


def investigate(
    alert: IncomingAlert,
    settings: Settings,
    strategy_instructions: str | None,
) -> dict[str, Any]:
    # 将告警上下文作为证据调查的边界；额外规则只补充调查重点，
    # 不改变“只读、证据优先、证据不足不下确定结论”的统一要求。
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
    guidance = strategy_instructions or "Use your general Kubernetes troubleshooting knowledge and the available read-only data sources."
    ask = f"""Investigate this Prometheus Alertmanager alert in the Kubernetes cluster.

Alert context:
```json
{json.dumps(alert_context, ensure_ascii=False, indent=2)}
```

Investigation guidance:
{guidance}

Safety and evidence requirements:
- Use only read-only Kubernetes, Linux, logs, metrics, and configuration inspection. Never change cluster state.
- Distinguish an observed symptom from a proven root cause. Do not invent missing command output or evidence.
- Return verdict `confirmed_incident` only when the evidence confirms a real issue; `possible_false_positive` only with evidence supporting that judgment; otherwise use `insufficient_evidence`.
- For every evidence item, name the source (for example a Kubernetes object, command/tool, metric, or log) and set `available=false` when that evidence could not be obtained.
- Recommend concrete remediation only when the cause is supported by evidence. When evidence is insufficient, put only the next read-only information-gathering steps in `follow_up` and leave `recommended_actions` empty.
- Set cause_category, cause_scope, and root_cause_resource to null if they cannot be established. cause_scope should be a stable normalized scope such as a node, namespace, workload, or cluster. root_cause_resource is the suspected cause resource, not merely the alerted object.
- Include the affected alert resources in affected_resources, using stable namespace/name style identifiers when possible.
- Respond with only the requested structured fields.
"""
    headers = {"Content-Type": "application/json"}
    if settings.holmes_api_key:
        headers["X-API-Key"] = settings.holmes_api_key
    body = {
        "ask": ask,
        "stream": False,
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "AlertInvestigation", "strict": True, "schema": RESULT_SCHEMA},
        },
    }

    try:
        # 当前集群 Holmes 0.42.0 使用 /api/chat；stream=false 返回完整结果，
        # analysis 字段承载 response_format 对应的 JSON 字符串。
        with httpx.Client(timeout=settings.holmes_timeout_seconds) as client:
            response = client.post(f"{settings.holmes_api_url}/api/chat", headers=headers, json=body)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HolmesError(f"Holmes request failed: {exc}") from exc

    try:
        envelope = response.json()
        analysis = envelope.get("analysis")
        result = json.loads(analysis) if isinstance(analysis, str) else analysis
    except (ValueError, AttributeError, TypeError) as exc:
        raise HolmesError("Holmes returned an invalid JSON response envelope") from exc

    _validate_result(result)
    return result


def _validate_result(result: Any) -> None:
    # 把响应契约错误当作 Holmes 调查失败，进入有限重试；不把坏响应
    # 当成“可能误报”发给用户。
    if not isinstance(result, dict):
        raise HolmesError("Holmes structured analysis is not a JSON object")
    if result.get("verdict") not in VERDICT_VALUES:
        raise HolmesError("Holmes response is missing a supported verdict")
    for key in ("summary", "evidence", "recommended_actions", "follow_up", "affected_resources"):
        if key not in result:
            raise HolmesError(f"Holmes response is missing required field: {key}")
    if not isinstance(result["evidence"], list):
        raise HolmesError("Holmes evidence must be an array")
    for item in result["evidence"]:
        if not isinstance(item, dict) or not all(k in item for k in ("source", "detail", "available")):
            raise HolmesError("Holmes returned an evidence item without source/detail/available")
    if result["verdict"] == "insufficient_evidence" and result["recommended_actions"]:
        # 证据不足时只允许提出后续取证步骤，不能保留确定性的修复建议。
        result["recommended_actions"] = []
