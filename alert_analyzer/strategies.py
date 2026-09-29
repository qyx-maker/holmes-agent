from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class StrategyRegistry:
    """读取可选的告警专属调查提示；默认仍走 Holmes 通用调查路径。"""

    def __init__(self, path: Path):
        self.path = path
        self.rules: list[dict[str, Any]] = []
        self.reload()

    def reload(self) -> None:
        # 缺少配置文件时仍可用通用调查；配置存在但格式错误则启动失败，
        # 避免规则拼写错误被静默忽略。
        if not self.path.exists():
            self.rules = []
            return
        raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict) or not isinstance(raw.get("rules", []), list):
            raise ValueError("Alert rules config must be an object containing a rules array")
        rules = raw.get("rules", [])
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict) or not isinstance(rule.get("match", {}), dict):
                raise ValueError(f"Rule {index} must have an object-valued match field")
            if not isinstance(rule.get("guidance", ""), str):
                raise ValueError(f"Rule {index} guidance must be a string")
        self.rules = rules

    def instructions_for(self, alert: dict[str, Any]) -> str | None:
        labels = alert.get("labels") or {}
        # 按配置顺序取第一个完全匹配的规则；未匹配时返回 None，
        # 由 Holmes 客户端使用通用只读调查提示。
        for rule in self.rules:
            if all(str(labels.get(key, "")) == str(value) for key, value in rule.get("match", {}).items()):
                return rule.get("guidance") or None
        return None
