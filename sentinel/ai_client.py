from __future__ import annotations

import json
from typing import List
from urllib import request, error

from .models import ScanFinding, AppSettings


class AIAnalyzer:
    def summarize_findings(self, findings: List[ScanFinding], settings: AppSettings) -> str:
        if not findings:
            return "Угроз не найдено. Система выглядит чистой по текущим эвристикам."

        if not settings.api_key:
            return self._local_summary(findings)

        payload = {
            "model": settings.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Ты SOC-аналитик. Дай краткое заключение по угрозам и рекомендации.",
                },
                {
                    "role": "user",
                    "content": json.dumps([f.to_dict() for f in findings], ensure_ascii=False),
                },
            ],
            "temperature": 0.2,
        }
        data = json.dumps(payload).encode("utf-8")

        req = request.Request(
            settings.endpoint,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {settings.api_key}",
            },
        )

        try:
            with request.urlopen(req, timeout=20) as resp:
                parsed = json.loads(resp.read().decode("utf-8"))
            return parsed["choices"][0]["message"]["content"].strip()
        except (error.URLError, KeyError, IndexError, TimeoutError, json.JSONDecodeError) as exc:
            return (
                "Внешний ИИ недоступен, использован локальный fallback. "
                f"Причина: {exc}.\n\n{self._local_summary(findings)}"
            )

    def _local_summary(self, findings: List[ScanFinding]) -> str:
        critical = [f for f in findings if f.severity in {"High", "Critical"}]
        medium = [f for f in findings if f.severity == "Medium"]
        top = sorted(findings, key=lambda x: x.score, reverse=True)[:5]

        lines = [
            "Локальный AI-отчёт:",
            f"- Всего подозрительных файлов: {len(findings)}",
            f"- Высокий/критический риск: {len(critical)}",
            f"- Средний риск: {len(medium)}",
            "- Топ объектов:",
        ]
        for item in top:
            lines.append(f"  • {item.path} ({item.severity}, score={item.score:.1f})")
        lines.append("Рекомендация: изолировать high/critical, провести ручную проверку и перескан после очистки.")
        return "\n".join(lines)
