from __future__ import annotations

import json
from typing import List
from urllib import request, error

from .models import ScanFinding, AppSettings


class AIAnalyzer:
    def summarize_findings(self, findings: List[ScanFinding], settings: AppSettings) -> str:
        if not findings:
            return "No threats found. The system appears clean based on current heuristics."

        if not settings.api_key:
            return self._local_summary(findings)

        payload = {
            "model": settings.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a SOC analyst. Provide a concise threat assessment and remediation recommendations.",
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
                "External AI is unavailable; local fallback was used. "
                f"Reason: {exc}.\n\n{self._local_summary(findings)}"
            )

    def _local_summary(self, findings: List[ScanFinding]) -> str:
        critical = [f for f in findings if f.severity in {"High", "Critical"}]
        medium = [f for f in findings if f.severity == "Medium"]
        top = sorted(findings, key=lambda x: x.score, reverse=True)[:5]

        lines = [
            "Local AI report:",
            f"- Total suspicious files: {len(findings)}",
            f"- High/Critical risk: {len(critical)}",
            f"- Medium risk: {len(medium)}",
            "- Top items:",
        ]
        for item in top:
            lines.append(f"  • {item.path} ({item.severity}, score={item.score:.1f})")
        lines.append("Recommendation: isolate high/critical files, run manual investigation, and rescan after cleanup.")
        return "\n".join(lines)
