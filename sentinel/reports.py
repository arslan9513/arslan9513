from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .models import ScanFinding, ProcessFinding, ReportSnapshot


class ReportBuilder:
    def __init__(self, reports_dir: str = "reports") -> None:
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        quick_findings: List[ScanFinding],
        deep_findings: List[ScanFinding],
        process_findings: List[ProcessFinding],
    ) -> Path:
        snapshot = ReportSnapshot.now(
            quick_scan_count=len(quick_findings),
            deep_scan_count=len(deep_findings),
            process_alerts=len(process_findings),
        )
        payload = {
            "meta": snapshot.__dict__,
            "quick_scan": [f.to_dict() for f in quick_findings],
            "deep_scan": [f.to_dict() for f in deep_findings],
            "process_alerts": [p.to_dict() for p in process_findings],
        }
        out_file = self.reports_dir / f"report_{snapshot.created_at.replace(':', '-')}.json"
        out_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return out_file
