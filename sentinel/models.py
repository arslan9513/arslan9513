from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, Any


@dataclass
class ScanFinding:
    path: str
    threat_name: str
    severity: str
    reason: str
    score: float
    sha256: str
    size: int
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessFinding:
    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    cmdline: str
    risk: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AppSettings:
    api_key: str = ""
    endpoint: str = "https://api.openai.com/v1/chat/completions"
    model: str = "gpt-4o-mini"
    max_file_size_mb: int = 20
    quarantine_dir: str = "./quarantine"


@dataclass
class ReportSnapshot:
    created_at: str
    quick_scan_count: int
    deep_scan_count: int
    process_alerts: int

    @classmethod
    def now(cls, quick_scan_count: int, deep_scan_count: int, process_alerts: int) -> "ReportSnapshot":
        return cls(
            created_at=datetime.utcnow().isoformat(),
            quick_scan_count=quick_scan_count,
            deep_scan_count=deep_scan_count,
            process_alerts=process_alerts,
        )
