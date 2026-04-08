from __future__ import annotations

import hashlib
import math
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Tuple

from .models import ScanFinding


MALWARE_KEYWORDS = [
    b"powershell -enc",
    b"cmd.exe /c",
    b"keylogger",
    b"mimikatz",
    b"ransom",
    b"wallet stealer",
]

SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".ps1", ".vbs", ".scr", ".dll", ".js", ".jar"}


class SystemScanner:
    def __init__(self, max_file_size_mb: int = 20) -> None:
        self.max_size = max_file_size_mb * 1024 * 1024

    def quick_scan(self, roots: Iterable[str]) -> List[ScanFinding]:
        findings: List[ScanFinding] = []
        for root in roots:
            path = Path(root)
            if not path.exists():
                continue
            for file in path.glob("**/*"):
                if not file.is_file():
                    continue
                if file.stat().st_size > self.max_size:
                    continue
                if file.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                    finding = self._analyze_file(file, deep=False)
                    if finding:
                        findings.append(finding)
        return findings

    def deep_scan(self, roots: Iterable[str]) -> List[ScanFinding]:
        findings: List[ScanFinding] = []
        for root in roots:
            path = Path(root)
            if not path.exists():
                continue
            for file in path.glob("**/*"):
                if not file.is_file():
                    continue
                if file.stat().st_size > self.max_size:
                    continue
                finding = self._analyze_file(file, deep=True)
                if finding:
                    findings.append(finding)
        return findings

    def _analyze_file(self, file: Path, deep: bool) -> ScanFinding | None:
        try:
            data = file.read_bytes()
        except OSError:
            return None

        score, reasons = self._score_file(file, data, deep)
        if score < 35:
            return None

        severity = "Low"
        if score >= 85:
            severity = "Critical"
        elif score >= 65:
            severity = "High"
        elif score >= 45:
            severity = "Medium"

        return ScanFinding(
            path=str(file),
            threat_name="Potential.Malware.Generic",
            severity=severity,
            reason=", ".join(reasons),
            score=score,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            created_at=datetime.utcnow().isoformat(),
        )

    def _score_file(self, file: Path, data: bytes, deep: bool) -> Tuple[float, List[str]]:
        score = 0.0
        reasons: List[str] = []

        suffix = file.suffix.lower()
        if suffix in SUSPICIOUS_EXTENSIONS:
            score += 25
            reasons.append(f"Подозрительное расширение {suffix}")

        lower = data.lower()
        matches = sum(1 for marker in MALWARE_KEYWORDS if marker in lower)
        if matches:
            score += 20 + matches * 8
            reasons.append(f"Найдены сигнатурные ключи: {matches}")

        entropy = self._shannon_entropy(data[: min(len(data), 50000)])
        if entropy > 7.2:
            score += 25
            reasons.append(f"Высокая энтропия ({entropy:.2f})")

        if deep and b"socket" in lower and b"subprocess" in lower:
            score += 20
            reasons.append("Комбинация socket + subprocess")

        if deep and b"cryptography" in lower and b"fernet" in lower:
            score += 18
            reasons.append("Возможная шифровальная активность")

        return min(score, 100.0), reasons

    @staticmethod
    def _shannon_entropy(chunk: bytes) -> float:
        if not chunk:
            return 0.0
        freq = [0] * 256
        for b in chunk:
            freq[b] += 1

        entropy = 0.0
        length = len(chunk)
        for count in freq:
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
