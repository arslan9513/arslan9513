from __future__ import annotations

from typing import List

import psutil

from .models import ProcessFinding

SUSPICIOUS_PROCESS_MARKERS = ["powershell", "wscript", "cscript", "nc", "ncat", "mimikatz"]


class ProcessMonitor:
    def snapshot(self) -> List[ProcessFinding]:
        findings: List[ProcessFinding] = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "cmdline"]):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                cmdline_list = info.get("cmdline") or []
                cmdline = " ".join(cmdline_list).lower()
                cpu = float(info.get("cpu_percent") or 0.0)
                memory = float((info.get("memory_info").rss if info.get("memory_info") else 0) / (1024 * 1024))

                score = 0
                if any(marker in name for marker in SUSPICIOUS_PROCESS_MARKERS):
                    score += 40
                if any(marker in cmdline for marker in SUSPICIOUS_PROCESS_MARKERS):
                    score += 35
                if cpu > 75:
                    score += 20
                if memory > 1024:
                    score += 15

                risk = "Low"
                if score >= 70:
                    risk = "High"
                elif score >= 45:
                    risk = "Medium"

                if risk != "Low":
                    findings.append(
                        ProcessFinding(
                            pid=int(info.get("pid") or 0),
                            name=info.get("name") or "unknown",
                            cpu_percent=cpu,
                            memory_mb=memory,
                            cmdline=" ".join(cmdline_list),
                            risk=risk,
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return findings
