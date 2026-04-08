from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .models import AppSettings


class SettingsStore:
    def __init__(self, path: str = "settings.json") -> None:
        self.path = Path(path)

    def load(self) -> AppSettings:
        if not self.path.exists():
            return AppSettings()
        raw: Dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
        return AppSettings(**raw)

    def save(self, settings: AppSettings) -> None:
        self.path.write_text(
            json.dumps(settings.__dict__, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
