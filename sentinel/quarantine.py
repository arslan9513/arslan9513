from __future__ import annotations

import shutil
from pathlib import Path


class QuarantineManager:
    def __init__(self, quarantine_dir: str) -> None:
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def isolate(self, path: str) -> str:
        src = Path(path)
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(path)
        dest = self.quarantine_dir / src.name
        counter = 1
        while dest.exists():
            dest = self.quarantine_dir / f"{src.stem}_{counter}{src.suffix}"
            counter += 1
        shutil.move(str(src), str(dest))
        return str(dest)
