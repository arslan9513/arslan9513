from __future__ import annotations

import sys

from PyQt5.QtWidgets import QApplication

from .ui import MainWindow


def run() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
