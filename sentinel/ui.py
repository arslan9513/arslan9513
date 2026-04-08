from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import List

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .ai_client import AIAnalyzer
from .models import AppSettings, ScanFinding, ProcessFinding
from .monitor import ProcessMonitor
from .quarantine import QuarantineManager
from .reports import ReportBuilder
from .scanner import SystemScanner
from .storage import SettingsStore


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SentinelAI Defender")
        self.resize(1450, 900)

        self.settings_store = SettingsStore()
        self.settings = self.settings_store.load()

        self.scanner = SystemScanner(max_file_size_mb=self.settings.max_file_size_mb)
        self.monitor = ProcessMonitor()
        self.ai = AIAnalyzer()
        self.report_builder = ReportBuilder()
        self.quarantine = QuarantineManager(self.settings.quarantine_dir)

        self.quick_findings: List[ScanFinding] = []
        self.deep_findings: List[ScanFinding] = []
        self.process_findings: List[ProcessFinding] = []

        self._build_ui()
        self._bind_actions()

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QHBoxLayout(root)

        splitter = QSplitter(Qt.Horizontal)
        root_layout.addWidget(splitter)

        self.nav = QListWidget()
        self.nav.setFixedWidth(260)
        self.nav.addItems(
            [
                "1. Dashboard",
                "2. Quick Scan",
                "3. Deep Scan",
                "4. Process Monitor",
                "5. Quarantine",
                "6. AI Assistant",
                "7. Reports",
                "8. Settings",
            ]
        )

        self.pages = QStackedWidget()

        self.dashboard_page = self._make_dashboard_page()
        self.quick_page = self._make_quick_scan_page()
        self.deep_page = self._make_deep_scan_page()
        self.process_page = self._make_process_page()
        self.quarantine_page = self._make_quarantine_page()
        self.ai_page = self._make_ai_page()
        self.reports_page = self._make_reports_page()
        self.settings_page = self._make_settings_page()

        for page in [
            self.dashboard_page,
            self.quick_page,
            self.deep_page,
            self.process_page,
            self.quarantine_page,
            self.ai_page,
            self.reports_page,
            self.settings_page,
        ]:
            self.pages.addWidget(page)

        splitter.addWidget(self.nav)
        splitter.addWidget(self.pages)
        splitter.setStretchFactor(1, 1)

        self.setCentralWidget(root)
        self.nav.setCurrentRow(0)

    def _make_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        title = QLabel("System Threat Dashboard")
        title.setStyleSheet("font-size: 24px; font-weight: 700;")

        self.dashboard_summary = QLabel("Run scans to build a threat summary.")
        self.dashboard_summary.setWordWrap(True)

        self.dashboard_log = QPlainTextEdit()
        self.dashboard_log.setReadOnly(True)

        layout.addWidget(title)
        layout.addWidget(self.dashboard_summary)
        layout.addWidget(self.dashboard_log)
        return page

    def _make_quick_scan_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.quick_paths = QLineEdit(str(Path.home()))
        quick_btn_bar = QHBoxLayout()
        self.btn_quick_scan = QPushButton("Run Quick Scan")
        self.btn_quick_browse = QPushButton("Select Folder")
        quick_btn_bar.addWidget(self.btn_quick_scan)
        quick_btn_bar.addWidget(self.btn_quick_browse)

        self.quick_table = self._make_findings_table()

        layout.addWidget(QLabel("Quick scan folders (separate with ';')"))
        layout.addWidget(self.quick_paths)
        layout.addLayout(quick_btn_bar)
        layout.addWidget(self.quick_table)
        return page

    def _make_deep_scan_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.deep_paths = QLineEdit(str(Path.home()))
        deep_btn_bar = QHBoxLayout()
        self.btn_deep_scan = QPushButton("Run Deep Scan")
        self.btn_deep_browse = QPushButton("Select Folder")
        deep_btn_bar.addWidget(self.btn_deep_scan)
        deep_btn_bar.addWidget(self.btn_deep_browse)

        self.deep_table = self._make_findings_table()

        layout.addWidget(QLabel("Deep scan folders (separate with ';')"))
        layout.addWidget(self.deep_paths)
        layout.addLayout(deep_btn_bar)
        layout.addWidget(self.deep_table)
        return page

    def _make_process_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.btn_process_scan = QPushButton("Refresh Process Snapshot")
        self.process_table = QTableWidget(0, 6)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "CPU%", "RAM MB", "Risk", "Cmdline"])
        self.process_table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.btn_process_scan)
        layout.addWidget(self.process_table)
        return page

    def _make_quarantine_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.quarantine_path_input = QLineEdit()
        self.btn_isolate = QPushButton("Move File To Quarantine")
        self.quarantine_log = QPlainTextEdit()
        self.quarantine_log.setReadOnly(True)

        layout.addWidget(QLabel("File path to isolate"))
        layout.addWidget(self.quarantine_path_input)
        layout.addWidget(self.btn_isolate)
        layout.addWidget(self.quarantine_log)
        return page

    def _make_ai_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.btn_ai_analyze = QPushButton("Analyze Findings with AI")
        self.ai_output = QPlainTextEdit()
        self.ai_output.setReadOnly(True)
        layout.addWidget(self.btn_ai_analyze)
        layout.addWidget(self.ai_output)
        return page

    def _make_reports_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.btn_export_report = QPushButton("Export JSON Report")
        self.reports_log = QPlainTextEdit()
        self.reports_log.setReadOnly(True)
        layout.addWidget(self.btn_export_report)
        layout.addWidget(self.reports_log)
        return page

    def _make_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        form = QFormLayout()

        self.settings_api_key = QLineEdit(self.settings.api_key)
        self.settings_api_key.setEchoMode(QLineEdit.Password)
        self.settings_endpoint = QLineEdit(self.settings.endpoint)
        self.settings_model = QLineEdit(self.settings.model)
        self.settings_max_size = QLineEdit(str(self.settings.max_file_size_mb))
        self.settings_quarantine_dir = QLineEdit(self.settings.quarantine_dir)

        form.addRow("API Key", self.settings_api_key)
        form.addRow("Endpoint", self.settings_endpoint)
        form.addRow("Model", self.settings_model)
        form.addRow("Max file size (MB)", self.settings_max_size)
        form.addRow("Quarantine folder", self.settings_quarantine_dir)

        self.btn_save_settings = QPushButton("Save Settings")
        self.settings_log = QPlainTextEdit()
        self.settings_log.setReadOnly(True)

        layout.addLayout(form)
        layout.addWidget(self.btn_save_settings)
        layout.addWidget(self.settings_log)
        return page

    def _bind_actions(self) -> None:
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.btn_quick_scan.clicked.connect(self.run_quick_scan)
        self.btn_deep_scan.clicked.connect(self.run_deep_scan)
        self.btn_process_scan.clicked.connect(self.run_process_monitor)
        self.btn_ai_analyze.clicked.connect(self.run_ai_analysis)
        self.btn_export_report.clicked.connect(self.export_report)
        self.btn_save_settings.clicked.connect(self.save_settings)
        self.btn_isolate.clicked.connect(self.isolate_file)
        self.btn_quick_browse.clicked.connect(lambda: self._pick_folder(self.quick_paths))
        self.btn_deep_browse.clicked.connect(lambda: self._pick_folder(self.deep_paths))

    def _pick_folder(self, target: QLineEdit) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            current = target.text().strip()
            target.setText(f"{current};{folder}" if current else folder)

    def _extract_paths(self, raw: str) -> List[str]:
        return [p.strip() for p in raw.split(";") if p.strip()]

    def _make_findings_table(self) -> QTableWidget:
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(["Path", "Threat", "Severity", "Score", "SHA256", "Reason"])
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def _fill_findings_table(self, table: QTableWidget, data: List[ScanFinding]) -> None:
        table.setRowCount(len(data))
        for row, finding in enumerate(data):
            table.setItem(row, 0, QTableWidgetItem(finding.path))
            table.setItem(row, 1, QTableWidgetItem(finding.threat_name))
            table.setItem(row, 2, QTableWidgetItem(finding.severity))
            table.setItem(row, 3, QTableWidgetItem(f"{finding.score:.1f}"))
            table.setItem(row, 4, QTableWidgetItem(finding.sha256[:16] + "..."))
            table.setItem(row, 5, QTableWidgetItem(finding.reason))

    def _refresh_dashboard(self) -> None:
        total = len(self.quick_findings) + len(self.deep_findings)
        high = len([f for f in self.quick_findings + self.deep_findings if f.severity in {"High", "Critical"}])
        proc = len(self.process_findings)
        text = (
            f"Total findings: {total}\n"
            f"High/Critical: {high}\n"
            f"Process alerts: {proc}\n"
            f"Quarantine folder: {self.settings.quarantine_dir}"
        )
        self.dashboard_summary.setText(text)

    def run_quick_scan(self) -> None:
        paths = self._extract_paths(self.quick_paths.text())
        self.quick_findings = self.scanner.quick_scan(paths)
        self._fill_findings_table(self.quick_table, self.quick_findings)
        self.dashboard_log.appendPlainText(f"Quick scan completed. Found: {len(self.quick_findings)}")
        self._refresh_dashboard()

    def run_deep_scan(self) -> None:
        paths = self._extract_paths(self.deep_paths.text())
        self.deep_findings = self.scanner.deep_scan(paths)
        self._fill_findings_table(self.deep_table, self.deep_findings)
        self.dashboard_log.appendPlainText(f"Deep scan completed. Found: {len(self.deep_findings)}")
        self._refresh_dashboard()

    def run_process_monitor(self) -> None:
        self.process_findings = self.monitor.snapshot()
        self.process_table.setRowCount(len(self.process_findings))
        for row, p in enumerate(self.process_findings):
            self.process_table.setItem(row, 0, QTableWidgetItem(str(p.pid)))
            self.process_table.setItem(row, 1, QTableWidgetItem(p.name))
            self.process_table.setItem(row, 2, QTableWidgetItem(f"{p.cpu_percent:.1f}"))
            self.process_table.setItem(row, 3, QTableWidgetItem(f"{p.memory_mb:.1f}"))
            self.process_table.setItem(row, 4, QTableWidgetItem(p.risk))
            self.process_table.setItem(row, 5, QTableWidgetItem(p.cmdline))
        self.dashboard_log.appendPlainText(f"Process monitor updated. Alerts: {len(self.process_findings)}")
        self._refresh_dashboard()

    def run_ai_analysis(self) -> None:
        merged = self.quick_findings + self.deep_findings
        summary = self.ai.summarize_findings(merged, self.settings)
        self.ai_output.setPlainText(summary)
        self.dashboard_log.appendPlainText("AI analysis generated.")

    def export_report(self) -> None:
        output = self.report_builder.export(self.quick_findings, self.deep_findings, self.process_findings)
        self.reports_log.appendPlainText(f"Report exported: {output}")
        self.dashboard_log.appendPlainText(f"Report saved: {output}")

    def save_settings(self) -> None:
        try:
            updated = AppSettings(
                api_key=self.settings_api_key.text().strip(),
                endpoint=self.settings_endpoint.text().strip(),
                model=self.settings_model.text().strip(),
                max_file_size_mb=int(self.settings_max_size.text().strip()),
                quarantine_dir=self.settings_quarantine_dir.text().strip(),
            )
        except ValueError:
            QMessageBox.warning(self, "Error", "Max file size must be an integer")
            return

        self.settings = updated
        self.settings_store.save(self.settings)
        self.scanner = SystemScanner(max_file_size_mb=self.settings.max_file_size_mb)
        self.quarantine = QuarantineManager(self.settings.quarantine_dir)
        self.settings_log.appendPlainText("Settings saved")
        self.dashboard_log.appendPlainText("Settings updated.")
        self._refresh_dashboard()

    def isolate_file(self) -> None:
        target = self.quarantine_path_input.text().strip()
        if not target:
            QMessageBox.information(self, "Info", "Please provide a file path")
            return

        try:
            new_path = self.quarantine.isolate(target)
            self.quarantine_log.appendPlainText(f"File isolated: {new_path}")
            self.dashboard_log.appendPlainText(f"File moved to quarantine: {new_path}")
        except FileNotFoundError:
            QMessageBox.warning(self, "Error", "File not found")

    def dump_state(self) -> str:
        payload = {
            "settings": asdict(self.settings),
            "quick_findings": [f.to_dict() for f in self.quick_findings],
            "deep_findings": [f.to_dict() for f in self.deep_findings],
            "process_findings": [p.to_dict() for p in self.process_findings],
        }
        return str(payload)
