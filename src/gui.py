import json
import os
import sqlite3
import sys
import zipfile
from pathlib import Path

from src.scanner_rules import ALLOWED_EXTENSIONS, SKIP_DIRS
from utils.auto_patch import PatchPlan, apply_patch_plan, create_patch_plan
from utils.cve_audit import database_path, merge_findings, scan_dependencies, update_database
from utils.git_hooks import install_precommit_hook
from utils.git_history import scan_git_history
from utils.license_guard import is_pro_unlocked, save_license_key
from utils.package_reputation import audit_package_reputation
from utils.passive_probe import probe_security_headers
from utils.report_exporter import export_html_report, export_json_report
from utils.incremental_scan import scan_incremental_project

try:
    from PyQt6.QtCore import (
        QFileSystemWatcher,
        QEasingCurve,
        QThread,
        QSize,
        QTimer,
        Qt,
        QVariantAnimation,
        pyqtSignal,
    )
    from PyQt6.QtCore import QAbstractTableModel, QModelIndex
    from PyQt6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPixmap
    from PyQt6.QtWidgets import (
        QApplication,
        QAbstractItemView,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QFrame,
        QBoxLayout,
        QHBoxLayout,
        QInputDialog,
        QLabel,
        QListWidget,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QPlainTextEdit,
        QProgressBar,
        QScrollArea,
        QSplitter,
        QTableView,
        QVBoxLayout,
        QWidget,
        QHeaderView,
        QStatusBar,
        QSystemTrayIcon,
    )
except ImportError as exc:
    raise SystemExit(
        "PyQt6 is required to run the ProtoSec desktop app. "
        "Install it with: python -m pip install -r requirements.txt"
    ) from exc


THEMES = {
    "dark": {
        "background": "#0b0914",
        "surface": "#100d1c",
        "card": "#151126",
        "card_hover": "#20183a",
        "border": "#30264b",
        "text": "#e6f0ff",
        "muted": "#a49ab9",
        "accent": "#b58aff",
        "accent_hover": "#c7a8ff",
        "accent_text": "#160d26",
        "secondary": "#211a36",
        "input": "#100d1c",
        "selection": "#352450",
        "table_alt": "#100e1d",
        "scroll": "#59427d",
        "shadow": "#07060d",
    },
    "light": {
        "background": "#f3f0fa",
        "surface": "#faf8ff",
        "card": "#ffffff",
        "card_hover": "#f5f0ff",
        "border": "#ded6ee",
        "text": "#211833",
        "muted": "#756888",
        "accent": "#7446c8",
        "accent_hover": "#613ab0",
        "accent_text": "#ffffff",
        "secondary": "#eee8f8",
        "input": "#faf8ff",
        "selection": "#eadfff",
        "table_alt": "#f8f6fc",
        "scroll": "#c4b5dc",
        "shadow": "#e5ddf0",
    },
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff6685",
    "HIGH": "#ffad66",
    "MEDIUM": "#f5d166",
    "LOW": "#63d7b2",
}


def scanner_binary_path() -> Path:
    name = "scanner_core.exe" if sys.platform == "win32" else "scanner_core"
    application_dir = Path(__file__).resolve().parent.parent
    bundle_dir = Path(getattr(sys, "_MEIPASS", application_dir))
    candidates = (
        bundle_dir / name,
        application_dir / name,
        application_dir / "build" / "bin" / name,
        application_dir / "build" / "cmake" / "bin" / name,
    )
    return next((candidate for candidate in candidates if candidate.is_file()), candidates[0])


def asset_path(name: str) -> Path:
    if Path(name).name != name or name in {"", ".", ".."}:
        raise ValueError("Asset names must be a single filename.")
    application_dir = Path(__file__).resolve().parent.parent
    bundle_dir = Path(getattr(sys, "_MEIPASS", application_dir))
    executable_dir = (
        Path(sys.executable).resolve().parent
        if getattr(sys, "frozen", False)
        else application_dir
    )
    candidates = (
        bundle_dir / "assets" / name,
        executable_dir / "assets" / name,
        application_dir / "assets" / name,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"ProtoSec asset is missing: {name}")


class FindingsTableModel(QAbstractTableModel):
    HEADERS = ("SEVERITY", "DETECTION", "LOCATION", "ACTION")

    def __init__(self, parent=None):
        super().__init__(parent)
        self._findings = []
        self._visible_rows = []
        self._query = ""
        self._severity = "ALL SEVERITIES"

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._visible_rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        finding = self._findings[self._visible_rows[index.row()]]
        column = index.column()
        if role == Qt.ItemDataRole.UserRole:
            return finding
        if role == Qt.ItemDataRole.ToolTipRole:
            return str(finding.get("file_path", ""))
        if role == Qt.ItemDataRole.ForegroundRole and column == 0:
            severity = str(finding.get("severity", "MEDIUM")).upper()
            return QColor(SEVERITY_COLORS.get(severity, "#8294aa"))
        if role == Qt.ItemDataRole.TextAlignmentRole and column == 3:
            return int(Qt.AlignmentFlag.AlignCenter)
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if column == 0:
            return f"  {str(finding.get('severity', 'MEDIUM')).upper()}"
        if column == 1:
            return f"{finding.get('rule_id', 'GEN-000')}   {finding.get('title', 'Security finding')}"
        if column == 2:
            return f"{finding.get('file_path', '')}:{finding.get('line_number', '')}"
        return "Copy"

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
            and 0 <= section < len(self.HEADERS)
        ):
            return self.HEADERS[section]
        return None

    def finding_at(self, visible_row: int) -> dict | None:
        if not 0 <= visible_row < len(self._visible_rows):
            return None
        return self._findings[self._visible_rows[visible_row]]

    def set_findings(self, findings: list[dict]):
        self.beginResetModel()
        self._findings = findings
        self._update_visible_rows()
        self.endResetModel()

    def set_filter(self, query: str, severity: str):
        query = query.strip().casefold()
        severity = severity.upper()
        if query == self._query and severity == self._severity:
            return
        self.beginResetModel()
        self._query = query
        self._severity = severity
        self._update_visible_rows()
        self.endResetModel()

    def _update_visible_rows(self):
        self._visible_rows = []
        for index, finding in enumerate(self._findings):
            severity = str(finding.get("severity", "MEDIUM")).upper()
            if self._severity != "ALL SEVERITIES" and severity != self._severity:
                continue
            if self._query:
                searchable = " ".join(
                    (
                        severity,
                        str(finding.get("rule_id", "")),
                        str(finding.get("title", "")),
                        str(finding.get("file_path", "")),
                        str(finding.get("line_number", "")),
                    )
                ).casefold()
                if self._query not in searchable:
                    continue
            self._visible_rows.append(index)


class ScanWorker(QThread):
    progress = pyqtSignal(str, int, int, str)
    completed = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(
        self,
        folder_path: str,
        scan_cve: bool = False,
        check_package_reputation: bool = False,
        scan_history: bool = False,
        force_hash_paths: set[str] | None = None,
    ):
        super().__init__()
        self.folder_path = folder_path
        self.scan_cve = scan_cve
        self.check_package_reputation = check_package_reputation
        self.scan_history = scan_history
        self.force_hash_paths = set(force_hash_paths or ())

    def run(self):
        try:
            report = scan_incremental_project(
                self.folder_path,
                progress_callback=self.progress.emit,
                force_hash_paths=self.force_hash_paths,
            )
            if self.scan_cve:
                report = merge_findings(
                    report,
                    scan_dependencies(self.folder_path),
                )
            if self.check_package_reputation:
                report = merge_findings(
                    report,
                    audit_package_reputation(self.folder_path),
                )
            if self.scan_history:
                report = merge_findings(
                    report,
                    scan_git_history(self.folder_path),
                )
            self.completed.emit(report)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            self.failed.emit(str(exc))


class CveUpdateWorker(QThread):
    progress = pyqtSignal(str, int, int, str)
    completed = pyqtSignal(str, int)
    failed = pyqtSignal(str)

    def run(self):
        try:
            path, count = update_database(progress_callback=self.progress.emit)
            self.completed.emit(str(path), count)
        except (OSError, ValueError, RuntimeError, sqlite3.Error, zipfile.BadZipFile) as exc:
            self.failed.emit(str(exc))


class LiveWatchSetupWorker(QThread):
    completed = pyqtSignal(str, list, list, bool)
    failed = pyqtSignal(str, str)

    def __init__(self, root_path: str, parent=None):
        super().__init__(parent)
        self.root_path = root_path

    def run(self):
        directories = []
        source_files = []
        limited = False

        def raise_walk_error(error):
            raise error

        try:
            for current_root, dirs, filenames in os.walk(
                self.root_path, onerror=raise_walk_error
            ):
                if self.isInterruptionRequested():
                    return
                dirs[:] = [
                    name
                    for name in dirs
                    if name not in SKIP_DIRS
                    and not (Path(current_root) / name).is_symlink()
                ]
                if len(directories) < 1096:
                    directories.append(current_root)
                else:
                    limited = True
                for filename in filenames:
                    if self.isInterruptionRequested():
                        return
                    path = Path(current_root) / filename
                    if path.is_symlink():
                        continue
                    lower_name = filename.lower()
                    dependency_manifest = lower_name == "package-lock.json" or (
                        lower_name.startswith("requirements") and path.suffix.lower() == ".txt"
                    )
                    if (
                        path.suffix.lower() not in ALLOWED_EXTENSIONS
                        and not lower_name.startswith(".env")
                        and not dependency_manifest
                    ):
                        continue
                    if len(source_files) < 3000:
                        source_files.append(str(path))
                    else:
                        limited = True
                if len(directories) >= 1096 and len(source_files) >= 3000:
                    limited = True
                    break
            self.completed.emit(self.root_path, source_files, directories, limited)
        except OSError as exc:
            self.failed.emit(self.root_path, str(exc))


class PassiveProbeWorker(QThread):
    completed = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, url: str, authorized: bool, parent=None):
        super().__init__(parent)
        self.url = url
        self.authorized = authorized

    def run(self):
        try:
            self.completed.emit(probe_security_headers(self.url, self.authorized))
        except (OSError, RuntimeError, ValueError) as exc:
            self.failed.emit(str(exc))


class PassiveHeadersDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Passive security-header check")
        self.resize(680, 440)
        self.worker = None
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "Makes one HEAD request to the origin only. It does not read page data, "
            "follow redirects, or test rate limits."
        ))
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://staging.example.com or http://localhost:3000")
        layout.addWidget(self.url_edit)
        self.authorized_checkbox = QCheckBox(
            "I own or am authorized to check this non-local host"
        )
        layout.addWidget(self.authorized_checkbox)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("Header results will appear here.")
        layout.addWidget(self.output, 1)
        buttons = QHBoxLayout()
        buttons.addStretch()
        self.check_button = QPushButton("Check headers")
        self.check_button.clicked.connect(self._start_probe)
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.reject)
        buttons.addWidget(self.check_button)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)

    def _start_probe(self):
        self.check_button.setEnabled(False)
        self.output.setPlainText("Checking the origin…")
        self.worker = PassiveProbeWorker(
            self.url_edit.text(),
            self.authorized_checkbox.isChecked(),
            self,
        )
        self.worker.completed.connect(self._show_result)
        self.worker.failed.connect(self._show_error)
        self.worker.start()

    def _show_result(self, result: dict):
        self.check_button.setEnabled(True)
        self.output.setPlainText(json.dumps(result, indent=2))

    def _show_error(self, message: str):
        self.check_button.setEnabled(True)
        self.output.setPlainText("Header check failed:\n" + message)

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.worker.wait()
        super().closeEvent(event)


class AutoPatchPreviewDialog(QDialog):
    def __init__(self, root_path: str, plan: PatchPlan, parent=None):
        super().__init__(parent)
        self.root_path = root_path
        self.plan = plan
        self.setWindowTitle("Review safe auto-patches")
        self.resize(900, 600)
        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.file_list = QListWidget()
        self.file_list.addItems([item.relative_path for item in plan.files])
        self.diff_view = QPlainTextEdit()
        self.diff_view.setReadOnly(True)
        preview = plan.unified_diff
        if plan.skipped:
            preview += "\n\nSkipped for safety:\n" + "\n".join(plan.skipped)
        self.diff_view.setPlainText(preview or "No safe automatic changes were found.")
        splitter.addWidget(self.file_list)
        splitter.addWidget(self.diff_view)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        buttons = QHBoxLayout()
        buttons.addStretch()
        self.apply_button = QPushButton("Apply Patch")
        self.apply_button.setEnabled(bool(plan.files))
        self.apply_button.clicked.connect(self.apply_patch)
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.reject)
        buttons.addWidget(self.apply_button)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)

    def apply_patch(self):
        answer = QMessageBox.question(
            self,
            "Apply reviewed changes?",
            "Apply these exact changes to the project? Files changed since preview will be rejected.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            changed = apply_patch_plan(self.root_path, self.plan)
        except (OSError, RuntimeError, ValueError) as exc:
            QMessageBox.critical(self, "Patch not applied", str(exc))
            return
        QMessageBox.information(self, "Patch applied", "Updated:\n" + "\n".join(changed))
        self.accept()


class ProtoSecWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ProtoSec v1.0.0 — Local Security Workbench")
        self.setMinimumSize(560, 460)
        self.resize(1320, 860)
        self.setAcceptDrops(True)
        self.theme_name = "dark"
        self.selected_folder = ""
        self.findings = []
        self.current_report = None
        self.worker = None
        self.cve_update_worker = None
        self.live_watch_worker = None
        self._live_watch_refresh_pending = False
        self._live_scan_in_progress = False
        self._live_change_pending = False
        self._score_animation = None
        self._icon_cache = {}
        self._pending_changed_files = set()
        self.pro_active, self.license_status = is_pro_unlocked()
        self._ui_ready = False

        self.root = QWidget()
        self.root.setObjectName("appRoot")
        self.setCentralWidget(self.root)

        self._build_ui()
        self._build_menu_bar()
        self._apply_icons()
        self._configure_live_guard()
        self._ui_ready = True
        self._update_responsive_layout(self.width(), self.height())
        self._apply_theme()

    def _build_ui(self):
        shell = QHBoxLayout(self.root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        self.sidebar = sidebar
        sidebar.setFixedWidth(226)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(22, 24, 18, 22)
        side_layout.setSpacing(18)

        brand = QHBoxLayout()
        mark = QLabel("⌁")
        mark.setObjectName("brandMark")
        self.brand_mark = mark
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setFixedSize(38, 38)
        wordmark = QVBoxLayout()
        brand_name = QLabel("PROTOSEC")
        brand_name.setObjectName("brandName")
        brand_caption = QLabel("LOCAL SECURITY")
        brand_caption.setObjectName("brandCaption")
        brand_caption.setWordWrap(True)
        wordmark.addWidget(brand_name)
        wordmark.addWidget(brand_caption)
        brand.addWidget(mark)
        brand.addSpacing(10)
        brand.addLayout(wordmark)
        brand.addStretch()
        side_layout.addLayout(brand)

        section_label = QLabel("WORKSPACE")
        section_label.setObjectName("sectionLabel")
        side_layout.addWidget(section_label)
        workspace_chip = QLabel("◈    Security overview")
        workspace_chip.setObjectName("workspaceChip")
        side_layout.addWidget(workspace_chip)

        side_layout.addStretch()
        privacy_card = QFrame()
        privacy_card.setObjectName("privacyCard")
        privacy_layout = QVBoxLayout(privacy_card)
        privacy_layout.setContentsMargins(14, 14, 14, 14)
        privacy_layout.setSpacing(6)
        privacy_title = QLabel("◉  PRIVATE BY DESIGN")
        privacy_title.setObjectName("privacyTitle")
        privacy_text = QLabel("Your source code stays on this machine.")
        privacy_text.setObjectName("privacyText")
        privacy_text.setWordWrap(True)
        privacy_layout.addWidget(privacy_title)
        privacy_layout.addWidget(privacy_text)
        side_layout.addWidget(privacy_card)

        engine_status = QLabel("●  LOCAL ENGINE READY")
        engine_status.setObjectName("engineStatus")
        side_layout.addWidget(engine_status)
        shell.addWidget(sidebar)

        content = QWidget()
        content.setObjectName("content")
        content_layout = QVBoxLayout(content)
        self.content_layout = content_layout
        content_layout.setContentsMargins(32, 26, 32, 28)
        content_layout.setSpacing(20)

        topbar = QHBoxLayout()
        self.topbar_layout = topbar
        heading = QVBoxLayout()
        eyebrow = QLabel("PROTOSEC v1.0.0   /   LOCAL MODE")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Project overview")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Scan locally. Find issues. Keep your code private.")
        subtitle.setObjectName("subtitle")
        heading.addWidget(eyebrow)
        heading.addWidget(title)
        heading.addWidget(subtitle)
        heading_widget = QWidget()
        heading_widget.setLayout(heading)
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        self.actions_layout = actions_layout
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(12)
        self.license_button = QPushButton("Pro active" if self.pro_active else "Activate license")
        self.license_button.setObjectName("themeButton")
        self.license_button.clicked.connect(self.activate_license)
        actions_layout.addWidget(self.license_button)
        self.export_json_button = QPushButton("JSON")
        self.export_json_button.setObjectName("themeButton")
        self.export_json_button.setEnabled(False)
        self.export_json_button.clicked.connect(self.export_json)
        actions_layout.addWidget(self.export_json_button)
        self.export_html_button = QPushButton("HTML")
        self.export_html_button.setObjectName("themeButton")
        self.export_html_button.setEnabled(False)
        self.export_html_button.clicked.connect(self.export_html)
        actions_layout.addWidget(self.export_html_button)
        self.theme_button = QPushButton("Switch to light")
        self.theme_button.setObjectName("themeButton")
        self.theme_button.clicked.connect(self.toggle_theme)
        actions_layout.addWidget(self.theme_button)
        topbar.addWidget(heading_widget, 1)
        topbar.addWidget(actions_widget)
        content_layout.addLayout(topbar)

        scan_card = QFrame()
        scan_card.setObjectName("scanCard")
        scan_layout = QVBoxLayout(scan_card)
        scan_layout.setContentsMargins(20, 18, 20, 18)
        scan_layout.setSpacing(12)
        scan_heading = QHBoxLayout()
        self.scan_heading_layout = scan_heading
        scan_title = QLabel("TARGET PROJECT")
        scan_title.setObjectName("cardEyebrow")
        scan_heading.addWidget(scan_title)
        self.scan_cve_checkbox = QCheckBox("Scan CVE")
        self.scan_cve_checkbox.setObjectName("scanCveCheckbox")
        self.scan_cve_checkbox.setChecked(False)
        self._update_cve_scan_tooltip()
        scan_heading.addWidget(self.scan_cve_checkbox)
        self.live_guard_checkbox = QCheckBox("Live Guard")
        self.live_guard_checkbox.setObjectName("liveGuardCheckbox")
        self.live_guard_checkbox.setToolTip(
            "Watch the selected project and rescan after file changes."
        )
        scan_heading.addWidget(self.live_guard_checkbox)
        scan_heading.addStretch()
        self.engine_badge = QLabel("◉  ENGINE AUTO-DETECT")
        self.engine_badge.setObjectName("engineBadge")
        scan_heading.addWidget(self.engine_badge)
        scan_layout.addLayout(scan_heading)

        picker_row = QHBoxLayout()
        self.picker_layout = picker_row
        self.path_input = QLineEdit()
        self.path_input.setObjectName("pathInput")
        self.path_input.setReadOnly(True)
        self.path_input.setPlaceholderText("Choose a project folder to inspect…")
        picker_row.addWidget(self.path_input, 1)
        self.browse_button = QPushButton("Browse")
        self.browse_button.setObjectName("secondaryButton")
        self.browse_button.clicked.connect(self.choose_folder)
        picker_row.addWidget(self.browse_button)
        self.scan_button = QPushButton("Run scan")
        self.scan_button.setObjectName("primaryButton")
        self.scan_button.setEnabled(False)
        self.scan_button.clicked.connect(self.run_scan)
        picker_row.addWidget(self.scan_button)
        scan_layout.addLayout(picker_row)

        progress_row = QHBoxLayout()
        self.progress_layout = progress_row
        self.progress_label = QLabel("Choose a folder to begin.")
        self.progress_label.setObjectName("progressLabel")
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("scanProgress")
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedWidth(190)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_row.addWidget(self.progress_label, 1)
        progress_row.addWidget(self.progress_bar)
        scan_layout.addLayout(progress_row)
        content_layout.addWidget(scan_card)

        stats_row = QHBoxLayout()
        self.stats_layout = stats_row
        stats_row.setSpacing(14)
        score_card, self.score_value, self.score_caption = self._stat_card(
            "SECURITY SCORE", "--", "Awaiting first scan", "scoreCard"
        )
        issues_card, self.issue_value, self.issue_caption = self._stat_card(
            "FINDINGS", "—", "Detected in target", "issuesCard"
        )
        engine_card, self.engine_value, self.engine_caption = self._stat_card(
            "SCAN ENGINE", "AUTO", "C++ core or Python fallback", "engineCard"
        )
        stats_row.addWidget(score_card, 1)
        stats_row.addWidget(issues_card, 1)
        stats_row.addWidget(engine_card, 1)
        content_layout.addLayout(stats_row)

        findings_header = QHBoxLayout()
        self.findings_header_layout = findings_header
        findings_title = QVBoxLayout()
        findings_heading = QLabel("Findings")
        findings_heading.setObjectName("sectionTitle")
        findings_subtitle = QLabel("Select a finding to inspect its evidence and remediation prompt.")
        findings_subtitle.setObjectName("subtitle")
        findings_title.addWidget(findings_heading)
        findings_title.addWidget(findings_subtitle)
        findings_title_widget = QWidget()
        findings_title_widget.setLayout(findings_title)
        findings_controls = QWidget()
        findings_controls_layout = QHBoxLayout(findings_controls)
        self.findings_controls_layout = findings_controls_layout
        findings_controls_layout.setContentsMargins(0, 0, 0, 0)
        findings_controls_layout.setSpacing(12)
        self.search_input = QLineEdit()
        self.search_input.setObjectName("searchInput")
        self.search_input.setPlaceholderText("⌕   Search findings")
        self.search_input.setMinimumWidth(0)
        self.search_input.setMaximumWidth(220)
        self.search_input.textChanged.connect(self._queue_findings_filter)
        findings_controls_layout.addWidget(self.search_input, 1)
        self.severity_filter = QComboBox()
        self.severity_filter.setObjectName("severityFilter")
        self.severity_filter.setMinimumWidth(0)
        self.severity_filter.setMaximumWidth(156)
        self.severity_filter.addItems(["All severities", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self._queue_findings_filter)
        findings_controls_layout.addWidget(self.severity_filter, 1)
        findings_header.addWidget(findings_title_widget, 1)
        findings_header.addWidget(findings_controls)
        content_layout.addLayout(findings_header)

        self.table_model = FindingsTableModel(self)
        self.table = QTableView()
        self.table.setObjectName("findingsTable")
        self.table.setModel(self.table_model)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.verticalHeader().setMinimumSectionSize(36)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setWordWrap(False)
        self.table.setMinimumHeight(190)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 108)
        self.table.setColumnWidth(2, 190)
        self.table.setColumnWidth(3, 76)
        self.table.selectionModel().currentChanged.connect(self._show_selected_finding)
        self.table.clicked.connect(self._copy_row_prompt)
        content_layout.addWidget(self.table, 1)
        self.table.hide()

        self.empty_state = QLabel("No scan results yet. Choose a project folder and run a scan.")
        self.empty_state.setObjectName("emptyState")
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(self.empty_state)

        detail_card = QFrame()
        detail_card.setObjectName("detailCard")
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(18, 15, 18, 16)
        detail_layout.setSpacing(10)
        detail_header = QHBoxLayout()
        detail_title = QLabel("REMEDIATION PROMPT")
        detail_title.setObjectName("cardEyebrow")
        detail_header.addWidget(detail_title)
        detail_header.addStretch()
        self.auto_fix_button = QPushButton("Auto-fix safe issues")
        self.auto_fix_button.setObjectName("secondaryButton")
        self.auto_fix_button.setEnabled(False)
        self.auto_fix_button.clicked.connect(self.preview_auto_patches)
        detail_header.addWidget(self.auto_fix_button)
        self.copy_button = QPushButton("Copy prompt")
        self.copy_button.setObjectName("secondaryButton")
        self.copy_button.setEnabled(False)
        self.copy_button.clicked.connect(self.copy_selected_prompt)
        detail_header.addWidget(self.copy_button)
        detail_layout.addLayout(detail_header)
        self.detail_prompt = QLabel("Select a finding above to see a suggested fix prompt.")
        self.detail_prompt.setObjectName("detailPrompt")
        self.detail_prompt.setWordWrap(True)
        self.detail_prompt.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        detail_layout.addWidget(self.detail_prompt)
        content_layout.addWidget(detail_card)
        self.main_scroll_area = QScrollArea()
        self.main_scroll_area.setObjectName("mainScrollArea")
        self.main_scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.main_scroll_area.setWidgetResizable(True)
        self.main_scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.main_scroll_area.viewport().setObjectName("mainScrollViewport")
        self.main_scroll_area.viewport().setAutoFillBackground(True)
        self.main_scroll_area.setWidget(content)
        shell.addWidget(self.main_scroll_area, 1)
        self.findings_filter_timer = QTimer(self)
        self.findings_filter_timer.setSingleShot(True)
        self.findings_filter_timer.setInterval(140)
        self.findings_filter_timer.timeout.connect(self._filter_findings)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready · scans run locally and source files are not uploaded.")

    def _build_menu_bar(self):
        file_menu = self.menuBar().addMenu("&File")
        open_action = QAction("Choose project folder…", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.choose_folder)
        file_menu.addAction(open_action)

        scan_action = QAction("Run scan", self)
        scan_action.setShortcut("Ctrl+R")
        scan_action.triggered.connect(self.run_scan)
        file_menu.addAction(scan_action)
        file_menu.addSeparator()
        file_menu.addAction("Export JSON report", self.export_json)
        file_menu.addAction("Export HTML report", self.export_html)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        view_menu = self.menuBar().addMenu("&View")
        theme_action = QAction("Toggle theme", self)
        theme_action.setShortcut("Ctrl+T")
        theme_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(theme_action)

        tools_menu = self.menuBar().addMenu("&Tools")
        self.scan_cve_action = QAction("Scan CVE", self)
        self.scan_cve_action.setCheckable(True)
        self.scan_cve_action.setChecked(False)
        tools_menu.addAction(self.scan_cve_action)
        self.scan_cve_action.toggled.connect(self.scan_cve_checkbox.setChecked)
        self.scan_cve_checkbox.toggled.connect(self.scan_cve_action.setChecked)
        self.update_cve_action = QAction("Update CVE database…", self)
        self.update_cve_action.triggered.connect(self.update_cve_database)
        tools_menu.addAction(self.update_cve_action)
        self.auto_patch_action = QAction("Auto-fix safe issues…", self)
        self.auto_patch_action.triggered.connect(self.preview_auto_patches)
        tools_menu.addAction(self.auto_patch_action)
        self.install_hook_action = QAction("Install pre-commit hook…", self)
        self.install_hook_action.triggered.connect(self.install_git_hook)
        tools_menu.addAction(self.install_hook_action)
        self.probe_headers_action = QAction("Check security headers…", self)
        self.probe_headers_action.triggered.connect(self.open_passive_header_check)
        tools_menu.addAction(self.probe_headers_action)
        self.package_reputation_action = QAction("Check package names online", self)
        self.package_reputation_action.setCheckable(True)
        self.package_reputation_action.setToolTip(
            "When enabled for a manual scan, sends dependency names to the public npm and PyPI registries."
        )
        tools_menu.addAction(self.package_reputation_action)
        self.history_scan_action = QAction("Scan Git history for secrets", self)
        self.history_scan_action.setCheckable(True)
        self.history_scan_action.setToolTip(
            "When enabled for a manual scan, inspects up to 100 local commits; secret values stay redacted."
        )
        tools_menu.addAction(self.history_scan_action)
        self.live_guard_action = QAction("Live Guard", self)
        self.live_guard_action.setCheckable(True)
        tools_menu.addAction(self.live_guard_action)
        self.live_guard_action.toggled.connect(self.live_guard_checkbox.setChecked)
        self.live_guard_checkbox.toggled.connect(self.set_live_guard)

        help_menu = self.menuBar().addMenu("&Help")
        about_action = QAction("About ProtoSec", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        self.open_action = open_action
        self.scan_menu_action = scan_action
        self.theme_action = theme_action
        self.about_action = about_action

    def _accent_icon(self, filename: str) -> QIcon:
        cache_key = (filename, self.theme_name)
        if cache_key in self._icon_cache:
            return self._icon_cache[cache_key]
        source = QIcon(str(asset_path(filename)))
        pixmap = source.pixmap(QSize(18, 18))
        if pixmap.isNull():
            raise RuntimeError(f"Could not load ProtoSec icon: {filename}")
        tinted = QPixmap(pixmap.size())
        tinted.fill(Qt.GlobalColor.transparent)
        painter = QPainter(tinted)
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
        painter.fillRect(tinted.rect(), QColor(THEMES[self.theme_name]["accent"]))
        painter.end()
        icon = QIcon(tinted)
        self._icon_cache[cache_key] = icon
        return icon

    def _apply_icons(self):
        brand_icon = self._accent_icon("shield-check.svg")
        self.setWindowIcon(brand_icon)
        self.brand_mark.setText("")
        self.brand_mark.setPixmap(brand_icon.pixmap(QSize(23, 23)))
        self.license_button.setIcon(self._accent_icon("shield-check.svg"))
        self.export_json_button.setIcon(self._accent_icon("download.svg"))
        self.export_html_button.setIcon(self._accent_icon("download.svg"))
        self.theme_button.setIcon(
            self._accent_icon("moon.svg" if self.theme_name == "dark" else "sun.svg")
        )
        self.browse_button.setIcon(self._accent_icon("folder-open.svg"))
        self.scan_button.setIcon(self._accent_icon("scan-search.svg"))
        self.copy_button.setIcon(self._accent_icon("copy.svg"))
        self.open_action.setIcon(self._accent_icon("folder-open.svg"))
        self.scan_menu_action.setIcon(self._accent_icon("scan-search.svg"))
        self.scan_cve_action.setIcon(self._accent_icon("bug.svg"))
        self.update_cve_action.setIcon(self._accent_icon("download.svg"))
        self.auto_patch_action.setIcon(self._accent_icon("wand-sparkles.svg"))
        self.install_hook_action.setIcon(self._accent_icon("shield-check.svg"))
        self.probe_headers_action.setIcon(self._accent_icon("scan-search.svg"))
        self.package_reputation_action.setIcon(self._accent_icon("bug.svg"))
        self.history_scan_action.setIcon(self._accent_icon("git-branch.svg"))
        self.live_guard_action.setIcon(self._accent_icon("eye.svg"))
        self.theme_action.setIcon(self._accent_icon("moon.svg"))
        self.about_action.setIcon(self._accent_icon("info.svg"))
        for button in (
            self.license_button,
            self.export_json_button,
            self.export_html_button,
            self.theme_button,
            self.browse_button,
            self.scan_button,
            self.copy_button,
            self.auto_fix_button,
            self.live_guard_checkbox,
        ):
            if isinstance(button, QPushButton):
                button.setIconSize(QSize(18, 18))

    def _configure_live_guard(self):
        self.file_watcher = QFileSystemWatcher(self)
        self.file_watcher.directoryChanged.connect(self._queue_live_scan)
        self.file_watcher.fileChanged.connect(self._queue_live_scan)
        self.live_scan_timer = QTimer(self)
        self.live_scan_timer.setSingleShot(True)
        self.live_scan_timer.setInterval(800)
        self.live_scan_timer.timeout.connect(self._run_live_scan)
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.windowIcon())
        self.tray_icon.setVisible(QSystemTrayIcon.isSystemTrayAvailable())

    def set_live_guard(self, enabled: bool):
        if enabled and not self.selected_folder:
            self.status_bar.showMessage("Choose a project folder before enabling Live Guard.")
            self.live_guard_checkbox.setChecked(False)
            self.live_guard_action.setChecked(False)
            return
        if not enabled:
            paths = self.file_watcher.directories() + self.file_watcher.files()
            if paths:
                self.file_watcher.removePaths(paths)
            self.live_scan_timer.stop()
            self._live_change_pending = False
            self._live_watch_refresh_pending = False
            self._pending_changed_files.clear()
            self.status_bar.showMessage("Live Guard stopped.")
            return
        self._refresh_live_watch_paths()
        self.status_bar.showMessage("Preparing Live Guard watches…")

    def _refresh_live_watch_paths(self):
        if not self.selected_folder or not self.live_guard_checkbox.isChecked():
            return
        if self.live_watch_worker is not None and self.live_watch_worker.isRunning():
            self._live_watch_refresh_pending = True
            return
        self._live_watch_refresh_pending = False
        self.live_watch_worker = LiveWatchSetupWorker(self.selected_folder, self)
        self.live_watch_worker.completed.connect(self._live_watch_paths_ready)
        self.live_watch_worker.failed.connect(self._live_watch_setup_failed)
        self.live_watch_worker.start()

    def _live_watch_paths_ready(
        self, root_path: str, source_files: list, directories: list, limited: bool
    ):
        self.live_watch_worker = None
        if not self.live_guard_checkbox.isChecked():
            return
        if root_path != self.selected_folder:
            self._refresh_live_watch_paths()
            return
        watch_paths = source_files + directories
        current_paths = set(self.file_watcher.directories() + self.file_watcher.files())
        desired_paths = set(watch_paths)
        stale = sorted(current_paths - desired_paths)
        if stale:
            self.file_watcher.removePaths(stale)
        missing = sorted(desired_paths - current_paths)
        failed = self.file_watcher.addPaths(missing) if missing else []
        if limited or failed:
            self.status_bar.showMessage(
                f"Live Guard is watching {len(watch_paths) - len(failed)} paths; "
                "some project paths may not be watched because of watch limits.",
                8000,
            )
        elif not self.worker or not self.worker.isRunning():
            self.status_bar.showMessage("Live Guard is watching the selected project.")
        if self._live_watch_refresh_pending:
            self._refresh_live_watch_paths()

    def _live_watch_setup_failed(self, root_path: str, message: str):
        self.live_watch_worker = None
        if self.live_guard_checkbox.isChecked() and root_path == self.selected_folder:
            self.status_bar.showMessage(f"Live Guard could not watch the project: {message}", 10000)
        if self._live_watch_refresh_pending:
            self._refresh_live_watch_paths()

    def _queue_live_scan(self, _path: str):
        if not self.live_guard_checkbox.isChecked():
            return
        if _path in self.file_watcher.files():
            self._pending_changed_files.add(_path)
        self._live_change_pending = True
        self.live_scan_timer.start()

    def _run_live_scan(self):
        if not self._live_change_pending:
            return
        if (
            self.worker is not None and self.worker.isRunning()
            or self.cve_update_worker is not None and self.cve_update_worker.isRunning()
        ):
            self.live_scan_timer.start()
            return
        self._refresh_live_watch_paths()
        self._live_change_pending = False
        self._live_scan_in_progress = True
        self._start_scan(include_optional_checks=False)

    def _notify_live_findings(self):
        if not self._live_scan_in_progress:
            return
        self._live_scan_in_progress = False
        if self.findings:
            prompt = self.findings[0].get("fix_prompt", "")
            if prompt:
                QApplication.clipboard().setText(prompt)
            message = f"Found {len(self.findings)} issue(s); the first fix prompt is on the clipboard."
            if self.tray_icon.isVisible():
                self.tray_icon.showMessage(
                    "ProtoSec Live Guard",
                    message,
                    QSystemTrayIcon.MessageIcon.Warning,
                    6000,
                )
            self.status_bar.showMessage(message, 8000)
        if self._live_change_pending:
            self.live_scan_timer.start()

    def show_about(self):
        QMessageBox.about(
            self,
            "About ProtoSec",
            "ProtoSec v1.0.0\nLocal-first security scanning with no code uploads.",
        )

    def _update_cve_scan_tooltip(self):
        database = database_path()
        if database.is_file():
            description = "Scan pinned npm/PyPI dependencies against the local OSV database"
        else:
            description = "No local OSV database is installed. Choose Tools > Update CVE database"
        self.scan_cve_checkbox.setToolTip(f"{description}: {database}")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._ui_ready:
            self._update_responsive_layout(event.size().width(), event.size().height())

    def closeEvent(self, event):
        if self.live_watch_worker is not None and self.live_watch_worker.isRunning():
            self.live_watch_worker.requestInterruption()
            self.live_watch_worker.wait()
        self.tray_icon.hide()
        super().closeEvent(event)

    def _update_responsive_layout(self, width: int, height: int):
        compact = width < 1180
        narrow = width < 640
        self.sidebar.setFixedWidth(190 if compact else 226)
        self.sidebar.setVisible(width > 820)
        self.topbar_layout.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        narrow_direction = (
            QBoxLayout.Direction.TopToBottom
            if narrow
            else QBoxLayout.Direction.LeftToRight
        )
        for layout in (
            self.actions_layout,
            self.scan_heading_layout,
            self.picker_layout,
            self.progress_layout,
            self.stats_layout,
            self.findings_controls_layout,
        ):
            layout.setDirection(narrow_direction)
        self.findings_header_layout.setDirection(
            QBoxLayout.Direction.TopToBottom if width < 1100 else QBoxLayout.Direction.LeftToRight
        )
        horizontal_margin = 10 if narrow else 16 if width <= 820 else 24 if compact else 32
        vertical_margin = 12 if height < 560 else 16 if height < 700 else 26
        self.content_layout.setContentsMargins(
            horizontal_margin,
            vertical_margin,
            horizontal_margin,
            12 if height < 560 else 18 if height < 700 else 28,
        )
        self.content_layout.setSpacing(10 if narrow or height < 560 else 12 if height < 700 else 20)
        self.progress_bar.setFixedWidth(115 if narrow else 130 if width < 900 else 190)
        self.search_input.setMaximumWidth(220)
        self.severity_filter.setMaximumWidth(156)
        self.table.setColumnWidth(0, 94 if narrow else 108)
        self.table.setColumnWidth(2, 108 if narrow else 150 if width < 900 else 190)
        self.table.setColumnWidth(3, 64 if narrow else 76)

    def _stat_card(self, heading: str, value: str, caption: str, name: str):
        card = QFrame()
        card.setObjectName(name)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 15, 18, 15)
        layout.setSpacing(5)
        title = QLabel(heading)
        title.setObjectName("cardEyebrow")
        number = QLabel(value)
        number.setObjectName("statValue")
        footnote = QLabel(caption)
        footnote.setObjectName("statCaption")
        layout.addWidget(title)
        layout.addWidget(number)
        layout.addWidget(footnote)
        return card, number, footnote

    def _apply_theme(self):
        colors = THEMES[self.theme_name]
        self.setStyleSheet(
            """
            QMainWindow { background: %(background)s; }
            QWidget#appRoot { background: %(background)s; color: %(text)s; }
            QWidget { color: %(text)s; font-family: "Segoe UI Variable", "Segoe UI", sans-serif; font-size: 10pt; }
            QFrame#sidebar { background: %(surface)s; border-right: 1px solid %(border)s; }
            QWidget#content, QWidget#mainScrollViewport { background: %(background)s; }
            QMenuBar, QMenu { background: %(surface)s; color: %(text)s; }
            QMenuBar::item:selected, QMenu::item:selected { background: %(selection)s; color: %(accent)s; }
            QLabel#brandMark { color: %(accent)s; background: %(selection)s; border: 1px solid %(border)s; border-radius: 12px; font-size: 23pt; font-weight: 700; }
            QLabel#brandName { font-size: 11pt; font-weight: 800; letter-spacing: 1px; }
            QLabel#brandCaption, QLabel#sectionLabel, QLabel#eyebrow, QLabel#cardEyebrow { color: %(muted)s; font-size: 8pt; font-weight: 700; letter-spacing: 1.1px; }
            QLabel#brandCaption { font-size: 7pt; letter-spacing: 0.4px; }
            QLabel#sectionLabel { margin-top: 21px; }
            QLabel#workspaceChip { background: %(selection)s; color: %(accent)s; border: 1px solid %(border)s; border-radius: 8px; padding: 11px 10px; font-weight: 650; }
            QFrame#privacyCard, QFrame#scanCard, QFrame#scoreCard, QFrame#issuesCard, QFrame#engineCard, QFrame#detailCard { background: %(card)s; border: 1px solid %(border)s; border-radius: 13px; }
            QScrollArea#mainScrollArea { border: none; background: %(background)s; }
            QStatusBar { background: %(surface)s; color: %(muted)s; border-top: 1px solid %(border)s; }
            QStatusBar::item { border: none; }
            QLabel#privacyTitle { color: %(accent)s; font-size: 8pt; font-weight: 800; }
            QLabel#privacyText, QLabel#subtitle, QLabel#statCaption { color: %(muted)s; }
            QLabel#engineStatus { color: %(accent)s; font-family: "Cascadia Code", "Consolas", monospace; font-size: 8pt; font-weight: 700; }
            QLabel#pageTitle { font-size: 23pt; font-weight: 750; }
            QLabel#sectionTitle { font-size: 15pt; font-weight: 700; }
            QLabel#engineBadge { background: %(selection)s; color: %(accent)s; border-radius: 8px; padding: 6px 9px; font-size: 8pt; font-weight: 700; }
            QLineEdit, QComboBox { background: %(input)s; border: 1px solid %(border)s; border-radius: 8px; padding: 10px 12px; selection-background-color: %(accent)s; }
            QLineEdit:focus, QComboBox:focus { border: 1px solid %(accent)s; }
            QLineEdit#pathInput, QLineEdit#searchInput { min-height: 20px; }
            QComboBox::drop-down { border: 0; width: 25px; }
            QCheckBox { spacing: 7px; color: %(text)s; }
            QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid %(border)s; border-radius: 4px; background: %(input)s; }
            QCheckBox::indicator:checked { background: %(accent)s; border-color: %(accent)s; }
            QPushButton { border: 1px solid %(border)s; border-radius: 8px; padding: 10px 14px; font-weight: 650; }
            QPushButton#primaryButton { background: %(accent)s; color: %(accent_text)s; border-color: %(accent)s; }
            QPushButton#primaryButton:hover { background: %(accent_hover)s; border-color: %(accent_hover)s; }
            QPushButton#secondaryButton, QPushButton#themeButton { background: %(secondary)s; color: %(text)s; }
            QPushButton#secondaryButton:hover, QPushButton#themeButton:hover { background: %(card_hover)s; border-color: %(accent)s; }
            QPushButton:disabled { background: %(secondary)s; color: %(muted)s; border-color: %(border)s; }
            QLabel#statValue { font-size: 22pt; font-weight: 750; }
            QProgressBar#scanProgress { background: %(secondary)s; border: none; border-radius: 4px; min-height: 7px; max-height: 7px; }
            QProgressBar#scanProgress::chunk { background: %(accent)s; border-radius: 4px; }
            QLabel#progressLabel { color: %(muted)s; font-size: 9pt; }
            QTableView#findingsTable { background: %(card)s; alternate-background-color: %(table_alt)s; border: 1px solid %(border)s; border-radius: 11px; padding: 4px; selection-background-color: %(selection)s; outline: 0; }
            QTableView#findingsTable::item { padding: 8px 7px; border: none; }
            QHeaderView::section { background: %(surface)s; color: %(muted)s; border: none; border-bottom: 1px solid %(border)s; padding: 10px 8px; font-size: 8pt; font-weight: 750; letter-spacing: 0.8px; }
            QLabel#emptyState { color: %(muted)s; padding: 9px; }
            QLabel#detailPrompt { color: %(text)s; background: %(input)s; border: 1px solid %(border)s; border-radius: 8px; padding: 11px 12px; font-family: "Cascadia Code", "Consolas", monospace; font-size: 9pt; }
            QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
            QScrollBar::handle:vertical { background: %(scroll)s; border-radius: 5px; min-height: 24px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
            """
            % colors
        )
        self.main_scroll_area.viewport().setStyleSheet(
            f"background-color: {colors['background']};"
        )
        self.status_bar.setStyleSheet(
            f"background-color: {colors['surface']}; color: {colors['muted']}; "
            f"border-top: 1px solid {colors['border']};"
        )

    def toggle_theme(self):
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        self.theme_button.setText("Switch to dark" if self.theme_name == "light" else "Switch to light")
        self._icon_cache.clear()
        self._apply_theme()
        self._apply_icons()

    def run_scan(self):
        self._start_scan(include_optional_checks=True)

    def _start_scan(self, include_optional_checks: bool):
        if (
            not self.selected_folder
            or (self.worker is not None and self.worker.isRunning())
            or (self.cve_update_worker is not None and self.cve_update_worker.isRunning())
        ):
            return
        self.scan_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.copy_button.setEnabled(False)
        self.auto_fix_button.setEnabled(False)
        self.progress_bar.setRange(0, 0)
        self.progress_label.setText("Starting local scanner…")
        self.engine_value.setText("RUNNING")
        self.engine_caption.setText("Analyzing selected project")
        self.current_report = None
        self.export_json_button.setEnabled(False)
        self.export_html_button.setEnabled(False)
        self.table_model.set_findings([])
        self.table.hide()
        self.findings = []
        self.empty_state.setText("Scanning local files…")
        self.empty_state.show()

        self.worker = ScanWorker(
            self.selected_folder,
            scan_cve=self.scan_cve_checkbox.isChecked(),
            check_package_reputation=(
                include_optional_checks and self.package_reputation_action.isChecked()
            ),
            scan_history=(
                include_optional_checks and self.history_scan_action.isChecked()
            ),
            force_hash_paths=set(self._pending_changed_files),
        )
        self._pending_changed_files.clear()
        self.worker.progress.connect(self._update_progress)
        self.worker.completed.connect(self._scan_completed)
        self.worker.failed.connect(self._scan_failed)
        self.worker.start()

    def preview_auto_patches(self):
        if not self.selected_folder or not self.findings:
            return
        try:
            plan = create_patch_plan(self.selected_folder, self.findings)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            QMessageBox.critical(self, "Could not prepare patch preview", str(exc))
            return
        AutoPatchPreviewDialog(self.selected_folder, plan, self).exec()

    def install_git_hook(self):
        if not self.selected_folder:
            QMessageBox.information(
                self, "Select a project", "Choose a Git repository before installing its pre-commit hook."
            )
            return
        scanner = scanner_binary_path()
        if not scanner.is_file():
            QMessageBox.warning(
                self,
                "Scanner core unavailable",
                "Build the C++ scanner before installing a pre-commit hook.",
            )
            return
        answer = QMessageBox.question(
            self,
            "Install pre-commit hook",
            "Install a local Git hook that scans staged file contents before each commit? "
            "An existing hook will never be overwritten.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Yes,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            hook_path = install_precommit_hook(Path(self.selected_folder), scanner)
        except (OSError, RuntimeError, ValueError) as exc:
            QMessageBox.critical(self, "Could not install pre-commit hook", str(exc))
            return
        QMessageBox.information(
            self,
            "Pre-commit hook installed",
            f"Staged files will be scanned before commit:\n{hook_path}",
        )

    def open_passive_header_check(self):
        PassiveHeadersDialog(self).exec()

    def update_cve_database(self):
        if (
            self.cve_update_worker is not None
            and self.cve_update_worker.isRunning()
        ):
            return
        if self.worker is not None and self.worker.isRunning():
            self.status_bar.showMessage("Wait for the current scan to finish before updating the CVE database.")
            return
        self.update_cve_action.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.progress_bar.setRange(0, 0)
        self.progress_label.setText("Downloading the official npm and PyPI OSV feeds…")
        self.cve_update_worker = CveUpdateWorker()
        self.cve_update_worker.progress.connect(self._cve_update_progress)
        self.cve_update_worker.completed.connect(self._cve_update_completed)
        self.cve_update_worker.failed.connect(self._cve_update_failed)
        self.cve_update_worker.start()

    def _cve_update_progress(self, stage: str, current: int, total: int, detail: str):
        if stage == "downloading" and total:
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(current)
            self.progress_label.setText(f"Downloading OSV {detail}: {current:,} / {total:,} bytes")
        elif stage == "indexing":
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(current)
            self.progress_label.setText(f"Indexing OSV {detail}: {current:,} / {total:,} advisories")
        else:
            self.progress_bar.setRange(0, 0)
            self.progress_label.setText(f"Preparing OSV {detail} database…")

    def _cve_update_completed(self, path: str, count: int):
        self._update_cve_scan_tooltip()
        self.update_cve_action.setEnabled(True)
        self.scan_button.setEnabled(bool(self.selected_folder))
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_label.setText(f"Local OSV database ready: {count:,} package advisories.")
        self.status_bar.showMessage(f"OSV data saved locally: {path}", 8000)

    def _cve_update_failed(self, message: str):
        self.update_cve_action.setEnabled(True)
        self.scan_button.setEnabled(bool(self.selected_folder))
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_label.setText("CVE database update failed.")
        QMessageBox.critical(self, "CVE database update failed", message)

    def _update_progress(self, stage: str, current: int, total: int, detail: str):
        if stage == "discovering":
            message = "Indexing project files"
            if detail and detail != ".":
                message += f"  ·  {detail}"
            self.progress_label.setText(message)
            self.progress_bar.setRange(0, 0)
            return
        if stage == "hashing":
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(current)
            self.progress_label.setText(
                f"Checking file metadata and hashes {current:,} / {total:,}  ·  {detail}"
            )
            return
        if total > 0:
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(current)
            self.progress_label.setText(
                f"Scanning {current:,} / {total:,} files  ·  {detail}"
            )
        else:
            self.progress_label.setText(f"Scanning  ·  {detail}")

    def _scan_completed(self, report: dict):
        self._set_idle()
        self.current_report = report
        report.setdefault("project_path", self.selected_folder)
        self.findings = report.get("findings", [])
        self.auto_fix_button.setEnabled(bool(self.findings))
        self.issue_value.setText(str(report.get("total_issues", report.get("summary", {}).get("total", len(self.findings)))))
        using_cpp = scanner_binary_path().is_file()
        self.engine_value.setText("C++20" if using_cpp else "PYTHON")
        self.engine_caption.setText("Mapped, parallel core" if using_cpp else "Local scanner fallback")
        self.export_json_button.setEnabled(True)
        self.export_html_button.setEnabled(True)
        self._animate_score(int(report.get("security_score", 100)))
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_label.setText(
            f"Scan complete  ·  {len(self.findings):,} finding(s)  ·  {self.selected_folder}"
        )
        cache_stats = report.get("incremental", {})
        if "bytes_hashed" in cache_stats:
            cache_message = (
                f" · {cache_stats.get('files_metadata_cached', 0):,} files reused by metadata"
                f" · {cache_stats.get('bytes_hashed', 0):,} bytes hashed"
            )
        else:
            cache_message = ""
        self.status_bar.showMessage(
            f"Scan complete · {len(self.findings):,} finding(s){cache_message}",
            8000,
        )
        self._populate_findings()
        self._notify_live_findings()

    def _scan_failed(self, message: str):
        if self.worker is not None:
            self._pending_changed_files.update(self.worker.force_hash_paths)
        self._notify_live_findings()
        self._set_idle()
        self.engine_value.setText("ERROR")
        self.engine_caption.setText("Scan did not complete")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Scan failed. Review the error details.")
        self.current_report = None
        self.export_json_button.setEnabled(False)
        self.export_html_button.setEnabled(False)
        self.status_bar.showMessage("Scan failed")
        QMessageBox.critical(self, "Scanner error", message)

    def _set_idle(self):
        self.scan_button.setEnabled(bool(self.selected_folder))
        self.browse_button.setEnabled(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and any(
            Path(url.toLocalFile()).is_dir() for url in event.mimeData().urls()
        ):
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            path = Path(url.toLocalFile())
            if path.is_dir():
                self._set_target_folder(path)
                event.acceptProposedAction()
                return

    def _set_target_folder(self, folder: Path):
        self.selected_folder = str(folder.resolve())
        self._pending_changed_files.clear()
        self.path_input.setText(self.selected_folder)
        self.path_input.setToolTip(self.selected_folder)
        self.scan_button.setEnabled(True)
        self.auto_fix_button.setEnabled(False)
        self.export_json_button.setEnabled(False)
        self.export_html_button.setEnabled(False)
        self.progress_label.setText("Ready to scan this local folder.")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        if self.live_guard_checkbox.isChecked():
            self._refresh_live_watch_paths()

    def choose_folder(self):
        selected = QFileDialog.getExistingDirectory(self, "Select a project folder", self.selected_folder)
        if selected:
            self._set_target_folder(Path(selected))

    def _animate_score(self, score: int):
        self._score_animation = QVariantAnimation(self)
        self._score_animation.setDuration(620)
        self._score_animation.setStartValue(0)
        self._score_animation.setEndValue(score)
        self._score_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._score_animation.valueChanged.connect(
            lambda value: self.score_value.setText(str(int(value)))
        )
        self._score_animation.finished.connect(
            lambda: self.score_caption.setText("out of 100 · local score")
        )
        self._score_animation.start()

    def _populate_findings(self):
        self.table_model.set_findings(self.findings)
        if not self.findings:
            self.empty_state.setText(
                "No findings detected. This target is clear based on the enabled rules."
            )
            self.detail_prompt.setText("No remediation prompt is needed.")
            self.copy_button.setEnabled(False)
        else:
            self.table.show()
            self.table.selectRow(0)
            self._show_selected_finding(self.table.currentIndex(), QModelIndex())
        self._filter_findings()

    def _show_selected_finding(self, current: QModelIndex, _previous: QModelIndex):
        if not current.isValid():
            self.detail_prompt.setText("Select a finding above to see a suggested fix prompt.")
            self.copy_button.setEnabled(False)
            return
        finding = self.table_model.finding_at(current.row())
        if not finding:
            return
        snippet = finding.get("snippet", "")
        prompt = finding.get("fix_prompt", "No remediation prompt available.")
        details = f"{prompt}\n\nEvidence: {snippet}" if snippet else prompt
        self.detail_prompt.setText(details)
        self.copy_button.setEnabled(bool(finding.get("fix_prompt")))

    def _queue_findings_filter(self, _value=None):
        self.findings_filter_timer.start()

    def _filter_findings(self, _value=None):
        query = self.search_input.text()
        severity_filter = self.severity_filter.currentText().upper()
        self.table_model.set_filter(query, severity_filter)
        visible = self.table_model.rowCount()
        self.table.setVisible(visible > 0)
        self.empty_state.setVisible(visible == 0)
        if visible == 0:
            self.empty_state.setText(
                "No findings match the selected search and severity filters."
                if self.findings
                else "No findings detected. This target is clear based on the enabled rules."
            )
            self.detail_prompt.setText("Select a finding above to see a suggested fix prompt.")
            self.copy_button.setEnabled(False)
        elif not self.table.currentIndex().isValid():
            self.table.selectRow(0)

    def copy_selected_prompt(self):
        current = self.table.currentIndex()
        if current.isValid():
            finding = self.table_model.finding_at(current.row())
            if finding:
                self._copy_prompt(finding)

    def _copy_prompt(self, finding: dict):
        prompt = finding.get("fix_prompt", "")
        if prompt:
            QApplication.clipboard().setText(prompt)
            self.status_bar.showMessage("Remediation prompt copied to clipboard.", 3500)

    def _copy_row_prompt(self, index: QModelIndex):
        if not index.isValid() or index.column() != 3:
            return
        finding = self.table_model.finding_at(index.row())
        if finding:
            self._copy_prompt(finding)

    def export_json(self):
        if self.current_report is None:
            return
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Export ProtoSec JSON report", "protosec-report.json", "JSON reports (*.json)"
        )
        if not output_path:
            return
        try:
            export_json_report(self.current_report, output_path)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        self.status_bar.showMessage(f"JSON report saved to {output_path}", 5000)

    def export_html(self):
        if self.current_report is None:
            return
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Export ProtoSec HTML report", "protosec-report.html", "HTML reports (*.html)"
        )
        if not output_path:
            return
        try:
            export_html_report(self.current_report, self.selected_folder, output_path)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        self.status_bar.showMessage(f"HTML report saved to {output_path}", 5000)

    def activate_license(self):
        token, accepted = QInputDialog.getMultiLineText(
            self,
            "Activate ProtoSec Pro",
            "Paste your signed ProtoSec license token:",
        )
        if not accepted or not token.strip():
            return
        active, message = save_license_key(token)
        if not active:
            QMessageBox.warning(self, "License not activated", message)
            return
        self.pro_active = True
        self.license_status = message
        self.license_button.setText("✓   Pro active")
        self.status_bar.showMessage(message, 5000)
        QMessageBox.information(self, "ProtoSec Pro activated", message)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("ProtoSec")
    app.setFont(QFont("Segoe UI", 10))
    window = ProtoSecWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
