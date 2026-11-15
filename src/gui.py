import json
import subprocess
import sys
import threading
from pathlib import Path

from src.main import scan_repository
from utils.license_guard import is_pro_unlocked, save_license_key
from utils.report_exporter import export_html_report, export_json_report

try:
    from PyQt6.QtCore import QEasingCurve, QPropertyAnimation, QThread, Qt, QVariantAnimation, pyqtSignal
    from PyQt6.QtGui import QColor, QFont
    from PyQt6.QtWidgets import (
        QApplication,
        QComboBox,
        QFileDialog,
        QFrame,
        QGraphicsOpacityEffect,
        QBoxLayout,
        QHBoxLayout,
        QInputDialog,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QProgressBar,
        QScrollArea,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
        QHeaderView,
        QStatusBar,
    )
except ImportError as exc:
    raise SystemExit(
        "PyQt6 is required to run the ProtoSec desktop app. "
        "Install it with: python -m pip install -r requirements.txt"
    ) from exc


THEMES = {
    "dark": {
        "background": "#080d16",
        "surface": "#0d1522",
        "card": "#111c2c",
        "card_hover": "#152338",
        "border": "#1d2c40",
        "text": "#e6f0ff",
        "muted": "#8294aa",
        "accent": "#55e6c1",
        "accent_hover": "#7af2d2",
        "accent_text": "#071712",
        "secondary": "#19283b",
        "input": "#0b1421",
        "selection": "#173b43",
        "table_alt": "#0f1927",
        "scroll": "#2b3c50",
        "shadow": "#050910",
    },
    "light": {
        "background": "#f0f5f8",
        "surface": "#f8fbfc",
        "card": "#ffffff",
        "card_hover": "#f3f9f8",
        "border": "#d8e3e8",
        "text": "#122432",
        "muted": "#607585",
        "accent": "#087f70",
        "accent_hover": "#096d61",
        "accent_text": "#ffffff",
        "secondary": "#e8f0f2",
        "input": "#f7fafb",
        "selection": "#d9f2ec",
        "table_alt": "#f6f9fa",
        "scroll": "#b9c9d0",
        "shadow": "#dce6ea",
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


class ScanWorker(QThread):
    progress = pyqtSignal(str, int, int, str)
    completed = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, folder_path: str):
        super().__init__()
        self.folder_path = folder_path

    def run(self):
        try:
            binary_path = scanner_binary_path()
            if binary_path.is_file():
                report = self._run_cpp(binary_path)
            else:
                report = scan_repository(self.folder_path, progress_callback=self.progress.emit)
            self.completed.emit(report)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            self.failed.emit(str(exc))

    def _run_cpp(self, binary_path: Path) -> dict:
        process = subprocess.Popen(
            [str(binary_path), self.folder_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        output_chunks = []
        error_messages = []

        def drain_stdout():
            if process.stdout is not None:
                output_chunks.append(process.stdout.read())

        stdout_thread = threading.Thread(target=drain_stdout, daemon=True)
        stdout_thread.start()
        if process.stderr is not None:
            for line in process.stderr:
                parts = line.rstrip("\r\n").split("\t", 3)
                if len(parts) == 4 and parts[0] == "PROGRESS":
                    try:
                        self.progress.emit("scanning", int(parts[1]), int(parts[2]), parts[3])
                    except ValueError:
                        continue
                elif line.strip():
                    error_messages.append(line.strip())
        return_code = process.wait()
        stdout_thread.join()

        if return_code != 0:
            message = "\n".join(error_messages)
            raise RuntimeError(message or "C++ scanner failed. Check that the selected folder is accessible.")
        return json.loads("".join(output_chunks))


class ProtoSecWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ProtoSec v1.0.0 — Local Security Workbench")
        self.setMinimumSize(760, 560)
        self.resize(1320, 860)
        self.setAcceptDrops(True)
        self.theme_name = "dark"
        self.selected_folder = ""
        self.findings = []
        self.current_report = None
        self.worker = None
        self._theme_animation = None
        self._score_animation = None
        self.pro_active, self.license_status = is_pro_unlocked()
        self._ui_ready = False

        self.root = QWidget()
        self.root.setObjectName("appRoot")
        self.setCentralWidget(self.root)
        self.root_effect = QGraphicsOpacityEffect(self.root)
        self.root.setGraphicsEffect(self.root_effect)

        self._build_ui()
        self._ui_ready = True
        self._update_responsive_layout(self.width(), self.height())
        self._apply_theme()
        self._animate_intro()

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
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setFixedSize(38, 38)
        wordmark = QVBoxLayout()
        brand_name = QLabel("PROTOSEC")
        brand_name.setObjectName("brandName")
        brand_caption = QLabel("LOCAL SECURITY")
        brand_caption.setObjectName("brandCaption")
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
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(12)
        self.license_button = QPushButton(
            "✓   Pro active" if self.pro_active else "◇   Activate license"
        )
        self.license_button.setObjectName("themeButton")
        self.license_button.clicked.connect(self.activate_license)
        actions_layout.addWidget(self.license_button)
        self.export_json_button = QPushButton("⇩  JSON")
        self.export_json_button.setObjectName("themeButton")
        self.export_json_button.setEnabled(False)
        self.export_json_button.clicked.connect(self.export_json)
        actions_layout.addWidget(self.export_json_button)
        self.export_html_button = QPushButton("⇩  HTML")
        self.export_html_button.setObjectName("themeButton")
        self.export_html_button.setEnabled(False)
        self.export_html_button.clicked.connect(self.export_html)
        actions_layout.addWidget(self.export_html_button)
        self.theme_button = QPushButton("☼   Switch to light")
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
        scan_title = QLabel("TARGET PROJECT")
        scan_title.setObjectName("cardEyebrow")
        scan_heading.addWidget(scan_title)
        scan_heading.addStretch()
        self.engine_badge = QLabel("◉  ENGINE AUTO-DETECT")
        self.engine_badge.setObjectName("engineBadge")
        scan_heading.addWidget(self.engine_badge)
        scan_layout.addLayout(scan_heading)

        picker_row = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setObjectName("pathInput")
        self.path_input.setReadOnly(True)
        self.path_input.setPlaceholderText("Choose a project folder to inspect…")
        picker_row.addWidget(self.path_input, 1)
        self.browse_button = QPushButton("⌕   Browse")
        self.browse_button.setObjectName("secondaryButton")
        self.browse_button.clicked.connect(self.choose_folder)
        picker_row.addWidget(self.browse_button)
        self.scan_button = QPushButton("▶   Run scan")
        self.scan_button.setObjectName("primaryButton")
        self.scan_button.setEnabled(False)
        self.scan_button.clicked.connect(self.run_scan)
        picker_row.addWidget(self.scan_button)
        scan_layout.addLayout(picker_row)

        progress_row = QHBoxLayout()
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
        findings_controls_layout.setContentsMargins(0, 0, 0, 0)
        findings_controls_layout.setSpacing(12)
        self.search_input = QLineEdit()
        self.search_input.setObjectName("searchInput")
        self.search_input.setPlaceholderText("⌕   Search findings")
        self.search_input.setFixedWidth(220)
        self.search_input.textChanged.connect(self._filter_findings)
        findings_controls_layout.addWidget(self.search_input)
        self.severity_filter = QComboBox()
        self.severity_filter.setObjectName("severityFilter")
        self.severity_filter.addItems(["All severities", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self._filter_findings)
        findings_controls_layout.addWidget(self.severity_filter)
        findings_header.addWidget(findings_title_widget, 1)
        findings_header.addWidget(findings_controls)
        content_layout.addLayout(findings_header)

        self.table = QTableWidget(0, 4)
        self.table.setObjectName("findingsTable")
        self.table.setHorizontalHeaderLabels(["SEVERITY", "DETECTION", "LOCATION", ""])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setMinimumHeight(190)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 108)
        self.table.setColumnWidth(2, 190)
        self.table.setColumnWidth(3, 104)
        self.table.currentCellChanged.connect(self._show_selected_finding)
        self.table.cellClicked.connect(self._copy_row_prompt)
        content_layout.addWidget(self.table, 1)

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
        self.copy_button = QPushButton("▣   Copy prompt")
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
        self.main_scroll_area.setWidget(content)
        shell.addWidget(self.main_scroll_area, 1)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready · scans run locally and source files are not uploaded.")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._ui_ready:
            self._update_responsive_layout(event.size().width(), event.size().height())

    def _update_responsive_layout(self, width: int, height: int):
        compact = width < 1180
        self.sidebar.setFixedWidth(190 if compact else 226)
        self.sidebar.setVisible(width > 820)
        self.topbar_layout.setDirection(
            QBoxLayout.Direction.TopToBottom if compact else QBoxLayout.Direction.LeftToRight
        )
        self.findings_header_layout.setDirection(
            QBoxLayout.Direction.TopToBottom if width < 1100 else QBoxLayout.Direction.LeftToRight
        )
        horizontal_margin = 16 if width <= 820 else 24 if compact else 32
        vertical_margin = 16 if height < 700 else 26
        self.content_layout.setContentsMargins(
            horizontal_margin,
            vertical_margin,
            horizontal_margin,
            18 if height < 700 else 28,
        )
        self.content_layout.setSpacing(12 if height < 700 else 20)
        self.progress_bar.setFixedWidth(130 if width < 900 else 190)
        self.search_input.setFixedWidth(180 if width < 900 else 220)
        self.table.setColumnWidth(2, 150 if width < 900 else 190)

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
            QWidget#appRoot { background: %(background)s; color: %(text)s; }
            QWidget { color: %(text)s; font-family: "Segoe UI Variable", "Segoe UI", sans-serif; font-size: 10pt; }
            QFrame#sidebar { background: %(surface)s; border-right: 1px solid %(border)s; }
            QWidget#content { background: %(background)s; }
            QLabel#brandMark { color: %(accent)s; background: %(selection)s; border: 1px solid %(border)s; border-radius: 12px; font-size: 23pt; font-weight: 700; }
            QLabel#brandName { font-size: 11pt; font-weight: 800; letter-spacing: 1px; }
            QLabel#brandCaption, QLabel#sectionLabel, QLabel#eyebrow, QLabel#cardEyebrow { color: %(muted)s; font-size: 8pt; font-weight: 700; letter-spacing: 1.1px; }
            QLabel#sectionLabel { margin-top: 21px; }
            QLabel#workspaceChip { background: %(selection)s; color: %(accent)s; border: 1px solid %(border)s; border-radius: 8px; padding: 11px 10px; font-weight: 650; }
            QFrame#privacyCard, QFrame#scanCard, QFrame#scoreCard, QFrame#issuesCard, QFrame#engineCard, QFrame#detailCard { background: %(card)s; border: 1px solid %(border)s; border-radius: 13px; }
            QScrollArea#mainScrollArea { border: none; background: %(background)s; }
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
            QTableWidget#findingsTable { background: %(card)s; alternate-background-color: %(table_alt)s; border: 1px solid %(border)s; border-radius: 11px; padding: 4px; selection-background-color: %(selection)s; outline: 0; }
            QTableWidget#findingsTable::item { padding: 8px 7px; border: none; }
            QHeaderView::section { background: %(surface)s; color: %(muted)s; border: none; border-bottom: 1px solid %(border)s; padding: 10px 8px; font-size: 8pt; font-weight: 750; letter-spacing: 0.8px; }
            QLabel#emptyState { color: %(muted)s; padding: 9px; }
            QLabel#detailPrompt { color: %(text)s; background: %(input)s; border: 1px solid %(border)s; border-radius: 8px; padding: 11px 12px; font-family: "Cascadia Code", "Consolas", monospace; font-size: 9pt; }
            QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
            QScrollBar::handle:vertical { background: %(scroll)s; border-radius: 5px; min-height: 24px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
            """
            % colors
        )

    def _animate_intro(self):
        self.root_effect.setOpacity(0.0)
        animation = QPropertyAnimation(self.root_effect, b"opacity", self)
        animation.setDuration(480)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation.start()
        self._intro_animation = animation

    def toggle_theme(self):
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        self.theme_button.setText("◐   Switch to dark" if self.theme_name == "light" else "☼   Switch to light")

        fade_out = QPropertyAnimation(self.root_effect, b"opacity", self)
        fade_out.setDuration(120)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.55)
        fade_out.setEasingCurve(QEasingCurve.Type.OutQuad)

        def finish_transition():
            self._apply_theme()
            fade_in = QPropertyAnimation(self.root_effect, b"opacity", self)
            fade_in.setDuration(230)
            fade_in.setStartValue(0.55)
            fade_in.setEndValue(1.0)
            fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
            fade_in.start()
            self._theme_animation = fade_in

        fade_out.finished.connect(finish_transition)
        fade_out.start()
        self._theme_animation = fade_out

    def run_scan(self):
        if not self.selected_folder or (self.worker is not None and self.worker.isRunning()):
            return
        self.scan_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.copy_button.setEnabled(False)
        self.progress_bar.setRange(0, 0)
        self.progress_label.setText("Starting local scanner…")
        self.engine_value.setText("RUNNING")
        self.engine_caption.setText("Analyzing selected project")
        self.current_report = None
        self.export_json_button.setEnabled(False)
        self.export_html_button.setEnabled(False)
        self.table.setRowCount(0)
        self.findings = []
        self.empty_state.setText("Scanning local files…")
        self.empty_state.show()

        self.worker = ScanWorker(self.selected_folder)
        self.worker.progress.connect(self._update_progress)
        self.worker.completed.connect(self._scan_completed)
        self.worker.failed.connect(self._scan_failed)
        self.worker.start()

    def _update_progress(self, stage: str, current: int, total: int, detail: str):
        if stage == "discovering":
            message = "Indexing project files"
            if detail and detail != ".":
                message += f"  ·  {detail}"
            self.progress_label.setText(message)
            self.progress_bar.setRange(0, 0)
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
        self.status_bar.showMessage(f"Scan complete · {len(self.findings):,} finding(s)", 5000)
        self._populate_findings()

    def _scan_failed(self, message: str):
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
        self.path_input.setText(self.selected_folder)
        self.path_input.setToolTip(self.selected_folder)
        self.scan_button.setEnabled(True)
        self.export_json_button.setEnabled(False)
        self.export_html_button.setEnabled(False)
        self.progress_label.setText("Ready to scan this local folder.")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

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
        self.table.setRowCount(len(self.findings))
        for row, finding in enumerate(self.findings):
            severity = str(finding.get("severity", "MEDIUM")).upper()
            rule = finding.get("rule_id", "GEN-000")
            title = finding.get("title", "Security finding")
            location = f"{finding.get('file_path', '')}:{finding.get('line_number', '')}"

            severity_item = QTableWidgetItem(f"  {severity}")
            severity_item.setForeground(QColor(SEVERITY_COLORS.get(severity, "#8294aa")))
            severity_item.setData(Qt.ItemDataRole.UserRole, finding)
            self.table.setItem(row, 0, severity_item)
            self.table.setItem(row, 1, QTableWidgetItem(f"{rule}   {title}"))
            self.table.setItem(row, 2, QTableWidgetItem(location))

            copy_row_button = QPushButton("▣  Copy")
            copy_row_button.setObjectName("secondaryButton")
            copy_row_button.setProperty("findingRow", row)
            copy_row_button.clicked.connect(
                lambda checked=False, item=finding: self._copy_prompt(item)
            )
            self.table.setCellWidget(row, 3, copy_row_button)
            self.table.setRowHeight(row, 42)

        self.empty_state.setVisible(not self.findings)
        if not self.findings:
            self.empty_state.setText("No findings detected. This target is clear based on the enabled rules.")
            self.detail_prompt.setText("No remediation prompt is needed.")
            self.copy_button.setEnabled(False)
        else:
            self.table.setCurrentCell(0, 0)
            self._show_selected_finding(0, 0, -1, -1)
        self._filter_findings()

    def _show_selected_finding(self, row: int, _column: int, _previous_row: int, _previous_column: int):
        if row < 0:
            return
        item = self.table.item(row, 0)
        if item is None:
            return
        finding = item.data(Qt.ItemDataRole.UserRole)
        if not finding:
            return
        snippet = finding.get("snippet", "")
        prompt = finding.get("fix_prompt", "No remediation prompt available.")
        details = f"{prompt}\n\nEvidence: {snippet}" if snippet else prompt
        self.detail_prompt.setText(details)
        self.copy_button.setEnabled(bool(finding.get("fix_prompt")))

    def _filter_findings(self, _value=None):
        query = self.search_input.text().strip().casefold()
        severity_filter = self.severity_filter.currentText().upper()
        for row in range(self.table.rowCount()):
            severity_item = self.table.item(row, 0)
            detection_item = self.table.item(row, 1)
            location_item = self.table.item(row, 2)
            severity = severity_item.text().strip().upper() if severity_item else ""
            content = " ".join(
                item.text() for item in (detection_item, location_item) if item is not None
            ).casefold()
            hidden = (
                (severity_filter != "ALL SEVERITIES" and severity != severity_filter)
                or (query and query not in content and query not in severity.casefold())
            )
            self.table.setRowHidden(row, bool(hidden))

    def copy_selected_prompt(self):
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 0)
        if item is not None:
            finding = item.data(Qt.ItemDataRole.UserRole)
            if finding:
                self._copy_prompt(finding)

    def _copy_prompt(self, finding: dict):
        prompt = finding.get("fix_prompt", "")
        if prompt:
            QApplication.clipboard().setText(prompt)
            self.status_bar.showMessage("Remediation prompt copied to clipboard.", 3500)

    def _copy_row_prompt(self, row: int, _column: int):
        item = self.table.item(row, 0)
        if item is not None:
            finding = item.data(Qt.ItemDataRole.UserRole)
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
