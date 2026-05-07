"""IPbrowse - Local network scanner with PySide6 GUI."""
from __future__ import annotations

import csv
import json
import random
import re
import sys
import threading
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPointF,
    QSortFilterProxyModel,
    Qt,
    QThread,
    QTimer,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QDesktopServices,
    QFont,
    QGuiApplication,
    QIcon,
    QPainter,
    QPen,
    QPolygonF,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QStatusBar,
    QStyle,
    QTabWidget,
    QTableView,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from scanner import (
    COMMON_PORTS,
    Host,
    TOP_PORTS,
    _parse_arp_table,
    detect_local_subnet,
    expand_target,
    get_default_gateway,
    get_wifi_info,
    lookup_vendor,
    ping,
    scan_network,
)


COLUMNS = [
    ("status", "Статус"),
    ("ip", "IP-адрес"),
    ("hostname", "Имя хоста"),
    ("mac", "MAC-адрес"),
    ("vendor", "Производитель"),
    ("response_ms", "Отклик (мс)"),
    ("open_ports", "Открытые порты"),
]


# Timing templates: nmap-style presets that override the manual ping-timeout
# and worker-count spin-boxes when the corresponding -T<N> flag is selected.
# Format: { id: (short_name, ru_description, ping_timeout_ms, workers) }
TIMING_TEMPLATES: dict[int, tuple[str, str, int, int]] = {
    0: ("Paranoid", "очень медленно, для скрытных сканов", 5000, 1),
    1: ("Sneaky", "медленно", 3000, 10),
    2: ("Polite", "мягкий темп", 1500, 30),
    3: ("Normal", "обычная скорость (по умолчанию)", 700, 100),
    4: ("Aggressive", "быстро", 300, 200),
    5: ("Insane", "максимальная скорость", 150, 400),
}


@dataclass
class ScanFlags:
    """Optional scan flags configurable per tab via the FlagsDialog."""

    skip_ping: bool = False                 # -Pn
    timing: int = 3                         # -T<N>; 3 = no override
    top_ports: int = 0                      # --top-ports N; 0 = disabled
    randomize_ports: bool = False           # --randomize-ports
    retries: int = 1                        # --retry N; 1 = no extra retries
    exclude_text: str = ""                  # --exclude IPs / ranges

    def is_default(self) -> bool:
        return self == ScanFlags()

    def to_summary(self) -> str:
        """Human-readable summary like ``-Pn -T4 --top-ports 100``."""
        parts: list[str] = []
        if self.skip_ping:
            parts.append("-Pn")
        if self.timing != 3:
            parts.append(f"-T{self.timing}")
        if self.top_ports:
            parts.append(f"--top-ports {self.top_ports}")
        if self.randomize_ports:
            parts.append("--randomize-ports")
        if self.retries > 1:
            parts.append(f"--retry {self.retries}")
        if self.exclude_text.strip():
            parts.append(f"--exclude {self.exclude_text.strip()}")
        return " ".join(parts)


class FlagsDialog(QDialog):
    """Modal dialog that lets the user toggle additional scan flags."""

    _FLAG_STYLE = (
        "color: #89b4fa; font-family: Consolas, monospace; "
        "font-weight: bold;"
    )

    def __init__(self, current: ScanFlags, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Флаги сканирования")
        self.setModal(True)
        self.resize(620, 480)
        self._build_ui()
        self._apply_to_ui(current)

    # ----- UI construction -----
    def _flag_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(self._FLAG_STYLE)
        lbl.setMinimumWidth(150)
        return lbl

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        info = QLabel(
            "Дополнительные параметры сканирования. Применяются поверх "
            "значений из основной панели вкладки."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #94e2d5; font-style: italic;")
        root.addWidget(info)

        # ---- Host discovery ----
        host_box = QGroupBox("Обнаружение хостов")
        host_layout = QVBoxLayout(host_box)
        host_layout.setSpacing(6)

        self.cb_skip_ping = QCheckBox()
        skip_row = QHBoxLayout()
        skip_row.addWidget(self.cb_skip_ping)
        skip_row.addWidget(self._flag_label("-Pn"))
        skip_row.addWidget(QLabel(
            "Пропустить ping (сканировать все адреса как активные)"
        ), 1)
        host_layout.addLayout(skip_row)

        self.cb_retries = QCheckBox()
        retry_row = QHBoxLayout()
        retry_row.addWidget(self.cb_retries)
        retry_row.addWidget(self._flag_label("--retry"))
        retry_row.addWidget(QLabel("Повторов ping при недоступности:"))
        self.sp_retries = QSpinBox()
        self.sp_retries.setRange(2, 5)
        self.sp_retries.setValue(2)
        retry_row.addWidget(self.sp_retries)
        retry_row.addStretch(1)
        host_layout.addLayout(retry_row)

        root.addWidget(host_box)

        # ---- Timing ----
        timing_box = QGroupBox("Тайминг")
        timing_layout = QHBoxLayout(timing_box)
        timing_layout.addWidget(self._flag_label("-T<N>"))
        timing_layout.addWidget(QLabel("Шаблон скорости:"))
        self.cmb_timing = QComboBox()
        for tid, (name, desc, _, _) in TIMING_TEMPLATES.items():
            self.cmb_timing.addItem(f"T{tid} — {name} ({desc})", tid)
        self.cmb_timing.setCurrentIndex(3)
        timing_layout.addWidget(self.cmb_timing, 1)
        root.addWidget(timing_box)

        # ---- Ports ----
        ports_box = QGroupBox("Порты")
        ports_layout = QVBoxLayout(ports_box)
        ports_layout.setSpacing(6)

        self.cb_top_ports = QCheckBox()
        top_row = QHBoxLayout()
        top_row.addWidget(self.cb_top_ports)
        top_row.addWidget(self._flag_label("--top-ports"))
        top_row.addWidget(QLabel(
            "Сканировать только N самых популярных портов:"
        ))
        self.sp_top_ports = QSpinBox()
        self.sp_top_ports.setRange(1, len(TOP_PORTS))
        self.sp_top_ports.setValue(100)
        top_row.addWidget(self.sp_top_ports)
        top_row.addStretch(1)
        ports_layout.addLayout(top_row)

        self.cb_randomize = QCheckBox()
        rand_row = QHBoxLayout()
        rand_row.addWidget(self.cb_randomize)
        rand_row.addWidget(self._flag_label("--randomize-ports"))
        rand_row.addWidget(QLabel("Случайный порядок сканирования портов"), 1)
        ports_layout.addLayout(rand_row)

        root.addWidget(ports_box)

        # ---- Exclusions ----
        excl_box = QGroupBox("Исключения")
        excl_layout = QVBoxLayout(excl_box)
        excl_layout.setSpacing(4)
        excl_top = QHBoxLayout()
        excl_top.addWidget(self._flag_label("--exclude"))
        excl_top.addWidget(QLabel(
            "Адреса и подсети, которые нужно пропустить:"
        ), 1)
        excl_layout.addLayout(excl_top)
        self.le_exclude = QLineEdit()
        self.le_exclude.setPlaceholderText(
            "например, 192.168.1.1, 192.168.1.10-15, 10.0.0.0/24"
        )
        excl_layout.addWidget(self.le_exclude)
        root.addWidget(excl_box)

        root.addStretch(1)

        # ---- Buttons ----
        btn_row = QHBoxLayout()
        btn_reset = QPushButton("Сбросить")
        btn_reset.clicked.connect(self._reset)
        btn_row.addWidget(btn_reset)
        btn_row.addStretch(1)
        btn_cancel = QPushButton("Отмена")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_ok = QPushButton("Применить")
        btn_ok.setDefault(True)
        btn_ok.setObjectName("scan")  # reuse blue accent style
        btn_ok.clicked.connect(self.accept)
        btn_row.addWidget(btn_ok)
        root.addLayout(btn_row)

    # ----- Data binding -----
    def _apply_to_ui(self, f: ScanFlags) -> None:
        self.cb_skip_ping.setChecked(f.skip_ping)
        idx = self.cmb_timing.findData(f.timing)
        self.cmb_timing.setCurrentIndex(idx if idx >= 0 else 3)
        self.cb_top_ports.setChecked(f.top_ports > 0)
        if f.top_ports > 0:
            self.sp_top_ports.setValue(f.top_ports)
        self.cb_randomize.setChecked(f.randomize_ports)
        self.cb_retries.setChecked(f.retries > 1)
        if f.retries > 1:
            self.sp_retries.setValue(f.retries)
        self.le_exclude.setText(f.exclude_text)

    def _reset(self) -> None:
        self._apply_to_ui(ScanFlags())

    def get_flags(self) -> ScanFlags:
        return ScanFlags(
            skip_ping=self.cb_skip_ping.isChecked(),
            timing=int(self.cmb_timing.currentData()),
            top_ports=self.sp_top_ports.value() if self.cb_top_ports.isChecked() else 0,
            randomize_ports=self.cb_randomize.isChecked(),
            retries=self.sp_retries.value() if self.cb_retries.isChecked() else 1,
            exclude_text=self.le_exclude.text().strip(),
        )


class HostsModel(QAbstractTableModel):
    """Table model holding scan results."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._hosts: list[Host] = []
        self._show_dead = False
        self._progress: dict[str, tuple[int, int]] = {}

    # ---- Qt model API ----
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: D401, B008
        return 0 if parent.isValid() else len(self._visible_hosts())

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section][1]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        host = self._visible_hosts()[index.row()]
        key = COLUMNS[index.column()][0]

        if role == Qt.DisplayRole:
            if key == "status":
                return "🟢 Online" if host.alive else "🔴 Offline"
            if key == "ip":
                return host.ip
            if key == "hostname":
                return host.hostname or "—"
            if key == "mac":
                return host.mac.upper() if host.mac else "—"
            if key == "vendor":
                return host.vendor or "—"
            if key == "response_ms":
                return f"{host.response_ms:.1f}" if host.response_ms is not None else "—"
            if key == "open_ports":
                if not host.scan_complete:
                    progress = self._progress.get(host.ip)
                    if progress and progress[1] > 0:
                        d, t = progress
                        return f"Сканирование портов… {int(d * 100 / t)}%"
                    if host.alive and host.port_scan_total > 0:
                        return "Ожидание сканирования…"
                    return "—"
                if not host.open_ports:
                    return "—"
                parts = []
                for p in host.open_ports:
                    name = COMMON_PORTS.get(p)
                    parts.append(f"{p} ({name})" if name else str(p))
                return ", ".join(parts)
        elif role == Qt.ForegroundRole:
            if not host.alive:
                return QColor("#888888")
        elif role == Qt.TextAlignmentRole:
            if key in ("response_ms", "status"):
                return int(Qt.AlignCenter)
        elif role == Qt.FontRole:
            if key in ("ip", "mac"):
                f = QFont("Consolas")
                return f
        return None

    # ---- public API ----
    def set_show_dead(self, show: bool) -> None:
        self.beginResetModel()
        self._show_dead = show
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._hosts.clear()
        self._progress.clear()
        self.endResetModel()

    def upsert(self, host: Host) -> None:
        if host.scan_complete:
            self._progress.pop(host.ip, None)
        # Replace existing row for the same IP, or append.
        for i, existing in enumerate(self._hosts):
            if existing.ip == host.ip:
                self._hosts[i] = host
                # signal changes
                if not self._show_dead and not host.alive:
                    self.beginResetModel()
                    self.endResetModel()
                else:
                    visible = self._visible_hosts()
                    if host in visible:
                        row = visible.index(host)
                        top = self.index(row, 0)
                        bot = self.index(row, self.columnCount() - 1)
                        self.dataChanged.emit(top, bot)
                    else:
                        self.beginResetModel()
                        self.endResetModel()
                return
        # append new
        if not self._show_dead and not host.alive:
            self._hosts.append(host)
            return
        row = len(self._visible_hosts())
        self.beginInsertRows(QModelIndex(), row, row)
        self._hosts.append(host)
        self.endInsertRows()

    def update_progress(self, ip: str, done: int, total: int) -> None:
        self._progress[ip] = (done, total)
        col = next((i for i, (k, _) in enumerate(COLUMNS) if k == "open_ports"), -1)
        if col < 0:
            return
        for row, h in enumerate(self._visible_hosts()):
            if h.ip == ip:
                idx = self.index(row, col)
                self.dataChanged.emit(idx, idx, [Qt.DisplayRole])
                return

    def hosts(self) -> list[Host]:
        return list(self._hosts)

    def alive_hosts(self) -> list[Host]:
        return [h for h in self._hosts if h.alive]

    def host_at(self, source_row: int) -> Host | None:
        """Return the Host shown at the given source-model row, or None."""
        visible = self._visible_hosts()
        if 0 <= source_row < len(visible):
            return visible[source_row]
        return None

    def _visible_hosts(self) -> list[Host]:
        if self._show_dead:
            return self._hosts
        return [h for h in self._hosts if h.alive]


class ScanWorker(QObject):
    """Runs the scan in a worker thread and emits Qt signals."""

    progress = Signal(int, int)  # done, total
    host_found = Signal(object)  # Host
    port_progress = Signal(str, int, int)  # ip, done, total
    finished = Signal()
    error = Signal(str)

    def __init__(
        self,
        targets: list[str],
        ping_timeout_ms: int,
        workers: int,
        resolve_hostnames: bool,
        detect_mac: bool,
        ports: list[int],
        port_timeout: float,
        port_workers: int = 64,
        skip_ping: bool = False,
        ping_retries: int = 1,
    ) -> None:
        super().__init__()
        self.targets = targets
        self.ping_timeout_ms = ping_timeout_ms
        self.workers = workers
        self.resolve_hostnames = resolve_hostnames
        self.detect_mac = detect_mac
        self.ports = ports
        self.port_timeout = port_timeout
        self.port_workers = port_workers
        self.skip_ping = skip_ping
        self.ping_retries = ping_retries
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            total = len(self.targets)
            done = 0
            self.progress.emit(0, total)

            def _on_partial(host: Host) -> None:
                self.host_found.emit(host)

            def _on_port_progress(ip: str, d: int, t: int) -> None:
                self.port_progress.emit(ip, d, t)

            for host in scan_network(
                self.targets,
                ping_timeout_ms=self.ping_timeout_ms,
                workers=self.workers,
                resolve_hostnames=self.resolve_hostnames,
                detect_mac=self.detect_mac,
                ports=self.ports,
                port_timeout=self.port_timeout,
                port_workers=self.port_workers,
                cancel_event=self._cancel,
                on_host_update=_on_partial,
                port_progress_cb=_on_port_progress,
                skip_ping=self.skip_ping,
                ping_retries=self.ping_retries,
            ):
                self.host_found.emit(host)
                if host.scan_complete:
                    done += 1
                    self.progress.emit(done, total)
                if self._cancel.is_set():
                    break
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


class SparklineWidget(QWidget):
    """Lightweight live line chart used for the Wi-Fi tab graphs."""

    def __init__(
        self,
        title: str = "",
        unit: str = "",
        color: str = "#89b4fa",
        max_points: int = 120,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._title = title
        self._unit = unit
        self._color = QColor(color)
        self._max_points = max_points
        self._values: list[float] = []
        self.setMinimumHeight(120)

    def reset(self) -> None:
        self._values.clear()
        self.update()

    def add_value(self, value: float) -> None:
        self._values.append(float(value))
        if len(self._values) > self._max_points:
            del self._values[: len(self._values) - self._max_points]
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor("#181825"))
        painter.setPen(QColor("#45475a"))
        painter.drawRect(self.rect().adjusted(0, 0, -1, -1))

        # Title with current value.
        painter.setPen(QColor("#89b4fa"))
        font = painter.font()
        font.setPointSize(9)
        font.setBold(True)
        painter.setFont(font)
        text = self._title
        if self._values:
            unit = f" {self._unit}" if self._unit else ""
            text += f"  ({self._values[-1]:.1f}{unit})"
        painter.drawText(8, 16, text)

        if not self._values:
            painter.setPen(QColor("#6c7086"))
            painter.drawText(self.rect(), Qt.AlignCenter, "нет данных")
            return

        chart = self.rect().adjusted(8, 24, -8, -8)
        mn, mx = min(self._values), max(self._values)
        if mx - mn < 1e-6:
            mx = mn + 1
        n = len(self._values)
        points: list[QPointF] = []
        for i, v in enumerate(self._values):
            x = chart.left() + chart.width() * (i / max(1, n - 1))
            y = chart.bottom() - chart.height() * (v - mn) / (mx - mn)
            points.append(QPointF(x, y))

        # Filled area under the curve.
        fill = QColor(self._color)
        fill.setAlpha(50)
        poly = QPolygonF(
            [QPointF(points[0].x(), chart.bottom())]
            + points
            + [QPointF(points[-1].x(), chart.bottom())]
        )
        painter.setBrush(QBrush(fill))
        painter.setPen(Qt.NoPen)
        painter.drawPolygon(poly)

        # Curve.
        pen = QPen(self._color)
        pen.setWidth(2)
        painter.setPen(pen)
        for i in range(1, len(points)):
            painter.drawLine(points[i - 1], points[i])


class ScanTab(QWidget):
    """Reusable scan view used for both local and external network tabs."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        default_target: str = "",
        show_auto_detect: bool = True,
        auto_start: bool = False,
        warning_text: str = "",
    ) -> None:
        super().__init__(parent)
        self.model = HostsModel(self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)

        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self.flags = ScanFlags()

        self._build_ui(default_target, show_auto_detect, warning_text)
        if auto_start:
            QTimer.singleShot(0, self.start_scan)

    # ---------- UI ----------
    def _build_ui(self, default_target: str, show_auto_detect: bool, warning_text: str) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        if warning_text:
            banner = QLabel(warning_text)
            banner.setWordWrap(True)
            banner.setObjectName("warningBanner")
            banner.setStyleSheet(
                "QLabel#warningBanner {"
                " background: #3b2d35; color: #f38ba8;"
                " border: 1px solid #f38ba8; border-radius: 6px;"
                " padding: 8px 12px; font-weight: bold;"
                "}"
            )
            root.addWidget(banner)

        # Settings group
        settings = QGroupBox("Параметры сканирования")
        form = QFormLayout(settings)
        form.setLabelAlignment(Qt.AlignRight)

        self.target_edit = QLineEdit(default_target)
        self.target_edit.setPlaceholderText("например, 192.168.1.0/24 или 192.168.1.1-50")
        target_row = QHBoxLayout()
        target_row.addWidget(self.target_edit, 1)
        if show_auto_detect:
            detect_btn = QPushButton("Авто")
            detect_btn.setToolTip("Определить локальную подсеть автоматически")
            detect_btn.clicked.connect(
                lambda: self.target_edit.setText(detect_local_subnet())
            )
            target_row.addWidget(detect_btn)
        form.addRow("Цель:", self._wrap(target_row))

        self.ping_timeout = QSpinBox()
        self.ping_timeout.setRange(100, 5000)
        self.ping_timeout.setValue(700)
        self.ping_timeout.setSuffix(" мс")

        self.workers = QSpinBox()
        self.workers.setRange(1, 512)
        self.workers.setValue(100)

        timeouts = QHBoxLayout()
        timeouts.addWidget(QLabel("Ping таймаут:"))
        timeouts.addWidget(self.ping_timeout)
        timeouts.addSpacing(20)
        timeouts.addWidget(QLabel("Потоки:"))
        timeouts.addWidget(self.workers)
        timeouts.addStretch(1)
        form.addRow("Производительность:", self._wrap(timeouts))

        self.cb_hostname = QCheckBox("Имена хостов")
        self.cb_hostname.setChecked(True)
        self.cb_mac = QCheckBox("MAC и производитель")
        self.cb_mac.setChecked(True)
        self.cb_ports = QCheckBox("Сканировать порты")
        self.cb_ports.setChecked(True)

        opts = QHBoxLayout()
        opts.addWidget(self.cb_hostname)
        opts.addWidget(self.cb_mac)
        opts.addWidget(self.cb_ports)
        opts.addStretch(1)
        form.addRow("Дополнительно:", self._wrap(opts))

        self.ports_edit = QLineEdit("1-65535")
        self.ports_edit.setPlaceholderText("например, 22,80,443,3389 или 1-65535")
        self.cb_ports.toggled.connect(self.ports_edit.setEnabled)
        form.addRow("Порты:", self.ports_edit)

        root.addWidget(settings)

        # Action row
        actions = QHBoxLayout()
        self.btn_scan = QPushButton(" Сканировать")
        self.btn_scan.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_scan.setObjectName("scan")
        self.btn_stop = QPushButton(" Остановить")
        self.btn_stop.setIcon(self.style().standardIcon(QStyle.SP_MediaStop))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_stop.setObjectName("stop")
        self.btn_clear = QPushButton(" Очистить")
        self.btn_clear.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        self.btn_clear.clicked.connect(self.clear_results)

        self.btn_flags = QPushButton(" Флаги")
        self.btn_flags.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        self.btn_flags.setToolTip("Дополнительные флаги: -Pn, -T<N>, --top-ports, --exclude и др.")
        self.btn_flags.clicked.connect(self._open_flags_dialog)

        actions.addWidget(self.btn_scan)
        actions.addWidget(self.btn_stop)
        actions.addWidget(self.btn_clear)
        actions.addWidget(self.btn_flags)
        actions.addSpacing(15)

        actions.addWidget(QLabel("Фильтр:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Поиск по любой колонке…")
        self.filter_edit.textChanged.connect(self.proxy.setFilterFixedString)
        actions.addWidget(self.filter_edit, 1)

        self.cb_show_dead = QCheckBox("Показывать недоступные")
        self.cb_show_dead.toggled.connect(self.model.set_show_dead)
        actions.addWidget(self.cb_show_dead)

        self.btn_export = QPushButton(" Экспорт")
        self.btn_export.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        self.btn_export.clicked.connect(self.export_results)
        actions.addWidget(self.btn_export)

        root.addLayout(actions)

        # Active flags summary (shown only when at least one flag differs
        # from the defaults).
        self.lbl_flags = QLabel("")
        self.lbl_flags.setStyleSheet(
            "color: #94e2d5; font-style: italic; padding: 2px 4px;"
        )
        self.lbl_flags.setVisible(False)
        root.addWidget(self.lbl_flags)

        # Table
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # Either left-click or right-click on a row pops up the copy menu
        # ("Копировать IP / MAC / …"). Ctrl/Shift+click is left alone so
        # multi-row selection keeps working the regular Qt way.
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_table_menu)
        self.table.clicked.connect(self._on_cell_clicked)
        widths = {0: 80, 1: 130, 2: 200, 3: 160, 4: 180, 5: 90}
        for col, w in widths.items():
            self.table.setColumnWidth(col, w)
        root.addWidget(self.table, 1)

        # Per-tab status row
        status_row = QHBoxLayout()
        self.status_label = QLabel("Готов к сканированию")
        status_row.addWidget(self.status_label, 1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(260)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setValue(0)
        status_row.addWidget(self.progress_bar)
        root.addLayout(status_row)

    def _wrap(self, layout) -> QWidget:
        w = QWidget()
        w.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)
        return w

    # ---------- Flags ----------
    def _open_flags_dialog(self) -> None:
        dlg = FlagsDialog(self.flags, self)
        if dlg.exec() == QDialog.Accepted:
            self.flags = dlg.get_flags()
            self._update_flags_label()

    def _update_flags_label(self) -> None:
        summary = self.flags.to_summary()
        if summary:
            self.lbl_flags.setText(f"Активные флаги: {summary}")
            self.lbl_flags.setVisible(True)
        else:
            self.lbl_flags.clear()
            self.lbl_flags.setVisible(False)

    # ---------- Clipboard / context menu ----------
    def _host_at_proxy(self, proxy_index: QModelIndex) -> Host | None:
        if not proxy_index.isValid():
            return None
        src = self.proxy.mapToSource(proxy_index)
        return self.model.host_at(src.row())

    def _copy_to_clipboard(self, text: str, what: str) -> None:
        if not text:
            return
        QApplication.clipboard().setText(text)
        self.status_label.setText(f"✓ Скопировано: {what}")
        QTimer.singleShot(2500, self._restore_status_label)

    def _restore_status_label(self) -> None:
        # Only revert the "✓ Скопировано: …" notice; never overwrite an
        # in-progress / finished scan status that the worker has set.
        if self.status_label.text().startswith("✓ Скопировано"):
            if self._worker is not None:
                self.status_label.setText("Сканирование продолжается…")
            else:
                self.status_label.setText("Готов к сканированию")

    def _build_copy_menu(self, host: Host) -> QMenu:
        """Construct the copy popup for the given Host."""
        menu = QMenu(self)
        if host.ip:
            menu.addAction(
                f"📋 Копировать IP — {host.ip}",
                lambda: self._copy_to_clipboard(host.ip, host.ip),
            )
        if host.hostname:
            menu.addAction(
                f"📋 Копировать имя хоста — {host.hostname}",
                lambda: self._copy_to_clipboard(host.hostname, host.hostname),
            )
        if host.mac:
            mac_up = host.mac.upper()
            menu.addAction(
                f"📋 Копировать MAC — {mac_up}",
                lambda: self._copy_to_clipboard(mac_up, mac_up),
            )
        if host.vendor:
            menu.addAction(
                "📋 Копировать производителя",
                lambda: self._copy_to_clipboard(host.vendor, host.vendor),
            )
        if host.open_ports:
            ports_str = ", ".join(str(p) for p in host.open_ports)
            menu.addAction(
                "📋 Копировать список портов",
                lambda: self._copy_to_clipboard(ports_str, "список портов"),
            )
        if menu.actions():
            menu.addSeparator()
        menu.addAction(
            "📋 Копировать строку (TSV)",
            lambda: self._copy_row(host),
        )
        return menu

    def _show_table_menu(self, pos) -> None:
        """Right-click handler — show the copy menu at the cursor."""
        proxy_index = self.table.indexAt(pos)
        host = self._host_at_proxy(proxy_index)
        if host is None:
            return
        self._build_copy_menu(host).exec(
            self.table.viewport().mapToGlobal(pos)
        )

    def _on_cell_clicked(self, proxy_index: QModelIndex) -> None:
        """Left-click handler — show the copy menu next to the clicked cell.

        Ctrl/Shift+click is left untouched so that the user can still
        multi-select rows in the regular Qt way.
        """
        if QGuiApplication.keyboardModifiers() & (
            Qt.ControlModifier | Qt.ShiftModifier
        ):
            return
        host = self._host_at_proxy(proxy_index)
        if host is None:
            return
        rect = self.table.visualRect(proxy_index)
        anchor = self.table.viewport().mapToGlobal(rect.bottomLeft())
        self._build_copy_menu(host).exec(anchor)

    def _copy_row(self, host: Host) -> None:
        parts = [
            host.ip,
            host.hostname or "",
            host.mac.upper() if host.mac else "",
            host.vendor or "",
            f"{host.response_ms:.1f}" if host.response_ms is not None else "",
            ",".join(str(p) for p in host.open_ports),
        ]
        self._copy_to_clipboard("\t".join(parts), "вся строка")

    # ---------- Scan control ----------
    def _parse_ports(self, text: str) -> list[int]:
        ports: set[int] = set()
        for chunk in text.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                a, b = chunk.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            else:
                ports.add(int(chunk))
        return sorted(p for p in ports if 1 <= p <= 65535)

    def start_scan(self) -> None:
        target = self.target_edit.text().strip()
        if not target:
            QMessageBox.warning(self, "Цель не указана", "Введите IP-адрес, диапазон или подсеть.")
            return
        try:
            targets = expand_target(target)
        except ValueError as e:
            QMessageBox.critical(self, "Ошибка", f"Некорректная цель: {e}")
            return
        if not targets:
            QMessageBox.warning(self, "Цель пуста", "Не удалось получить список адресов для сканирования.")
            return

        f = self.flags

        # --exclude: drop excluded addresses from the targets list.
        if f.exclude_text.strip():
            excluded: set[str] = set()
            for chunk in (c.strip() for c in f.exclude_text.split(",")):
                if not chunk:
                    continue
                try:
                    excluded.update(expand_target(chunk))
                except ValueError:
                    QMessageBox.critical(
                        self, "Ошибка",
                        f"Некорректное значение в --exclude: {chunk!r}",
                    )
                    return
            targets = [t for t in targets if t not in excluded]
            if not targets:
                QMessageBox.warning(
                    self, "Цель пуста",
                    "После применения --exclude не осталось адресов для сканирования.",
                )
                return

        if len(targets) > 4096:
            ans = QMessageBox.question(
                self,
                "Много адресов",
                f"Цель содержит {len(targets)} адресов. Продолжить?",
            )
            if ans != QMessageBox.Yes:
                return

        # Build the port list. --top-ports overrides the manual ports field;
        # --randomize-ports shuffles the resulting list.
        ports: list[int] = []
        if self.cb_ports.isChecked():
            if f.top_ports > 0:
                ports = list(TOP_PORTS[:f.top_ports])
            else:
                try:
                    ports = self._parse_ports(self.ports_edit.text())
                except ValueError:
                    QMessageBox.critical(self, "Ошибка", "Некорректный список портов.")
                    return
            if f.randomize_ports:
                random.shuffle(ports)

        # -T<N>: timing template overrides the manual ping-timeout / workers
        # spin-boxes when something other than T3 (the default) is selected.
        if f.timing != 3:
            _, _, ping_timeout_ms, workers = TIMING_TEMPLATES[f.timing]
        else:
            ping_timeout_ms = self.ping_timeout.value()
            workers = self.workers.value()

        self.model.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(max(1, len(targets)))
        self.status_label.setText(f"Сканирование {len(targets)} адресов…")
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)

        # For wide port ranges (e.g. 1-65535) bump per-host scan parallelism
        # and shorten the per-port timeout so the scan completes in reasonable
        # time. Small port lists keep the conservative defaults.
        if len(ports) > 1024:
            port_workers = 128
            port_timeout = 0.3
        else:
            port_workers = 64
            port_timeout = 0.6

        self._thread = QThread(self)
        self._worker = ScanWorker(
            targets=targets,
            ping_timeout_ms=ping_timeout_ms,
            workers=workers,
            resolve_hostnames=self.cb_hostname.isChecked(),
            detect_mac=self.cb_mac.isChecked(),
            ports=ports,
            port_timeout=port_timeout,
            port_workers=port_workers,
            skip_ping=f.skip_ping,
            ping_retries=f.retries,
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.host_found.connect(self.model.upsert)
        self._worker.port_progress.connect(self.model.update_progress)
        self._worker.progress.connect(self._on_progress)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._on_finished)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def stop_scan(self) -> None:
        if self._worker:
            self._worker.cancel()
            self.status_label.setText("Останавливаю сканирование…")

    def _on_progress(self, done: int, total: int) -> None:
        self.progress_bar.setMaximum(max(1, total))
        self.progress_bar.setValue(done)
        alive = len(self.model.alive_hosts())
        self.status_label.setText(
            f"Просканировано {done}/{total} • найдено активных: {alive}"
        )

    def _on_error(self, message: str) -> None:
        QMessageBox.critical(self, "Ошибка сканирования", message)

    def _on_finished(self) -> None:
        alive = len(self.model.alive_hosts())
        total = self.progress_bar.maximum()
        self.status_label.setText(
            f"Сканирование завершено • {total} адресов • активных: {alive}"
        )
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self._thread = None
        self._worker = None

    def clear_results(self) -> None:
        self.model.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Готов к сканированию")

    # ---------- Export ----------
    def export_results(self) -> None:
        hosts = self.model.alive_hosts() if not self.cb_show_dead.isChecked() else self.model.hosts()
        if not hosts:
            QMessageBox.information(self, "Нет данных", "Сначала запустите сканирование.")
            return

        default_name = f"scan_results_{datetime.now():%Y%m%d_%H%M%S}.csv"
        path_str, selected = QFileDialog.getSaveFileName(
            self,
            "Экспорт результатов",
            default_name,
            "CSV (*.csv);;JSON (*.json)",
        )
        if not path_str:
            return
        path = Path(path_str)

        try:
            if path.suffix.lower() == ".json" or "JSON" in selected:
                with path.open("w", encoding="utf-8") as f:
                    json.dump([h.to_dict() for h in hosts], f, ensure_ascii=False, indent=2)
            else:
                with path.open("w", encoding="utf-8", newline="") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=["ip", "alive", "hostname", "mac", "vendor", "response_ms", "open_ports"],
                    )
                    writer.writeheader()
                    for h in hosts:
                        writer.writerow(h.to_dict())
        except OSError as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить файл:\n{e}")
            return

        QMessageBox.information(self, "Готово", f"Сохранено {len(hosts)} записей:\n{path}")

    def shutdown(self) -> None:
        if self._worker:
            self._worker.cancel()
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(2000)


class WifiTab(QWidget):
    """Tab showing current Wi-Fi connection and router information."""

    REFRESH_MS = 2000

    # info, gateway_ip, gateway_mac, gateway_vendor, gateway_ping_ms (or None)
    refreshed = Signal(dict, str, str, str, object)

    def __init__(
        self,
        local_model: HostsModel | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._local_model = local_model
        self._build_ui()
        self.refreshed.connect(self._apply_refresh)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(self.REFRESH_MS)
        QTimer.singleShot(0, self._refresh)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        mono = QFont("Consolas")

        # ---- Wi-Fi connection info ----
        wifi_box = QGroupBox("Текущее Wi-Fi подключение")
        wifi_box.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        wifi_box_layout = QVBoxLayout(wifi_box)
        wifi_box_layout.setContentsMargins(8, 8, 8, 8)

        self.wifi_stack = QStackedWidget()
        # Page 0 — connected: form with all fields.
        connected_page = QWidget()
        wifi_form = QFormLayout(connected_page)
        wifi_form.setLabelAlignment(Qt.AlignRight)
        wifi_form.setContentsMargins(0, 0, 0, 0)
        self.lbl_iface = QLabel("—")
        self.lbl_ssid = QLabel("—")
        self.lbl_bssid = QLabel("—")
        self.lbl_signal = QLabel("—")
        self.lbl_channel = QLabel("—")
        self.lbl_radio = QLabel("—")
        self.lbl_auth = QLabel("—")
        self.lbl_speed = QLabel("—")
        for lbl in (self.lbl_ssid, self.lbl_bssid):
            lbl.setFont(mono)
        wifi_form.addRow("Интерфейс:", self.lbl_iface)
        wifi_form.addRow("SSID:", self.lbl_ssid)
        wifi_form.addRow("BSSID:", self.lbl_bssid)
        wifi_form.addRow("Сигнал:", self.lbl_signal)
        wifi_form.addRow("Канал:", self.lbl_channel)
        wifi_form.addRow("Тип радио:", self.lbl_radio)
        wifi_form.addRow("Безопасность:", self.lbl_auth)
        wifi_form.addRow("Скорость канала:", self.lbl_speed)

        # Page 1 — disconnected: a single centred message.
        disconnected_page = QWidget()
        disconnected_layout = QVBoxLayout(disconnected_page)
        disconnected_layout.setContentsMargins(0, 16, 0, 16)
        self.lbl_disconnected = QLabel("📡 Wi-Fi не подключен")
        self.lbl_disconnected.setAlignment(Qt.AlignCenter)
        self.lbl_disconnected.setStyleSheet(
            "color: #f9e2af; font-size: 18px; font-weight: bold; padding: 20px;"
        )
        disconnected_layout.addWidget(self.lbl_disconnected)

        self.wifi_stack.addWidget(connected_page)     # index 0
        self.wifi_stack.addWidget(disconnected_page)  # index 1
        wifi_box_layout.addWidget(self.wifi_stack)
        root.addWidget(wifi_box)

        # ---- Router info ----
        router_box = QGroupBox("Роутер")
        router_box.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        router_form = QFormLayout(router_box)
        router_form.setLabelAlignment(Qt.AlignRight)
        self.lbl_gw_ip = QLabel("—")
        self.lbl_gw_mac = QLabel("—")
        self.lbl_gw_vendor = QLabel("—")
        self.lbl_clients = QLabel("—")
        self.lbl_gw_ip.setFont(mono)
        self.lbl_gw_mac.setFont(mono)
        self.btn_admin = QPushButton("Открыть админку в браузере")
        self.btn_admin.clicked.connect(self._open_admin)
        self.btn_admin.setEnabled(False)
        router_form.addRow("IP-адрес:", self.lbl_gw_ip)
        router_form.addRow("MAC-адрес:", self.lbl_gw_mac)
        router_form.addRow("Производитель:", self.lbl_gw_vendor)
        router_form.addRow("Клиентов в сети:", self.lbl_clients)
        router_form.addRow("", self.btn_admin)
        root.addWidget(router_box)

        # ---- Graphs ----
        graphs_box = QGroupBox("Графики (обновление каждые 2 с)")
        graphs_box.setMinimumHeight(190)
        graphs_box.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        graphs_layout = QHBoxLayout(graphs_box)
        # Ping-to-router graph works on every connection (wired or Wi-Fi).
        self.ping_graph = SparklineWidget(title="Пинг до роутера", unit="мс", color="#cba6f7")
        self.signal_graph = SparklineWidget(title="Сигнал", unit="%", color="#a6e3a1")
        self.rx_graph = SparklineWidget(title="Приём", unit="Мбит/с", color="#89b4fa")
        self.tx_graph = SparklineWidget(title="Передача", unit="Мбит/с", color="#fab387")
        graphs_layout.addWidget(self.ping_graph, 1)
        graphs_layout.addWidget(self.signal_graph, 1)
        graphs_layout.addWidget(self.rx_graph, 1)
        graphs_layout.addWidget(self.tx_graph, 1)
        root.addWidget(graphs_box, 1)

    def _refresh(self) -> None:
        # Run blocking IO (netsh, ipconfig, ping, ARP) in a background thread
        # so the UI stays responsive; results come back via the `refreshed`
        # Qt signal, which is processed in the main thread.
        threading.Thread(target=self._do_refresh_bg, daemon=True).start()

    def _do_refresh_bg(self) -> None:
        try:
            info = get_wifi_info()
        except Exception:  # noqa: BLE001
            info = {}
        try:
            gw = get_default_gateway()
        except Exception:  # noqa: BLE001
            gw = ""
        mac = ""
        vendor = ""
        rtt: float | None = None
        if gw:
            try:
                alive, rtt_value = ping(gw, timeout_ms=500)
                if alive and rtt_value is not None:
                    rtt = rtt_value
                arp = _parse_arp_table()
                mac = arp.get(gw, "")
                if mac:
                    vendor = lookup_vendor(mac)
            except Exception:  # noqa: BLE001
                pass
        self.refreshed.emit(info, gw, mac, vendor, rtt)

    def _apply_refresh(
        self, info: dict, gw: str, mac: str, vendor: str, rtt,
    ) -> None:
        def pick(*keys: str) -> str:
            for k in keys:
                if k in info and info[k]:
                    return info[k]
            return ""

        name = pick("Name", "Имя")
        state = pick("State", "Состояние")
        ssid = pick("SSID")
        bssid = pick("BSSID")
        signal = pick("Signal", "Сигнал")
        channel = pick("Channel", "Канал")
        radio = pick("Radio type", "Тип радио")
        auth = pick("Authentication", "Проверка подлинности")
        rx = pick(
            "Receive rate (Mbps)",
            "Скорость приема (Мбит/с)",
            "Скорость приёма (Мбит/с)",
        )
        tx = pick("Transmit rate (Mbps)", "Скорость передачи (Мбит/с)")

        connected = bool(ssid) or (
            bool(info) and state.lower().startswith(("connected", "подкл"))
        )

        if connected:
            self.wifi_stack.setCurrentIndex(0)
            self.lbl_iface.setText(name or "—")
            self.lbl_ssid.setText(ssid or "—")
            self.lbl_bssid.setText(bssid.upper() if bssid else "—")
            self.lbl_signal.setText(signal or "—")
            self.lbl_channel.setText(channel or "—")
            self.lbl_radio.setText(radio or "—")
            self.lbl_auth.setText(auth or "—")
            speed_parts = []
            if rx:
                speed_parts.append(f"RX {rx} Мбит/с")
            if tx:
                speed_parts.append(f"TX {tx} Мбит/с")
            self.lbl_speed.setText(" · ".join(speed_parts) if speed_parts else "—")
        else:
            self.wifi_stack.setCurrentIndex(1)
            if not info:
                self.lbl_disconnected.setText(
                    "📡 Wi-Fi не подключен\n(беспроводной адаптер не обнаружен)"
                )
            else:
                self.lbl_disconnected.setText("📡 Wi-Fi не подключен")

        # Router info
        self.lbl_gw_ip.setText(gw or "—")
        self.btn_admin.setEnabled(bool(gw))
        self.lbl_gw_mac.setText(mac.upper() if mac else "—")
        self.lbl_gw_vendor.setText(vendor or "—")

        # Clients count from local scan tab
        if self._local_model is not None:
            alive = len(self._local_model.alive_hosts())
            self.lbl_clients.setText(f"{alive}")
        else:
            self.lbl_clients.setText("—")

        # Update graphs. Ping graph works on any link (wired or wireless);
        # the Wi-Fi graphs only get fed while a Wi-Fi connection is active.
        if rtt is not None:
            self.ping_graph.add_value(rtt)
        if connected:
            if signal:
                try:
                    digits = re.sub(r"[^\d]", "", signal)
                    if digits:
                        self.signal_graph.add_value(int(digits))
                except ValueError:
                    pass
            if rx:
                try:
                    self.rx_graph.add_value(float(rx))
                except ValueError:
                    pass
            if tx:
                try:
                    self.tx_graph.add_value(float(tx))
                except ValueError:
                    pass

    def _open_admin(self) -> None:
        ip = self.lbl_gw_ip.text().strip()
        if not ip or ip == "—":
            return
        QDesktopServices.openUrl(QUrl(f"http://{ip}"))

    def shutdown(self) -> None:
        self._timer.stop()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("IPbrowse — Сканер локальной сети")
        self.resize(1200, 760)

        self.tabs = QTabWidget(self)
        self.setCentralWidget(self.tabs)

        self.local_tab = ScanTab(
            default_target=detect_local_subnet(),
            show_auto_detect=True,
            auto_start=True,
        )
        self.external_tab = ScanTab(
            default_target="",
            show_auto_detect=False,
            auto_start=False,
            warning_text=(
                "⚠ Сканирование внешних сетей может нарушать правила провайдера и "
                "действующее законодательство. Сканируйте только те ресурсы, "
                "на которые у вас есть явное разрешение."
            ),
        )
        self.wifi_tab = WifiTab(local_model=self.local_tab.model)

        self.tabs.addTab(self.local_tab, "Локальная сеть")
        self.tabs.addTab(self.external_tab, "Внешние сети")
        self.tabs.addTab(self.wifi_tab, "Wi-Fi")

        self._apply_dark_theme()

    def _apply_dark_theme(self) -> None:
        self.setStyleSheet(
            """
            QWidget { background-color: #1e1e2e; color: #cdd6f4; font-size: 13px; }
            QGroupBox {
                border: 1px solid #45475a; border-radius: 6px;
                margin-top: 10px; padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin; subcontrol-position: top left;
                left: 10px; padding: 0 5px; color: #89b4fa;
            }
            QLineEdit, QSpinBox, QComboBox {
                background: #313244; border: 1px solid #45475a;
                border-radius: 4px; padding: 4px 6px; selection-background-color: #585b70;
            }
            QLineEdit:focus, QSpinBox:focus { border: 1px solid #89b4fa; }
            QPushButton {
                background: #45475a; color: #cdd6f4; border: none;
                padding: 6px 12px; border-radius: 4px;
            }
            QPushButton:hover { background: #585b70; }
            QPushButton:pressed { background: #6c7086; }
            QPushButton:disabled { background: #313244; color: #6c7086; }
            QPushButton#scan { background: #89b4fa; color: #1e1e2e; font-weight: bold; }
            QPushButton#scan:hover { background: #b4befe; }
            QPushButton#stop { background: #f38ba8; color: #1e1e2e; }
            QPushButton#stop:hover { background: #eba0ac; }
            QTableView {
                background: #181825; alternate-background-color: #1e1e2e;
                gridline-color: #313244; selection-background-color: #585b70;
                selection-color: #cdd6f4; border: 1px solid #313244; border-radius: 4px;
            }
            QHeaderView::section {
                background: #313244; color: #89b4fa; padding: 6px;
                border: none; border-right: 1px solid #45475a; font-weight: bold;
            }
            QStatusBar { background: #181825; color: #cdd6f4; }
            QProgressBar {
                background: #313244; border: 1px solid #45475a;
                border-radius: 3px; text-align: center; height: 16px;
            }
            QProgressBar::chunk { background: #a6e3a1; border-radius: 2px; }
            QCheckBox { spacing: 6px; }
            QCheckBox::indicator { width: 14px; height: 14px; }
            QCheckBox::indicator:unchecked {
                border: 1px solid #6c7086; background: #313244; border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #89b4fa; background: #89b4fa; border-radius: 3px;
            }
            QTabWidget::pane {
                border: 1px solid #313244; border-radius: 4px; background: #1e1e2e;
                top: -1px;
            }
            QTabBar::tab {
                background: #313244; color: #cdd6f4;
                padding: 8px 18px; border-top-left-radius: 6px;
                border-top-right-radius: 6px; margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #89b4fa; color: #1e1e2e; font-weight: bold;
            }
            QTabBar::tab:hover:!selected { background: #45475a; }
            QToolTip { background: #313244; color: #cdd6f4; border: 1px solid #45475a; }
            """
        )

    def closeEvent(self, event) -> None:  # noqa: N802
        self.local_tab.shutdown()
        self.external_tab.shutdown()
        self.wifi_tab.shutdown()
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("IPbrowse")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
