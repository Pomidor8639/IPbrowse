"""IPbrowse - Local network scanner with PySide6 GUI."""
from __future__ import annotations

import csv
import json
import os
import random
import re
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    QInputDialog,
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
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from scanner import (
    COMMON_PORTS,
    Host,
    IS_WINDOWS,
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

    # Scan method (informational — this scanner is TCP-connect only)
    tcp_connect: bool = False               # -sT (default behaviour, explicit)
    # Host discovery
    skip_ping: bool = False                 # -Pn
    arp_discovery: bool = False             # -PR (ARP cache supplement)
    retries: int = 1                        # --retry N; 1 = no extra retries
    randomize_hosts: bool = False           # --randomize-hosts
    # Resolution / identification
    no_dns: bool = False                    # -n / --no-dns
    no_mac: bool = False                    # --no-mac
    os_detect: bool = False                 # -O (TTL-based OS guess)
    version_detect: bool = False            # -sV (banner grabbing)
    # Timing
    timing: int = 3                         # -T<N>; 3 = no override
    host_timeout_ms: int = 0                # --host-timeout <ms>; 0 = auto
    # Ports
    no_ports: bool = False                  # -sn (skip port scan, ping only)
    fast_scan: bool = False                 # -F (top-100 alias)
    all_ports: bool = False                 # -p- (all ports, 1-65535)
    top_ports: int = 0                      # --top-ports N; 0 = disabled
    randomize_ports: bool = False           # --randomize-ports
    max_parallel: int = 0                   # --max-parallel N; 0 = auto
    # Exclusions
    exclude_text: str = ""                  # --exclude IPs / ranges
    # Output (auto-export when scan finishes if path is set)
    output_format: str = ""                 # "" / "normal" / "xml" / "grepable"
    output_path: str = ""                   # -oN / -oX / -oG <file>; "" = disabled

    def is_default(self) -> bool:
        return self == ScanFlags()

    def to_summary(self) -> str:
        """Human-readable summary like ``-Pn -T4 --top-ports 100``."""
        parts: list[str] = []
        if self.tcp_connect:
            parts.append("-sT")
        if self.skip_ping:
            parts.append("-Pn")
        if self.arp_discovery:
            parts.append("-PR")
        if self.no_dns:
            parts.append("-n")
        if self.no_mac:
            parts.append("--no-mac")
        if self.os_detect:
            parts.append("-O")
        if self.version_detect:
            parts.append("-sV")
        if self.no_ports:
            parts.append("-sn")
        if self.timing != 3:
            parts.append(f"-T{self.timing}")
        if self.host_timeout_ms > 0:
            parts.append(f"--host-timeout {self.host_timeout_ms}ms")
        if self.max_parallel > 0:
            parts.append(f"--max-parallel {self.max_parallel}")
        if self.fast_scan:
            parts.append("-F")
        if self.all_ports:
            parts.append("-p-")
        if self.top_ports:
            parts.append(f"--top-ports {self.top_ports}")
        if self.randomize_ports:
            parts.append("--randomize-ports")
        if self.randomize_hosts:
            parts.append("--randomize-hosts")
        if self.retries > 1:
            parts.append(f"--retry {self.retries}")
        if self.exclude_text.strip():
            parts.append(f"--exclude {self.exclude_text.strip()}")
        if self.output_format and self.output_path:
            switch = {
                "normal": "-oN",
                "xml": "-oX",
                "grepable": "-oG",
            }.get(self.output_format, "")
            if switch:
                parts.append(f"{switch} {self.output_path}")
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
        self.resize(680, 640)
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

        # The dialog is now tall enough that it can overflow on small
        # screens; wrap everything in a scroll area so every flag stays
        # reachable regardless of resolution.
        from PySide6.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll_inner = QWidget()
        body = QVBoxLayout(scroll_inner)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(10)

        # ---- Scan method ----
        method_box = QGroupBox("Метод сканирования")
        method_layout = QVBoxLayout(method_box)
        method_layout.setSpacing(6)

        self.cb_tcp_connect = QCheckBox()
        sct_row = QHBoxLayout()
        sct_row.addWidget(self.cb_tcp_connect)
        sct_row.addWidget(self._flag_label("-sT"))
        sct_row.addWidget(QLabel(
            "TCP Connect — единственный режим (полный TCP-handshake; помечается явно)"
        ), 1)
        method_layout.addLayout(sct_row)

        unsup = QLabel(
            "Недоступно без nmap / прав администратора:  -sS (SYN), "
            "-sU (UDP), -sO (IP protocol), -A (Aggressive), "
            "-sC / --script (NSE), -D (decoy), -f (fragmentation)."
        )
        unsup.setWordWrap(True)
        unsup.setStyleSheet("color: #f9e2af; font-style: italic;")
        method_layout.addWidget(unsup)

        body.addWidget(method_box)

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

        self.cb_arp_discovery = QCheckBox()
        pr_row = QHBoxLayout()
        pr_row.addWidget(self.cb_arp_discovery)
        pr_row.addWidget(self._flag_label("-PR"))
        pr_row.addWidget(QLabel(
            "Дополнительно проверять активность по ARP-кэшу "
            "(находит устройства, блокирующие ICMP)"
        ), 1)
        host_layout.addLayout(pr_row)

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

        self.cb_randomize_hosts = QCheckBox()
        rh_row = QHBoxLayout()
        rh_row.addWidget(self.cb_randomize_hosts)
        rh_row.addWidget(self._flag_label("--randomize-hosts"))
        rh_row.addWidget(QLabel(
            "Случайный порядок обхода адресов в цели"
        ), 1)
        host_layout.addLayout(rh_row)

        body.addWidget(host_box)

        # ---- Resolution / identification ----
        resolve_box = QGroupBox("Резолв и идентификация")
        resolve_layout = QVBoxLayout(resolve_box)
        resolve_layout.setSpacing(6)

        self.cb_no_dns = QCheckBox()
        nd_row = QHBoxLayout()
        nd_row.addWidget(self.cb_no_dns)
        nd_row.addWidget(self._flag_label("-n / --no-dns"))
        nd_row.addWidget(QLabel(
            "Не выполнять обратный DNS (отменяет «Имена хостов»)"
        ), 1)
        resolve_layout.addLayout(nd_row)

        self.cb_no_mac = QCheckBox()
        nm_row = QHBoxLayout()
        nm_row.addWidget(self.cb_no_mac)
        nm_row.addWidget(self._flag_label("--no-mac"))
        nm_row.addWidget(QLabel(
            "Не определять MAC и производителя (отменяет «MAC и производитель»)"
        ), 1)
        resolve_layout.addLayout(nm_row)

        self.cb_os_detect = QCheckBox()
        os_row = QHBoxLayout()
        os_row.addWidget(self.cb_os_detect)
        os_row.addWidget(self._flag_label("-O"))
        os_row.addWidget(QLabel(
            "Определять семейство ОС по TTL ответа ping (Linux/Windows/сетевое)"
        ), 1)
        resolve_layout.addLayout(os_row)

        self.cb_version_detect = QCheckBox()
        sv_row = QHBoxLayout()
        sv_row.addWidget(self.cb_version_detect)
        sv_row.addWidget(self._flag_label("-sV"))
        sv_row.addWidget(QLabel(
            "Снимать баннеры с открытых портов (SSH / HTTP / FTP / SMTP / …)"
        ), 1)
        resolve_layout.addLayout(sv_row)

        body.addWidget(resolve_box)

        # ---- Timing ----
        timing_box = QGroupBox("Тайминг")
        timing_layout = QVBoxLayout(timing_box)
        timing_layout.setSpacing(6)

        tt_row = QHBoxLayout()
        tt_row.addWidget(self._flag_label("-T<N>"))
        tt_row.addWidget(QLabel("Шаблон скорости:"))
        self.cmb_timing = QComboBox()
        for tid, (name, desc, _, _) in TIMING_TEMPLATES.items():
            self.cmb_timing.addItem(f"T{tid} — {name} ({desc})", tid)
        self.cmb_timing.setCurrentIndex(3)
        tt_row.addWidget(self.cmb_timing, 1)
        timing_layout.addLayout(tt_row)

        self.cb_host_timeout = QCheckBox()
        ht_row = QHBoxLayout()
        ht_row.addWidget(self.cb_host_timeout)
        ht_row.addWidget(self._flag_label("--host-timeout"))
        ht_row.addWidget(QLabel("Таймаут TCP-конекта на порт:"))
        self.sp_host_timeout = QSpinBox()
        self.sp_host_timeout.setRange(50, 10000)
        self.sp_host_timeout.setSingleStep(50)
        self.sp_host_timeout.setValue(600)
        self.sp_host_timeout.setSuffix(" мс")
        ht_row.addWidget(self.sp_host_timeout)
        ht_row.addStretch(1)
        timing_layout.addLayout(ht_row)

        body.addWidget(timing_box)

        # ---- Ports ----
        ports_box = QGroupBox("Порты")
        ports_layout = QVBoxLayout(ports_box)
        ports_layout.setSpacing(6)

        self.cb_no_ports = QCheckBox()
        sn_row = QHBoxLayout()
        sn_row.addWidget(self.cb_no_ports)
        sn_row.addWidget(self._flag_label("-sn / --no-ports"))
        sn_row.addWidget(QLabel(
            "Только обнаружение хостов, без сканирования портов"
        ), 1)
        ports_layout.addLayout(sn_row)

        self.cb_fast_scan = QCheckBox()
        f_row = QHBoxLayout()
        f_row.addWidget(self.cb_fast_scan)
        f_row.addWidget(self._flag_label("-F"))
        f_row.addWidget(QLabel(
            "Fast scan — только 100 самых популярных портов "
            "(алиас --top-ports 100)"
        ), 1)
        ports_layout.addLayout(f_row)

        self.cb_all_ports = QCheckBox()
        ap_row = QHBoxLayout()
        ap_row.addWidget(self.cb_all_ports)
        ap_row.addWidget(self._flag_label("-p-"))
        ap_row.addWidget(QLabel(
            "Сканировать все 65 535 портов (алиас 1-65535)"
        ), 1)
        ports_layout.addLayout(ap_row)

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

        self.cb_max_parallel = QCheckBox()
        mp_row = QHBoxLayout()
        mp_row.addWidget(self.cb_max_parallel)
        mp_row.addWidget(self._flag_label("--max-parallel"))
        mp_row.addWidget(QLabel("Параллельных портов на хост:"))
        self.sp_max_parallel = QSpinBox()
        self.sp_max_parallel.setRange(1, 1024)
        self.sp_max_parallel.setValue(64)
        mp_row.addWidget(self.sp_max_parallel)
        mp_row.addStretch(1)
        ports_layout.addLayout(mp_row)

        body.addWidget(ports_box)

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
        body.addWidget(excl_box)

        # ---- Output ----
        out_box = QGroupBox("Вывод (автоматический экспорт по окончании)")
        out_layout = QVBoxLayout(out_box)
        out_layout.setSpacing(6)

        self.cb_output = QCheckBox()
        of_row = QHBoxLayout()
        of_row.addWidget(self.cb_output)
        of_row.addWidget(self._flag_label("-oN / -oX / -oG"))
        of_row.addWidget(QLabel("Сохранять результат в файл:"))
        self.cmb_output_format = QComboBox()
        self.cmb_output_format.addItem("-oN  Текст (Normal)", "normal")
        self.cmb_output_format.addItem("-oX  XML", "xml")
        self.cmb_output_format.addItem("-oG  Grepable", "grepable")
        of_row.addWidget(self.cmb_output_format)
        of_row.addStretch(1)
        out_layout.addLayout(of_row)

        path_row = QHBoxLayout()
        self.le_output_path = QLineEdit()
        self.le_output_path.setPlaceholderText(
            "путь к файлу (оставьте пустым — спросим при сохранении)"
        )
        path_row.addWidget(self.le_output_path, 1)
        btn_browse = QPushButton("Обзор…")
        btn_browse.clicked.connect(self._pick_output_path)
        path_row.addWidget(btn_browse)
        out_layout.addLayout(path_row)

        body.addWidget(out_box)

        body.addStretch(1)
        scroll.setWidget(scroll_inner)
        root.addWidget(scroll, 1)

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

    def _pick_output_path(self) -> None:
        """Open a save dialog and write the chosen path into the line edit."""
        fmt_data = self.cmb_output_format.currentData() or "normal"
        ext, label = {
            "normal":   ("txt",  "Text (*.txt)"),
            "xml":      ("xml",  "XML (*.xml)"),
            "grepable": ("gnmap", "Grepable (*.gnmap)"),
        }[fmt_data]
        default = f"scan_{datetime.now():%Y%m%d_%H%M%S}.{ext}"
        path, _ = QFileDialog.getSaveFileName(
            self, "Файл для автоэкспорта", default, label
        )
        if path:
            self.le_output_path.setText(path)
            self.cb_output.setChecked(True)

    # ----- Data binding -----
    def _apply_to_ui(self, f: ScanFlags) -> None:
        # Method
        self.cb_tcp_connect.setChecked(f.tcp_connect)
        # Host discovery
        self.cb_skip_ping.setChecked(f.skip_ping)
        self.cb_arp_discovery.setChecked(f.arp_discovery)
        self.cb_retries.setChecked(f.retries > 1)
        if f.retries > 1:
            self.sp_retries.setValue(f.retries)
        self.cb_randomize_hosts.setChecked(f.randomize_hosts)
        # Resolution
        self.cb_no_dns.setChecked(f.no_dns)
        self.cb_no_mac.setChecked(f.no_mac)
        self.cb_os_detect.setChecked(f.os_detect)
        self.cb_version_detect.setChecked(f.version_detect)
        # Timing
        idx = self.cmb_timing.findData(f.timing)
        self.cmb_timing.setCurrentIndex(idx if idx >= 0 else 3)
        self.cb_host_timeout.setChecked(f.host_timeout_ms > 0)
        if f.host_timeout_ms > 0:
            self.sp_host_timeout.setValue(f.host_timeout_ms)
        # Ports
        self.cb_no_ports.setChecked(f.no_ports)
        self.cb_fast_scan.setChecked(f.fast_scan)
        self.cb_all_ports.setChecked(f.all_ports)
        self.cb_top_ports.setChecked(f.top_ports > 0)
        if f.top_ports > 0:
            self.sp_top_ports.setValue(f.top_ports)
        self.cb_randomize.setChecked(f.randomize_ports)
        self.cb_max_parallel.setChecked(f.max_parallel > 0)
        if f.max_parallel > 0:
            self.sp_max_parallel.setValue(f.max_parallel)
        # Exclusions
        self.le_exclude.setText(f.exclude_text)
        # Output
        self.cb_output.setChecked(bool(f.output_format and f.output_path))
        if f.output_format:
            i = self.cmb_output_format.findData(f.output_format)
            if i >= 0:
                self.cmb_output_format.setCurrentIndex(i)
        self.le_output_path.setText(f.output_path)

    def _reset(self) -> None:
        self._apply_to_ui(ScanFlags())

    def get_flags(self) -> ScanFlags:
        out_on = self.cb_output.isChecked() and bool(
            self.le_output_path.text().strip()
        )
        return ScanFlags(
            tcp_connect=self.cb_tcp_connect.isChecked(),
            skip_ping=self.cb_skip_ping.isChecked(),
            arp_discovery=self.cb_arp_discovery.isChecked(),
            retries=self.sp_retries.value() if self.cb_retries.isChecked() else 1,
            randomize_hosts=self.cb_randomize_hosts.isChecked(),
            no_dns=self.cb_no_dns.isChecked(),
            no_mac=self.cb_no_mac.isChecked(),
            os_detect=self.cb_os_detect.isChecked(),
            version_detect=self.cb_version_detect.isChecked(),
            timing=int(self.cmb_timing.currentData()),
            host_timeout_ms=(
                self.sp_host_timeout.value() if self.cb_host_timeout.isChecked() else 0
            ),
            no_ports=self.cb_no_ports.isChecked(),
            fast_scan=self.cb_fast_scan.isChecked(),
            all_ports=self.cb_all_ports.isChecked(),
            top_ports=self.sp_top_ports.value() if self.cb_top_ports.isChecked() else 0,
            randomize_ports=self.cb_randomize.isChecked(),
            max_parallel=(
                self.sp_max_parallel.value() if self.cb_max_parallel.isChecked() else 0
            ),
            exclude_text=self.le_exclude.text().strip(),
            output_format=self.cmb_output_format.currentData() if out_on else "",
            output_path=self.le_output_path.text().strip() if out_on else "",
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
                return "Online" if host.alive else "Offline"
            if key == "ip":
                return host.ip
            if key == "hostname":
                return host.hostname or "—"
            if key == "mac":
                return host.mac.upper() if host.mac else "—"
            if key == "vendor":
                # -O: OS guess from TTL is shown here next to the vendor.
                # Either may be empty; combine with " • " when both exist.
                if host.vendor and host.os_guess:
                    return f"{host.vendor} • {host.os_guess}"
                return host.vendor or host.os_guess or "—"
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
                    banner = host.banners.get(p, "") if host.banners else ""
                    if banner:
                        # Trim the banner to keep the cell compact; the
                        # full banner is available via the copy menu.
                        short = banner[:40]
                        if len(banner) > 40:
                            short += "…"
                        if name:
                            parts.append(f"{p} ({name}: {short})")
                        else:
                            parts.append(f"{p} ({short})")
                    elif name:
                        parts.append(f"{p} ({name})")
                    else:
                        parts.append(str(p))
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
        arp_discovery: bool = False,
        os_detect: bool = False,
        version_detect: bool = False,
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
        self.arp_discovery = arp_discovery
        self.os_detect = os_detect
        self.version_detect = version_detect
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            total = len(self.targets)
            # Per-IP progress weight in [0.0, 1.0]. Summing gives the number
            # of IPs effectively scanned so far — this lets the progress bar
            # advance smoothly *during* phase 2 port scans instead of
            # freezing on the count of dead hosts until every port sweep
            # finishes. Milestones:
            #   0.1 — alive detected in phase 1 (ping reply)
            #   0.2 — hostname / MAC resolved (start of phase 2)
            #   0.2 + 0.8 * ports_done / ports_total — port sweep progress
            #   1.0 — host fully scanned (dead in phase 1 or phase 2 done)
            weights: dict[str, float] = {ip: 0.0 for ip in self.targets}

            def _emit_progress() -> None:
                done = int(sum(weights.values()))
                self.progress.emit(done, total)

            _emit_progress()

            def _on_partial(host: Host) -> None:
                if host.ip in weights:
                    weights[host.ip] = max(weights[host.ip], 0.2)
                self.host_found.emit(host)
                _emit_progress()

            def _on_port_progress(ip: str, d: int, t: int) -> None:
                # Keep the assignment monotonic — callbacks for different
                # ports of the same host can race against the final
                # phase-2 yield that already bumped this IP's weight to 1.0.
                if ip in weights and t > 0:
                    weights[ip] = max(weights[ip], 0.2 + 0.8 * (d / t))
                self.port_progress.emit(ip, d, t)
                _emit_progress()

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
                arp_discovery=self.arp_discovery,
                os_detect=self.os_detect,
                version_detect=self.version_detect,
            ):
                self.host_found.emit(host)
                if host.ip in weights:
                    if host.scan_complete:
                        weights[host.ip] = 1.0
                    elif host.alive:
                        # Phase 1 alive detection — keep the value monotonic
                        # in case _on_partial has already bumped it to 0.2.
                        weights[host.ip] = max(weights[host.ip], 0.1)
                _emit_progress()
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
            # Defer the scan a bit so the window has time to paint and the
            # initial process-spawn storm (one ping per IP) doesn't make
            # the UI feel laggy on startup.
            QTimer.singleShot(800, self.start_scan)

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
        self.btn_flags.setToolTip(
            "Дополнительные флаги сканирования:\n"
            "-sT, -Pn, -PR, -n, --no-mac, -O, -sV, -sn, -F, -p-,\n"
            "-T<N>, --host-timeout, --top-ports, --randomize-hosts,\n"
            "--randomize-ports, --max-parallel, --retry, --exclude,\n"
            "-oN / -oX / -oG (автоэкспорт)"
        )
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
        self.status_label.setText(f"Скопировано: {what}")
        QTimer.singleShot(2500, self._restore_status_label)

    def _restore_status_label(self) -> None:
        # Only revert transient notices ("Скопировано: …", "SSH → …");
        # never overwrite an in-progress / finished scan status that
        # the worker has set.
        text = self.status_label.text()
        if text.startswith("Скопировано") or text.startswith("SSH →"):
            if self._worker is not None:
                self.status_label.setText("Сканирование продолжается…")
            else:
                self.status_label.setText("Готов к сканированию")

    def _build_copy_menu(self, host: Host) -> QMenu:
        """Construct the copy popup for the given Host."""
        menu = QMenu(self)
        # Actionable items first: if SSH (port 22) is open, expose a
        # "connect via SSH" entry that spawns a terminal with `ssh user@host`.
        if 22 in (host.open_ports or []):
            target = host.hostname or host.ip
            menu.addAction(
                f"Зайти по SSH — {target}",
                lambda: self._ssh_connect(host),
            )
            menu.addSeparator()
        if host.ip:
            menu.addAction(
                f"Копировать IP — {host.ip}",
                lambda: self._copy_to_clipboard(host.ip, host.ip),
            )
        if host.hostname:
            menu.addAction(
                f"Копировать имя хоста — {host.hostname}",
                lambda: self._copy_to_clipboard(host.hostname, host.hostname),
            )
        if host.mac:
            mac_up = host.mac.upper()
            menu.addAction(
                f"Копировать MAC — {mac_up}",
                lambda: self._copy_to_clipboard(mac_up, mac_up),
            )
        if host.vendor:
            menu.addAction(
                "Копировать производителя",
                lambda: self._copy_to_clipboard(host.vendor, host.vendor),
            )
        if host.open_ports:
            ports_str = ", ".join(str(p) for p in host.open_ports)
            menu.addAction(
                "Копировать список портов",
                lambda: self._copy_to_clipboard(ports_str, "список портов"),
            )
        if host.banners:
            banners_text = "\n".join(
                f"{p}: {b}" for p, b in sorted(host.banners.items())
            )
            menu.addAction(
                "Копировать баннеры",
                lambda: self._copy_to_clipboard(banners_text, "баннеры"),
            )
        if host.os_guess:
            menu.addAction(
                f"Копировать ОС — {host.os_guess}",
                lambda: self._copy_to_clipboard(host.os_guess, host.os_guess),
            )
        if menu.actions():
            menu.addSeparator()
        menu.addAction(
            "Копировать строку (TSV)",
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

    # ---------- SSH ----------
    def _ssh_connect(self, host: Host) -> None:
        """Open a terminal window running ``ssh <user>@<host>``.

        Triggered from the row context menu when port 22 is open. Asks
        the user for a login name (defaulting to the current OS user)
        and then spawns the system OpenSSH client in a new console
        window so the interactive session is visible.
        """
        target = host.hostname or host.ip
        if not target:
            return
        default_user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        user, ok = QInputDialog.getText(
            self,
            "SSH",
            f"Имя пользователя для {target} (оставьте пустым для текущего):",
            QLineEdit.Normal,
            default_user,
        )
        if not ok:
            return
        user = user.strip()
        target_arg = f"{user}@{target}" if user else target

        try:
            if IS_WINDOWS:
                # CREATE_NEW_CONSOLE is Windows-only; use the literal so
                # the import stays portable. `cmd /k` keeps the console
                # open after ssh exits so the user can read the final
                # messages instead of the window vanishing immediately.
                CREATE_NEW_CONSOLE = 0x00000010
                subprocess.Popen(
                    ["cmd", "/k", "ssh", target_arg],
                    creationflags=CREATE_NEW_CONSOLE,
                )
            else:
                # Try a few common Linux/macOS terminals in priority order.
                terminals = (
                    ["x-terminal-emulator", "-e", "ssh", target_arg],
                    ["gnome-terminal", "--", "ssh", target_arg],
                    ["konsole", "-e", "ssh", target_arg],
                    ["xterm", "-e", "ssh", target_arg],
                )
                last_err: Exception | None = None
                for cmd in terminals:
                    try:
                        subprocess.Popen(cmd)
                        last_err = None
                        break
                    except FileNotFoundError as exc:
                        last_err = exc
                        continue
                if last_err is not None:
                    raise last_err
            self.status_label.setText(f"SSH → {target_arg}")
            QTimer.singleShot(2500, self._restore_status_label)
        except FileNotFoundError:
            QMessageBox.critical(
                self,
                "SSH-клиент не найден",
                "Не удалось запустить ssh.\n\n"
                "Windows: установите компонент «OpenSSH Client» в "
                "«Параметры → Приложения → Дополнительные компоненты».\n"
                "Linux/macOS: убедитесь, что установлен ssh и хотя бы "
                "один графический терминал (gnome-terminal, konsole, xterm).",
            )
        except OSError as exc:
            QMessageBox.critical(self, "Ошибка SSH", str(exc))

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

        # --randomize-hosts: shuffle scan order (still report progress as
        # int(sum(weights)), so the bar is unaffected).
        if f.randomize_hosts:
            random.shuffle(targets)

        # Build the port list. Priority of port-set flags is:
        #   -sn / --no-ports : skip port stage entirely
        #   -p-              : 1-65535 (overrides everything below)
        #   -F               : top-100 (overrides --top-ports / manual)
        #   --top-ports N    : top-N
        #   <manual>         : whatever's in the ports field
        # --randomize-ports then shuffles the final list.
        ports: list[int] = []
        do_ports = self.cb_ports.isChecked() and not f.no_ports
        if do_ports:
            if f.all_ports:
                ports = list(range(1, 65536))
            elif f.fast_scan:
                ports = list(TOP_PORTS[:100])
            elif f.top_ports > 0:
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
        # Manual flag overrides take priority over the auto-pick above.
        if f.host_timeout_ms > 0:
            port_timeout = f.host_timeout_ms / 1000.0
        if f.max_parallel > 0:
            port_workers = f.max_parallel

        self._thread = QThread(self)
        self._worker = ScanWorker(
            targets=targets,
            ping_timeout_ms=ping_timeout_ms,
            workers=workers,
            resolve_hostnames=self.cb_hostname.isChecked() and not f.no_dns,
            detect_mac=self.cb_mac.isChecked() and not f.no_mac,
            ports=ports,
            port_timeout=port_timeout,
            port_workers=port_workers,
            skip_ping=f.skip_ping,
            ping_retries=f.retries,
            arp_discovery=f.arp_discovery,
            os_detect=f.os_detect,
            version_detect=f.version_detect,
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

        # -oN / -oX / -oG: auto-export to the path the user picked in
        # the Flags dialog. Failure is non-fatal — we just put the
        # error in the status bar instead of popping a dialog over the
        # finished scan.
        f = self.flags
        if f.output_format and f.output_path:
            try:
                hosts = self.model.alive_hosts()
                self._write_results(Path(f.output_path), hosts, f.output_format)
                self.status_label.setText(
                    f"Сканирование завершено • активных: {alive} "
                    f"• сохранено в {f.output_path}"
                )
            except OSError as exc:
                self.status_label.setText(
                    f"Сканирование завершено • не удалось сохранить: {exc}"
                )

    def clear_results(self) -> None:
        self.model.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Готов к сканированию")

    # ---------- Export ----------
    _CSV_FIELDS = [
        "ip", "alive", "hostname", "mac", "vendor",
        "response_ms", "ttl", "os_guess", "open_ports", "banners",
    ]

    def _write_results(
        self, path: Path, hosts: list[Host], fmt: str
    ) -> None:
        """Serialize ``hosts`` into ``path`` using the requested format.

        Supported formats: ``csv`` / ``json`` (Export button) and the
        nmap-style ``normal`` / ``xml`` / ``grepable`` (Flags dialog).
        Raises ``OSError`` on filesystem failure; the writer functions
        themselves never raise on host content.
        """
        fmt = fmt.lower()
        if fmt == "json":
            with path.open("w", encoding="utf-8") as fh:
                json.dump(
                    [h.to_dict() for h in hosts],
                    fh, ensure_ascii=False, indent=2,
                )
        elif fmt == "xml":
            self._write_xml(path, hosts)
        elif fmt == "grepable":
            self._write_grepable(path, hosts)
        elif fmt == "normal":
            self._write_normal(path, hosts)
        else:  # csv
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(
                    fh,
                    fieldnames=self._CSV_FIELDS,
                    extrasaction="ignore",
                )
                writer.writeheader()
                for h in hosts:
                    writer.writerow(h.to_dict())

    @staticmethod
    def _write_normal(path: Path, hosts: list[Host]) -> None:
        """nmap-style ``-oN`` text output."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with path.open("w", encoding="utf-8") as fh:
            fh.write(f"# IPbrowse scan report — {ts}\n\n")
            for h in hosts:
                fh.write(f"Nmap scan report for {h.ip}\n")
                fh.write(
                    f"Host is {'up' if h.alive else 'down'}"
                    + (f" ({h.response_ms:.1f} ms latency)" if h.response_ms is not None else "")
                    + ".\n"
                )
                if h.hostname:
                    fh.write(f"  Hostname: {h.hostname}\n")
                if h.mac:
                    vend = f" ({h.vendor})" if h.vendor else ""
                    fh.write(f"  MAC Address: {h.mac.upper()}{vend}\n")
                if h.os_guess:
                    fh.write(f"  OS guess: {h.os_guess}")
                    if h.ttl is not None:
                        fh.write(f" (TTL={h.ttl})")
                    fh.write("\n")
                if h.open_ports:
                    fh.write("  PORT     STATE  SERVICE         VERSION\n")
                    for p in h.open_ports:
                        svc = COMMON_PORTS.get(p, "")
                        ban = h.banners.get(p, "") if h.banners else ""
                        fh.write(
                            f"  {p:<5}/tcp open   {svc:<15} {ban}\n"
                        )
                fh.write("\n")

    @staticmethod
    def _write_xml(path: Path, hosts: list[Host]) -> None:
        """nmap-style ``-oX`` XML output (subset)."""
        from xml.sax.saxutils import quoteattr
        ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        with path.open("w", encoding="utf-8") as fh:
            fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            fh.write(
                f'<nmaprun scanner="ipbrowse" start={quoteattr(ts)} '
                f'version="1.0" xmloutputversion="1.04">\n'
            )
            for h in hosts:
                fh.write(
                    f'  <host>\n'
                    f'    <status state="{"up" if h.alive else "down"}"/>\n'
                    f'    <address addr={quoteattr(h.ip)} addrtype="ipv4"/>\n'
                )
                if h.mac:
                    fh.write(
                        f'    <address addr={quoteattr(h.mac.upper())} '
                        f'addrtype="mac" vendor={quoteattr(h.vendor or "")}/>\n'
                    )
                if h.hostname:
                    fh.write(
                        f'    <hostnames>\n'
                        f'      <hostname name={quoteattr(h.hostname)} type="PTR"/>\n'
                        f'    </hostnames>\n'
                    )
                if h.open_ports:
                    fh.write('    <ports>\n')
                    for p in h.open_ports:
                        svc = COMMON_PORTS.get(p, "")
                        ban = h.banners.get(p, "") if h.banners else ""
                        fh.write(
                            f'      <port protocol="tcp" portid="{p}">\n'
                            f'        <state state="open"/>\n'
                            f'        <service name={quoteattr(svc)}'
                        )
                        if ban:
                            fh.write(f' product={quoteattr(ban)}')
                        fh.write('/>\n')
                        fh.write('      </port>\n')
                    fh.write('    </ports>\n')
                if h.os_guess:
                    fh.write(
                        f'    <os><osmatch name={quoteattr(h.os_guess)} '
                        f'accuracy="50"/></os>\n'
                    )
                if h.response_ms is not None:
                    fh.write(
                        f'    <times srtt="{int(h.response_ms * 1000)}"/>\n'
                    )
                fh.write('  </host>\n')
            fh.write('</nmaprun>\n')

    @staticmethod
    def _write_grepable(path: Path, hosts: list[Host]) -> None:
        """nmap-style ``-oG`` grepable output, one host per line."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with path.open("w", encoding="utf-8") as fh:
            fh.write(f"# IPbrowse {ts}\n")
            for h in hosts:
                hostname = f"({h.hostname})" if h.hostname else "()"
                state = "Up" if h.alive else "Down"
                fh.write(f"Host: {h.ip} {hostname}\tStatus: {state}\n")
                if h.open_ports:
                    parts = []
                    for p in h.open_ports:
                        svc = COMMON_PORTS.get(p, "")
                        ban = h.banners.get(p, "") if h.banners else ""
                        # Format: port/state/proto//service//version/
                        parts.append(
                            f"{p}/open/tcp//{svc}//{ban}/"
                        )
                    fh.write(
                        f"Host: {h.ip} {hostname}\tPorts: " + ", ".join(parts)
                        + "\n"
                    )
                if h.os_guess:
                    fh.write(f"Host: {h.ip} {hostname}\tOS: {h.os_guess}\n")

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
            "CSV (*.csv);;JSON (*.json);;Text (-oN) (*.txt);;XML (-oX) (*.xml);;Grepable (-oG) (*.gnmap)",
        )
        if not path_str:
            return
        path = Path(path_str)

        # Pick the format from the dialog filter or the file extension.
        fmt = "csv"
        suffix = path.suffix.lower()
        if "JSON" in selected or suffix == ".json":
            fmt = "json"
        elif "Text" in selected or suffix == ".txt":
            fmt = "normal"
        elif "XML" in selected or suffix == ".xml":
            fmt = "xml"
        elif "Grepable" in selected or suffix == ".gnmap":
            fmt = "grepable"

        try:
            self._write_results(path, hosts, fmt)
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
        # Defer the first refresh a bit so we don't pile up against the
        # local scan tab also starting on launch.
        QTimer.singleShot(300, self._refresh)

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
        self.lbl_disconnected = QLabel("Wi-Fi не подключен")
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
                alive, rtt_value, _ttl = ping(gw, timeout_ms=500)
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
                    "Wi-Fi не подключен\n(беспроводной адаптер не обнаружен)"
                )
            else:
                self.lbl_disconnected.setText("Wi-Fi не подключен")

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


# Mass-scan speed presets: workers, per-port timeout (seconds), label, danger.
# "danger=True" pops a confirmation dialog before the scan starts because the
# combined connection rate can briefly knock out cheap SOHO routers / NAT
# tables.
MASS_SPEED_PRESETS: list[tuple[str, int, float, bool, str]] = [
    ("Медленно",   20,  1.5, False,
     "20 потоков · таймаут 1.5 с — безопасно, подходит для VPN / мобильных сетей"),
    ("Нормально", 100,  0.6, False,
     "100 потоков · таймаут 600 мс — обычная скорость, подходит для домашней сети"),
    ("Быстро",    300,  0.4, False,
     "300 потоков · таймаут 400 мс — заметная нагрузка на роутер, но обычно ок"),
    ("Опасно",    800,  0.2, True,
     "800 потоков · таймаут 200 мс — ВНИМАНИЕ: может уронить SOHO-роутер / NAT"),
]


def _load_targets_from_file(
    path: Path,
) -> tuple[list[str], list[str]]:
    """Read an IP list from a .txt or .csv file.

    Each line / first CSV column is fed through :func:`expand_target`,
    so single IPs, ranges (``192.168.1.1-50``), CIDRs (``10.0.0.0/24``)
    and comma-separated combinations all work. Lines starting with
    ``#`` and empty lines are skipped.

    Returns ``(targets, errors)`` where ``targets`` is deduplicated in
    input order and ``errors`` is a list of "<line>: <reason>" strings
    for entries that couldn't be parsed (so the UI can warn the user
    without aborting the whole list).
    """
    targets: list[str] = []
    errors: list[str] = []

    def _consume(line: str) -> None:
        line = line.strip()
        if not line or line.startswith("#"):
            return
        try:
            targets.extend(expand_target(line))
        except ValueError as exc:
            errors.append(f"{line!r}: {exc}")

    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not row:
                    continue
                _consume(row[0])
    else:
        with path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                _consume(raw)

    seen: set[str] = set()
    uniq: list[str] = []
    for ip in targets:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq, errors


class MassScanWorker(QObject):
    """Parallel single-port TCP-connect scan over a static IP list.

    For each ``(ip, port)`` pair the worker emits one ``result`` signal
    with the connection state — ``"open"`` / ``"closed"`` / ``"timeout"``
    / ``"error"`` — and the round-trip time in milliseconds.
    """

    progress = Signal(int, int)          # done, total
    result = Signal(str, int, str, float)  # ip, port, status, rtt_ms
    finished = Signal()
    error = Signal(str)

    def __init__(
        self,
        ips: list[str],
        ports: list[int],
        workers: int,
        timeout: float,
    ) -> None:
        super().__init__()
        self.ips = list(ips)
        self.ports = list(ports)
        self.workers = max(1, int(workers))
        self.timeout = float(timeout)
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    @staticmethod
    def _scan(ip: str, port: int, timeout: float) -> tuple[str, float]:
        """One TCP connect probe; returns (status, rtt_ms)."""
        import time
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        try:
            sock.connect((ip, port))
        except socket.timeout:
            return "timeout", timeout * 1000.0
        except ConnectionRefusedError:
            return "closed", (time.perf_counter() - start) * 1000.0
        except OSError:
            return "error", (time.perf_counter() - start) * 1000.0
        else:
            return "open", (time.perf_counter() - start) * 1000.0
        finally:
            sock.close()

    def run(self) -> None:
        try:
            jobs: list[tuple[str, int]] = [
                (ip, port) for ip in self.ips for port in self.ports
            ]
            total = len(jobs)
            self.progress.emit(0, total)
            # Throttle progress emission to ~1% increments (or every 50
            # jobs for tiny scans). Without this, a 65 535-port sweep
            # floods Qt's queued-connection event loop with progress
            # signals and starves the GUI thread, freezing the window.
            progress_step = max(50, total // 100)

            pool = ThreadPoolExecutor(
                max_workers=min(self.workers, max(1, total))
            )
            try:
                futures = {
                    pool.submit(self._scan, ip, port, self.timeout): (ip, port)
                    for ip, port in jobs
                }
                done = 0
                for fut in as_completed(futures):
                    if self._cancel.is_set():
                        break
                    ip, port = futures[fut]
                    try:
                        status, rtt = fut.result()
                    except Exception:  # noqa: BLE001
                        status, rtt = "error", 0.0
                    # Only opens are pushed to the GUI — writing every
                    # closed / timeout / error to a QTreeWidget on a
                    # 65k-port scan is what froze the window before.
                    # Closed / timeout / error states are still counted
                    # via `progress` so the bar / status line stay live.
                    if status == "open":
                        self.result.emit(ip, port, status, rtt)
                    done += 1
                    if done == total or done % progress_step == 0:
                        self.progress.emit(done, total)
            finally:
                # cancel_futures=True drops queued probes; in-flight ones
                # are bounded by self.timeout, so wait=True is responsive.
                pool.shutdown(wait=True, cancel_futures=True)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


class MassScanTab(QWidget):
    """Tab for scanning a user-supplied list of IPs against a single port.

    The list comes from a .txt / .csv file the user picks; lines may be
    bare IPs, ranges or CIDRs (delegated to ``expand_target``). The
    speed combo-box trades off worker count against socket timeout —
    the "Опасно" preset shows a confirmation dialog before starting
    because high connection rates can briefly knock out SOHO routers.
    """

    _COLUMNS = [
        ("ip",       "IP-адрес"),
        ("port",     "Порт"),
        ("status",   "Статус"),
        ("rtt",      "Отклик (мс)"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: MassScanWorker | None = None
        self._targets: list[str] = []
        self._results: list[tuple[str, int, str, float]] = []
        self._needle: str = ""  # cached lower-cased filter for hot-path checks
        self._build_ui()

    # ----- UI -----
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        intro = QLabel(
            "Загрузите список IP / диапазонов / подсетей из файла "
            "(.txt — по одной записи на строку, или .csv — первая колонка). "
            "Сканирование проверяет один и тот же порт на всех адресах в "
            "несколько потоков."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #94e2d5; font-style: italic; padding: 4px 0;")
        root.addWidget(intro)

        # ---- File picker row ----
        settings = QGroupBox("Параметры массового сканирования")
        form = QFormLayout(settings)
        form.setLabelAlignment(Qt.AlignRight)

        file_row = QHBoxLayout()
        self.le_file = QLineEdit()
        self.le_file.setPlaceholderText("Путь к файлу с IP (.txt или .csv)")
        self.le_file.textChanged.connect(self._on_file_changed)
        file_row.addWidget(self.le_file, 1)
        btn_browse = QPushButton(" Обзор…")
        btn_browse.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        btn_browse.clicked.connect(self._pick_file)
        file_row.addWidget(btn_browse)
        form.addRow("Файл:", self._wrap(file_row))

        self.lbl_targets = QLabel("Файл не выбран")
        self.lbl_targets.setStyleSheet("color: #6c7086; font-style: italic;")
        form.addRow("", self.lbl_targets)

        # ---- Port + speed row ----
        ps_row = QHBoxLayout()
        self.le_port = QLineEdit("22")
        self.le_port.setPlaceholderText("например, 22 или 22,80,443")
        self.le_port.setMaximumWidth(180)
        ps_row.addWidget(QLabel("Порт:"))
        ps_row.addWidget(self.le_port)
        ps_row.addSpacing(20)
        ps_row.addWidget(QLabel("Скорость:"))
        self.cmb_speed = QComboBox()
        for label, workers, timeout, danger, desc in MASS_SPEED_PRESETS:
            self.cmb_speed.addItem(label, (workers, timeout, danger, desc))
        self.cmb_speed.setCurrentIndex(1)  # Нормально
        self.cmb_speed.currentIndexChanged.connect(self._update_speed_hint)
        ps_row.addWidget(self.cmb_speed)
        ps_row.addStretch(1)
        form.addRow("", self._wrap(ps_row))

        self.lbl_speed_hint = QLabel("")
        self.lbl_speed_hint.setWordWrap(True)
        form.addRow("", self.lbl_speed_hint)
        self._update_speed_hint()

        root.addWidget(settings)

        # ---- Action row ----
        actions = QHBoxLayout()
        self.btn_scan = QPushButton(" Сканировать")
        self.btn_scan.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.btn_scan.setObjectName("scan")
        self.btn_scan.clicked.connect(self.start_scan)
        actions.addWidget(self.btn_scan)

        self.btn_stop = QPushButton(" Остановить")
        self.btn_stop.setIcon(self.style().standardIcon(QStyle.SP_MediaStop))
        self.btn_stop.setObjectName("stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        actions.addWidget(self.btn_stop)

        self.btn_clear = QPushButton(" Очистить")
        self.btn_clear.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        self.btn_clear.clicked.connect(self.clear_results)
        actions.addWidget(self.btn_clear)

        self.btn_export = QPushButton(" Экспорт")
        self.btn_export.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        self.btn_export.clicked.connect(self.export_results)
        actions.addWidget(self.btn_export)

        actions.addSpacing(20)
        actions.addWidget(QLabel("Фильтр:"))
        self.le_filter = QLineEdit()
        self.le_filter.setPlaceholderText("Поиск по IP / порту…")
        self.le_filter.textChanged.connect(self._on_filter_changed)
        actions.addWidget(self.le_filter, 1)

        # NOTE: a "Только открытые" checkbox used to live here, but the
        # worker now only emits result rows for ports it actually
        # connected to — closed / timeout / error rows are summarised in
        # progress instead of being pushed to the table. So the checkbox
        # is implicit (always-on) and was removed.

        root.addLayout(actions)

        # ---- Results table ----
        self.table = QTreeWidget()
        self.table.setColumnCount(len(self._COLUMNS))
        self.table.setHeaderLabels([c[1] for c in self._COLUMNS])
        self.table.setRootIsDecorated(False)
        self.table.setUniformRowHeights(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setSortingEnabled(True)
        for i, w in enumerate((180, 80, 120, 120)):
            self.table.setColumnWidth(i, w)
        root.addWidget(self.table, 1)

        # ---- Status row ----
        status_row = QHBoxLayout()
        self.status_label = QLabel("Готов к массовому сканированию")
        status_row.addWidget(self.status_label, 1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(260)
        self.progress_bar.setValue(0)
        status_row.addWidget(self.progress_bar)
        root.addLayout(status_row)

    @staticmethod
    def _wrap(layout) -> QWidget:
        w = QWidget()
        w.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)
        return w

    # ----- Speed / file handlers -----
    def _update_speed_hint(self) -> None:
        data = self.cmb_speed.currentData()
        if not data:
            return
        workers, timeout, danger, desc = data
        color = "#f38ba8" if danger else "#94e2d5"
        prefix = "ВНИМАНИЕ:  " if danger else ""
        self.lbl_speed_hint.setStyleSheet(f"color: {color};")
        self.lbl_speed_hint.setText(f"{prefix}{desc}")

    def _pick_file(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Выбрать файл со списком IP",
            "",
            "Список адресов (*.txt *.csv);;Текст (*.txt);;CSV (*.csv);;Все файлы (*.*)",
        )
        if path_str:
            self.le_file.setText(path_str)

    def _on_file_changed(self, text: str) -> None:
        text = text.strip()
        if not text:
            self._targets = []
            self.lbl_targets.setText("Файл не выбран")
            self.lbl_targets.setStyleSheet("color: #6c7086; font-style: italic;")
            return
        path = Path(text)
        if not path.is_file():
            self._targets = []
            self.lbl_targets.setText("Файл не найден")
            self.lbl_targets.setStyleSheet("color: #f38ba8;")
            return
        try:
            targets, errors = _load_targets_from_file(path)
        except OSError as exc:
            self._targets = []
            self.lbl_targets.setText(f"Не удалось прочитать файл: {exc}")
            self.lbl_targets.setStyleSheet("color: #f38ba8;")
            return
        self._targets = targets
        if not targets:
            self.lbl_targets.setText("Файл не содержит валидных адресов")
            self.lbl_targets.setStyleSheet("color: #f9e2af;")
            return
        msg = f"Загружено адресов: {len(targets)}"
        if errors:
            msg += f" · пропущено строк с ошибками: {len(errors)}"
        self.lbl_targets.setText(msg)
        self.lbl_targets.setStyleSheet(
            "color: #f9e2af;" if errors else "color: #a6e3a1;"
        )

    # ----- Scan control -----
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
        if not self._targets:
            QMessageBox.warning(
                self, "Нет адресов",
                "Выберите файл со списком IP-адресов.",
            )
            return
        try:
            ports = self._parse_ports(self.le_port.text())
        except ValueError:
            QMessageBox.critical(
                self, "Ошибка", "Некорректный список портов."
            )
            return
        if not ports:
            QMessageBox.warning(
                self, "Не указан порт",
                "Введите порт (например, 22) или список 22,80,443.",
            )
            return

        data = self.cmb_speed.currentData()
        workers, timeout, danger, _desc = data

        if danger:
            jobs = len(self._targets) * len(ports)
            ans = QMessageBox.warning(
                self,
                "Подтверждение опасной скорости",
                "Скорость «Опасно» создаёт до "
                f"{workers} одновременных TCP-соединений и шлёт "
                f"{jobs} проб с очень коротким таймаутом ({int(timeout * 1000)} мс).\n\n"
                "На бытовых роутерах и в небольших сетях это может:\n"
                "  • временно переполнить таблицу NAT;\n"
                "  • вызвать кратковременную потерю интернета;\n"
                "  • быть расценено IDS как сетевая атака.\n\n"
                "Запускать только в сети, которой вы владеете и где "
                "имеете право проводить такие тесты.\n\n"
                "Продолжить?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if ans != QMessageBox.Yes:
                return

        self.clear_results()
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_label.setText(
            f"Сканирование {len(self._targets)} адресов × {len(ports)} порт(ов)…"
        )
        # Disable sorting while results stream in so each insert is O(1)
        # instead of O(N log N). Sorting is restored in `_on_finished`.
        self.table.setSortingEnabled(False)

        self._thread = QThread(self)
        self._worker = MassScanWorker(
            ips=list(self._targets),
            ports=ports,
            workers=workers,
            timeout=timeout,
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.result.connect(self._on_result)
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
        # Worker only emits opens, so len(self._results) is the live
        # open count. Closed / timeout / error states are folded into
        # the (done - opens) tail.
        opens = len(self._results)
        self.status_label.setText(
            f"Просканировано {done}/{total} • найдено открытых: {opens}"
        )

    _STATUS_COLORS = {
        "open":    "#a6e3a1",
        "closed":  "#f9e2af",
        "timeout": "#fab387",
        "error":   "#f38ba8",
    }

    def _on_result(
        self, ip: str, port: int, status: str, rtt: float
    ) -> None:
        # Defensive — the worker already filters non-opens, but the slot
        # stays robust if that ever changes.
        if status != "open":
            return
        self._results.append((ip, port, status, rtt))

        item = QTreeWidgetItem([ip, str(port), status, f"{rtt:.1f}"])
        item.setTextAlignment(1, Qt.AlignCenter)
        item.setTextAlignment(3, Qt.AlignRight | Qt.AlignVCenter)
        item.setForeground(
            2, QBrush(QColor(self._STATUS_COLORS["open"]))
        )
        item.setData(0, Qt.UserRole, (ip, port, status, rtt))

        # Hot path: do NOT walk every existing row on insert (used to be
        # an O(N^2) loop via _apply_filter and was the GUI freeze). Just
        # apply the cached filter to *this* item.
        if self._needle and self._needle not in (
            f"{ip} {port}".lower()
        ):
            item.setHidden(True)

        # Auto-scroll to the new row if the user was already viewing the
        # bottom of the list. If they scrolled up to inspect older
        # results, the view stays put — they don't get yanked back.
        bar = self.table.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 4
        self.table.addTopLevelItem(item)
        if at_bottom:
            self.table.scrollToBottom()

    def _on_error(self, message: str) -> None:
        QMessageBox.critical(self, "Ошибка сканирования", message)

    def _on_finished(self) -> None:
        opened = len(self._results)
        total = self.progress_bar.maximum()
        done = self.progress_bar.value()
        self.status_label.setText(
            f"Завершено • просканировано {done}/{total} • открытых: {opened}"
        )
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        # Re-enable sorting now that the storm of inserts is over (we
        # disabled it in start_scan to avoid an O(N log N) re-sort on
        # every row added).
        self.table.setSortingEnabled(True)
        self._thread = None
        self._worker = None

    # ----- Results -----
    def clear_results(self) -> None:
        self._results.clear()
        self.table.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Готов к массовому сканированию")

    def _on_filter_changed(self, text: str) -> None:
        """Filter input changed — refresh `_needle` and re-evaluate rows."""
        self._needle = text.strip().lower()
        self._apply_filter()

    def _apply_filter(self) -> None:
        """Re-apply the cached filter to every existing row.

        Only called when the filter text actually changes (and after a
        scan ends), NOT on every result. Per-result filtering is done
        inline in ``_on_result`` against the already-cached needle.
        """
        needle = self._needle
        for i in range(self.table.topLevelItemCount()):
            it = self.table.topLevelItem(i)
            if not needle:
                it.setHidden(False)
                continue
            blob = f"{it.text(0)} {it.text(1)}".lower()
            it.setHidden(needle not in blob)

    def export_results(self) -> None:
        if not self._results:
            QMessageBox.information(
                self, "Нет данных", "Сначала запустите сканирование."
            )
            return
        default = f"mass_scan_{datetime.now():%Y%m%d_%H%M%S}.csv"
        path_str, _ = QFileDialog.getSaveFileName(
            self, "Экспорт результатов", default,
            "CSV (*.csv);;Текст (*.txt);;Все файлы (*.*)",
        )
        if not path_str:
            return
        path = Path(path_str)
        try:
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["ip", "port", "status", "rtt_ms"])
                for ip, port, status, rtt in self._results:
                    writer.writerow([ip, port, status, f"{rtt:.1f}"])
        except OSError as exc:
            QMessageBox.critical(
                self, "Ошибка", f"Не удалось сохранить файл:\n{exc}"
            )
            return
        QMessageBox.information(
            self, "Готово", f"Сохранено {len(self._results)} строк:\n{path}"
        )

    def shutdown(self) -> None:
        if self._worker:
            self._worker.cancel()
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(2000)


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
                "Внимание: сканирование внешних сетей может нарушать правила провайдера и "
                "действующее законодательство. Сканируйте только те ресурсы, "
                "на которые у вас есть явное разрешение."
            ),
        )
        self.wifi_tab = WifiTab(local_model=self.local_tab.model)
        self.mass_tab = MassScanTab()

        self.tabs.addTab(self.local_tab, "Локальная сеть")
        self.tabs.addTab(self.external_tab, "Внешние сети")
        self.tabs.addTab(self.wifi_tab, "Wi-Fi")
        self.tabs.addTab(self.mass_tab, "Массовое сканирование")

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

            QMenu {
                background: #181825; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 6px;
                padding: 4px;
            }
            QMenu::item {
                padding: 6px 22px 6px 14px; border-radius: 4px;
                margin: 1px 2px;
                background: transparent; color: #cdd6f4;
            }
            QMenu::item:selected, QMenu::item:hover {
                background: #585b70; color: #ffffff;
            }
            QMenu::item:disabled { color: #6c7086; }
            QMenu::separator {
                height: 1px; background: #45475a; margin: 4px 8px;
            }
            """
        )

    def closeEvent(self, event) -> None:  # noqa: N802
        self.local_tab.shutdown()
        self.external_tab.shutdown()
        self.wifi_tab.shutdown()
        self.mass_tab.shutdown()
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("IPbrowse")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
