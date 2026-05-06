"""IPbrowse - Local network scanner with PySide6 GUI."""
from __future__ import annotations

import csv
import json
import sys
import threading
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QSortFilterProxyModel,
    Qt,
    QThread,
    Signal,
)
from PySide6.QtGui import QAction, QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QStyle,
    QTableView,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from scanner import (
    COMMON_PORTS,
    Host,
    detect_local_subnet,
    expand_target,
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


class HostsModel(QAbstractTableModel):
    """Table model holding scan results."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._hosts: list[Host] = []
        self._show_dead = False

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
        self.endResetModel()

    def upsert(self, host: Host) -> None:
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

    def hosts(self) -> list[Host]:
        return list(self._hosts)

    def alive_hosts(self) -> list[Host]:
        return [h for h in self._hosts if h.alive]

    def _visible_hosts(self) -> list[Host]:
        if self._show_dead:
            return self._hosts
        return [h for h in self._hosts if h.alive]


class ScanWorker(QObject):
    """Runs the scan in a worker thread and emits Qt signals."""

    progress = Signal(int, int)  # done, total
    host_found = Signal(object)  # Host
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
    ) -> None:
        super().__init__()
        self.targets = targets
        self.ping_timeout_ms = ping_timeout_ms
        self.workers = workers
        self.resolve_hostnames = resolve_hostnames
        self.detect_mac = detect_mac
        self.ports = ports
        self.port_timeout = port_timeout
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            total = len(self.targets)
            done = 0
            self.progress.emit(0, total)
            for host in scan_network(
                self.targets,
                ping_timeout_ms=self.ping_timeout_ms,
                workers=self.workers,
                resolve_hostnames=self.resolve_hostnames,
                detect_mac=self.detect_mac,
                ports=self.ports,
                port_timeout=self.port_timeout,
                cancel_event=self._cancel,
            ):
                self.host_found.emit(host)
                done += 1
                self.progress.emit(done, total)
                if self._cancel.is_set():
                    break
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("IPbrowse — Сканер локальной сети")
        self.resize(1100, 650)

        self.model = HostsModel(self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterKeyColumn(-1)  # all columns
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)

        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None

        self._build_ui()
        self._apply_dark_theme()

    # ---------- UI ----------
    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # Settings group
        settings = QGroupBox("Параметры сканирования")
        form = QFormLayout(settings)
        form.setLabelAlignment(Qt.AlignRight)

        self.target_edit = QLineEdit(detect_local_subnet())
        self.target_edit.setPlaceholderText("например, 192.168.1.0/24 или 192.168.1.1-50")
        detect_btn = QPushButton("Авто")
        detect_btn.setToolTip("Определить локальную подсеть автоматически")
        detect_btn.clicked.connect(
            lambda: self.target_edit.setText(detect_local_subnet())
        )
        target_row = QHBoxLayout()
        target_row.addWidget(self.target_edit, 1)
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

        self.ports_edit = QLineEdit(",".join(str(p) for p in COMMON_PORTS))
        self.ports_edit.setPlaceholderText("например, 22,80,443,3389 или 1-1024")
        self.cb_ports.toggled.connect(self.ports_edit.setEnabled)
        form.addRow("Порты:", self.ports_edit)

        root.addWidget(settings)

        # Action row
        actions = QHBoxLayout()
        self.btn_scan = QPushButton(" Сканировать")
        self.btn_scan.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_stop = QPushButton(" Остановить")
        self.btn_stop.setIcon(self.style().standardIcon(QStyle.SP_MediaStop))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_clear = QPushButton(" Очистить")
        self.btn_clear.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        self.btn_clear.clicked.connect(self.clear_results)

        actions.addWidget(self.btn_scan)
        actions.addWidget(self.btn_stop)
        actions.addWidget(self.btn_clear)
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
        # default column widths
        widths = {0: 80, 1: 130, 2: 200, 3: 160, 4: 180, 5: 90}
        for col, w in widths.items():
            self.table.setColumnWidth(col, w)
        root.addWidget(self.table, 1)

        # Status bar with progress
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(260)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setValue(0)
        self.status_label = QLabel("Готов к сканированию")
        sb.addWidget(self.status_label, 1)
        sb.addPermanentWidget(self.progress_bar)

    def _wrap(self, layout) -> QWidget:
        w = QWidget()
        w.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)
        return w

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
            QToolTip { background: #313244; color: #cdd6f4; border: 1px solid #45475a; }
            """
        )
        self.btn_scan.setObjectName("scan")
        self.btn_stop.setObjectName("stop")
        self.btn_scan.style().unpolish(self.btn_scan)
        self.btn_scan.style().polish(self.btn_scan)
        self.btn_stop.style().unpolish(self.btn_stop)
        self.btn_stop.style().polish(self.btn_stop)

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
        if len(targets) > 4096:
            ans = QMessageBox.question(
                self,
                "Много адресов",
                f"Цель содержит {len(targets)} адресов. Продолжить?",
            )
            if ans != QMessageBox.Yes:
                return

        ports: list[int] = []
        if self.cb_ports.isChecked():
            try:
                ports = self._parse_ports(self.ports_edit.text())
            except ValueError:
                QMessageBox.critical(self, "Ошибка", "Некорректный список портов.")
                return

        self.model.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(max(1, len(targets)))
        self.status_label.setText(f"Сканирование {len(targets)} адресов…")
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)

        self._thread = QThread(self)
        self._worker = ScanWorker(
            targets=targets,
            ping_timeout_ms=self.ping_timeout.value(),
            workers=self.workers.value(),
            resolve_hostnames=self.cb_hostname.isChecked(),
            detect_mac=self.cb_mac.isChecked(),
            ports=ports,
            port_timeout=0.6,
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.host_found.connect(self.model.upsert)
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

    # ---------- Lifecycle ----------
    def closeEvent(self, event) -> None:  # noqa: N802
        if self._worker:
            self._worker.cancel()
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(2000)
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("IPbrowse")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
