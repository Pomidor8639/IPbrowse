"""Smoke test for the mass-scan export-field-picker dialog.

Verifies, without showing any window, that the new ``MassExportDialog``
collects field+format selections correctly and that the writer in
``MassScanTab.export_results`` honours them — i.e. clicking "Только
IP" really produces a flat list of IPs, "Все поля" with CSV writes
every column with a header, etc.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

# Some Windows shells (bash, legacy cmd) default stdout to a code page
# that cannot encode the Cyrillic labels we print below — the first
# flushed ``print`` then dies with ``OSError: [Errno 22] Invalid
# argument``. Reconfigure early so the smoke test runs on any shell.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

from PySide6.QtWidgets import QApplication, QDialog

import app


SAMPLE = [
    ("192.168.1.10", 22, "open", 1.2),
    ("192.168.1.11", 22, "open", 4.7),
    ("10.0.0.5",     22, "open", 17.0),
]


def make_tab(qapp: QApplication) -> app.MassScanTab:
    tab = app.MassScanTab()
    tab._results = list(SAMPLE)
    qapp.processEvents()
    return tab


def export(
    qapp: QApplication,
    tab: app.MassScanTab,
    fields: list[str],
    ext: str,
    sep: str,
    with_header: bool,
) -> str:
    """Drive ``export_results`` against an in-memory chosen path.

    Patches *instance methods* of MassExportDialog (rather than the
    whole class) so ``MassExportDialog.FIELDS`` remains the real tuple
    that the writer relies on for column headers.

    IMPORTANT: the instance-method patches use real Python functions
    rather than ``return_value=...`` MagicMocks. Installing a MagicMock
    as an attribute on a QDialog subclass corrupts PySide6's signal
    introspection — the very next ``signal.connect(...)`` call inside
    ``MassExportDialog._build_ui`` segfaults with an access violation
    on Windows. Plain callables don't trip the Shiboken type checks.
    Static-method patches on QFileDialog / QMessageBox are fine with
    ``return_value=...`` because those aren't looked up via signal
    introspection.
    """
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / f"export.{ext}"
        choice = (list(fields), ext, sep, with_header)

        def fake_exec(self):
            return QDialog.Accepted

        def fake_get_choice(self, _c=choice):
            return _c

        with patch.object(app.MassExportDialog, "exec", fake_exec), \
             patch.object(app.MassExportDialog, "get_choice",
                          fake_get_choice), \
             patch.object(app.QFileDialog, "getSaveFileName",
                          return_value=(str(out), "")), \
             patch.object(app.QMessageBox, "information"):
            tab.export_results()
        return out.read_text(encoding="utf-8")


def main() -> int:
    qapp = QApplication.instance() or QApplication(sys.argv)

    # 1) Real-dialog round-trip: presets pick the fields we expect.
    real_dlg = app.MassExportDialog()
    real_dlg._preset_only_ip()
    fields, ext, sep, with_header = real_dlg.get_choice()
    assert fields == ["ip"], fields
    assert (ext, sep, with_header) == ("txt", " ", False)
    print(f"preset 'Только IP' -> {fields}, {ext}, header={with_header}")

    real_dlg._preset_ip_port()
    fields, ext, sep, with_header = real_dlg.get_choice()
    assert fields == ["ip", "port"], fields
    assert (ext, sep, with_header) == ("csv", ",", True)
    print(f"preset 'IP + порт' -> {fields}, {ext}, header={with_header}")

    real_dlg._preset_all()
    fields, ext, sep, with_header = real_dlg.get_choice()
    assert fields == ["ip", "port", "status", "rtt_ms"], fields
    assert (ext, sep, with_header) == ("csv", ",", True)
    print(f"preset 'Все поля' -> {fields}, {ext}, header={with_header}")

    # 2) Writer: only IPs, plain text.
    tab = make_tab(qapp)
    text = export(qapp, tab, ["ip"], "txt", " ", False)
    assert text.splitlines() == [
        "192.168.1.10", "192.168.1.11", "10.0.0.5",
    ], text
    print(f"only-ip txt -> {text!r}")

    # 3) Writer: IP + port CSV with header.
    text = export(qapp, tab, ["ip", "port"], "csv", ",", True)
    lines = text.splitlines()
    assert lines[0] == "IP-адрес,Порт", lines[0]
    assert lines[1] == "192.168.1.10,22"
    assert len(lines) == 1 + len(SAMPLE)
    print(f"ip+port csv:\n{text}")

    # 4) Writer: all fields TSV with header.
    text = export(
        qapp, tab,
        ["ip", "port", "status", "rtt_ms"],
        "tsv", "\t", True,
    )
    lines = text.splitlines()
    assert lines[0] == "IP-адрес\tПорт\tСтатус\tОтклик (мс)", lines[0]
    assert lines[1] == "192.168.1.10\t22\topen\t1.2"
    assert len(lines) == 1 + len(SAMPLE)
    print(f"all tsv first row: {lines[1]!r}")

    # 5) Writer: rtt only, plain text without header.
    text = export(qapp, tab, ["rtt_ms"], "txt", " ", False)
    assert text.splitlines() == ["1.2", "4.7", "17.0"], text
    print(f"rtt-only txt -> {text!r}")

    # 6) Empty results -> writer not called, no crash.
    empty = app.MassScanTab()
    empty._results = []
    with patch.object(app.QMessageBox, "information") as info, \
         patch.object(app, "MassExportDialog") as Dlg:
        empty.export_results()
        info.assert_called_once()  # "Нет данных"
        Dlg.assert_not_called()
    print("empty-results path ok")

    print("ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
