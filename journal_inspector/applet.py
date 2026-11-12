#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = "linspectacles-journal-inspector"
APPLET_NAME = "Journal Inspector"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_PUBLISHER = "brunonlinespace"
APPLET_ORGANIZATION_ID = "linspectacles"
APPLET_ORGANIZATION_URL = "https://github.com/linspectacles/"
APPLET_REPOSITORY = "https://github.com/linspectacles/journal-inspector"
APPLET_VERSION = "1.0.0"

import json
import os
import re
import subprocess
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path

from PyQt6.QtCore import QDate, QSettings, Qt, QTimer, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QButtonGroup,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDateEdit,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QInputDialog,
    QPushButton,
    QRadioButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QStackedWidget,
    QAbstractItemView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ._support import (
    BaseInspectorTab,
    NumericTableWidgetItem,
    export_records_dialog,
    metadata_font_qss,
)

ENTRY_LIMITS = (100, 500, 1000, 5000, 10000, 25000, 50000)
DEFAULT_ENTRY_LIMIT = 500
MAX_ENTRY_LIMIT = 10000
NO_ENTRY_LIMIT = -1
NOT_REPORTED_PRIORITY = "__not_reported__"
ALL_SOURCES_LABEL = "All Sources"
DATE_SCOPE_ALL = "all"
DATE_SCOPE_TODAY = "today"
DATE_SCOPE_YESTERDAY = "yesterday"
DATE_SCOPE_CUSTOM = "custom"
BOOT_SCOPE_CURRENT = "current"
BOOT_SCOPE_PREVIOUS = "previous"
BOOT_SCOPE_CUSTOM = "custom"
LIST_BOOTS_PERIOD_ALL = "All"
LIST_BOOTS_PERIOD_THIS_MONTH = "This Month"
LIST_BOOTS_PERIOD_LAST_MONTH = "Last Month"
LIST_BOOTS_PERIOD_EARLIER = "Earlier"

PRIORITY_QUERY_NONE = ""
PRIORITY_QUERY_LEVELS = ("warning", "err", "crit", "alert")
PRIORITY_QUERY_OPTIONS = (
    ("Off (all priorities)", PRIORITY_QUERY_NONE),
    ("Warning and above (--priority=warning)", "warning"),
    ("Error and above (--priority=err)", "err"),
    ("Critical and above (--priority=crit)", "crit"),
    ("Alert and above (--priority=alert)", "alert"),
)
BOOT_LINE_RE = re.compile(r"^\s*([+-]?\d+)\s+([0-9a-fA-F]{32})\s+(.*)$")
BOOT_RANGE_DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
BOOT_RANGE_DATETIME_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\b")
BOOT_TIMESTAMP_RE = re.compile(
    r"(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?"
    r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[^\s—–]+"
)

# Native systemd journal _TRANSPORT values.  These are journal-defined
# acquisition dimensions, not LinSpectacles-created source categories.
JOURNAL_TRANSPORTS = (
    "audit",
    "driver",
    "syslog",
    "journal",
    "stdout",
    "kernel",
)

# The table's Source column is a plain sender/unit summary with normal table
# text. The top-level Source selector is the native journal _TRANSPORT
# acquisition scope.
PRIORITY_LABELS = {
    "0": "Emergency",
    "1": "Alert",
    "2": "Critical",
    "3": "Error",
    "4": "Warning",
    "5": "Notice",
    "6": "Info",
    "7": "Debug",
}

GROUP_ORDER = (
    "Message / Event",
    "Source / Transport",
    "Process / Credentials",
    "Systemd",
    "Kernel / Device",
    "Audit / Security",
    "Object / Target",
    "Boot / Machine",
    "Journal Address / Time",
    "Other Reported Fields",
)

PREFERRED_FIELD_ORDER = (
    "MESSAGE",
    "PRIORITY",
    "MESSAGE_ID",
    "SYSLOG_IDENTIFIER",
    "SYSLOG_FACILITY",
    "_TRANSPORT",
    "_PID",
    "_UID",
    "_GID",
    "_COMM",
    "_EXE",
    "_CMDLINE",
    "_CAP_EFFECTIVE",
    "_SYSTEMD_UNIT",
    "_SYSTEMD_USER_UNIT",
    "_SYSTEMD_SLICE",
    "_SYSTEMD_USER_SLICE",
    "_SYSTEMD_CGROUP",
    "_SYSTEMD_INVOCATION_ID",
    "_KERNEL_SUBSYSTEM",
    "_KERNEL_DEVICE",
    "_UDEV_SYSNAME",
    "_UDEV_DEVNODE",
    "_UDEV_DEVLINK",
    "_AUDIT_SESSION",
    "_AUDIT_LOGINUID",
    "_BOOT_ID",
    "_MACHINE_ID",
    "_HOSTNAME",
    "__REALTIME_TIMESTAMP",
    "_SOURCE_REALTIME_TIMESTAMP",
    "__MONOTONIC_TIMESTAMP",
    "_SOURCE_MONOTONIC_TIMESTAMP",
    "__CURSOR",
)
_PREFERRED_FIELD_INDEX = {field: index for index, field in enumerate(PREFERRED_FIELD_ORDER)}

SOURCES_TEXT = """Journal Inspector is read-only. Its displayed facts come from journalctl.

Journal Entries inventory
  journalctl [optional -b <boot>] --output=json --reverse --no-pager
             [optional -n <Journal Entry Limit>] [optional _TRANSPORT=<source>]

Boot List inventory
  journalctl --list-boots --no-pager --quiet

  The list is parsed directly into:
    Index | Boot ID | First Entry | Last Entry

  In this mode Date becomes Period with All, This Month, Last Month, and Earlier.
  Period classification uses the first date reported by journalctl --list-boots.
  Source, Priority, entry limit, Boot scope (-b), and the configured journal priority flag do not alter
  the --list-boots query.

Selected-boot Metadata Details in Boot List inventory
  journalctl -b <index> --no-pager --quiet -o json

  The selected boot summary is derived only from journal records visible to the
  current user. It reports first/last visible journal timestamp, recorded
  duration derived from them, Hostname/Machine ID/Kernel Release when reported,
  visible entry count, counts by reported journal priority, and first/last
  visible record summaries.

Metadata Details panel
  Configuration can hide the panel entirely; F3 toggles it at any time.

Lazy Metadata Details
  On: normal record text and selected-boot summaries are produced only when a
  row is selected. Boot List summaries are cached until the next scan.
  Off: normal record metadata is preformatted after acquisition and Boot List
  summaries are collected eagerly for every listed boot after the boot-list scan.

Entry limit
  The bounded choices are 100, 500, 1,000, 5,000, 10,000, 25,000, and 50,000 records.
  No limit omits journalctl -n entirely. This can retrieve a very large journal,
  take substantially longer, and consume much more memory. Journal Inspector
  warns before that setting is accepted. Entry limit is ignored in Boot List inventory.

Date scope
  Used in Journal Entries inventory when Boot scope (-b) is disabled.
  All dates: no --since/--until constraint.
  Today: --since <today 00:00:00>.
  Yesterday: --since <yesterday 00:00:00> --until <today 00:00:00>.
  Custom: --since <start 00:00:00> --until <day after end 00:00:00>.

Boot scope (-b)
  Journal Entries inventory only. When enabled, Date is replaced by Boot and the query
  uses journalctl -b. Current boot uses -b 0; Previous boot uses -b -1; Custom
  accepts an exact boot index or exact 32-character Boot ID.

Journal priority flag
  Journal Entries inventory only. Configuration can add one acquisition threshold:
    --priority=warning
    --priority=err
    --priority=crit
    --priority=alert
  Each threshold requests that priority and all more-severe priorities.

Reported metadata
  In Journal Entries inventory every FIELD=VALUE pair returned in each JSON record is
  retained. Unknown/new fields are never discarded.

Filtering
  Journal Entries: Search examines every reported field name/value; Priority maps to
  PRIORITY. Source is a top-level acquisition scope backed by native _TRANSPORT.
  Boot List inventory: Search examines Index, Boot ID, First Entry and Last Entry;
  Period is a local boot-list filter.

Disk Usage tab
  journalctl --disk-usage
  Queried when the Disk Usage tab is opened for the first time, with an
  explicit Refresh action for subsequent checks.

Journal storage
  systemd may use /var/log/journal and/or /run/log/journal. This applet does not
  open or modify journal files directly; access is through journalctl only.

Scan lifecycle
  Configuration → Enable automatic scan chooses explicit or automatic acquisition.
  In Boot List inventory, automatic scan applies to the boot list too.
"""


def _previous_month(year, month):
    if month == 1:
        return year - 1, 12
    return year, month - 1


def _period_for_boot_range(text, now=None):
    match = BOOT_RANGE_DATE_RE.search(str(text or ""))
    if not match:
        return ""
    try:
        dt = datetime.strptime(match.group(1), "%Y-%m-%d")
    except ValueError:
        return ""
    now = now or datetime.now()
    previous = _previous_month(now.year, now.month)
    if (dt.year, dt.month) == (now.year, now.month):
        return LIST_BOOTS_PERIOD_THIS_MONTH
    if (dt.year, dt.month) == previous:
        return LIST_BOOTS_PERIOD_LAST_MONTH
    if (dt.year, dt.month) < previous:
        return LIST_BOOTS_PERIOD_EARLIER
    return ""


def _split_boot_reported_range(text):
    value = str(text or "").strip()

    # Parse the two timestamps themselves instead of depending on one output
    # separator. This covers the traditional em/en-dash form and newer
    # column-aligned output.
    timestamps = [match.group(0).strip() for match in BOOT_TIMESTAMP_RE.finditer(value)]
    if len(timestamps) >= 2:
        return timestamps[0], timestamps[1]

    for separator in ("—", "–"):
        if separator in value:
            first, last = value.split(separator, 1)
            return first.strip(), last.strip()

    # Preserve unknown output honestly rather than inventing Last Entry.
    return value, ""


def _boot_range_sort_value(text):
    match = BOOT_RANGE_DATETIME_RE.search(str(text or ""))
    if not match:
        return float("-inf")
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return float("-inf")


def _parse_list_boots(text):
    records = []
    failures = 0
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.upper().startswith("IDX ") and "BOOT" in stripped.upper():
            # Some current journalctl builds display a column heading.
            continue
        match = BOOT_LINE_RE.match(line)
        if not match:
            failures += 1
            continue
        index_text = match.group(1)
        try:
            index_number = int(index_text)
        except ValueError:
            index_number = 0
        reported_range = match.group(3).strip()
        first_entry, last_entry = _split_boot_reported_range(reported_range)
        records.append({
            "index": index_text,
            "boot_id": match.group(2),
            "first_entry": first_entry,
            "last_entry": last_entry,
            "_index_number": index_number,
            "_first_sort": _boot_range_sort_value(first_entry),
            "_last_sort": _boot_range_sort_value(last_entry),
            "_period": _period_for_boot_range(first_entry or reported_range),
            "_reported_range": reported_range,
        })

    # Keep the requested backend command unchanged; order the presentation
    # locally as current/latest (0), then -1, -2, ... oldest.
    records.sort(key=lambda record: record.get("_index_number", -10**9), reverse=True)
    return records, failures


def _json_scalar(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        if value and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
            try:
                return bytes(value).decode("utf-8", errors="replace")
            except Exception:
                return ""
        for item in value:
            scalar = _json_scalar(item)
            if scalar:
                return scalar
    return ""


def _format_boot_metadata_timestamp(raw):
    try:
        micros = int(str(raw))
        dt = datetime.fromtimestamp(micros / 1_000_000).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z"), dt
    except Exception:
        return "Not reported", None


def _format_duration(delta):
    if delta is None:
        return "Not determined"
    seconds = max(0, int(delta.total_seconds()))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m {secs:02d}s"
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _boot_record_summary(obj):
    timestamp, _ = _format_boot_metadata_timestamp(_json_scalar(obj.get("__REALTIME_TIMESTAMP")))
    priority = _json_scalar(obj.get("PRIORITY"))
    priority_text = PRIORITY_LABELS.get(priority, "Unknown")
    identifier = (
        _json_scalar(obj.get("SYSLOG_IDENTIFIER"))
        or _json_scalar(obj.get("_COMM"))
        or _json_scalar(obj.get("_SYSTEMD_UNIT"))
        or "journal"
    )
    message = _json_scalar(obj.get("MESSAGE")).replace("\n", " ").strip()
    return f"{timestamp} | {priority or '?'} - {priority_text} | {identifier}: {message or '(no message)'}"


def _boot_metadata_details_text(details):
    identity = [
        f"Boot Index: {details.get('boot_index', 'Not reported')}",
        f"Boot ID: {details.get('boot_id', 'Not reported')}",
    ]
    acquisition_warning = str(details.get("boot_list_acquisition_warning", "") or "").strip()
    if acquisition_warning:
        identity.append(f"Boot List Acquisition: Partial — {acquisition_warning}")
    identity.append("")

    state = details.get("state")
    if state != "observed":
        label = {
            "restricted": "Restricted",
            "unavailable": "Unavailable",
            "error": "Error",
        }.get(state, "Unavailable")
        return "\n".join(identity + [
            f"Metadata Details: {label}",
            f"Reason: {details.get('message') or 'No additional information reported.'}",
        ])

    count = int(details.get("entries", 0) or 0)
    malformed = int(details.get("malformed_json_lines", 0) or 0)
    if count == 0:
        return "\n".join(identity + [
            "Visible Journal Entries: 0",
            f"Malformed JSON Lines Skipped: {malformed}",
        ])

    return "\n".join(identity + [
        f"First Visible Journal Timestamp: {details.get('first_timestamp', 'Not reported')}",
        f"Last Visible Journal Timestamp: {details.get('last_timestamp', 'Not reported')}",
        f"Recorded Duration (Derived): {details.get('duration', 'Not determined')}",
        f"Hostname: {details.get('hostname', 'Not reported')}",
        f"Machine ID: {details.get('machine_id', 'Not reported')}",
        f"Kernel Release: {details.get('kernel_release', 'Not reported')}",
        f"Visible Journal Entries: {count}",
        f"Malformed JSON Lines Skipped: {malformed}",
        f"Priority Counts: {details.get('priority_counts', 'None reported')}",
        f"First Visible Record Summary: {details.get('first_record', 'Not reported')}",
        f"Last Visible Record Summary: {details.get('last_record', 'Not reported')}",
    ])


def _command_environment():
    env = os.environ.copy()
    env.update({
        "SYSTEMD_COLORS": "0",
        "SYSTEMD_PAGER": "cat",
        "LC_ALL": "C",
        "LANG": "C",
    })
    return env


def _permission_text(text):
    low = (text or "").lower()
    return any(token in low for token in (
        "permission denied",
        "access denied",
        "operation not permitted",
        "not permitted",
    ))


def _string(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(_string(item) for item in value)
    if isinstance(value, (dict, tuple)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except TypeError:
            return str(value)
    return str(value)


def _reported_value(value):
    """Preserve the fact that a field exists even when its value is empty/null."""
    if value is None:
        return "null"
    if isinstance(value, list):
        if not value:
            return "[]"
        return ", ".join(_reported_value(item) for item in value)
    if isinstance(value, (dict, tuple)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except TypeError:
            return str(value)
    text = str(value)
    return text if text else "(empty)"


def _display_priority(value):
    value = str(value or "").strip()
    if value in PRIORITY_LABELS:
        return f"{value} - {PRIORITY_LABELS[value]}"
    return "Not reported" if not value else value


def _format_realtime(value):
    text = _string(value).strip()
    if not text:
        return "Not reported"
    try:
        microseconds = int(text)
        stamp = datetime.fromtimestamp(microseconds / 1_000_000).astimezone()
        return stamp.strftime("%Y-%m-%d %H:%M:%S.%f %Z").replace(
            stamp.strftime("%f"), stamp.strftime("%f")[:3]
        )
    except (ValueError, OSError, OverflowError):
        return text


def _journal_source(raw):
    for key in ("_SYSTEMD_UNIT", "OBJECT_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_COMM"):
        value = _string(raw.get(key)).strip()
        if value:
            return value
    executable = _string(raw.get("_EXE")).strip()
    if executable:
        return Path(executable).name or executable
    return "Unknown Source"


def _metadata_group(field):
    if field == "MESSAGE" or field == "PRIORITY" or field == "MESSAGE_ID" or field.startswith("CODE_") or field == "ERRNO":
        return "Message / Event"
    if field in {"SYSLOG_IDENTIFIER", "SYSLOG_FACILITY", "SYSLOG_PID", "_TRANSPORT", "_STREAM_ID", "_LINE_BREAK", "_NAMESPACE"}:
        return "Source / Transport"
    if field in {"_PID", "_UID", "_GID", "_COMM", "_EXE", "_CMDLINE", "_CAP_EFFECTIVE", "_SELINUX_CONTEXT"}:
        return "Process / Credentials"
    if field.startswith("_SYSTEMD_"):
        return "Systemd"
    if field.startswith("_KERNEL_") or field.startswith("_UDEV_"):
        return "Kernel / Device"
    if field.startswith("_AUDIT_") or field.startswith("AUDIT_"):
        return "Audit / Security"
    if field.startswith("OBJECT_"):
        return "Object / Target"
    if field in {"_BOOT_ID", "_MACHINE_ID", "_HOSTNAME", "_RUNTIME_SCOPE"}:
        return "Boot / Machine"
    if field.startswith("__") or field in {"_SOURCE_REALTIME_TIMESTAMP", "_SOURCE_MONOTONIC_TIMESTAMP"}:
        return "Journal Address / Time"
    return "Other Reported Fields"


def _field_sort_key(field):
    return (_PREFERRED_FIELD_INDEX.get(field, len(PREFERRED_FIELD_ORDER)), field.casefold())


def _metadata_display_value(field, value):
    raw = _reported_value(value)
    if field == "PRIORITY":
        normalized = _string(value).strip()
        if normalized in PRIORITY_LABELS:
            return f"{raw} ({PRIORITY_LABELS[normalized]})"
    if field in {"__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP"}:
        formatted = _format_realtime(value)
        if formatted != raw and formatted != "Not reported":
            return f"{raw} ({formatted})"
    return raw


def _format_field_line(field, value):
    text = _metadata_display_value(field, value)
    if "\n" not in text:
        return f"{field}: {text}"
    lines = text.splitlines()
    return f"{field}:\n" + "\n".join(f"  {line}" for line in lines)


def _parse_journal_json(text):
    records = []
    failures = 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            failures += 1
            continue
        if not isinstance(raw, dict):
            failures += 1
            continue
        priority_value = _string(raw.get("PRIORITY")).strip()
        source = _journal_source(raw)
        records.append({
            "time": _format_realtime(raw.get("__REALTIME_TIMESTAMP") or raw.get("_SOURCE_REALTIME_TIMESTAMP")),
            "source": source,
            "priority": _display_priority(priority_value),
            "priority_value": priority_value,
            "pid": _string(raw.get("_PID")).strip() or "Not reported",
            "message": _string(raw.get("MESSAGE")).strip() or "Not reported",
            "raw": raw,
        })
    return records, failures


def _build_record_details_text(record):
    raw = record.get("raw", {})
    if not isinstance(raw, dict) or not raw:
        return "No reported journal fields are available for this record.\n"

    grouped = {group: [] for group in GROUP_ORDER}
    for field in raw:
        grouped[_metadata_group(str(field))].append(str(field))

    lines = []
    for group in GROUP_ORDER:
        fields = grouped[group]
        if not fields:
            continue
        if lines:
            lines.append("")
        lines.append(f"--- {group} ---")
        for field in sorted(fields, key=_field_sort_key):
            lines.append(_format_field_line(field, raw.get(field)))
    return "\n".join(lines).rstrip() + "\n"


def _record_details_text(record):
    """Use eager preformat when prepared; otherwise execute the r7 formatter."""
    prepared = record.get("_preformatted_metadata_details")
    if isinstance(prepared, str):
        return prepared
    return _build_record_details_text(record)


class CustomDateDialog(QDialog):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Custom Date — Journal Inspector")
        self.setModal(True)

        root = QVBoxLayout(self)
        note = QLabel(
            "Choose an inclusive local-date range. Journal Inspector translates this "
            "to journalctl --since/--until boundaries for the next Scan."
        )
        note.setWordWrap(True)
        root.addWidget(note)

        form = QFormLayout()
        self.start_edit = QDateEdit()
        self.start_edit.setCalendarPopup(True)
        self.start_edit.setDisplayFormat("yyyy-MM-dd")
        self.start_edit.setDate(QDate.fromString(owner.custom_start_date, "yyyy-MM-dd"))
        form.addRow("From:", self.start_edit)

        self.end_edit = QDateEdit()
        self.end_edit.setCalendarPopup(True)
        self.end_edit.setDisplayFormat("yyyy-MM-dd")
        self.end_edit.setDate(QDate.fromString(owner.custom_end_date, "yyyy-MM-dd"))
        form.addRow("Through:", self.end_edit)
        root.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept_checked)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _accept_checked(self):
        start = self.start_edit.date()
        end = self.end_edit.date()
        if start > end:
            QMessageBox.information(self, "Custom Date", "The From date must not be later than the Through date.")
            return
        self.owner.set_custom_date_range(
            start.toString("yyyy-MM-dd"),
            end.toString("yyyy-MM-dd"),
            persist=True,
        )
        self.accept()


class JournalOptionsDialog(QDialog):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — Journal Inspector")
        self.resize(980, 720)
        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        configuration_page = QWidget()
        al = QVBoxLayout(configuration_page)
        al.setContentsMargins(12, 12, 12, 12)
        al.setSpacing(10)
        h = QLabel("Journal configuration")
        f = h.font(); f.setBold(True); h.setFont(f); al.addWidget(h)
        n = QLabel(
            "Metadata Details shows every reported journal field, grouped for readability. "
            "Query settings are remembered. With automatic scan enabled they are applied automatically; otherwise use Scan / Scan Again."
        )
        n.setWordWrap(True); al.addWidget(n)

        row = QHBoxLayout()
        row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentIndex(1 if owner.details_orientation == "vertical" else 0)
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        row.addWidget(self.layout_combo); row.addStretch(1); al.addLayout(row)

        self.show_metadata_panel = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        al.addWidget(self.show_metadata_panel)

        self.lazy_metadata = QCheckBox("Lazy Metadata Details")
        self.lazy_metadata.setChecked(owner.lazy_metadata_enabled)
        self.lazy_metadata.toggled.connect(self._lazy_metadata_changed)
        al.addWidget(self.lazy_metadata)
        lazy_note = QLabel(
            "On: details are produced only when a row is selected. In Boot List inventory the selected boot is "
            "queried once and cached until the next scan. Off: normal record details are preformatted and "
            "Boot List metadata is collected eagerly for every boot after scanning."
        )
        lazy_note.setWordWrap(True); al.addWidget(lazy_note)

        inventory_row = QHBoxLayout()
        inventory_row.addWidget(QLabel("Inventory:"))
        self.journal_entries = QRadioButton("Journal Entries")
        self.boot_list = QRadioButton("Boot List")
        self.inventory_group = QButtonGroup(self)
        self.inventory_group.setExclusive(True)
        self.inventory_group.addButton(self.journal_entries)
        self.inventory_group.addButton(self.boot_list)
        self.journal_entries.setChecked(not owner.list_boots_enabled)
        self.boot_list.setChecked(owner.list_boots_enabled)
        self.journal_entries.toggled.connect(self._journal_entries_selected)
        self.boot_list.toggled.connect(self._boot_list_selected)
        inventory_row.addWidget(self.journal_entries)
        inventory_row.addWidget(self.boot_list)
        inventory_row.addStretch(1)
        al.addLayout(inventory_row)
        list_boots_note = QLabel(
            "Journal Entries uses the configured journalctl record query. Boot List uses exactly "
            "journalctl --list-boots --no-pager --quiet and changes the inventory to Index, Boot ID, "
            "First Entry and Last Entry; Date becomes Period. Source, Priority, entry limit, Boot scope, "
            "and the configured priority flag do not alter the Boot List query. Ctrl+Shift+I toggles inventories."
        )
        list_boots_note.setWordWrap(True); al.addWidget(list_boots_note)

        limit_row = QHBoxLayout()
        limit_row.addWidget(QLabel("Journal entry limit:"))
        self.limit_combo = QComboBox()
        for value in ENTRY_LIMITS:
            self.limit_combo.addItem(f"{value:,}", value)
        self.limit_combo.addItem("No limit", NO_ENTRY_LIMIT)
        idx = self.limit_combo.findData(owner.entry_limit)
        self.limit_combo.setCurrentIndex(idx if idx >= 0 else self.limit_combo.findData(DEFAULT_ENTRY_LIMIT))
        self._limit_guard = False
        self.limit_combo.currentIndexChanged.connect(self._limit_changed)
        limit_row.addWidget(self.limit_combo); limit_row.addStretch(1); al.addLayout(limit_row)

        limit_note = QLabel(
            "No limit removes journalctl -n. It may retrieve a very large journal, take much longer, "
            "and consume substantially more memory. A warning is shown before it is enabled."
        )
        limit_note.setWordWrap(True)
        al.addWidget(limit_note)

        self.boot_scope = QCheckBox("Boot scope (-b) — Ctrl+B")
        self.boot_scope.setChecked(owner.boot_scope_enabled)
        self.boot_scope.toggled.connect(self._boot_scope_changed)
        al.addWidget(self.boot_scope)
        boot_note = QLabel(
            "Limits the scan to one boot. When enabled, the Date selector becomes Boot with "
            "Current boot, Previous boot, and Custom boot... choices."
        )
        boot_note.setWordWrap(True)
        al.addWidget(boot_note)

        priority_query_row = QHBoxLayout()
        priority_query_row.addWidget(QLabel("Journal priority flag:"))
        self.priority_query_combo = QComboBox()
        for label, value in PRIORITY_QUERY_OPTIONS:
            self.priority_query_combo.addItem(label, value)
        priority_index = self.priority_query_combo.findData(owner.priority_query_level)
        self.priority_query_combo.setCurrentIndex(priority_index if priority_index >= 0 else 0)
        self.priority_query_combo.currentIndexChanged.connect(self._priority_query_changed)
        priority_query_row.addWidget(self.priority_query_combo)
        priority_query_row.addStretch(1)
        al.addLayout(priority_query_row)

        priority_query_note = QLabel(
            "Journal Entries inventory only. The selected threshold is passed to journalctl during acquisition: "
            "Warning includes priorities 0–4, Error 0–3, Critical 0–2, and Alert 0–1. "
            "Shortcuts: Ctrl+Shift+0 Off, Ctrl+Shift+4 Warning, Ctrl+Shift+3 Error, "
            "Ctrl+Shift+2 Critical, Ctrl+Shift+1 Alert. "
            "The top-level Priority selector remains a local exact-priority filter."
        )
        priority_query_note.setWordWrap(True)
        al.addWidget(priority_query_note)

        self.automatic_scan = QCheckBox("Enable automatic scan — Ctrl+Shift+F5")
        self.automatic_scan.setChecked(owner.automatic_scan_enabled)
        self.automatic_scan.toggled.connect(self._automatic_scan_changed)
        al.addWidget(self.automatic_scan)
        automatic_scan_note = QLabel(
            "When enabled, Journal Inspector scans automatically when it opens and whenever an acquisition "
            "setting changes. The top-level Scan / Scan Again button is hidden. Search and Priority remain "
            "local filters and do not re-run journalctl."
        )
        automatic_scan_note.setWordWrap(True)
        al.addWidget(automatic_scan_note)

        scan_note = QLabel(
            "With automatic scan off, choose configuration, close this dialog, then use the top-level Scan button. "
            "F3 hides/restores Metadata Details; Shift+F5 repeats the current scan; Ctrl+L toggles Horizontal/Vertical; "
            "Ctrl+Shift+I toggles Journal Entries/Boot List; Ctrl+Shift+F5 toggles automatic scan; Ctrl+/ opens Options."
        )
        scan_note.setWordWrap(True)
        al.addWidget(scan_note)
        al.addStretch(1)
        tabs.addTab(configuration_page, "Configuration")

        disk_usage_page = QWidget()
        dul = QVBoxLayout(disk_usage_page)
        dul.setContentsMargins(12, 12, 12, 12)
        dul.setSpacing(10)

        disk_heading = QLabel("Journal disk usage")
        disk_heading_font = disk_heading.font()
        disk_heading_font.setBold(True)
        disk_heading_font.setPointSize(max(disk_heading_font.pointSize(), 11))
        disk_heading.setFont(disk_heading_font)
        dul.addWidget(disk_heading)

        disk_note = QLabel(
            "Read-only disk usage reported directly by journalctl. "
            "The command runs when this tab is opened for the first time; use Refresh to query it again."
        )
        disk_note.setWordWrap(True)
        dul.addWidget(disk_note)

        self.disk_usage_canvas = QTextEdit()
        self.disk_usage_canvas.setReadOnly(True)
        self.disk_usage_canvas.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen = getattr(owner, "_metadata_font", None)
        disk_font_rule = ""
        if chosen is not None:
            self.disk_usage_canvas.setFont(chosen)
            self.disk_usage_canvas.document().setDefaultFont(chosen)
            self.disk_usage_canvas.setCurrentFont(chosen)
            disk_font_rule = metadata_font_qss(chosen)
        self.disk_usage_canvas.setStyleSheet(
            "QTextEdit { "
            + disk_font_rule
            + " background-color: #151719; color: #dcdcdc; "
              "border: 1px solid #333333; }"
        )
        dul.addWidget(self.disk_usage_canvas, 1)

        disk_actions = QHBoxLayout()
        disk_actions.addStretch(1)
        self.disk_usage_refresh = QPushButton("Refresh")
        self.disk_usage_refresh.clicked.connect(self._refresh_disk_usage)
        disk_actions.addWidget(self.disk_usage_refresh)
        dul.addLayout(disk_actions)

        self._disk_usage_loaded = False
        self._set_disk_usage_canvas(
            "Journal Disk Usage",
            [
                ("Status", "Not queried"),
                ("Command", "journalctl --disk-usage"),
            ],
        )
        self._disk_usage_tab_index = tabs.addTab(disk_usage_page, "Disk Usage")
        tabs.currentChanged.connect(self._options_tab_changed)

        self._update_mode_controls()

        sources_page = QWidget()
        sl = QVBoxLayout(sources_page)
        sl.setContentsMargins(12, 12, 12, 12); sl.setSpacing(10)
        h = QLabel("Data Sources")
        f = h.font(); f.setBold(True); f.setPointSize(max(f.pointSize(), 11)); h.setFont(f); sl.addWidget(h)
        n = QLabel("Commands and system interfaces used by this read-only Journal Inspector.")
        n.setWordWrap(True); sl.addWidget(n)
        self.sources_text = QTextEdit(); self.sources_text.setReadOnly(True)
        t = self.sources_text
        chosen = getattr(owner, "_metadata_font", None); font_rule = ""
        if chosen is not None:
            t.setFont(chosen); t.document().setDefaultFont(chosen); t.setCurrentFont(chosen)
            font_rule = metadata_font_qss(chosen)
        t.setStyleSheet(
            "QTextEdit { "
            + font_rule
            + " background-color: #151719; color: #dcdcdc; "
              "border: 1px solid #333333; }"
        )

        source_key_format = QTextCharFormat()
        source_key_format.setForeground(QColor("#9cdcfe"))
        source_key_format.setFontWeight(600)
        source_value_format = QTextCharFormat()
        source_value_format.setForeground(QColor("#dcdcdc"))

        cursor = t.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in SOURCES_TEXT.splitlines():
            if line and not line[:1].isspace():
                cursor.insertText(line + "\n", source_key_format)
            else:
                cursor.insertText(line + "\n", source_value_format)
        cursor.insertText("\nCurrent configured scan query\n", source_key_format)
        cursor.insertText("  " + " ".join(owner._journal_command()) + "\n", source_value_format)
        t.setTextCursor(cursor)
        t.moveCursor(QTextCursor.MoveOperation.Start)
        sl.addWidget(t, 1)
        self._sources_tab_index = tabs.addTab(sources_page, "Sources")

        export_page = QWidget()
        el = QVBoxLayout(export_page)
        el.setContentsMargins(12, 12, 12, 12); el.setSpacing(10)
        h = QLabel("Export details")
        f = h.font(); f.setBold(True); h.setFont(f); el.addWidget(h)
        n = QLabel("Select the Journal Inspector details to include in the export.")
        n.setWordWrap(True); el.addWidget(n)
        self.journal_export_checks = []
        self.boot_export_checks = []
        for key, label in [
            ("time", "Time"),
            ("source", "Source summary"),
            ("priority", "Priority"),
            ("pid", "PID"),
            ("message", "Message"),
        ]:
            c = QCheckBox(label); c.setChecked(True); el.addWidget(c)
            self.journal_export_checks.append((key, label, c))
        for key, label in [
            ("index", "Index"),
            ("boot_id", "Boot ID"),
            ("first_entry", "First Entry"),
            ("last_entry", "Last Entry"),
        ]:
            c = QCheckBox(label); c.setChecked(True); el.addWidget(c)
            self.boot_export_checks.append((key, label, c))
        self.checks = []
        self.record_details = QCheckBox()
        self.record_details.setChecked(False); el.addWidget(self.record_details)
        self._sync_export_mode()
        el.addStretch(1)
        er = QHBoxLayout(); er.addStretch(1)
        b = QPushButton("Export..."); b.clicked.connect(self._export_selected); er.addWidget(b); el.addLayout(er)
        tabs.addTab(export_page, "Export")

        about_page = QWidget()
        bl = QVBoxLayout(about_page)
        bl.setContentsMargins(24, 20, 24, 18); bl.setSpacing(8)
        icon = QLabel(); icon.setAlignment(Qt.AlignmentFlag.AlignCenter); icon.setFixedSize(112, 112)
        ip = Path(__file__).resolve().parent / "icon.png"
        if ip.is_file():
            pm = QPixmap(str(ip))
            if not pm.isNull():
                icon.setPixmap(pm.scaled(112, 112, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        bl.addWidget(icon, alignment=Qt.AlignmentFlag.AlignHCenter)
        name = QLabel("<h2 style='margin:0'>Journal Inspector</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(name)
        v = QLabel(f"Version {APPLET_VERSION}"); v.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(v)
        sg = QLabel("<b>Expose. Explore. Explain.</b>"); sg.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(sg)
        d = QLabel(
            "A read-only LinSpectacles applet for structured systemd journal inspection, with explicit scanning, complete grouped record metadata, "
            "optional table-only viewing, configurable lazy details, keyboard-driven boot and priority controls, "
            "priority acquisition thresholds, a Boot List inventory backed by --list-boots, and read-only journal disk-usage reporting."
        )
        d.setWordWrap(True); d.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(d)
        det = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            f"<a href='{APPLET_ORGANIZATION_URL}'>{APPLET_ORGANIZATION_ID}</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        det.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction | Qt.TextInteractionFlag.TextSelectableByMouse)
        det.setOpenExternalLinks(True)
        det.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(det)
        cp = QLabel("Copyright © 2026 <a href='https://github.com/brunonlinespace'>brunonlinespace</a>")
        cp.setOpenExternalLinks(True); cp.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(cp)
        lic = QLabel("Licensed under GNU GPLv3 or later.")
        lic.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(lic)
        ru = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "README.md")).toString()
        lu = QUrl.fromLocalFile(str(Path(__file__).resolve().parent.parent / "LICENSE")).toString()
        links = QLabel(
            f"<a href='{ru}'>README</a> &nbsp;·&nbsp; "
            f"<a href='{lu}'>License</a> &nbsp;·&nbsp; "
            f"<a href='{APPLET_REPOSITORY}'>Repository</a>"
        )
        links.setOpenExternalLinks(True); links.setAlignment(Qt.AlignmentFlag.AlignCenter); bl.addWidget(links)
        bl.addStretch(1); tabs.addTab(about_page, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject); root.addWidget(buttons)

    def _layout_changed(self, text):
        orientation = "vertical" if str(text).lower().startswith("vertical") else "horizontal"
        self.owner.set_details_orientation(orientation, persist=True)

    def _metadata_panel_changed(self, checked):
        self.owner.set_metadata_panel_visible(bool(checked), persist=True)

    def _lazy_metadata_changed(self, checked):
        self.owner.set_lazy_metadata_enabled(bool(checked), persist=True)

    def _journal_entries_selected(self, checked):
        if checked:
            self.owner.set_list_boots_enabled(False, persist=True)
            self._update_mode_controls()
            self._sync_export_mode()

    def _boot_list_selected(self, checked):
        if checked:
            self.owner.set_list_boots_enabled(True, persist=True)
            self._update_mode_controls()
            self._sync_export_mode()

    def _sync_export_mode(self):
        boot_list = bool(self.owner.list_boots_enabled)
        for _key, _label, checkbox in getattr(self, "journal_export_checks", []):
            checkbox.setVisible(not boot_list)
        for _key, _label, checkbox in getattr(self, "boot_export_checks", []):
            checkbox.setVisible(boot_list)
        self.checks = (
            getattr(self, "boot_export_checks", [])
            if boot_list
            else getattr(self, "journal_export_checks", [])
        )
        if hasattr(self, "record_details"):
            self.record_details.setText(
                "Boot Metadata Details" if boot_list else "All Reported Fields (grouped)"
            )

    def _update_mode_controls(self):
        normal = not self.owner.list_boots_enabled
        self.limit_combo.setEnabled(normal)
        self.boot_scope.setEnabled(normal)
        self.priority_query_combo.setEnabled(normal)

    def _limit_changed(self, _index):
        if self._limit_guard:
            return
        value = self.limit_combo.currentData()
        if value is None:
            return
        value = int(value)
        if value == NO_ENTRY_LIMIT and self.owner.entry_limit != NO_ENTRY_LIMIT:
            answer = QMessageBox.warning(
                self,
                "No journal entry limit",
                "No limit removes the journalctl entry cap. On a machine with a large persistent journal "
                "this can retrieve many thousands of records, take much longer, and use substantially more memory.\n\n"
                "Enable No limit anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self._limit_guard = True
                try:
                    old_index = self.limit_combo.findData(self.owner.entry_limit)
                    self.limit_combo.setCurrentIndex(
                        old_index if old_index >= 0 else self.limit_combo.findData(DEFAULT_ENTRY_LIMIT)
                    )
                finally:
                    self._limit_guard = False
                return
        self.owner.set_entry_limit(value, persist=True)

    def _boot_scope_changed(self, checked):
        self.owner.set_boot_scope_enabled(bool(checked), persist=True)

    def _priority_query_changed(self, _index):
        self.owner.set_priority_query_level(
            str(self.priority_query_combo.currentData() or ""),
            persist=True,
        )

    def _options_tab_changed(self, index):
        if index == self._disk_usage_tab_index and not self._disk_usage_loaded:
            self._refresh_disk_usage()
        if index == getattr(self, "_sources_tab_index", -1):
            self._refresh_sources()

    def _refresh_sources(self):
        t = getattr(self, "sources_text", None)
        if t is None:
            return
        source_key_format = QTextCharFormat()
        source_key_format.setForeground(QColor("#9cdcfe"))
        source_key_format.setFontWeight(600)
        source_value_format = QTextCharFormat()
        source_value_format.setForeground(QColor("#dcdcdc"))
        t.clear()
        cursor = t.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in SOURCES_TEXT.splitlines():
            if line and not line[:1].isspace():
                cursor.insertText(line + "\n", source_key_format)
            else:
                cursor.insertText(line + "\n", source_value_format)
        cursor.insertText("\nCurrent configured scan query\n", source_key_format)
        cursor.insertText("  " + " ".join(self.owner._journal_command()) + "\n", source_value_format)
        t.setTextCursor(cursor)
        t.moveCursor(QTextCursor.MoveOperation.Start)

    @staticmethod
    def _disk_usage_formats():
        key_format = QTextCharFormat()
        key_format.setForeground(QColor("#9cdcfe"))
        key_format.setFontWeight(600)
        value_format = QTextCharFormat()
        value_format.setForeground(QColor("#dcdcdc"))
        return key_format, value_format

    def _set_disk_usage_canvas(self, heading, properties):
        key_format, value_format = self._disk_usage_formats()
        self.disk_usage_canvas.clear()
        cursor = self.disk_usage_canvas.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(str(heading) + "\n", key_format)
        for key, value in properties:
            cursor.insertText(f"{key}: ", key_format)
            cursor.insertText(str(value or "Not reported") + "\n", value_format)
        self.disk_usage_canvas.setTextCursor(cursor)
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.disk_usage_canvas.setTextCursor(cursor)
        self.disk_usage_canvas.verticalScrollBar().setValue(0)

    def _refresh_disk_usage(self):
        self.disk_usage_refresh.setEnabled(False)
        self._set_disk_usage_canvas(
            "Journal Disk Usage",
            [("Status", "Querying"), ("Command", "journalctl --disk-usage")],
        )
        QApplication.processEvents()

        try:
            result = subprocess.run(
                ["journalctl", "--disk-usage"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
                env=_command_environment(),
            )
            output = (result.stdout or "").strip()
            error = (result.stderr or "").strip()
            if result.returncode == 0:
                properties = [
                    ("Status", "Observed"),
                    ("Command", "journalctl --disk-usage"),
                    ("Reported", output or "No output reported"),
                ]
            else:
                properties = [
                    ("Status", "Unavailable"),
                    ("Command", "journalctl --disk-usage"),
                    ("Reason", error or output or f"journalctl exited with status {result.returncode}"),
                ]
        except FileNotFoundError:
            properties = [
                ("Status", "Unavailable"),
                ("Command", "journalctl --disk-usage"),
                ("Reason", "journalctl is not installed."),
            ]
        except subprocess.TimeoutExpired:
            properties = [
                ("Status", "Unavailable"),
                ("Command", "journalctl --disk-usage"),
                ("Reason", "Disk-usage query timed out."),
            ]
        except Exception as exc:
            properties = [
                ("Status", "Unavailable"),
                ("Command", "journalctl --disk-usage"),
                ("Reason", str(exc)),
            ]
        finally:
            self._disk_usage_loaded = True
            self.disk_usage_refresh.setEnabled(True)

        self._set_disk_usage_canvas("Journal Disk Usage", properties)

    def _automatic_scan_changed(self, checked):
        self.owner.set_automatic_scan_enabled(bool(checked), persist=True)

    def _export_selected(self):
        columns = []
        for key, label, checkbox in self.checks:
            if checkbox.isChecked():
                columns.append((key, label, 220, "left"))
        if self.record_details.isChecked():
            label = "Boot Metadata Details" if self.owner.list_boots_enabled else "All Reported Fields"
            columns.append(("record_details", label, 520, "left"))
        if not columns:
            QMessageBox.information(self, "Export", "Select at least one detail to export.")
            return
        records = []
        for src in self.owner.modules_data:
            item = {key: src.get(key, "") for key, _label, checkbox in self.checks if checkbox.isChecked()}
            if self.record_details.isChecked():
                if self.owner.list_boots_enabled:
                    details = self.owner._boot_detail_cache.get(src.get("boot_id"))
                    if details is None:
                        details = self.owner._collect_boot_details(src)
                        self.owner._boot_detail_cache[src.get("boot_id")] = details
                    item["record_details"] = _boot_metadata_details_text(details)
                else:
                    item["record_details"] = _record_details_text(src)
            records.append(item)
        if not records:
            QMessageBox.information(self, "Export", "There is no collected data to export yet.")
            return
        path = export_records_dialog(self, APPLET_NAME, records, columns=columns)
        if path is not None:
            self.owner.set_status(f"Exported data to {path}")



class JournalInspectorTab(BaseInspectorTab):
    NUMERIC_COLUMNS = set()

    def __init__(self, parent=None):
        columns = [
            ("time", "Time", 205, "left"),
            ("source", "Source", 190, "left"),
            ("priority", "Priority", 125, "left"),
            ("pid", "PID", 85, "right"),
            ("message", "Message", 520, "left"),
        ]
        super().__init__("Journal Entries", columns, [ALL_SOURCES_LABEL], parent)
        self.export_title = APPLET_NAME
        self._parse_failures = 0
        self._has_scanned = False
        self._query_dirty = False
        self._scope_guard = False
        self._configuration_open = False
        self.list_boots_enabled = False
        self.list_boots_period = LIST_BOOTS_PERIOD_ALL
        self.metadata_panel_visible = True
        self.lazy_metadata_enabled = True
        self._boot_detail_cache = {}
        self._list_boots_acquisition_warning = ""
        self._normal_columns = list(self.columns)
        self._list_boots_columns = [
            ("index", "Index", 80, "right"),
            ("boot_id", "Boot ID", 275, "left"),
            ("first_entry", "First Entry", 300, "left"),
            ("last_entry", "Last Entry", 300, "left"),
        ]

        # exp2-r5 isolation rule: the r7 Journal QTableWidget is never
        # repurposed for --list-boots. List Boots owns a separate table.
        self.inventory_stack = QStackedWidget()
        self.table.setParent(self.inventory_stack)
        self.inventory_stack.addWidget(self.table)

        self.boot_table = QTableWidget(0, len(self._list_boots_columns))
        self.boot_table.setHorizontalHeaderLabels([column[1] for column in self._list_boots_columns])
        self.boot_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.boot_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.boot_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.boot_table.setAlternatingRowColors(True)
        self.boot_table.verticalHeader().setVisible(False)
        for index, (_column_id, _label, width, _alignment) in enumerate(self._list_boots_columns):
            self.boot_table.setColumnWidth(index, width)
        self.boot_table.itemSelectionChanged.connect(self._on_boot_select)
        self.boot_table.horizontalHeader().sectionClicked.connect(self._sort_boots_by_section)
        self.boot_table.horizontalHeader().setSortIndicatorShown(False)
        self.inventory_stack.addWidget(self.boot_table)

        # Reinsert the stack where the original r7 table lived.
        self.splitter.insertWidget(0, self.inventory_stack)
        self.splitter.setSizes([480, 700])
        self._boot_sort_reverse = {}
        self._auto_scan_timer = QTimer(self)
        self._auto_scan_timer.setSingleShot(True)
        self._auto_scan_timer.setInterval(250)
        self._auto_scan_timer.timeout.connect(self.load_modules)

        # Keep the established Journal Inspector hierarchy: Source is a
        # top-level selector. Search/Date/Priority are the filtering row.
        self.category_label.setText("Source:")

        # BaseInspectorTab wires this combo to local filter_modules(). Source is
        # now a journal acquisition scope, so disconnect that inherited binding.
        try:
            self.category_dropdown.currentTextChanged.disconnect()
        except TypeError:
            pass

        self.search_entry.setPlaceholderText("Search all journal fields...")
        self.search_entry.setMinimumWidth(0)
        self.search_entry.setMaximumWidth(320)
        self.category_dropdown.setMinimumWidth(0)
        self.category_dropdown.setMaximumWidth(16777215)
        self.category_dropdown.setMinimumContentsLength(len("Previous boot"))
        self.category_dropdown.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )

        filter_layout = self.layout().itemAt(1).layout()
        filter_layout.removeWidget(self.category_label)
        filter_layout.removeWidget(self.category_dropdown)
        self.category_label.setStyleSheet("")
        refresh_index = self.dash_layout.indexOf(self.refresh_btn)
        self.dash_layout.insertWidget(refresh_index, self.category_label)
        self.dash_layout.insertWidget(refresh_index + 1, self.category_dropdown)

        insert_index = filter_layout.indexOf(self.filter_status_lbl)

        self.date_label = QLabel("Date:")
        self.date_label.setStyleSheet("font-weight: 600;")
        filter_layout.insertWidget(insert_index, self.date_label)
        insert_index += 1

        # One top-level temporal selector. Configuration -> Boot scope (-b)
        # switches this same control between Date and Boot semantics.
        self.date_dropdown = QComboBox()
        self.date_dropdown.setMinimumWidth(0)
        self.date_dropdown.setMaximumWidth(260)
        filter_layout.insertWidget(insert_index, self.date_dropdown)
        insert_index += 1

        self.priority_label = QLabel("Priority:")
        self.priority_label.setStyleSheet("font-weight: 600;")
        filter_layout.insertWidget(insert_index, self.priority_label)
        insert_index += 1

        self.priority_dropdown = QComboBox()
        self.priority_dropdown.addItem("All", "")
        for value in ("0", "1", "2", "3", "4", "5", "6", "7"):
            self.priority_dropdown.addItem(_display_priority(value), value)
        self.priority_dropdown.addItem("Not reported", NOT_REPORTED_PRIORITY)
        self.priority_dropdown.setMinimumWidth(0)
        self.priority_dropdown.currentIndexChanged.connect(self.filter_modules)
        filter_layout.insertWidget(insert_index, self.priority_dropdown)

        self.export_btn.hide()
        export_index = self.dash_layout.indexOf(self.export_btn)
        self.options_btn = QPushButton("Options...")
        self.options_btn.clicked.connect(self.show_options)
        self.dash_layout.insertWidget(export_index, self.options_btn)

        self.details_orientation = "horizontal"
        self.entry_limit = DEFAULT_ENTRY_LIMIT
        self.priority_query_level = PRIORITY_QUERY_NONE
        self.boot_scope_enabled = False
        self.boot_scope = BOOT_SCOPE_CURRENT
        self.custom_boot_selector = ""
        self.automatic_scan_enabled = False
        today_text = date.today().isoformat()
        self.source_transport = ""
        self.date_scope = DATE_SCOPE_ALL
        self.custom_start_date = today_text
        self.custom_end_date = today_text
        self._load_preferences()
        self._populate_source_scope()
        self._rebuild_temporal_scope_selector()
        self.category_dropdown.currentIndexChanged.connect(self._source_scope_changed)
        self.date_dropdown.currentIndexChanged.connect(self._temporal_scope_changed)

        self._shortcut_ack = ""
        self._last_status_text = ""
        self._shortcut_ack_timer = QTimer(self)
        self._shortcut_ack_timer.setSingleShot(True)
        self._shortcut_ack_timer.setInterval(1800)
        self._shortcut_ack_timer.timeout.connect(self._clear_shortcut_ack)

        self._shortcuts = []

        def add_shortcut(sequence, handler):
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            shortcut.activated.connect(handler)
            self._shortcuts.append(shortcut)
            return shortcut

        self._metadata_shortcut = add_shortcut("F3", self._shortcut_toggle_metadata)
        add_shortcut("Ctrl+Shift+I", self._shortcut_toggle_list_boots)
        add_shortcut("Ctrl+B", self._shortcut_toggle_boot_scope)
        add_shortcut("Ctrl+L", self._shortcut_toggle_layout)
        add_shortcut("Shift+F5", self._shortcut_repeat_scan)
        add_shortcut("Ctrl+Shift+F5", self._shortcut_toggle_automatic_scan)
        add_shortcut("Ctrl+/", self._shortcut_open_options)

        for value in range(8):
            add_shortcut(f"Ctrl+{value}", lambda v=value: self._shortcut_priority_exact(str(v)))
        add_shortcut("Ctrl+A", self._shortcut_priority_all)
        add_shortcut("Ctrl+Shift+A", self._shortcut_priority_not_reported)

        add_shortcut("Ctrl+Shift+0", lambda: self._shortcut_priority_threshold(""))
        add_shortcut("Ctrl+Shift+4", lambda: self._shortcut_priority_threshold("warning"))
        add_shortcut("Ctrl+Shift+3", lambda: self._shortcut_priority_threshold("err"))
        add_shortcut("Ctrl+Shift+2", lambda: self._shortcut_priority_threshold("crit"))
        add_shortcut("Ctrl+Shift+1", lambda: self._shortcut_priority_threshold("alert"))

        self._apply_inventory_mode()
        self.set_metadata_panel_visible(self.metadata_panel_visible, persist=False)

        self.refresh_btn.setText("Scan")
        self._apply_scan_mode()

        # Preserve the visible ascending/descending feedback learned from the
        # older Kernel Messages implementation while keeping backing-data sort.
        self.table.horizontalHeader().setSortIndicatorShown(False)

        self.modules_data.clear()
        self.table.setRowCount(0)
        self.clear_info()
        self._populate_source_scope()
        self._update_counter()
        if self.automatic_scan_enabled:
            self.set_status("Automatic scan enabled. Collecting journal records...")
            self._schedule_auto_scan(delay_ms=0)
        else:
            self.set_status(
                "Not scanned. Choose Period/Options if needed, then press Scan."
                if self.list_boots_enabled
                else "Not scanned. Choose Date/Boot/Options if needed, then press Scan."
            )

    def set_status(self, text):
        self._last_status_text = str(text)
        shown = self._last_status_text
        if getattr(self, "_shortcut_ack", ""):
            shown = f"{self._shortcut_ack} · {shown}"
        super().set_status(shown)

    def _ack_shortcut(self, label):
        self._shortcut_ack = f"Shortcut {label}"
        if hasattr(self, "_shortcut_ack_timer"):
            self._shortcut_ack_timer.start()
        base = self._last_status_text or "Accepted."
        super().set_status(f"{self._shortcut_ack} · {base}")

    def _clear_shortcut_ack(self):
        self._shortcut_ack = ""
        super().set_status(self._last_status_text)

    def _shortcut_toggle_metadata(self):
        self._ack_shortcut("F3")
        self.toggle_metadata_panel()
        state = "shown" if self.metadata_panel_visible else "hidden"
        self.set_status(f"Metadata Details panel {state}.")

    def _shortcut_toggle_list_boots(self):
        self._ack_shortcut("Ctrl+Shift+I")
        self.set_list_boots_enabled(not self.list_boots_enabled, persist=True)
        self.set_status(
            "Inventory: Boot List."
            if self.list_boots_enabled
            else "Inventory: Journal Entries."
        )

    def _shortcut_toggle_boot_scope(self):
        self._ack_shortcut("Ctrl+B")
        if self.list_boots_enabled:
            self.set_status("Boot scope (-b) is not applicable while Boot List inventory is active.")
            return
        self.set_boot_scope_enabled(not self.boot_scope_enabled, persist=True)
        self.set_status(
            "Boot scope (-b) enabled."
            if self.boot_scope_enabled
            else "Boot scope (-b) removed."
        )

    def _shortcut_toggle_layout(self):
        self._ack_shortcut("Ctrl+L")
        orientation = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        self.set_details_orientation(orientation, persist=True)
        self.set_status(f"Metadata Details layout: {orientation.title()}.")

    def _shortcut_repeat_scan(self):
        self._ack_shortcut("Shift+F5")
        self.set_status(
            "Repeating Boot List scan..."
            if self.list_boots_enabled
            else "Repeating journal scan..."
        )
        self.load_modules()

    def _shortcut_toggle_automatic_scan(self):
        self._ack_shortcut("Ctrl+Shift+F5")
        self.set_automatic_scan_enabled(not self.automatic_scan_enabled, persist=True)
        self.set_status(
            "Automatic scan enabled."
            if self.automatic_scan_enabled
            else "Automatic scan disabled."
        )

    def _shortcut_open_options(self):
        self._ack_shortcut("Ctrl+/")
        self.set_status("Opening Options...")
        self.show_options()

    def _shortcut_priority_exact(self, value):
        self._ack_shortcut(f"Ctrl+{value}")
        if self.list_boots_enabled:
            self.set_status("Exact journal priority filtering is not applicable in Boot List inventory.")
            return
        index = self.priority_dropdown.findData(str(value))
        if index >= 0:
            self.priority_dropdown.setCurrentIndex(index)
        self.set_status(f"Priority inspection: {_display_priority(str(value))}.")

    def _shortcut_priority_all(self):
        self._ack_shortcut("Ctrl+A")
        if self.list_boots_enabled:
            self.set_status("Exact journal priority filtering is not applicable in Boot List inventory.")
            return
        index = self.priority_dropdown.findData("")
        if index >= 0:
            self.priority_dropdown.setCurrentIndex(index)
        self.set_status("Priority inspection: All.")

    def _shortcut_priority_not_reported(self):
        self._ack_shortcut("Ctrl+Shift+A")
        if self.list_boots_enabled:
            self.set_status("Exact journal priority filtering is not applicable in Boot List inventory.")
            return
        index = self.priority_dropdown.findData(NOT_REPORTED_PRIORITY)
        if index >= 0:
            self.priority_dropdown.setCurrentIndex(index)
        self.set_status("Priority inspection: Not reported.")

    def _shortcut_priority_threshold(self, level):
        shortcut_by_level = {
            "": "Ctrl+Shift+0",
            "warning": "Ctrl+Shift+4",
            "err": "Ctrl+Shift+3",
            "crit": "Ctrl+Shift+2",
            "alert": "Ctrl+Shift+1",
        }
        label_by_level = {
            "": "Off (all priorities)",
            "warning": "Warning and above",
            "err": "Error and above",
            "crit": "Critical and above",
            "alert": "Alert and above",
        }
        self._ack_shortcut(shortcut_by_level.get(level, "Ctrl+Shift"))
        if self.list_boots_enabled:
            self.set_status("The journal priority acquisition flag is not applicable in Boot List inventory.")
            return
        self.set_priority_query_level(level, persist=True)
        self.set_status(f"Journal priority acquisition: {label_by_level.get(level, level)}.")

    def _date_bounds(self):
        today = date.today()
        if self.date_scope == DATE_SCOPE_TODAY:
            return today, today
        if self.date_scope == DATE_SCOPE_YESTERDAY:
            yesterday = today - timedelta(days=1)
            return yesterday, yesterday
        if self.date_scope == DATE_SCOPE_CUSTOM:
            try:
                start = date.fromisoformat(self.custom_start_date)
                end = date.fromisoformat(self.custom_end_date)
            except ValueError:
                return today, today
            if start > end:
                start, end = end, start
            return start, end
        return None, None

    def _boot_argument(self):
        if self.boot_scope == BOOT_SCOPE_CURRENT:
            return "0"
        if self.boot_scope == BOOT_SCOPE_PREVIOUS:
            return "-1"
        return self.custom_boot_selector

    @staticmethod
    def _valid_custom_boot(value):
        value = str(value or "").strip()
        if re.fullmatch(r"[+-]?\d+", value):
            return True
        compact = value.replace("-", "")
        return bool(re.fullmatch(r"[0-9A-Fa-f]{32}", compact))

    def _prompt_custom_boot(self):
        value, ok = QInputDialog.getText(
            self,
            "Custom boot",
            "Enter an exact journal boot index (for example -3 or -7)\n"
            "or an exact Boot ID copied from Boot History:",
            text=self.custom_boot_selector,
        )
        if not ok:
            return False
        value = str(value or "").strip()
        if not self._valid_custom_boot(value):
            QMessageBox.warning(
                self,
                "Custom boot",
                "Enter an exact journal boot index (for example -3) or a 32-character Boot ID.",
            )
            return False
        self.custom_boot_selector = value
        settings = self._settings()
        settings.setValue("custom_boot_selector", value)
        settings.sync()
        return True

    def _journal_command(self):
        if self.list_boots_enabled:
            return ["journalctl", "--list-boots", "--no-pager", "--quiet"]
        command = ["journalctl"]
        if self.boot_scope_enabled:
            command.extend(["-b", self._boot_argument()])
        command.extend([
            "--output=json",
            "--reverse",
            "--no-pager",
        ])
        if not self.boot_scope_enabled:
            start, end = self._date_bounds()
            if start is not None:
                command.extend(["--since", f"{start.isoformat()} 00:00:00"])
                command.extend(["--until", f"{(end + timedelta(days=1)).isoformat()} 00:00:00"])
        if self.entry_limit != NO_ENTRY_LIMIT:
            command.extend(["-n", str(self.entry_limit)])
        if self.source_transport:
            command.append(f"_TRANSPORT={self.source_transport}")
        if self.priority_query_level:
            command.insert(1, f"--priority={self.priority_query_level}")
        return command

    def _populate_source_scope(self):
        """Populate Source from native journal _TRANSPORT values.

        Keep the documented native transports available even when the current
        bounded result set happens not to contain one of them.  Any additional
        transport actually observed in collected records is added verbatim.
        """
        observed = set()
        for record in self.modules_data:
            raw = record.get("raw", {})
            if isinstance(raw, dict):
                value = _string(raw.get("_TRANSPORT")).strip()
                if value:
                    observed.add(value)

        values = list(JOURNAL_TRANSPORTS)
        for value in sorted(observed, key=str.casefold):
            if value not in values:
                values.append(value)

        self.category_dropdown.blockSignals(True)
        self.category_dropdown.clear()
        self.category_dropdown.addItem(ALL_SOURCES_LABEL, "")
        for value in values:
            self.category_dropdown.addItem(value, value)
        index = self.category_dropdown.findData(self.source_transport)
        self.category_dropdown.setCurrentIndex(index if index >= 0 else 0)
        self.category_dropdown.blockSignals(False)

    def _source_scope_changed(self, _index):
        if self.list_boots_enabled:
            return
        transport = str(self.category_dropdown.currentData() or "")
        if transport == self.source_transport:
            return
        self.source_transport = transport
        settings = self._settings()
        settings.setValue("source_transport", transport)
        settings.sync()
        self._mark_query_dirty()

    def _rebuild_temporal_scope_selector(self):
        self._scope_guard = True
        try:
            self.date_dropdown.clear()
            if self.list_boots_enabled:
                self.date_label.setText("Period:")
                for label in (
                    LIST_BOOTS_PERIOD_ALL,
                    LIST_BOOTS_PERIOD_THIS_MONTH,
                    LIST_BOOTS_PERIOD_LAST_MONTH,
                    LIST_BOOTS_PERIOD_EARLIER,
                ):
                    self.date_dropdown.addItem(label, label)
                index = self.date_dropdown.findData(self.list_boots_period)
            elif self.boot_scope_enabled:
                self.date_label.setText("Boot:")
                self.date_dropdown.addItem("Current boot", BOOT_SCOPE_CURRENT)
                self.date_dropdown.addItem("Previous boot", BOOT_SCOPE_PREVIOUS)
                custom_label = "Custom boot..."
                if self.custom_boot_selector:
                    shown = self.custom_boot_selector
                    if len(shown) > 18:
                        shown = shown[:15] + "..."
                    custom_label = f"Custom boot: {shown}"
                self.date_dropdown.addItem(custom_label, BOOT_SCOPE_CUSTOM)
                index = self.date_dropdown.findData(self.boot_scope)
            else:
                self.date_label.setText("Date:")
                self.date_dropdown.addItem("All dates", DATE_SCOPE_ALL)
                self.date_dropdown.addItem("Today", DATE_SCOPE_TODAY)
                self.date_dropdown.addItem("Yesterday", DATE_SCOPE_YESTERDAY)
                if self.custom_start_date == self.custom_end_date:
                    custom_label = f"Custom: {self.custom_start_date}"
                else:
                    custom_label = f"Custom: {self.custom_start_date} → {self.custom_end_date}"
                self.date_dropdown.addItem(custom_label, DATE_SCOPE_CUSTOM)
                index = self.date_dropdown.findData(self.date_scope)
            self.date_dropdown.setCurrentIndex(index if index >= 0 else 0)
        finally:
            self._scope_guard = False

    def _temporal_scope_changed(self, _index):
        if self._scope_guard:
            return

        if self.list_boots_enabled:
            requested = str(self.date_dropdown.currentData() or LIST_BOOTS_PERIOD_ALL)
            self.set_list_boots_period(requested, persist=True)
            return

        if self.boot_scope_enabled:
            requested = str(self.date_dropdown.currentData() or BOOT_SCOPE_CURRENT)
            previous = self.boot_scope
            if requested == BOOT_SCOPE_CUSTOM:
                if not self._prompt_custom_boot():
                    self._scope_guard = True
                    try:
                        old_index = self.date_dropdown.findData(previous)
                        self.date_dropdown.setCurrentIndex(old_index if old_index >= 0 else 0)
                    finally:
                        self._scope_guard = False
                    return
            self.set_boot_scope(requested, persist=True)
            return

        requested = str(self.date_dropdown.currentData() or DATE_SCOPE_ALL)
        previous = self.date_scope
        if requested == DATE_SCOPE_CUSTOM:
            dialog = CustomDateDialog(self)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                self._scope_guard = True
                try:
                    old_index = self.date_dropdown.findData(previous)
                    self.date_dropdown.setCurrentIndex(old_index if old_index >= 0 else 0)
                finally:
                    self._scope_guard = False
                return
        self.set_date_scope(requested, persist=True)

    def _record_matches_search(self, record, query):
        if not query:
            return True
        if self.list_boots_enabled:
            return any(
                query in str(record.get(key, "")).lower()
                for key in ("index", "boot_id", "first_entry", "last_entry")
            )
        raw = record.get("raw", {})
        for field, value in raw.items():
            if query in str(field).lower() or query in _reported_value(value).lower():
                return True
        return any(
            query in str(record.get(key, "")).lower()
            for key in ("time", "source", "priority", "pid", "message")
        )

    def _reset_details_to_top(self):
        cursor = self.info_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.info_text.setTextCursor(cursor)
        self.info_text.verticalScrollBar().setValue(0)

    def _render_record_details(self, record):
        self.info_text.setPlainText(_record_details_text(record))
        self._reset_details_to_top()

    def _render_boot_details(self, details):
        if not self.metadata_panel_visible:
            return
        self.info_text.setPlainText(_boot_metadata_details_text(details))
        self._reset_details_to_top()

    def _synchronize_details_after_rebuild(self, matches):
        self.clear_info()
        signals_were_blocked = self.table.blockSignals(True)
        try:
            self.table.clearSelection()
            if not matches:
                self.table.setCurrentCell(-1, -1)
            else:
                self.table.setCurrentCell(0, 0)
                self.table.selectRow(0)
        finally:
            self.table.blockSignals(signals_were_blocked)

        if matches:
            self._render_record_details(matches[0])
        self._reset_details_to_top()

    def _synchronize_boot_details_after_rebuild(self, matches):
        self.clear_info()
        blocked = self.boot_table.blockSignals(True)
        try:
            self.boot_table.clearSelection()
            self.boot_table.setCurrentCell(-1, -1)
        finally:
            self.boot_table.blockSignals(blocked)
        self._reset_details_to_top()

    def filter_modules(self, *_):
        if self.list_boots_enabled:
            return self._filter_boot_modules()
        query = self.search_entry.text().strip().lower()
        selected_priority = str(self.priority_dropdown.currentData() or "")

        matches = []
        for record in self.modules_data:
            if selected_priority == NOT_REPORTED_PRIORITY:
                if record.get("priority_value"):
                    continue
            elif selected_priority and record.get("priority_value") != selected_priority:
                continue

            if not self._record_matches_search(record, query):
                continue
            matches.append(record)

        signals_were_blocked = self.table.blockSignals(True)
        try:
            self.clear_info()
            self.table.clearSelection()
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(matches))
            for row, record in enumerate(matches):
                for column_index, (column_id, _label, _width, alignment) in enumerate(self.columns):
                    value = record.get(column_id, "")
                    if column_id == "priority":
                        try:
                            sort_value = int(record.get("priority_value", 99))
                        except (TypeError, ValueError):
                            sort_value = 99
                        item = NumericTableWidgetItem(str(value), sort_value)
                    elif column_id == "pid" and str(value).isdigit():
                        item = NumericTableWidgetItem(str(value), int(value))
                    else:
                        item = QTableWidgetItem(str(value))
                    if column_index == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                    if alignment == "right":
                        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    else:
                        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                    self.style_table_item(item, column_id, record)
                    self.table.setItem(row, column_index, item)
        finally:
            self.table.blockSignals(signals_were_blocked)

        self._synchronize_details_after_rebuild(matches)

        self.export_btn.setEnabled(bool(self.modules_data))
        filtered = bool(query or selected_priority)
        if filtered:
            self.filter_status_lbl.setText(f"(Showing {len(matches)} of {len(self.modules_data)} items)")
        else:
            self.filter_status_lbl.clear()

    def _filter_boot_modules(self):
        query = self.search_entry.text().strip().lower()
        selected_period = str(self.date_dropdown.currentData() or LIST_BOOTS_PERIOD_ALL)
        matches = []
        for record in self.modules_data:
            if selected_period != LIST_BOOTS_PERIOD_ALL and record.get("_period") != selected_period:
                continue
            if not self._record_matches_search(record, query):
                continue
            matches.append(record)

        blocked = self.boot_table.blockSignals(True)
        try:
            self.clear_info()
            self.boot_table.clearSelection()
            self.boot_table.setSortingEnabled(False)
            self.boot_table.setRowCount(len(matches))
            for row, record in enumerate(matches):
                for column_index, (column_id, _label, _width, alignment) in enumerate(self._list_boots_columns):
                    value = record.get(column_id, "")
                    if column_id == "index":
                        item = NumericTableWidgetItem(str(value), int(record.get("_index_number", 0)))
                    else:
                        item = QTableWidgetItem(str(value))
                    if column_index == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                    if alignment == "right":
                        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    else:
                        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                    self.boot_table.setItem(row, column_index, item)
        finally:
            self.boot_table.blockSignals(blocked)

        self._synchronize_boot_details_after_rebuild(matches)
        self.export_btn.setEnabled(bool(self.modules_data))
        filtered = bool(query or selected_period != LIST_BOOTS_PERIOD_ALL)
        if filtered:
            self.filter_status_lbl.setText(f"(Showing {len(matches)} of {len(self.modules_data)} items)")
        else:
            self.filter_status_lbl.clear()

    def _set_sort_indicator(self, column_id, reverse):
        # Normal Journal indicator uses only the immutable r7 normal columns.
        for index, (candidate, _label, _width, _alignment) in enumerate(self.columns):
            if candidate == column_id:
                header = self.table.horizontalHeader()
                header.setSortIndicatorShown(True)
                header.setSortIndicator(
                    index,
                    Qt.SortOrder.DescendingOrder if reverse else Qt.SortOrder.AscendingOrder,
                )
                return

    def sort_by(self, column_id):
        reverse = self._sort_reverse.get(column_id, False)

        if column_id == "priority":
            def key_func(record):
                try:
                    return int(record.get("priority_value", 99))
                except (TypeError, ValueError):
                    return 99
        elif column_id == "pid":
            def key_func(record):
                value = str(record.get("pid", ""))
                return int(value) if value.isdigit() else -1
        else:
            key_func = lambda record: str(record.get(column_id, "")).lower()

        try:
            self.modules_data.sort(key=key_func, reverse=reverse)
        except Exception:
            self.modules_data.sort(key=lambda record: str(record.get(column_id, "")).lower(), reverse=reverse)

        self._sort_reverse[column_id] = not reverse
        self._set_sort_indicator(column_id, reverse)
        self.filter_modules()

    def _sort_boots_by_section(self, section):
        if section < 0 or section >= len(self._list_boots_columns):
            return
        column_id = self._list_boots_columns[section][0]
        reverse = self._boot_sort_reverse.get(column_id, False)
        if column_id == "index":
            key_func = lambda record: int(record.get("_index_number", 0))
        elif column_id == "first_entry":
            key_func = lambda record: float(record.get("_first_sort", float("-inf")))
        elif column_id == "last_entry":
            key_func = lambda record: float(record.get("_last_sort", float("-inf")))
        else:
            key_func = lambda record: str(record.get(column_id, "")).lower()
        self.modules_data.sort(key=key_func, reverse=reverse)
        self._boot_sort_reverse[column_id] = not reverse
        header = self.boot_table.horizontalHeader()
        header.setSortIndicatorShown(True)
        header.setSortIndicator(
            section,
            Qt.SortOrder.DescendingOrder if reverse else Qt.SortOrder.AscendingOrder,
        )
        self._filter_boot_modules()

    def load_modules(self):
        self.modules_data.clear()
        self._boot_detail_cache.clear()
        self._list_boots_acquisition_warning = ""
        self.clear_info()
        self._has_scanned = False
        self._query_dirty = False
        self._update_counter(scanning=True)
        self.set_status("Scanning Boot List..." if self.list_boots_enabled else "Scanning journal records...")
        self.refresh_btn.setText("Scanning...")
        self.refresh_btn.setEnabled(False)
        QApplication.processEvents()
        try:
            try:
                result = subprocess.run(
                    self._journal_command(),
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=(
                        15 if self.list_boots_enabled
                        else 180 if self.entry_limit == NO_ENTRY_LIMIT
                        else 90 if self.entry_limit >= 50000
                        else 60 if self.entry_limit >= 25000
                        else 45 if self.entry_limit >= 10000
                        else 30
                    ),
                    env=_command_environment(),
                )
            except FileNotFoundError:
                result = None

            if result is None:
                self._parse_failures = 0
                status = "Unavailable: journalctl is not available on this system."
            else:
                if self.list_boots_enabled:
                    self.modules_data, self._parse_failures = _parse_list_boots(result.stdout or "")
                else:
                    self.modules_data, self._parse_failures = _parse_journal_json(result.stdout or "")
                stderr = (result.stderr or "").strip().replace("\n", " ")
                if result.returncode != 0 and not self.modules_data:
                    if _permission_text(stderr):
                        status = (
                            "Restricted: current permissions could not read the journal boot index."
                            if self.list_boots_enabled
                            else "Restricted: current permissions could not read the requested journal records."
                        )
                    else:
                        status = f"Unavailable: {stderr or 'journalctl returned an error.'}"
                elif self.list_boots_enabled and result.returncode != 0:
                    diagnostic = stderr or "No diagnostic text was reported."
                    self._list_boots_acquisition_warning = (
                        f"journalctl --list-boots exited with status {result.returncode}: {diagnostic}"
                    )
                    status = (
                        f"Partial: {len(self.modules_data):,} journal boot record(s) parsed; "
                        f"journalctl exited with status {result.returncode}"
                    )
                    if self._parse_failures:
                        status += f"; skipped {self._parse_failures:,} unreadable line(s)"
                    status += f". {diagnostic}"
                elif self._parse_failures:
                    noun = "boot record" if self.list_boots_enabled else "journal record"
                    status = (
                        f"Observed: {len(self.modules_data):,} {noun}(s); "
                        f"skipped {self._parse_failures:,} unreadable line(s)."
                    )
                else:
                    status = (
                        f"Observed: {len(self.modules_data):,} journal boot record(s)."
                        if self.list_boots_enabled
                        else f"Observed: {len(self.modules_data):,} journal record(s)."
                    )

            self._has_scanned = True
            if not self.list_boots_enabled:
                self._populate_source_scope()
            if not self.lazy_metadata_enabled:
                if self.list_boots_enabled:
                    self._prefetch_boot_details()
                else:
                    for record in self.modules_data:
                        record["_preformatted_metadata_details"] = _build_record_details_text(record)
            self.filter_modules()
            self._update_counter()
            self.set_status(status)
        except subprocess.TimeoutExpired:
            self.modules_data = []
            self._has_scanned = True
            self.filter_modules()
            self._update_counter()
            self.set_status("Unavailable: Boot List scan timed out." if self.list_boots_enabled else "Unavailable: journal scan timed out.")
        except Exception as exc:
            self.modules_data = []
            self._has_scanned = True
            self.filter_modules()
            self._update_counter()
            self.set_status(f"Unavailable: {exc}")
        finally:
            self._apply_scan_mode()

    def _collect_boot_details(self, record):
        index = str(record.get("index", "0"))
        identity = {
            "boot_index": index,
            "boot_id": str(record.get("boot_id", "") or "Not reported"),
            "boot_list_acquisition_warning": self._list_boots_acquisition_warning,
        }
        try:
            result = subprocess.run(
                ["journalctl", "-b", index, "--no-pager", "--quiet", "-o", "json"],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
                env=_command_environment(),
            )
        except FileNotFoundError:
            return {**identity, "state": "unavailable", "message": "journalctl is not installed."}
        except subprocess.TimeoutExpired:
            return {**identity, "state": "unavailable", "message": "Journal record inspection timed out."}
        except Exception as exc:
            return {**identity, "state": "error", "message": str(exc)}

        if result.returncode != 0:
            message = (result.stderr or result.stdout or "").strip()
            if _permission_text(message):
                return {**identity, "state": "restricted", "message": message or "Journal access is restricted."}
            return {**identity, "state": "error", "message": message or f"journalctl exited with status {result.returncode}."}

        entries = []
        malformed_json_lines = 0
        for line in (result.stdout or "").splitlines():
            try:
                obj = json.loads(line)
            except Exception:
                malformed_json_lines += 1
                continue
            if isinstance(obj, dict):
                entries.append(obj)

        if not entries:
            return {
                **identity,
                "state": "observed",
                "entries": 0,
                "malformed_json_lines": malformed_json_lines,
            }

        first_obj = entries[0]
        last_obj = entries[-1]
        first_text, first_dt = _format_boot_metadata_timestamp(_json_scalar(first_obj.get("__REALTIME_TIMESTAMP")))
        last_text, last_dt = _format_boot_metadata_timestamp(_json_scalar(last_obj.get("__REALTIME_TIMESTAMP")))
        duration = last_dt - first_dt if first_dt is not None and last_dt is not None else None

        priority_counts = Counter()
        hostname = ""
        machine_id = ""
        kernel_release = ""
        for obj in entries:
            priority = _json_scalar(obj.get("PRIORITY"))
            if priority:
                priority_counts[priority] += 1
            if not hostname:
                hostname = _json_scalar(obj.get("_HOSTNAME"))
            if not machine_id:
                machine_id = _json_scalar(obj.get("_MACHINE_ID"))
            if not kernel_release:
                kernel_release = _json_scalar(obj.get("_KERNEL_RELEASE"))

        priority_text = ", ".join(
            f"{number} - {PRIORITY_LABELS.get(number, 'Unknown')}: {priority_counts[number]}"
            for number in sorted(priority_counts, key=lambda value: int(value) if value.isdigit() else 99)
        ) or "None reported"

        return {
            **identity,
            "state": "observed",
            "entries": len(entries),
            "malformed_json_lines": malformed_json_lines,
            "first_timestamp": first_text,
            "last_timestamp": last_text,
            "duration": _format_duration(duration),
            "hostname": hostname or "Not reported",
            "machine_id": machine_id or "Not reported",
            "kernel_release": kernel_release or "Not reported",
            "priority_counts": priority_text,
            "first_record": _boot_record_summary(first_obj),
            "last_record": _boot_record_summary(last_obj),
        }

    def _prefetch_boot_details(self):
        total = len(self.modules_data)
        for position, record in enumerate(self.modules_data, start=1):
            boot_id = record.get("boot_id")
            if boot_id in self._boot_detail_cache:
                continue
            self.set_status(f"Collecting boot metadata {position:,} of {total:,}...")
            QApplication.processEvents()
            self._boot_detail_cache[boot_id] = self._collect_boot_details(record)

    def on_module_select(self):
        record = self.current_record()
        if not record:
            self.clear_info()
            return
        self._render_record_details(record)
        self.set_status(
            f"Inspecting journal entry from [{record.get('source', 'Unknown Source')}] "
            f"at priority {record.get('priority', 'Not reported')}."
        )

    def _boot_current_record(self):
        row = self.boot_table.currentRow()
        if row < 0:
            return None
        item = self.boot_table.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def _on_boot_select(self):
        if not self.list_boots_enabled:
            return
        record = self._boot_current_record()
        if not record:
            self.clear_info()
            return
        if not self.metadata_panel_visible:
            return
        boot_id = record.get("boot_id")
        details = self._boot_detail_cache.get(boot_id)
        if details is None:
            self.info_text.setPlainText("Inspecting selected boot journal records...")
            self.set_status(f"Inspecting journal records for boot {record.get('index', '')}...")
            QApplication.processEvents()
            details = self._collect_boot_details(record)
            self._boot_detail_cache[boot_id] = details
        self._render_boot_details(details)
        if details.get("state") == "observed":
            malformed = int(details.get("malformed_json_lines", 0) or 0)
            status = f"Showing journal-visible metadata for boot {record.get('index', '')}."
            if malformed:
                status += f" Skipped {malformed:,} malformed JSON line(s)."
            if self._list_boots_acquisition_warning:
                status += " Boot list acquisition was partial."
            self.set_status(status)
        else:
            status = f"Could not inspect journal-visible metadata for boot {record.get('index', '')}."
            if self._list_boots_acquisition_warning:
                status += " Boot list acquisition was partial."
            self.set_status(status)

    def get_export_records(self):
        if self.list_boots_enabled:
            return [
                {
                    "index": record.get("index", ""),
                    "boot_id": record.get("boot_id", ""),
                    "first_entry": record.get("first_entry", ""),
                    "last_entry": record.get("last_entry", ""),
                }
                for record in self.modules_data
            ]
        return [
            {
                "time": record.get("time", ""),
                "source": record.get("source", ""),
                "priority": record.get("priority", ""),
                "pid": record.get("pid", ""),
                "message": record.get("message", ""),
            }
            for record in self.modules_data
        ]

    def show_options(self):
        self._configuration_open = True
        try:
            JournalOptionsDialog(self).exec()
        finally:
            self._configuration_open = False
            if self.automatic_scan_enabled and self._query_dirty:
                self._schedule_auto_scan()

    def _settings(self):
        return QSettings("brunonlinespace", "Journal Inspector")

    def _load_preferences(self):
        settings = self._settings()
        orientation = str(settings.value("details_orientation", "horizontal") or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"

        raw_limit = settings.value("entry_limit", DEFAULT_ENTRY_LIMIT)
        raw_limit_text = str(raw_limit).strip().lower()
        if raw_limit_text == "no-limit":
            limit = NO_ENTRY_LIMIT
        elif raw_limit_text in {"all", "none", "0", ""}:
            # Old experimental unbounded values are not silently revived.
            limit = MAX_ENTRY_LIMIT
        else:
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError):
                limit = DEFAULT_ENTRY_LIMIT
            if limit not in ENTRY_LIMITS:
                limit = DEFAULT_ENTRY_LIMIT

        if settings.contains("priority_query_level"):
            priority_query_level = str(
                settings.value("priority_query_level", "") or ""
            ).strip().lower()
            if priority_query_level not in PRIORITY_QUERY_LEVELS:
                priority_query_level = PRIORITY_QUERY_NONE
        else:
            # Migrate the previous single Errors-only preference.
            errors_value = settings.value("errors_only", False)
            if isinstance(errors_value, str):
                old_errors_only = errors_value.strip().lower() in {"1", "true", "yes", "on"}
            else:
                old_errors_only = bool(errors_value)
            priority_query_level = "err" if old_errors_only else PRIORITY_QUERY_NONE

        boot_scope_value = settings.value("boot_scope_enabled", False)
        if isinstance(boot_scope_value, str):
            boot_scope_enabled = boot_scope_value.strip().lower() in {"1", "true", "yes", "on"}
        else:
            boot_scope_enabled = bool(boot_scope_value)

        boot_scope = str(settings.value("boot_scope", BOOT_SCOPE_CURRENT) or BOOT_SCOPE_CURRENT).lower()
        if boot_scope not in {BOOT_SCOPE_CURRENT, BOOT_SCOPE_PREVIOUS, BOOT_SCOPE_CUSTOM}:
            boot_scope = BOOT_SCOPE_CURRENT

        custom_boot_selector = str(settings.value("custom_boot_selector", "") or "").strip()
        if custom_boot_selector and not self._valid_custom_boot(custom_boot_selector):
            custom_boot_selector = ""

        if settings.contains("automatic_scan_enabled"):
            automatic_scan_value = settings.value("automatic_scan_enabled", False)
            if isinstance(automatic_scan_value, str):
                automatic_scan_enabled = automatic_scan_value.strip().lower() in {"1", "true", "yes", "on"}
            else:
                automatic_scan_enabled = bool(automatic_scan_value)
        elif settings.contains("scan_button_enabled"):
            # r5's wording was backwards relative to the intended behaviour.
            # Migrate an unchecked old "Enable top-level Scan button" as the
            # user's intended automatic-scan choice.
            old_scan_button_value = settings.value("scan_button_enabled", True)
            if isinstance(old_scan_button_value, str):
                old_scan_button_enabled = old_scan_button_value.strip().lower() not in {"0", "false", "no", "off"}
            else:
                old_scan_button_enabled = bool(old_scan_button_value)
            automatic_scan_enabled = not old_scan_button_enabled
        else:
            automatic_scan_enabled = False

        list_boots_value = settings.value("list_boots_enabled", False)
        if isinstance(list_boots_value, str):
            list_boots_enabled = list_boots_value.strip().lower() in {"1", "true", "yes", "on"}
        else:
            list_boots_enabled = bool(list_boots_value)

        metadata_panel_value = settings.value("metadata_panel_visible", True)
        if isinstance(metadata_panel_value, str):
            metadata_panel_visible = metadata_panel_value.strip().lower() not in {"0", "false", "no", "off"}
        else:
            metadata_panel_visible = bool(metadata_panel_value)

        lazy_value = settings.value("lazy_metadata_enabled", True)
        if isinstance(lazy_value, str):
            lazy_metadata_enabled = lazy_value.strip().lower() not in {"0", "false", "no", "off"}
        else:
            lazy_metadata_enabled = bool(lazy_value)

        list_boots_period = str(settings.value("list_boots_period", LIST_BOOTS_PERIOD_ALL) or LIST_BOOTS_PERIOD_ALL)
        if list_boots_period not in {LIST_BOOTS_PERIOD_ALL, LIST_BOOTS_PERIOD_THIS_MONTH, LIST_BOOTS_PERIOD_LAST_MONTH, LIST_BOOTS_PERIOD_EARLIER}:
            list_boots_period = LIST_BOOTS_PERIOD_ALL

        scope = str(settings.value("date_scope", DATE_SCOPE_ALL) or DATE_SCOPE_ALL).lower()
        if scope not in {DATE_SCOPE_ALL, DATE_SCOPE_TODAY, DATE_SCOPE_YESTERDAY, DATE_SCOPE_CUSTOM}:
            scope = DATE_SCOPE_ALL

        today_text = date.today().isoformat()
        custom_start = str(settings.value("custom_start_date", today_text) or today_text)
        custom_end = str(settings.value("custom_end_date", today_text) or today_text)
        try:
            date.fromisoformat(custom_start)
        except ValueError:
            custom_start = today_text
        try:
            date.fromisoformat(custom_end)
        except ValueError:
            custom_end = custom_start

        source_transport = str(settings.value("source_transport", "") or "").strip()
        if source_transport and source_transport not in JOURNAL_TRANSPORTS:
            # Preserve only a syntactically safe raw journal value if it came
            # from a future/extra transport observed by a prior build.
            if not source_transport.replace("_", "").replace("-", "").isalnum():
                source_transport = ""

        self.entry_limit = limit
        self.list_boots_enabled = list_boots_enabled
        self.list_boots_period = list_boots_period
        self.metadata_panel_visible = metadata_panel_visible
        self.lazy_metadata_enabled = lazy_metadata_enabled
        self.priority_query_level = priority_query_level
        self.boot_scope_enabled = boot_scope_enabled
        self.boot_scope = boot_scope
        self.custom_boot_selector = custom_boot_selector
        self.automatic_scan_enabled = automatic_scan_enabled
        self.source_transport = source_transport
        self.date_scope = scope
        self.custom_start_date = custom_start
        self.custom_end_date = custom_end
        self.set_details_orientation(orientation, persist=False)

    def _update_counter(self, *, scanning=False):
        if self.list_boots_enabled:
            if scanning:
                self.stats_label.setText("Journal Boots: Scanning...")
            elif not self._has_scanned:
                self.stats_label.setText("Journal Boots: Not scanned")
            else:
                self.stats_label.setText(f"Journal Boots: {len(self.modules_data):,}")
            return
        if scanning:
            self.stats_label.setText("Journal Entries: Scanning...")
        elif not self._has_scanned:
            self.stats_label.setText("Journal Entries: Not scanned")
        else:
            suffix_parts = []
            if self.source_transport:
                suffix_parts.append(f"Source: {self.source_transport}")
            if self.boot_scope_enabled:
                if self.boot_scope == BOOT_SCOPE_CURRENT:
                    suffix_parts.append("Boot: Current")
                elif self.boot_scope == BOOT_SCOPE_PREVIOUS:
                    suffix_parts.append("Boot: Previous")
                else:
                    shown = self.custom_boot_selector or "Custom"
                    suffix_parts.append(f"Boot: {shown}")
            suffix = (" — " + " · ".join(suffix_parts)) if suffix_parts else ""
            self.stats_label.setText(f"Journal Entries: {len(self.modules_data):,}{suffix}")

    def _schedule_auto_scan(self, delay_ms=None):
        if not self.automatic_scan_enabled:
            return
        if self._configuration_open:
            self.set_status("Automatic scan will run when Configuration closes.")
            return
        if delay_ms is None:
            delay_ms = 250
        self._auto_scan_timer.start(max(0, int(delay_ms)))

    def _apply_scan_mode(self):
        manual = not self.automatic_scan_enabled
        self.refresh_btn.setVisible(manual)
        self.refresh_btn.setEnabled(manual)
        if manual:
            self.refresh_btn.setText("Scan Again" if self._has_scanned else "Scan")

    def _mark_query_dirty(self):
        self._query_dirty = True
        if self.automatic_scan_enabled:
            if self._configuration_open:
                self.set_status("Scan scope/options changed. Automatic scan will run when Configuration closes.")
            else:
                self.set_status("Scan scope/options changed. Refreshing automatically...")
                self._schedule_auto_scan()
        elif self._has_scanned:
            self.set_status(
                "Boot List/options changed. Press Scan Again to apply them."
                if self.list_boots_enabled
                else "Scan scope/options changed. Press Scan Again to apply them to the journal inventory."
            )
        else:
            self.set_status(
                "Boot List/options saved. Press Scan to collect journal boot history."
                if self.list_boots_enabled
                else "Scan scope/options saved. Press Scan to collect journal records."
            )

    def _apply_inventory_mode(self):
        # Never mutate self.table/self.columns here. Those remain the exact
        # normal Journal inventory created by BaseInspectorTab (r7 behavior).
        self.inventory_stack.setCurrentWidget(
            self.boot_table if self.list_boots_enabled else self.table
        )
        self.category_label.setVisible(not self.list_boots_enabled)
        self.category_dropdown.setVisible(not self.list_boots_enabled)
        self.priority_label.setVisible(not self.list_boots_enabled)
        self.priority_dropdown.setVisible(not self.list_boots_enabled)
        self.search_entry.setPlaceholderText(
            "Search boot index, ID or reported times..."
            if self.list_boots_enabled
            else "Search all journal fields..."
        )
        self._rebuild_temporal_scope_selector()
        self.modules_data.clear()
        self._boot_detail_cache.clear()
        self.table.setRowCount(0)
        self.boot_table.setRowCount(0)
        self.clear_info()
        self._has_scanned = False
        self._update_counter()

    def set_list_boots_enabled(self, enabled, *, persist=True):
        enabled = bool(enabled)
        if self.list_boots_enabled == enabled:
            return
        self.list_boots_enabled = enabled
        if persist:
            settings = self._settings()
            settings.setValue("list_boots_enabled", enabled)
            settings.sync()
        self._apply_inventory_mode()
        self._mark_query_dirty()

    def set_list_boots_period(self, period, *, persist=True):
        period = str(period or LIST_BOOTS_PERIOD_ALL)
        if period not in {LIST_BOOTS_PERIOD_ALL, LIST_BOOTS_PERIOD_THIS_MONTH, LIST_BOOTS_PERIOD_LAST_MONTH, LIST_BOOTS_PERIOD_EARLIER}:
            period = LIST_BOOTS_PERIOD_ALL
        self.list_boots_period = period
        if persist:
            settings = self._settings()
            settings.setValue("list_boots_period", period)
            settings.sync()
        # Period is a local filter; it never re-runs journalctl.
        self.filter_modules()

    def set_metadata_panel_visible(self, visible, *, persist=True):
        visible = bool(visible)
        self.metadata_panel_visible = visible
        panel = self.splitter.widget(1)
        if panel is not None:
            panel.setVisible(visible)
        if visible:
            self.set_details_orientation(self.details_orientation, persist=False)
            if self.list_boots_enabled and self._boot_current_record() is not None:
                self._on_boot_select()
        if persist:
            settings = self._settings()
            settings.setValue("metadata_panel_visible", visible)
            settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def set_lazy_metadata_enabled(self, enabled, *, persist=True):
        enabled = bool(enabled)
        if self.lazy_metadata_enabled == enabled:
            return
        self.lazy_metadata_enabled = enabled
        if persist:
            settings = self._settings()
            settings.setValue("lazy_metadata_enabled", enabled)
            settings.sync()
        if self._has_scanned:
            if not enabled:
                if self.list_boots_enabled:
                    self._prefetch_boot_details()
                else:
                    for record in self.modules_data:
                        record["_preformatted_metadata_details"] = _build_record_details_text(record)
            else:
                for record in self.modules_data:
                    record.pop("_preformatted_metadata_details", None)
        self.set_status(
            "Lazy Metadata Details enabled."
            if enabled
            else "Lazy Metadata Details disabled; details are prepared eagerly."
        )

    def set_entry_limit(self, limit, *, persist=True):
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = DEFAULT_ENTRY_LIMIT
        if limit != NO_ENTRY_LIMIT and limit not in ENTRY_LIMITS:
            limit = DEFAULT_ENTRY_LIMIT
        if self.entry_limit == limit:
            return
        self.entry_limit = limit
        if persist:
            settings = self._settings()
            settings.setValue("entry_limit", "no-limit" if limit == NO_ENTRY_LIMIT else limit)
            settings.sync()
        self._mark_query_dirty()

    def set_boot_scope_enabled(self, enabled, *, persist=True):
        enabled = bool(enabled)
        changed = self.boot_scope_enabled != enabled
        self.boot_scope_enabled = enabled
        self._rebuild_temporal_scope_selector()
        if persist:
            settings = self._settings()
            settings.setValue("boot_scope_enabled", enabled)
            settings.sync()
        if changed:
            self._mark_query_dirty()

    def set_boot_scope(self, scope, *, persist=True):
        scope = str(scope or BOOT_SCOPE_CURRENT).lower()
        if scope not in {BOOT_SCOPE_CURRENT, BOOT_SCOPE_PREVIOUS, BOOT_SCOPE_CUSTOM}:
            scope = BOOT_SCOPE_CURRENT
        changed = self.boot_scope != scope
        self.boot_scope = scope
        self._rebuild_temporal_scope_selector()
        if persist:
            settings = self._settings()
            settings.setValue("boot_scope", scope)
            if self.custom_boot_selector:
                settings.setValue("custom_boot_selector", self.custom_boot_selector)
            settings.sync()
        if changed or scope == BOOT_SCOPE_CUSTOM:
            self._mark_query_dirty()

    def set_automatic_scan_enabled(self, enabled, *, persist=True):
        enabled = bool(enabled)
        changed = self.automatic_scan_enabled != enabled
        self.automatic_scan_enabled = enabled
        if persist:
            settings = self._settings()
            settings.setValue("automatic_scan_enabled", enabled)
            # Retire the r5 inverse-control preference after migration.
            settings.remove("scan_button_enabled")
            settings.sync()

        self._apply_scan_mode()

        if enabled:
            if changed:
                self._query_dirty = True
            if self._configuration_open:
                self.set_status("Automatic scan enabled. It will run when Configuration closes.")
            else:
                self.set_status("Automatic scan enabled. Refreshing journal records...")
                self._schedule_auto_scan(delay_ms=0)
        else:
            self._auto_scan_timer.stop()
            if self._has_scanned:
                self.set_status("Automatic scan disabled. Use Scan Again to refresh the journal inventory.")
            else:
                self.set_status("Automatic scan disabled. Use Scan to collect journal records.")

    def set_date_scope(self, scope, *, persist=True):
        scope = str(scope or DATE_SCOPE_ALL).lower()
        if scope not in {DATE_SCOPE_ALL, DATE_SCOPE_TODAY, DATE_SCOPE_YESTERDAY, DATE_SCOPE_CUSTOM}:
            scope = DATE_SCOPE_ALL
        changed = self.date_scope != scope
        self.date_scope = scope
        self._rebuild_temporal_scope_selector()
        if persist:
            settings = self._settings()
            settings.setValue("date_scope", scope)
            settings.sync()
        if changed:
            self._mark_query_dirty()

    def set_custom_date_range(self, start_text, end_text, *, persist=True):
        start = date.fromisoformat(str(start_text))
        end = date.fromisoformat(str(end_text))
        if start > end:
            start, end = end, start
        new_start = start.isoformat()
        new_end = end.isoformat()
        changed = (self.custom_start_date, self.custom_end_date) != (new_start, new_end)
        self.custom_start_date = new_start
        self.custom_end_date = new_end
        self.date_scope = DATE_SCOPE_CUSTOM
        self._rebuild_temporal_scope_selector()
        if persist:
            settings = self._settings()
            settings.setValue("custom_start_date", new_start)
            settings.setValue("custom_end_date", new_end)
            settings.setValue("date_scope", DATE_SCOPE_CUSTOM)
            settings.sync()
        if changed or self.date_scope == DATE_SCOPE_CUSTOM:
            self._mark_query_dirty()

    def set_priority_query_level(self, level, *, persist=True):
        level = str(level or "").strip().lower()
        if level not in PRIORITY_QUERY_LEVELS:
            level = PRIORITY_QUERY_NONE
        if self.priority_query_level == level:
            return
        self.priority_query_level = level
        if persist:
            settings = self._settings()
            settings.setValue("priority_query_level", level)
            settings.remove("errors_only")
            settings.sync()
        self._mark_query_dirty()

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation
        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None
        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None:
                details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None:
                details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([480, 700])
        if persist:
            settings = self._settings()
            settings.setValue("details_orientation", orientation)
            settings.sync()


def create_applet(parent=None):
    return JournalInspectorTab(parent=parent)


def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET

    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_AUTHOR)
    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)

    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    window.resize(1280, 780)
    window.setCentralWidget(create_applet())
    window.show()
    return app.exec()
