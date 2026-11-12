# Journal Inspector 0.0.6

Read-only LinSpectacles applet for structured systemd journal inspection.

## 0.0.5 identity rebrand

Renamed from the `0.0.4-r2` Journal Inspector baseline to the official LinSpectacles applet ID and Python package. The official green-spectacles logo, About branding, titlebar, repository and export heading have been updated. All acquisition, view, filter, metadata, export schema, settings and shortcut behavior is unchanged.


## 0.0.4 hardening

This release deliberately preserves the accepted r6 normal Journal selection
and Metadata Details architecture.

### Boot-list acquisition integrity

The backend remains exactly:

`journalctl --list-boots --no-pager --quiet`

If journalctl returns parsable boot rows **and** exits non-zero, Journal
Inspector now keeps the usable rows but labels the acquisition **Partial**.
The exit status and diagnostic are retained in the status line and carried into
selected-boot Metadata Details / exported Boot Metadata Details. Such output is
no longer silently presented as a clean `Observed` scan.

### Selected-boot JSON integrity

The selected-boot command remains exactly:

`journalctl -b <index> --no-pager --quiet -o json`

Malformed JSON lines are now counted rather than silently disappearing.
Metadata Details exposes:

`Malformed JSON Lines Skipped: N`

Successfully parsed dictionary records continue to drive the same timestamp,
duration, host, machine, kernel, priority-count, and first/last-summary logic.

### Suite-safe scan shortcuts

- `Shift+F5` — repeat the current Journal / List Boots scan
- `Ctrl+Shift+F5` — toggle automatic scan on/off
- plain `F5` — intentionally unbound by Journal Inspector so the Suite may keep
  its Dashboard shortcut

All existing shortcut status acknowledgements remain.
## Added

- Metadata Details panel visibility option; `F3` toggles it without changing acquisition.
- Lazy Metadata Details option.
  - On: selected-row details only; List Boots boot summaries are cached on selection.
  - Off: normal details are preformatted and List Boots summaries are eagerly queried for every listed boot after scan.
- List Boots mode using exactly `journalctl --list-boots --no-pager --quiet`.

### List Boots inventory

`Index | Boot ID | First Entry | Last Entry`

Date becomes Period:

`All | This Month | Last Month | Earlier`

Period classification uses the first date in the range reported by `--list-boots`, matching the current Boot History applet. Source and Priority controls are hidden in this mode; normal Source/Date/Priority settings are preserved for return to normal journal mode.

### List Boots Metadata Details

For the selected boot, Journal Inspector runs `journalctl -b <index> --no-pager --quiet -o json` and derives only from records visible to the current user:

- First visible journal timestamp
- Last visible journal timestamp
- Recorded duration derived from those timestamps
- Hostname, Machine ID, Kernel Release when reported
- Visible journal entry count
- Counts by reported priority
- First visible record summary
- Last visible record summary

The boot summary algorithm follows the current Boot History `0.0.1-exp1-r4` experience while remaining a mode inside Journal Inspector.

## exp2-r1

### List Boots
Backend remains exactly:

`journalctl --list-boots --no-pager --quiet`

FIRST ENTRY and LAST ENTRY are now parsed by recognizing the two reported
timestamps instead of depending on one separator glyph. Current/latest boot is
shown first by default: `0, -1, -2, ...`.

### Journal priority flag
Configuration now offers:
- Off
- Warning and above (`--priority=warning`)
- Error and above (`--priority=err`)
- Critical and above (`--priority=crit`)
- Alert and above (`--priority=alert`)

A saved old Errors-only preference migrates to Error.

### Disk Usage
A new Disk Usage tab immediately follows Configuration. It runs:

`journalctl --disk-usage`

on first tab selection and has an explicit Refresh button.

Its canvas copies Boot Timing Advanced:
- background `#151719`
- values `#dcdcdc`
- border `#333333`
- bold keys/headings `#9cdcfe`

## exp2-r2 shortcuts and presentation

List Boots Metadata Details now begins with `Boot Index:` and `Boot ID:`.

Applet-local shortcuts:
- F3 — show/hide Metadata Details
- Ctrl+Shift+B — toggle List Boots
- Ctrl+B — add/remove normal Boot scope (-b), where applicable
- Ctrl+H — Horizontal Metadata Details
- Ctrl+V — Vertical Metadata Details
- F5 — repeat the current scan
- Ctrl+Shift+F5 — toggle automatic scan

Exact local priority inspection:
Ctrl+0..7 = priorities 0..7; Ctrl+A = All; Ctrl+Shift+A = Not reported.

Acquisition thresholds:
Ctrl+Shift+4 = Warning and above
Ctrl+Shift+3 = Error and above
Ctrl+Shift+2 = Critical and above
Ctrl+Shift+1 = Alert and above

Shortcut actions are acknowledged in the existing status line.

Export now appears before Sources. Sources now uses the same palette as Disk
Usage / Boot Timing Advanced: #151719 canvas, #dcdcdc values, #333333 border,
and bold #9cdcfe headings/keys.

## exp2-r3 shortcut/order correction

- `Ctrl+Shift+0` clears the journal acquisition threshold back to Off / all priorities.
- `Shift+F5` toggles automatic scan on/off.
- The previous `Ctrl+Shift+F5` binding is removed.
- `Ctrl+/` opens `Options...`.
- Options tab order places `Sources` before `Export` again.

All shortcut actions continue to acknowledge themselves in the existing status line.

## exp2-r5 r7 normal-table restoration

This revision discards the r4 signal workaround and fixes the exp2 regression at its architectural boundary.

The normal Journal inventory is once again the original BaseInspectorTab QTableWidget created with the r7 columns. It is never recolumned or repurposed by List Boots. Its original `itemSelectionChanged -> on_module_select`, `current_record()`, row population, first-row synchronization, and normal sorting path remain intact.

List Boots now owns a second independent QTableWidget (`boot_table`) in a QStackedWidget occupying the same left inventory area. Mode switching only changes which table is visible. The boot table owns its own selection, sorting, and lazy boot metadata.

This explicitly removes exp2's former `self.table.setColumnCount(...)` / `self.columns = ...` mode mutation, which was the major structural difference from the known-good exp1-r7 selection path.

## exp2-r6 — restore exp1-r7 normal Metadata Details behavior

The user confirmed normal Journal row-selection Metadata Details worked in
exp1-r7 and broke starting with exp2.

r6 therefore restores the normal selection/render path from exp1-r7 rather
than adding another signal workaround:

- `journal_inspector/_support.py` is byte-for-byte exp1-r7 again;
- BaseInspectorTab again owns `table.itemSelectionChanged -> on_module_select`;
- normal `on_module_select()` is the exp1-r7 method;
- normal `_render_record_details()` is the exp1-r7 method;
- normal `_synchronize_details_after_rebuild()` is the exp1-r7 method;
- the normal filter/sort path is restored from exp1-r7;
- there is no exp2 normal metadata cache or current-cell workaround.

Lazy Metadata Details now stays outside this selection path. In eager mode,
normal records receive a preformatted hidden detail string at scan time;
the normal r7 formatter entry point transparently uses it. Switching Lazy back
on removes those prepared strings.

The separate List Boots table and all later exp2 features remain.

## 0.0.4-r1 shortcut correction

Corrects the intended automatic-scan shortcut:

- `Shift+F5` — repeat the current scan
- `Ctrl+Shift+F5` — toggle automatic scan on/off
- plain `F5` remains intentionally unbound by Journal Inspector so the Suite can keep Dashboard

No acquisition, parsing, metadata, selection, filtering, sorting, export, or List Boots behavior changed.
