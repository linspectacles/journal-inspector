<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/journal-inspector.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/journal-inspector.png"
      alt="Journal Inspector screenshot"
      width="900"
    >
  </a>
</p>

# Journal Inspector

**Expose. Explore. Explain.**

Journal Inspector is a read-only structured systemd-journal inspector with separate Journal Entries and Boot List inventories, explicit acquisition controls and full reported metadata retention.

Current release: **1.0.0**

Repository: <https://github.com/linspectacles/journal-inspector>

## What Journal Inspector is

Journal Inspector answers a focused question: **what journal records or recorded boots are visible to the current user, and what did `journalctl` actually report?**

It keeps acquisition and interpretation close to the Linux interfaces actually used by the applet. When a source is unavailable, restricted, or does not report a field, the README does not imply that the applet can manufacture the missing information.

## Highlights

- **Journal Entries** inventory from JSON output, retaining every returned field rather than a fixed subset.
- **Boot List** inventory from `journalctl --list-boots --no-pager --quiet` with a separate table and selected-boot summary.
- Boot/date scope, native `_TRANSPORT` source scope, local priority filtering and optional journal priority acquisition thresholds.
- Configurable bounded entry limits plus an explicit warning before accepting **No limit**.
- Lazy or eager Metadata Details behaviour.
- Malformed JSON lines are counted rather than silently disappearing.
- Boot-list acquisition can retain usable rows while reporting a **Partial** result when `journalctl` also returns an error status.
- **Disk Usage** view from `journalctl --disk-usage` with explicit refresh.

## Data sources and acquisition

- `journalctl ... --output=json --reverse --no-pager` for Journal Entries.
- `journalctl --list-boots --no-pager --quiet` for the Boot List.
- `journalctl -b <index> --no-pager --quiet -o json` for selected-boot summaries.
- `journalctl --disk-usage` for the Disk Usage view.

The applet uses those sources according to the acquisition paths implemented in this release. Optional tools or privileged helpers only affect the views/actions that explicitly use them; they are not treated as silent substitutes for unrelated sources.

## Interface

Journal Inspector follows the LinSpectacles inventory + **Metadata Details** pattern where applicable: an acquired inventory remains separate from the details for the selected record, and search/filter controls operate on the data the applet has actually collected.

The applet's **Options** surface provides the presentation/source/about controls implemented by this release, together with export controls where present in the source. Applet-specific actions remain explicit rather than being folded into background collection.

## Read-only and scope boundaries

Journal Inspector accesses the journal only through `journalctl`; it does not open or modify journal files directly. Results are limited by the current user's journal access. Filtering and acquisition scopes are kept distinct so local presentation filters are not presented as new scans.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| Show / hide Metadata Details | `F3` |
| Repeat current scan | `Shift+F5` |
| Toggle automatic scan | `Ctrl+Shift+F5` |
| Toggle Boot List | `Ctrl+Shift+B` |
| Toggle normal boot scope | `Ctrl+B` |
| Options | `Ctrl+/` |

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are:

- Python 3.
- PyQt6 for the graphical interface.

Create a local virtual environment if you do not already have the required Python packages in the environment you want to use:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_journal_inspector/standalone.py
```

Linux commands, procfs/sysfs interfaces, system services, or optional helpers mentioned in **Data sources and acquisition** are applet-specific runtime inputs. A missing optional source is handled by the applet's existing availability/error path; it is not replaced here with an invented dependency or capability.

No RPM installation instructions are included in this README.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_journal_inspector/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── journal_inspector/
    ├── applet.py
    ├── _support.py
    ├── icon.png
    └── README.md
```

`applet.json` supplies the LinSpectacles applet identity and entrypoint metadata. `standalone.py` launches the applet directly, while the package's applet factory provides the host-loadable LinSpectacles integration used by the source.

## Configuration

Presentation and inspection preferences are persisted only through the settings mechanisms already implemented by the applet. Persisted UI state does not grant the applet permission to modify the inspected Linux subsystem.

## Scope

Journal Inspector is intentionally specialist. Related Linux information that belongs to another LinSpectacles subsystem remains outside this applet rather than being inferred or duplicated here.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- Repository: <https://github.com/linspectacles/journal-inspector>
- Issues: <https://github.com/linspectacles/journal-inspector/issues>

<p align="center">
  <a href="https://github.com/linspectacles/journal-inspector">
    <img
      src="journal_inspector/icon.png"
      alt="Journal Inspector"
      width="256"
    >
  </a>
</p>
