# DICOM Anonymizer Pro

A desktop tool for batch anonymization of DICOM files. Strips patient-identifying data, remaps UIDs, and shifts dates — while preserving imaging data and clinically relevant attributes.

## Features

- Removes all patient identifiers (name, ID, address, etc.)
- Preserves `PatientSex` and `PatientAge`
- Shifts dates by a random per-patient offset (±10 years)
- Remaps all UIDs consistently within a study
- Removes private tags
- Detects burned-in annotations and warns
- Simple GUI — no command line required

## Requirements

- Windows 10/11 (64-bit)
- No Python installation needed — runs as a standalone `.exe`

## Installation

Download `DICOM-Anonymizer.exe` from the [Releases](../../releases) page and run it directly. No installation required.

## Usage

1. Launch `DICOM-Anonymizer.exe`
2. **Input folder** — select the folder containing original DICOM files (subfolders are scanned recursively)
3. **Output folder** — select where anonymized files will be saved (folder structure is preserved)
4. **Prefix** — optional prefix for generated patient IDs (default: `ANON`)
5. Click **Start**

Output patient IDs follow the format `PREFIX_XXXXXXXX` where `XXXXXXXX` is a SHA-256 derived hash of the original patient ID. The same original ID always maps to the same anonymized ID within a session.

## What gets anonymized

| Tag | Action |
|-----|--------|
| Patient name | Replaced with anonymized ID |
| Patient ID | Replaced with anonymized ID |
| All other `(0010,xxxx)` tags | Removed |
| All PN (person name) tags | Removed |
| Study/series/instance UIDs | Remapped consistently |
| Dates | Shifted by random per-patient offset |
| Times | Zeroed out |
| Private tags | Removed |

## Building from source

Requires Python 3.10 and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/YOUR_USERNAME/dicom-anonymizer.git
cd dicom-anonymizer
poetry install
poetry run python anonymize_dicom.py
```

To build a Windows `.exe` locally (on Windows):

```bash
poetry run pyinstaller --onefile --windowed --collect-data gooey anonymize_dicom.py
```

## Notes

- Files are identified as DICOM by magic bytes (`DICM` at offset 128), not by extension
- The tool does **not** handle burned-in pixel annotations — if detected, a warning is printed but the file is still processed
- Date offsets are random per patient and not stored — re-running on the same data will produce different date shifts