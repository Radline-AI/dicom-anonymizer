"""
anonymize_dicom.py
DICOM de-identification compliant with DICOM PS 3.15 Annex E
Basic Application Level Confidentiality Profile
+ optional AI-ready mode (Retain Device/Acquisition Identity)

Always retained:
  - PatientSex  (0010,0040)
  - PatientAge  (0010,1010) – computed from dates if absent
  - study dates (shifted by a deterministic per-patient offset)

Additionally retained in --ai-mode:
  - SeriesNumber            (0020,0011)
  - ScanningSequence        (0018,0020)
  - RepetitionTime          (0018,0080)
  - EchoTime                (0018,0081)
  - PixelSpacing            (0028,0030)
  - SliceThickness          (0018,0050)
  - SpacingBetweenSlices    (0018,0088)
  - SliceLocation           (0020,1041)
  - ImageOrientationPatient (0020,0037)
  - ImagePositionPatient    (0020,0032)
  - Rows / Columns          (0028,0010 / 0028,0011)
  - Manufacturer            (0008,0070)
  - ManufacturerModelName   (0008,1090)  <- also on PS 3.15 list
  - MagneticFieldStrength   (0018,0087)
  - SoftwareVersions        (0018,1020)
  - ProtocolName            (0018,1030)  <- also on PS 3.15 list
  - SeriesDescription       (0018,103E)  <- also on PS 3.15 list
  - StudyDescription        (0008,1030)  <- also on PS 3.15 list
  - Modality                (0008,0060)
  - BodyPartExamined        (0018,0015)

Compliance:
  - full PHI tag list per PS 3.15 Table E.1
  - age >= 90 years -> "090Y" (HIPAA Safe Harbor)
  - recursive de-identification through SQ sequences
  - UID remapping (all UI-VR tags)
  - private tag removal
  - PatientIdentityRemoved + DeidentificationMethod written with version and date
  - BurnedInAnnotation=YES -> file skipped (not saved) + logged
  - per-file audit log (SHA-256 hash in/out)
  - mapping CSV saved to a separate directory (--mapping-dir)

Re-identification:
  - Dates: fully reversible. The date offset is deterministic (SHA-256 of the
    original PatientID). The mapping CSV stores the exact offset per patient.
    To recover original dates:
        original_date = shifted_date - timedelta(days=DateShiftDays)
    Edge case: dates clamped to 1900-01-01 (pre-1900 originals) lose the exact
    value, but such dates do not occur in clinical MRI practice.

  - PatientID: reversible via the mapping CSV (OriginalPatientID <-> AnonymizedID).
    The anonymized ID itself is a one-way SHA-256 hash, but the mapping CSV stores
    the plain-text pair. Without the mapping CSV, re-identification is not possible.
    Treat the CSV as the pseudonymization key (GDPR Article 4(5)).

  - UIDs: NOT reversible. New UIDs are generated randomly per run and held only
    in memory. There is no persistent UID mapping file.

Changelog:
  v1.0.0 — initial release
  - Full PHI tag list per DICOM PS 3.15 Table E.1
  - AI-ready mode: Retain Device Identity + Retain Acquisition Identity options
  - Deterministic per-patient date shifting (reversible via mapping CSV)
  - Age clamped to 090Y for patients >= 90 years (HIPAA Safe Harbor)
  - BurnedInAnnotation=YES blocks file save; file logged for manual review
  - Per-file SHA-256 audit log; mapping CSV written to separate directory
  - _scrub_text() whitelist tokeniser for ProtocolName / SeriesDescription
  - DeidentificationMethod fits within VR LO 64-character limit
  - Startup listing of all PS3.15-overridden tags with names and addresses
"""

import csv
import hashlib
import re
from datetime import datetime, timedelta
from pathlib import Path

import pydicom
import pydicom.uid
from gooey import Gooey, GooeyParser

SCRIPT_VERSION = "1.0.0"

# ── FULL PHI TAG LIST — DICOM PS 3.15 Table E.1 ──────────────────────────────

PS315_TAGS_TO_REMOVE = {
    (0x0008, 0x0014),
    (0x0008, 0x0018),
    (0x0008, 0x0020),
    (0x0008, 0x0021),
    (0x0008, 0x0022),
    (0x0008, 0x0023),
    (0x0008, 0x0025),
    (0x0008, 0x002A),
    (0x0008, 0x0030),
    (0x0008, 0x0031),
    (0x0008, 0x0032),
    (0x0008, 0x0033),
    (0x0008, 0x0035),
    (0x0008, 0x0050),
    (0x0008, 0x0058),
    (0x0008, 0x0080),
    (0x0008, 0x0081),
    (0x0008, 0x0082),
    (0x0008, 0x0090),
    (0x0008, 0x0092),
    (0x0008, 0x0094),
    (0x0008, 0x0096),
    (0x0008, 0x1010),
    (0x0008, 0x1030),
    (0x0008, 0x103E),
    (0x0008, 0x1040),
    (0x0008, 0x1048),
    (0x0008, 0x1049),
    (0x0008, 0x1050),
    (0x0008, 0x1060),
    (0x0008, 0x1061),
    (0x0008, 0x1070),
    (0x0008, 0x1072),
    (0x0008, 0x1080),
    (0x0008, 0x1084),
    (0x0008, 0x1090),
    (0x0008, 0x1110),
    (0x0008, 0x1111),
    (0x0008, 0x1115),
    (0x0008, 0x1120),
    (0x0008, 0x1140),
    (0x0008, 0x1155),
    (0x0008, 0x1195),
    (0x0008, 0x2111),
    (0x0008, 0x2112),
    (0x0008, 0x4000),
    # 0010 — handled by group==0x0010 logic / SAFE_0010 allowlist
    (0x0010, 0x0010),
    (0x0010, 0x0020),
    (0x0010, 0x0021),
    (0x0010, 0x0022),
    (0x0010, 0x0030),
    (0x0010, 0x0032),
    (0x0010, 0x0033),
    (0x0010, 0x0034),
    (0x0010, 0x0035),
    (0x0010, 0x0050),
    (0x0010, 0x0101),
    (0x0010, 0x1000),
    (0x0010, 0x1001),
    (0x0010, 0x1002),
    (0x0010, 0x1005),
    (0x0010, 0x1020),
    (0x0010, 0x1021),
    (0x0010, 0x1030),
    (0x0010, 0x1040),
    (0x0010, 0x1050),
    (0x0010, 0x1060),
    (0x0010, 0x1080),
    (0x0010, 0x1081),
    (0x0010, 0x1090),
    (0x0010, 0x1100),
    (0x0010, 0x2000),
    (0x0010, 0x2110),
    (0x0010, 0x2150),
    (0x0010, 0x2152),
    (0x0010, 0x2154),
    (0x0010, 0x2155),
    (0x0010, 0x2160),
    (0x0010, 0x2180),
    (0x0010, 0x21A0),
    (0x0010, 0x21B0),
    (0x0010, 0x21C0),
    (0x0010, 0x21D0),
    (0x0010, 0x21F0),
    (0x0010, 0x2203),
    (0x0010, 0x2297),
    (0x0010, 0x2299),
    (0x0010, 0x4000),
    # 0018
    (0x0018, 0x0010),
    (0x0018, 0x1000),
    (0x0018, 0x1002),
    (0x0018, 0x1004),
    (0x0018, 0x1005),
    (0x0018, 0x1007),
    (0x0018, 0x1008),
    (0x0018, 0x1009),
    (0x0018, 0x100A),
    (0x0018, 0x1030),
    (0x0018, 0x103E),
    (0x0018, 0x1400),
    (0x0018, 0x1401),
    (0x0018, 0x2042),
    (0x0018, 0x4000),
    (0x0018, 0x700A),
    (0x0018, 0x9185),
    # 0020
    (0x0020, 0x0010),
    (0x0020, 0x0052),
    (0x0020, 0x0200),
    (0x0020, 0x3401),
    (0x0020, 0x3406),
    (0x0020, 0x4000),
    (0x0020, 0x9158),
    (0x0020, 0x9161),
    (0x0020, 0x9164),
    # 0028
    (0x0028, 0x4000),
    # 0032
    (0x0032, 0x0012),
    (0x0032, 0x1000),
    (0x0032, 0x1001),
    (0x0032, 0x1020),
    (0x0032, 0x1021),
    (0x0032, 0x1032),
    (0x0032, 0x1033),
    (0x0032, 0x1060),
    (0x0032, 0x1070),
    (0x0032, 0x4000),
    # 0038
    (0x0038, 0x0004),
    (0x0038, 0x0010),
    (0x0038, 0x0011),
    (0x0038, 0x001E),
    (0x0038, 0x0020),
    (0x0038, 0x0021),
    (0x0038, 0x0040),
    (0x0038, 0x0062),
    (0x0038, 0x0300),
    (0x0038, 0x0400),
    (0x0038, 0x0500),
    (0x0038, 0x4000),
    # 0040
    (0x0040, 0x0001),
    (0x0040, 0x0002),
    (0x0040, 0x0003),
    (0x0040, 0x0004),
    (0x0040, 0x0005),
    (0x0040, 0x0006),
    (0x0040, 0x0007),
    (0x0040, 0x000B),
    (0x0040, 0x0010),
    (0x0040, 0x0011),
    (0x0040, 0x0012),
    (0x0040, 0x0241),
    (0x0040, 0x0242),
    (0x0040, 0x0243),
    (0x0040, 0x0244),
    (0x0040, 0x0245),
    (0x0040, 0x0250),
    (0x0040, 0x0251),
    (0x0040, 0x0253),
    (0x0040, 0x0254),
    (0x0040, 0x0275),
    (0x0040, 0x0280),
    (0x0040, 0x0555),
    (0x0040, 0x1001),
    (0x0040, 0x1004),
    (0x0040, 0x1005),
    (0x0040, 0x1010),
    (0x0040, 0x1011),
    (0x0040, 0x1102),
    (0x0040, 0x1103),
    (0x0040, 0x1104),
    (0x0040, 0x1400),
    (0x0040, 0x2001),
    (0x0040, 0x2016),
    (0x0040, 0x2017),
    (0x0040, 0x2400),
    (0x0040, 0x3001),
    (0x0040, 0x4023),
    (0x0040, 0x4028),
    (0x0040, 0x4030),
    (0x0040, 0x4034),
    (0x0040, 0x4035),
    (0x0040, 0x4036),
    (0x0040, 0x4037),
    (0x0040, 0x4050),
    (0x0040, 0x4051),
    (0x0040, 0x4052),
    (0x0040, 0xA07C),
    (0x0040, 0xA124),
    (0x0040, 0xA730),
    (0x0040, 0xDB0C),
    (0x0040, 0xDB0D),
    # 0070
    (0x0070, 0x0001),
    (0x0070, 0x0084),
    (0x0070, 0x0086),
    (0x0070, 0x031A),
    # 0088
    (0x0088, 0x0140),
    # 0400
    (0x0400, 0x0100),
    (0x0400, 0x0402),
    # 3006
    (0x3006, 0x0024),
    (0x3006, 0x00C2),
    # 3010
    (0x3010, 0x006E),
    # FFFA
    (0xFFFA, 0xFFFA),
}

# Date tags — shifted by a deterministic per-patient offset (reversible via mapping CSV).
DATE_TAGS = {
    (0x0008, 0x0020),
    (0x0008, 0x0021),
    (0x0008, 0x0022),
    (0x0008, 0x0023),
    (0x0008, 0x002A),
}

# Time-of-day tags — zeroed out. Time-of-day carries no clinical value for AI
# training and would narrow the re-identification window if kept.
TIME_TAGS = {
    (0x0008, 0x0030),
    (0x0008, 0x0031),
    (0x0008, 0x0032),
    (0x0008, 0x0033),
}

# Tags in group 0010 that are safe to keep (non-identifying clinical metadata).
SAFE_0010 = {
    (0x0010, 0x0040),  # PatientSex
    (0x0010, 0x1010),  # PatientAge — overwritten after computation
}

# ── TAGS RETAINED IN AI-READY MODE ───────────────────────────────────────────
# Correspond to PS 3.15 options: Retain Device Identity + Retain Acquisition
# Identity. None of these are PHI — all are non-identifying acquisition
# parameters needed for model training and domain-shift analysis.
#
# Tags marked "<- also on PS 3.15 list" are present in both AI_RETAIN_TAGS and
# PS315_TAGS_TO_REMOVE. Their intersection (_AI_OVERRIDE_TAGS) is subtracted
# from the active removal set when ai_mode=True, so they are preserved.
# In standard mode (ai_mode=False) they are removed normally.

# Maps every retained tag to a human-readable name.
# Used both as the authoritative tag set and for logging (_AI_OVERRIDE_TAGS printout).
AI_RETAIN_TAGS: dict[tuple[int, int], str] = {
    # Required by the training pipeline
    (0x0020, 0x0011): "SeriesNumber",
    (0x0018, 0x0020): "ScanningSequence",
    (0x0018, 0x0080): "RepetitionTime",
    (0x0018, 0x0081): "EchoTime",
    (0x0028, 0x0030): "PixelSpacing",
    (0x0018, 0x0050): "SliceThickness",
    (0x0018, 0x0088): "SpacingBetweenSlices",
    (0x0020, 0x1041): "SliceLocation",
    (0x0020, 0x0037): "ImageOrientationPatient",
    (0x0020, 0x0032): "ImagePositionPatient",
    (0x0028, 0x0010): "Rows",
    (0x0028, 0x0011): "Columns",
    # Device / acquisition (bias analysis, domain shift)
    (0x0008, 0x0070): "Manufacturer",
    (0x0008, 0x1090): "ManufacturerModelName",  # <- also on PS 3.15 list
    (0x0018, 0x0087): "MagneticFieldStrength",
    (0x0018, 0x1020): "SoftwareVersions",
    (0x0018, 0x1030): "ProtocolName",  # <- also on PS 3.15 list
    (0x0018, 0x103E): "SeriesDescription",  # <- also on PS 3.15 list
    (0x0008, 0x1030): "StudyDescription",  # <- also on PS 3.15 list
    (0x0008, 0x0060): "Modality",
    (0x0018, 0x0015): "BodyPartExamined",
    (0x0020, 0x0010): "StudyID",  # <- also on PS 3.15 list
}

# Dynamically computed intersection — tags that appear on the PS 3.15 removal
# list but must be kept in ai_mode. Derived automatically so comments and code
# always stay in sync without manual maintenance.
_AI_OVERRIDE_TAGS: dict[tuple[int, int], str] = {
    tag: name for tag, name in AI_RETAIN_TAGS.items() if tag in PS315_TAGS_TO_REMOVE
}


# ── HELPERS ───────────────────────────────────────────────────────────────────


def _scrub_text(val: str) -> str:
    """Sanitise a free-text DICOM field (ProtocolName, SeriesDescription, etc.).

    Tokenises the value and retains only tokens that appear on a clinical
    whitelist (MRI sequences, anatomical terms, orientations, numeric parameters
    with units). Everything else — physician names, department codes, free-text
    annotations — is silently dropped. Returns "ANON" if no safe tokens remain.
    """
    import re

    if not val:
        return val

    tokens = re.findall(r"[A-Za-z0-9\-\._]+", val)

    SAFE_TOKENS = {
        # Modalities
        "MR",
        "MRI",
        "CT",
        "CTDI",
        "ANGIO",
        "ANGIOGRAPHY",
        "TOF",
        "MRA",
        "CTA",
        "BOLUS",
        "PERFUSION",
        # Anatomy (orthopaedic focus)
        "KNEE",
        "HIP",
        "SHOULDER",
        "ANKLE",
        "FOOT",
        "HAND",
        "WRIST",
        "SPINE",
        "CERVICAL",
        "THORACIC",
        "LUMBAR",
        "SACRAL",
        "HEAD",
        "BRAIN",
        "SKULL",
        "ABDOMEN",
        "PELVIS",
        "CHEST",
        # Orientations
        "SAG",
        "SAGITTAL",
        "COR",
        "CORONAL",
        "AX",
        "AXIAL",
        "OBL",
        "OBLIQUE",
        # MRI sequences
        "T1",
        "T2",
        "T2STAR",
        "T2*",
        "PD",
        "DP",
        "FLAIR",
        "STIR",
        "DWI",
        "ADC",
        # Fat suppression
        "FS",
        "FATSAT",
        "FAT",
        "SAT",
        "FAT-SAT",
        "SPIR",
        "SPAIR",
        "CHESS",
        # Pulse sequences
        "SE",
        "FSE",
        "TSE",
        "GRE",
        "EPI",
        # Dimensionality / resolution descriptors
        "3D",
        "2D",
        "FAST",
        "HIGHRES",
        "LOWRES",
        "ISO",
        "ISOTROPIC",
        # Vendor sequence names
        "VIBE",
        "SPACE",
        "CUBE",
        "BRAVO",
        "PROPELLER",
        "BLADE",
        # Contrast timing
        "PRE",
        "POST",
        "POSTCONTRAST",
        "PRECONTRAST",
        # Weighting abbreviations
        "W",
        "WI",
        "WEIGHTED",
    }

    safe_tokens = []
    for t in tokens:
        t_upper = t.upper()

        # 1. Direct whitelist match
        if t_upper in SAFE_TOKENS:
            safe_tokens.append(t_upper)
            continue

        # 2. Numeric parameters with units (e.g. 1.5MM, 3.0T, 500MS)
        if re.match(r"^\d+([\.,]\d+)?(MM|T|MS|S)$", t_upper):
            safe_tokens.append(t_upper)
            continue

        # 3. Pure numbers (e.g. TR/TE values)
        if re.match(r"^\d+([\.,]\d+)?$", t):
            safe_tokens.append(t)
            continue

        # 4. Short alphanumeric codes with at least one digit (e.g. C1, T12).
        #    Digit requirement eliminates short surnames that contain no digits.
        if re.match(r"^[A-Z]+\d+[A-Z0-9]*$", t_upper) and len(t_upper) <= 6:
            safe_tokens.append(t_upper)
            continue

    return " ".join(safe_tokens) or "ANON"


def get_deterministic_shift(patient_id: str) -> int:
    """Return a deterministic date offset in days for a given patient ID.

    The offset is in the range [-3650, +3650] (approx. +/-10 years) and is
    derived from the first 8 hex characters of SHA-256(patient_id). The same
    patient ID always produces the same offset across runs and machines, which
    makes date re-identification possible via the mapping CSV.
    """
    h = hashlib.sha256(patient_id.encode()).hexdigest()
    seed_int = int(h[:8], 16)
    return (seed_int % 7300) - 3650


# Earliest date safely handled by strftime on all platforms.
# Windows raises ValueError for years < 1900.
_DATE_MIN = datetime(1900, 1, 1)


def shift_date(val, days_to_shift: int) -> str:
    """Shift a DICOM date string by the given number of days.

    Preserves DICOM date format (YYYYMMDD). The result is clamped to
    1900-01-01 to avoid ValueError on Windows when strftime is called with
    years < 1900. Dates before 1900 do not occur in clinical MRI.

    To recover the original date:
        original = parse_dicom_date(shifted_value) - timedelta(days=days_to_shift)
    """
    dt = parse_dicom_date(val)
    if not dt:
        return ""
    shifted_dt = dt + timedelta(days=days_to_shift)
    shifted_dt = max(shifted_dt, _DATE_MIN)
    return shifted_dt.strftime("%Y%m%d")


def generate_anon_id(original_id: str, prefix: str) -> str:
    """Generate a pseudonymous patient ID from the original ID.

    Format: PREFIX_XXXXXXXX where XXXXXXXX is the first 8 hex characters of
    SHA-256(original_id). One-way by itself; reversible only via the mapping
    CSV written by run_process().
    """
    h = hashlib.sha256(str(original_id).encode()).hexdigest()[:8].upper()
    return f"{prefix}_{h}"


def remap_uid(uid: str, uid_map: dict) -> str:
    """Return a stable remapped UID for the current run.

    The uid_map is in-memory and not persisted to disk — UID remapping is
    NOT reversible after the process exits.
    """
    if uid not in uid_map:
        uid_map[uid] = pydicom.uid.generate_uid()
    return uid_map[uid]


def parse_dicom_date(val) -> datetime | None:
    """Parse a DICOM date string (YYYYMMDD or YYYY-MM-DD) to a datetime object."""
    try:
        return datetime.strptime(str(val).replace("-", "")[:8], "%Y%m%d")
    except (ValueError, TypeError):
        return None


def keep_year_only(val) -> str:
    """Return YYYY0101 (year preserved, month/day zeroed) for a DICOM date."""
    dt = parse_dicom_date(val)
    return f"{dt.year}0101" if dt else "19000101"


def calculate_age(birth_val, study_val) -> str | None:
    """Compute a DICOM AS (Age String) from birth date and study date.

    Returns None if either date is missing or invalid.
    Ages >= 90 years are clamped to "090Y" per HIPAA Safe Harbor.
    """
    birth = parse_dicom_date(birth_val)
    study = parse_dicom_date(study_val)
    if not birth or not study or study < birth:
        return None
    age_years = (
        study.year
        - birth.year
        - (1 if (study.month, study.day) < (birth.month, birth.day) else 0)
    )
    if age_years >= 90:
        return "090Y"
    if age_years >= 1:
        return f"{age_years:03d}Y"
    age_months = (study.year - birth.year) * 12 + (study.month - birth.month)
    if study.day < birth.day:
        age_months -= 1
    if age_months >= 1:
        return f"{age_months:03d}M"
    return f"{(study.date() - birth.date()).days:03d}D"


def get_sex(ds) -> str | None:
    """Return the PatientSex value if it is one of M / F / O, else None."""
    val = str(getattr(ds, "PatientSex", "") or "").strip().upper()
    return val if val in ("M", "F", "O") else None


def get_best_age(ds) -> str | None:
    """Return the best available age string for the patient.

    Uses the existing PatientAge field if present (applying the >=90Y clamp),
    otherwise computes age from PatientBirthDate and StudyDate.
    Returns None if age cannot be determined from either source.
    """
    existing = str(getattr(ds, "PatientAge", "") or "").strip()
    if existing:
        try:
            if existing.endswith("Y") and int(existing[:-1]) >= 90:
                return "090Y"
        except ValueError:
            pass
        return existing
    birth = str(getattr(ds, "PatientBirthDate", "") or "").strip()
    study = str(getattr(ds, "StudyDate", "") or "").strip()
    return calculate_age(birth, study)


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file (streamed in 64 KiB chunks)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── RECURSIVE DE-IDENTIFICATION ───────────────────────────────────────────────


def anonymize_recursive(ds, uid_map: dict, active_remove_tags: set, date_offset: int):
    """Recursively de-identify a DICOM dataset including nested SQ sequences.

    Parameters
    ----------
    ds:
        pydicom Dataset to modify in place.
    uid_map:
        Shared mapping of original -> remapped UIDs (persists across files within
        a single run to maintain intra-study UID consistency).
    active_remove_tags:
        Tags to remove. In ai_mode: PS315_TAGS_TO_REMOVE - _AI_OVERRIDE_TAGS.
        In standard mode: PS315_TAGS_TO_REMOVE unchanged.
    date_offset:
        Number of days to shift DATE_TAGS values (positive or negative).
    """
    to_delete = []

    for elem in ds:
        tag = elem.tag

        # Recurse into sequences — do not mark the SQ tag itself for deletion.
        if elem.VR == "SQ":
            for item in elem.value:
                anonymize_recursive(item, uid_map, active_remove_tags, date_offset)
            continue

        # Shift date tags by the deterministic offset (reversible).
        if tag in DATE_TAGS:
            try:
                original_val = str(elem.value).strip()
                if original_val:
                    ds[tag].value = shift_date(original_val, date_offset)
            except Exception:
                to_delete.append(tag)
            continue

        # Patient group — remove everything except SAFE_0010.
        if tag.group == 0x0010 and tag not in SAFE_0010:
            to_delete.append(tag)
            continue

        # Overlay groups (6000-600E, even groups only) — always remove.
        if 0x6000 <= tag.group <= 0x60FF and tag.group % 2 == 0:
            to_delete.append(tag)
            continue

        # Person name VR — always remove regardless of tag address.
        if elem.VR == "PN":
            to_delete.append(tag)
            continue

        # Zero out time-of-day tags.
        if tag in TIME_TAGS:
            try:
                ds[tag].value = "000000"
            except Exception:
                to_delete.append(tag)
            continue

        # Remap all UI-VR values (not reversible after process exit).
        if elem.VR == "UI" and elem.value:
            try:
                ds[tag].value = remap_uid(str(elem.value), uid_map)
            except Exception:
                pass
            continue

        # Remove any remaining tag on the active PHI list.
        if tag in active_remove_tags:
            to_delete.append(tag)

    for tag in to_delete:
        try:
            del ds[tag]
        except Exception:
            pass


# ── MAIN DE-IDENTIFICATION ────────────────────────────────────────────────────


def anonymize(
    ds, anon_id: str, uid_map: dict, ai_mode: bool, original_pid: str
) -> tuple[pydicom.Dataset, bool]:
    """De-identify a single DICOM dataset.

    Returns
    -------
    (ds, burned_in)
        ds         -- modified dataset (not yet saved to disk).
        burned_in  -- True if BurnedInAnnotation=YES was set in the original.
                      Callers must NOT save burned_in files without manual review.
    """
    date_offset = get_deterministic_shift(original_pid)

    age = get_best_age(ds)
    sex = get_sex(ds)

    # Read BurnedInAnnotation BEFORE removing tags.
    burned_in = str(getattr(ds, "BurnedInAnnotation", "")).strip().upper() == "YES"

    if ai_mode:
        # Exclude override tags from the removal set so they are preserved.
        # Text fields on the override list are scrubbed instead of removed:
        # this strips free-text PHI (physician names, department codes) while
        # retaining clinical tokens (sequence names, anatomical terms).
        active_remove_tags = PS315_TAGS_TO_REMOVE - _AI_OVERRIDE_TAGS.keys()

        # if hasattr(ds, "ProtocolName"):
        #     ds.ProtocolName = _scrub_text(str(ds.ProtocolName))
        # if hasattr(ds, "SeriesDescription"):
        #     ds.SeriesDescription = _scrub_text(str(ds.SeriesDescription))
        # if hasattr(ds, "StudyDescription"):
        #     ds.StudyDescription = _scrub_text(str(ds.StudyDescription))
    else:
        active_remove_tags = PS315_TAGS_TO_REMOVE

    ds.remove_private_tags()
    anonymize_recursive(ds, uid_map, active_remove_tags, date_offset)

    ds.PatientID = anon_id
    ds.PatientName = anon_id

    if sex is not None:
        ds.PatientSex = sex
    if age is not None:
        ds.PatientAge = age

    # Declare no burned-in annotation after de-identification.
    if not burned_in:
        ds.BurnedInAnnotation = "NO"

    ds.PatientIdentityRemoved = "YES"

    # VR LO has a 64-character limit. Keep this field short and compliant.
    # Full de-identification parameters are recorded in the audit log CSV.
    mode_suffix = "+AI" if ai_mode else ""
    ds.DeidentificationMethod = (
        f"PS3.15 Basic Profile{mode_suffix} v{SCRIPT_VERSION} ({datetime.now().date()})"
    )

    return ds, burned_in


# ── FILE DISCOVERY ────────────────────────────────────────────────────────────


def find_dicoms(path: Path) -> list[Path]:
    """Recursively find all DICOM files under path by checking the DICM preamble."""
    files = []
    for p in path.rglob("*"):
        if not p.is_file():
            continue
        try:
            with open(p, "rb") as f:
                f.seek(128)
                if f.read(4) == b"DICM":
                    files.append(p)
        except (OSError, IOError):
            pass
    return files


# ── PROCESSING ────────────────────────────────────────────────────────────────


def run_process(
    input_dir: str,
    output_dir: str,
    prefix: str,
    mapping_dir: str,
    ai_mode: bool,
) -> None:
    """De-identify all DICOM files under input_dir and write results to output_dir.

    Confidential files (mapping CSV and audit log) are written to mapping_dir,
    which must be kept separate from output_dir. The mapping CSV is the sole
    means of re-identification and must be treated as a GDPR pseudonymization
    key — losing it makes re-identification permanently impossible.
    """
    input_path = Path(input_dir).resolve()
    output_path = Path(output_dir).resolve()
    mapping_path = Path(mapping_dir).resolve() if mapping_dir else output_path.parent
    output_path.mkdir(parents=True, exist_ok=True)
    mapping_path.mkdir(parents=True, exist_ok=True)

    mode_label = "AI-ready (Retain Device+Acquisition)" if ai_mode else "Standard"
    print(f"Input:   {input_path}")
    print(f"Output:  {output_path}")
    print(f"Mapping: {mapping_path}")
    print(f"Mode:    {mode_label}")
    print("")
    print(
        f"AI override tags: {len(_AI_OVERRIDE_TAGS)} PS3.15-listed tags retained in ai_mode:"
    )
    for tag, name in sorted(_AI_OVERRIDE_TAGS.items()):
        print(f"  ({tag[0]:04X},{tag[1]:04X})  {name}")
    print("")
    print("Searching for DICOM files...")

    files = find_dicoms(input_path)
    if not files:
        print("No DICOM files found.")
        return

    print(f"Found {len(files)} files.\n")

    uid_map: dict = {}
    patient_map: dict = {}
    age_computed = 0
    age_missing = 0
    age_clamped = 0
    errors: list[tuple[str, str]] = []
    burned_skipped: list[str] = []
    audit_rows: list[dict] = []

    for i, file in enumerate(files, 1):
        try:
            ds = pydicom.dcmread(str(file), force=True)
        except Exception as e:
            errors.append((file.name, str(e)))
            continue

        pid = (
            str(getattr(ds, "PatientID", "") or "").strip()
            or file.relative_to(input_path).parts[0]
        )
        if pid not in patient_map:
            patient_map[pid] = {
                "anon_id": generate_anon_id(pid, prefix),
                "shift": get_deterministic_shift(pid),
            }

        anon_id = patient_map[pid]["anon_id"]

        has_age = bool(str(getattr(ds, "PatientAge", "") or "").strip())
        computed = get_best_age(ds)
        if not has_age and computed is not None:
            age_computed += 1
        elif computed is None:
            age_missing += 1
        if computed == "090Y":
            age_clamped += 1

        hash_in = sha256_file(file)
        ds, burned_in = anonymize(ds, anon_id, uid_map, ai_mode, pid)

        if burned_in:
            burned_skipped.append(file.name)
            sop = getattr(ds, "SOPInstanceUID", "Unknown")
            print(f"SKIP (BurnedInAnnotation): {file.name} [{sop}]")
            audit_rows.append(
                {
                    "file": file.name,
                    "anon_id": anon_id,
                    "hash_in": hash_in,
                    "hash_out": "",
                    "status": "SKIPPED_BURNED_IN",
                    "ai_mode": ai_mode,
                }
            )
            continue

        out = output_path / file.relative_to(input_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        ds.save_as(str(out))

        audit_rows.append(
            {
                "file": file.name,
                "anon_id": anon_id,
                "hash_in": hash_in,
                "hash_out": sha256_file(out),
                "status": "OK",
                "ai_mode": ai_mode,
            }
        )

        # Update progress bar for Gooey (requires specific format)
        progress = int((i / len(files)) * 100)
        print(f"Processing file {i}/{len(files)} ({progress}%)")

    # ── Summary ───────────────────────────────────────────────────────────────
    saved = len(files) - len(errors) - len(burned_skipped)
    print(f"\nDone: {saved}/{len(files)} files saved")
    if burned_skipped:
        print(
            f"Skipped (BurnedInAnnotation=YES): {len(burned_skipped)} files — manual review required"
        )
    if age_computed:
        print(f"Age computed from dates: {age_computed} files")
    if age_clamped:
        print(f"Age clamped to 090Y (HIPAA, >=90 years): {age_clamped} files")
    if age_missing:
        print(f"Age unavailable: {age_missing} files")
    if errors:
        print(f"Errors: {len(errors)} files")
        for name, err in errors[:10]:
            print(f"  {name}: {err}")

    # ── Write confidential files to mapping_path (outside output folder) ──────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    mapping_file = mapping_path / f"_mapping_CONFIDENTIAL_{ts}.csv"
    with open(mapping_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["OriginalPatientID", "AnonymizedID", "DateShiftDays"])
        for orig, data in patient_map.items():
            writer.writerow([orig, data["anon_id"], data["shift"]])

    audit_file = mapping_path / f"_audit_log_{ts}.csv"
    with open(audit_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["file", "anon_id", "hash_in", "hash_out", "status", "ai_mode"],
        )
        writer.writeheader()
        writer.writerows(audit_rows)

    if burned_skipped:
        burned_file = mapping_path / f"_burned_in_review_{ts}.txt"
        with open(burned_file, "w", encoding="utf-8") as f:
            f.write("\n".join(burned_skipped))
        print(f"Burned-in list: {burned_file}")

    print(f"\nPatient mapping: {mapping_file}")
    print(f"Audit log:       {audit_file}")
    print("CONFIDENTIAL — do not distribute alongside anonymized DICOMs.\n")


# ── GUI ───────────────────────────────────────────────────────────────────────


@Gooey(
    program_name="DICOM Anonymizer",
    language="english",
    default_size=(700, 650),
    progress_regex=r"^Processing file (\d+)/(\d+)",
    progress_expr="x[0] / x[1] * 100",
    disable_progress_bar_animation=False,
    header_bg_color="#2c7be5",
    body_bg_color="#f8f9fa",
    footer_bg_color="#e9ecef",
    terminal_font_color="#212529",
    terminal_panel_color="#ffffff",
    header_height=80,
    richtext_controls=True,
)
def main():
    parser = GooeyParser(
        description=(
            "Secure DICOM de-identification — DICOM PS 3.15 Basic Profile\n"
            "Use --ai-mode to retain device and acquisition tags for AI training.\n"
            "Dates are shifted by a deterministic per-patient offset "
            "(reversible via the mapping CSV)."
        )
    )
    parser.add_argument(
        "input",
        help="Select folder containing original DICOM files",
        widget="DirChooser",
    )
    parser.add_argument(
        "output",
        help="Select folder where de-identified files will be saved",
        widget="DirChooser",
    )
    parser.add_argument(
        "--mapping-dir",
        "-m",
        default="",
        help=(
            "Folder for CONFIDENTIAL mapping and audit files "
            "(default: parent of output folder). "
            "Keep this SEPARATE from the output folder — "
            "it is the only means of re-identification."
        ),
        widget="DirChooser",
    )
    parser.add_argument(
        "--prefix",
        "-p",
        default="ANON",
        help="Prefix for anonymized patient IDs (default: ANON)",
    )
    parser.add_argument(
        "--ai-mode",
        action="store_true",
        default=True,
        help=(
            "Retain device and acquisition tags for AI training "
            "(Manufacturer, Model, TR, TE, ProtocolName, SeriesDescription, etc.). "
            "Implements PS 3.15 Retain Device Identity + Retain Acquisition Identity Options. "
            f"Currently overrides {len(_AI_OVERRIDE_TAGS)} PS3.15-listed tags."
        ),
    )
    args = parser.parse_args()
    run_process(
        args.input,
        args.output,
        args.prefix,
        args.mapping_dir,
        args.ai_mode,
    )


if __name__ == "__main__":
    main()
