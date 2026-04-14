import hashlib
import random
from datetime import datetime, timedelta
from pathlib import Path

import pydicom
import pydicom.uid
from gooey import Gooey, GooeyParser

# ── CONFIG ────────────────────────────────────────────────────────────────────

SAFE_0010 = {
    (0x0010, 0x0040),  # PatientSex
    (0x0010, 0x1010),  # PatientAge
}

DATE_TAGS = {
    (0x0008, 0x0020),
    (0x0008, 0x0021),
    (0x0008, 0x0022),
    (0x0008, 0x0023),
    (0x0008, 0x002A),
}

TIME_TAGS = {
    (0x0008, 0x0030),
    (0x0008, 0x0031),
    (0x0008, 0x0032),
    (0x0008, 0x0033),
}

# ── HELPERS ───────────────────────────────────────────────────────────────────


def generate_anon_id(original_id: str, prefix: str):
    h = hashlib.sha256(str(original_id).encode()).hexdigest()[:8].upper()
    return f"{prefix}_{h}"


def remap_uid(uid, uid_map):
    if uid not in uid_map:
        uid_map[uid] = pydicom.uid.generate_uid()
    return uid_map[uid]


def parse_date(val):
    try:
        return datetime.strptime(str(val)[:8], "%Y%m%d")
    except (ValueError, TypeError):
        return None


def shift_date(val, offset_days):
    dt = parse_date(val)
    if not dt:
        return "19000101"
    new_dt = dt + timedelta(days=offset_days)
    return new_dt.strftime("%Y%m%d")


def get_sex(ds):
    return getattr(ds, "PatientSex", None)


def get_best_age(ds):
    return getattr(ds, "PatientAge", None)


# ── RECURSION ─────────────────────────────────────────────────────────────────


def anonymize_recursive(ds, uid_map, date_offset):
    to_delete = []

    for elem in ds:
        tag = elem.tag

        # Sequences
        if elem.VR == "SQ":
            for item in elem.value:
                anonymize_recursive(item, uid_map, date_offset)
            continue

        # 1. Remove all Patient (0010) tags except whitelist
        if tag.group == 0x0010 and tag not in SAFE_0010:
            to_delete.append(tag)
            continue

        # 2. Remove all PN tags (PatientName will be overwritten separately)
        if elem.VR == "PN":
            to_delete.append(tag)
            continue

        # 3. Shift dates by offset
        if tag in DATE_TAGS:
            ds[tag].value = shift_date(elem.value, date_offset)
            continue

        # 4. Zero out times
        if tag in TIME_TAGS:
            ds[tag].value = "000000"
            continue

        # 5. Remap UIDs
        if elem.VR == "UI":
            try:
                if elem.value:
                    ds[tag].value = remap_uid(str(elem.value), uid_map)
            except Exception:
                pass

    for tag in to_delete:
        if tag in ds:
            del ds[tag]


# ── MAIN ANONYMIZATION ────────────────────────────────────────────────────────


def anonymize(ds, anon_id, uid_map, date_offset):
    age = get_best_age(ds)
    sex = get_sex(ds)

    ds.remove_private_tags()
    anonymize_recursive(ds, uid_map, date_offset)

    ds.PatientID = anon_id
    ds.PatientName = anon_id

    if sex is not None:
        ds.PatientSex = sex
    if age is not None:
        ds.PatientAge = age

    ds.PatientIdentityRemoved = "YES"

    if getattr(ds, "BurnedInAnnotation", "") == "YES":
        print(
            f"WARNING: Burned-in annotation detected in file: {getattr(ds, 'SOPInstanceUID', 'Unknown')}"
        )

    return ds


# ── FILE DISCOVERY ────────────────────────────────────────────────────────────


def find_dicoms(path):
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


def run_process(input_dir, output_dir, prefix):
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = find_dicoms(input_dir)
    print(f"Found: {len(files)} files")

    uid_map = {}
    patient_map = {}
    date_offsets = {}

    for i, file in enumerate(files, 1):
        try:
            ds = pydicom.dcmread(file)
        except Exception as e:
            print(f"Read error {file}: {e}")
            continue

        pid = str(getattr(ds, "PatientID", "UNKNOWN"))

        if pid not in patient_map:
            patient_map[pid] = generate_anon_id(pid, prefix)
            date_offsets[pid] = random.randint(-3650, 3650)

        anon_id = patient_map[pid]
        offset = date_offsets[pid]

        ds = anonymize(ds, anon_id, uid_map, offset)

        out = output_dir / file.relative_to(input_dir)
        out.parent.mkdir(parents=True, exist_ok=True)
        ds.save_as(out)

        if i % 50 == 0 or i == len(files):
            print(f"Progress: {i}/{len(files)}")

    print("DONE")


# ── GUI ───────────────────────────────────────────────────────────────────────


@Gooey(
    program_name="DICOM Anonymizer Pro",
    language="english",
    default_size=(700, 600),
    progress_indicator_type="smooth",
    header_bg_color="#2c7be5",
    body_bg_color="#f8f9fa",
    footer_bg_color="#e9ecef",
    terminal_font_color="#212529",
    terminal_panel_color="#ffffff",
    header_height=80,
    richtext_controls=True,
)
def main():
    parser = GooeyParser(description="Tool for secure anonymization of DICOM data")
    parser.add_argument(
        "input",
        help="Select folder containing original DICOM files",
        widget="DirChooser",
    )
    parser.add_argument(
        "output",
        help="Select folder where anonymized data will be saved",
        widget="DirChooser",
    )
    parser.add_argument(
        "--prefix",
        "-p",
        default="ANON",
        help="Prefix for new patient identifiers",
    )
    args = parser.parse_args()
    run_process(args.input, args.output, args.prefix)


if __name__ == "__main__":
    main()
