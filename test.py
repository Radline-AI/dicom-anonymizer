def _scrub_text(val: str) -> str:
    import re

    if not val:
        return val

    # Tokenizacja (bezpieczna dla DICOM stringów)
    tokens = re.findall(r"[A-Za-z0-9\-\._]+", val)

    SAFE_TOKENS = {
        # ── Modalities ─────────────────────────────────────────
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
        # ── Anatomia (orto) ────────────────────────────────────
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
        # ── Orientacje ─────────────────────────────────────────
        "SAG",
        "SAGITTAL",
        "COR",
        "CORONAL",
        "AX",
        "AXIAL",
        "OBL",
        "OBLIQUE",
        # ── Sekwencje MRI ──────────────────────────────────────
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
        # ── Fat suppression ────────────────────────────────────
        "FS",
        "FATSAT",
        "FAT",
        "SAT",
        "FAT-SAT",
        "SPIR",
        "SPAIR",
        "CHESS",
        # ── Techniczne ─────────────────────────────────────────
        "SE",
        "FSE",
        "TSE",
        "GRE",
        "EPI",
        "3D",
        "2D",
        # ── Parametry / opis ───────────────────────────────────
        "FAST",
        "HIGHRES",
        "LOWRES",
        "ISO",
        "ISOTROPIC",
        # ── Vendor / style naming ──────────────────────────────
        "VIBE",
        "SPACE",
        "CUBE",
        "BRAVO",
        "PROPELLER",
        "BLADE",
        # ── Inne często spotykane ──────────────────────────────
        "PRE",
        "POST",
        "POSTCONTRAST",
        "PRECONTRAST",
        "W",
        "WI",
        "WEIGHTED",
    }

    safe_tokens = []

    for t in tokens:
        t_upper = t.upper()

        # 1. Najpierw sprawdzaj Whitelist (najpewniejsze)
        if t_upper in SAFE_TOKENS:
            safe_tokens.append(t_upper)
            continue

        # 2. Parametry z jednostkami (np. 1.5MM, 3.0T) - bardzo ważne dla AI
        if re.match(r"^\d+([\.,]\d+)?(MM|T|MS|S)$", t_upper):
            safe_tokens.append(t_upper)
            continue

        # 3. Same liczby (np. TR/TE)
        if re.match(r"^\d+([\.,]\d+)?$", t):
            safe_tokens.append(t)
            continue

        # 4. Znane bezpieczne skróty, które mają cyfry (np. C1, T12, 3D)
        # To eliminuje krótkie nazwiska typu "Kowals"
        if re.match(r"^[A-Z]+\d+[A-Z0-9]*$", t_upper) and len(t_upper) <= 6:
            safe_tokens.append(t_upper)
            continue

    return " ".join(safe_tokens) or "ANON"


if __name__ == "__main__":
    _scrub_text("CT ANGIO MARIAN PAZDIOCH")
