#!/usr/bin/env python3
"""EXP-0030c — production IEEE-754 float-provenance feature pipeline
(CMRI-only rule; NMRI is explicitly OUT of scope, see below).

Materializes, as a real production module, the F2 (IEEE-754 bit-structure)
feature computation and the TRAIN-normal reference set that previously only
existed inside the research modules `ml/exp0032_admissible_ceiling_audit.py`
and `ml/exp0030_float_provenance_detector.py`. This module is imported by
`ml/rules.py` (`CmriFloatProvenanceRule`) and `ml/iforest_detector.py`
(`run_detector`'s permanent-for-future-runs definition), and by
`ml/exp0030c_cmri_production_wiring.py` (the experiment that trains,
serializes, and scores the CMRI classifier this module's features feed).

Design choice, disclosed per instruction: the low-level IEEE-754 bit-decode
helpers (`ieee754_bits`, `nearest_reference_distance`,
`quantization_grid_distance`, `mantissa_low_bits_entropy`), the constants
that parameterize them (`QUANTIZATION_STEPS`, `ADC_LATTICE_STEPS`,
`MANTISSA_LOW_BITS`, `TRAILING_BUFFER_SAMPLES`), `F2_NAMES` itself, and
`SeriesIndex` (the aligned-pressure-series + bucket-lookup helper) are
IMPORTED UNCHANGED from `ml/exp0032_admissible_ceiling_audit.py` rather than
duplicated. Rationale: these are pure, side-effect-free numeric functions
with no dependency on anything EXP-0032-specific (no labels, no cohort
logic, no XGBoost); duplicating them would create two copies that could
silently drift out of sync (e.g. if `MANTISSA_LOW_BITS` were ever tuned),
which is more brittle than one shared, historically-frozen source of truth.
`ml/exp0032_admissible_ceiling_audit.py` itself is NEVER edited by this
module or anything that imports from it. What IS duplicated/re-derived here
is the actual F2-row ASSEMBLY (`f2_row` below): EXP-0032's `window_row`
computes F1+F2+F3 together (including the F3 Wasserstein-reference-sample
machinery this production path does not need); `f2_row` here computes ONLY
the 7 F2 features, so the production path does not carry an unused
dependency on a capped Wasserstein reference sample.

CMRI ONLY. Per EXP-0030b's decision (isolated marginal trade ratio >= 3:1:
CMRI worst-case 5.33:1, GO; NMRI worst-case 1.19:1, NO-GO), this module and
everything built on it is used for a CMRI-only production rule. It contains
no NMRI-specific logic and must not be extended to fire an NMRI float rule
without a separate pre-registered decision.

Pressure is the ARFF-aligned "pressure measurement" value — egress traffic
extracted from Mississippi State ICS testbed dataset, used as a simulated
diode-observer view — never real diode capture data.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
from importlib.metadata import version
from pathlib import Path

import numpy as np

from exp0032_admissible_ceiling_audit import (
    ADC_LATTICE_STEPS, F2_NAMES, MANTISSA_LOW_BITS, QUANTIZATION_STEPS,
    TRAILING_BUFFER_SAMPLES, SeriesIndex, ieee754_bits,
    mantissa_low_bits_entropy, nearest_reference_distance,
    quantization_grid_distance,
)

ROOT = Path(__file__).resolve().parent.parent
REFERENCE_PATH = ROOT / "data" / "experiments" / "exp0030c_train_normal_reference.json"
MODEL_PATH = ROOT / "data" / "artifacts" / "exp0030c_cmri_float_provenance_model.json"
MODEL_METADATA_PATH = ROOT / "data" / "artifacts" / "exp0030c_cmri_float_provenance_model_meta.json"

PROVENANCE_STATEMENT = (
    "egress traffic extracted from Mississippi State ICS testbed dataset, "
    "used as a simulated diode-observer view — never real diode capture data"
)


# --------------------------------------------------------------- F2 feature row (production)

def f2_row(si: SeriesIndex, w_index: int, train_normal_sorted: np.ndarray) -> dict[str, float] | None:
    """Single F2 (IEEE-754 bit-structure) feature row for one window's LAST
    own pressure sample, plus a trailing causal buffer for
    `mantissa_entropy_local`. Returns None (undefined) if the window has no
    own pressure sample. Feature order/names are identical to, and must
    stay identical to, `exp0032_admissible_ceiling_audit.F2_NAMES` — see
    the identity assertion below, which will fail loudly if that ever
    drifts rather than silently misaligning feature columns fed to the
    serialized model."""
    positions = si.positions_by_bucket.get(w_index)
    if not positions:
        return None
    last_pos = positions[-1]
    value = float(si.values[last_pos])

    exponent, mantissa_low, trailing_zero = ieee754_bits(np.array([value]))
    row: dict[str, float] = {
        "exponent": float(exponent[0]),
        "mantissa_low_bits": float(mantissa_low[0]),
        "trailing_zero_bits": float(trailing_zero[0]),
        "ulp_distance_to_train_normal": float(
            nearest_reference_distance(np.array([value]), train_normal_sorted)[0]
        ),
        "quantization_distance": float(
            quantization_grid_distance(np.array([value]), QUANTIZATION_STEPS)[0]
        ),
        "adc_lattice_distance": float(
            quantization_grid_distance(np.array([value]), ADC_LATTICE_STEPS)[0]
        ),
    }
    buf_start = max(0, last_pos - TRAILING_BUFFER_SAMPLES + 1)
    buffer = si.values[buf_start:last_pos + 1]
    _, buffer_mantissa_low, _ = ieee754_bits(buffer)
    row["mantissa_entropy_local"] = mantissa_low_bits_entropy(buffer_mantissa_low)

    assert list(row.keys()) == list(F2_NAMES), (
        "f2_row's feature order drifted from exp0032_admissible_ceiling_audit.F2_NAMES"
    )
    return row


# --------------------------------------------------------------- TRAIN-normal reference artifact

def build_train_normal_reference(si: SeriesIndex, blocks) -> np.ndarray:
    """Sorted, deduplicated raw float64 TRAIN-normal 0x03 pressure values.
    TRAIN-normal only, built from the frozen manifest split (`blocks`,
    an `exp0019_pressure_rate_plausibility.Blocks()` instance) — never
    TRAIN-attack, VAL, or TEST. This is `R`, the reference set used by
    `ulp_distance_to_train_normal` (min |value - r| over r in R)."""
    is_train_normal = np.array(
        [blocks.label(int(b)) == "train_normal" for b in si.bucket_by_pos], dtype=bool,
    )
    train_normal_values = si.values[is_train_normal]
    if len(train_normal_values) < 500:
        raise RuntimeError("too few TRAIN-normal samples for a reference distribution")
    return np.sort(np.unique(train_normal_values))


def save_reference(train_normal_sorted: np.ndarray, blocks, path: Path = REFERENCE_PATH) -> dict:
    """Persist the TRAIN-normal reference set as a versioned JSON artifact.

    To refresh: re-run `ml/exp0030c_cmri_production_wiring.py`'s
    `run_experiment()` (or call this function directly with a freshly-built
    `train_normal_sorted`/`blocks` pair) after TRAIN data or the manifest
    split changes; this OVERWRITES the artifact (unlike the TEST-scored-once
    ledgers elsewhere in this project, this is a TRAIN-only derived artifact
    that is safe and expected to be regenerated whenever TRAIN-normal data
    changes — it carries no TEST information and no scoring-once constraint
    applies to it)."""
    payload = {
        "schema_version": 1,
        "artifact": "exp0030c_train_normal_reference",
        "description": (
            "Sorted, deduplicated raw float64 TRAIN-normal egress 0x03 response "
            "pressure values (R). Used as the nearest-neighbour reference for "
            "ulp_distance_to_train_normal = min(|v - r| for r in R)."
        ),
        "provenance": PROVENANCE_STATEMENT,
        "split_id": blocks.split_id,
        "split_sha256": blocks.split_sha256,
        "n_values": int(len(train_normal_sorted)),
        "min": float(train_normal_sorted[0]),
        "max": float(train_normal_sorted[-1]),
        "values": [float(v) for v in train_normal_sorted],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return {"path": str(path), "n_values": payload["n_values"],
            "split_id": payload["split_id"], "split_sha256": payload["split_sha256"]}


def load_reference(path: Path = REFERENCE_PATH) -> np.ndarray:
    """Load the sorted, deduplicated TRAIN-normal reference set. Does NOT
    verify manifest identity itself (callers that care, e.g. `run_detector`,
    should compare `blocks.split_id`/`split_sha256` against the returned
    metadata via `load_reference_metadata` before trusting it for a fresh
    scoring run)."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    return np.asarray(payload["values"], dtype=float)


def load_reference_metadata(path: Path = REFERENCE_PATH) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in payload.items() if k != "values"}


# --------------------------------------------------------------- serialized model artifact

def save_model(clf, threshold: float, feature_names, model_path: Path = MODEL_PATH,
               metadata_path: Path = MODEL_METADATA_PATH) -> dict:
    """Serialize the fitted CMRI-only XGBoost classifier via XGBoost's own
    native JSON format (`Booster.save_model`, portable across xgboost
    versions per XGBoost's documented compatibility guarantee — preferred
    over joblib/pickle, which pin to a specific scikit-learn/xgboost/Python
    build). Threshold and feature names/order are stored in a small sidecar
    metadata JSON, since XGBoost's own save format does not carry either."""
    model_path.parent.mkdir(parents=True, exist_ok=True)
    # XGBoost infers its save FORMAT from the filename extension, so the
    # temp file must keep the same ".json" suffix (not ".json.tmp") or it
    # silently falls back to UBJSON, which `XGBClassifier.load_model` then
    # fails to parse as JSON.
    tmp_model = model_path.with_name(model_path.stem + ".tmp" + model_path.suffix)
    clf.save_model(str(tmp_model))
    os.replace(tmp_model, model_path)

    metadata = {
        "schema_version": 1,
        "artifact": "exp0030c_cmri_float_provenance_model",
        "description": (
            "CMRI-only XGBoost classifier over F2 (IEEE-754 bit-structure) "
            "features, fit on the TRAIN residual cohort missed by the "
            "currently-wired combined detector (protocol OR pressure OR rate "
            "OR IF), threshold fit on VAL to keep Normal FPR <= MAX_NORMAL_FPR."
        ),
        "provenance": PROVENANCE_STATEMENT,
        "model_path": str(model_path.relative_to(ROOT)) if model_path.is_relative_to(ROOT) else str(model_path),
        "threshold": float(threshold),
        "feature_names": list(feature_names),
        "xgboost_version": version("xgboost"),
        "python": platform.python_version(),
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
    }
    tmp_meta = metadata_path.with_suffix(metadata_path.suffix + ".tmp")
    tmp_meta.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_meta, metadata_path)
    return metadata


def load_model(model_path: Path = MODEL_PATH, metadata_path: Path = MODEL_METADATA_PATH):
    """Load the serialized CMRI-only classifier + threshold + feature order.
    Returns (clf: XGBClassifier, threshold: float, feature_names: list[str])."""
    from xgboost import XGBClassifier

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    current_sha256 = hashlib.sha256(model_path.read_bytes()).hexdigest()
    if current_sha256 != metadata["model_sha256"]:
        raise ValueError("exp0030c CMRI model file does not match its metadata checksum")
    clf = XGBClassifier()
    clf.load_model(str(model_path))
    return clf, float(metadata["threshold"]), list(metadata["feature_names"])
