#!/usr/bin/env python3
"""EXP-0023 — descriptive audit of the 14 undecoded `0x03` register-data bytes.

INVESTIGATIVE / DESCRIPTIVE ONLY. No detector, rule, model or threshold is built or
touched here. `run_detector`, `iforest_detector.py`, `features_windowed.py`, `rules.py`,
Layer A, `app.py` and all closed/prior EXP files are not imported for write access and
are not modified.

Frame layout (Modbus-RTU, verified against a live TXT/ARFF-aligned frame, see
`test_exp0023_...`): a canonical `0x03` egress read-response is 23 bytes —
`addr(1) func(1) byte_count(1)=18 register-data(18) crc(2)`. The 18-byte register-data
region is `frame[3:21]`. The last 4 bytes, `frame[17:21]`, are the previously decoded
big-endian float32 pressure measurement (EXP-0016, byte-for-byte verified against the
ARFF `pressure measurement` column). The first 14 bytes, `frame[3:17]`
(register-data offsets 0-13), are the undecoded region this experiment characterizes.

`source` is never parsed, read, or used anywhere in this file (F-02 rig artifact —
unobservable / forbidden, see DECISION_LOG.md). Egress is `destination == 1` only.
TRAIN/VALIDATION boundaries come only from the corrected manifest
`verified-egress-5s-exp0008-pretest-v1` via `exp0021_msci_mpci.Blocks`. TEST is not
read.
"""
from __future__ import annotations

import json
import math
import os
import platform
import struct
from collections import defaultdict
from importlib.metadata import version
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np

from exp0009_payload import ARFF_SHA256, RAW_ARFF, TXT_SHA256, _arff_data_rows, _parse_optional_float, _sha256
from exp0017_operational import load_result
from exp0021_msci_mpci import Blocks, EXP0017_TEST_CONFUSION, grade_effect
from features_txt import RAW_TXT

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments" / "exp0023_register_bytes.json"
)

CATEGORY_NAMES = ["Normal", "NMRI", "CMRI", "MSCI", "MPCI", "MFCI", "DoS", "Recon"]
WINDOW_SECONDS = 5.0
READ_RESPONSE_LEN = 23
FUNC_READ = 0x03

# register-data region is frame[3:21] (18 bytes); undecoded slice is frame[3:17]
REG_DATA_START = 3
REG_DATA_LEN = 18
UNDECODED_LEN = 14
PRESSURE_OFFSET_IN_REGDATA = 14  # frame[17:21] == pressure float32

# priority order for the attack-comparison stage (task step 5 / step 3 of the pre-reg)
CATEGORY_PRIORITY = ["MSCI", "MPCI", "NMRI", "CMRI", "MFCI", "DoS", "Recon"]
CATEGORY_INDEX = {name: i for i, name in enumerate(CATEGORY_NAMES)}


# --------------------------------------------------------------- byte extraction

def undecoded_bytes(frame: bytes) -> bytes | None:
    """Return the 14 undecoded register-data bytes, or None if not a canonical
    0x03 response."""
    if len(frame) != READ_RESPONSE_LEN or frame[1] != FUNC_READ:
        return None
    if frame[2] != REG_DATA_LEN:
        return None
    return frame[REG_DATA_START:REG_DATA_START + UNDECODED_LEN]


def pressure_bytes(frame: bytes) -> bytes:
    return frame[REG_DATA_START + PRESSURE_OFFSET_IN_REGDATA:REG_DATA_START + REG_DATA_LEN]


# --------------------------------------------------------------- scan

class Sample:
    __slots__ = ("bucket", "cat", "spec", "ts", "undecoded", "pressure", "pressure_from_bytes")

    def __init__(self, bucket: int, cat: int, spec: int, ts: float, undecoded: bytes,
                 pressure: float | None, pressure_from_bytes: float):
        self.bucket = bucket
        self.cat = cat
        self.spec = spec
        self.ts = ts
        self.undecoded = undecoded
        self.pressure = pressure
        self.pressure_from_bytes = pressure_from_bytes


class RegisterByteScan:
    """Result container for `scan_register_bytes()`: one verified TXT<->ARFF pass
    over egress 0x03 canonical responses, keeping the raw undecoded bytes."""

    def __init__(self) -> None:
        self.samples: list[Sample] = []
        self.egress_rows = 0
        self.egress_0x03_canonical = 0


def scan_register_bytes(*, txt_path: Path = RAW_TXT, arff_path: Path = RAW_ARFF) -> RegisterByteScan:
    """Single-pass TXT+ARFF reader (reads the raw hex frame directly, since
    `iter_records()` discards it after decoding the structural fields)."""
    if _sha256(txt_path) != TXT_SHA256:
        raise ValueError("TXT sha256 mismatch")
    if _sha256(arff_path) != ARFF_SHA256:
        raise ValueError("ARFF sha256 mismatch")
    scan = RegisterByteScan()

    rows = iter(_arff_data_rows(arff_path))
    sentinel = object()
    row_count = 0
    with txt_path.open("r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != 6:
                continue
            hexframe, cat, spec, src, dst, ts_s = parts
            try:
                frame = bytes.fromhex(hexframe)
                ts = float(ts_s)
                cat_i, spec_i = int(cat), int(spec)
                dst_i = int(dst)
            except ValueError:
                continue
            row = next(rows, sentinel)
            if row is sentinel:
                raise ValueError("ARFF has fewer rows than TXT")
            row_count += 1
            if dst_i != 1:
                continue
            if len(row) != 20:
                raise ValueError(f"ARFF row {row_count} has {len(row)} fields, expected 20")
            if (int(row[15]) != 0 or float(row[16]) != ts
                    or int(row[18]) != cat_i or int(row[19]) != spec_i):
                raise ValueError(f"TXT/ARFF alignment mismatch at row {row_count}")
            scan.egress_rows += 1
            ub = undecoded_bytes(frame)
            if ub is None:
                continue
            scan.egress_0x03_canonical += 1
            arff_pressure = _parse_optional_float(row[13])
            bucket = math.floor(ts / WINDOW_SECONDS)
            (p_bytes,) = struct.unpack(">f", pressure_bytes(frame))
            scan.samples.append(Sample(
                bucket=bucket, cat=cat_i, spec=spec_i, ts=ts, undecoded=ub,
                pressure=arff_pressure if arff_pressure is not None and math.isfinite(arff_pressure) else None,
                pressure_from_bytes=p_bytes,
            ))
        if next(rows, sentinel) is not sentinel:
            raise ValueError("ARFF has more rows than TXT")
    return scan


# --------------------------------------------------------------- per-byte stats

def byte_entropy_bits(values: Sequence[int]) -> float:
    if not values:
        return 0.0
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    n = len(values)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def audit_byte(offset: int, samples: Sequence[Sample]) -> dict:
    values = [s.undecoded[offset] for s in samples]
    distinct = sorted(set(values))
    n = len(values)
    entropy = byte_entropy_bits(values)
    is_constant = len(distinct) <= 1
    return {
        "offset": offset,
        "n": n,
        "n_distinct": len(distinct),
        "min": min(values) if values else None,
        "max": max(values) if values else None,
        "distinct_values_sample": distinct[:20],
        "entropy_bits": entropy,
        "is_constant": is_constant,
    }


def audit_register_pair(reg_idx: int, samples: Sequence[Sample]) -> dict:
    """Big-endian 16-bit register at undecoded-region byte offsets (2*reg_idx, 2*reg_idx+1)."""
    lo = 2 * reg_idx
    values = [(s.undecoded[lo] << 8) | s.undecoded[lo + 1] for s in samples]
    distinct = sorted(set(values))
    return {
        "register_index": reg_idx,
        "byte_offsets": [lo, lo + 1],
        "n": len(values),
        "n_distinct": len(distinct),
        "min": min(values) if values else None,
        "max": max(values) if values else None,
        "distinct_values_sample": distinct[:20],
        "is_constant": len(distinct) <= 1,
    }


def audit_float_candidate(offset: int, samples: Sequence[Sample]) -> dict:
    """Big-endian float32 candidate starting at undecoded-region byte `offset`
    (0 <= offset <= 10, so the 4-byte window stays inside the 14-byte region)."""
    values = []
    n_nan_inf = 0
    for s in samples:
        chunk = s.undecoded[offset:offset + 4]
        (f,) = struct.unpack(">f", chunk)
        if math.isfinite(f):
            values.append(f)
        else:
            n_nan_inf += 1
    if not values:
        return {"offset": offset, "n": 0, "n_finite": 0, "n_nan_inf": n_nan_inf}
    arr = np.asarray(values, dtype=float)
    return {
        "offset": offset,
        "n": len(values) + n_nan_inf,
        "n_finite": len(values),
        "n_nan_inf": n_nan_inf,
        "min": float(arr.min()),
        "max": float(arr.max()),
        "mean": float(arr.mean()),
        "std": float(arr.std(ddof=1)) if len(arr) > 1 else 0.0,
        "n_distinct": len(set(values)),
        "looks_plausible_measurement_range": bool(0.0 <= arr.min() and arr.max() < 1e6),
    }


def pearson(a: Sequence[float], b: Sequence[float]) -> float | None:
    if len(a) < 2 or len(b) < 2 or len(a) != len(b):
        return None
    a_arr, b_arr = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if a_arr.std() == 0 or b_arr.std() == 0:
        return None
    r = float(np.corrcoef(a_arr, b_arr)[0, 1])
    return r if math.isfinite(r) else None


def spearman(a: Sequence[float], b: Sequence[float]) -> float | None:
    if len(a) < 2 or len(b) < 2 or len(a) != len(b):
        return None
    a_rank = _rank(a)
    b_rank = _rank(b)
    return pearson(a_rank, b_rank)


def _rank(values: Sequence[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1
    return ranks


# --------------------------------------------------------------- per-window aggregation

def window_means(samples: Sequence[Sample], value_fn) -> dict[int, float]:
    """Mean of value_fn(sample) per w_index bucket."""
    acc: dict[int, list[float]] = defaultdict(list)
    for s in samples:
        acc[s.bucket].append(value_fn(s))
    return {b: float(np.mean(v)) for b, v in acc.items() if v}


def build_bucket_cats(blocks: Blocks, samples: Sequence[Sample]) -> dict[int, set[int]]:
    """bucket -> set of categorized_attack values seen, restricted to TRAIN+VAL.
    Computed once and reused across every field's `category_cohens_d` call."""
    scope = blocks.train | blocks.validation
    bucket_cats: dict[int, set[int]] = defaultdict(set)
    for s in samples:
        if s.bucket in scope:
            bucket_cats[s.bucket].add(s.cat)
    return bucket_cats


def _pstdev_d(a: Sequence[float], b: Sequence[float]) -> float:
    a_arr, b_arr = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if len(a_arr) < 2 or len(b_arr) < 2:
        return 0.0
    pooled = math.sqrt((a_arr.std(ddof=0) ** 2 + b_arr.std(ddof=0) ** 2) / 2.0)
    if pooled == 0.0:
        return 0.0
    return float((a_arr.mean() - b_arr.mean()) / pooled)


def category_cohens_d(field_by_window: Mapping[int, float],
                       bucket_cats: Mapping[int, set[int]]) -> dict:
    """Cohen's d (population-SD, EXP-0014/0015 convention) between pure-category
    windows and (a) full pure-Normal windows and (b) nearest-index matched
    pure-Normal windows, for TRAIN+VALIDATION only (`bucket_cats` is already scoped)."""
    import bisect

    pure_normal_buckets = sorted(b for b, cats in bucket_cats.items()
                                  if cats == {0} and b in field_by_window)
    normal_vals_full = [field_by_window[b] for b in pure_normal_buckets]

    out: dict[str, dict] = {}
    for cat_name in CATEGORY_PRIORITY:
        cat_id = CATEGORY_INDEX[cat_name]
        pure_buckets = sorted(b for b, cats in bucket_cats.items()
                               if cats == {cat_id} and b in field_by_window)
        if not pure_buckets:
            out[cat_name] = {"n_windows": 0, "note": "no pure windows with this field observed"}
            continue
        attack_vals = [field_by_window[b] for b in pure_buckets]
        d_full = _pstdev_d(attack_vals, normal_vals_full) if normal_vals_full else 0.0
        # nearest-index matched pure-Normal (bisect — EXP-0015 convention)
        matched_vals = []
        if pure_normal_buckets:
            for b in pure_buckets:
                pos = bisect.bisect_left(pure_normal_buckets, b)
                candidates = [p for p in (pos, pos - 1) if 0 <= p < len(pure_normal_buckets)]
                best = min(candidates, key=lambda p: abs(pure_normal_buckets[p] - b))
                matched_vals.append(field_by_window[pure_normal_buckets[best]])
        d_matched = _pstdev_d(attack_vals, matched_vals) if matched_vals else 0.0
        out[cat_name] = {
            "n_windows": len(pure_buckets),
            "attack_mean": float(np.mean(attack_vals)),
            "attack_std": float(np.std(attack_vals, ddof=0)),
            "cohens_d_vs_full_normal": d_full,
            "cohens_d_vs_matched_normal": d_matched,
            "grade_full": grade_effect(d_full),
            "grade_matched": grade_effect(d_matched),
        }
    out["_normal_n_windows"] = len(pure_normal_buckets)
    return out


# --------------------------------------------------------------- main experiment

def run_experiment() -> dict:
    # ---- identity gate: EXP-0017 reproduced from its checksummed artifact ----
    result = load_result()
    comb = np.array(result.protocol_pred) | np.array(result.pressure_pred) | np.array(result.if_pred)
    assert np.array_equal(comb, np.array(result.comb_pred)), "comb reproduction mismatch"
    y = np.array(result.y_test)
    tn = int(np.sum((comb == 0) & (y == 0)))
    fp = int(np.sum((comb == 1) & (y == 0)))
    fn = int(np.sum((comb == 0) & (y == 1)))
    tp = int(np.sum((comb == 1) & (y == 1)))
    identity_ok = (tn, fp, fn, tp) == EXP0017_TEST_CONFUSION

    if not identity_ok:
        raise ValueError(f"EXP-0017 identity gate FAILED: got {(tn, fp, fn, tp)}, "
                          f"expected {EXP0017_TEST_CONFUSION}")

    blocks = Blocks()
    scan = scan_register_bytes()

    # ---- sanity: pressure bytes reproduce ARFF, on every egress 0x03 canonical
    # Normal-category row with a non-missing ARFF pressure value (offset-math
    # ground truth). Attack-category rows are deliberately excluded: under CMRI
    # /MSCI/MPCI injection the pressure register is attacker-falsified, so the
    # decoded float and the ARFF value can legitimately disagree there — that is
    # the phenomenon under study elsewhere (EXP-0016/0019), not an offset bug.
    # Tolerance is 1e-4 relative, matching the ARFF text field's ~6-significant-
    # digit precision (float32 has ~7), not float64 exactness.
    pressure_checked = 0
    pressure_mismatches = 0
    for s in scan.samples:
        if s.pressure is None or s.cat != 0:
            continue
        pressure_checked += 1
        if not math.isclose(s.pressure_from_bytes, s.pressure, rel_tol=1e-4, abs_tol=1e-4):
            pressure_mismatches += 1
    if pressure_checked == 0 or pressure_mismatches > 0:
        raise ValueError(
            f"pressure-offset sanity check FAILED: checked={pressure_checked}, "
            f"mismatches={pressure_mismatches} — frame layout is ambiguous, stopping "
            "rather than guessing"
        )

    train_normal_buckets = blocks.train & blocks.pure_normal
    train_normal_samples = [s for s in scan.samples if s.bucket in train_normal_buckets]

    per_byte = [audit_byte(off, train_normal_samples) for off in range(UNDECODED_LEN)]
    per_register = [audit_register_pair(i, train_normal_samples) for i in range(UNDECODED_LEN // 2)]
    per_float_offset = [audit_float_candidate(off, train_normal_samples) for off in range(0, UNDECODED_LEN - 3)]

    # correlate every non-constant byte with pressure (where present) and time
    non_constant_bytes = [b["offset"] for b in per_byte if not b["is_constant"]]
    correlations = {}
    for off in non_constant_bytes:
        vals = [s.undecoded[off] for s in train_normal_samples]
        press = [s.pressure for s in train_normal_samples]
        have_press = [(v, p) for v, p in zip(vals, press) if p is not None]
        ts = [s.ts for s in train_normal_samples]
        correlations[off] = {
            "pearson_vs_pressure": pearson([v for v, _ in have_press], [p for _, p in have_press]) if have_press else None,
            "spearman_vs_pressure": spearman([v for v, _ in have_press], [p for _, p in have_press]) if have_press else None,
            "pearson_vs_time": pearson(vals, ts),
            "n_with_pressure": len(have_press),
        }

    # bucket -> categories seen (TRAIN+VAL scope), computed once and reused below
    bucket_cats = build_bucket_cats(blocks, scan.samples)

    # attack comparison for every non-constant byte (task step 3/5): window-mean value
    attack_comparison = {}
    for off in non_constant_bytes:
        field_by_window = window_means(scan.samples, lambda s, o=off: s.undecoded[o])
        attack_comparison[off] = category_cohens_d(field_by_window, bucket_cats)

    # also run the register-pair and float-offset candidates through the same
    # attack-comparison machinery if they show variation beyond their constant bytes
    register_attack_comparison = {}
    for reg in per_register:
        if reg["is_constant"]:
            continue
        idx = reg["register_index"]
        field_by_window = window_means(
            scan.samples, lambda s, i=idx: (s.undecoded[2 * i] << 8) | s.undecoded[2 * i + 1])
        register_attack_comparison[idx] = category_cohens_d(field_by_window, bucket_cats)

    float_attack_comparison = {}
    for f in per_float_offset:
        if f.get("n_distinct", 0) <= 1:
            continue
        off = f["offset"]

        def _val(s, o=off):
            (v,) = struct.unpack(">f", s.undecoded[o:o + 4])
            return v if math.isfinite(v) else 0.0
        field_by_window = window_means(scan.samples, _val)
        float_attack_comparison[off] = category_cohens_d(field_by_window, bucket_cats)

    return {
        "experiment": "EXP-0023",
        "status": "TESTED",
        "identity_gates": {
            "exp0017_reproduced": identity_ok,
            "exp0017_confusion": [tn, fp, fn, tp],
            "expected_confusion": list(EXP0017_TEST_CONFUSION),
            "split_id": blocks.split_id,
            "split_sha256": blocks.split_sha256,
        },
        "scan_counts": {
            "egress_rows": scan.egress_rows,
            "egress_0x03_canonical_responses": scan.egress_0x03_canonical,
            "train_normal_canonical_samples": len(train_normal_samples),
        },
        "pressure_offset_sanity_check": {
            "n_checked_against_arff": pressure_checked,
            "n_mismatches": pressure_mismatches,
            "all_match": pressure_mismatches == 0,
        },
        "per_byte_train_normal": per_byte,
        "per_register_pair_train_normal": per_register,
        "per_float_offset_train_normal": per_float_offset,
        "non_constant_byte_offsets": non_constant_bytes,
        "correlations_train_normal": correlations,
        "attack_comparison_per_byte": attack_comparison,
        "attack_comparison_per_register_pair": register_attack_comparison,
        "attack_comparison_per_float_offset": float_attack_comparison,
        "environment": {
            "python": platform.python_version(),
            "numpy": version("numpy"),
        },
    }


# --------------------------------------------------------------- I/O

def _json_ready(value):
    if isinstance(value, dict):
        return {str(k): _json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_ready(v) for v in value]
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, np.ndarray):
        return _json_ready(value.tolist())
    return value


def write_result_atomic(result: Mapping, path: Path = RESULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w") as fh:
        json.dump(_json_ready(result), fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(json.dumps(_json_ready(result), indent=2, sort_keys=True)[:4000])


if __name__ == "__main__":
    main()
