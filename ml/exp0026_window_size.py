#!/usr/bin/env python3
"""EXP-0026 — does a natively longer observation window reveal MSCI/MPCI
pressure-consequence separation that the fixed 5-second window dilutes?

**Descriptive/diagnostic first.** This is a NEW, SEPARATE pipeline variant. It
does NOT modify, import for construction, or call the existing 5-second
production pipeline: `ml/features_windowed.py` and `ml/iforest_detector.run_detector`
are untouched. `exp0021_msci_mpci.Blocks`/`cohens_d`/`grade_effect` are imported
READ-ONLY, exactly as the pre-registration's step 3 asked ("reuse EXP-0014/0021's
feature definitions").

Different question than EXP-0021's episode aggregation: instead of aggregating
several already-built 5s windows AFTER the fact (tied to variable-length
attack-label episodes), this rebuilds the observation unit natively at a fixed
longer duration BEFORE any feature is computed, testing window sizes 5s
(baseline), 15s, 30s, 60s.

Feature scope (disclosed in the pre-registration): EXP-0021's five pressure
features only (`p_std`, `p_range`, `p_max_abs_step`, `p_trend_abs`,
`p_mean_shift`) — EXP-0014 already established MSCI/MPCI write frames are
byte-identical to Normal writes, so protocol/rate/entropy features are
structurally invariant to window size and are not re-explored here.

Split-boundary rule: a native window of size W comprises `n5 = W/5` consecutive
5-second buckets; it is DISCARDED ENTIRELY (never truncated) unless every one
of those `n5` bucket ids belongs to the SAME manifest block (all TRAIN, all
VALIDATION, or all TEST). This also discards windows crossing the manifest's
own internal TRAIN/VALIDATION gaps. No frame or feature value is ever computed
from a partial-duration window.

See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0026, 2026-09-12) for the full
pre-registration, decision bar, and gate.
"""
from __future__ import annotations

import json
import math
import os
import platform
from collections import defaultdict
from importlib.metadata import version
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np

from exp0009_payload import (
    ARFF_SHA256, RAW_ARFF, TXT_SHA256, _arff_data_rows, _parse_optional_float, _sha256,
)
from exp0021_msci_mpci import Blocks, cohens_d, grade_effect
from features_txt import RAW_TXT, iter_records

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments" / "exp0026_window_size.json"
)
CATEGORY_NAMES = ["Normal", "NMRI", "CMRI", "MSCI", "MPCI", "MFCI", "DoS", "Recon"]
CATEGORIES = {"MSCI": 3, "MPCI": 4}
BASE_WINDOW_SECONDS = 5.0
READ_RESPONSE = (0x03, 23, 0)  # function_code, frame_len_bytes, is_request
PRESSURE_COL = 13

FEATURE_NAMES = ("p_std", "p_range", "p_max_abs_step", "p_trend_abs", "p_mean_shift")

# ---- pre-registered constants ----
WINDOW_SIZES_SECONDS = (5.0, 15.0, 30.0, 60.0)
GATE_MIN_ABS_D = 0.5
GATE_MIN_N_PURE_ATTACK = 30
# EXP-0021 saved reference (TRAIN+VALIDATION, window-level, not episode-level),
# reproduced here as a 5s-baseline consistency check before trusting new sizes.
EXP0021_WINDOW_LEVEL_REFERENCE = {
    "MSCI": {"p_std": 0.144, "p_range": 0.144, "p_max_abs_step": 0.144,
             "p_trend_abs": 0.144, "p_mean_shift": 0.245},
    "MPCI": {"p_std": 0.242, "p_range": 0.242, "p_max_abs_step": 0.242,
             "p_trend_abs": 0.242, "p_mean_shift": 0.263},
}
REFERENCE_TOLERANCE = 0.01  # absolute Cohen's d difference allowed at 5s baseline


# --------------------------------------------------------------- scan

class Scan:
    """One verified TXT<->ARFF pass, TRAIN+VALIDATION+TEST scope (5s-bucket
    membership decided later, per candidate window size)."""

    def __init__(self) -> None:
        self.egress_rows = 0
        # 5s-bucket -> set of categorized_attack values seen (any egress frame)
        self.categories_by_5s_bucket: dict[int, set[int]] = defaultdict(set)
        # 5s-bucket -> [(timestamp, pressure)] for canonical 0x03 responses
        self.pressure_by_5s_bucket: dict[int, list[tuple[float, float]]] = defaultdict(list)


def bucket5_of(ts: float) -> int:
    return math.floor(ts / BASE_WINDOW_SECONDS)


def scan_egress(*, txt_path: Path = RAW_TXT, arff_path: Path = RAW_ARFF) -> Scan:
    if _sha256(txt_path) != TXT_SHA256:
        raise ValueError("TXT sha256 mismatch")
    if _sha256(arff_path) != ARFF_SHA256:
        raise ValueError("ARFF sha256 mismatch")
    scan = Scan()
    rows = _arff_data_rows(arff_path)
    sentinel = object()
    row_iterator = iter(rows)
    row_count = 0
    for record in iter_records(txt_path):
        row = next(row_iterator, sentinel)
        if row is sentinel:
            raise ValueError("ARFF has fewer rows than TXT")
        row_count += 1
        if record.record_index != row_count:
            raise ValueError(f"TXT row index mismatch at row {row_count}")
        if record.destination != 1:
            continue
        if len(row) != 20:
            raise ValueError(f"ARFF row {row_count} has {len(row)} fields, expected 20")
        if (int(row[15]) != 0 or float(row[16]) != record.timestamp
                or int(row[18]) != record.categorized_attack
                or int(row[19]) != record.specific_attack):
            raise ValueError(f"TXT/ARFF alignment mismatch at row {row_count}")
        scan.egress_rows += 1
        b5 = bucket5_of(record.timestamp)
        scan.categories_by_5s_bucket[b5].add(record.categorized_attack)
        if (record.function_code, record.frame_len_bytes, record.is_request) == READ_RESPONSE:
            value = _parse_optional_float(row[PRESSURE_COL])
            if value is not None and math.isfinite(value):
                scan.pressure_by_5s_bucket[b5].append((float(record.timestamp), float(value)))
    if next(row_iterator, sentinel) is not sentinel:
        raise ValueError("ARFF has more rows than TXT")
    return scan


# --------------------------------------------------------------- native windows

class NativeWindow:
    __slots__ = ("nb_index", "categories", "pressure")

    def __init__(self, nb_index: int, categories: frozenset[int],
                 pressure: list[tuple[float, float]]) -> None:
        self.nb_index = nb_index
        self.categories = categories
        self.pressure = pressure


def native_block_label(nb_index: int, n5: int, blocks: Blocks) -> str | None:
    """The manifest block ('train'/'validation'/'test') this native window
    belongs to, or None if it must be discarded (spans a boundary or gap)."""
    sub = range(nb_index * n5, nb_index * n5 + n5)
    if all(b in blocks.train for b in sub):
        return "train"
    if all(b in blocks.validation for b in sub):
        return "validation"
    if all(b in blocks.test for b in sub):
        return "test"
    return None


def build_native_windows(
    scan: Scan, blocks: Blocks, window_seconds: float,
) -> tuple[dict[str, list[NativeWindow]], int]:
    """Native windows grouped by block label ('train'/'validation'/'test');
    returns (by_block, n_discarded). Every included window has the FULL native
    duration — no truncation."""
    n5 = int(round(window_seconds / BASE_WINDOW_SECONDS))
    if n5 * BASE_WINDOW_SECONDS != window_seconds:
        raise ValueError(f"window_seconds={window_seconds} is not a multiple of {BASE_WINDOW_SECONDS}")

    all_5s_buckets = sorted(
        set(scan.categories_by_5s_bucket) | set(scan.pressure_by_5s_bucket)
    )
    native_ids = sorted({b // n5 for b in all_5s_buckets})

    by_block: dict[str, list[NativeWindow]] = defaultdict(list)
    n_discarded = 0
    for nb in native_ids:
        label = native_block_label(nb, n5, blocks)
        if label is None:
            n_discarded += 1
            continue
        sub = range(nb * n5, nb * n5 + n5)
        cats: set[int] = set()
        pressure: list[tuple[float, float]] = []
        for b5 in sub:
            cats |= scan.categories_by_5s_bucket.get(b5, set())
            pressure.extend(scan.pressure_by_5s_bucket.get(b5, ()))
        if not cats:
            # no egress frame at all in this native window's span -> not a real window
            n_discarded += 1
            continue
        by_block[label].append(NativeWindow(nb, frozenset(cats), sorted(pressure)))
    for label in by_block:
        by_block[label].sort(key=lambda w: w.nb_index)
    return dict(by_block), n_discarded


# --------------------------------------------------------------- features

def native_window_features(
    window: NativeWindow, preceding_by_index: Mapping[int, NativeWindow],
) -> dict[str, float] | None:
    """EXP-0021's five pressure features, computed from this native window's OWN
    pressure samples. None if fewer than two samples (dispersion undefined),
    matching EXP-0021's own rule. `p_mean_shift` is versus the mean pressure of
    the immediately preceding native window of the SAME size (0.0 if that
    window has no pressure samples), generalizing EXP-0021's "no prior data"
    convention from episode-relative to native-window-relative.
    """
    samples = window.pressure
    if len(samples) < 2:
        return None
    times = np.array([t for t, _ in samples], dtype=float)
    values = np.array([p for _, p in samples], dtype=float)
    steps = np.abs(np.diff(values))
    slope = 0.0
    if times.max() > times.min():
        slope = float(np.polyfit(times - times.min(), values, 1)[0])
    prev = preceding_by_index.get(window.nb_index - 1)
    prior_values = [p for _, p in prev.pressure] if prev is not None else []
    shift = abs(float(values.mean()) - float(np.mean(prior_values))) if prior_values else 0.0
    return {
        "p_std": float(values.std()),
        "p_range": float(values.max() - values.min()),
        "p_max_abs_step": float(steps.max()) if steps.size else 0.0,
        "p_trend_abs": abs(slope),
        "p_mean_shift": shift,
    }


def _containing(windows: Sequence[NativeWindow], cat: int) -> list[NativeWindow]:
    """Any window with >=1 frame of this category, regardless of what else co-
    occurs in it. Matches EXP-0021's window-level cohort exactly (its `episode`
    membership test is specific-attack-id-based, but those ids are each unique
    to one categorized_result, so this is the same population)."""
    return [w for w in windows if cat in w.categories]


def _pure(windows: Sequence[NativeWindow], cat: int) -> list[NativeWindow]:
    """Windows with >=1 frame of this category and no OTHER attack category
    co-occurring (Normal co-occurrence is fine). EXP-0014's cohort — reported
    alongside `_containing` as secondary context, not the primary comparison,
    since it is a stricter/different population."""
    return [w for w in windows if cat in w.categories and w.categories <= {0, cat}]


def _pure_normal(windows: Sequence[NativeWindow]) -> list[NativeWindow]:
    return [w for w in windows if w.categories == frozenset({0})]


# --------------------------------------------------------------- per-size analysis

def analyse_window_size(scan: Scan, blocks: Blocks, window_seconds: float) -> dict:
    by_block, n_discarded = build_native_windows(scan, blocks, window_seconds)
    train_and_val = list(by_block.get("train", [])) + list(by_block.get("validation", []))
    train_and_val.sort(key=lambda w: w.nb_index)
    by_index = {w.nb_index: w for w in train_and_val}

    pure_normal = _pure_normal(train_and_val)
    normal_feats: dict[str, list[float]] = defaultdict(list)
    for w in pure_normal:
        f = native_window_features(w, by_index)
        if f:
            for name in FEATURE_NAMES:
                normal_feats[name].append(f[name])

    per_category: dict[str, dict] = {}
    for cat_name, cat_id in CATEGORIES.items():
        containing = _containing(train_and_val, cat_id)
        pure = _pure(train_and_val, cat_id)

        def _feats(windows: Sequence[NativeWindow]) -> dict[str, list[float]]:
            out: dict[str, list[float]] = defaultdict(list)
            for w in windows:
                f = native_window_features(w, by_index)
                if f:
                    for name in FEATURE_NAMES:
                        out[name].append(f[name])
            return out

        containing_feats = _feats(containing)
        pure_feats = _feats(pure)

        feature_rows = []
        for name in FEATURE_NAMES:
            a, b = containing_feats[name], normal_feats[name]
            d = cohens_d(a, b)
            d_pure = cohens_d(pure_feats[name], normal_feats[name])
            feature_rows.append({
                "feature": name,
                "n_attack_containing": len(a), "n_normal": len(b),
                "attack_mean": float(np.mean(a)) if a else None,
                "normal_mean": float(np.mean(b)) if b else None,
                "cohens_d": d, "effect": grade_effect(d),
                "clears_gate": bool(abs(d) >= GATE_MIN_ABS_D and len(a) >= GATE_MIN_N_PURE_ATTACK),
                "n_attack_pure": len(pure_feats[name]),
                "cohens_d_pure_cohort": d_pure,
                "effect_pure_cohort": grade_effect(d_pure),
            })

        per_category[cat_name] = {
            "cohort_note": (
                "primary comparison ('containing') matches EXP-0021's window-level "
                "cohort: any window with >=1 frame of this category, regardless of "
                "co-occurring categories. 'pure' (EXP-0014's cohort: no OTHER attack "
                "category co-occurring) is reported alongside as secondary context."
            ),
            "n_containing_windows_with_features": len(containing_feats[FEATURE_NAMES[0]]) if containing_feats else 0,
            "n_containing_windows_total": len(containing),
            "n_pure_windows_total": len(pure),
            "features": feature_rows,
        }

    return {
        "window_seconds": window_seconds,
        "n5_base_buckets_per_window": int(round(window_seconds / BASE_WINDOW_SECONDS)),
        "n_native_windows_train": len(by_block.get("train", [])),
        "n_native_windows_validation": len(by_block.get("validation", [])),
        "n_native_windows_discarded_boundary_or_empty": n_discarded,
        "n_pure_normal_windows_with_features": len(normal_feats[FEATURE_NAMES[0]]) if normal_feats else 0,
        "per_category": per_category,
    }


def five_second_baseline_check(result_5s: dict) -> dict:
    """Consistency check against EXP-0021's saved window-level Cohen's d
    (TRAIN+VALIDATION, pooled) — must reproduce closely before trusting the
    new window sizes at all."""
    checks = []
    ok = True
    for cat_name, ref_features in EXP0021_WINDOW_LEVEL_REFERENCE.items():
        rows = {r["feature"]: r["cohens_d"] for r in result_5s["per_category"][cat_name]["features"]}
        for feat_name, ref_d in ref_features.items():
            got_d = rows[feat_name]
            diff = abs(got_d - ref_d)
            passed = diff <= REFERENCE_TOLERANCE
            ok = ok and passed
            checks.append({
                "category": cat_name, "feature": feat_name,
                "exp0021_reference_d": ref_d, "exp0026_5s_d": got_d,
                "abs_diff": diff, "within_tolerance": passed,
            })
    return {"tolerance": REFERENCE_TOLERANCE, "all_within_tolerance": ok, "checks": checks}


# --------------------------------------------------------------- gate

def decision_gate(by_size: dict[float, dict]) -> dict:
    passing = []
    for w, result in by_size.items():
        if w == BASE_WINDOW_SECONDS:
            continue  # baseline is the reference, not a candidate to "pass"
        for cat_name, cat_result in result["per_category"].items():
            for row in cat_result["features"]:
                if row["clears_gate"]:
                    passing.append({
                        "window_seconds": w, "category": cat_name,
                        "feature": row["feature"], "cohens_d": row["cohens_d"],
                        "n_attack": row["n_attack_containing"],
                    })
    return {
        "rule": f"|Cohen's d| >= {GATE_MIN_ABS_D} AND n_containing_attack_windows >= "
                f"{GATE_MIN_N_PURE_ATTACK}, at some (window size > 5s, category, feature)",
        "passing_triples": passing,
        "passed": bool(passing),
        "consequence": ("build and evaluate a standalone detector at the best "
                        "passing window size" if passing else
                        "STOP — no detector built; descriptive findings only"),
    }


# --------------------------------------------------------------- experiment

def run_experiment() -> dict:
    scan = scan_egress()
    blocks = Blocks()

    by_size = {}
    for w in WINDOW_SIZES_SECONDS:
        by_size[w] = analyse_window_size(scan, blocks, w)

    baseline_check = five_second_baseline_check(by_size[BASE_WINDOW_SECONDS])
    gate = decision_gate(by_size)

    return {
        "status": "TESTED" if baseline_check["all_within_tolerance"] else "TESTED — BASELINE CHECK FAILED",
        "experiment": "EXP-0026",
        "scope": "egress only (destination == 1); MSCI/MPCI vs Normal; TRAIN+VALIDATION only",
        "does_not_modify": ["ml/features_windowed.py", "ml/iforest_detector.run_detector",
                            "the 5s production pipeline"],
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "window_sizes_seconds": list(WINDOW_SIZES_SECONDS),
        "feature_scope_note": (
            "EXP-0021's five pressure features only, computed natively per window "
            "(not EXP-0014's 16 protocol/rate/entropy features -- those are "
            "structurally invariant to window size, per EXP-0014's own finding "
            "that MSCI/MPCI writes are byte-identical to Normal writes)."
        ),
        "five_second_baseline_consistency_check": baseline_check,
        "by_window_size": {str(w): r for w, r in by_size.items()},
        "decision_gate": gate,
        "software": {"python": platform.python_version(), "numpy": version("numpy")},
        "limitations": [
            "Pressure is the ARFF-aligned value, not a live 0x03 byte decode.",
            "Native windows are fixed-grid, not aligned to attack-episode "
            "boundaries the way EXP-0021's episode aggregation was -- a native "
            "window can start/end mid-episode, which this experiment does not "
            "correct for.",
            "The 5s baseline consistency check compares against EXP-0021's saved "
            "numbers to 0.01 absolute tolerance; small discrepancies could arise "
            "from independent re-derivation even if both are correct.",
            "One testbed; egress-only; TRAIN+VALIDATION only until (and unless) "
            "the pre-registered gate passes.",
        ],
    }


# --------------------------------------------------------------- io

def _json_ready(value):
    if isinstance(value, Mapping):
        return {k: _json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_ready(v) for v in value]
    if isinstance(value, np.generic):
        return _json_ready(value.item())
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def write_result_atomic(result: Mapping, path: Path = RESULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(_json_ready(result), indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _format_report(r: Mapping) -> str:
    lines = [
        "# EXP-0026 — native window-size exploration for MSCI/MPCI pressure separation",
        "",
        f"Status: {r['status']}",
        "",
        "## 5s-baseline consistency check (vs EXP-0021's saved window-level d)",
        f"All within {r['five_second_baseline_consistency_check']['tolerance']} tolerance: "
        f"{r['five_second_baseline_consistency_check']['all_within_tolerance']}",
        "",
    ]
    for w_str, result in r["by_window_size"].items():
        lines += [
            f"## window = {w_str}s "
            f"(TRAIN {result['n_native_windows_train']}, VALIDATION "
            f"{result['n_native_windows_validation']}, discarded "
            f"{result['n_native_windows_discarded_boundary_or_empty']})",
            "",
            "| category | feature | n containing | n normal | d | effect | n pure | d (pure) | gate |",
            "|---|---|---:|---:|---:|---|---:|---:|---|",
        ]
        for cat_name, cat_result in result["per_category"].items():
            for row in cat_result["features"]:
                lines.append(
                    f"| {cat_name} | {row['feature']} | {row['n_attack_containing']} | {row['n_normal']} "
                    f"| {row['cohens_d']:+.3f} | {row['effect']} | {row['n_attack_pure']} "
                    f"| {row['cohens_d_pure_cohort']:+.3f} | "
                    f"{'PASS' if row['clears_gate'] else '-'} |"
                )
        lines.append("")
    lines += [
        f"## Decision gate: {'PASSED' if r['decision_gate']['passed'] else 'NOT PASSED'}",
        f"- {r['decision_gate']['rule']}",
        f"- {r['decision_gate']['consequence']}",
    ]
    return "\n".join(lines)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(_format_report(result))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
