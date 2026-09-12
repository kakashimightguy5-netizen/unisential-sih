#!/usr/bin/env python3
"""EXP-0027 — does EXP-0026's MSCI 60s `p_std` pure-cohort effect survive
against the REALISTIC evaluation population?

EXP-0026 disclosed, as an explicitly non-gate-authorized secondary finding,
that MSCI's "pure" 60s native windows (no OTHER attack category co-occurring)
show a large `p_std` effect vs pure-Normal (d=1.426). A user-requested
diagnostic (not committed as an experiment) then verified this was not a
small-n artifact: broad (not outlier-driven), stable under bootstrap
resampling (95% CI (1.12, 1.75)), spread across 74 distinct episodes.

The open question EXP-0026 flagged: the "pure" cohort excludes any MSCI window
that also contains a co-occurring attack category — a real deployment cannot
know in advance which windows are "pure," so this experiment re-measures the
SAME feature against the REALISTIC population (every MSCI-containing window,
pure + mixed) to check whether the effect is a selection artifact or survives.

Descriptive/diagnostic first: no detector is built unless the pre-registered
gate passes. `ml/features_windowed.py`, `ml/iforest_detector.run_detector`,
and `ml/exp0026_window_size.py` are all imported/reused READ-ONLY, never
modified. See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0027, 2026-09-12) for
the full pre-registration.
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

from exp0021_msci_mpci import Blocks, cohens_d, grade_effect
from exp0026_window_size import (
    CATEGORY_NAMES,
    NativeWindow,
    _containing,
    _pure,
    _pure_normal,
    build_native_windows,
    native_window_features,
    scan_egress,
)

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0027_msci_realistic_population.json"
)
MSCI_CATEGORY = 3
WINDOW_SECONDS = 60.0  # the size EXP-0026's pure-cohort finding was measured at
FEATURE = "p_std"

# ---- pre-registered constants (same bar as EXP-0021/0026, not weakened) ----
GATE_MIN_ABS_D = 0.5
GATE_MIN_N = 30
# EXP-0026's saved 60s pure-cohort reference, reproduced here as an identity check.
EXP0026_PURE_COHORT_D_REFERENCE = 1.426
REFERENCE_TOLERANCE = 0.01


# --------------------------------------------------------------- populations

def other_category_of(window: NativeWindow) -> frozenset[int]:
    """Attack categories in this window OTHER than MSCI and Normal."""
    return frozenset(c for c in window.categories if c not in (0, MSCI_CATEGORY))


def split_containing_into_pure_and_mixed(
    containing: Sequence[NativeWindow],
) -> tuple[list[NativeWindow], list[NativeWindow]]:
    pure, mixed = [], []
    for w in containing:
        (pure if not other_category_of(w) else mixed).append(w)
    return pure, mixed


def feature_values(
    windows: Sequence[NativeWindow], by_index: Mapping[int, NativeWindow], feature: str = FEATURE,
) -> np.ndarray:
    out = []
    for w in windows:
        f = native_window_features(w, by_index)
        if f is not None:
            out.append(f[feature])
    return np.array(out, dtype=float)


# --------------------------------------------------------------- analysis

def run_analysis() -> dict:
    scan = scan_egress()
    blocks = Blocks()
    by_block, n_discarded = build_native_windows(scan, blocks, WINDOW_SECONDS)
    train_and_val = list(by_block.get("train", [])) + list(by_block.get("validation", []))
    train_and_val.sort(key=lambda w: w.nb_index)
    by_index = {w.nb_index: w for w in train_and_val}

    pure_normal = _pure_normal(train_and_val)
    normal_values = feature_values(pure_normal, by_index)

    pure_msci = _pure(train_and_val, MSCI_CATEGORY)
    containing_msci = _containing(train_and_val, MSCI_CATEGORY)
    pure_check, mixed = split_containing_into_pure_and_mixed(containing_msci)
    # `_pure` (categories <= {0, cat}) and the "no other category" split above
    # must select the identical population -- cross-checked, not assumed.
    if {w.nb_index for w in pure_check} != {w.nb_index for w in pure_msci}:
        raise RuntimeError("pure-cohort re-derivation mismatch vs exp0026._pure")

    pure_values = feature_values(pure_msci, by_index)
    containing_values = feature_values(containing_msci, by_index)
    mixed_values = feature_values(mixed, by_index)

    d_pure = cohens_d(pure_values, normal_values)
    d_containing = cohens_d(containing_values, normal_values)
    d_mixed = cohens_d(mixed_values, normal_values) if mixed_values.size else None

    identity_check = {
        "exp0026_reference_d": EXP0026_PURE_COHORT_D_REFERENCE,
        "reproduced_d": d_pure,
        "abs_diff": abs(d_pure - EXP0026_PURE_COHORT_D_REFERENCE),
        "within_tolerance": abs(d_pure - EXP0026_PURE_COHORT_D_REFERENCE) <= REFERENCE_TOLERANCE,
    }

    # co-occurring-category breakdown of the "mixed" windows
    by_other_cat: dict[str, list[NativeWindow]] = defaultdict(list)
    for w in mixed:
        others = sorted(other_category_of(w))
        label = "+".join(CATEGORY_NAMES[c] for c in others)
        by_other_cat[label].append(w)

    breakdown = []
    for label, windows in sorted(by_other_cat.items()):
        values = feature_values(windows, by_index)
        breakdown.append({
            "co_occurring_categories": label,
            "n_windows": len(windows),
            "n_with_features": int(values.size),
            "p_std_mean": float(values.mean()) if values.size else None,
            "p_std_median": float(np.median(values)) if values.size else None,
            "n_huge_gt_1e6": int((values > 1e6).sum()) if values.size else 0,
        })

    # Additional, purely INFORMATIONAL cross-check (not part of the pre-
    # registered decision rule, which uses `d_containing` above unmodified):
    # does CMRI's own forged-pressure co-occurrence explain the mixed-cohort
    # collapse, or is heterogeneous-population pooling the real mechanism?
    cmri_id = CATEGORY_NAMES.index("CMRI")
    mixed_with_cmri = [w for w in mixed if cmri_id in other_category_of(w)]
    mixed_without_cmri = [w for w in mixed if cmri_id not in other_category_of(w)]
    v_mix_cmri = feature_values(mixed_with_cmri, by_index)
    v_mix_no_cmri = feature_values(mixed_without_cmri, by_index)
    containing_excluding_cmri = pure_msci + mixed_without_cmri
    v_containing_no_cmri = feature_values(containing_excluding_cmri, by_index)

    cmri_mechanism_check = {
        "note": (
            "Informational only -- does not change the pre-registered gate result "
            "above. Checks whether CMRI's own forged-pressure co-occurrence (real "
            "attack data, same phenomenon as the EXP-0026 p_mean_shift erratum) "
            "explains the mixed-cohort collapse, or whether pooling heterogeneous "
            "sub-populations for Cohen's d is the more fundamental mechanism."
        ),
        "mixed_with_cmri_co_occurrence": {
            "n": int(v_mix_cmri.size), "cohens_d_vs_pure_normal": cohens_d(v_mix_cmri, normal_values),
            "median": float(np.median(v_mix_cmri)) if v_mix_cmri.size else None,
        },
        "mixed_without_cmri_co_occurrence": {
            "n": int(v_mix_no_cmri.size), "cohens_d_vs_pure_normal": cohens_d(v_mix_no_cmri, normal_values),
            "median": float(np.median(v_mix_no_cmri)) if v_mix_no_cmri.size else None,
        },
        "all_containing_excluding_any_cmri_co_occurrence": {
            "n": int(v_containing_no_cmri.size),
            "cohens_d_vs_pure_normal": cohens_d(v_containing_no_cmri, normal_values),
            "median": float(np.median(v_containing_no_cmri)) if v_containing_no_cmri.size else None,
        },
    }

    n_containing = int(containing_values.size)
    gate = {
        "rule": f"|Cohen's d| >= {GATE_MIN_ABS_D} AND n >= {GATE_MIN_N}, on the ALL-"
                f"MSCI-containing-windows-vs-pure-Normal comparison (realistic population)",
        "cohens_d_all_containing": d_containing,
        "n_all_containing": n_containing,
        "passed": bool(abs(d_containing) >= GATE_MIN_ABS_D and n_containing >= GATE_MIN_N),
    }
    gate["consequence"] = (
        "proceed to build and measure a standalone detector (VALIDATION-first)"
        if gate["passed"] else
        "STOP -- report as a selection-effect artifact of the pure-cohort filtering, "
        "not a deployable signal; still a valuable, well-verified negative result"
    )

    return {
        "status": "TESTED" if identity_check["within_tolerance"] else "TESTED — IDENTITY CHECK FAILED",
        "experiment": "EXP-0027",
        "scope": "egress only (destination == 1); MSCI vs Normal; 60s native windows; TRAIN+VALIDATION only",
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "window_seconds": WINDOW_SECONDS,
        "feature": FEATURE,
        "n_native_windows_train": len(by_block.get("train", [])),
        "n_native_windows_validation": len(by_block.get("validation", [])),
        "n_native_windows_discarded_boundary_or_empty": n_discarded,
        "identity_check_vs_exp0026_pure_cohort": identity_check,
        "populations": {
            "pure_msci_vs_pure_normal": {
                "n_msci": int(pure_values.size), "n_normal": int(normal_values.size),
                "cohens_d": d_pure, "effect": grade_effect(d_pure),
                "median_msci": float(np.median(pure_values)) if pure_values.size else None,
                "median_normal": float(np.median(normal_values)) if normal_values.size else None,
            },
            "all_containing_msci_vs_pure_normal": {
                "n_msci": n_containing, "n_normal": int(normal_values.size),
                "cohens_d": d_containing, "effect": grade_effect(d_containing),
                "median_msci": float(np.median(containing_values)) if containing_values.size else None,
                "median_normal": float(np.median(normal_values)) if normal_values.size else None,
                "n_huge_gt_1e6": int((containing_values > 1e6).sum()) if containing_values.size else 0,
            },
            "mixed_only_msci_vs_pure_normal": {
                "n_msci": int(mixed_values.size), "n_normal": int(normal_values.size),
                "cohens_d": d_mixed, "effect": grade_effect(d_mixed) if d_mixed is not None else None,
                "median_msci": float(np.median(mixed_values)) if mixed_values.size else None,
            },
        },
        "mixed_cohort_breakdown_by_co_occurring_category": breakdown,
        "cmri_mechanism_check_informational": cmri_mechanism_check,
        "decision_gate": gate,
        "software": {"python": platform.python_version(), "numpy": version("numpy")},
        "limitations": [
            "Pressure is the ARFF-aligned value, not a live 0x03 byte decode.",
            "60s window size only, reusing EXP-0026's construction unchanged -- "
            "other window sizes are out of scope for this follow-up.",
            "The co-occurring-category breakdown groups mixed windows by the exact "
            "SET of other categories present, so some groups may be very small; "
            "counts are reported per group rather than hidden.",
            "One testbed; egress-only; TRAIN+VALIDATION only until (and unless) the "
            "pre-registered gate passes.",
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
    p = r["populations"]
    lines = [
        "# EXP-0027 — MSCI 60s p_std: pure cohort vs the realistic population",
        "",
        f"Status: {r['status']}",
        "",
        f"Identity check vs EXP-0026 pure-cohort d ({r['identity_check_vs_exp0026_pure_cohort']['exp0026_reference_d']}): "
        f"reproduced {r['identity_check_vs_exp0026_pure_cohort']['reproduced_d']:.4f}, "
        f"within tolerance: {r['identity_check_vs_exp0026_pure_cohort']['within_tolerance']}",
        "",
        "| population | n MSCI | n Normal | d | effect |",
        "|---|---:|---:|---:|---|",
        f"| pure MSCI vs pure Normal | {p['pure_msci_vs_pure_normal']['n_msci']} | "
        f"{p['pure_msci_vs_pure_normal']['n_normal']} | "
        f"{p['pure_msci_vs_pure_normal']['cohens_d']:+.3f} | {p['pure_msci_vs_pure_normal']['effect']} |",
        f"| ALL MSCI-containing vs pure Normal | {p['all_containing_msci_vs_pure_normal']['n_msci']} | "
        f"{p['all_containing_msci_vs_pure_normal']['n_normal']} | "
        f"{p['all_containing_msci_vs_pure_normal']['cohens_d']:+.3f} | "
        f"{p['all_containing_msci_vs_pure_normal']['effect']} |",
        f"| mixed-only MSCI vs pure Normal | {p['mixed_only_msci_vs_pure_normal']['n_msci']} | "
        f"{p['mixed_only_msci_vs_pure_normal']['n_normal']} | "
        f"{p['mixed_only_msci_vs_pure_normal']['cohens_d']:+.3f} | "
        f"{p['mixed_only_msci_vs_pure_normal']['effect']} |",
        "",
        "## Mixed-cohort breakdown by co-occurring category",
        "",
        "| co-occurring | n windows | n w/ features | p_std mean | p_std median | n huge (>1e6) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in r["mixed_cohort_breakdown_by_co_occurring_category"]:
        mean = f"{row['p_std_mean']:.3g}" if row["p_std_mean"] is not None else "n/a"
        median = f"{row['p_std_median']:.3g}" if row["p_std_median"] is not None else "n/a"
        lines.append(
            f"| {row['co_occurring_categories']} | {row['n_windows']} | {row['n_with_features']} "
            f"| {mean} | {median} | {row['n_huge_gt_1e6']} |"
        )
    c = r["cmri_mechanism_check_informational"]
    lines += [
        "",
        "## CMRI-mechanism cross-check (informational only, does not change the gate)",
        "",
        f"- {c['note']}",
        f"- mixed WITH CMRI co-occurrence: n={c['mixed_with_cmri_co_occurrence']['n']}, "
        f"d={c['mixed_with_cmri_co_occurrence']['cohens_d_vs_pure_normal']:+.3f}",
        f"- mixed WITHOUT CMRI co-occurrence: n={c['mixed_without_cmri_co_occurrence']['n']}, "
        f"d={c['mixed_without_cmri_co_occurrence']['cohens_d_vs_pure_normal']:+.3f}",
        f"- ALL containing EXCLUDING any CMRI co-occurrence: "
        f"n={c['all_containing_excluding_any_cmri_co_occurrence']['n']}, "
        f"d={c['all_containing_excluding_any_cmri_co_occurrence']['cohens_d_vs_pure_normal']:+.3f}",
        "",
        f"## Decision gate: {'PASSED' if r['decision_gate']['passed'] else 'NOT PASSED'}",
        f"- {r['decision_gate']['rule']}",
        f"- {r['decision_gate']['consequence']}",
    ]
    return "\n".join(lines)


def main() -> None:
    result = run_analysis()
    write_result_atomic(result)
    print(_format_report(result))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
